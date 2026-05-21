"""
/v1/telemetry — Batch event ingestion from agents.

Agents POST batches of security events here every flush interval (default: 5s).
The server persists them to DuckDB for dashboard / alerting consumption.

Query your logs any time with:
  duckdb /data/aiss.duckdb
  SELECT * FROM security_events ORDER BY created_at DESC LIMIT 100;
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks

from app.models import SecurityEvent
from app.schemas import TelemetryBatch, TelemetryAck
from app.auth import verify_api_key
import structlog

log = structlog.get_logger(__name__)
router = APIRouter()

# Cap batch size to prevent DoS
MAX_BATCH_SIZE = 1000


@router.post(
    "/telemetry",
    response_model=TelemetryAck,
    summary="Ingest a batch of security events",
    status_code=status.HTTP_202_ACCEPTED,
)
def ingest_telemetry(
    batch: TelemetryBatch,
    background_tasks: BackgroundTasks,
    agent_id: str = Depends(verify_api_key),
) -> TelemetryAck:

    if len(batch.events) > MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Batch size {len(batch.events)} exceeds maximum {MAX_BATCH_SIZE}",
        )

    # Persist in background to return fast
    background_tasks.add_task(_persist_events, agent_id, batch.events)

    log.info(
        "Telemetry batch accepted",
        agent_id=agent_id,
        count=len(batch.events),
    )

    return TelemetryAck(accepted=len(batch.events), status="queued")


def _persist_events(agent_id: str, events: list) -> None:
    """Background task: write events to DuckDB in a single transaction.

    Uses _db_lock so this background thread does not race with request threads
    that also hold the shared DuckDB connection via StaticPool.
    """
    from app.database import SessionLocal, _db_lock

    _db_lock.acquire()
    session = SessionLocal()
    try:
        for ev in events:
            event = SecurityEvent(
                id=ev.id,
                agent_id=agent_id,
                client_ip=ev.client_ip,
                method=ev.method,
                uri=ev.uri,
                action=ev.action,
                tier=ev.tier,
                cve_id=ev.cve_id or "",
                rule_name=ev.rule_name or "",
                reason=ev.reason or "",
                ml_score=ev.ml_score,
                latency_ms=ev.latency_ms,
            )
            session.add(event)
        session.commit()
        log.debug("Telemetry batch persisted", agent_id=agent_id, count=len(events))
    except Exception as exc:
        session.rollback()
        log.error("Failed to persist telemetry batch", error=str(exc))
    finally:
        session.close()
        _db_lock.release()
