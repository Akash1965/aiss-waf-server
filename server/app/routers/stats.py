"""
/v1/stats — Aggregated security statistics for dashboards.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, and_, case, desc, text
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import SecurityEvent
from app.auth import verify_api_key
import structlog

log = structlog.get_logger(__name__)
router = APIRouter()


@router.get(
    "/summary",
    summary="Aggregated event counts over a time window",
)
def get_summary(
    hours: int = Query(default=24, ge=1, le=720, description="Window in hours"),
    agent_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> dict:

    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    base = and_(SecurityEvent.created_at >= since)
    if agent_id:
        base = and_(base, SecurityEvent.agent_id == agent_id)

    # Total events
    total = db.execute(select(func.count()).where(base)).scalar() or 0

    # Blocked events
    blocked = db.execute(
        select(func.count()).where(and_(base, SecurityEvent.action == "BLOCK"))
    ).scalar() or 0

    # Top CVEs
    top_cves_result = db.execute(
        select(SecurityEvent.cve_id, func.count().label("count"))
        .where(and_(base, SecurityEvent.cve_id != ""))
        .group_by(SecurityEvent.cve_id)
        .order_by(func.count().desc())
        .limit(10)
    )
    top_cves = [{"cve_id": row.cve_id, "count": row.count} for row in top_cves_result]

    # Top blocked IPs
    top_ips_result = db.execute(
        select(SecurityEvent.client_ip, func.count().label("count"))
        .where(and_(base, SecurityEvent.action == "BLOCK"))
        .group_by(SecurityEvent.client_ip)
        .order_by(func.count().desc())
        .limit(10)
    )
    top_ips = [{"ip": row.client_ip, "count": row.count} for row in top_ips_result]

    # Block rate by tier
    tiers_result = db.execute(
        select(SecurityEvent.tier, func.count().label("count"))
        .where(and_(base, SecurityEvent.action == "BLOCK"))
        .group_by(SecurityEvent.tier)
        .order_by(SecurityEvent.tier)
    )
    tiers = [{"tier": row.tier, "count": row.count} for row in tiers_result]

    block_rate = round(blocked / total * 100, 2) if total > 0 else 0.0

    return {
        "window_hours": hours,
        "agent_id": agent_id,
        "total_requests": total,
        "total_blocked": blocked,
        "total_permitted": total - blocked,
        "block_rate_pct": block_rate,
        "top_cves": top_cves,
        "top_attacker_ips": top_ips,
        "blocks_by_tier": tiers,
    }


@router.get(
    "/timeline",
    summary="Hourly event counts for charting",
)
def get_timeline(
    hours: int = Query(default=24, ge=1, le=168),
    agent_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> dict:
    """Returns hourly bucket counts (total, blocked) for the past N hours."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    base = SecurityEvent.created_at >= since
    if agent_id:
        base = and_(base, SecurityEvent.agent_id == agent_id)

    # Use a raw SQL string to avoid DuckDB binder errors that occur when
    # SQLAlchemy generates parameterised date_trunc($N, col) expressions —
    # DuckDB cannot prove that the $N in SELECT matches the $N in GROUP BY
    # and raises "column must appear in GROUP BY".
    raw_sql = text("""
        SELECT
            date_trunc('hour', created_at) AS hour,
            count(*)                        AS total,
            sum(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) AS blocked
        FROM security_events
        WHERE created_at >= :since
          AND (:agent_id IS NULL OR agent_id = :agent_id)
        GROUP BY date_trunc('hour', created_at)
        ORDER BY date_trunc('hour', created_at)
    """)

    result = db.execute(raw_sql, {"since": since, "agent_id": agent_id})
    buckets = [
        {
            "hour": row.hour.isoformat() if row.hour else None,
            "total": row.total,
            "blocked": int(row.blocked or 0),
        }
        for row in result
    ]

    return {"window_hours": hours, "buckets": buckets}


@router.get(
    "/events",
    summary="Recent security events (for live event log)",
)
def get_events(
    limit: int = Query(default=100, ge=1, le=500),
    action: Optional[str] = Query(default=None, description="Filter by BLOCK or PERMIT"),
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> dict:
    """Returns the most recent N security events ordered by time descending."""
    stmt = select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(limit)
    if action:
        stmt = stmt.where(SecurityEvent.action == action.upper())
    rows = db.execute(stmt).scalars().all()
    events = [
        {
            "id":         e.id,
            "agent_id":   e.agent_id,
            "client_ip":  e.client_ip,
            "method":     e.method,
            "uri":        e.uri,
            "action":     e.action,
            "tier":       e.tier,
            "cve_id":     e.cve_id,
            "rule_name":  e.rule_name,
            "reason":     e.reason,
            "ml_score":   e.ml_score,
            "latency_ms": e.latency_ms,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in rows
    ]
    return {"events": events, "total": len(events)}
