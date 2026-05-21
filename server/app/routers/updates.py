"""
/v1/updates — CVE signature delta endpoint.

Agents poll this endpoint every N minutes (default: 60) to fetch new or
modified CVE patterns since their last sync timestamp.

Query params:
  since     — RFC3339 timestamp (e.g. 2026-01-01T00:00:00Z)
  agent_id  — Agent identifier for audit logging
"""

from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy import select, and_
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import CVESignature, Agent
from app.schemas import CVEUpdateResponse
from app.auth import verify_api_key
import structlog

log = structlog.get_logger(__name__)
router = APIRouter()


@router.get(
    "/updates",
    response_model=List[CVEUpdateResponse],
    summary="Fetch CVE signature deltas",
    description="Returns all CVE signatures modified since `since`. "
                "Agents call this on a schedule to stay current.",
)
def get_updates(
    since: str = Query(
        default="",
        description="RFC3339 timestamp — return signatures modified after this time",
    ),
    agent_id: str = Query(default="", description="Agent identifier"),
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> List[CVEUpdateResponse]:

    # Parse the `since` timestamp
    since_dt: Optional[datetime] = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid `since` timestamp format: {since!r}. Use RFC3339.",
            )

    # Build query
    stmt = select(CVESignature).where(CVESignature.active == True)  # noqa: E712
    if since_dt:
        stmt = stmt.where(CVESignature.modified_at > since_dt)

    stmt = stmt.order_by(CVESignature.modified_at.desc())

    signatures = db.execute(stmt).scalars().all()

    # Update agent's last_seen and last_cve_sync
    if agent_id:
        agent = db.execute(
            select(Agent).where(Agent.id == agent_id)
        ).scalar_one_or_none()
        if agent:
            agent.last_seen = datetime.now(timezone.utc)
            agent.last_cve_sync = datetime.now(timezone.utc)

    log.info(
        "CVE delta served",
        agent_id=agent_id,
        since=since,
        count=len(signatures),
    )

    return [
        CVEUpdateResponse(
            id=sig.id,
            cve_id=sig.cve_id,
            pattern=sig.pattern,
            severity=sig.severity,
            cvss=sig.cvss,
            affected_product=sig.affected_product,
            active=sig.active,
            modified_at=sig.modified_at.isoformat(),
        )
        for sig in signatures
    ]
