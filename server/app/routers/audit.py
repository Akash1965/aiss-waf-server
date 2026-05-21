"""
/v1/audit — Immutable audit log endpoints.

Compliance:
  • Singapore IM8 v5.0 §4.1-4.3 — Audit log retrieval and verification
  • MAS TRM 2021 §9.4 — Audit trail non-repudiation
  • CSA Cybersecurity Code of Practice §10 — Incident forensics
"""

import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditLog
from app.auth import verify_api_key, require_role
from app.config import settings
import structlog

log = structlog.get_logger(__name__)
router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────

class AuditEntry(BaseModel):
    id: str
    timestamp: datetime
    actor: str
    client_ip: str
    method: str
    path: str
    query: str
    status: int
    elapsed_ms: float
    user_agent: str
    prev_hash: str
    chain_hash: str

    model_config = {"from_attributes": True}


class AuditVerifyResult(BaseModel):
    ok: bool
    entries_checked: int
    first_broken_at: Optional[str] = None
    message: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get(
    "",
    response_model=List[AuditEntry],
    summary="Retrieve audit log entries",
    description="Returns paginated audit log entries (newest first). "
                "Admin or viewer role required.",
)
def list_audit_entries(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    actor: Optional[str] = Query(None, description="Filter by actor"),
    since: Optional[datetime] = Query(None, description="ISO-8601 start timestamp"),
    db: Session = Depends(get_db),
    _: str = Depends(require_role(["admin", "viewer"])),
) -> List[AuditEntry]:
    stmt = select(AuditLog).order_by(AuditLog.timestamp.desc())
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    if since:
        stmt = stmt.where(AuditLog.timestamp >= since)
    stmt = stmt.limit(limit).offset(offset)

    rows = db.execute(stmt).scalars().all()
    return [AuditEntry.model_validate(r) for r in rows]


@router.get(
    "/verify",
    response_model=AuditVerifyResult,
    summary="Verify HMAC chain integrity",
    description="Re-computes each entry's chain_hash and verifies the "
                "chain is unbroken. Returns the first broken entry if any. "
                "Admin role required.",
)
def verify_chain(
    db: Session = Depends(get_db),
    _: str = Depends(require_role(["admin"])),
) -> AuditVerifyResult:
    stmt = select(AuditLog).order_by(AuditLog.timestamp.asc())
    rows = db.execute(stmt).scalars().all()

    prev_hash = "GENESIS"
    for i, row in enumerate(rows):
        payload = f"{row.prev_hash}|{row.timestamp.isoformat()}|{row.actor}|{row.method}|{row.path}|{row.status}"
        expected = hmac.new(
            settings.secret_key.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

        if row.chain_hash != expected or row.prev_hash != prev_hash:
            log.warning(
                "Audit chain integrity failure",
                entry_id=row.id,
                position=i,
                expected=expected,
                got=row.chain_hash,
            )
            return AuditVerifyResult(
                ok=False,
                entries_checked=i + 1,
                first_broken_at=row.id,
                message=f"Chain broken at entry #{i + 1} (id={row.id})",
            )
        prev_hash = row.chain_hash

    return AuditVerifyResult(
        ok=True,
        entries_checked=len(rows),
        message=f"All {len(rows)} entries verified — chain is intact.",
    )


@router.delete(
    "/purge",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Purge old audit log entries",
    description="Delete entries older than `days` days (default 365). "
                "Minimum 180 days (IM8 online retention requirement). "
                "Admin role required.",
)
def purge_old_entries(
    days: int = Query(365, ge=180),
    db: Session = Depends(get_db),
    _: str = Depends(require_role(["admin"])),
) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    deleted = db.query(AuditLog).filter(AuditLog.timestamp < cutoff).delete()
    db.commit()
    log.info("Audit log purged", entries_deleted=deleted, cutoff=cutoff.isoformat())


@router.post(
    "/reset-chain",
    summary="Reset the audit chain (admin only)",
    description=(
        "**Emergency admin action.**  Clears ALL audit log entries and resets "
        "the HMAC chain pointer to GENESIS.  Use this only after a confirmed "
        "chain-break caused by a software bug (e.g. race condition before "
        "the chain serialisation fix).  The reset itself is logged to stdout "
        "with the actor identity for non-repudiation."
        "\n\n"
        "Compliance note (IM8 §4.3): document the reason for the reset in your "
        "incident register before calling this endpoint."
    ),
)
def reset_chain(
    db: Session = Depends(get_db),
    actor: str = Depends(require_role(["admin"])),
) -> dict:
    """Truncate audit_logs and reset the in-memory chain pointer to GENESIS."""
    from app.middleware.audit import _instance as audit_mw

    # Count entries being dropped for the response
    total = db.execute(__import__("sqlalchemy").select(__import__("sqlalchemy").func.count()).select_from(AuditLog)).scalar() or 0

    # Truncate the table inside the existing DB session
    db.query(AuditLog).delete()
    db.commit()

    # Reset the live middleware chain pointer (serialised with _chain_lock)
    if audit_mw is not None:
        with audit_mw._chain_lock:
            audit_mw._last_hash = "GENESIS"
        log.warning(
            "Audit chain RESET by admin",
            actor=actor,
            entries_dropped=total,
            new_genesis="GENESIS",
        )
    else:
        log.warning(
            "Audit chain DB cleared but middleware instance not found — "
            "restart server to sync _last_hash",
            actor=actor,
            entries_dropped=total,
        )

    return {
        "ok": True,
        "entries_dropped": total,
        "new_genesis": "GENESIS",
        "message": (
            f"Audit chain reset by {actor}. "
            f"{total} entries dropped. "
            "Chain will restart from GENESIS on next request."
        ),
    }
