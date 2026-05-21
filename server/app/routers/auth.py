"""
/v1/auth — API key issuance and JWT token generation.

Compliance:
  • Singapore IM8 v5.0 §3.3 — Authentication
  • MAS TRM 2021 §9.1 — Access control
  • CSA Cyber Essentials — Least privilege, role separation
  • NIST SP 800-131A Rev 2 — RS256 signing
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import APIKey
from app.auth import hash_api_key, create_access_token, require_role, verify_api_key
from app.schemas import APIKeyCreateResponse
import structlog

log = structlog.get_logger(__name__)
router = APIRouter()

# ── Schemas ───────────────────────────────────────────────────────────────────

class TokenRequest(BaseModel):
    api_key: str = Field(..., description="Raw API key to exchange for a JWT")

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int
    role: str


class APIKeyCreateRequestV2(BaseModel):
    description: Optional[str] = None
    agent_id: Optional[str] = None
    role: str = Field("agent", pattern="^(admin|viewer|agent)$",
                      description="RBAC role: admin | viewer | agent")
    expires_in_days: Optional[int] = Field(None, ge=1, le=3650)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post(
    "/keys",
    response_model=APIKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Issue a new API key (admin only in production)",
    description="The raw key is returned **once** and never stored. "
                "Only the HMAC-SHA256 hash is persisted. "
                "In development mode, any non-empty key is accepted.",
)
def create_api_key(
    req: APIKeyCreateRequestV2,
    db: Session = Depends(get_db),
    actor: str = Depends(require_role(["admin"])),
) -> APIKeyCreateResponse:
    raw_key = secrets.token_urlsafe(48)
    key_hash = hash_api_key(raw_key)

    expires_at = None
    if req.expires_in_days and req.expires_in_days > 0:
        expires_at = datetime.now(timezone.utc) + timedelta(days=req.expires_in_days)

    api_key = APIKey(
        key_hash=key_hash,
        description=req.description or "",
        agent_id=req.agent_id,
        role=req.role,
        expires_at=expires_at,
    )
    db.add(api_key)
    db.commit()

    log.info(
        "API key issued",
        issued_by=actor,
        description=req.description,
        agent_id=req.agent_id,
        role=req.role,
        expires_at=expires_at,
    )

    return APIKeyCreateResponse(
        key=raw_key,
        description=req.description or "",
        expires_at=expires_at.isoformat() if expires_at else None,
    )


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Exchange API key for a JWT (RS256)",
    description="Submit a valid API key to receive a short-lived RS256 JWT "
                "suitable for dashboard and browser clients. "
                "In development mode any non-empty key is accepted with admin role.",
)
def exchange_for_token(
    req: TokenRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    from app.auth import _lookup_api_key
    from app.config import settings

    if settings.environment == "development":
        actor = req.api_key[:20] or "dev-actor"
        role  = "admin"
    else:
        try:
            actor, role = _lookup_api_key(req.api_key)
        except HTTPException:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key.",
            )

    expires_minutes = settings.access_token_expire_minutes
    token = create_access_token(subject=actor, role=role, expires_minutes=expires_minutes)

    log.info("JWT issued", actor=actor, role=role, expires_minutes=expires_minutes)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in_seconds=expires_minutes * 60,
        role=role,
    )


@router.get(
    "/me",
    summary="Return current caller identity and role",
)
def whoami(
    actor: str = Depends(verify_api_key),
) -> dict:
    from app.auth import verify_api_key_with_role
    return {"actor": actor}
