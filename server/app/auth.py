"""
AISS Authentication & Authorization
=====================================
• API key verification (HMAC-SHA256 hashed at rest)
• RBAC dependency — require_role(["admin","viewer","agent"])
• JWT issuance & verification — RS256 asymmetric (FIPS 186-5 / NIST SP 800-131A)

Compliance:
  • Singapore IM8 v5.0 §3.3 — Strong authentication
  • MAS TRM 2021 §9.1 — Access control
  • CSA Cyber Essentials — Least privilege
  • NIST SP 800-131A Rev 2 — RS256 (RSA-2048+ / SHA-256)
  • Japan CRYPTREC TR-02 — RSA-PSS / RSASSA-PKCS1-v1_5 with SHA-256
"""

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from jose import JWTError, jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from app.config import settings
import structlog

log = structlog.get_logger(__name__)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
BEARER_HEADER  = APIKeyHeader(name="Authorization", auto_error=False)

# ── RSA-2048 key pair for JWT RS256 ──────────────────────────────────────────
# Keys are generated on first run and persisted to /data/jwt_{private,public}.pem
# Override with AISS_JWT_PRIVATE_KEY_PATH / AISS_JWT_PUBLIC_KEY_PATH env vars.

_JWT_PRIVATE_KEY: Optional[object] = None
_JWT_PUBLIC_KEY:  Optional[object] = None
_JWT_PRIVATE_PEM: Optional[str]    = None
_JWT_PUBLIC_PEM:  Optional[str]    = None


def _load_or_generate_jwt_keys() -> None:
    """Load RSA-2048 JWT key pair from disk, or generate if absent."""
    global _JWT_PRIVATE_KEY, _JWT_PUBLIC_KEY, _JWT_PRIVATE_PEM, _JWT_PUBLIC_PEM

    priv_path = Path(os.environ.get("AISS_JWT_PRIVATE_KEY_PATH", "/data/jwt_private.pem"))
    pub_path  = Path(os.environ.get("AISS_JWT_PUBLIC_KEY_PATH",  "/data/jwt_public.pem"))

    if priv_path.exists() and pub_path.exists():
        _JWT_PRIVATE_PEM = priv_path.read_text()
        _JWT_PUBLIC_PEM  = pub_path.read_text()
        log.info("JWT RS256 keys loaded from disk", priv=str(priv_path))
    else:
        log.info("Generating RSA-2048 JWT key pair (FIPS 186-5 / NIST SP 800-131A)")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        _JWT_PRIVATE_PEM = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        _JWT_PUBLIC_PEM = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        # Persist to /data if writeable
        try:
            priv_path.parent.mkdir(parents=True, exist_ok=True)
            priv_path.write_text(_JWT_PRIVATE_PEM)
            pub_path.write_text(_JWT_PUBLIC_PEM)
            priv_path.chmod(0o600)  # owner-read-only
            log.info("JWT RS256 key pair persisted", priv=str(priv_path))
        except OSError as e:
            log.warning("Could not persist JWT keys (in-memory only)", error=str(e))


# Initialise keys at import time
_load_or_generate_jwt_keys()


# ── Hashing ───────────────────────────────────────────────────────────────────

def hash_api_key(raw_key: str) -> str:
    """HMAC-SHA256 of the raw API key for safe storage (never stores plaintext)."""
    return hmac.new(
        settings.secret_key.encode(),
        raw_key.encode(),
        hashlib.sha256,
    ).hexdigest()


# ── JWT helpers ───────────────────────────────────────────────────────────────

def create_access_token(
    subject: str,
    role: str = "viewer",
    expires_minutes: Optional[int] = None,
) -> str:
    """
    Issue a JWT signed with RS256 (asymmetric — private key signs, public verifies).
    Subject is agent_id or user identifier; role is embedded as a claim.
    """
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes or settings.access_token_expire_minutes
    )
    payload = {
        "sub":  subject,
        "role": role,
        "iat":  datetime.now(timezone.utc),
        "exp":  expire,
        "iss":  "aiss-server",
    }
    algorithm = "RS256" if settings.algorithm.upper() == "RS256" else "HS256"
    signing_key = _JWT_PRIVATE_PEM if algorithm == "RS256" else settings.secret_key

    return jwt.encode(payload, signing_key, algorithm=algorithm)


def decode_access_token(token: str) -> dict:
    """Verify and decode a JWT.  Raises HTTPException on failure."""
    algorithm = "RS256" if settings.algorithm.upper() == "RS256" else "HS256"
    verify_key = _JWT_PUBLIC_PEM if algorithm == "RS256" else settings.secret_key
    try:
        return jwt.decode(token, verify_key, algorithms=[algorithm])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
        )


# ── Internal helpers ──────────────────────────────────────────────────────────

def _extract_bearer(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def _lookup_api_key(raw_key: str) -> tuple[str, str]:
    """
    Validate raw API key against DB.
    Returns (actor, role).  Raises HTTPException if invalid.
    """
    from app.database import SessionLocal
    from app.models import APIKey
    from sqlalchemy import select

    key_hash = hash_api_key(raw_key)
    with SessionLocal() as db:
        stmt = select(APIKey).where(
            APIKey.key_hash == key_hash,
            APIKey.active.is_(True),
        )
        row = db.execute(stmt).scalar_one_or_none()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or expired API key.",
        )

    # Check expiry
    if row.expires_at and row.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key has expired.",
        )

    actor = row.agent_id or raw_key[:12] + "..."
    role  = getattr(row, "role", "agent") or "agent"
    return actor, role


# ── FastAPI dependencies ──────────────────────────────────────────────────────

def verify_api_key(
    x_api_key: Optional[str] = Security(API_KEY_HEADER),
    authorization: Optional[str] = Security(BEARER_HEADER),
) -> str:
    """
    Dependency: validate API key or Bearer JWT.
    Returns actor string (agent_id or key prefix).
    Development: accepts any non-empty key without DB lookup.
    """
    raw = x_api_key or _extract_bearer(authorization)

    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide X-API-Key header or Authorization: Bearer <key>.",
        )

    if settings.environment == "development":
        return raw  # Dev: trust any key

    # Check if it's a JWT first
    if raw.startswith("eyJ"):
        payload = decode_access_token(raw)
        return payload.get("sub", "unknown")

    actor, _ = _lookup_api_key(raw)
    return actor


def verify_api_key_with_role(
    x_api_key: Optional[str] = Security(API_KEY_HEADER),
    authorization: Optional[str] = Security(BEARER_HEADER),
) -> tuple[str, str]:
    """
    Dependency: returns (actor, role).
    Development: role is always 'admin'.
    """
    raw = x_api_key or _extract_bearer(authorization)

    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing credentials.",
        )

    if settings.environment == "development":
        return raw, "admin"

    # JWT path
    if raw.startswith("eyJ"):
        payload = decode_access_token(raw)
        return payload.get("sub", "unknown"), payload.get("role", "viewer")

    return _lookup_api_key(raw)


def require_role(allowed_roles: List[str]):
    """
    Factory dependency — returns a callable that enforces role membership.

    Usage:
      @router.get("/admin-only")
      def endpoint(_: str = Depends(require_role(["admin"]))):
          ...
    """
    def _check(creds: tuple[str, str] = Depends(verify_api_key_with_role)) -> str:
        actor, role = creds
        if role not in allowed_roles:
            log.warning(
                "RBAC denial",
                actor=actor,
                role=role,
                required=allowed_roles,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role}' is not authorised. Required: {allowed_roles}",
            )
        return actor
    return _check


def create_api_key_router():
    """Returns the /v1/auth router (imported in main.py)."""
    from app.routers.auth import router
    return router
