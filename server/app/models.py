"""SQLAlchemy ORM models.

All primary keys use UUID strings for full DuckDB compatibility.
DuckDB does not support PostgreSQL's SERIAL type; UUID PKs sidestep this
entirely and are more portable.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean, DateTime, Float, Integer, String, Text, ForeignKey, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── CVE Signatures ────────────────────────────────────────────────────────────

class CVESignature(Base):
    __tablename__ = "cve_signatures"

    id: Mapped[str]              = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    cve_id: Mapped[str]          = mapped_column(String(64), unique=True, nullable=False, index=True)
    name: Mapped[str]            = mapped_column(String(256), nullable=False)
    description: Mapped[str]     = mapped_column(Text, default="")
    pattern: Mapped[str]         = mapped_column(Text, nullable=False)
    flags: Mapped[str]           = mapped_column(String(64), default="")
    severity: Mapped[str]        = mapped_column(String(16), default="MEDIUM")
    cvss: Mapped[float]          = mapped_column(Float, default=0.0)
    affected_product: Mapped[str]= mapped_column(String(256), default="")
    active: Mapped[bool]         = mapped_column(Boolean, default=True)
    source: Mapped[str]          = mapped_column(String(64), default="manual")  # nvd|cisa|osv|manual
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    modified_at: Mapped[datetime]= mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# ── Agents ────────────────────────────────────────────────────────────────────

class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str]              = mapped_column(String(64), primary_key=True)
    hostname: Mapped[str]        = mapped_column(String(256), nullable=False)
    ip: Mapped[str]              = mapped_column(String(64), default="")
    server_type: Mapped[str]     = mapped_column(String(32), default="nginx")  # nginx|apache
    version: Mapped[str]         = mapped_column(String(32), default="")
    mode: Mapped[str]            = mapped_column(String(16), default="enforce")  # enforce|shadow
    api_key_hash: Mapped[str]    = mapped_column(String(256), nullable=False)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_cve_sync: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    events: Mapped[list["SecurityEvent"]] = relationship("SecurityEvent", back_populates="agent_rel")


# ── Security Events ───────────────────────────────────────────────────────────

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[str]              = mapped_column(String(64), primary_key=True,
                                                  default=lambda: str(uuid.uuid4()))
    agent_id: Mapped[str]        = mapped_column(String(64), ForeignKey("agents.id"), index=True)
    client_ip: Mapped[str]       = mapped_column(String(64), default="")
    method: Mapped[str]          = mapped_column(String(16), default="")
    uri: Mapped[str]             = mapped_column(Text, default="")
    action: Mapped[str]          = mapped_column(String(16), default="PERMIT", index=True)
    tier: Mapped[int]            = mapped_column(Integer, default=0)
    cve_id: Mapped[str]          = mapped_column(String(64), default="", index=True)
    rule_name: Mapped[str]       = mapped_column(String(256), default="")
    reason: Mapped[str]          = mapped_column(Text, default="")
    ml_score: Mapped[float]      = mapped_column(Float, default=0.0)
    latency_ms: Mapped[float]    = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    agent_rel: Mapped[Agent]     = relationship("Agent", back_populates="events")

    __table_args__ = (
        Index("idx_events_agent_action", "agent_id", "action"),
        Index("idx_events_created_at", "created_at"),
    )


# ── API Keys ──────────────────────────────────────────────────────────────────

class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str]              = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    key_hash: Mapped[str]        = mapped_column(String(256), unique=True, nullable=False)
    description: Mapped[str]     = mapped_column(String(256), default="")
    agent_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # RBAC role: admin | viewer | agent  (CSA Cyber Essentials — least privilege)
    role: Mapped[str]            = mapped_column(String(16), default="agent", nullable=False)
    active: Mapped[bool]         = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


# ── Immutable Audit Log ───────────────────────────────────────────────────────
# Singapore IM8 v5.0 §4.1-4.3, MAS TRM 2021 §9.4 — tamper-evident chain

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str]              = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[datetime]  = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    actor: Mapped[str]           = mapped_column(String(64), default="anonymous", index=True)
    client_ip: Mapped[str]       = mapped_column(String(64), default="")
    method: Mapped[str]          = mapped_column(String(16), default="")
    path: Mapped[str]            = mapped_column(String(1024), default="")
    query: Mapped[str]           = mapped_column(String(512), default="")
    status: Mapped[int]          = mapped_column(Integer, default=0, index=True)
    elapsed_ms: Mapped[float]    = mapped_column(Float, default=0.0)
    user_agent: Mapped[str]      = mapped_column(String(256), default="")
    # HMAC-SHA256 chain seal (prev_hash → chain_hash)
    prev_hash: Mapped[str]       = mapped_column(String(64), nullable=False)
    chain_hash: Mapped[str]      = mapped_column(String(64), nullable=False, unique=True, index=True)

    __table_args__ = (
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_actor", "actor"),
    )
