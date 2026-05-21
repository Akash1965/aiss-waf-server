"""Pydantic request/response schemas."""

from typing import List, Optional
from pydantic import BaseModel, Field


# ── CVE Updates ───────────────────────────────────────────────────────────────

class CVEUpdateResponse(BaseModel):
    id: str
    cve_id: str
    pattern: str
    severity: str
    cvss: float
    affected_product: str
    active: bool
    modified_at: str


# ── Telemetry ─────────────────────────────────────────────────────────────────

class TelemetryEvent(BaseModel):
    id: str
    client_ip: str = ""
    method: str = ""
    uri: str = ""
    action: str = "PERMIT"
    tier: int = 0
    cve_id: Optional[str] = None
    rule_name: Optional[str] = None
    reason: Optional[str] = None
    ml_score: float = 0.0
    latency_ms: float = 0.0


class TelemetryBatch(BaseModel):
    events: List[TelemetryEvent] = Field(default_factory=list)


class TelemetryAck(BaseModel):
    accepted: int
    status: str


# ── Agents ────────────────────────────────────────────────────────────────────

class AgentRegisterRequest(BaseModel):
    agent_id: str
    hostname: str
    ip: Optional[str] = None
    server_type: str = "nginx"
    version: Optional[str] = None
    api_key: str  # raw key — hashed server-side


class AgentResponse(BaseModel):
    id: str
    hostname: str
    ip: str
    server_type: str
    version: str
    mode: str
    last_seen: Optional[str]
    created_at: str


# ── Auth ──────────────────────────────────────────────────────────────────────

class APIKeyCreateRequest(BaseModel):
    description: Optional[str] = None
    agent_id: Optional[str] = None
    expires_in_days: Optional[int] = Field(default=365, ge=1, le=3650)


class APIKeyCreateResponse(BaseModel):
    key: str  # shown once
    description: str
    expires_at: Optional[str]
