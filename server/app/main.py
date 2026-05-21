"""
AISS Central Server — AI Security Shield
Provides the management API, CVE update distribution, and telemetry aggregation
for all AISS agents deployed on Nginx / Apache hosts.

Endpoints:
  GET  /v1/updates             — Delta CVE signature feed for agents
  POST /v1/telemetry           — Batch event ingestion from agents
  GET  /v1/stats               — Aggregated security statistics
  GET  /v1/agents              — Registered agent list
  POST /v1/agents/{id}/command — Send reload/mode-switch command to agent
  GET  /health                 — Health check
  GET  /metrics                — Prometheus metrics (via instrumentator)
"""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from app.config import settings
from app.database import init_db, SessionLocal, _db_lock
from app.cve_sync import CVESyncWorker
from app.doris import event_writer
from app.grpc_server import serve_grpc
from app.routers import updates, telemetry, agents, stats, auth
from app.routers import audit as audit_router
from app.routers import inspect as inspect_router
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.audit import AuditLogMiddleware
import structlog

# ── Structured logging ────────────────────────────────────────────────────────
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

log = structlog.get_logger(__name__)


# ── Bootstrap admin key ───────────────────────────────────────────────────────

def _seed_bootstrap_key() -> None:
    """Create an initial admin API key on first startup (production only).

    Uses settings.secret_key (Render's AISS_SECRET_KEY) as the bootstrap
    credential so the operator can authenticate immediately after deploy.
    Skipped when any active admin key already exists in the DB.
    """
    if settings.environment == "development":
        return  # Dev mode accepts any key — no seeding needed

    from app.models import APIKey
    from app.auth import hash_api_key
    from sqlalchemy import select

    with _db_lock:
        with SessionLocal() as db:
            existing = db.execute(
                select(APIKey).where(
                    APIKey.role == "admin",
                    APIKey.active.is_(True),
                )
            ).scalars().first()

            if existing:
                log.info("Bootstrap key already present — skipping seed")
                return

            bootstrap_key = settings.secret_key
            db.add(APIKey(
                agent_id    = "bootstrap-admin",
                key_hash    = hash_api_key(bootstrap_key),
                description = "Bootstrap admin key (value = AISS_SECRET_KEY env var)",
                role        = "admin",
                active      = True,
            ))
            db.commit()

    log.info(
        "Bootstrap admin key seeded — use AISS_SECRET_KEY value as X-API-Key",
        hint="Set X-API-Key: <AISS_SECRET_KEY value> to authenticate",
    )


# ── Application lifespan ──────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("AISS server starting", version="1.0.0", env=settings.environment)
    await init_db()
    _seed_bootstrap_key()

    # Start Doris batch writer (security events flushed every 1 s or 5 000 events)
    await event_writer.start()
    grpc_task = asyncio.create_task(serve_grpc(port=settings.grpc_port))

    # Seed + schedule CVE sync worker
    worker = CVESyncWorker()
    await worker.sync_all()                          # immediate seed on startup
    cve_task = asyncio.create_task(worker.run_forever())

    yield

    cve_task.cancel()
    await worker.close()
    grpc_task.cancel()
    await event_writer.stop()
    log.info("AISS server shutting down")


# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="AISS Central Server",
    description="AI Security Shield — central management and CVE distribution server",
    version="1.0.0",
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url="/redoc" if settings.environment != "production" else None,
    lifespan=lifespan,
)

# ── Prometheus metrics ────────────────────────────────────────────────────────
Instrumentator(
    should_group_status_codes=True,
    should_ignore_untemplated=True,
    should_respect_env_var=True,
    should_instrument_requests_inprogress=True,
    excluded_handlers=["/health", "/metrics"],
).instrument(app).expose(app)

# ── Security middleware stack (outermost → innermost) ─────────────────────────
# Order matters with Starlette: last added runs first.
# Desired order (request): RateLimit → Audit → SecurityHeaders → CORS → routes
# Starlette processes in LIFO order, so we add innermost first:

# 1. Security headers — applied to every response
app.add_middleware(SecurityHeadersMiddleware)

# 2. Immutable audit logging — records every non-health request
app.add_middleware(AuditLogMiddleware, secret_key=settings.secret_key)

# 3. Rate limiting — rejects abusive clients before routing
app.add_middleware(RateLimitMiddleware, requests_per_minute=settings.rate_limit_per_minute)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Agent-ID", "X-API-Key", "X-Request-ID"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth.router,              prefix="/v1/auth",     tags=["auth"])
app.include_router(updates.router,           prefix="/v1",          tags=["updates"])
app.include_router(telemetry.router,         prefix="/v1",          tags=["telemetry"])
app.include_router(agents.router,            prefix="/v1/agents",   tags=["agents"])
app.include_router(stats.router,             prefix="/v1/stats",    tags=["stats"])
app.include_router(audit_router.router,      prefix="/v1/audit",    tags=["audit"])
app.include_router(inspect_router.router,    prefix="/v1/inspect",  tags=["inspect"])


@app.get("/health", tags=["health"])
async def health():
    """Liveness probe — returns 200 when server is up."""
    return {"status": "ok", "version": "1.0.0"}
