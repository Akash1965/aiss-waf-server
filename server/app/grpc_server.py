"""
AISS gRPC server — runs alongside FastAPI using grpc.aio.

Implements:
  SubmitTelemetry  — receives batched events, enqueues to Doris writer
  GetCVEUpdates    — streams CVE signature deltas to the requesting agent
  RegisterAgent    — upserts agent registration into Doris + DuckDB

Start this server from main.py lifespan alongside the Uvicorn HTTP server.
"""

import asyncio
import json
import time
from datetime import datetime, timezone
from typing import AsyncIterator

import grpc
import grpc.aio
import structlog
from sqlalchemy import select, text

from app.config import settings
from app.database import SessionLocal
from app.doris import event_writer, upsert_agent
from app.models import CVESignature, Agent

log = structlog.get_logger(__name__)

# ── Import generated stubs (falls back to hand-written dataclasses) ───────────
try:
    import aiss_pb2
    import aiss_pb2_grpc
    _USE_PROTO = True
except ImportError:
    _USE_PROTO = False
    log.warning("grpc stubs not found — gRPC server disabled; run proto/generate.sh")


class AISSServicer:
    """Implements the AISS gRPC service methods."""

    async def SubmitTelemetry(self, request, context):
        """Receive a batch of security events and queue them for Doris."""
        accepted = 0
        for ev in request.events:
            event_dict = {
                "created_at":  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "id":          ev.request_id or f"grpc-{time.time_ns()}",
                "agent_id":    ev.agent_id,
                "client_ip":   ev.client_ip,
                "method":      ev.method,
                "uri":         ev.uri[:2048],
                "action":      ev.action,
                "tier":        ev.tier,
                "cve_id":      ev.cve_id,
                "rule_name":   ev.rule_name,
                "reason":      ev.reason[:1024],
                "ml_score":    ev.ml_score,
                "latency_ms":  ev.latency_ms,
                "server_type": ev.server_type,
            }
            if event_writer.enqueue(event_dict):
                accepted += 1

        log.debug("gRPC SubmitTelemetry", accepted=accepted, total=len(request.events))
        if _USE_PROTO:
            return aiss_pb2.TelemetryAck(accepted=accepted, message="ok")
        return type("Ack", (), {"accepted": accepted, "message": "ok"})()

    async def GetCVEUpdates(self, request, context) -> AsyncIterator:
        """Stream CVE signature rows modified after request.since."""
        since_str = request.since or "1970-01-01T00:00:00Z"
        try:
            since_dt = datetime.fromisoformat(since_str.replace("Z", "+00:00"))
        except ValueError:
            since_dt = datetime(1970, 1, 1, tzinfo=timezone.utc)

        log.info("gRPC GetCVEUpdates", agent=request.agent_id, since=since_str)

        with SessionLocal() as db:
            rows = db.execute(
                select(CVESignature).where(
                    CVESignature.active == True,
                    CVESignature.modified_at >= since_dt,
                )
            ).scalars().all()

        for row in rows:
            if _USE_PROTO:
                yield aiss_pb2.CVESignature(
                    id=int(row.id) if row.id else 0,
                    cve_id=row.cve_id,
                    name=row.name or "",
                    pattern=row.pattern,
                    flags=row.flags or "",
                    severity=row.severity,
                    cvss=float(row.cvss or 0),
                    affected_product=row.affected_product or "",
                    active=bool(row.active),
                    modified_at=row.modified_at.isoformat() if row.modified_at else "",
                )
            # gRPC not available — context should not have been entered
            await asyncio.sleep(0)  # yield event loop

    async def RegisterAgent(self, request, context):
        """Upsert agent registration into Doris + local DuckDB."""
        now = datetime.now(timezone.utc)
        row = {
            "id":          request.id,
            "hostname":    request.hostname,
            "ip":          request.ip,
            "server_type": request.server_type,
            "version":     request.version,
            "mode":        request.mode,
            "last_seen":   now.strftime("%Y-%m-%d %H:%M:%S"),
            "created_at":  now.strftime("%Y-%m-%d %H:%M:%S"),
        }
        # Best-effort Doris upsert (runs in thread pool to avoid blocking)
        await asyncio.get_event_loop().run_in_executor(None, upsert_agent, row)
        log.info("Agent registered", agent_id=request.id, hostname=request.hostname)

        if _USE_PROTO:
            return aiss_pb2.AgentAck(ok=True, message="registered")
        return type("Ack", (), {"ok": True, "message": "registered"})()


async def serve_grpc(port: int = 50051) -> None:
    """
    Start the async gRPC server with mTLS when certs are available.

    mTLS (MAS TRM §9.3, NIST SP 800-52 Rev 2):
      - Server presents aiss-server.crt (ECDSA P-384)
      - Client must present a cert signed by the AISS CA (require_client_auth=True)
      - Falls back to insecure if certs not present (development mode)
    """
    if not _USE_PROTO:
        log.warning("gRPC server NOT started (stubs missing — run proto/generate.sh)")
        return

    server = grpc.aio.server()
    aiss_pb2_grpc.add_AISSServicer_to_server(AISSServicer(), server)
    listen_addr = f"[::]:{port}"

    # ── Attempt mTLS ──────────────────────────────────────────────────────────
    import os
    from pathlib import Path

    cert_dir   = Path(os.environ.get("AISS_CERT_DIR", "/certs"))
    server_crt = cert_dir / "aiss-server.crt"
    server_key = cert_dir / "aiss-server.key"
    ca_crt     = cert_dir / "ca.crt"

    if server_crt.exists() and server_key.exists() and ca_crt.exists():
        try:
            server_credentials = grpc.ssl_server_credentials(
                [(server_key.read_bytes(), server_crt.read_bytes())],
                root_certificates=ca_crt.read_bytes(),
                require_client_auth=True,          # mutual TLS — clients must present cert
            )
            server.add_secure_port(listen_addr, server_credentials)
            log.info("gRPC server started with mTLS", addr=listen_addr, cert_dir=str(cert_dir))
        except Exception as exc:
            log.warning("mTLS setup failed, falling back to insecure gRPC", error=str(exc))
            server.add_insecure_port(listen_addr)
            log.info("gRPC server started (insecure fallback)", addr=listen_addr)
    else:
        server.add_insecure_port(listen_addr)
        log.info("gRPC server started (insecure — certs not found)", addr=listen_addr,
                 cert_dir=str(cert_dir))

    await server.start()
    try:
        await server.wait_for_termination()
    except asyncio.CancelledError:
        await server.stop(grace=5)
        log.info("gRPC server stopped")
