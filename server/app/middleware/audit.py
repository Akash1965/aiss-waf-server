"""
AISS Immutable Audit Log Middleware
=====================================
Records every API access with a HMAC-SHA256 chain seal to detect tampering.

Compliance:
  • Singapore IM8 v5.0 §4.1-4.3 — Audit Logging Requirements
      - Who: actor (API key / agent_id), IP, user agent
      - What: method, path, status code, request size
      - When: UTC timestamp (ISO-8601)
      - Outcome: HTTP status
  • MAS TRM 2021 §9.4 — Audit Trail
      - 6-month online retention minimum; 1-year archive
      - Tamper-evident (chained HMAC)
      - Non-repudiation
  • CSA Cybersecurity Code of Practice §10 — Incident Forensics
  • Japan METI Security Action §3.3 — Log Management
  • Korea K-ISMS Annex A §12.4 — Logging and Monitoring

Chain integrity:
  Each log entry stores:
    prev_hash   = chain_hash of the immediately preceding DB entry
    chain_hash  = HMAC-SHA256(secret, prev_hash|timestamp|actor|method|path|status)
  Verifying the chain: GET /v1/audit/verify

Bug fixes in this version (v3):
  1. Race condition — a threading.Lock (_chain_lock) serialises the entire
     capture-compute-write-update cycle.  Without it, two concurrent requests
     could both read the same _last_hash and produce two DB entries with
     identical prev_hash, breaking the chain.

  2. DB write failure rollback — _last_hash is now updated ONLY after a
     successful session.commit().  Previously an IntegrityError (e.g. duplicate
     chain_hash) would leave _last_hash pointing to a hash that was never stored,
     poisoning every subsequent entry.

  3. Restart gap — on __init__ the middleware reads the latest chain_hash from
     the audit_logs table and seeds _last_hash from it.  Previously a server
     restart always reset _last_hash to "GENESIS", breaking the chain at the
     first post-restart write.

  4. Timestamp-order mismatch — the request timestamp is now captured INSIDE
     _append_to_chain, AFTER acquiring _chain_lock.  Previously it was captured
     in dispatch() before the thread-pool submission, so a thread that was
     scheduled later could carry an earlier timestamp than the entry it links
     to.  The verify endpoint sorts entries by timestamp; if timestamp order
     differed from chain order, verification saw a spurious chain break even
     though the prev_hash links were perfectly valid.
"""

import hashlib
import hmac
import threading
import time
import uuid
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
import structlog

log = structlog.get_logger(__name__)

# Paths exempt from audit logging (health / metrics noise)
SKIP_PATHS = {"/health", "/metrics", "/docs", "/redoc", "/openapi.json"}

# Module-level reference to the running middleware instance.
# Set in __init__ so the audit router's reset-chain endpoint can reach
# _chain_lock and _last_hash without app.middleware_stack inspection.
_instance: "AuditLogMiddleware | None" = None


def _compute_chain_hash(
    secret: str,
    prev_hash: str,
    timestamp: str,
    actor: str,
    method: str,
    path: str,
    status: int,
) -> str:
    """HMAC-SHA256 chain seal — links this entry to the previous one."""
    payload = f"{prev_hash}|{timestamp}|{actor}|{method}|{path}|{status}"
    return hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()  # type: ignore[attr-defined]


def _load_last_chain_hash() -> str:
    """
    Read the most recent chain_hash from audit_logs on startup.

    Fixes restart gap bug: without this, _last_hash resets to "GENESIS" after
    every server restart, causing the first post-restart entry to have the wrong
    prev_hash and breaking verification at that point.

    Returns "GENESIS" if the table is empty or unreachable.
    """
    try:
        from sqlalchemy import text as sa_text
        from app.database import SessionLocal, _db_lock

        _db_lock.acquire()
        session = SessionLocal()
        try:
            row = session.execute(
                sa_text(
                    "SELECT chain_hash FROM audit_logs "
                    "ORDER BY timestamp DESC LIMIT 1"
                )
            ).fetchone()
            if row:
                log.info("Audit chain resumed from DB", last_hash=row[0][:16] + "…")
                return row[0]
            return "GENESIS"
        finally:
            session.close()
            _db_lock.release()
    except Exception as exc:
        log.warning("Could not load last audit chain hash — starting from GENESIS", error=str(exc))
        return "GENESIS"


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Write a tamper-evident audit entry for every non-health API call."""

    def __init__(self, app, secret_key: str):
        super().__init__(app)
        self._secret = secret_key

        # Register this instance globally so routers can reset the chain
        global _instance
        _instance = self

        # ── Fix #1: serialise all chain operations ─────────────────────────
        # A threading.Lock ensures that the sequence
        #   read _last_hash → compute chain_hash → write DB → update _last_hash
        # is atomic with respect to other concurrent requests.
        # Without this lock two simultaneous requests read the same prev_hash,
        # producing two DB entries that share it, breaking verification.
        self._chain_lock = threading.Lock()

        # ── Fix #3: resume chain from DB on restart ────────────────────────
        self._last_hash = _load_last_chain_hash()

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in SKIP_PATHS:
            return await call_next(request)

        start  = time.monotonic()
        req_id = request.headers.get("x-request-id", str(uuid.uuid4()))
        actor  = (
            request.headers.get("x-api-key", "")
            or request.headers.get("authorization", "")[:20]
            or "anonymous"
        )

        response = await call_next(request)

        elapsed_ms = round((time.monotonic() - start) * 1000, 2)

        partial = {
            "id":         req_id,
            # timestamp is intentionally omitted here; it is stamped inside
            # _append_to_chain AFTER acquiring _chain_lock.  This guarantees
            # that the recorded timestamp is monotonically increasing with
            # chain order even under concurrent requests.
            #
            # Bug fixed (Fix #4): capturing ts here (before the thread-pool
            # submission) meant a thread that acquired _chain_lock later could
            # still carry an earlier timestamp, making timestamp-ordered
            # verification see a "gap" in the chain.
            "actor":      actor[:64],
            "client_ip":  request.headers.get(
                              "x-real-ip",
                              request.client.host if request.client else "",
                          ),
            "method":     request.method,
            "path":       request.url.path[:1024],
            "query":      str(request.url.query)[:512],
            "status":     response.status_code,
            "elapsed_ms": elapsed_ms,
            "user_agent": request.headers.get("user-agent", "")[:256],
        }

        # Run the entire chain-append in a thread-pool executor.
        # _append_to_chain holds _chain_lock for the full
        # capture → stamp-timestamp → compute → write → update cycle, so no
        # two calls can interleave their chain operations or their timestamps.
        import asyncio
        loop = asyncio.get_event_loop()
        asyncio.ensure_future(
            loop.run_in_executor(None, self._append_to_chain, partial)
        )

        response.headers["X-Request-ID"] = req_id
        return response

    def _append_to_chain(self, partial: dict) -> None:
        """
        Thread-safe chain append.

        Holds _chain_lock for the entire operation:
          1. Stamp timestamp (Fix #4 — inside lock so order matches chain)
          2. Snapshot prev_hash
          3. Compute chain_hash
          4. Write to DB
          5. Update _last_hash only on SUCCESS  (Fix #2)

        If the DB write fails, _last_hash is NOT updated, so the next entry
        will retry with the same prev_hash — producing a valid continuation
        of the chain (the failed entry is simply absent from the log, which
        the verifier will flag, but subsequent entries remain consistent).
        """
        with self._chain_lock:
            # ── Fix #4: stamp timestamp inside the lock ────────────────────
            # Capturing it before run_in_executor could yield a timestamp that
            # is EARLIER than the previous chain entry's timestamp (if the
            # thread pool schedules this task after another that was submitted
            # later but ran first).  Stamping here guarantees the timestamp is
            # always >= the previous entry's timestamp, so ORDER BY timestamp
            # produces the same sequence as the chain's prev_hash linkage.
            ts = datetime.now(timezone.utc).isoformat()

            prev_hash  = self._last_hash
            chain_hash = _compute_chain_hash(
                self._secret,
                prev_hash,
                ts,
                partial["actor"],
                partial["method"],
                partial["path"],
                partial["status"],
            )

            entry = {**partial, "timestamp": ts, "prev_hash": prev_hash, "chain_hash": chain_hash}

            if _write_sync(entry):
                # ── Fix #2: update only after confirmed DB write ──────────
                self._last_hash = chain_hash
            else:
                log.warning(
                    "Audit entry dropped — _last_hash NOT advanced",
                    path=partial["path"],
                    prev_hash=prev_hash[:16],
                )


def _write_sync(entry: dict) -> bool:
    """
    Persist one audit entry to DuckDB.
    Returns True on success, False on failure.
    """
    try:
        from app.database import SessionLocal, _db_lock
        from app.models import AuditLog

        _db_lock.acquire()
        session = SessionLocal()
        try:
            record = AuditLog(
                id         = entry["id"],
                timestamp  = datetime.fromisoformat(entry["timestamp"]),
                actor      = entry["actor"],
                client_ip  = entry["client_ip"],
                method     = entry["method"],
                path       = entry["path"],
                query      = entry["query"],
                status     = entry["status"],
                elapsed_ms = entry["elapsed_ms"],
                user_agent = entry["user_agent"],
                prev_hash  = entry["prev_hash"],
                chain_hash = entry["chain_hash"],
            )
            session.add(record)
            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            log.error("Audit log write failed", error=str(exc), path=entry["path"])
            return False
        finally:
            session.close()
            _db_lock.release()
    except Exception as exc:
        log.error("Audit log DB error", error=str(exc))
        return False
