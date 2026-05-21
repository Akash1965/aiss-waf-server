"""
AISS Rate Limiting Middleware
==============================
Per-IP sliding-window rate limiter to prevent brute-force and DoS attacks.

Compliance:
  • Singapore IM8 v5.0 §4.3 — DoS Protection
  • MAS TRM 2021 §9.2.4 — Availability Controls
  • CSA Cybersecurity Code of Practice for CII — §8 (Resilience)
  • NIST SP 800-44 v2 §6.3 — Rate Limiting
  • Korea K-ISMS Annex A §17 (Business Continuity)

Tiers:
  • Global API:    300 req/min per IP (configurable via AISS_RATE_LIMIT_PER_MINUTE)
  • Auth paths:     10 req/min per IP (login, key issuance — brute-force prevention)
  • Telemetry:    1200 req/min per IP (agent batch POSTs are high frequency)
"""

import time
from collections import defaultdict, deque
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
import structlog

log = structlog.get_logger(__name__)

# Paths with tighter rate limits
AUTH_PATHS     = {"/v1/auth", "/v1/agents/register"}
TELEMETRY_PATH = "/v1/telemetry"


class SlidingWindowRateLimiter:
    """Thread-safe per-IP sliding-window counter."""

    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit   = limit
        self.window  = window_seconds
        self._store: dict[str, deque] = defaultdict(deque)
        self._lock   = Lock()

    def is_allowed(self, key: str) -> tuple[bool, int]:
        """Returns (allowed, requests_remaining)."""
        now = time.monotonic()
        cutoff = now - self.window

        with self._lock:
            dq = self._store[key]
            # Evict stale timestamps
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= self.limit:
                return False, 0

            dq.append(now)
            remaining = max(0, self.limit - len(dq))
            return True, remaining


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Apply tiered rate limiting based on path and IP."""

    def __init__(self, app, requests_per_minute: int = 300):
        super().__init__(app)
        self.global_limiter   = SlidingWindowRateLimiter(requests_per_minute)
        self.auth_limiter     = SlidingWindowRateLimiter(10)        # 10/min for auth
        self.telemetry_limiter = SlidingWindowRateLimiter(1200)     # 1200/min for agents

    async def dispatch(self, request: Request, call_next) -> JSONResponse:
        client_ip = (
            request.headers.get("x-real-ip")
            or request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or request.client.host
            or "unknown"
        )
        path = request.url.path

        # Choose the correct rate limiter for this path
        if any(path.startswith(p) for p in AUTH_PATHS):
            limiter = self.auth_limiter
            limit_type = "auth"
        elif path.startswith(TELEMETRY_PATH):
            limiter = self.telemetry_limiter
            limit_type = "telemetry"
        else:
            limiter = self.global_limiter
            limit_type = "global"

        allowed, remaining = limiter.is_allowed(client_ip)

        if not allowed:
            log.warning(
                "Rate limit exceeded",
                client_ip=client_ip,
                path=path,
                limit_type=limit_type,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please slow down.",
                    "type":   limit_type,
                    "retry_after_seconds": 60,
                },
                headers={
                    "Retry-After":           "60",
                    "X-RateLimit-Limit":     str(limiter.limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset":     str(int(time.time()) + 60),
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"]     = str(limiter.limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
