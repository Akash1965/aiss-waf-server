"""
AISS Security Headers Middleware
=================================
Injects government-standard HTTP security headers on every response.

Compliance:
  • Singapore IM8 v5.0 §3.5 — Secure Web Application Headers
  • MAS TRM 2021 §9.2 — Application Security Controls
  • CSA Cybersecurity Code of Practice for CII — §7 (Web Security)
  • OWASP Secure Headers Project
  • NIST SP 800-44 v2 — Web Server Security Guidelines
  • Japan METI Cybersecurity Action Programme §3 (Secure Coding)
  • Korea K-ISMS Annex A §14 (System Acquisition / Development)
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add government-standard security headers to every HTTP response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # ── Strict Transport Security (IM8 §3.5, MAS TRM §9.3.2) ────────────
        # 2-year max-age with subDomains + preload list eligibility
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )

        # ── Clickjacking Prevention (OWASP, IM8 §3.5) ─────────────────────
        response.headers["X-Frame-Options"] = "DENY"

        # ── MIME-type sniffing (IM8 §3.5) ─────────────────────────────────
        response.headers["X-Content-Type-Options"] = "nosniff"

        # ── XSS Filter (legacy browsers) ──────────────────────────────────
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # ── Referrer Policy (PDPA §24 — data minimisation) ────────────────
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # ── Permissions Policy (feature policy) ───────────────────────────
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), "
            "usb=(), interest-cohort=()"
        )

        # ── Content Security Policy (CSP) ─────────────────────────────────
        # Permits self + FastAPI Swagger UI inline scripts
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net fonts.googleapis.com; "
            "font-src 'self' fonts.gstatic.com; "
            "img-src 'self' data: fastapi.tiangolo.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

        # ── Cache-Control for API responses ───────────────────────────────
        # Prevent sensitive API responses from being cached by intermediaries
        if request.url.path.startswith("/v1/"):
            response.headers["Cache-Control"] = (
                "no-store, no-cache, must-revalidate, max-age=0"
            )
            response.headers["Pragma"] = "no-cache"

        # ── Remove server version disclosure ──────────────────────────────
        response.headers["Server"] = "AISS-Gateway"

        # ── Cross-Origin Resource Policy ──────────────────────────────────
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

        # ── X-Request-ID for traceability (MAS TRM §9.4 — audit trail) ───
        import uuid
        if "x-request-id" not in request.headers:
            response.headers["X-Request-ID"] = str(uuid.uuid4())
        else:
            response.headers["X-Request-ID"] = request.headers["x-request-id"]

        return response
