"""
AISS WAF Proxy
==============
Reverse proxy that consults the AISS Unix Domain Socket before forwarding
every HTTP request to the backend (dummy-server).

Flow:
  1. Receive request
  2. Send JSON to /tmp/aiss.sock  →  get PERMIT or BLOCK verdict
  3. BLOCK  → return 403 HTML block page
  4. PERMIT → proxy to backend, also POST telemetry to aiss-server
"""

import asyncio
import base64
import json
import logging
import os
import socket as _socket
import ssl
import urllib.parse
import uuid

import aiohttp
from aiohttp import web

AISS_SOCKET  = os.getenv("AISS_SOCKET_PATH", "/tmp/aiss.sock")
BACKEND_URL  = os.getenv("BACKEND_URL",       "http://dummy-server:5000")
AISS_SERVER  = os.getenv("AISS_SERVER_URL",   "http://aiss-server:8080")
API_KEY      = os.getenv("AISS_API_KEY",      "dev-key")
AGENT_ID     = os.getenv("AISS_AGENT_ID",     "waf-proxy-demo")
PORT         = int(os.getenv("PORT",          "8888"))

# Derive the backend host for the Host header (e.g. "nit-mca-forum.vercel.app")
_parsed_backend = urllib.parse.urlparse(BACKEND_URL)
BACKEND_HOST    = _parsed_backend.netloc  # e.g. nit-mca-forum.vercel.app
BACKEND_SCHEME  = _parsed_backend.scheme  # http or https

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("waf-proxy")

BLOCK_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>403 — Blocked by AISS WAF</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
      background:#0d1117;color:#e6edf3;display:flex;align-items:center;
      justify-content:center;min-height:100vh}}
.box{{text-align:center;max-width:540px;padding:48px;background:#161b22;
      border:1px solid #30363d;border-radius:16px;border-top:4px solid #f85149}}
.icon{{font-size:48px;margin-bottom:20px}}
h1{{font-size:28px;color:#f85149;margin-bottom:6px}}
.sub{{font-size:13px;color:#8b949e;margin-bottom:28px}}
.reason{{font-family:monospace;font-size:13px;background:#0d1117;
          border:1px solid #30363d;padding:14px 16px;border-radius:8px;
          color:#e6edf3;text-align:left;word-break:break-all;margin-bottom:20px}}
.meta{{font-size:12px;color:#8b949e;line-height:1.8}}
.badge{{display:inline-block;padding:5px 14px;
        background:rgba(248,81,73,.15);color:#f85149;
        border:1px solid rgba(248,81,73,.3);border-radius:20px;
        font-size:12px;font-weight:700;margin-top:24px}}
strong{{color:#e6edf3}}
</style>
</head>
<body><div class="box">
  <div class="icon">🛡</div>
  <h1>Request Blocked</h1>
  <div class="sub">HTTP 403 — AISS AI Security Shield</div>
  <div class="reason">{reason}</div>
  <div class="meta">
    Tier: <strong>{tier}</strong> &nbsp;·&nbsp;
    CVE: <strong>{cve_id}</strong> &nbsp;·&nbsp;
    ML Score: <strong>{ml_score:.3f}</strong> &nbsp;·&nbsp;
    Latency: <strong>{latency_ms:.1f} ms</strong>
  </div>
  <div class="badge">⚠ Blocked by AISS WAF</div>
</div></body>
</html>"""


def _consult_aiss(req_data: dict) -> dict:
    """Synchronously send JSON to the AISS Unix socket and return the verdict."""
    try:
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(AISS_SOCKET)

        payload = json.dumps(req_data).encode() + b"\n"
        sock.sendall(payload)

        buf = b""
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf:
                break
        sock.close()
        return json.loads(buf.strip())
    except Exception as exc:
        log.warning("AISS socket error — fail-open: %s", exc)
        return {
            "action": "PERMIT",
            "reason": f"fail-open: {exc}",
            "tier": 0,
            "ml_score": 0.0,
            "latency_ms": 0.0,
        }


async def _register_agent() -> None:
    """Register this WAF proxy as an agent with the AISS server on startup."""
    import socket as _s
    hostname = _s.gethostname()
    payload = {
        "agent_id":    AGENT_ID,
        "hostname":    hostname,
        "ip":          "waf-proxy",
        "server_type": "nginx",
        "version":     "1.0.0",
        "api_key":     API_KEY,
    }
    for attempt in range(10):
        try:
            async with aiohttp.ClientSession() as s:
                resp = await s.post(
                    f"{AISS_SERVER}/v1/agents/register",
                    json=payload,
                    headers={"X-API-Key": API_KEY},
                    timeout=aiohttp.ClientTimeout(total=5),
                )
                if resp.status in (201, 409):   # 409 = already registered, that's fine
                    log.info("Agent registered with AISS server (status=%d)", resp.status)
                    return
        except Exception as exc:
            log.warning("Agent registration attempt %d failed: %s", attempt + 1, exc)
        await asyncio.sleep(3)


async def _heartbeat_loop() -> None:
    """Send a heartbeat to update last_seen every 30 s."""
    while True:
        try:
            async with aiohttp.ClientSession() as s:
                await s.post(
                    f"{AISS_SERVER}/v1/agents/{AGENT_ID}/heartbeat",
                    headers={"X-API-Key": API_KEY},
                    timeout=aiohttp.ClientTimeout(total=3),
                )
        except Exception:
            pass
        await asyncio.sleep(30)


async def _send_telemetry(server_url: str, api_key: str, event: dict) -> None:
    """Fire-and-forget telemetry POST to the AISS central server."""
    try:
        async with aiohttp.ClientSession() as s:
            await s.post(
                f"{server_url}/v1/telemetry",
                json={"events": [event]},
                headers={"X-API-Key": api_key},
                timeout=aiohttp.ClientTimeout(total=2),
            )
    except Exception:
        pass


async def health(request: web.Request) -> web.Response:
    """Liveness probe — Docker healthcheck hits this directly (no AISS socket)."""
    return web.Response(
        status=200,
        content_type="application/json",
        text='{"status":"ok","service":"waf-proxy"}',
    )


async def handle(request: web.Request) -> web.Response:
    body = await request.read()

    headers_lower = {k.lower(): v for k, v in request.headers.items()}
    client_ip = request.headers.get("X-Real-IP", request.remote or "0.0.0.0")

    req_data = {
        "request_id":   str(uuid.uuid4()),
        "client_ip":    client_ip,
        "method":       request.method,
        "uri":          request.path,
        "query_string": request.query_string,
        "content_type": request.content_type or "",
        "content_length": len(body),
        "headers":      headers_lower,
        "body":         base64.b64encode(body[:4096]).decode() if body else "",
        "user_agent":   request.headers.get("User-Agent", ""),
        "server_type":  "nginx",
    }

    # Consult AISS agent in a thread pool (socket I/O is blocking)
    loop = asyncio.get_event_loop()
    verdict = await loop.run_in_executor(None, _consult_aiss, req_data)

    action     = verdict.get("action", "PERMIT")
    reason     = verdict.get("reason", "")
    tier       = int(verdict.get("tier", 0))
    cve_id     = verdict.get("cve_id", "") or ""
    rule_name  = verdict.get("rule_name", "") or ""
    ml_score   = float(verdict.get("ml_score", 0.0))
    latency_ms = float(verdict.get("latency_ms", 0.0))

    log.info(
        "%s  %-6s %-40s  tier=%d  cve=%-20s  %.1fms",
        action, request.method, request.path[:40], tier, cve_id or "-", latency_ms,
    )

    # Send telemetry asynchronously (non-blocking)
    event = {
        "id":         req_data["request_id"],
        "client_ip":  client_ip,
        "method":     request.method,
        "uri":        request.path,
        "action":     action,
        "tier":       tier,
        "cve_id":     cve_id,
        "rule_name":  rule_name,
        "reason":     reason,
        "ml_score":   ml_score,
        "latency_ms": latency_ms,
    }
    asyncio.ensure_future(_send_telemetry(AISS_SERVER, API_KEY, event))

    if action == "BLOCK":
        return web.Response(
            status=403,
            content_type="text/html",
            text=BLOCK_HTML.format(
                reason=reason,
                tier=tier,
                cve_id=cve_id or "N/A",
                ml_score=ml_score,
                latency_ms=latency_ms,
            ),
        )

    # PERMIT — proxy to backend
    target_url = BACKEND_URL.rstrip("/") + str(request.rel_url)

    # Build proxy headers: strip hop-by-hop headers, set correct Host for the backend
    SKIP_HEADERS = {"host", "transfer-encoding", "connection", "keep-alive",
                    "proxy-authenticate", "proxy-authorization", "te", "trailers", "upgrade"}
    proxy_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in SKIP_HEADERS
    }
    # Must set Host to the backend's hostname (critical for Vercel/CDN routing)
    if BACKEND_HOST:
        proxy_headers["Host"] = BACKEND_HOST
    proxy_headers["X-Real-IP"]           = client_ip
    proxy_headers["X-Forwarded-For"]     = client_ip
    proxy_headers["X-Forwarded-Proto"]   = "https" if BACKEND_SCHEME == "https" else "http"
    proxy_headers["X-WAF-Verdict"]       = "PERMIT"

    # SSL connector — verify certs for HTTPS backends
    connector = aiohttp.TCPConnector(ssl=ssl.create_default_context()) \
                if BACKEND_SCHEME == "https" else aiohttp.TCPConnector()

    try:
        async with aiohttp.ClientSession(connector=connector) as s:
            async with s.request(
                request.method,
                target_url,
                headers=proxy_headers,
                data=body,
                allow_redirects=True,   # follow Vercel redirects (www → non-www etc.)
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                content = await resp.read()
                resp_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() not in ("transfer-encoding", "content-encoding",
                                         "connection", "strict-transport-security")
                }
                return web.Response(
                    status=resp.status,
                    headers=resp_headers,
                    body=content,
                )
    except aiohttp.ClientConnectorError as exc:
        log.error("Backend unreachable: %s", exc)
        return web.Response(status=502, text=f"Backend unreachable: {exc}")
    except Exception as exc:
        log.error("Proxy error: %s", exc)
        return web.Response(status=502, text=f"Proxy error: {exc}")


async def on_startup(app_: web.Application) -> None:
    """Run once when the server starts — register agent and kick off heartbeat."""
    asyncio.ensure_future(_register_agent())
    asyncio.ensure_future(_heartbeat_loop())


app = web.Application()
app.on_startup.append(on_startup)
# /health is handled directly — never proxied to backend or checked by AISS
app.router.add_get("/health", health)
app.router.add_route("*", "/{path_info:.*}", handle)

if __name__ == "__main__":
    log.info("WAF Proxy starting on :%d  backend=%s", PORT, BACKEND_URL)
    web.run_app(app, host="0.0.0.0", port=PORT, access_log=None)
