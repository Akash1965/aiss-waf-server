"""
/v1/inspect — Synchronous HTTP request inspection endpoint.

Called by Vercel Edge Middleware (and any HTTP client) to obtain a WAF verdict
before forwarding traffic to the protected application.  Returns PERMIT or BLOCK
with full telemetry — identical to what the Unix-socket agent would emit.

Inspection pipeline (Python-side "lite" engine):
  Tier 1 — CVE regex signatures loaded from DuckDB
  Tier 2 — Hardcoded SQL-injection & XSS semantic patterns
  Tier 3 — Basic anomaly heuristics (path traversal, RCE keywords, SSRF)

Fail-open: any exception → PERMIT (never block legitimate traffic due to a bug).

Compliance:
  • Singapore IM8 v5.0 §3 — Threat prevention at perimeter
  • MAS TRM 2021 §9.2 — Application-layer security controls
  • OWASP Top-10 2021 — A03 Injection, A07 Auth failures
"""

import base64
import logging
import re
import time
import uuid
import urllib.parse
from typing import Any, Dict, Optional

import threading
import time as _time

from fastapi import APIRouter, BackgroundTasks, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session  # still used by _ensure_agent_registered

from app.models import CVESignature, SecurityEvent
from app.auth import verify_api_key
import structlog

log = structlog.get_logger(__name__)
router = APIRouter()

# ── In-memory CVE signature cache ─────────────────────────────────────────────
# The inspect endpoint reads CVE signatures on every request.  Hitting DuckDB
# each time contends with the global _db_lock that the CVE-sync background task
# holds while bulk-inserting 700+ signatures — causing all inspect requests to
# block for several seconds.
#
# Solution: load signatures into a module-level list every 60 s.  The cache
# is refreshed by a daemon thread that acquires _db_lock independently, leaving
# the request threads free.  Stale cache (> 120 s) means we skip Tier 1 and
# rely on Tiers 2 & 3 (fail-open for CVE scan only, not for the whole request).

_cve_cache: list = []           # list of (compiled_regex, flags_str, sig_dict)
_cve_cache_ts: float = 0.0      # epoch seconds of last successful refresh
_cve_cache_lock = threading.Lock()
_CVE_CACHE_TTL = 60             # seconds between refreshes


def _refresh_cve_cache() -> None:
    """Load all active CVE signatures from DuckDB into the module cache."""
    global _cve_cache, _cve_cache_ts
    from app.database import SessionLocal, _db_lock

    _db_lock.acquire()
    session = SessionLocal()
    try:
        sigs = session.execute(
            select(CVESignature).where(CVESignature.active.is_(True))
        ).scalars().all()
        compiled = []
        for sig in sigs:
            re_flags = re.IGNORECASE if (sig.flags and "i" in sig.flags.lower()) else 0
            try:
                compiled.append((re.compile(sig.pattern, re_flags), sig))
            except re.error:
                pass
        with _cve_cache_lock:
            _cve_cache = compiled
            _cve_cache_ts = _time.monotonic()
        log.info("CVE cache refreshed", count=len(compiled))
    except Exception as exc:
        log.warning("CVE cache refresh failed", error=str(exc))
    finally:
        session.close()
        _db_lock.release()


def _cve_cache_daemon() -> None:
    """Background daemon thread: refresh CVE cache every _CVE_CACHE_TTL seconds."""
    # Initial delay so the server finishes startup before we hit the DB
    _time.sleep(5)
    while True:
        try:
            _refresh_cve_cache()
        except Exception as exc:
            log.warning("CVE cache daemon error", error=str(exc))
        _time.sleep(_CVE_CACHE_TTL)


# Start the cache daemon once at import time (module-level singleton)
_daemon = threading.Thread(target=_cve_cache_daemon, daemon=True, name="cve-cache-daemon")
_daemon.start()


# ── Request / Response schemas ─────────────────────────────────────────────────

class InspectRequest(BaseModel):
    """Metadata for a single inbound HTTP request to be inspected."""

    method: str          = Field(default="GET",  description="HTTP verb")
    uri: str             = Field(default="/",    description="Request path (no query string)")
    query_string: str    = Field(default="",     description="Raw query string, e.g. 'id=1&x=y'")
    client_ip: str       = Field(default="",     description="Originating client IP")
    user_agent: str      = Field(default="",     description="User-Agent header value")
    content_type: str    = Field(default="",     description="Content-Type header value")
    # Body is optional and base64-encoded (same contract as the Unix-socket agent)
    body: str            = Field(default="",     description="Base64-encoded request body (max 4 KB)")
    headers: Dict[str, str] = Field(default_factory=dict, description="Flattened request headers")
    # Optional — set by Vercel middleware to identify the origin application
    source_app: str      = Field(default="",     description="Identifier for the calling application")


class InspectVerdict(BaseModel):
    """WAF verdict for the inspected request."""

    action: str      = Field(..., description="PERMIT or BLOCK")
    tier: int        = Field(..., description="0=static, 1=CVE, 2=injection, 3=heuristic")
    cve_id: str      = ""
    rule_name: str   = ""
    reason: str      = ""
    ml_score: float  = 0.0
    latency_ms: float = 0.0
    request_id: str  = ""


# ── Hardcoded Tier-2 patterns (SQL injection, XSS) ────────────────────────────
# These run even when the CVE database is empty (zero-day protection baseline).

_SQLI_PATTERNS = [
    (re.compile(r"(?:--|\bOR\b|\bAND\b)[\s\S]*?(?:=|LIKE|BETWEEN)", re.IGNORECASE),
     "SQL-INJECT-OR-AND"),
    (re.compile(r"(?:UNION[\s\S]+SELECT|INSERT[\s\S]+INTO|DROP[\s\S]+TABLE|"
                r"UPDATE[\s\S]+SET|DELETE[\s\S]+FROM|TRUNCATE[\s\S]+TABLE)", re.IGNORECASE),
     "SQL-INJECT-DML"),
    (re.compile(r"(?:xp_cmdshell|EXEC\s*\(|EXECUTE\s*\(|sp_executesql)", re.IGNORECASE),
     "SQL-INJECT-EXEC"),
    (re.compile(r"(?:SLEEP\s*\(\s*\d+|BENCHMARK\s*\(|WAITFOR\s+DELAY)", re.IGNORECASE),
     "SQL-INJECT-TIME-BLIND"),
    (re.compile(r"(?:'[\s]*OR[\s]*'[^']*'[\s]*=[\s]*'|\"[\s]*OR[\s]*\"[^\"]*\"[\s]*=[\s]*\")", re.IGNORECASE),
     "SQL-INJECT-TAUTOLOGY"),
    # Column-enumeration via ORDER BY / GROUP BY followed by SQL comment
    (re.compile(r"(?:ORDER\s+BY|GROUP\s+BY)\s+\d+[\s]*(?:--|#|/\*|;)", re.IGNORECASE),
     "SQL-INJECT-ORDER-BY"),
    # HAVING tautology (blind / error-based)
    (re.compile(r"HAVING\s+\d+\s*=\s*\d+", re.IGNORECASE),
     "SQL-INJECT-HAVING"),
    # Quote + SQL comment — classic string-termination injection: admin'-- / foo"/*
    (re.compile(r"['\"][\s]*(?:--|#|/\*)", re.IGNORECASE),
     "SQL-INJECT-COMMENT"),
]

_XSS_PATTERNS = [
    (re.compile(r"<script[\s>]", re.IGNORECASE),            "XSS-SCRIPT-TAG"),
    (re.compile(r"javascript\s*:", re.IGNORECASE),           "XSS-JS-PROTO"),
    # vbscript: protocol (IE/Edge legacy XSS vector)
    (re.compile(r"vbscript\s*:", re.IGNORECASE),             "XSS-VBSCRIPT"),
    (re.compile(r"on(?:load|error|click|mouse\w+|focus|blur|key\w*|submit|reset|change|"
                r"drag\w*|drop|copy|cut|paste|scroll|resize|context\w*)\s*=",
                re.IGNORECASE),                              "XSS-EVENT-HANDLER"),
    (re.compile(r"<iframe[\s>]", re.IGNORECASE),             "XSS-IFRAME"),
    (re.compile(r"<img[^>]+src\s*=\s*['\"]?\s*javascript:", re.IGNORECASE), "XSS-IMG-JS"),
    (re.compile(r"expression\s*\(", re.IGNORECASE),          "XSS-CSS-EXPR"),
    (re.compile(r"&#x[0-9a-fA-F]+;|&#\d+;", re.IGNORECASE), "XSS-HTML-ENTITY"),
    # Additional dangerous HTML tags
    (re.compile(r"<(?:object|embed|applet|form|input|button|link|meta|base)[\s>]",
                re.IGNORECASE),                              "XSS-DANGEROUS-TAG"),
    # SVG-based XSS (namespace confusion)
    (re.compile(r"<svg[^>]*>", re.IGNORECASE),               "XSS-SVG"),
    # data: URI with script
    (re.compile(r"data:\s*text/html|data:\s*application/javascript",
                re.IGNORECASE),                              "XSS-DATA-URI"),
]

# ── Tier-3 heuristics ────────────────────────────────────────────────────────
# Organised by attack family.  Each entry is (compiled_regex, rule_name).

_HEURISTIC_PATTERNS = [

    # ── Path Traversal ──────────────────────────────────────────────────────
    (re.compile(r"(?:\.\.[\\/]){2,}",                        re.IGNORECASE), "PATH-TRAVERSAL"),

    # ── LFI — Sensitive Files ───────────────────────────────────────────────
    (re.compile(r"/etc/(?:passwd|shadow|group|hosts|hostname|crontab|cron\.d|"
                r"sudoers|ssh/|ssl/|nginx|apache)",           re.IGNORECASE), "LFI-SENSITIVE-FILE"),
    (re.compile(r"/proc/self",                                re.IGNORECASE), "LFI-PROC"),
    (re.compile(r"/var/(?:log|www|run|lib|spool)",            re.IGNORECASE), "LFI-VAR-PATH"),
    (re.compile(r"(?:data|expect|php|zip|phar|glob|ogg|rar)://",
                                                              re.IGNORECASE), "LFI-STREAM-WRAPPER"),
    (re.compile(r"(?:/boot/|/sys/|/dev/)",                    re.IGNORECASE), "LFI-SYS-PATH"),

    # ── RCE — Shell & Interpreter ───────────────────────────────────────────
    (re.compile(r"(?:cmd\.exe|/bin/sh|/bin/bash|/bin/zsh|powershell|pwsh)",
                                                              re.IGNORECASE), "RCE-SHELL"),
    (re.compile(r"(?:\beval\b|\bexec\b|\bsystem\b|\bpassthru\b)\s*\(",
                                                              re.IGNORECASE), "RCE-EVAL"),
    # Backtick command substitution — require a known shell command inside
    (re.compile(r"`\s*(?:cat|ls|id|whoami|wget|curl|nc|netcat|ncat|bash|sh|"
                r"python\d?|perl|ruby|php|uname|ifconfig|hostname)\b",
                                                              re.IGNORECASE), "RCE-BACKTICK"),
    # Newline followed by shell command (log-injection / command splitting)
    (re.compile(r"(?:%0[aAdD]|\n|\r)\s*(?:cat|ls|id|whoami|wget|curl|"
                r"nc|bash|sh|python|perl)\b",                re.IGNORECASE), "RCE-NEWLINE-INJECT"),
    # PHP obfuscation helpers
    (re.compile(r"(?:base64_decode|str_rot13|gzinflate|gzuncompress|"
                r"str_replace|preg_replace)\s*\(",            re.IGNORECASE), "PHP-OBFUSCATION"),
    # $() and ${} shell/template substitution with dangerous content
    (re.compile(r"\$\(\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh|python|perl)\b",
                                                              re.IGNORECASE), "RCE-SHELL-SUBST"),

    # ── SSRF — Dangerous schemes & internal addresses ───────────────────────
    (re.compile(r"file://|dict://|gopher://|ldap://|tftp://|sftp://",
                                                              re.IGNORECASE), "SSRF-SCHEME"),
    (re.compile(r"169\.254\.169\.254|metadata\.google\.internal",
                                                              re.IGNORECASE), "SSRF-IMDS"),
    # Loopback / localhost
    (re.compile(r"(?:https?://|@|//|=)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|"
                r"\[::1\]|::1)",                              re.IGNORECASE), "SSRF-LOCALHOST"),
    # RFC-1918 private subnets
    (re.compile(r"(?:https?://|@|//|=)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                r"192\.168\.\d{1,3}\.\d{1,3}|"
                r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
                                                              re.IGNORECASE), "SSRF-PRIVATE-SUBNET"),

    # ── XXE ─────────────────────────────────────────────────────────────────
    (re.compile(r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM",           re.IGNORECASE), "XXE-ENTITY"),
    # <!ENTITY without SYSTEM keyword (parameter / internal entities)
    (re.compile(r"<!ENTITY\s+[\w%]",                          re.IGNORECASE), "XXE-ENTITY-GENERIC"),

    # ── SSTI — Server-Side Template Injection ────────────────────────────────
    # Jinja2 / Twig / Django: {{ ... }}
    (re.compile(r"\{\{[\s\S]{1,200}?\}\}",                   re.IGNORECASE), "SSTI-TEMPLATE-JINJA"),
    # ERB (Ruby) / JSP: <%= ... %>
    (re.compile(r"<%=[\s\S]{1,200}?%>",                      re.IGNORECASE), "SSTI-ERB"),
    # FreeMarker / Thymeleaf: [#...] / th:...
    (re.compile(r"\[#(?:assign|list|if|include|import|attempt)\b",
                                                              re.IGNORECASE), "SSTI-FREEMARKER"),
    # Smarty: {php}...{/php}
    (re.compile(r"\{php\}",                                   re.IGNORECASE), "SSTI-SMARTY"),
    # Spring/FreeMarker/Thymeleaf: ${...}  — flag any ${} in request params.
    # Legitimate query strings do not use ${} syntax; only template engines do.
    (re.compile(r"\$\{[^}]{1,200}\}",                        re.IGNORECASE), "SSTI-SPRING"),
    # Ruby string interpolation: #{...}  — same reasoning
    (re.compile(r"#\{[^}]{1,200}\}",                         re.IGNORECASE), "SSTI-RUBY"),

    # ── NoSQL Injection ─────────────────────────────────────────────────────
    # MongoDB operator keywords in query params: user[$gt]=  /  {"$where":...}
    (re.compile(r"\$(?:gt|lt|gte|lte|ne|eq|in|nin|exists|where|regex|or|and|not|"
                r"all|size|type|mod|text|near|geoWithin|elemMatch)\b",
                                                              re.IGNORECASE), "NOSQL-OPERATOR"),
    # Bracket notation: user[$gt]=  (common in PHP/Express query parsing)
    (re.compile(r"\[\s*\$(?:gt|lt|gte|lte|ne|eq|in|nin|where|regex|or|and)\s*\]",
                                                              re.IGNORECASE), "NOSQL-PARAM-INJECT"),
    # $where with JS function body
    (re.compile(r"\$where\s*[=:]\s*['\"]?\s*function\s*\(",  re.IGNORECASE), "NOSQL-WHERE-FUNC"),

    # ── Command Injection Operators ─────────────────────────────────────────
    # || chaining — only flag when followed by a shell command
    (re.compile(r"\|\|\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh|python|perl|"
                r"uname|env|printenv|set)\b",                re.IGNORECASE), "CMD-INJECT-OR"),

    # ── CRLF Injection ──────────────────────────────────────────────────────
    # %0D%0A (raw or decoded) followed by any HTTP header name.
    # Note: use X-[\w-]+ not X-[A-Za-z] — the latter only matches one char
    # and fails on headers like X-Injected, X-Forwarded-For, etc.
    (re.compile(r"(?:%0[dD]%0[aA]|%0[aA]|\\r\\n|\r\n)\s*"
                r"(?:Set-Cookie|Location|Content-Type|Transfer-Encoding|"
                r"X-[\w-]+|WWW-Authenticate|Content-Length|Pragma)\s*:",
                re.IGNORECASE),                               "CRLF-INJECT"),
    # Bare embedded newline in a URL parameter (generic log injection)
    (re.compile(r"(?:%0[aAdD]|\n|\r)\S",                     re.IGNORECASE), "LOG-NEWLINE-INJECT"),

    # ── Sensitive Endpoint Probing (A01/A02) ─────────────────────────────────
    # Attackers probe for misconfigured / exposed management endpoints
    (re.compile(r"(?:^|/)(?:\.env|\.htpasswd|\.htaccess|web\.config|"
                r"WEB-INF/|\.git/HEAD|\.svn/entries|\.DS_Store)\b",
                re.IGNORECASE), "SENSITIVE-FILE-PROBE"),
    (re.compile(r"(?:^|/)(?:server-status|server-info|actuator/|"
                r"__debug__|_admin/|manager/html|adminer\.php|"
                r"phpmyadmin|wp-login\.php|xmlrpc\.php)\b",
                re.IGNORECASE), "ADMIN-ENDPOINT-PROBE"),

    # ── LDAP Injection (A05) ─────────────────────────────────────────────────
    (re.compile(r"\*\s*\)\s*\(|\)\s*\(\s*(?:uid|cn|mail|ou|dc|"
                r"objectClass|sAMAccountName|memberOf)\s*[=*]",
                re.IGNORECASE), "LDAP-INJECT"),
    (re.compile(r"(?:uid|cn|mail|objectClass)\s*=\s*\*\s*\)",
                re.IGNORECASE), "LDAP-WILDCARD"),
    # LDAP always-true OR filters and parenthesis injection
    (re.compile(r"\)\s*\(\s*\||\|\s*\(\s*(?:uid|cn|mail|objectClass|password)=",
                re.IGNORECASE), "LDAP-OR-INJECT"),

    # ── Struts2 / OGNL Injection (A03/A05) ───────────────────────────────────
    (re.compile(r"%\{[^}]{1,200}\}",                         re.IGNORECASE), "OGNL-INJECT"),

    # ── Deserialization Attacks (A08) ─────────────────────────────────────────
    # Java serialized object magic bytes (base64: rO0AB) or raw (0xACED 0x0005)
    (re.compile(r"rO0AB[A-Za-z0-9+/=]{4,}",                 re.IGNORECASE), "DESER-JAVA"),
    # PHP object injection: O:<len>:"<class>":<props>:{...}
    (re.compile(r'O:\d+:"[A-Za-z_]\w*":\d+:\{',             re.IGNORECASE), "DESER-PHP"),
    # Python pickle opcodes (commonly base64-encoded then wrapped)
    (re.compile(r"(?:gASV|cposix\n|cos\n|cglobal\n|creduced\n|"
                r"__reduce__|pickle\.loads)",                 re.IGNORECASE), "DESER-PYTHON"),
    # YAML deserialization !! tag
    (re.compile(r"!!\s*python/(?:object|apply|name|module|callable)",
                re.IGNORECASE), "DESER-YAML"),

    # ── Prototype Pollution / Mass Assignment (A06) ────────────────────────────
    (re.compile(r"__proto__|constructor\s*\.\s*prototype|Object\.prototype",
                re.IGNORECASE), "PROTO-POLLUTION"),
    # JSON prototype pollution via "constructor" key
    (re.compile(r'"constructor"\s*:\s*\{|"__proto__"\s*:\s*\{',
                re.IGNORECASE), "PROTO-POLLUTION-JSON"),
    # Mass assignment: privileged field injection in JSON body
    (re.compile(r'"(?:role|isAdmin|is_admin|is_superuser|admin|superuser|'
                r'permissions|privilege|elevated|root)"\s*:\s*'
                r'(?:true|"admin"|"root"|"superadmin"|"superuser"|\d{3,})',
                re.IGNORECASE), "MASS-ASSIGN-PRIVILEGE"),

    # ── JWT none-algorithm bypass (A01/A04/A07) ────────────────────────────────
    # eyJhbGciOiJub25lIn0 = base64({"alg":"none"})
    (re.compile(r"eyJhbGciOiJub25lIn0",                      re.IGNORECASE), "JWT-NONE-ALG"),

    # ── Default / Hardcoded Credentials in Authorization header (A02/A07) ──────
    # Common default creds in HTTP Basic auth (base64-encoded user:pass)
    # admin:admin, admin:password, root:root, guest:guest, admin:123456
    (re.compile(r"Basic\s+(?:YWRtaW46YWRtaW4=|YWRtaW46cGFzc3dvcmQ=|"
                r"cm9vdDpyb290|Z3Vlc3Q6Z3Vlc3Q=|YWRtaW46MTIzNDU2|"
                r"dXNlcjp1c2Vy|dGVzdDp0ZXN0)",              re.IGNORECASE), "DEFAULT-CREDS"),

    # ── AWS / Cloud Credential Exposure in URLs (A04) ─────────────────────────
    (re.compile(r"AKIA[0-9A-Z]{16}",                                0), "AWS-KEY-EXPOSED"),
    # Generic API key / secret in query params
    (re.compile(r"(?:apikey|api_key|secret|aws_secret|private_key)\s*="
                r"\s*[A-Za-z0-9/+]{20,}",                   re.IGNORECASE), "CREDENTIAL-IN-URL"),
    # Plaintext password in URL query string
    (re.compile(r"(?:^|&|\?)(?:password|passwd|pwd|pass)\s*=\s*[^&\s]{6,}",
                re.IGNORECASE),                              "PASSWORD-IN-URL"),

    # ── OS Command Injection — short commands after operators (A05/A10) ────────
    # Single pipe: cmd | id, cmd | nc, etc.
    (re.compile(r"\|\s*(?:id|ls|nc|ps|env|set|w|who|tty)\b", re.IGNORECASE), "CMD-INJECT-PIPE"),
    # Semicolon + short dangerous commands (no file path needed)
    (re.compile(r";\s*(?:id|nc|env|set|w|who|tty|uname)\b",  re.IGNORECASE), "CMD-INJECT-SHORT"),

    # ── Format String Attacks (A10) ───────────────────────────────────────────
    # Three or more consecutive printf-style format specifiers, or %n write
    (re.compile(r"(?:%[diouxXeEfFgGaAcsSp]){3,}|%n",        re.IGNORECASE), "FORMAT-STRING"),

    # ── Python format-string SSTI ({0.__class__.__mro__}) ─────────────────────
    # Legitimate requests do not use Python object attribute traversal via {}.
    # {0.__class__}, {self.__dict__}, {config.__init__} are all SSTI probes.
    (re.compile(r"\{[0-9a-zA-Z_]*\.__(?:class|dict|mro|bases|subclasses|"
                r"globals|init|import|builtins|module)\b",
                re.IGNORECASE), "SSTI-PYTHON-FORMAT"),

    # ── Java serialization magic bytes in hex form (aced0005…) ────────────────
    # Raw Java serialized streams start with 0xACED 0x0005. Attackers sometimes
    # send them hex-encoded in query params.
    (re.compile(r"\baced[0-9a-f]{4}[0-9a-f]{2,}",           re.IGNORECASE), "DESER-JAVA-HEX"),

    # ── Prototype pollution via bracket notation in query string ───────────────
    # constructor[prototype][field]=x  /  [prototype][field]=x
    (re.compile(r"constructor\[prototype\]|\[prototype\]\[", re.IGNORECASE), "PROTO-POLLUTION-CHAIN"),

    # ── Default credentials in JSON body (A02/A07) ─────────────────────────────
    # {"password":"admin"}, {"password":"root"}, {"password":"123456"}, etc.
    (re.compile(r'"password"\s*:\s*"(?:admin|root|password|123456|pass|'
                r'p@ssw0rd|letmein|welcome|guest|test|qwerty|abc123)"',
                re.IGNORECASE), "DEFAULT-CREDS-JSON"),

    # ── Null-byte injection (LDAP / file path truncation) ─────────────────────
    # %00 URL-encoded or literal null (\x00) used to terminate strings early.
    (re.compile(r"%00|\x00",                                 0),            "NULL-BYTE-INJECT"),

    # ── UTF-8 overlong path traversal (%c0%af, %c1%9c, %e0%80%af) ─────────────
    # Overlong multi-byte encodings of '/' used to bypass simple ../  filters.
    (re.compile(r"%c0%af|%c1%9c|%e0%80%af|%c0%2f|%c0%5c",  re.IGNORECASE), "PATH-TRAVERSAL-OVERLONG"),
]

# Static file extensions that are never threat-bearing — skip inspection for speed
_STATIC_EXTS = frozenset({
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
})


def _is_static(uri: str) -> bool:
    lower = uri.lower().split("?")[0]
    return any(lower.endswith(ext) for ext in _STATIC_EXTS) or lower.startswith("/_next/")


# Regex that matches strings containing ONLY valid base64 characters.
# Used by _decode_body to guard the second-pass decode: we only re-decode
# text1 if it actually looks like another base64 blob, preventing garbage
# bytes (from treating normal JSON/HTML text as base64) from producing
# spurious newlines that would trip LOG-NEWLINE-INJECT and similar patterns.
_BASE64_CONTENT_RE = re.compile(r'^[A-Za-z0-9+/=\s]{16,}$')


def _decode_body(body_b64: str) -> str:
    """
    Decode the base64-encoded body field and return a scan string.

    Also attempts a second decode pass ONLY when the decoded content itself
    looks like another base64 blob (all base64-alphabet chars, length ≥16).
    This catches attackers who double-encode payloads to evade WAF pattern
    matching (e.g., body field contains b64(b64("<script>"))), while avoiding
    a false-positive path where normal JSON bodies decoded as base64 produce
    garbage bytes with incidental newlines that match LOG-NEWLINE-INJECT.
    """
    if not body_b64:
        return ""
    try:
        raw1  = base64.b64decode(body_b64 + "==")[:4096]
        text1 = raw1.decode("utf-8", errors="replace")
        # Second-pass: only if text1 looks like a base64 string itself
        if _BASE64_CONTENT_RE.match(text1.strip()):
            try:
                raw2  = base64.b64decode(text1.strip() + "==")[:4096]
                text2 = raw2.decode("utf-8", errors="replace")
                if text2 != text1 and len(text2) > 3:
                    return f"{text1} {text2}"
            except Exception:
                pass
        return text1
    except Exception:
        return ""


def _url_decode(s: str) -> str:
    """
    URL-decode up to two levels and return all distinct forms joined by spaces.

    Single-level decode catches:   %3Cscript%3E  →  <script>
    Double-level decode catches:   ..%252F       →  ..%2F  →  ../
    Both forms are included in the scan target so pattern matching runs
    against every representation of the payload.
    """
    try:
        d1 = urllib.parse.unquote_plus(s)
        d2 = urllib.parse.unquote_plus(d1)
        parts = [s]
        if d1 != s:
            parts.append(d1)
        if d2 != d1:
            parts.append(d2)
        return " ".join(parts)
    except Exception:
        return s


def _build_scan_target(req: InspectRequest) -> str:
    """Concatenate ALL injectable surfaces into a single scan string.

    Scanning every header value (not just a named subset) ensures that
    attacks delivered via custom headers — e.g. Log4Shell in X-Api-Version,
    JWT none-alg in Authorization, default credentials in Authorization —
    are detected regardless of which header the attacker uses.
    """
    parts = [
        _url_decode(req.uri),
        _url_decode(req.query_string),
        req.user_agent,
        _decode_body(req.body),
    ]
    # Scan ALL request header values (skip the API-key header to avoid
    # false positives from random key material)
    for hname, hval in req.headers.items():
        if hname.lower() not in ("x-api-key",):
            parts.append(hval)
    return " ".join(filter(None, parts))


def _check_cve_signatures(scan_text: str) -> Optional[dict]:
    """
    Tier 1 — scan against in-memory CVE signature cache.

    Uses the module-level cache loaded by _cve_cache_daemon, so this call
    never touches DuckDB and never contends with _db_lock.  If the cache is
    empty or stale (> 120 s), Tier 1 is skipped — Tiers 2 & 3 still run.
    """
    with _cve_cache_lock:
        cache = list(_cve_cache)
        cache_age = _time.monotonic() - _cve_cache_ts

    if not cache or cache_age > 120:
        return None  # Cache not ready yet — skip Tier 1, rely on Tiers 2 & 3

    for compiled_re, sig in cache:
        try:
            if compiled_re.search(scan_text):
                return {
                    "cve_id":    sig.cve_id,
                    "rule_name": sig.name,
                    "severity":  sig.severity,
                    "reason":    f"CVE pattern match: {sig.name} ({sig.cve_id})",
                }
        except re.error:
            pass
    return None


def _check_tier2(scan_text: str) -> Optional[dict]:
    """Tier 2 — SQL injection & XSS pattern matching."""
    for pattern, rule_name in _SQLI_PATTERNS:
        if pattern.search(scan_text):
            return {
                "cve_id":    "",
                "rule_name": rule_name,
                "severity":  "HIGH",
                "reason":    f"SQL injection pattern detected: {rule_name}",
            }
    for pattern, rule_name in _XSS_PATTERNS:
        if pattern.search(scan_text):
            return {
                "cve_id":    "",
                "rule_name": rule_name,
                "severity":  "HIGH",
                "reason":    f"XSS pattern detected: {rule_name}",
            }
    return None


def _check_tier3(scan_text: str) -> Optional[dict]:
    """Tier 3 — Heuristic checks (path traversal, RCE, SSRF, XXE)."""
    for pattern, rule_name in _HEURISTIC_PATTERNS:
        if pattern.search(scan_text):
            return {
                "cve_id":    "",
                "rule_name": rule_name,
                "severity":  "MEDIUM",
                "reason":    f"Heuristic threat pattern: {rule_name}",
            }
    return None


# ── Background task: persist event ────────────────────────────────────────────

# Stable agent ID used for all events originating from the Vercel middleware.
# This ID is auto-registered in the agents table on first use.
_VERCEL_AGENT_ID = "vercel-middleware"

def _ensure_agent_registered(session, source_app: str) -> str:
    """
    Ensure a virtual agent row exists for this source app.
    Returns the agent_id to use.  Safe to call on every request — the SELECT
    is fast and the INSERT is skipped when the row already exists.
    """
    from app.models import Agent
    from datetime import datetime, timezone

    agent_id = source_app if source_app else _VERCEL_AGENT_ID
    try:
        existing = session.execute(
            select(Agent).where(Agent.id == agent_id)
        ).scalar_one_or_none()

        if existing is None:
            agent = Agent(
                id=agent_id,
                hostname=source_app or "vercel-edge",
                ip="vercel-edge",
                server_type="vercel",
                version="edge-middleware",
                mode="enforce",
                api_key_hash="vercel-middleware",
                last_seen=datetime.now(timezone.utc),
            )
            session.add(agent)
            session.flush()
            log.info("Auto-registered Vercel middleware agent", agent_id=agent_id)
        else:
            # Update last_seen
            existing.last_seen = datetime.now(timezone.utc)

    except Exception as exc:
        log.debug("Agent ensure skipped", error=str(exc))
        agent_id = _VERCEL_AGENT_ID

    return agent_id


def _persist_inspect_event(
    req: InspectRequest,
    verdict: InspectVerdict,
    api_actor: str,
) -> None:
    """
    Write the inspection result to security_events for dashboard visibility.

    Fixes vs original:
    - Acquires _db_lock before opening a session (prevents DuckDB
      'cannot start a transaction within a transaction' errors)
    - Uses source_app as agent_id and auto-registers the agent row
    - Called for ALL verdicts (PERMIT + BLOCK), not just BLOCK
    """
    from app.database import SessionLocal, _db_lock

    _db_lock.acquire()
    session = SessionLocal()
    try:
        # Resolve the agent_id (source_app > api_actor > fallback)
        source_app = req.source_app or api_actor or _VERCEL_AGENT_ID
        agent_id = _ensure_agent_registered(session, source_app)

        event = SecurityEvent(
            id=verdict.request_id,
            agent_id=agent_id,
            client_ip=req.client_ip,
            method=req.method,
            uri=req.uri,
            action=verdict.action,
            tier=verdict.tier,
            cve_id=verdict.cve_id,
            rule_name=verdict.rule_name,
            reason=verdict.reason,
            ml_score=verdict.ml_score,
            latency_ms=verdict.latency_ms,
        )
        session.add(event)
        session.commit()
    except Exception as exc:
        log.warning("inspect event persist failed", error=str(exc))
        session.rollback()
    finally:
        session.close()
        _db_lock.release()


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=InspectVerdict,
    summary="Inspect an HTTP request and return a WAF verdict",
    description=(
        "Submit request metadata and receive a PERMIT or BLOCK verdict in <100ms. "
        "Designed for Vercel Edge Middleware integration — call this before forwarding "
        "each request to your Next.js application. "
        "**Fail-open**: any internal error returns PERMIT so your site never goes dark "
        "due to a WAF glitch."
    ),
    response_description="WAF verdict with tier, matched rule, and timing information",
)
def inspect_request(
    req: InspectRequest,
    background_tasks: BackgroundTasks,
    agent_id: str = Depends(verify_api_key),
) -> InspectVerdict:
    """
    3-tier request inspection — zero DB lock contention on the hot path.
      Tier 1 → CVE regex signatures (in-memory cache, refreshed every 60 s)
      Tier 2 → SQL injection + XSS (hardcoded OWASP patterns)
      Tier 3 → RCE / SSRF / LFI / XXE heuristics
    Persistence is offloaded to a background task that acquires _db_lock
    independently, so it never delays the verdict response.
    """
    request_id = str(uuid.uuid4())
    t0 = time.perf_counter()

    try:
        # Fast-path: skip static assets (JS, CSS, images, Next.js internals)
        # Static assets are never threat-bearing — no DB query, sub-millisecond.
        if _is_static(req.uri):
            latency = (time.perf_counter() - t0) * 1000
            return InspectVerdict(
                action="PERMIT",
                tier=0,
                reason="Static asset — skipped",
                latency_ms=round(latency, 2),
                request_id=request_id,
            )

        scan_text = _build_scan_target(req)

        # ── Tier 1: CVE signatures (in-memory cache — no lock contention) ──
        match = _check_cve_signatures(scan_text)
        if match:
            latency = (time.perf_counter() - t0) * 1000
            verdict = InspectVerdict(
                action="BLOCK",
                tier=1,
                cve_id=match["cve_id"],
                rule_name=match["rule_name"],
                reason=match["reason"],
                latency_ms=round(latency, 2),
                request_id=request_id,
            )
            background_tasks.add_task(_persist_inspect_event, req, verdict, agent_id)
            log.warning(
                "BLOCK tier=1",
                cve=match["cve_id"], rule=match["rule_name"],
                ip=req.client_ip, uri=req.uri,
            )
            return verdict

        # ── Tier 2: SQL injection / XSS ───────────────────────────────────
        match = _check_tier2(scan_text)
        if match:
            latency = (time.perf_counter() - t0) * 1000
            verdict = InspectVerdict(
                action="BLOCK",
                tier=2,
                rule_name=match["rule_name"],
                reason=match["reason"],
                latency_ms=round(latency, 2),
                request_id=request_id,
            )
            background_tasks.add_task(_persist_inspect_event, req, verdict, agent_id)
            log.warning(
                "BLOCK tier=2",
                rule=match["rule_name"], ip=req.client_ip, uri=req.uri,
            )
            return verdict

        # ── Tier 3: heuristics ─────────────────────────────────────────────
        match = _check_tier3(scan_text)
        if match:
            latency = (time.perf_counter() - t0) * 1000
            verdict = InspectVerdict(
                action="BLOCK",
                tier=3,
                rule_name=match["rule_name"],
                reason=match["reason"],
                latency_ms=round(latency, 2),
                request_id=request_id,
            )
            background_tasks.add_task(_persist_inspect_event, req, verdict, agent_id)
            log.warning(
                "BLOCK tier=3",
                rule=match["rule_name"], ip=req.client_ip, uri=req.uri,
            )
            return verdict

        # ── All tiers passed: PERMIT ───────────────────────────────────────
        latency = (time.perf_counter() - t0) * 1000
        verdict = InspectVerdict(
            action="PERMIT",
            tier=0,
            reason="",
            latency_ms=round(latency, 2),
            request_id=request_id,
        )
        # Persist ALL events (PERMIT + BLOCK) so the dashboard shows real
        # forum traffic, not just attacks.
        background_tasks.add_task(_persist_inspect_event, req, verdict, agent_id)
        return verdict

    except Exception as exc:
        # Fail-open: never block traffic due to an internal WAF error
        log.error("inspect pipeline error — fail-open", error=str(exc), uri=req.uri)
        latency = (time.perf_counter() - t0) * 1000
        return InspectVerdict(
            action="PERMIT",
            tier=0,
            reason=f"fail-open: {exc}",
            latency_ms=round(latency, 2),
            request_id=request_id,
        )
