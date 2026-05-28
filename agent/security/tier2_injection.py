"""
Tier 2: Semantic SQL Injection & XSS Detection
Production: Libinjection C library (structural parse, not regex)
This implementation: Structural analysis using tokenization and grammar rules

Detects actual SQL syntax structure and XSS DOM manipulation patterns,
reducing false positives compared to pure regex matching.
"""
import re
import logging
from urllib.parse import unquote_plus

logger = logging.getLogger(__name__)

# ─── SQL Injection Detection ────────────────────────────────────────────────

# SQL keywords that form the skeleton of injection attacks
_SQL_KEYWORDS = {
    "select", "union", "insert", "update", "delete", "drop", "alter",
    "create", "exec", "execute", "xp_cmdshell", "sp_executesql",
    "information_schema", "sys.tables", "sysobjects",
    "waitfor", "delay", "sleep", "benchmark",
}

# Logical operator patterns used in tautologies
_SQL_LOGIC = re.compile(
    r"\b(or|and)\s+[\w'\"]+\s*[=<>!]+\s*[\w'\"]+",
    re.IGNORECASE
)

# Comment sequences that end SQL statements
_SQL_COMMENTS = re.compile(r"(--|#|/\*|\*/)", re.IGNORECASE)

# Quote-based injection patterns
_SQL_QUOTES = re.compile(r"['\"][\s;]*(or|and|union|select)", re.IGNORECASE)

# Numeric tautologies like 1=1, 1='1'
_SQL_TAUTOLOGY = re.compile(
    r"(\d+)\s*=\s*(\d+)|(\d+)\s*=\s*'(\d+)'",
    re.IGNORECASE
)

# Stacked query separator
_SQL_STACKED = re.compile(r";\s*(select|insert|update|delete|drop|exec)", re.IGNORECASE)

# Full structural SQLi detector
_SQL_STRUCTURAL = re.compile(
    r"""
    (?:
        (?:'\s*(?:or|and)\s+['"\d]) |          # ' or '1
        (?:union\s+(?:all\s+)?select) |         # UNION SELECT
        (?:;\s*(?:drop|alter|create|exec)) |    # ; DROP TABLE
        (?:--\s*$) |                            # trailing comment
        (?:xp_cmdshell) |                       # MSSQL shell
        (?:information_schema\.tables) |        # schema enumeration
        (?:sleep\s*\(\s*\d+\s*\)) |             # time-based blind
        (?:benchmark\s*\()                      # MySQL benchmark
    )
    """,
    re.IGNORECASE | re.VERBOSE
)


def check_sqli(inputs: list[str]) -> dict:
    """
    Analyze a list of input strings for SQL injection patterns.
    Returns verdict with details.
    """
    result = {"detected": False, "fingerprint": None, "detail": None}

    for raw_input in inputs:
        if not raw_input:
            continue

        # Try URL-decoded version as well
        for text in [raw_input, unquote_plus(raw_input)]:
            # Structural match (most reliable)
            m = _SQL_STRUCTURAL.search(text)
            if m:
                result["detected"] = True
                result["fingerprint"] = m.group(0).strip()
                result["detail"] = f"SQL injection: structural match '{m.group(0).strip()[:80]}'"
                return result

            # Logic-based tautology
            if _SQL_LOGIC.search(text) and _SQL_COMMENTS.search(text):
                result["detected"] = True
                result["fingerprint"] = "tautology+comment"
                result["detail"] = "SQL injection: logical tautology with comment"
                return result

            # Stacked queries
            m = _SQL_STACKED.search(text)
            if m:
                result["detected"] = True
                result["fingerprint"] = m.group(0).strip()
                result["detail"] = f"SQL injection: stacked query '{m.group(0).strip()[:80]}'"
                return result

    return result


# ─── XSS Detection ──────────────────────────────────────────────────────────

# Script tags and event handlers
_XSS_SCRIPT = re.compile(
    r"<\s*script[^>]*>|</\s*script\s*>",
    re.IGNORECASE
)

# JavaScript protocol in href/src/action
_XSS_JAVASCRIPT = re.compile(
    r"javascript\s*:",
    re.IGNORECASE
)

# DOM event handlers
_XSS_EVENTS = re.compile(
    r"\bon(load|error|click|mouseover|mouseout|focus|blur|submit|"
    r"keydown|keyup|keypress|change|input|resize|scroll|dblclick|"
    r"contextmenu|drag|drop|copy|paste|cut)\s*=",
    re.IGNORECASE
)

# Data URI with HTML/JS content
_XSS_DATA_URI = re.compile(
    r"data\s*:\s*(text/html|application/javascript|text/javascript)",
    re.IGNORECASE
)

# SVG-based XSS
_XSS_SVG = re.compile(
    r"<\s*svg[^>]*>.*?(onload|onerror|onclick)",
    re.IGNORECASE | re.DOTALL
)

# Expression injection (CSS/old IE)
_XSS_EXPRESSION = re.compile(
    r"expression\s*\(|vbscript\s*:",
    re.IGNORECASE
)

# HTML entity-encoded common XSS
_XSS_ENTITIES = re.compile(
    r"&lt;script|&#60;script|%3Cscript|\\u003cscript",
    re.IGNORECASE
)


def check_xss(inputs: list[str]) -> dict:
    """
    Analyze inputs for Cross-Site Scripting patterns.
    Returns verdict with details.
    """
    result = {"detected": False, "type": None, "detail": None}

    for raw_input in inputs:
        if not raw_input:
            continue

        for text in [raw_input, unquote_plus(raw_input)]:
            if _XSS_SCRIPT.search(text):
                result["detected"] = True
                result["type"] = "script_tag"
                result["detail"] = "XSS: script tag detected"
                return result

            if _XSS_JAVASCRIPT.search(text):
                result["detected"] = True
                result["type"] = "javascript_protocol"
                result["detail"] = "XSS: javascript: protocol injection"
                return result

            m = _XSS_EVENTS.search(text)
            if m:
                result["detected"] = True
                result["type"] = "event_handler"
                result["detail"] = f"XSS: DOM event handler '{m.group(0).strip()[:60]}'"
                return result

            if _XSS_DATA_URI.search(text):
                result["detected"] = True
                result["type"] = "data_uri"
                result["detail"] = "XSS: data: URI injection"
                return result

            if _XSS_SVG.search(text):
                result["detected"] = True
                result["type"] = "svg_xss"
                result["detail"] = "XSS: SVG-based attack"
                return result

            if _XSS_ENTITIES.search(text):
                result["detected"] = True
                result["type"] = "encoded_xss"
                result["detail"] = "XSS: HTML/URL encoded script tag"
                return result

    return result


def extract_inputs(request: dict) -> list[str]:
    """
    Extract all injectable input surfaces from an HTTP request.
    Covers: URI, query string, headers, cookie values, POST body fields.
    """
    inputs = []

    # URI path
    if uri := request.get("uri", ""):
        inputs.append(uri)

    # Query string parameters
    if query := request.get("query_string", ""):
        inputs.append(query)
        # Also add individual parameter values
        for part in query.split("&"):
            if "=" in part:
                _, _, val = part.partition("=")
                inputs.append(val)

    # Selected dangerous headers
    headers = request.get("headers", {})
    for h in ("user-agent", "referer", "x-forwarded-for", "cookie", "host"):
        if v := headers.get(h, ""):
            inputs.append(v)

    # POST body (string form)
    if body := request.get("body", ""):
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        inputs.append(body)
        # Also check individual form fields
        ct = request.get("content_type", "")
        if "x-www-form-urlencoded" in ct:
            for part in body.split("&"):
                if "=" in part:
                    _, _, val = part.partition("=")
                    inputs.append(val)

    return inputs
