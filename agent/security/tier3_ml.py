"""
Tier 3: ML Anomaly Detection
Production: ONNX Runtime (C++ bindings, pre-trained Random Forest/CNN model)
This implementation: Heuristic scoring model with weighted feature analysis

Catches zero-day threats and behavioral anomalies that signature-based
methods miss. Outputs a score from 0.0 (clean) to 1.0 (malicious).
Requests scoring >= BLOCK_THRESHOLD are blocked.
"""
import re
import math
import logging
from urllib.parse import unquote_plus

logger = logging.getLogger(__name__)

BLOCK_THRESHOLD = 0.85
SUSPICIOUS_THRESHOLD = 0.60


class MLAnomalyScorer:
    """
    Heuristic anomaly scoring engine.
    Production: swap this class with ONNX Runtime inference session.
    """

    def __init__(self, threshold: float = BLOCK_THRESHOLD):
        self.threshold = threshold
        logger.info(f"ML anomaly scorer initialized (threshold={threshold})")

    def extract_features(self, request: dict) -> dict:
        """Extract numerical features from an HTTP request."""
        uri = request.get("uri", "")
        query = request.get("query_string", "")
        headers = request.get("headers", {})
        body = request.get("body", b"")
        method = request.get("method", "GET").upper()
        content_type = request.get("content_type", "")

        if isinstance(body, bytes):
            body_str = body.decode("utf-8", errors="replace")
        else:
            body_str = body or ""

        ua = headers.get("user-agent", "")
        full_request = f"{uri} {query} {body_str}"

        return {
            # Request structure
            "method_encoded": _encode_method(method),
            "uri_length": len(uri),
            "query_length": len(query),
            "header_count": len(headers),
            "body_length": len(body_str),

            # Anomaly indicators
            "uri_entropy": _shannon_entropy(uri),
            "query_entropy": _shannon_entropy(query),
            "body_entropy": _shannon_entropy(body_str),
            "special_char_ratio": _special_char_ratio(full_request),
            "encoded_char_count": full_request.count("%"),
            "double_encoded": 1 if "%25" in full_request else 0,
            "null_bytes": 1 if ("\x00" in full_request or "%00" in full_request) else 0,
            "unicode_escape": 1 if re.search(r"\\u[0-9a-fA-F]{4}", full_request) else 0,

            # Content analysis
            "has_base64_body": _has_base64_indicator(body_str),
            "has_json_body": 1 if "application/json" in content_type else 0,
            "param_count": full_request.count("="),
            "excessive_params": 1 if full_request.count("=") > 20 else 0,

            # User-agent anomalies
            "ua_length": len(ua),
            "ua_has_scanner": _is_scanner_ua(ua),
            "ua_empty": 1 if not ua else 0,
            "ua_suspicious": _is_suspicious_ua(ua),

            # Header anomalies
            "unusual_method": 1 if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS") else 0,
            "has_x_forwarded": 1 if "x-forwarded-for" in headers else 0,
            "has_proxy_headers": _has_proxy_headers(headers),
        }

    def score(self, request: dict) -> dict:
        """
        Compute anomaly score for a request.
        Returns:
            {
                "score": float,       # 0.0 = clean, 1.0 = malicious
                "action": str,        # "PERMIT" | "BLOCK" | "SUSPICIOUS"
                "features": dict,     # extracted features
                "reason": str,        # human-readable explanation
            }
        """
        features = self.extract_features(request)
        score, reasons = _compute_score(features)

        if score >= self.threshold:
            action = "BLOCK"
        elif score >= SUSPICIOUS_THRESHOLD:
            action = "SUSPICIOUS"
        else:
            action = "PERMIT"

        reason = "; ".join(reasons) if reasons else "No anomalies detected"

        return {
            "score": round(score, 4),
            "action": action,
            "features": features,
            "reason": reason,
        }


# ─── Scoring Logic ────────────────────────────────────────────────────────

def _compute_score(f: dict) -> tuple[float, list[str]]:
    """
    Weighted heuristic scoring.
    Each factor contributes a partial score; total is clamped to [0, 1].
    """
    total = 0.0
    reasons = []

    # Null bytes — almost always malicious in web requests
    if f["null_bytes"]:
        total += 0.7
        reasons.append("null bytes in request")

    # Double URL encoding — bypass attempt
    if f["double_encoded"]:
        total += 0.5
        reasons.append("double URL encoding detected")

    # Excessive URL encoding
    if f["encoded_char_count"] > 30:
        total += 0.25
        reasons.append(f"excessive URL encoding ({f['encoded_char_count']} encoded chars)")

    # Very long URI (path traversal or buffer overflow attempt)
    if f["uri_length"] > 2000:
        total += 0.4
        reasons.append(f"suspicious URI length ({f['uri_length']} chars)")
    elif f["uri_length"] > 1000:
        total += 0.2

    # High entropy query string (obfuscated payload)
    if f["query_entropy"] > 4.5:
        total += 0.3
        reasons.append(f"high query string entropy ({f['query_entropy']:.2f})")

    # High entropy body
    if f["body_entropy"] > 5.5 and f["body_length"] > 100:
        total += 0.25
        reasons.append(f"high body entropy ({f['body_entropy']:.2f})")

    # Known scanner user-agents
    if f["ua_has_scanner"]:
        total += 0.35
        reasons.append("known security scanner user-agent")

    # Suspicious user-agent
    if f["ua_suspicious"]:
        total += 0.4
        reasons.append("suspicious user-agent pattern")

    # Empty user-agent (many bots)
    if f["ua_empty"]:
        total += 0.15
        reasons.append("empty user-agent")

    # Unusual HTTP method
    if f["unusual_method"]:
        total += 0.2
        reasons.append(f"unusual HTTP method")

    # Base64 body content
    if f["has_base64_body"]:
        total += 0.2
        reasons.append("Base64-encoded content in body")

    # Excessive parameters
    if f["excessive_params"]:
        total += 0.2
        reasons.append(f"excessive parameter count ({f['param_count']})")

    # High special character ratio (likely injection attempt)
    if f["special_char_ratio"] > 0.15:
        total += 0.3
        reasons.append(f"high special character ratio ({f['special_char_ratio']:.2f})")

    # Proxy/anonymizer headers combined with suspicious activity
    if f["has_proxy_headers"] and total > 0.2:
        total += 0.1
        reasons.append("proxy headers with suspicious activity")

    # Unicode escape sequences
    if f["unicode_escape"]:
        total += 0.2
        reasons.append("unicode escape sequences in request")

    return min(total, 1.0), reasons


# ─── Feature Helpers ─────────────────────────────────────────────────────

def _encode_method(method: str) -> int:
    methods = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3,
               "PATCH": 4, "HEAD": 5, "OPTIONS": 6}
    return methods.get(method, 7)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    from collections import Counter
    counts = Counter(text)
    total = len(text)
    entropy = 0.0
    for c in counts.values():
        p = c / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _special_char_ratio(text: str) -> float:
    if not text:
        return 0.0
    special = sum(1 for c in text if c in "!@#$%^&*(){}[]|\\<>/?;:'\"")
    return round(special / len(text), 4)


def _has_base64_indicator(body: str) -> int:
    b64_re = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    return 1 if b64_re.search(body) else 0


_SCANNER_UA = re.compile(
    r"(?i)(nmap|nikto|sqlmap|masscan|zgrab|gobuster|dirbuster|wfuzz|"
    r"burpsuite|owasp|acunetix|nessus|openvas|w3af|skipfish|havij|"
    r"hydra|medusa|metasploit|curl/[0-9]+|python-requests|go-http-client|"
    r"libwww|wget|scrapy|mechanize|phantomjs|headlesschrome)"
)

_SUSPICIOUS_UA = re.compile(
    r"(?i)(\.\./|<script|select\s+from|union\s+select|eval\(|base64_decode)"
)


def _is_scanner_ua(ua: str) -> int:
    return 1 if _SCANNER_UA.search(ua) else 0


def _is_suspicious_ua(ua: str) -> int:
    return 1 if _SUSPICIOUS_UA.search(ua) else 0


def _has_proxy_headers(headers: dict) -> int:
    proxy_headers = {
        "via", "forwarded", "x-real-ip",
        "x-originating-ip", "x-cluster-client-ip"
    }
    return 1 if any(h in headers for h in proxy_headers) else 0
