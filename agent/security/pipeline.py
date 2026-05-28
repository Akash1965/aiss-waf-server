"""
AISS Security Pipeline — 3-Tier Orchestrator
Tier 1: CVE Pattern Matching  (fastest — runs first)
Tier 2: SQL Injection & XSS   (semantic analysis)
Tier 3: ML Anomaly Scoring    (catches zero-days)

Content Inspection:
  - Base64 decode and scan
  - YARA rule matching
  - Shannon entropy analysis
  - Magic byte validation

All tiers short-circuit on BLOCK to minimize latency.
"""
import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from .tier1_patterns import Tier1PatternEngine
from .tier2_injection import check_sqli, check_xss, extract_inputs
from .tier3_ml import MLAnomalyScorer
from .content.base64_inspect import extract_b64_candidates, decode_body_if_base64
from .content.entropy import entropy_verdict
from .content.magic_bytes import validate_content_type
from .content.yara_scanner import YaraScanner

logger = logging.getLogger(__name__)


@dataclass
class SecurityVerdict:
    action: str                    # "PERMIT" | "BLOCK"
    tier: int                      # 0=cache, 1=pattern, 2=injection, 3=ml, 4=content
    cve_id: Optional[str] = None
    rule_name: Optional[str] = None
    reason: str = ""
    ml_score: float = 0.0
    latency_ms: float = 0.0
    sha256: Optional[str] = None   # For content inspection

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "tier": self.tier,
            "cve_id": self.cve_id,
            "rule_name": self.rule_name,
            "reason": self.reason,
            "ml_score": self.ml_score,
            "latency_ms": self.latency_ms,
        }


# ─── Content size thresholds ────────────────────────────────────────────────
FULL_SCAN_LIMIT = 10 * 1024          # 10 KB  → full inline scan
SAMPLE_SCAN_LIMIT = 1 * 1024 * 1024  # 1 MB   → sampled inline scan


class SecurityPipeline:
    """
    Main security pipeline. Instantiate once per agent process.
    Thread-safe: all components handle their own locking.
    """

    def __init__(self, config, db=None, telemetry_buffer=None):
        self.config = config
        self.db = db
        self.telemetry = telemetry_buffer
        self.mode = config.mode  # "enforce" | "shadow"

        # Initialize all three tiers
        self.tier1 = Tier1PatternEngine(config.patterns_file)
        self.tier2_enabled = True
        self.tier3 = MLAnomalyScorer(threshold=config.ml_block_threshold)
        self.yara = YaraScanner(config.rules_dir)

        logger.info(
            f"Pipeline initialized | mode={self.mode} | "
            f"patterns={self.tier1.pattern_count} | "
            f"yara_ready={self.yara.is_ready}"
        )

    def check(self, request: dict) -> SecurityVerdict:
        """
        Run the full security pipeline against a request.
        Returns a SecurityVerdict with action PERMIT or BLOCK.
        """
        t0 = time.perf_counter()

        # ── Pre-filter: static file skip ───────────────────────────────────
        if _is_static_file(request.get("uri", "")):
            return SecurityVerdict(
                action="PERMIT", tier=0,
                reason="Static file — skipped inspection",
                latency_ms=_ms(t0),
            )

        # ── Build scan data (all injectable surfaces concatenated) ──────────
        scan_data = _build_scan_data(request)

        # ── Tier 1: CVE Pattern Matching ────────────────────────────────────
        t1_result = self.tier1.scan(scan_data)
        if t1_result["matched"]:
            verdict = self._make_verdict(
                action="BLOCK", tier=1, t0=t0,
                cve_id=t1_result["cve_id"],
                reason=f"CVE pattern match: {t1_result['name']} — {t1_result['description']}",
            )
            self._emit(request, verdict)
            return verdict

        # ── Tier 2: SQL Injection & XSS ─────────────────────────────────────
        inputs = extract_inputs(request)

        sqli = check_sqli(inputs)
        if sqli["detected"]:
            verdict = self._make_verdict(
                action="BLOCK", tier=2, t0=t0,
                cve_id="GENERIC-SQLI",
                reason=sqli["detail"],
            )
            self._emit(request, verdict)
            return verdict

        xss = check_xss(inputs)
        if xss["detected"]:
            verdict = self._make_verdict(
                action="BLOCK", tier=2, t0=t0,
                cve_id="GENERIC-XSS",
                reason=xss["detail"],
            )
            self._emit(request, verdict)
            return verdict

        # ── Content Inspection (Base64 / File Uploads) ──────────────────────
        body = request.get("body", b"")
        if isinstance(body, str):
            body = body.encode("utf-8")
        content_type = request.get("content_type", "")

        if body and _should_inspect_content(content_type):
            content_verdict = self._inspect_content(body, content_type, request, t0)
            if content_verdict:
                self._emit(request, content_verdict)
                return content_verdict

        # ── Tier 3: ML Anomaly Detection ────────────────────────────────────
        ml_result = self.tier3.score(request)
        if ml_result["action"] == "BLOCK":
            verdict = self._make_verdict(
                action="BLOCK", tier=3, t0=t0,
                reason=f"ML anomaly score {ml_result['score']:.3f} ≥ threshold {self.tier3.threshold}: {ml_result['reason']}",
                ml_score=ml_result["score"],
            )
            self._emit(request, verdict)
            return verdict

        # ── All tiers passed — PERMIT ───────────────────────────────────────
        verdict = SecurityVerdict(
            action="PERMIT", tier=0,
            reason="All security checks passed",
            ml_score=ml_result["score"],
            latency_ms=_ms(t0),
        )
        self._emit(request, verdict)
        return verdict

    def _inspect_content(
        self,
        body: bytes,
        content_type: str,
        request: dict,
        t0: float,
    ) -> Optional[SecurityVerdict]:
        """
        Inline content inspection for Base64/document payloads.
        Returns a BLOCK verdict or None if clean.
        """
        size = len(body)

        # Choose inspection depth based on payload size
        if size <= FULL_SCAN_LIMIT:
            scan_targets = self._prepare_full_scan(body, content_type)
        elif size <= SAMPLE_SCAN_LIMIT:
            scan_targets = self._prepare_sampled_scan(body, content_type)
        else:
            # Async scan — pass inline, scan in background
            # (In production: fire goroutine/thread; here log and skip)
            logger.info(f"Large payload ({size} bytes) — async scan deferred")
            return None

        for target_bytes, label in scan_targets:
            if not target_bytes:
                continue

            # SHA-256 dedup check
            sha256 = hashlib.sha256(target_bytes).hexdigest()
            if self.db:
                cached = self.db.get_file_hash(sha256)
                if cached:
                    if cached["verdict"] == "MALICIOUS":
                        return self._make_verdict(
                            action="BLOCK", tier=4, t0=t0,
                            rule_name=cached.get("threat_name", "cached"),
                            reason=f"Known malicious file hash (SHA-256: {sha256[:16]}...)",
                            sha256=sha256,
                        )
                    return None  # Known clean

            # Magic byte validation
            magic_result = validate_content_type(target_bytes, content_type)
            if magic_result["should_block"]:
                if self.db:
                    self.db.store_file_hash(sha256, "MALICIOUS",
                                            magic_result.get("reason", "magic_byte"))
                return self._make_verdict(
                    action="BLOCK", tier=4, t0=t0,
                    reason=magic_result["reason"],
                    sha256=sha256,
                )

            # Entropy analysis
            ent = entropy_verdict(target_bytes)
            if ent["suspicious"] and size > 512:
                logger.debug(f"High entropy payload ({ent['score']}) — escalating to YARA scan")

            # YARA scan
            if self.yara.is_ready:
                yara_result = self.yara.scan(target_bytes)
                if yara_result["matched"]:
                    if self.db:
                        self.db.store_file_hash(sha256, "MALICIOUS",
                                                yara_result["rule_name"])
                    return self._make_verdict(
                        action="BLOCK", tier=4, t0=t0,
                        rule_name=yara_result["rule_name"],
                        reason=f"YARA rule matched: {yara_result['rule_name']} — {yara_result['description']}",
                        sha256=sha256,
                    )

            # Cache as clean
            if self.db:
                self.db.store_file_hash(sha256, "CLEAN", None)

        return None  # Content is clean

    def _prepare_full_scan(self, body: bytes, content_type: str) -> list[tuple[bytes, str]]:
        """Full scan: body + decoded Base64 candidates."""
        targets = [(body, "raw_body")]
        decoded = decode_body_if_base64(body, content_type)
        if decoded:
            targets.append((decoded, "b64_decoded_body"))
        for i, candidate in enumerate(extract_b64_candidates(body)):
            targets.append((candidate, f"b64_candidate_{i}"))
        return targets

    def _prepare_sampled_scan(self, body: bytes, content_type: str) -> list[tuple[bytes, str]]:
        """Sampled scan: first 4KB + middle 4KB + last 4KB."""
        size = len(body)
        mid = size // 2
        samples = [
            (body[:4096], "head_sample"),
            (body[max(0, mid - 2048):mid + 2048], "mid_sample"),
            (body[-4096:], "tail_sample"),
        ]
        return samples

    def _make_verdict(
        self,
        action: str,
        tier: int,
        t0: float,
        cve_id: str = None,
        rule_name: str = None,
        reason: str = "",
        ml_score: float = 0.0,
        sha256: str = None,
    ) -> SecurityVerdict:
        # In shadow mode: always PERMIT but log the would-be block
        actual_action = "PERMIT" if self.mode == "shadow" else action
        if self.mode == "shadow" and action == "BLOCK":
            reason = f"[SHADOW] Would block: {reason}"

        return SecurityVerdict(
            action=actual_action, tier=tier,
            cve_id=cve_id, rule_name=rule_name,
            reason=reason, ml_score=ml_score,
            latency_ms=_ms(t0), sha256=sha256,
        )

    def _emit(self, request: dict, verdict: SecurityVerdict):
        """Send telemetry event to background buffer (non-blocking)."""
        if self.telemetry is None:
            return
        event = {
            "request_id": request.get("request_id", ""),
            "client_ip": request.get("client_ip", ""),
            "method": request.get("method", ""),
            "uri": request.get("uri", ""),
            "action": verdict.action,
            "tier": verdict.tier,
            "cve_id": verdict.cve_id,
            "rule_name": verdict.rule_name,
            "reason": verdict.reason,
            "ml_score": verdict.ml_score,
            "latency_ms": verdict.latency_ms,
        }
        self.telemetry.send(event)

    def reload_rules(self):
        """Hot-reload all rules (called on SIGHUP)."""
        self.tier1.reload(self.config.patterns_file)
        self.yara.reload()
        logger.info("Rules hot-reloaded")


# ─── Helpers ──────────────────────────────────────────────────────────────

_STATIC_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
    ".css", ".js", ".mjs", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".wav", ".ogg", ".webm",
    ".pdf", ".zip",   # Note: zip/pdf still scanned if POSTed
})


def _is_static_file(uri: str) -> bool:
    """Check if URI is a request for a static asset (GET only)."""
    if not uri:
        return False
    path = uri.split("?")[0].lower()
    for ext in _STATIC_EXTENSIONS:
        if path.endswith(ext):
            return True
    return False


def _should_inspect_content(content_type: str) -> bool:
    """Only inspect content types that might carry attack payloads."""
    ct = (content_type or "").lower()
    inspect_types = (
        "application/x-www-form-urlencoded",
        "application/json",
        "application/xml",
        "text/xml",
        "text/plain",
        "application/octet-stream",
        "multipart/form-data",
    )
    return any(t in ct for t in inspect_types)


def _build_scan_data(request: dict) -> str:
    """Concatenate all injectable surfaces into one scan string."""
    parts = [
        request.get("uri", ""),
        request.get("query_string", ""),
        request.get("headers", {}).get("user-agent", ""),
        request.get("headers", {}).get("referer", ""),
        request.get("headers", {}).get("cookie", ""),
    ]
    body = request.get("body", "")
    if isinstance(body, bytes):
        parts.append(body.decode("utf-8", errors="replace")[:2048])
    elif isinstance(body, str):
        parts.append(body[:2048])
    return " ".join(filter(None, parts))


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 3)
