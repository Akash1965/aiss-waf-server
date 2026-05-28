"""
Tier 1: CVE Pattern Matching
Production: Intel Hyperscan (C library, thousands of patterns at memory-bandwidth speed)
This implementation: Python regex engine (same patterns, same logic, functional equivalent)

Patterns are compiled once at startup and reused across all requests.
"""
import re
import json
import logging
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class CVEPattern:
    __slots__ = ("id", "cve_id", "name", "severity", "cvss", "compiled", "affected_product", "description")

    def __init__(self, data: dict):
        self.id = data["id"]
        self.cve_id = data["cve_id"]
        self.name = data["name"]
        self.severity = data["severity"]
        self.cvss = data.get("cvss", 0.0)
        self.affected_product = data.get("affected_product", "generic")
        self.description = data.get("description", "")
        flags = re.IGNORECASE if "CASELESS" in data.get("flags", "") else 0
        self.compiled = re.compile(data["pattern"], flags)


class Tier1PatternEngine:
    """
    CVE signature matching engine.
    Equivalent to Intel Hyperscan: multi-pattern scan across request data.
    """

    def __init__(self, patterns_file: str):
        self._patterns: list[CVEPattern] = []
        self._lock = threading.RLock()
        self.load_patterns(patterns_file)

    def load_patterns(self, patterns_file: str):
        """Load and compile CVE patterns from JSON file."""
        path = Path(patterns_file)
        if not path.exists():
            logger.warning(f"CVE patterns file not found: {patterns_file}")
            return

        try:
            with open(path) as f:
                raw = json.load(f)

            compiled = []
            errors = 0
            for entry in raw:
                try:
                    compiled.append(CVEPattern(entry))
                except re.error as e:
                    logger.warning(f"Bad pattern for {entry.get('cve_id')}: {e}")
                    errors += 1

            with self._lock:
                self._patterns = compiled

            logger.info(f"Loaded {len(compiled)} CVE patterns ({errors} skipped)")
        except Exception as e:
            logger.error(f"Failed to load CVE patterns: {e}")

    def reload(self, patterns_file: str):
        """Hot-reload patterns without interrupting in-flight scans."""
        self.load_patterns(patterns_file)

    def scan(self, data: str | bytes) -> dict:
        """
        Scan input data against all CVE patterns.
        Returns first match or empty result.

        Returns:
            {
                "matched": bool,
                "cve_id": str,
                "name": str,
                "severity": str,
                "cvss": float,
                "description": str,
            }
        """
        result = {
            "matched": False,
            "cve_id": None,
            "name": None,
            "severity": None,
            "cvss": 0.0,
            "description": None,
        }

        if not data:
            return result

        if isinstance(data, bytes):
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                text = ""
        else:
            text = data

        with self._lock:
            patterns = list(self._patterns)

        # Sort by severity (CRITICAL first) to return the worst match
        for pattern in sorted(patterns, key=lambda p: _severity_order(p.severity)):
            try:
                if pattern.compiled.search(text):
                    result["matched"] = True
                    result["cve_id"] = pattern.cve_id
                    result["name"] = pattern.name
                    result["severity"] = pattern.severity
                    result["cvss"] = pattern.cvss
                    result["description"] = pattern.description
                    return result  # Short-circuit on first CRITICAL match
            except Exception as e:
                logger.debug(f"Pattern scan error for {pattern.cve_id}: {e}")

        return result

    @property
    def pattern_count(self) -> int:
        with self._lock:
            return len(self._patterns)


def _severity_order(severity: str) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return order.get(severity, 99)
