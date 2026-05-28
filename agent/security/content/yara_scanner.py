"""
YARA Rule Scanner
Loads all .yar files from the rules directory and scans data.
Supports hot-reload via reload() method.
"""
import os
import threading
import logging
from pathlib import Path
from typing import Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logging.warning("yara-python not available; YARA scanning disabled")

logger = logging.getLogger(__name__)


class YaraScanner:
    """Thread-safe YARA rule scanner with hot-reload support."""

    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        self._rules = None
        self._lock = threading.RLock()
        self._load_rules()

    def _load_rules(self):
        if not YARA_AVAILABLE:
            return

        rules_path = Path(self.rules_dir)
        if not rules_path.exists():
            logger.warning(f"YARA rules directory not found: {self.rules_dir}")
            return

        yar_files = list(rules_path.glob("*.yar"))
        if not yar_files:
            logger.warning(f"No .yar files found in {self.rules_dir}")
            return

        filepaths = {f.stem: str(f) for f in yar_files}
        try:
            compiled = yara.compile(filepaths=filepaths)
            with self._lock:
                self._rules = compiled
            logger.info(f"Loaded YARA rules from {len(filepaths)} file(s): {list(filepaths.keys())}")
        except yara.SyntaxError as e:
            logger.error(f"YARA syntax error: {e}")
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")

    def reload(self):
        """Hot-reload rules without stopping the scanner."""
        logger.info("Reloading YARA rules...")
        self._load_rules()

    def scan(self, data: bytes, timeout: int = 5) -> dict:
        """
        Scan data against all loaded YARA rules.
        Returns:
            {
                "matched": bool,
                "rule_name": str | None,
                "namespace": str | None,
                "severity": str | None,
                "description": str | None,
                "tags": list[str],
            }
        """
        result = {
            "matched": False,
            "rule_name": None,
            "namespace": None,
            "severity": None,
            "description": None,
            "tags": [],
        }

        if not YARA_AVAILABLE or self._rules is None:
            return result

        if not data:
            return result

        try:
            with self._lock:
                rules_ref = self._rules
            matches = rules_ref.match(data=data, timeout=timeout)
            if matches:
                best = matches[0]  # First match is sufficient to block
                result["matched"] = True
                result["rule_name"] = best.rule
                result["namespace"] = best.namespace
                result["tags"] = list(best.tags)
                result["severity"] = best.meta.get("severity", "HIGH")
                result["description"] = best.meta.get("description", "")
        except yara.TimeoutError:
            logger.warning("YARA scan timed out")
        except Exception as e:
            logger.error(f"YARA scan error: {e}")

        return result

    @property
    def is_ready(self) -> bool:
        return YARA_AVAILABLE and self._rules is not None
