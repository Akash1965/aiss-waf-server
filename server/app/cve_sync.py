"""
CVE feed synchronisation worker.

Pulls from NVD v2.0, CISA KEV, and OSV.dev on a schedule and upserts
normalised patterns into the cve_signatures table for distribution to agents.

Run standalone:
    python -m app.cve_sync

Or as a background task started from the server process.
"""

import asyncio
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import structlog
from sqlalchemy import select

from app.config import settings
from app.database import SessionLocal
from app.models import CVESignature

log = structlog.get_logger(__name__)

# ── Known exploit patterns (NVD CVE → regex) ─────────────────────────────────
# These supplement auto-generated patterns with hand-curated detection regexes.
HANDCRAFTED_PATTERNS: list[dict] = [
    {
        "cve_id": "CVE-2021-44228",
        "name": "Log4Shell",
        "pattern": r"\$\{jndi:(ldap|rmi|dns)://",
        "flags": "CASELESS",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "affected_product": "Apache Log4j2",
        "source": "handcrafted",
    },
    {
        "cve_id": "CVE-2021-45046",
        "name": "Log4Shell v2",
        "pattern": r"\$\{.*jndi:.*://",
        "flags": "CASELESS",
        "severity": "CRITICAL",
        "cvss": 9.0,
        "affected_product": "Apache Log4j2",
        "source": "handcrafted",
    },
    {
        "cve_id": "CVE-2014-6271",
        "name": "Shellshock",
        "pattern": r"\(\)\s*\{\s*[^}]*\};\s*",
        "flags": "",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "affected_product": "GNU Bash",
        "source": "handcrafted",
    },
    {
        "cve_id": "CVE-2022-22965",
        "name": "Spring4Shell",
        "pattern": r"class\.module\.classLoader",
        "flags": "CASELESS",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "affected_product": "Spring Framework",
        "source": "handcrafted",
    },
    {
        "cve_id": "CVE-2017-9841",
        "name": "PHPUnit RCE",
        "pattern": r"vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php",
        "flags": "CASELESS",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "affected_product": "PHPUnit",
        "source": "handcrafted",
    },
    {
        "cve_id": "CVE-2017-5638",
        "name": "Apache Struts2 OGNL",
        "pattern": r"%\{.*\.getClass\(\)\.forName\(.*\)\}|Content-Type:.*%\{",
        "flags": "CASELESS",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "affected_product": "Apache Struts2",
        "source": "handcrafted",
    },
    {
        "cve_id": "CVE-2021-26084",
        "name": "Confluence OGNL",
        "pattern": r"\{[^}]*\.getClass\(\)\.forName\(",
        "flags": "CASELESS",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "affected_product": "Atlassian Confluence",
        "source": "handcrafted",
    },
    {
        "cve_id": "GENERIC-SQLI",
        "name": "SQL Injection",
        "pattern": r"(?i)(union\s+select|or\s+1\s*=\s*1|;\s*drop\s+table|exec\s*xp_cmdshell)",
        "flags": "CASELESS",
        "severity": "HIGH",
        "cvss": 8.0,
        "affected_product": "generic",
        "source": "handcrafted",
    },
    {
        "cve_id": "GENERIC-XSS",
        "name": "Cross-Site Scripting",
        "pattern": r"<script[^>]*>|javascript:|on(?:load|error|click|mouseover)\s*=",
        "flags": "CASELESS",
        "severity": "HIGH",
        "cvss": 7.5,
        "affected_product": "generic",
        "source": "handcrafted",
    },
]


class CVESyncWorker:
    """Pulls CVE feeds and upserts patterns into DuckDB."""

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)

    async def run_forever(self) -> None:
        """Background loop — runs every CVE_SYNC_INTERVAL_HOURS."""
        log.info("CVE sync worker started",
                 interval_hours=settings.cve_sync_interval_hours)
        while True:
            try:
                await self.sync_all()
            except Exception as exc:
                log.error("CVE sync error", error=str(exc))

            await asyncio.sleep(settings.cve_sync_interval_hours * 3600)

    async def sync_all(self) -> int:
        """Sync all feeds. Returns count of upserted patterns."""
        total = 0
        total += await self._upsert_handcrafted()
        total += await self._sync_cisa_kev()
        total += await self._sync_osv()
        if settings.nvd_api_key:
            total += await self._sync_nvd()
        log.info("CVE sync complete", total_upserted=total)
        return total

    async def _sync_osv(self) -> int:
        """Pull CVEs from OSV.dev for web-server-relevant ecosystems.

        OSV is often updated faster than NVD for open-source packages and
        covers ecosystems like PyPI, npm, Go, Maven that NVD misses or delays.
        We query a curated list of products known to be relevant to web servers.
        """
        OSV_QUERY_URL = "https://api.osv.dev/v1/query"

        # Packages most relevant to Nginx/Apache deployments
        TARGETS = [
            {"name": "nginx",       "ecosystem": "OSS-Fuzz"},
            {"name": "apache",      "ecosystem": "OSS-Fuzz"},
            {"name": "openssl",     "ecosystem": "OSS-Fuzz"},
            {"name": "php",         "ecosystem": "OSS-Fuzz"},
            {"name": "log4j-core",  "ecosystem": "Maven"},
            {"name": "spring-core", "ecosystem": "Maven"},
            {"name": "struts2-core","ecosystem": "Maven"},
            {"name": "django",      "ecosystem": "PyPI"},
            {"name": "flask",       "ecosystem": "PyPI"},
            {"name": "express",     "ecosystem": "npm"},
        ]

        patterns: list[dict] = []
        for target in TARGETS:
            try:
                resp = await self.client.post(
                    OSV_QUERY_URL,
                    json={"package": {"name": target["name"], "ecosystem": target["ecosystem"]}},
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                log.warning("OSV query failed", package=target["name"], error=str(exc))
                continue

            for vuln in data.get("vulns", []):
                # OSV IDs can be CVE-* or GHSA-* etc.
                osv_id = vuln.get("id", "")
                if not osv_id:
                    continue

                # Prefer CVE alias if present
                aliases = vuln.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), osv_id)

                summary = vuln.get("summary", "")
                details = vuln.get("details", "")
                description = (summary or details)[:512]

                # Severity from database_specific or severity list
                severity = "MEDIUM"
                cvss = 5.0
                for sev in vuln.get("severity", []):
                    score_str = sev.get("score", "")
                    try:
                        cvss = float(score_str.split("/")[0]) if "/" not in score_str else float(score_str.split("CVSS:")[1].split("/")[0])
                    except Exception:
                        pass
                    if cvss >= 9.0:
                        severity = "CRITICAL"
                    elif cvss >= 7.0:
                        severity = "HIGH"
                    break

                # Build pattern from affected package name + known payload hints
                pat = _product_to_pattern(target["name"], "")
                if not pat:
                    continue

                # Skip if we already have a hand-crafted pattern for this CVE
                if any(p["cve_id"] == cve_id for p in HANDCRAFTED_PATTERNS):
                    continue

                patterns.append({
                    "cve_id":           cve_id,
                    "name":             summary[:120] if summary else cve_id,
                    "pattern":          pat,
                    "flags":            "CASELESS",
                    "severity":         severity,
                    "cvss":             cvss,
                    "affected_product": target["name"],
                    "source":           "osv",
                    "description":      description,
                })

        count = await self._upsert_patterns(patterns)
        log.info("OSV sync", count=count)
        return count

    async def _upsert_handcrafted(self) -> int:
        """Upsert the built-in hand-crafted patterns."""
        return await self._upsert_patterns(HANDCRAFTED_PATTERNS)

    async def _sync_cisa_kev(self) -> int:
        """Pull CISA Known Exploited Vulnerabilities catalogue."""
        try:
            resp = await self.client.get(settings.cisa_kev_url)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log.warning("CISA KEV fetch failed", error=str(exc))
            return 0

        patterns = []
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if not cve_id:
                continue

            # Build a minimal regex from the product name
            product = vuln.get("product", "")
            vendor  = vuln.get("vendorProject", "")
            pattern = _product_to_pattern(product, vendor)
            if not pattern:
                continue

            patterns.append({
                "cve_id": cve_id,
                "name": vuln.get("vulnerabilityName", cve_id),
                "pattern": pattern,
                "flags": "CASELESS",
                "severity": "HIGH",  # CISA KEV are all actively exploited
                "cvss": 8.0,
                "affected_product": f"{vendor} {product}".strip(),
                "source": "cisa_kev",
                "description": vuln.get("shortDescription", ""),
            })

        count = await self._upsert_patterns(patterns)
        log.info("CISA KEV sync", count=count)
        return count

    async def _sync_nvd(self) -> int:
        """Pull NVD v2.0 recent CVEs (last 30 days, CRITICAL only)."""
        since = (datetime.now(timezone.utc) - timedelta(days=30)).strftime(
            "%Y-%m-%dT%H:%M:%S.000"
        )
        try:
            resp = await self.client.get(
                settings.nvd_base_url,
                params={
                    "pubStartDate": since,
                    "cvssV3Severity": "CRITICAL",
                    "resultsPerPage": 100,
                },
                headers={"apiKey": settings.nvd_api_key},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log.warning("NVD fetch failed", error=str(exc))
            return 0

        patterns = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "",
            )
            cvss = 0.0
            metrics = cve.get("metrics", {})
            for v in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if v in metrics and metrics[v]:
                    cvss = metrics[v][0].get("cvssData", {}).get("baseScore", 0.0)
                    break

            # Extract affected products for pattern building
            configs = cve.get("configurations", [])
            product_name = _extract_nvd_product(configs)
            pattern = _product_to_pattern(product_name, "")
            if not pattern:
                continue

            patterns.append({
                "cve_id": cve_id,
                "name": cve_id,
                "pattern": pattern,
                "flags": "CASELESS",
                "severity": "CRITICAL",
                "cvss": cvss,
                "affected_product": product_name,
                "source": "nvd",
                "description": desc[:512],
            })

        count = await self._upsert_patterns(patterns)
        log.info("NVD sync", count=count)
        return count

    async def _upsert_patterns(self, patterns: list[dict]) -> int:
        """Upsert a list of pattern dicts into cve_signatures (DuckDB).

        Uses SELECT-then-INSERT/UPDATE — dialect-agnostic, works on DuckDB.
        The DB calls are synchronous (DuckDB is in-process); running them
        directly in this async method is fine for a background worker.
        """
        if not patterns:
            return 0

        count = 0
        # Deduplicate within the batch by cve_id (same CVE from multiple feeds
        # within one sync pass would otherwise cause a bulk-INSERT constraint error).
        seen_in_batch: set[str] = set()

        with SessionLocal() as db:
            for p in patterns:
                if not p.get("pattern") or not p.get("cve_id"):
                    continue

                cve_id = p["cve_id"]
                if cve_id in seen_in_batch:
                    continue
                seen_in_batch.add(cve_id)

                # Validate regex before storing
                try:
                    re.compile(p["pattern"])
                except re.error:
                    log.warning("Invalid regex skipped", cve_id=cve_id)
                    continue

                # Dialect-agnostic upsert: flush after each add so the next
                # SELECT in the same session sees uncommitted rows correctly.
                existing = db.execute(
                    select(CVESignature).where(CVESignature.cve_id == cve_id)
                ).scalar_one_or_none()

                if existing:
                    existing.pattern       = p["pattern"]
                    existing.severity      = p.get("severity", "MEDIUM")
                    existing.cvss          = p.get("cvss", 0.0)
                    existing.active        = True
                    existing.modified_at   = datetime.now(timezone.utc)
                else:
                    db.add(CVESignature(
                        cve_id           = cve_id,
                        name             = p.get("name", cve_id),
                        description      = p.get("description", ""),
                        pattern          = p["pattern"],
                        flags            = p.get("flags", ""),
                        severity         = p.get("severity", "MEDIUM"),
                        cvss             = p.get("cvss", 0.0),
                        affected_product = p.get("affected_product", ""),
                        active           = True,
                        source           = p.get("source", "unknown"),
                    ))
                    db.flush()  # make this row visible to subsequent SELECTs in the session
                count += 1

            db.commit()

        return count

    async def close(self) -> None:
        await self.client.aclose()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _product_to_pattern(product: str, vendor: str) -> Optional[str]:
    """
    Convert a product/vendor name into a URL/header detection regex.
    Returns None if the name is too generic to be a useful WAF pattern.

    Bug fixed: previously took only the first token of the combined
    vendor+product string.  Single common English words (e.g. "code",
    "use", "web", "data") produced patterns that matched nearly any
    request body, causing a high false-positive rate.

    Fix:
    - Require the first meaningful token to be ≥ 5 chars AND not in
      the common-word blocklist.
    - If the first token is generic, try the second; if none qualify,
      return None (skip this CVE — it cannot be expressed as a
      simple token pattern without excessive false positives).
    """
    GENERIC_WORDS = {
        # Common English words that aren't product identifiers
        "code", "core", "base", "host", "main", "type", "test", "data",
        "file", "user", "open", "http", "https", "html", "java", "linux",
        "ruby", "perl", "python", "golang", "swift", "rust", "node",
        "web", "net", "lib", "app", "api", "run", "get", "set", "new",
        "old", "via", "key", "out", "log", "use", "php", "all", "any",
        "some", "from", "this", "that", "with", "have", "been", "will",
        "more", "over", "into", "also", "back", "read", "write", "null",
        "true", "false", "none", "text", "name", "path", "home", "root",
        "version", "windows", "driver", "stack", "buffer", "overflow",
        "remote", "local", "server", "client", "system", "service",
        "manager", "module", "plugin", "package", "library",
    }

    combined = f"{vendor} {product}".strip().lower()

    GENERIC_FULL = {"", "n/a", "unknown", "various", "multiple", "all"}
    if combined in GENERIC_FULL or len(combined) < 4:
        return None

    # Sanitise: keep alphanumeric, spaces, dashes, underscores
    safe = re.sub(r"[^a-z0-9\s_\-]", "", combined).strip()
    if not safe:
        return None

    # Find the first token that is specific enough to use as a regex
    tokens = safe.split()
    chosen = None
    for tok in tokens:
        tok = tok.strip("_-")
        # Must be ≥ 5 chars and not a generic English word
        if len(tok) >= 5 and tok not in GENERIC_WORDS:
            chosen = tok
            break

    if chosen is None:
        return None  # All tokens are too generic — skip this CVE

    return re.escape(chosen)


def _extract_nvd_product(configs: list) -> str:
    """Extract the first meaningful product name from NVD configurations."""
    for node in configs:
        for match in node.get("cpeMatch", []):
            cpe = match.get("criteria", "")
            parts = cpe.split(":")
            if len(parts) >= 5:
                return parts[4]  # product field
    return ""


async def main() -> None:
    worker = CVESyncWorker()
    try:
        await worker.sync_all()
    finally:
        await worker.close()


if __name__ == "__main__":
    asyncio.run(main())
