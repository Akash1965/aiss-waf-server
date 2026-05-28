"""
DuckDB Local Storage
Manages: IP reputation, CVE signatures, file hash cache, agent config.
Single-writer pattern: all writes go through a dedicated thread.
"""
import threading
import logging
import queue
import time
from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta, timezone

import duckdb

logger = logging.getLogger(__name__)

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cve_signatures (
    id          INTEGER PRIMARY KEY,
    cve_id      VARCHAR NOT NULL,
    pattern     TEXT NOT NULL,
    severity    VARCHAR DEFAULT 'MEDIUM',
    active      BOOLEAN DEFAULT TRUE,
    loaded_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip          VARCHAR PRIMARY KEY,
    verdict     VARCHAR NOT NULL,
    reason      TEXT,
    cve_id      VARCHAR,
    expires_at  TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS file_hashes (
    sha256      VARCHAR PRIMARY KEY,
    verdict     VARCHAR NOT NULL,
    threat_name TEXT,
    scanned_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agent_config (
    key         VARCHAR PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_events (
    id          VARCHAR PRIMARY KEY,
    client_ip   VARCHAR,
    method      VARCHAR,
    uri         TEXT,
    action      VARCHAR,
    tier        INTEGER,
    cve_id      VARCHAR,
    rule_name   VARCHAR,
    reason      TEXT,
    ml_score    DOUBLE,
    latency_ms  DOUBLE,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


class DuckDBStore:
    """
    Thread-safe DuckDB store.
    Reads are direct; writes are queued to a single writer thread.
    """

    def __init__(self, db_path: str = ":memory:"):
        self._db_path = db_path

        # Ensure parent directory exists
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        # Main read connection (DuckDB supports multiple readers)
        self._read_conn = duckdb.connect(db_path)
        self._read_lock = threading.Lock()

        # Write connection + queue (single-writer pattern)
        self._write_conn = duckdb.connect(db_path)
        self._write_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._write_thread = threading.Thread(
            target=self._write_loop, daemon=True, name="duckdb-writer"
        )
        self._shutdown = threading.Event()

        # Initialize schema
        self._write_conn.execute(_SCHEMA_SQL)
        self._write_conn.commit()
        self._write_thread.start()

        logger.info(f"DuckDB store initialized at {db_path}")

    # ── IP Reputation ────────────────────────────────────────────────────

    def get_ip_verdict(self, ip: str) -> Optional[dict]:
        """Returns cached verdict or None if expired/not found."""
        with self._read_lock:
            rows = self._read_conn.execute(
                "SELECT verdict, reason, cve_id, expires_at FROM ip_reputation "
                "WHERE ip = ? AND expires_at > CURRENT_TIMESTAMP",
                [ip]
            ).fetchall()
        if rows:
            r = rows[0]
            return {"verdict": r[0], "reason": r[1], "cve_id": r[2]}
        return None

    def set_ip_verdict(self, ip: str, verdict: str, reason: str = "",
                       cve_id: str = None, ttl_seconds: int = 60):
        expires = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        self._enqueue(
            "INSERT OR REPLACE INTO ip_reputation (ip, verdict, reason, cve_id, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            [ip, verdict, reason, cve_id, expires.isoformat()]
        )

    def cleanup_expired_ips(self):
        self._enqueue(
            "DELETE FROM ip_reputation WHERE expires_at <= CURRENT_TIMESTAMP",
            []
        )

    # ── CVE Signatures ────────────────────────────────────────────────────

    def get_active_signatures(self) -> list[dict]:
        with self._read_lock:
            rows = self._read_conn.execute(
                "SELECT id, cve_id, pattern, severity FROM cve_signatures WHERE active = TRUE"
            ).fetchall()
        return [
            {"id": r[0], "cve_id": r[1], "pattern": r[2], "severity": r[3]}
            for r in rows
        ]

    def upsert_signature(self, sig_id: int, cve_id: str, pattern: str,
                         severity: str = "HIGH"):
        self._enqueue(
            "INSERT OR REPLACE INTO cve_signatures (id, cve_id, pattern, severity, active) "
            "VALUES (?, ?, ?, ?, TRUE)",
            [sig_id, cve_id, pattern, severity]
        )

    def deactivate_signature(self, cve_id: str):
        self._enqueue(
            "UPDATE cve_signatures SET active = FALSE WHERE cve_id = ?",
            [cve_id]
        )

    # ── File Hash Cache ────────────────────────────────────────────────────

    def get_file_hash(self, sha256: str) -> Optional[dict]:
        with self._read_lock:
            rows = self._read_conn.execute(
                "SELECT verdict, threat_name FROM file_hashes WHERE sha256 = ?",
                [sha256]
            ).fetchall()
        if rows:
            return {"verdict": rows[0][0], "threat_name": rows[0][1]}
        return None

    def store_file_hash(self, sha256: str, verdict: str, threat_name: str = None):
        self._enqueue(
            "INSERT OR REPLACE INTO file_hashes (sha256, verdict, threat_name) VALUES (?, ?, ?)",
            [sha256, verdict, threat_name]
        )

    # ── Agent Config ──────────────────────────────────────────────────────

    def get_config(self, key: str) -> Optional[str]:
        with self._read_lock:
            rows = self._read_conn.execute(
                "SELECT value FROM agent_config WHERE key = ?", [key]
            ).fetchall()
        return rows[0][0] if rows else None

    def set_config(self, key: str, value: str):
        self._enqueue(
            "INSERT OR REPLACE INTO agent_config (key, value) VALUES (?, ?)",
            [key, value]
        )

    # ── Security Events ───────────────────────────────────────────────────

    def store_event(self, event: dict):
        import uuid
        self._enqueue(
            "INSERT INTO security_events "
            "(id, client_ip, method, uri, action, tier, cve_id, rule_name, reason, ml_score, latency_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                str(uuid.uuid4()),
                event.get("client_ip", ""),
                event.get("method", ""),
                event.get("uri", "")[:2000],
                event.get("action", ""),
                event.get("tier", 0),
                event.get("cve_id"),
                event.get("rule_name"),
                event.get("reason", "")[:1000],
                event.get("ml_score", 0.0),
                event.get("latency_ms", 0.0),
            ]
        )

    def get_recent_events(self, limit: int = 100, action: str = None) -> list[dict]:
        query = "SELECT * FROM security_events"
        params = []
        if action:
            query += " WHERE action = ?"
            params.append(action)
        query += f" ORDER BY created_at DESC LIMIT {limit}"
        with self._read_lock:
            rows = self._read_conn.execute(query, params).fetchall()
        cols = ["id", "client_ip", "method", "uri", "action", "tier",
                "cve_id", "rule_name", "reason", "ml_score", "latency_ms", "created_at"]
        return [dict(zip(cols, r)) for r in rows]

    def get_stats(self) -> dict:
        with self._read_lock:
            total = self._read_conn.execute(
                "SELECT COUNT(*) FROM security_events"
            ).fetchone()[0]
            blocked = self._read_conn.execute(
                "SELECT COUNT(*) FROM security_events WHERE action = 'BLOCK'"
            ).fetchone()[0]
            top_cves = self._read_conn.execute(
                "SELECT cve_id, COUNT(*) as cnt FROM security_events "
                "WHERE cve_id IS NOT NULL GROUP BY cve_id ORDER BY cnt DESC LIMIT 5"
            ).fetchall()
        return {
            "total_events": total,
            "total_blocked": blocked,
            "total_permitted": total - blocked,
            "top_cves": [{"cve_id": r[0], "count": r[1]} for r in top_cves],
        }

    # ── Internal ──────────────────────────────────────────────────────────

    def _enqueue(self, sql: str, params: list):
        try:
            self._write_queue.put_nowait((sql, params))
        except queue.Full:
            logger.warning("DuckDB write queue full — dropping event")

    def _write_loop(self):
        """Dedicated writer thread — processes the write queue."""
        while not self._shutdown.is_set():
            batch = []
            try:
                item = self._write_queue.get(timeout=0.1)
                batch.append(item)
                # Drain the queue for batch efficiency
                while not self._write_queue.empty() and len(batch) < 200:
                    try:
                        batch.append(self._write_queue.get_nowait())
                    except queue.Empty:
                        break
            except queue.Empty:
                continue

            try:
                for sql, params in batch:
                    self._write_conn.execute(sql, params)
                self._write_conn.commit()
            except Exception as e:
                logger.error(f"DuckDB write error: {e}")

    def close(self):
        self._shutdown.set()
        self._write_thread.join(timeout=5)
        self._read_conn.close()
        self._write_conn.close()
        logger.info("DuckDB store closed")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
