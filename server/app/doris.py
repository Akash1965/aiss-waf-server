"""
Apache Doris client for the AISS Central Server.

Provides two write paths:
  1. Stream Load (HTTP) — high-throughput bulk ingestion for security_events.
  2. MySQL protocol (pymysql) — DDL, upserts for cve_signatures and agents.

Security events are NEVER written synchronously.  They are accumulated in an
asyncio.Queue and flushed every FLUSH_INTERVAL_SEC seconds or FLUSH_BATCH_SIZE
events, whichever comes first.
"""

import asyncio
import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx
import pymysql
import pymysql.cursors
import structlog

from app.config import settings

log = structlog.get_logger(__name__)

FLUSH_INTERVAL_SEC = 1
FLUSH_BATCH_SIZE   = 5_000


# ── Low-level MySQL helpers ────────────────────────────────────────────────────

def _get_mysql_conn() -> pymysql.Connection:
    """Open a synchronous MySQL connection to the Doris FE."""
    return pymysql.connect(
        host     = settings.doris_host,
        port     = settings.doris_port,
        user     = settings.doris_user,
        password = settings.doris_password,
        database = settings.doris_database,
        charset  = "utf8mb4",
        cursorclass = pymysql.cursors.DictCursor,
        connect_timeout = 10,
    )


def execute_ddl(sql: str) -> None:
    """Run a DDL statement (CREATE TABLE, ALTER TABLE, etc.)."""
    try:
        conn = _get_mysql_conn()
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql)
        log.info("Doris DDL executed", sql=sql[:80])
    except Exception as exc:
        log.warning("Doris DDL failed", error=str(exc), sql=sql[:80])


# ── Upsert helpers ────────────────────────────────────────────────────────────

def upsert_cve_signature(row: dict) -> None:
    """INSERT or UPDATE a single CVE signature row in Doris."""
    sql = """
        INSERT INTO cve_signatures
            (cve_id, name, description, pattern, flags, severity, cvss,
             affected_product, active, source, modified_at)
        VALUES
            (%(cve_id)s, %(name)s, %(description)s, %(pattern)s, %(flags)s,
             %(severity)s, %(cvss)s, %(affected_product)s, %(active)s,
             %(source)s, %(modified_at)s)
    """
    row.setdefault("modified_at", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
    try:
        conn = _get_mysql_conn()
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql, row)
        conn.commit()
    except Exception as exc:
        log.warning("Doris CVE upsert failed", cve_id=row.get("cve_id"), error=str(exc))


def upsert_agent(row: dict) -> None:
    """INSERT or UPDATE an agent registration row."""
    sql = """
        INSERT INTO agents
            (id, hostname, ip, server_type, version, mode, last_seen, created_at)
        VALUES
            (%(id)s, %(hostname)s, %(ip)s, %(server_type)s, %(version)s,
             %(mode)s, %(last_seen)s, %(created_at)s)
    """
    try:
        conn = _get_mysql_conn()
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql, row)
        conn.commit()
    except Exception as exc:
        log.warning("Doris agent upsert failed", agent_id=row.get("id"), error=str(exc))


# ── Stream Load (batch events) ────────────────────────────────────────────────

def _stream_load_batch(events: list[dict]) -> bool:
    """
    Push a batch of security events to Doris via HTTP Stream Load.

    Doris Stream Load is a synchronous HTTP call but it is called from a
    background asyncio task, so it will not block the event loop.
    """
    if not events:
        return True

    be_host = getattr(settings, "doris_be_host", settings.doris_host)
    be_port = getattr(settings, "doris_be_port", 8040)
    url = f"http://{be_host}:{be_port}/api/{settings.doris_database}/security_events/_stream_load"

    # Serialize as CSV (Doris Stream Load CSV is faster than JSON for large batches)
    columns = [
        "created_at", "id", "agent_id", "client_ip", "method", "uri",
        "action", "tier", "cve_id", "rule_name", "reason",
        "ml_score", "latency_ms", "server_type",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore",
                            quoting=csv.QUOTE_ALL, lineterminator="\n")
    for e in events:
        e.setdefault("created_at",
                     datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
        writer.writerow(e)

    try:
        resp = httpx.put(
            url,
            content=buf.getvalue().encode(),
            headers={
                "Authorization": "Basic cm9vdDo=",  # base64("root:")
                "Expect": "100-continue",
                "label": f"aiss_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
                "column_separator": ",",
                "format": "CSV",
                "columns": ",".join(columns),
            },
            timeout=30.0,
        )
        result = resp.json()
        if result.get("Status") not in ("Success", "Publish Timeout"):
            log.warning("Stream Load non-success", status=result.get("Status"),
                        message=result.get("Message", ""))
            return False
        log.debug("Stream Load OK", rows=len(events), status=result.get("Status"))
        return True
    except Exception as exc:
        log.warning("Stream Load failed", error=str(exc), rows=len(events))
        return False


# ── Async batch writer ────────────────────────────────────────────────────────

class DorisEventWriter:
    """
    Collects security events and flushes them to Doris in batches.

    Usage:
        writer = DorisEventWriter()
        await writer.start()
        writer.enqueue(event_dict)
        # on shutdown:
        await writer.stop()
    """

    def __init__(self) -> None:
        self._queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=100_000)
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._flush_loop(), name="doris-flush")
        log.info("Doris event writer started",
                 interval_sec=FLUSH_INTERVAL_SEC,
                 batch_size=FLUSH_BATCH_SIZE)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        # Drain remaining
        remaining: list[dict] = []
        while not self._queue.empty():
            try:
                remaining.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        if remaining:
            await asyncio.get_event_loop().run_in_executor(
                None, _stream_load_batch, remaining
            )
        log.info("Doris event writer stopped")

    def enqueue(self, event: dict) -> bool:
        """Non-blocking enqueue. Returns False if the queue is full (drop)."""
        try:
            self._queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            log.warning("Doris queue full — event dropped")
            return False

    async def _flush_loop(self) -> None:
        while True:
            batch: list[dict] = []
            deadline = asyncio.get_event_loop().time() + FLUSH_INTERVAL_SEC

            # Drain up to FLUSH_BATCH_SIZE events within the flush interval
            while len(batch) < FLUSH_BATCH_SIZE:
                remaining_time = deadline - asyncio.get_event_loop().time()
                if remaining_time <= 0:
                    break
                try:
                    event = await asyncio.wait_for(
                        self._queue.get(), timeout=remaining_time
                    )
                    batch.append(event)
                except asyncio.TimeoutError:
                    break

            if batch:
                await asyncio.get_event_loop().run_in_executor(
                    None, _stream_load_batch, batch
                )


# ── Module-level singleton ────────────────────────────────────────────────────
event_writer = DorisEventWriter()
