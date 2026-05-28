"""
Telemetry Ring Buffer
Non-blocking event collection + background batch flush to server.
The security pipeline never waits on telemetry — if buffer is full, events are dropped.
"""
import threading
import queue
import time
import logging
import json
from typing import Optional, Callable

logger = logging.getLogger(__name__)


class TelemetryBuffer:
    """
    Lock-free (queue-based) ring buffer for security events.
    Background thread flushes in batches to the central server.
    """

    def __init__(
        self,
        flush_fn: Callable[[list[dict]], None] = None,
        capacity: int = 10_000,
        batch_size: int = 1000,
        flush_interval: float = 1.0,
        db=None,
    ):
        self._queue: queue.Queue = queue.Queue(maxsize=capacity)
        self._flush_fn = flush_fn
        self._db = db
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._dropped = 0
        self._flushed = 0
        self._shutdown = threading.Event()

        self._thread = threading.Thread(
            target=self._flush_loop,
            daemon=True,
            name="telemetry-flusher",
        )
        self._thread.start()
        logger.info(
            f"Telemetry buffer started (capacity={capacity}, "
            f"batch={batch_size}, interval={flush_interval}s)"
        )

    def send(self, event: dict) -> bool:
        """
        Non-blocking event submission.
        Returns True if queued, False if dropped (buffer full).
        """
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            self._dropped += 1
            if self._dropped % 100 == 1:
                logger.warning(f"Telemetry buffer full — {self._dropped} events dropped")
            return False

    def _flush_loop(self):
        """Background flush thread."""
        while not self._shutdown.is_set():
            batch = self._drain_batch()
            if batch:
                self._flush(batch)
            else:
                time.sleep(self._flush_interval)

    def _drain_batch(self) -> list[dict]:
        """Drain up to batch_size events from the queue."""
        batch = []
        deadline = time.monotonic() + self._flush_interval
        while len(batch) < self._batch_size and time.monotonic() < deadline:
            try:
                event = self._queue.get_nowait()
                batch.append(event)
            except queue.Empty:
                break
        return batch

    def _flush(self, batch: list[dict]):
        """Flush a batch: store locally in DuckDB and send to server."""
        # Always store in local DuckDB
        if self._db:
            for event in batch:
                try:
                    self._db.store_event(event)
                except Exception as e:
                    logger.debug(f"DuckDB event store error: {e}")

        # Send to central server (optional — won't block if unavailable)
        if self._flush_fn:
            try:
                self._flush_fn(batch)
                self._flushed += len(batch)
            except Exception as e:
                logger.debug(f"Telemetry server flush error: {e}")

    def stop(self, timeout: float = 5.0):
        """Graceful shutdown — flush remaining events."""
        self._shutdown.set()
        # Flush remaining
        remaining = self._drain_batch()
        if remaining:
            self._flush(remaining)
        self._thread.join(timeout=timeout)
        logger.info(
            f"Telemetry buffer stopped | "
            f"flushed={self._flushed} dropped={self._dropped}"
        )

    @property
    def stats(self) -> dict:
        return {
            "queued": self._queue.qsize(),
            "flushed": self._flushed,
            "dropped": self._dropped,
        }
