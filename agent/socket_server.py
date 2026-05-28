"""
AISS Unix Domain Socket Server
Listens on /tmp/aiss.sock and serves security verdicts to the Nginx/Apache C module.

Protocol (simple line-based for interoperability with C):
  Request:  JSON line → {"request_id": "...", "method": "...", "uri": "...", ...}\n
  Response: JSON line → {"action": "PERMIT"|"BLOCK", "reason": "...", "tier": 1}\n

Each connection is handled in a separate thread (equivalent to goroutines in Go).
Thread pool limits concurrency to prevent resource exhaustion at 10k RPS.
"""
import os
import json
import socket
import threading
import logging
import signal
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

logger = logging.getLogger(__name__)


class UDSServer:
    """
    Unix Domain Socket server for the AISS security agent.
    Non-blocking accept loop + thread pool for request handling.
    """

    def __init__(
        self,
        socket_path: str,
        pipeline,
        max_workers: int = 256,
        timeout: float = 0.01,  # 10ms fail-open timeout
    ):
        self.socket_path = socket_path
        self.pipeline = pipeline
        self.timeout = timeout
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="aiss-worker",
        )
        self._server_sock: Optional[socket.socket] = None
        self._running = threading.Event()
        self._stats = {
            "total": 0,
            "blocked": 0,
            "permitted": 0,
            "errors": 0,
            "fail_open": 0,
        }
        self._stats_lock = threading.Lock()

    def start(self):
        """Start listening on the Unix Domain Socket."""
        # Remove stale socket
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

        self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(self.socket_path)
        # www-data group needs read/write access
        os.chmod(self.socket_path, 0o660)
        self._server_sock.listen(1024)
        self._server_sock.settimeout(1.0)  # Allow periodic shutdown checks
        self._running.set()

        logger.info(f"AISS agent listening on {self.socket_path}")

        try:
            while self._running.is_set():
                try:
                    conn, _ = self._server_sock.accept()
                    self._executor.submit(self._handle_connection, conn)
                except socket.timeout:
                    continue  # Check _running flag
                except OSError:
                    if self._running.is_set():
                        logger.error("Accept error", exc_info=True)
                    break
        finally:
            self._cleanup()

    def _handle_connection(self, conn: socket.socket):
        """Handle a single connection from the C module."""
        with self._stats_lock:
            self._stats["total"] += 1

        conn.settimeout(self.timeout)

        try:
            # Read request (newline-delimited JSON)
            data = b""
            while True:
                try:
                    chunk = conn.recv(8192)
                    if not chunk:
                        break
                    data += chunk
                    if b"\n" in data:
                        break
                except socket.timeout:
                    break

            if not data:
                self._send_fail_open(conn)
                return

            request = json.loads(data.decode("utf-8").strip())

            # Run security pipeline
            t0 = time.perf_counter()
            verdict = self.pipeline.check(request)
            latency_ms = (time.perf_counter() - t0) * 1000

            # Fail-Open: if pipeline took too long, permit and log
            if latency_ms > self.timeout * 1000:
                logger.warning(
                    f"Pipeline latency {latency_ms:.1f}ms exceeds threshold — "
                    f"Fail-Open for {request.get('client_ip', '?')}"
                )
                with self._stats_lock:
                    self._stats["fail_open"] += 1
                self._send_fail_open(conn)
                return

            response = {
                "action": verdict.action,
                "reason": verdict.reason,
                "tier": verdict.tier,
                "cve_id": verdict.cve_id,
                "ml_score": verdict.ml_score,
                "latency_ms": round(latency_ms, 3),
            }
            conn.sendall((json.dumps(response) + "\n").encode("utf-8"))

            with self._stats_lock:
                if verdict.action == "BLOCK":
                    self._stats["blocked"] += 1
                else:
                    self._stats["permitted"] += 1

        except json.JSONDecodeError as e:
            logger.warning(f"Malformed request JSON: {e}")
            self._send_fail_open(conn)
            with self._stats_lock:
                self._stats["errors"] += 1
        except Exception as e:
            logger.error(f"Request handler error: {e}", exc_info=True)
            self._send_fail_open(conn)
            with self._stats_lock:
                self._stats["errors"] += 1
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _send_fail_open(self, conn: socket.socket):
        """Send Fail-Open PERMIT response."""
        try:
            response = json.dumps({
                "action": "PERMIT",
                "reason": "fail-open",
                "tier": 0,
            }) + "\n"
            conn.sendall(response.encode("utf-8"))
        except Exception:
            pass

    def stop(self):
        """Graceful shutdown."""
        logger.info("Shutting down AISS agent...")
        self._running.clear()
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        self._executor.shutdown(wait=True, cancel_futures=False)
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass
        logger.info(f"AISS agent stopped | stats={self._stats}")

    @property
    def stats(self) -> dict:
        with self._stats_lock:
            return dict(self._stats)
