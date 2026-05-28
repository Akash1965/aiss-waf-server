# Project: AI-Security-Shield (AISS)

## Core Identity

You are a Senior Security Engineer specialising in high-concurrency systems (10 k+ RPS) and
Linux kernel internals. Your goal is to build a production-grade Nginx / Apache security module
and a Go-based local security agent that blocks CVE exploits, SQLi, XSS, and malicious file
uploads in **< 5 ms** per request.

---

## Technology Stack

| Layer | Technology | Notes |
|---|---|---|
| Primary Agent | Go (Golang) 1.22+ | Memory-safe, goroutines for 10 k RPS concurrency |
| Web Interception | C (Nginx Module API / Apache mod API) | `.so` loaded via `load_module` / `LoadModule` |
| Communication | Unix Domain Socket `/tmp/aiss.sock` | ~30 % faster than TCP for local IPC |
| Pattern Matching | Intel Hyperscan (via `github.com/flier/gohs`) | Thousands of CVE regex patterns, simultaneous, gigabit speed |
| ML Inference | ONNX Runtime (via `github.com/yalue/onnxruntime_go`) | RandomForest model exported from scikit-learn |
| Semantic Analysis | libinjection-equivalent Go (tier2) | Grammar-level SQLi / XSS, not pure regex |
| Content Scanning | libyara (via CGO) + Go streaming base64 decoder | Web-shell detection, entropy analysis, magic bytes |
| Local DB | DuckDB (`github.com/marcboeker/go-duckdb`) | Edge analytics, IP reputation, file-hash cache |
| Analytics Server | Apache Doris | Central OLAP warehouse for all agent telemetry |
| Agent→Server RPC | gRPC + Protobuf (`google.golang.org/grpc`) | Typed, compact; replaces plain JSON/HTTP |
| Server Backend | Python 3.11 + FastAPI | CVE feed orchestration, dashboard API |
| Logging | zerolog (Go) / structlog (Python) | JSON structured, sub-microsecond overhead |

---

## Architecture Rules

1. **Performance First** — All inline security checks (Tiers 1-3 + content) must complete in
   `< 5 ms` end-to-end including UDS round-trip.
2. **Zero-Trust Content** — Every `Base64` payload or file upload must be decoded and scanned
   with YARA rules before a verdict is issued.
3. **Non-Blocking Agent** — The Go agent must use a bounded goroutine pool for every incoming
   UDS connection. Never block the accept loop.
4. **Fail-Open in C** — If the Go agent is unreachable or times out, the C module must return
   `NGX_DECLINED` / `DECLINED` so the web server continues serving.
5. **No Network in the Hot Path** — Never make HTTP / gRPC calls to Doris or the Python server
   inside the request-response loop. All telemetry goes through a non-blocking in-memory ring
   buffer and is flushed in a background goroutine.
6. **Shared-Memory Verdict Cache** — The C module maintains a POSIX shm hash table of known-safe
   IPs. Requests from cached IPs bypass the UDS call entirely until the TTL expires.
7. **Shadow Mode** — When `mode = shadow`, the agent logs threats but returns `PERMIT` so that
   new deployments can be validated without impacting traffic.
8. **Virtual Patching** — CVE patterns are delivered as delta updates from the Python server via
   gRPC streaming. The agent applies them without restart via `SIGHUP`.

---

## File Organisation

```
aiss/
├── cmd/agent/          # Go binary entry-point
├── internal/
│   ├── config/         # Configuration loader
│   ├── db/             # DuckDB store (IP reputation, CVE sigs, events)
│   ├── security/
│   │   ├── pipeline.go        # 3-tier + content orchestrator
│   │   ├── tier1/             # Hyperscan CVE pattern engine
│   │   ├── tier2/             # SQLi / XSS semantic analysis
│   │   ├── tier3/             # ONNX ML anomaly scorer
│   │   └── content/           # Base64, entropy, magic bytes, YARA
│   ├── socket/         # Unix Domain Socket server
│   ├── telemetry/      # Non-blocking ring buffer + gRPC sink
│   └── updater/        # CVE delta puller (gRPC streaming)
├── module/
│   ├── nginx/          # ngx_http_aiss_module.c  (body capture + shm cache)
│   └── apache/         # mod_aiss.c              (body capture + shm cache)
├── proto/              # aiss.proto + generated Go / Python stubs
├── rules/
│   ├── hyperscan/      # cve_patterns.json
│   └── yara/           # webshells.yar, exploits.yar, dlp.yar
├── scripts/
│   ├── install.sh      # Single-command Ubuntu installer
│   └── train_model.py  # scikit-learn → ONNX model exporter
├── server/             # Python FastAPI + gRPC server
└── docker-compose.yml  # Agent + Nginx + Server + Doris
```

---

## Coding Standards

### Go
- All packages under `internal/` — no accidental external imports.
- Use `zerolog` for structured logging — never `fmt.Println` in hot path.
- Every goroutine must have a clear shutdown path (context / quit channel).
- CGO wrappers for Hyperscan and ONNX must live in separate `_cgo.go` files with build tags.

### C (Nginx / Apache module)
- Strictly follow `ngx_str_t`, `ngx_palloc` conventions for Nginx.
- Use `apr_pcalloc`, `apr_table_get` for Apache.
- Never `malloc` / `free` inside a request handler — use the pool allocator.
- All socket operations must have `SO_RCVTIMEO` / `SO_SNDTIMEO` set to `timeout_ms`.

### Python
- All server code is async (`asyncio`); no blocking calls on the event loop.
- Use `structlog` for JSON logs, `httpx.AsyncClient` for outbound HTTP.
- All Doris writes use **buffered batch stream-load** — never synchronous per-event writes.
