# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

AISS (AI Security Shield) is a two-component WAF system:

1. **Go agent** (`cmd/agent/`, `internal/`) — A high-performance binary that plugs into Nginx/Apache via a Unix Domain Socket. Inspects every HTTP request through a 3-tier + content pipeline targeting < 5 ms at 10,000 RPS.

2. **Python server** (`server/`) — A FastAPI + gRPC service that distributes CVE signature updates to agents, aggregates telemetry, and exposes a REST management API. Deployed to Render; backed by DuckDB (embedded) and optionally Apache Doris (OLAP warehouse).

The two components communicate over gRPC (proto defined in `proto/aiss.proto`). The Python server also exposes `/v1/inspect` — an HTTP WAF endpoint used by Vercel Edge Middleware to get verdicts without deploying the Go agent.

---

## Commands

### Go Agent

```bash
make build          # compile to dist/aiss-agent
make test           # go test -v -count=1 ./...
make test-race      # tests + race detector
make test-short     # skip integration tests
make bench          # benchmarks with -benchmem
make cover          # coverage.html report
make lint           # golangci-lint run ./...
make vet            # go vet ./...
make run-dev        # go run ./cmd/agent --config ./aiss.conf
```

Single package test:
```bash
go test -v ./internal/security/tier2/...
go test -v -run TestCheckSQLi ./internal/security/tier2/
```

Optional native backends (not in go.mod by default):
```bash
# Hyperscan (x86_64 only) — build with -tags hyperscan
go get github.com/flier/gohs@latest
go build -tags hyperscan ./cmd/agent

# ONNX runtime — build with -tags onnx
go get github.com/yalue/onnxruntime_go@latest
go build -tags onnx ./cmd/agent
```

### Python Server

```bash
cd server
pip install -r requirements.txt

# Run locally (in-memory DuckDB, any API key accepted)
uvicorn app.main:app --reload --port 8080

# Run a single test file
python -m pytest tests/test_inspect.py -v    # if tests exist

# Regenerate gRPC stubs from proto
bash proto/generate.sh
```

### Full Stack (Docker)

```bash
make docker-up      # start everything: Nginx, agent, server, Doris
make docker-down    # stop and remove volumes
make docker-test    # build + run tests in Docker

# Apple Silicon — Doris BE requires x86_64; run FE only locally, BE on UTM VM
docker compose up                          # arm64 (no local BE)
docker compose --profile local-be up      # x86_64 (local BE)
```

### Certs (mTLS)

```bash
bash certs/generate-certs.sh    # regenerate CA + all service certs
```

### ML Model

```bash
# Only needed to retrain; scikit-learn/onnx not in requirements.txt
pip install scikit-learn numpy onnx skl2onnx
python scripts/train_model.py   # produces agent/ml/aiss_model.onnx
```

---

## Architecture

### Go Agent Security Pipeline (`internal/security/pipeline.go`)

Every request flows through four stages in order; the first match blocks:

| Tier | Location | What it does |
|------|----------|--------------|
| 0 | `pipeline.go` | Static file bypass + IP verdict cache (DuckDB `ip_reputation`) |
| 1 | `tier1/` | CVE regex patterns from `rules/hyperscan/cve_patterns.json`. Default: `[]*regexp.Regexp`. Build tag `hyperscan`: Intel Hyperscan database. Hot-reload via `SIGHUP` → `Engine.Load()`. |
| 2 | `tier2/` | Hardcoded structural patterns for SQLi (UNION SELECT, stacked queries, tautologies) and XSS (script tags, event handlers, data-URIs). Runs against URL-decoded AND double-decoded inputs. |
| Content | `content/` | Base64 decode, magic-byte type mismatch, Shannon entropy, YARA scan. Chunked: full scan ≤10 KB, sampled 10 KB–1 MB, async >1 MB. SHA-256 dedup in DuckDB. |
| 3 | `tier3/` | 22-feature heuristic scorer returning 0.0–1.0. Build tag `onnx`: ONNX Runtime inference using the same features. Default threshold: 0.85. |

Mode `shadow`: pipeline logs threats but always returns PERMIT (for validation without traffic impact).

### Python Server Inspection Pipeline (`server/app/routers/inspect.py`)

A "lite" version of the same logic used when Go agent isn't deployed (e.g., Vercel middleware):

- **Tier 1**: CVE signatures loaded from DuckDB into an in-memory cache every 60 s by a daemon thread. The cache decouples request handlers from `_db_lock` contention during CVE sync.
- **Tier 2**: Hardcoded `_SQLI_PATTERNS` and `_XSS_PATTERNS` in the file — edit these lists to add/remove rules.
- **Tier 3**: `_HEURISTIC_PATTERNS` list covering path traversal, LFI, RCE, SSRF, SSTI, XXE, NoSQL, deserialization, prototype pollution, etc. **This is the primary place to add new detection rules.**

`InspectRequest` accepts a base64-encoded `body` field. `_decode_body()` handles double-decoding with a guard: second-pass only runs if the decoded text matches `^[A-Za-z0-9+/=\s]{16,}$` (prevents JSON decoded as base64 from producing garbage bytes that trip heuristic rules).

### DuckDB Concurrency Contract

DuckDB uses a single shared connection via SQLAlchemy `StaticPool`. **This is the most important constraint in the Python server:**

- `_db_lock` (a `threading.Lock` in `database.py`) **must** be held whenever creating a `SessionLocal()`.
- Every router and middleware that touches the DB must import and acquire `_db_lock` — use the `get_db()` FastAPI dependency for request handlers.
- The CVE sync worker (`cve_sync.py`) acquires `_db_lock` per-CVE (not per-batch) so request handlers can interleave between upserts.
- `scalar_one_or_none()` is **unsafe** on DuckDB — duplicate rows can occur mid-transaction. Use `.scalars().first()` everywhere.

### Authentication

`X-API-Key` header is required on all `/v1/*` endpoints. Two paths:

1. **Bootstrap**: if `raw_key == settings.secret_key` (the `AISS_SECRET_KEY` env var), admin access is granted immediately without a DB lookup. Use this to authenticate on a fresh Render deploy.
2. **DB lookup**: key is HMAC-SHA256'd with `settings.secret_key` and matched against the `api_keys` table.

In `AISS_ENVIRONMENT=development`, any non-empty key is accepted (dev shortcut).

### Audit Log Chain

`AuditLogMiddleware` writes a tamper-evident HMAC chain to `audit_logs`. Key invariants:
- `_chain_lock` serialises the entire read-prev → compute → write → advance cycle.
- Timestamp is stamped **inside** `_chain_lock` (not at dispatch time) so chain order matches timestamp order.
- `_last_hash` is updated only after a confirmed `session.commit()`.

### gRPC / Proto

`proto/aiss.proto` defines three RPCs: `SubmitTelemetry`, `GetCVEUpdates` (streaming), `RegisterAgent`. Go stubs are pre-generated in `proto/gen/go/`. Python stubs are generated by `proto/generate.sh` into `server/app/` at Docker build time.

### CVE Feed Sources

`server/app/cve_sync.py` pulls from NVD v2, CISA KEV, and OSV.dev on a schedule (`AISS_CVE_SYNC_INTERVAL_HOURS`, default 1 h). Patterns that are too generic (tokens < 5 chars or in a blocklist) are silently skipped by `_product_to_pattern()`.

### Deployment

- **Render (production)**: `render.yaml` defines the web service. `startCommand` must NOT be set for Docker runtime — the port is injected via `$PORT` env var and handled by `${PORT:-8080}` shell form in the Dockerfile `CMD`.
- **Vercel (dashboard + forum)**: `aiss-dashboard/` and `nit-mca-forum/` both use `AISS_API_URL` and `AISS_API_KEY` server-side env vars (no `NEXT_PUBLIC_` prefix).
- `/docs` and `/redoc` are disabled in `AISS_ENVIRONMENT=production`.
