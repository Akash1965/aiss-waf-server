# AISS — AI Security Shield

AISS is a production-grade Web Application Firewall (WAF) that protects Nginx and Apache web servers from CVE exploits, SQL injection, XSS, malicious file uploads, and 20+ other attack categories. It combines a high-performance Go agent (< 5 ms per request at 10,000 RPS) with a Python management server that distributes live CVE signatures from NVD, CISA KEV, and OSV.dev.

---

## Architecture Overview

```
Internet ──► Nginx / Apache
                │
                │  Unix Domain Socket (/tmp/aiss.sock)
                ▼
         ┌─────────────┐        gRPC (port 50051)        ┌──────────────────┐
         │  Go Agent   │ ◄────────────────────────────── │  Python Server   │
         │             │  CVE delta stream                │  (FastAPI)       │
         │  3-tier     │  Telemetry batch upload          │                  │
         │  pipeline   │                                  │  DuckDB (hot)    │
         └─────────────┘                                  │  Apache Doris    │
               │                                          │  (analytics)     │
               │  DuckDB                                  └──────────────────┘
               │  (local cache)                                    ▲
               │                                                   │ REST API
               └────────────────────────────────────────► Dashboard / Vercel Middleware
```

**Two deployment modes:**

| Mode | Use case |
|------|----------|
| **Full stack** | Go agent on the web server host, Python server as central management |
| **HTTP inspect** | No agent; Vercel Edge Middleware calls `/v1/inspect` over HTTPS — same detection logic, no Nginx/Apache module required |

---

## Security Pipeline

Every HTTP request passes through four stages in order. The first match blocks the request:

| Tier | Engine | Detects |
|------|--------|---------|
| **0** | IP verdict cache (DuckDB) | Known-malicious IPs bypass full scan |
| **1** | CVE regex patterns (Hyperscan or Go regexp) | Log4Shell, Shellshock, Spring4Shell, 1 700+ live CVEs |
| **2** | Structural injection patterns | SQL injection, XSS — URL-decoded and double-decoded |
| **3** | ML heuristic scorer (22 features) | Path traversal, RCE, SSRF, SSTI, XXE, deserialization, prototype pollution, LDAP injection, and more |
| **4** | Content inspection (YARA + entropy) | Web shells, malicious uploads, base64-encoded payloads |

**Fail-open**: any pipeline exception returns `PERMIT` — bugs never block legitimate traffic.  
**Shadow mode**: pipeline detects threats but always returns `PERMIT` — safe for initial deployment validation.

---

## Key Features

- **Live CVE signatures** synced hourly from NVD v2, CISA KEV, and OSV.dev (~1,700+ patterns)
- **OWASP Top 10 2025** coverage across all tiers
- **Immutable audit log** — HMAC-SHA256 chained entries (Singapore IM8 / MAS TRM compliant)
- **RBAC API keys** — admin / viewer / agent roles
- **Prometheus metrics** at `/metrics`
- **Hot rule reload** via `kill -HUP` (no restart required)
- **Apache Doris** integration for central OLAP analytics across all agents
- **mTLS** between agents and central server (ECDSA P-384 certificates)
- **Vercel Edge Middleware** integration for serverless deployments

---

## Repository Layout

```
aiss/
├── cmd/agent/          # Go binary entry-point
├── internal/
│   ├── config/         # Agent configuration loader
│   ├── db/             # DuckDB store (IP reputation, CVE sigs, file hashes)
│   ├── security/
│   │   ├── pipeline.go # 3-tier + content orchestrator (hot path)
│   │   ├── tier1/      # CVE pattern engine (regexp / Hyperscan)
│   │   ├── tier2/      # SQLi / XSS semantic analysis
│   │   ├── tier3/      # ML anomaly scorer (heuristic / ONNX)
│   │   └── content/    # Base64 decode, entropy, magic bytes, YARA
│   ├── socket/         # Unix Domain Socket server (bounded goroutine pool)
│   ├── telemetry/      # Non-blocking ring buffer + gRPC batch sink
│   └── updater/        # CVE delta puller (gRPC streaming)
├── module/
│   ├── nginx/          # ngx_http_aiss_module.c
│   └── apache/         # mod_aiss.c
├── server/             # Python FastAPI + gRPC management server
│   └── app/
│       ├── routers/    # inspect, auth, agents, stats, audit, updates
│       └── middleware/ # audit chain, rate limiter, security headers
├── proto/              # aiss.proto + generated Go / Python stubs
├── rules/
│   ├── hyperscan/      # cve_patterns.json
│   └── yara/           # webshells.yar, exploits.yar, dlp.yar, apt_regional.yar
├── scripts/
│   ├── install.sh      # Single-command Ubuntu/Debian/RHEL installer
│   └── train_model.py  # scikit-learn → ONNX model exporter
├── docker-compose.yml  # Full stack (agent + Nginx + server + Doris)
├── render.yaml         # Render.com Blueprint (server only, free tier)
└── CLAUDE.md           # AI assistant guide for this codebase
```

---

## Quick Start

### Option A — Full stack with Docker Compose

```bash
git clone https://git.cloudloyalty.in/CloudLoyalty/CloudServerSecurity.git
cd CloudServerSecurity

# x86_64 (includes local Doris BE)
docker compose --profile local-be up -d

# Apple Silicon / arm64 (Doris BE on UTM VM — see INSTALLATION.md)
docker compose up -d
```

Services started:
- **Nginx** on `:80` / `:443` (TLS 1.3)
- **AISS server** REST on `:8080`, gRPC on `:50051`
- **Apache Doris FE** on `:9030` (MySQL protocol)

### Option B — Server only on Render (free tier)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://dashboard.render.com/new/blueprint)

Connect the repository, select `render.yaml`, and deploy. The server will be live at `https://<name>.onrender.com`. Use the `AISS_SECRET_KEY` Render generates as your initial `X-API-Key`.

### Option C — Install Go agent on an existing server

```bash
sudo bash scripts/install.sh \
    --server-url https://your-aiss-server.example.com \
    --api-key    <your-api-key> \
    --mode       shadow \
    --web-server nginx
```

---

## API Overview

All endpoints require `X-API-Key` header (except `/health`).

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness probe |
| `POST` | `/v1/inspect` | WAF verdict for a single request |
| `GET` | `/v1/updates` | CVE signature delta feed for agents |
| `POST` | `/v1/telemetry` | Batch event ingestion from agents |
| `GET` | `/v1/stats/summary` | Aggregated security statistics |
| `GET` | `/v1/stats/timeline` | Event counts over time |
| `GET` | `/v1/agents/` | Registered agent list |
| `POST` | `/v1/auth/keys` | Issue a new API key |
| `GET` | `/v1/audit` | Tamper-evident audit log |
| `GET` | `/v1/audit/verify` | Verify audit chain integrity |
| `GET` | `/metrics` | Prometheus metrics |

Interactive docs (non-production only): `http://localhost:8080/docs`

---

## Compliance

| Standard | Coverage |
|----------|----------|
| OWASP Top 10 2025 | A01–A10 detection across all tiers |
| Singapore IM8 v5.0 | §3 threat prevention, §4 audit logging |
| MAS TRM 2021 | §9.2 application-layer controls, §9.4 audit trail |
| CSA Cybersecurity Code of Practice | §10 incident forensics |
| Korea K-ISMS Annex A | §12.4 logging and monitoring |

---

## Documentation

- **[REQUIREMENTS.md](REQUIREMENTS.md)** — System and software requirements
- **[INSTALLATION.md](INSTALLATION.md)** — Detailed installation and configuration guide
- **[CLAUDE.md](CLAUDE.md)** — Architecture deep-dive and developer reference
