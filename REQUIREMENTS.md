# REQUIREMENTS.md — AISS System Requirements

This document lists all hardware, OS, and software requirements for each component of AISS.

---

## Hardware Requirements

### Go Agent (on each protected web server)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores (x86_64 or arm64) | 4+ cores |
| RAM | 256 MB | 512 MB |
| Disk | 500 MB (rules + DuckDB cache) | 2 GB |
| Architecture | x86_64 or aarch64 | x86_64 (for Hyperscan) |

> **Note:** Intel Hyperscan (optional) requires x86_64. The default regexp backend runs on any architecture including Apple Silicon and ARM servers.

### Python Server (central management)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 core | 2 cores |
| RAM | 512 MB | 1 GB |
| Disk | 1 GB (DuckDB data) | 10 GB |

> **Render free tier**: 512 MB RAM, ephemeral disk. DuckDB is stored in `/tmp` and is wiped on redeploy. Fully functional for CVE distribution and inspect API.

### Apache Doris (optional — central analytics warehouse)

| Resource | Minimum |
|----------|---------|
| CPU | 4 cores (x86_64 only) |
| RAM | 8 GB FE + 16 GB BE (24 GB total minimum) |
| Disk | 20 GB |
| Architecture | **x86_64 only** — Doris does not support arm64 |

> Doris is entirely optional. AISS works fully without it using DuckDB only.

---

## Operating System

### Go Agent + Web Server Host

| OS | Versions |
|----|---------|
| Ubuntu | 20.04 LTS, 22.04 LTS, 24.04 LTS |
| Debian | 11 (Bullseye), 12 (Bookworm) |
| RHEL / CentOS / AlmaLinux | 8, 9 |
| Amazon Linux | 2, 2023 |
| macOS | 13+ (development only) |

### Python Server

Any Linux distribution with Docker, or any platform supported by Python 3.11+.

---

## Software Requirements

### Build Requirements (Go Agent)

| Software | Version | Notes |
|----------|---------|-------|
| Go | 1.22+ | Required for building from source |
| GCC / G++ | 11+ | Required — `go-duckdb` uses CGO |
| `build-essential` | any | Debian/Ubuntu meta-package for GCC toolchain |
| `pkg-config` | any | Required for CGO library discovery |
| Git | 2.0+ | For fetching Go modules |

Install on Ubuntu/Debian:
```bash
sudo apt-get install -y gcc g++ build-essential pkg-config git
```

Install on RHEL/CentOS:
```bash
sudo dnf install -y gcc gcc-c++ make pkg-config git
```

### Optional Build Dependencies (Go Agent)

| Software | Version | Build Tag | Notes |
|----------|---------|-----------|-------|
| Intel Hyperscan | 5.4+ | `hyperscan` | **x86_64 only**. Multi-pattern matching at Gbps speeds. Replaces default regexp engine. |
| libhyperscan-dev | 5.4+ | `hyperscan` | Debian pkg: `libhyperscan-dev` |
| ONNX Runtime | 1.18.0 | `onnx` | ML inference. Replaces heuristic scorer with trained GBM model. |

Install Hyperscan on Ubuntu/Debian:
```bash
sudo apt-get install -y libhyperscan-dev libhyperscan5
```

### Python Server Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| Python | 3.11+ | Runtime |
| fastapi | ≥ 0.115.0 | HTTP framework |
| uvicorn[standard] | ≥ 0.32.0 | ASGI server (uvloop + httptools) |
| sqlalchemy | ≥ 2.0.36 | ORM for DuckDB |
| duckdb | ≥ 1.0.0 | Embedded OLAP database |
| duckdb-engine | ≥ 0.13.0 | SQLAlchemy dialect for DuckDB |
| pydantic | ≥ 2.11.0 | Data validation |
| pydantic-settings | ≥ 2.7.0 | Environment-based config |
| httpx | ≥ 0.27.0 | Async HTTP client (CVE feed fetching) |
| python-jose[cryptography] | ≥ 3.3.0 | JWT signing/verification |
| passlib[bcrypt] | ≥ 1.7.4 | Password hashing |
| grpcio | ≥ 1.65.0 | Async gRPC server |
| grpcio-tools | ≥ 1.65.0 | protoc plugin (for regenerating stubs) |
| protobuf | ≥ 5.27.0 | Protobuf runtime |
| structlog | ≥ 24.1.0 | Structured JSON logging |
| prometheus-fastapi-instrumentator | ≥ 7.0.0 | `/metrics` endpoint |
| pymysql | ≥ 1.1.0 | Doris connection (MySQL protocol) |
| cryptography | ≥ 43.0.0 | pymysql TLS support |
| pytz | ≥ 2024.1 | Timezone support |
| aiofiles | ≥ 23.2.1 | Async file I/O |
| python-multipart | ≥ 0.0.9 | Form data parsing |
| alembic | ≥ 1.14.0 | DB migrations |

All Python dependencies are pinned in `server/requirements.txt`.

**ML model training only** (not needed at runtime):
```
scikit-learn, numpy, onnx, skl2onnx
```

### Docker Requirements

| Software | Version | Notes |
|----------|---------|-------|
| Docker Engine | 24.0+ | Required for containerised deployment |
| Docker Compose | v2.20+ | `docker compose` (v2 CLI plugin) |

### Web Server (for the C module)

| Software | Version |
|----------|---------|
| Nginx | 1.20+ |
| Apache HTTP Server | 2.4+ |

### Runtime — Web Server Host

The compiled C module (`ngx_http_aiss_module.so` / `mod_aiss.so`) requires no additional libraries at runtime. The Go agent binary is statically linked (DuckDB embedded via CGO).

### Optional — gRPC Stub Regeneration

Only needed if `proto/aiss.proto` is modified:

| Software | Version |
|---------|---------|
| protoc | 3.21+ |
| protoc-gen-go | latest |
| protoc-gen-go-grpc | latest |

Regenerate with:
```bash
bash proto/generate.sh
```

---

## Network Requirements

| Port | Direction | Component | Purpose |
|------|-----------|-----------|---------|
| 80 | Inbound | Nginx | HTTP (redirects to 443) |
| 443 | Inbound | Nginx | HTTPS (TLS 1.3) |
| 8080 | Inbound | AISS server | REST API (internal / Render) |
| 50051 | Agent → Server | gRPC | Telemetry + CVE streaming |
| 9030 | AISS server → Doris | MySQL | Analytics queries |
| 8040 | AISS server → Doris BE | HTTP | Stream Load |
| 443 (outbound) | Server → Internet | CVE feeds | NVD, CISA KEV, OSV.dev |

The Go agent communicates with Nginx/Apache via a **Unix Domain Socket** at `/tmp/aiss.sock` — no TCP port required on the web server host.

---

## Compliance Certification Requirements

For regulated environments (Singapore IM8 / MAS TRM), the following must be confirmed:

- TLS 1.2 minimum on all external interfaces (TLS 1.3 preferred)
- ECDSA P-384 or RSA-4096 certificates (not RSA-2048)
- Audit logs retained online ≥ 6 months, archived ≥ 12 months
- `AISS_SECRET_KEY` must be a cryptographically random 256-bit value
- Doris or equivalent OLAP store for audit log archiving
