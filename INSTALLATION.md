# INSTALLATION.md — AISS Installation Guide

This guide covers three deployment paths:

1. **[Docker Compose](#1-docker-compose-full-stack)** — full stack locally or on a VM (recommended for evaluation)
2. **[Render.com](#2-render-deployment-server-only)** — Python server on free cloud infrastructure
3. **[Manual install](#3-manual-installation)** — Go agent + Python server on bare metal / existing servers

---

## 1. Docker Compose — Full Stack

### Prerequisites

- Docker Engine 24.0+
- Docker Compose v2.20+
- 4 GB RAM minimum (8 GB recommended if running Doris BE locally)

### Clone the repository

```bash
git clone https://git.cloudloyalty.in/CloudLoyalty/CloudServerSecurity.git
cd CloudServerSecurity
```

### Generate TLS certificates

```bash
bash certs/generate-certs.sh
```

This creates a local CA and certificates for Nginx, the AISS agent, the WAF proxy, and gRPC mTLS in `certs/`.

### Configure environment

```bash
cp aiss.dev.conf.example aiss.dev.conf
# Edit aiss.dev.conf and set api_key to a random secret
```

Set `AISS_SECRET_KEY` (required for production):

```bash
export AISS_SECRET_KEY=$(openssl rand -base64 32)
```

### Start the stack

**x86_64 hosts** (includes local Doris BE):
```bash
docker compose --profile local-be up -d
```

**Apple Silicon / arm64** (Doris BE requires x86_64 — run a UTM VM for the BE, or skip Doris):
```bash
docker compose up -d
```

### Verify

```bash
# Server health
curl http://localhost:8080/health
# {"status":"ok","version":"1.0.0"}

# Agent socket is live
test -S /tmp/aiss.sock && echo "Agent socket OK"

# Nginx is proxying
curl -I http://localhost/
```

### Doris setup (first time only)

If using Doris, after both FE and BE are healthy, register the BE:

```bash
mysql -h 127.0.0.1 -P 9030 -u root -e \
  "ALTER SYSTEM ADD BACKEND '172.20.0.11:9050';"
```

Wait ~60 seconds, then check:
```bash
mysql -h 127.0.0.1 -P 9030 -u root -e "SHOW BACKENDS\G"
# Alive: true
```

---

## 2. Render Deployment — Server Only

The Python server can be deployed on Render's free tier using the included `render.yaml` Blueprint.

### Steps

1. Push the repository to GitHub or GitLab.
2. Go to [dashboard.render.com](https://dashboard.render.com/new/blueprint).
3. Connect the repository and select the `render.yaml` file.
4. Click **Apply**. Render will:
   - Build the Docker image from `server/Dockerfile`
   - Inject `PORT`, `AISS_SECRET_KEY` (auto-generated), and all other env vars from `render.yaml`
5. Wait for the deploy to show **Live** (3–5 minutes for the first build).

### First login

The `AISS_SECRET_KEY` shown in Render's **Environment** tab is your admin API key:

```bash
curl https://<your-service>.onrender.com/health
# {"status":"ok","version":"1.0.0"}

curl https://<your-service>.onrender.com/v1/updates \
  -H "X-API-Key: <AISS_SECRET_KEY value>"
# Returns CVE signatures
```

### Issue a dedicated API key

```bash
curl -X POST https://<your-service>.onrender.com/v1/auth/keys \
  -H "X-API-Key: <AISS_SECRET_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"description":"my-app","role":"agent","expires_in_days":365}'
```

### Wire into Vercel middleware

Set these env vars in your Vercel project:

| Variable | Value |
|----------|-------|
| `AISS_WAF_URL` | `https://<your-service>.onrender.com` |
| `AISS_API_KEY` | The agent key from the step above |

Then in your Next.js `middleware.ts`:

```typescript
const WAF_URL = process.env.AISS_WAF_URL;
const API_KEY = process.env.AISS_API_KEY;

export async function middleware(request: NextRequest) {
  const res = await fetch(`${WAF_URL}/v1/inspect`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-API-Key": API_KEY },
    body: JSON.stringify({
      method: request.method,
      uri: request.nextUrl.pathname,
      query_string: request.nextUrl.search.slice(1),
      client_ip: request.headers.get("x-forwarded-for") ?? "",
      user_agent: request.headers.get("user-agent") ?? "",
      source_app: "my-vercel-app",
    }),
    signal: AbortSignal.timeout(4000),
  });
  const verdict = await res.json();
  if (verdict.action === "BLOCK") {
    return new NextResponse("Forbidden", { status: 403 });
  }
  return NextResponse.next();
}
```

> **Note:** Render free instances spin down after 15 minutes of inactivity. The first request after spin-down may take 30–50 seconds. Upgrade to a paid instance to avoid cold starts in production.

---

## 3. Manual Installation

### 3a. Install the Python Server

#### System packages

```bash
# Ubuntu / Debian
sudo apt-get update && sudo apt-get install -y python3.11 python3.11-venv python3-pip

# RHEL / CentOS
sudo dnf install -y python3.11 python3.11-pip
```

#### Application setup

```bash
cd server
python3.11 -m venv .venv
source .venv/bin/activate
pip install --no-cache-dir -r requirements.txt
```

#### Configure

Create `/etc/aiss/server.env`:

```env
AISS_ENVIRONMENT=production
AISS_DATABASE_URL=duckdb:////data/aiss.duckdb
AISS_SECRET_KEY=<256-bit random key: openssl rand -base64 32>
AISS_ALGORITHM=HS256
AISS_ALLOWED_ORIGINS=["https://your-app.example.com"]
AISS_RATE_LIMIT_PER_MINUTE=300
ENABLE_METRICS=true

# Optional — Apache Doris
AISS_DORIS_HOST=your-doris-fe.example.com
AISS_DORIS_PORT=9030
AISS_DORIS_USER=root
AISS_DORIS_PASSWORD=
AISS_DORIS_DATABASE=aiss
```

#### Run as a systemd service

```bash
sudo tee /etc/systemd/system/aiss-server.service <<EOF
[Unit]
Description=AISS Central Server
After=network.target

[Service]
Type=simple
User=aiss
WorkingDirectory=/opt/aiss/server
EnvironmentFile=/etc/aiss/server.env
ExecStart=/opt/aiss/server/.venv/bin/uvicorn app.main:app \
    --host 0.0.0.0 --port 8080 --workers 1 --loop uvloop
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now aiss-server
```

Verify:
```bash
curl http://localhost:8080/health
```

---

### 3b. Install the Go Agent

#### Build from source

```bash
# Install Go 1.22+
wget -qO /tmp/go.tar.gz https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf /tmp/go.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Build the agent (standard — no Hyperscan/ONNX)
make build
# Binary: dist/aiss-agent

# Build with Hyperscan (x86_64 only, faster pattern matching)
sudo apt-get install -y libhyperscan-dev
go get github.com/flier/gohs@latest
make build LDFLAGS="-tags hyperscan"
# or: go build -tags hyperscan -o dist/aiss-agent ./cmd/agent

# Build with ONNX ML inference
go get github.com/yalue/onnxruntime_go@latest
make build LDFLAGS="-tags onnx"
```

#### One-line installer (Ubuntu/Debian/RHEL)

```bash
sudo bash scripts/install.sh \
    --server-url https://your-aiss-server.example.com \
    --api-key    <your-api-key> \
    --mode       shadow \
    --web-server nginx
```

The installer:
- Creates `aiss` system user
- Installs binary to `/opt/aiss/aiss-agent`
- Writes config to `/etc/aiss/aiss.conf`
- Copies YARA rules to `/etc/aiss/rules/yara/`
- Installs and starts the `aiss-agent` systemd service
- Writes Nginx or Apache config snippet

Switch to enforce mode when ready:
```bash
sudo sed -i 's/mode.*=.*shadow/mode = enforce/' /etc/aiss/aiss.conf
sudo systemctl restart aiss-agent
```

#### Manual configuration

Edit `/etc/aiss/aiss.conf`:

```toml
agent_id    = "aiss-prod-web01"
mode        = "shadow"           # shadow (log only) or enforce (block)
socket_path = "/tmp/aiss.sock"

server_url  = "https://your-aiss-server.example.com"
api_key     = "<api-key>"

db_path       = "/var/lib/aiss/aiss.db"
patterns_file = "/etc/aiss/cve_patterns.json"
rules_dir     = "/etc/aiss/rules/yara"
log_level     = "info"

ml_block_threshold    = 0.85
verdict_cache_ttl     = 60
socket_timeout_ms     = 10
max_workers           = 32
telemetry_batch_size  = 200
telemetry_flush_sec   = 5.0
cve_sync_interval_sec = 3600
```

All values can also be set via `AISS_<KEY>` environment variables (e.g. `AISS_MODE=enforce`).

---

### 3c. Nginx Module Integration

#### Load the module

Add to `nginx.conf` (before `events {}`):
```nginx
load_module modules/ngx_http_aiss_module.so;
```

#### Enable per virtual host

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    # Enable AISS inspection
    aiss_enable  on;
    aiss_socket  /tmp/aiss.sock;
    aiss_timeout 10;   # ms; requests exceeding this are passed (fail-open)

    location / {
        proxy_pass http://backend;
    }
}
```

#### Build the module against your Nginx version

```bash
cd module/nginx
NGINX_VERSION=$(nginx -v 2>&1 | grep -oP '\d+\.\d+\.\d+')
wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
tar xzf nginx-${NGINX_VERSION}.tar.gz

cd nginx-${NGINX_VERSION}
./configure \
    --add-dynamic-module=../module/nginx \
    --with-compat \
    $(nginx -V 2>&1 | grep -oP "(?<=configure arguments: ).*")

make modules
sudo cp objs/ngx_http_aiss_module.so /etc/nginx/modules/
sudo nginx -t && sudo systemctl reload nginx
```

---

### 3d. Apache Module Integration

#### Enable the module

```bash
sudo cp module/apache/mod_aiss.so /usr/lib/apache2/modules/
sudo tee /etc/apache2/mods-available/aiss.load <<EOF
LoadModule aiss_module /usr/lib/apache2/modules/mod_aiss.so
EOF
sudo a2enmod aiss
```

#### Configure

```apache
<IfModule mod_aiss.c>
    <Location />
        AISSEnable  On
        AISSSocket  /tmp/aiss.sock
        AISSTimeout 10
    </Location>
</IfModule>
```

```bash
sudo systemctl reload apache2
```

---

## Configuration Reference

### Server Environment Variables

All variables use the `AISS_` prefix.

| Variable | Default | Description |
|----------|---------|-------------|
| `AISS_ENVIRONMENT` | `development` | `development` or `production` |
| `AISS_DATABASE_URL` | `duckdb:///:memory:` | DuckDB file path. Use `duckdb:////data/aiss.duckdb` in production |
| `AISS_SECRET_KEY` | `CHANGE_ME_IN_PRODUCTION_USE_256_BIT_KEY` | HMAC key for JWT + API key hashing + audit chain. **Must be changed in production** |
| `AISS_ALGORITHM` | `HS256` | JWT algorithm: `HS256` or `RS256` |
| `AISS_ALLOWED_ORIGINS` | `["http://localhost:3000"]` | JSON array of CORS-allowed origins |
| `AISS_RATE_LIMIT_PER_MINUTE` | `1000` | Max requests per IP per minute |
| `AISS_GRPC_PORT` | `50051` | gRPC server port |
| `AISS_NVD_API_KEY` | `` | NVD API key (higher rate limits — get free at nvd.nist.gov) |
| `AISS_CVE_SYNC_INTERVAL_HOURS` | `1` | CVE feed refresh interval |
| `AISS_DORIS_HOST` | `localhost` | Doris FE host (leave blank to disable Doris) |
| `ENABLE_METRICS` | `false` | Set `true` to expose `/metrics` for Prometheus |

### Agent Configuration Keys

| Key | Default | Description |
|-----|---------|-------------|
| `agent_id` | auto-generated | Unique identifier for this agent |
| `mode` | `enforce` | `enforce` (block threats) or `shadow` (log only) |
| `socket_path` | `/tmp/aiss.sock` | Unix socket path for Nginx/Apache communication |
| `server_url` | `http://localhost:8080` | AISS central server URL |
| `api_key` | `` | API key for authenticating with the server |
| `ml_block_threshold` | `0.85` | ML score above which requests are blocked (0.0–1.0) |
| `verdict_cache_ttl` | `60` | Seconds to cache IP verdicts |
| `socket_timeout_ms` | `10` | Timeout for Nginx/Apache socket calls (fail-open on exceed) |
| `max_workers` | `CPU × 32` | Goroutine pool size |

---

## Operational Commands

### Agent

```bash
systemctl status aiss-agent            # Status
systemctl reload aiss-agent            # Reload config
journalctl -u aiss-agent -f            # Stream logs
kill -HUP $(pidof aiss-agent)          # Hot-reload CVE patterns and YARA rules
```

### Server

```bash
# Query the live DuckDB directly
duckdb /data/aiss.duckdb \
  "SELECT action, count(*) FROM security_events GROUP BY action"

# Check CVE signature count
curl http://localhost:8080/v1/updates \
  -H "X-API-Key: $KEY" | python3 -m json.tool | grep -c cve_id

# Verify audit chain integrity
curl http://localhost:8080/v1/audit/verify \
  -H "X-API-Key: $KEY"
```

### Load testing

```bash
# Requires wrk
make load-test
# wrk -t12 -c400 -d30s --latency http://localhost/api/test
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `cannot start a transaction within a transaction` | Two threads opened `SessionLocal()` without `_db_lock` | Ensure all DB access in the Python server holds `_db_lock` before calling `SessionLocal()` |
| `MultipleResultsFound` on startup | Duplicate rows in `cve_signatures` during CVE sync | Use `.scalars().first()` instead of `.scalar_one_or_none()` |
| Agent socket `Permission denied` | `www-data` cannot access `/tmp/aiss.sock` | Add `www-data` to the `aiss` group: `usermod -aG aiss www-data` |
| Nginx returns 500 after module load | Module compiled against wrong Nginx version | Rebuild the module against the exact `nginx -v` version |
| Render deploy health check fails | `startCommand` set in `render.yaml` for a Docker service | Remove `startCommand` — Render Docker services use the Dockerfile `CMD` |
| All requests blocked on startup | CVE sync holding `_db_lock` during large batch | CVE sync acquires the lock per-CVE; wait for initial sync to complete (~60 s) |
| `X-API-Key` returns 403 on fresh Render deploy | No keys seeded in empty DB | Use the `AISS_SECRET_KEY` env var value directly as the `X-API-Key` header |
