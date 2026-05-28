#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# AISS Agent Installer — AI Security Shield
#
# Usage:
#   curl -sSL https://your-server/install.sh | sudo bash
#
# Or with options:
#   sudo bash install.sh \
#       --server-url  https://aiss.example.com \
#       --api-key     <your-api-key> \
#       --socket      /tmp/aiss.sock \
#       --mode        shadow \
#       --web-server  nginx
#
# Supports: Ubuntu 20.04+, Debian 11+, RHEL/CentOS 8+
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
AISS_VERSION="${AISS_VERSION:-latest}"
AISS_SERVER_URL="${AISS_SERVER_URL:-}"
AISS_API_KEY="${AISS_API_KEY:-}"
AISS_SOCKET="${AISS_SOCKET:-/tmp/aiss.sock}"
AISS_MODE="${AISS_MODE:-shadow}"        # shadow = log-only; enforce = block
AISS_WEB_SERVER="${AISS_WEB_SERVER:-nginx}"
AISS_INSTALL_DIR="/opt/aiss"
AISS_CONFIG_DIR="/etc/aiss"
AISS_DATA_DIR="/var/lib/aiss"
AISS_LOG_DIR="/var/log/aiss"
AISS_RULES_DIR="/etc/aiss/rules"
AISS_USER="aiss"
AISS_GROUP="aiss"
AISS_BINARY="aiss-agent"
AISS_SERVICE="aiss-agent"

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${BLUE}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}══ $* ══${RESET}"; }

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --server-url)  AISS_SERVER_URL="$2";  shift 2 ;;
        --api-key)     AISS_API_KEY="$2";     shift 2 ;;
        --socket)      AISS_SOCKET="$2";      shift 2 ;;
        --mode)        AISS_MODE="$2";        shift 2 ;;
        --web-server)  AISS_WEB_SERVER="$2";  shift 2 ;;
        --version)     AISS_VERSION="$2";     shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--server-url URL] [--api-key KEY] [--socket PATH]"
            echo "          [--mode enforce|shadow] [--web-server nginx|apache]"
            exit 0
            ;;
        *) warn "Unknown argument: $1"; shift ;;
    esac
done

# ── Pre-flight checks ─────────────────────────────────────────────────────────
section "Pre-flight checks"

[[ $EUID -eq 0 ]] || error "This installer must be run as root (sudo)."

OS_ID="$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')"
OS_VER="$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"')"
ARCH="$(uname -m)"

info "Detected OS: ${OS_ID} ${OS_VER} (${ARCH})"

case "${ARCH}" in
    x86_64)  GOARCH="amd64" ;;
    aarch64) GOARCH="arm64" ;;
    *)       error "Unsupported architecture: ${ARCH}" ;;
esac

case "${AISS_WEB_SERVER}" in
    nginx|apache|apache2|httpd) ;;
    *) error "Unknown web server: ${AISS_WEB_SERVER}. Use 'nginx' or 'apache'." ;;
esac

case "${AISS_MODE}" in
    shadow|enforce) ;;
    *) error "Unknown mode: ${AISS_MODE}. Use 'shadow' or 'enforce'." ;;
esac

ok "Pre-flight checks passed"

# ── Create system user ────────────────────────────────────────────────────────
section "System user"

if ! id -u "${AISS_USER}" &>/dev/null; then
    useradd --system --shell /usr/sbin/nologin \
            --home-dir "${AISS_DATA_DIR}" \
            --create-home "${AISS_USER}"
    ok "Created system user: ${AISS_USER}"
else
    info "User ${AISS_USER} already exists — skipping"
fi

# ── Create directories ────────────────────────────────────────────────────────
section "Directories"

for dir in "${AISS_INSTALL_DIR}" "${AISS_CONFIG_DIR}" "${AISS_DATA_DIR}" \
           "${AISS_LOG_DIR}" "${AISS_RULES_DIR}/yara"; do
    mkdir -p "${dir}"
done

chown -R "${AISS_USER}:${AISS_GROUP}" "${AISS_DATA_DIR}" "${AISS_LOG_DIR}"
chmod 750 "${AISS_CONFIG_DIR}" "${AISS_DATA_DIR}"
ok "Directories created"

# ── Download Go agent binary ──────────────────────────────────────────────────
section "Agent binary"

BINARY_PATH="${AISS_INSTALL_DIR}/${AISS_BINARY}"

if [[ -n "${AISS_SERVER_URL}" ]]; then
    DOWNLOAD_URL="${AISS_SERVER_URL}/downloads/aiss-agent-linux-${GOARCH}"
    info "Downloading agent from ${DOWNLOAD_URL}"
    curl -sSfL "${DOWNLOAD_URL}" -o "${BINARY_PATH}" || {
        warn "Download failed — attempting to build from source"
        _build_from_source
    }
else
    # Build from source (assumes we're in the project directory)
    _build_from_source() {
        if command -v go &>/dev/null; then
            info "Building from source..."
            GO_SRC_DIR="$(dirname "$0")/.."
            cd "${GO_SRC_DIR}/aiss" 2>/dev/null || cd "${GO_SRC_DIR}"
            GOOS=linux GOARCH="${GOARCH}" go build -ldflags="-s -w" \
                -o "${BINARY_PATH}" ./cmd/agent/
            info "Built from source"
        else
            error "No server URL provided and Go not installed. Cannot obtain binary."
        fi
    }
    _build_from_source
fi

chmod 755 "${BINARY_PATH}"
ok "Agent binary installed at ${BINARY_PATH}"

# ── Install CVE patterns ──────────────────────────────────────────────────────
section "CVE patterns"

CVE_PATTERNS="${AISS_CONFIG_DIR}/cve_patterns.json"
if [[ ! -f "${CVE_PATTERNS}" ]]; then
    # Copy bundled patterns if they exist alongside the installer
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    BUNDLED="${SCRIPT_DIR}/../rules/hyperscan/cve_patterns.json"
    if [[ -f "${BUNDLED}" ]]; then
        cp "${BUNDLED}" "${CVE_PATTERNS}"
        ok "CVE patterns installed from bundle"
    else
        # Write a minimal bootstrap set
        cat > "${CVE_PATTERNS}" <<'EOF'
[
  {"id":1,"cve_id":"CVE-2021-44228","name":"Log4Shell","severity":"CRITICAL","cvss":10.0,
   "pattern":"\\$\\{jndi:(ldap|rmi|dns)://","flags":"CASELESS","affected_product":"log4j",
   "description":"Log4Shell JNDI injection"},
  {"id":2,"cve_id":"CVE-2014-6271","name":"Shellshock","severity":"CRITICAL","cvss":10.0,
   "pattern":"\\(\\)\\s*\\{\\s*[^}]*\\};\\s*","flags":"","affected_product":"bash",
   "description":"Shellshock bash injection"},
  {"id":3,"cve_id":"CVE-2022-22965","name":"Spring4Shell","severity":"CRITICAL","cvss":9.8,
   "pattern":"class\\.module\\.classLoader","flags":"CASELESS","affected_product":"spring",
   "description":"Spring4Shell"}
]
EOF
        ok "Minimal CVE pattern bootstrap written"
    fi
fi

# ── Install YARA rules ────────────────────────────────────────────────────────
section "YARA rules"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
for f in "${SCRIPT_DIR}/../rules/yara/"*.yar; do
    [[ -f "$f" ]] && cp "$f" "${AISS_RULES_DIR}/yara/" && info "Installed: $(basename "$f")"
done
ok "YARA rules installed"

# ── Write configuration ───────────────────────────────────────────────────────
section "Configuration"

AGENT_ID="aiss-$(hostname -s)-$(openssl rand -hex 4)"
CONFIG_FILE="${AISS_CONFIG_DIR}/aiss.conf"

if [[ -f "${CONFIG_FILE}" ]]; then
    info "Config file already exists — skipping (delete to regenerate)"
else
    cat > "${CONFIG_FILE}" <<EOF
# AISS Agent configuration
# Generated by installer on $(date -u +"%Y-%m-%dT%H:%M:%SZ")

agent_id    = "${AGENT_ID}"
mode        = "${AISS_MODE}"
socket_path = "${AISS_SOCKET}"

db_path     = "${AISS_DATA_DIR}/aiss.db"
log_level   = "info"

patterns_file = "${AISS_CONFIG_DIR}/cve_patterns.json"
rules_dir     = "${AISS_RULES_DIR}/yara"

ml_threshold          = 0.85
content_full_scan_limit   = 10240
content_sample_limit      = 1048576
verdict_cache_ttl     = 60
socket_timeout_ms     = 10
max_workers           = 16
telemetry_batch_size  = 200
telemetry_flush_sec   = 5.0

server_url  = "${AISS_SERVER_URL}"
api_key     = "${AISS_API_KEY}"
cve_sync_interval_sec = 3600
EOF
    chmod 640 "${CONFIG_FILE}"
    chown root:"${AISS_GROUP}" "${CONFIG_FILE}"
    ok "Configuration written to ${CONFIG_FILE}"
fi

# ── Systemd service ───────────────────────────────────────────────────────────
section "Systemd service"

cat > "/etc/systemd/system/${AISS_SERVICE}.service" <<EOF
[Unit]
Description=AISS Agent — AI Security Shield
Documentation=https://docs.aiss.io
After=network.target
Wants=network.target

[Service]
Type=simple
User=${AISS_USER}
Group=${AISS_GROUP}
ExecStart=${BINARY_PATH} -config ${CONFIG_FILE}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStartSec=30s
TimeoutStopSec=30s

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${AISS_DATA_DIR} ${AISS_LOG_DIR}
RuntimeDirectory=aiss
RuntimeDirectoryMode=0755
PrivateTmp=true
CapabilityBoundingSet=

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aiss-agent

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${AISS_SERVICE}"
ok "Systemd service enabled and started"

# ── Configure web server module ───────────────────────────────────────────────
section "Web server module"

case "${AISS_WEB_SERVER}" in
    nginx)
        _configure_nginx
        ;;
    apache|apache2|httpd)
        _configure_apache
        ;;
esac

# ── Nginx integration ─────────────────────────────────────────────────────────
_configure_nginx() {
    info "Configuring Nginx..."

    NGINX_CONF_DIR="/etc/nginx/conf.d"
    AISS_NGINX_CONF="${NGINX_CONF_DIR}/aiss.conf"

    if [[ ! -f "${AISS_NGINX_CONF}" ]]; then
        cat > "${AISS_NGINX_CONF}" <<NGINXEOF
# AISS — AI Security Shield module configuration
# Include this in your server blocks or at http {} level.
#
# If the module is compiled in (ngx_http_aiss_module.so), load it:
# load_module modules/ngx_http_aiss_module.so;

# Enable AISS inspection on all locations
aiss_enable  on;
aiss_socket  ${AISS_SOCKET};
aiss_timeout 10;
NGINXEOF
        ok "Nginx config written to ${AISS_NGINX_CONF}"
        info "Add 'include conf.d/aiss.conf;' to your nginx.conf if not already included"
    else
        info "Nginx AISS config already exists — skipping"
    fi

    # Test and reload nginx if running
    if systemctl is-active --quiet nginx 2>/dev/null; then
        nginx -t && systemctl reload nginx && ok "Nginx reloaded" || \
            warn "Nginx config test failed — check ${AISS_NGINX_CONF}"
    fi
}

# ── Apache integration ────────────────────────────────────────────────────────
_configure_apache() {
    info "Configuring Apache..."

    APACHE_MODS_DIR="/etc/apache2/mods-available"
    [[ -d "${APACHE_MODS_DIR}" ]] || APACHE_MODS_DIR="/etc/httpd/conf.modules.d"

    AISS_APACHE_CONF="/etc/apache2/conf-available/aiss.conf"
    [[ -d /etc/apache2 ]] || AISS_APACHE_CONF="/etc/httpd/conf.d/aiss.conf"

    if [[ ! -f "${AISS_APACHE_CONF}" ]]; then
        cat > "${AISS_APACHE_CONF}" <<APACHEEOF
# AISS — AI Security Shield module configuration
# Activate with: a2enconf aiss && systemctl reload apache2

<IfModule mod_aiss.c>
    <Location />
        AISSEnable  On
        AISSSocket  ${AISS_SOCKET}
        AISSTimeout 10
    </Location>
</IfModule>
APACHEEOF
        ok "Apache config written to ${AISS_APACHE_CONF}"
    fi

    # Enable on Debian/Ubuntu systems
    if command -v a2enconf &>/dev/null; then
        a2enconf aiss 2>/dev/null || true
        systemctl is-active --quiet apache2 && \
            systemctl reload apache2 && ok "Apache reloaded" || true
    fi
}

# ── Agent registration ────────────────────────────────────────────────────────
section "Agent registration"

if [[ -n "${AISS_SERVER_URL}" && -n "${AISS_API_KEY}" ]]; then
    HOSTNAME="$(hostname -f)"
    IP="$(hostname -I | awk '{print $1}')"

    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${AISS_SERVER_URL}/v1/agents/register" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: ${AISS_API_KEY}" \
        -d "{
            \"agent_id\":\"${AGENT_ID}\",
            \"hostname\":\"${HOSTNAME}\",
            \"ip\":\"${IP}\",
            \"server_type\":\"${AISS_WEB_SERVER}\",
            \"api_key\":\"${AISS_API_KEY}\"
        }" 2>/dev/null) || HTTP_STATUS="000"

    if [[ "${HTTP_STATUS}" =~ ^2 ]]; then
        ok "Agent registered with central server (ID: ${AGENT_ID})"
    else
        warn "Agent registration returned HTTP ${HTTP_STATUS} — check credentials"
    fi
else
    warn "No server URL or API key provided — agent will run in standalone mode"
fi

# ── Post-install health check ─────────────────────────────────────────────────
section "Health check"

sleep 2  # give the service a moment to start

if systemctl is-active --quiet "${AISS_SERVICE}"; then
    ok "AISS agent service is running"
else
    warn "AISS agent service not running — check: journalctl -u ${AISS_SERVICE} -n 50"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
section "Installation complete"

echo -e "
${GREEN}${BOLD}AISS Agent successfully installed!${RESET}

  Binary:    ${BINARY_PATH}
  Config:    ${CONFIG_FILE}
  DB:        ${AISS_DATA_DIR}/aiss.db
  Socket:    ${AISS_SOCKET}
  Mode:      ${BOLD}${AISS_MODE}${RESET}
  Agent ID:  ${AGENT_ID}

${BOLD}Useful commands:${RESET}
  systemctl status ${AISS_SERVICE}          # Check agent status
  systemctl reload ${AISS_SERVICE}          # Reload config
  journalctl -u ${AISS_SERVICE} -f          # Stream logs
  kill -HUP \$(pidof ${AISS_BINARY})        # Hot-reload YARA rules

${YELLOW}NOTE:${RESET} Agent is running in ${BOLD}${AISS_MODE}${RESET} mode.
$( [[ "${AISS_MODE}" == "shadow" ]] && \
echo "  Switch to enforce mode when you're confident in the rules:
  sed -i 's/mode.*=.*shadow/mode = enforce/' ${CONFIG_FILE}
  systemctl restart ${AISS_SERVICE}" )
"
