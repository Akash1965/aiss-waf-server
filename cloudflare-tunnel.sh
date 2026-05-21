#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# AISS Cloudflare Tunnel — Real-World Integration Launcher
#
# This script:
#   1. Verifies / installs cloudflared (macOS Homebrew)
#   2. Starts the AISS Docker Compose stack
#   3. Waits for the AISS server to be healthy
#   4. Opens a Cloudflare Quick Tunnel (no account, no domain needed)
#      → prints the public HTTPS URL for use as AISS_WAF_URL in Vercel
#   5. Optionally issues a new agent API key for the Vercel middleware
#
# Usage:
#   chmod +x cloudflare-tunnel.sh
#   ./cloudflare-tunnel.sh
#
# The quick-tunnel URL is temporary (changes every restart).  For a stable URL
# with a named tunnel (free Cloudflare account required) see the comment block
# at the bottom of this file.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m';  BOLD='\033[1m';     RESET='\033[0m'

info()    { echo -e "${CYAN}[AISS]${RESET} $*"; }
success() { echo -e "${GREEN}[AISS]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[AISS]${RESET} $*"; }
error()   { echo -e "${RED}[AISS]${RESET} $*" >&2; }
bold()    { echo -e "${BOLD}$*${RESET}"; }

# ── Configuration ─────────────────────────────────────────────────────────────
AISS_SERVER_PORT=${AISS_SERVER_PORT:-8080}          # FastAPI server local port
COMPOSE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/docker-compose.yml"
ADMIN_KEY=${AISS_ADMIN_KEY:-"dev-key"}              # Used for API key issuance
TUNNEL_URL_FILE="/tmp/aiss_tunnel_url.txt"

# ── Step 1: Install cloudflared ───────────────────────────────────────────────
install_cloudflared() {
    if command -v cloudflared &>/dev/null; then
        CFDV=$(cloudflared --version 2>&1 | head -1)
        success "cloudflared already installed: $CFDV"
        return 0
    fi

    info "cloudflared not found — installing via Homebrew..."
    if ! command -v brew &>/dev/null; then
        error "Homebrew not found.  Install it from https://brew.sh then re-run."
        error "Or install cloudflared manually: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
        exit 1
    fi
    brew install cloudflared
    success "cloudflared installed."
}

# ── Step 2: Start Docker Compose stack ───────────────────────────────────────
start_compose() {
    info "Starting AISS Docker Compose stack..."
    docker compose -f "$COMPOSE_FILE" up -d --build

    info "Waiting for AISS server to become healthy on port $AISS_SERVER_PORT..."
    local retries=30
    until curl -sf "http://localhost:${AISS_SERVER_PORT}/health" >/dev/null 2>&1; do
        retries=$((retries - 1))
        if [[ $retries -le 0 ]]; then
            error "AISS server did not become healthy in 60 seconds."
            error "Check logs: docker compose -f $COMPOSE_FILE logs aiss-server"
            exit 1
        fi
        sleep 2
    done
    success "AISS server is healthy."
}

# ── Step 3: Start Cloudflare Quick Tunnel ─────────────────────────────────────
start_tunnel() {
    info "Opening Cloudflare Quick Tunnel → http://localhost:${AISS_SERVER_PORT} ..."
    info "(Quick tunnels are free, no account needed, URL changes on restart)"

    # Run cloudflared in background, capture its stderr (which contains the URL)
    cloudflared tunnel --url "http://localhost:${AISS_SERVER_PORT}" \
        --no-autoupdate \
        2>&1 | tee /tmp/cloudflared_output.log &
    TUNNEL_PID=$!
    echo $TUNNEL_PID > /tmp/aiss_tunnel.pid

    # Wait for the trycloudflare.com URL to appear in the log
    info "Waiting for tunnel URL..."
    local retries=30
    local tunnel_url=""
    while [[ -z "$tunnel_url" && $retries -gt 0 ]]; do
        sleep 2
        retries=$((retries - 1))
        tunnel_url=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /tmp/cloudflared_output.log 2>/dev/null | head -1 || true)
    done

    if [[ -z "$tunnel_url" ]]; then
        error "Failed to extract tunnel URL from cloudflared output."
        error "cloudflared log:"
        cat /tmp/cloudflared_output.log
        exit 1
    fi

    echo "$tunnel_url" > "$TUNNEL_URL_FILE"
    export TUNNEL_URL="$tunnel_url"
}

# ── Step 4: Issue Vercel agent API key ────────────────────────────────────────
issue_agent_key() {
    local tunnel_url="$1"

    info "Issuing a new 'agent' API key for Vercel middleware..."
    local response
    response=$(curl -sf -X POST "${tunnel_url}/v1/auth/keys" \
        -H "X-API-Key: ${ADMIN_KEY}" \
        -H "Content-Type: application/json" \
        -d '{"description":"vercel-middleware-agent","role":"agent","expires_in_days":365}' \
        2>&1) || {
        warn "Could not issue API key automatically (server may be in dev mode)."
        warn "Issue one manually: POST ${tunnel_url}/v1/auth/keys"
        return 1
    }

    local raw_key
    raw_key=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])" 2>/dev/null || true)

    if [[ -z "$raw_key" ]]; then
        warn "Response from /v1/auth/keys: $response"
        warn "Could not parse API key.  Issue one manually."
        return 1
    fi

    echo "$raw_key"
}

# ── Step 5: Print final instructions ─────────────────────────────────────────
print_summary() {
    local tunnel_url="$1"
    local api_key="$2"

    echo ""
    bold "═══════════════════════════════════════════════════════════════"
    bold "  AISS WAF — Real-World Integration Ready"
    bold "═══════════════════════════════════════════════════════════════"
    echo ""
    success "Cloudflare Tunnel URL:  ${CYAN}${tunnel_url}${RESET}"
    echo ""
    bold "  Next steps:"
    echo ""
    echo "  1. Copy these two values into Vercel Dashboard:"
    echo "     Settings → Environment Variables → Production"
    echo ""
    echo -e "     ${BOLD}AISS_WAF_URL${RESET} = ${GREEN}${tunnel_url}${RESET}"
    if [[ -n "$api_key" ]]; then
        echo -e "     ${BOLD}AISS_API_KEY${RESET} = ${GREEN}${api_key}${RESET}"
    else
        echo -e "     ${BOLD}AISS_API_KEY${RESET} = <issue manually via ${tunnel_url}/v1/auth/keys>"
    fi
    echo ""
    echo "  2. Also set them locally in nit-mca-forum/.env.local:"
    echo "       AISS_WAF_URL=${tunnel_url}"
    if [[ -n "$api_key" ]]; then
        echo "       AISS_API_KEY=${api_key}"
    fi
    echo ""
    echo "  3. Redeploy the forum on Vercel:"
    echo "       cd $(dirname "$COMPOSE_FILE")/../nit-mca-forum"
    echo "       vercel --prod"
    echo "     Or push to your main branch and let Vercel auto-deploy."
    echo ""
    echo "  4. Test the WAF by sending a test SQLi probe:"
    echo "       curl -sk '${tunnel_url}/?id=1%20OR%201=1' -v"
    echo "     You should receive a 403 Blocked response."
    echo ""
    bold "  Dashboard:  ${CYAN}http://localhost:3000${RESET}  (run: cd aiss-dashboard && npm run dev)"
    bold "  AISS API:   ${CYAN}${tunnel_url}/docs${RESET}"
    echo ""
    warn "Quick-tunnel URL changes on every restart."
    warn "For a stable named tunnel, see: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/"
    echo ""
    bold "═══════════════════════════════════════════════════════════════"
    echo ""
    info "Tunnel is running (PID $TUNNEL_PID). Press Ctrl+C to stop everything."
}

# ── Cleanup on exit ───────────────────────────────────────────────────────────
cleanup() {
    echo ""
    info "Shutting down..."
    [[ -n "${TUNNEL_PID:-}" ]] && kill "$TUNNEL_PID" 2>/dev/null || true
    info "Tunnel stopped.  To stop Docker stack: docker compose -f $COMPOSE_FILE down"
}
trap cleanup EXIT INT TERM

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    bold ""
    bold "  AISS WAF — Cloudflare Tunnel Launcher"
    bold "  ───────────────────────────────────────"
    echo ""

    install_cloudflared
    start_compose
    start_tunnel

    local api_key=""
    api_key=$(issue_agent_key "$TUNNEL_URL") || true

    print_summary "$TUNNEL_URL" "$api_key"

    # Keep the script alive so the tunnel keeps running
    wait "$TUNNEL_PID"
}

main "$@"

# ─────────────────────────────────────────────────────────────────────────────
# Named Tunnel Setup (stable URL — requires free Cloudflare account)
# ─────────────────────────────────────────────────────────────────────────────
#
# 1. Log in to Cloudflare:
#      cloudflared tunnel login
#
# 2. Create a named tunnel:
#      cloudflared tunnel create aiss-waf
#
# 3. Create config file ~/.cloudflared/config.yml:
#      tunnel: <TUNNEL_ID from step 2>
#      credentials-file: /Users/<you>/.cloudflared/<TUNNEL_ID>.json
#      ingress:
#        - hostname: aiss.yourdomain.com
#          service: http://localhost:8080
#        - service: http_status:404
#
# 4. Route DNS:
#      cloudflared tunnel route dns aiss-waf aiss.yourdomain.com
#
# 5. Run:
#      cloudflared tunnel run aiss-waf
#
# Your AISS_WAF_URL will then be https://aiss.yourdomain.com (permanent).
# ─────────────────────────────────────────────────────────────────────────────
