#!/usr/bin/env bash
# ── vm_be_start.sh ────────────────────────────────────────────────────────────
# Run this script INSIDE the UTM x86_64 VM (Ubuntu 22.04 recommended).
#
# It:
#   1. Installs Docker CE if not already present
#   2. Pulls the Doris BE image
#   3. Starts the BE container pointing at the Doris FE on the Mac host
#
# Usage (run as root or with sudo):
#   bash vm_be_start.sh <MAC_HOST_IP> [VM_IP]
#
# Arguments:
#   MAC_HOST_IP  IP of the Mac on the UTM shared network (default: 192.168.64.1)
#   VM_IP        IP of this VM (auto-detected if omitted)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

MAC_HOST_IP="${1:-192.168.64.1}"
VM_IP="${2:-}"
BE_PORT=9050
BE_HTTP_PORT=8040
DORIS_IMAGE="apache/doris:be-4.1.1"
CONTAINER_NAME="aiss-doris-be"

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Auto-detect VM IP ─────────────────────────────────────────────────────────
if [[ -z "$VM_IP" ]]; then
    # Pick the first non-loopback IPv4 that can reach the Mac
    VM_IP=$(ip route get "$MAC_HOST_IP" 2>/dev/null \
            | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
    [[ -z "$VM_IP" ]] && error "Cannot auto-detect VM IP. Pass it as second argument."
fi

info "Mac host IP : $MAC_HOST_IP"
info "VM IP       : $VM_IP"
info "BE ports    : $BE_PORT (heartbeat)  $BE_HTTP_PORT (Stream Load)"

# ── 1. Install Docker CE ──────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    info "Docker not found — installing Docker CE..."
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg lsb-release
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
    info "Docker CE installed successfully."
else
    info "Docker already installed: $(docker --version)"
fi

# ── 2. Verify connectivity to FE ─────────────────────────────────────────────
info "Testing connectivity to Doris FE at $MAC_HOST_IP:9030 ..."
for i in $(seq 1 10); do
    if bash -c "echo > /dev/tcp/$MAC_HOST_IP/9030" 2>/dev/null; then
        info "Doris FE reachable on port 9030."
        break
    fi
    [[ $i -eq 10 ]] && error "Cannot reach $MAC_HOST_IP:9030 after 10 attempts. Check Mac firewall and that docker compose is running."
    warn "Attempt $i/10 — retrying in 3 s..."
    sleep 3
done

# ── 3. Stop any existing BE container ────────────────────────────────────────
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    info "Stopping existing $CONTAINER_NAME container..."
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm   "$CONTAINER_NAME" 2>/dev/null || true
fi

# ── 4. Pull image ─────────────────────────────────────────────────────────────
info "Pulling $DORIS_IMAGE ..."
docker pull "$DORIS_IMAGE"

# ── 5. Run BE ─────────────────────────────────────────────────────────────────
info "Starting Doris BE container..."
docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    --net host \
    --shm-size 4g \
    --ulimit nofile=65536:65536 \
    --ulimit memlock=-1:-1 \
    -e FE_MASTER_IP="$MAC_HOST_IP" \
    -e BE_IP="$VM_IP" \
    -e BE_PORT="$BE_PORT" \
    -e PRIORITY_NETWORKS="${VM_IP%.*}.0/24" \
    -v aiss-doris-be-data:/opt/apache-doris/be/storage \
    -v aiss-doris-be-log:/opt/apache-doris/be/log \
    "$DORIS_IMAGE"

info "Doris BE container started. Waiting for it to register with FE..."
for i in $(seq 1 30); do
    STATUS=$(docker inspect --format='{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "missing")
    if [[ "$STATUS" != "running" ]]; then
        error "Container exited unexpectedly. Run: docker logs $CONTAINER_NAME"
    fi
    if curl -sf "http://localhost:$BE_HTTP_PORT/api/health" &>/dev/null; then
        echo
        info "Doris BE is healthy and ready."
        break
    fi
    printf '.'
    [[ $i -eq 30 ]] && { echo; warn "BE not yet healthy after 30 s — still starting up. Check: docker logs $CONTAINER_NAME"; }
    sleep 2
done

echo
info "==================================================================="
info "Doris BE is running on this VM at $VM_IP:$BE_HTTP_PORT"
info "The Mac's .env.vm should contain:"
echo  "    DORIS_BE_HOST=$VM_IP"
echo  "    DORIS_BE_PORT=$BE_HTTP_PORT"
info "==================================================================="
info "To view logs : docker logs -f $CONTAINER_NAME"
info "To stop      : docker stop $CONTAINER_NAME"
