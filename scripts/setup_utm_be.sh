#!/usr/bin/env bash
# ── setup_utm_be.sh ───────────────────────────────────────────────────────────
# Runs on the Mac. Guides you through setting up a UTM x86_64 VM to host the
# Doris BE, then wires everything back to the Mac's docker-compose stack.
#
# Prerequisites on the Mac:
#   • UTM installed  (https://mac.getutm.app  — free)
#   • Ubuntu 22.04 x86_64 VM already created in UTM and booted
#   • SSH access to the VM (or you can paste the VM script manually)
#
# Usage:
#   bash scripts/setup_utm_be.sh [VM_IP]
#
# If VM_IP is omitted the script will ask for it interactively.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${NC}"; }
prompt()  { echo -e "${YELLOW}▶${NC} $*"; }

# ── Step 0: Check we are on Apple Silicon ────────────────────────────────────
step "Checking architecture"
ARCH=$(uname -m)
if [[ "$ARCH" != "arm64" ]]; then
    warn "This script is intended for Apple Silicon (arm64). Detected: $ARCH"
    warn "On x86_64 you can run the Doris BE directly. Use --profile local-be:"
    echo "  docker compose --profile local-be up --build --detach"
    exit 0
fi
info "Apple Silicon detected — UTM VM approach is the right choice."

# ── Step 1: UTM installation check ───────────────────────────────────────────
step "Checking UTM"
if ! open -Ra UTM 2>/dev/null && [[ ! -d "/Applications/UTM.app" ]]; then
    warn "UTM not found in /Applications."
    prompt "Install UTM now? (requires Homebrew)"
    read -r -p "  [y/N] " REPLY
    if [[ "$REPLY" =~ ^[Yy]$ ]]; then
        if command -v brew &>/dev/null; then
            brew install --cask utm
        else
            echo "  Homebrew not found. Download UTM manually from https://mac.getutm.app"
            echo "  Then re-run this script."
            exit 1
        fi
    else
        echo "  Download UTM from https://mac.getutm.app, install it, then re-run."
        exit 1
    fi
else
    info "UTM is installed."
fi

# ── Step 2: Create the UTM VM (manual instructions) ──────────────────────────
step "UTM VM configuration"
cat <<'INSTRUCTIONS'

  If you haven't created the Ubuntu VM yet, follow these steps in UTM:

  1. Open UTM → click "+"  → "Virtualize" (NOT Emulate) is NOT available for x86_64
     on Apple Silicon — choose "Emulate" → "Linux"
  2. Architecture : x86_64
  3. Boot ISO     : Ubuntu Server 22.04 LTS  (download from https://ubuntu.com/download/server)
  4. CPU cores    : 2 (minimum)  →  4 recommended
  5. RAM          : 4096 MB minimum  →  6144 MB recommended (Doris BE is memory-hungry)
  6. Disk         : 30 GB minimum
  7. Network      : Shared Network  (UTM default — gives VM IP in 192.168.64.x range)
  8. Complete the Ubuntu install, enable SSH:
       sudo apt-get install -y openssh-server
       sudo systemctl enable --now ssh
  9. Note the VM's IP:
       ip addr show | grep 'inet ' | grep -v 127

INSTRUCTIONS

# ── Step 3: Get VM IP ─────────────────────────────────────────────────────────
step "VM IP address"
VM_IP="${1:-}"
if [[ -z "$VM_IP" ]]; then
    prompt "Enter the IP address of your UTM VM (e.g. 192.168.64.2):"
    read -r VM_IP
fi
# Basic validation
if ! [[ "$VM_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    error "Invalid IP address: $VM_IP"
fi

# ── Step 4: Detect the Mac's IP reachable from the VM ────────────────────────
step "Detecting Mac host IP"
# On UTM shared network the Mac gateway is always the first host in the VM's subnet
MAC_UTM_IP=$(echo "$VM_IP" | awk -F. '{print $1"."$2"."$3".1"}')
# Double-check by looking at the Mac's own interfaces
MAC_ACTUAL_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "$MAC_UTM_IP")
info "Mac UTM gateway  : $MAC_UTM_IP"
info "Mac interface IP : $MAC_ACTUAL_IP"
info "Using $MAC_UTM_IP as the IP the VM will use to reach the Doris FE."
MAC_HOST_IP="$MAC_UTM_IP"

# ── Step 5: Verify SSH connectivity ──────────────────────────────────────────
step "Verifying SSH connectivity to VM"
SSH_USER="${SSH_USER:-ubuntu}"
prompt "SSH user for the VM (default: ubuntu):"
read -r -p "  [ubuntu] " SSH_USER_INPUT
SSH_USER="${SSH_USER_INPUT:-ubuntu}"

info "Testing SSH connection to $SSH_USER@$VM_IP ..."
if ! ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
         "$SSH_USER@$VM_IP" "echo ok" &>/dev/null; then
    warn "SSH connection failed. You can still proceed manually:"
    echo "  1. Copy scripts/vm_be_start.sh to the VM:"
    echo "       scp $SCRIPT_DIR/vm_be_start.sh $SSH_USER@$VM_IP:~/"
    echo "  2. SSH into the VM and run:"
    echo "       sudo bash ~/vm_be_start.sh $MAC_HOST_IP $VM_IP"
    echo "  3. Then come back and re-run this script to generate .env.vm"
    echo
    MANUAL_MODE=true
else
    info "SSH connection successful."
    MANUAL_MODE=false
fi

# ── Step 6: Copy and run vm_be_start.sh on the VM ────────────────────────────
step "Deploying Doris BE on the VM"
if [[ "$MANUAL_MODE" == "false" ]]; then
    info "Copying vm_be_start.sh to VM..."
    scp -o StrictHostKeyChecking=no \
        "$SCRIPT_DIR/vm_be_start.sh" \
        "$SSH_USER@$VM_IP:~/vm_be_start.sh"

    info "Running vm_be_start.sh on VM (this will take a few minutes for Docker install + image pull)..."
    ssh -o StrictHostKeyChecking=no -t "$SSH_USER@$VM_IP" \
        "sudo bash ~/vm_be_start.sh $MAC_HOST_IP $VM_IP"
else
    info "Skipping automatic deploy (manual mode)."
    echo "  Once the BE is running on the VM, press ENTER to continue."
    read -r
fi

# ── Step 7: Verify BE is reachable from the Mac ──────────────────────────────
step "Verifying BE health from Mac"
BE_URL="http://$VM_IP:8040/api/health"
info "Polling $BE_URL ..."
for i in $(seq 1 20); do
    if curl -sf "$BE_URL" &>/dev/null; then
        info "Doris BE is healthy and reachable from the Mac."
        break
    fi
    [[ $i -eq 20 ]] && error "Doris BE at $VM_IP:8040 not responding after 40 s. Check: ssh $SSH_USER@$VM_IP 'docker logs aiss-doris-be'"
    printf '.'
    sleep 2
done
echo

# ── Step 8: Generate .env.vm ─────────────────────────────────────────────────
step "Generating .env.vm"
ENV_FILE="$REPO_ROOT/.env.vm"
cat > "$ENV_FILE" <<EOF
# Auto-generated by setup_utm_be.sh on $(date)
# Doris BE is running in UTM VM at $VM_IP

DORIS_BE_HOST=$VM_IP
DORIS_BE_PORT=8040
EOF
info ".env.vm written to $ENV_FILE"

# ── Step 9: Verify FE can see the BE ─────────────────────────────────────────
step "Checking Doris FE recognises the BE"
sleep 5
BE_STATUS=$(curl -sf "http://localhost:8030/api/show_proc?path=/backends" \
    -u root: 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    rows = d.get('data',{}).get('rows',[])
    alive = [r for r in rows if len(r) > 6 and r[5] == 'true']
    print(f'{len(alive)} alive' if alive else 'no alive backends')
except Exception as e:
    print(f'parse error: {e}')
" 2>/dev/null || echo "unknown")
info "Doris FE backend status: $BE_STATUS"

# ── Step 10: Print final instructions ────────────────────────────────────────
step "Setup complete"
cat <<DONE

  ${GREEN}Doris BE is running in your UTM VM at ${VM_IP}.${NC}

  To start the full AISS stack in VM mode:

    cd $(basename "$REPO_ROOT")
    docker compose \\
        -f docker-compose.yml \\
        -f docker-compose.vm.yml \\
        --env-file .env.vm \\
        up --build --detach

  To stop the BE on the VM:
    ssh $SSH_USER@$VM_IP 'docker stop aiss-doris-be'

  To view BE logs:
    ssh $SSH_USER@$VM_IP 'docker logs -f aiss-doris-be'

  NOTE: The UTM VM must be running before you start the Docker stack.
        The VM uses the UTM Shared Network — it starts automatically with UTM.

DONE
