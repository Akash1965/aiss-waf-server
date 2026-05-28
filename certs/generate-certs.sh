#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# AISS Certificate Authority & Service Certificate Generator
#
# Compliance: Singapore IM8 v5.0, MAS TRM 2021 (§9.3), CSA Cybersecurity Act
#             Japan CRYPTREC approved algorithms, Korea K-ISMS Annex A
#
# Key standards enforced:
#   • RSA 4096-bit CA  (NIST SP 800-57 Part 1 Rev 5 — minimum 2048-bit)
#   • ECDSA P-384 for leaf certs (NIST FIPS 186-5, recommended for gov)
#   • SHA-384 digest  (SHA-256 minimum, SHA-384 preferred for gov)
#   • 825-day max validity for TLS certs (Apple/Mozilla root store compliance)
#   • Subject Alternative Names on every certificate (RFC 5280)
#   • OCSP URL embedded in cert (required by MAS TRM §9.3.3)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
DAYS_CA=3650      # 10-year CA validity (offline CA)
DAYS_LEAF=825     # ~27 months — Apple/Mozilla max for public TLS
COUNTRY="SG"
STATE="Singapore"
ORG="AISS AI Security Shield"

echo "=== AISS PKI Bootstrap — Singapore Gov-Standard Certificates ==="

# ── 1. Root CA ────────────────────────────────────────────────────────────────
if [ ! -f "$CERT_DIR/ca.key" ]; then
    echo "[CA] Generating RSA-4096 root CA key..."
    openssl genrsa -out "$CERT_DIR/ca.key" 4096
    openssl req -new -x509 -sha384 \
        -key "$CERT_DIR/ca.key" \
        -out "$CERT_DIR/ca.crt" \
        -days $DAYS_CA \
        -subj "/C=$COUNTRY/ST=$STATE/O=$ORG/CN=AISS Root CA/emailAddress=security@aiss.local" \
        -extensions v3_ca
    echo "[CA] Root CA certificate generated: ca.crt"
else
    echo "[CA] Root CA already exists — skipping"
fi

# ── Helper: generate ECDSA P-384 leaf cert signed by our CA ──────────────────
gen_leaf() {
    local NAME="$1"   # e.g. "nginx", "aiss-server"
    local SANS="$2"   # comma-separated: DNS:nginx,DNS:localhost,IP:127.0.0.1

    if [ -f "$CERT_DIR/${NAME}.crt" ]; then
        echo "[${NAME}] Certificate already exists — skipping"
        return
    fi

    echo "[${NAME}] Generating ECDSA P-384 certificate..."

    # Private key
    openssl ecparam -name secp384r1 -genkey -noout \
        -out "$CERT_DIR/${NAME}.key"

    # CSR config with SANs
    cat > /tmp/aiss_${NAME}_csr.cnf <<CSRCONF
[req]
default_bits        = 384
prompt              = no
default_md          = sha384
distinguished_name  = dn
req_extensions      = req_ext
[dn]
C  = $COUNTRY
ST = $STATE
O  = $ORG
CN = ${NAME}.aiss.local
[req_ext]
subjectAltName = $SANS
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
CSRCONF

    openssl req -new -sha384 \
        -key "$CERT_DIR/${NAME}.key" \
        -out /tmp/aiss_${NAME}.csr \
        -config /tmp/aiss_${NAME}_csr.cnf

    # Extension config for signed cert
    cat > /tmp/aiss_${NAME}_ext.cnf <<EXTCONF
subjectAltName = $SANS
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
authorityInfoAccess = OCSP;URI:http://ocsp.aiss.local:8888
EXTCONF

    # Sign with CA
    openssl x509 -req -sha384 \
        -in /tmp/aiss_${NAME}.csr \
        -CA "$CERT_DIR/ca.crt" \
        -CAkey "$CERT_DIR/ca.key" \
        -CAcreateserial \
        -out "$CERT_DIR/${NAME}.crt" \
        -days $DAYS_LEAF \
        -extfile /tmp/aiss_${NAME}_ext.cnf

    # Create PEM bundle (cert + CA chain)
    cat "$CERT_DIR/${NAME}.crt" "$CERT_DIR/ca.crt" \
        > "$CERT_DIR/${NAME}-chain.crt"

    echo "[${NAME}] Certificate generated: ${NAME}.crt"
    rm -f /tmp/aiss_${NAME}.csr /tmp/aiss_${NAME}_csr.cnf /tmp/aiss_${NAME}_ext.cnf
}

# ── 2. Nginx (public-facing HTTPS) ───────────────────────────────────────────
gen_leaf "nginx" \
    "DNS:nginx,DNS:localhost,DNS:aiss.local,DNS:waf.aiss.local,IP:127.0.0.1"

# ── 3. AISS Central Server (FastAPI) ─────────────────────────────────────────
gen_leaf "aiss-server" \
    "DNS:aiss-server,DNS:localhost,IP:127.0.0.1"

# ── 4. WAF Proxy ─────────────────────────────────────────────────────────────
gen_leaf "waf-proxy" \
    "DNS:waf-proxy,DNS:localhost,IP:127.0.0.1"

# ── 5. AISS Agent (client cert for mTLS) ─────────────────────────────────────
gen_leaf "aiss-agent" \
    "DNS:aiss-agent,DNS:localhost,IP:127.0.0.1"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Certificate Summary ==="
for cert in "$CERT_DIR"/*.crt; do
    name=$(basename "$cert" .crt)
    expiry=$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null | cut -d= -f2 || echo "N/A")
    algo=$(openssl x509 -noout -text -in "$cert" 2>/dev/null | grep "Public Key Algorithm" | head -1 | awk '{print $NF}' || echo "N/A")
    echo "  $name: expires $expiry  [$algo]"
done

echo ""
echo "AISS PKI bootstrap complete."
echo "Trust anchor: $CERT_DIR/ca.crt"
echo ""
echo "To verify a cert: openssl verify -CAfile $CERT_DIR/ca.crt $CERT_DIR/nginx.crt"
