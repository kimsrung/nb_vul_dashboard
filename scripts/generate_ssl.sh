#!/usr/bin/env bash
# ==============================================================================
# Helper Script: Generate Self-Signed Fallback SSL Certificate for Nginx
# Usage: ./scripts/generate_ssl.sh [DOMAIN_NAME] [OUTPUT_DIR] [--force]
# Example: ./scripts/generate_ssl.sh alert-dashboard.nbc.gov.kh ./ssl
# ==============================================================================
set -euo pipefail

DOMAIN="${1:-${DOMAIN_NAME:-alert-dashboard.nbc.gov.kh}}"
OUTPUT_DIR="${2:-./ssl}"
FORCE="${3:-false}"

if [ "${1:-}" = "--force" ] || [ "${2:-}" = "--force" ]; then
    FORCE="true"
fi

CERT_FILE="${OUTPUT_DIR}/server.crt"
KEY_FILE="${OUTPUT_DIR}/server.key"

echo "================================================================="
echo " 🔒 SSL Certificate Setup for Threat Center Dashboard"
echo " Target Domain: ${DOMAIN}"
echo " Output Directory: ${OUTPUT_DIR}"
echo "================================================================="

mkdir -p "${OUTPUT_DIR}"

if [ -f "${CERT_FILE}" ] && [ -f "${KEY_FILE}" ] && [ "${FORCE}" != "true" ]; then
    echo "✅ SSL certificate and private key already exist at:"
    echo "   Cert: ${CERT_FILE}"
    echo "   Key:  ${KEY_FILE}"
    echo "   (Use --force to regenerate a new self-signed certificate)"
    exit 0
fi

echo "🔧 Generating 4096-bit RSA self-signed fallback certificate..."

# Detect host IP addresses for SAN
LOCAL_IPS=$(hostname -I 2>/dev/null || ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' || echo "")

TMP_CONF=$(mktemp)
cat <<EOF > "${TMP_CONF}"
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext
x509_extensions = v3_ca

[dn]
C = KH
ST = Phnom Penh
L = Phnom Penh
O = National Bank of Cambodia
OU = IT Security
CN = ${DOMAIN}

[req_ext]
subjectAltName = @alt_names

[v3_ca]
subjectAltName = @alt_names
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = ${DOMAIN}
DNS.2 = localhost
DNS.3 = *.nbc.gov.kh
IP.1 = 127.0.0.1
EOF

# Append detected IPs to SAN
IP_INDEX=2
for ip in ${LOCAL_IPS}; do
    # Validate IPv4 format
    if echo "$ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "IP.${IP_INDEX} = ${ip}" >> "${TMP_CONF}"
        IP_INDEX=$((IP_INDEX + 1))
    fi
done

openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
    -keyout "${KEY_FILE}" \
    -out "${CERT_FILE}" \
    -config "${TMP_CONF}" \
    -extensions v3_ca 2>/dev/null

rm -f "${TMP_CONF}"

chmod 600 "${KEY_FILE}"
chmod 644 "${CERT_FILE}"

echo "✅ Self-signed SSL certificate successfully generated:"
echo "   Cert: ${CERT_FILE}"
echo "   Key:  ${KEY_FILE}"
echo ""
echo "   Valid Subject Alternative Names (SANs):"
openssl x509 -in "${CERT_FILE}" -noout -text | grep -A 1 "Subject Alternative Name" || true
echo "================================================================="
