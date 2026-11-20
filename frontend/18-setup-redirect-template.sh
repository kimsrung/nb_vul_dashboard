#!/bin/sh
set -e

# ==============================================================================
# Select Nginx template based on REDIRECT_TO_DOMAIN flag & SSL Cert Readability
# Runs before 20-envsubst-on-templates.sh in Nginx docker entrypoint
# ==============================================================================

mkdir -p /etc/nginx/templates
rm -f /etc/nginx/templates/*.template

if [ "${REDIRECT_TO_DOMAIN:-false}" = "true" ]; then
    echo "18-setup-redirect-template.sh: REDIRECT_TO_DOMAIN=true -> Activating IP-to-Domain 301 redirection to ${DOMAIN_NAME}"
    cp /etc/nginx/template-sources/nginx.redirect.conf.template /etc/nginx/templates/default.conf.template
else
    echo "18-setup-redirect-template.sh: REDIRECT_TO_DOMAIN=false -> Activating Direct Access mode (serves IP, localhost & domain directly)"
    cp /etc/nginx/template-sources/nginx.direct.conf.template /etc/nginx/templates/default.conf.template
fi

# ==============================================================================
# Certificate Verification & Fallback Protection:
# Check if host-mounted SSL certificates in /etc/nginx/ssl exist and are readable
# by the unprivileged nginx user (UID 101).
# If unreadable (e.g. host 0600 root-owned permissions or missing/empty files),
# fall back to internal generated self-signed certificates in /etc/nginx/ssl-fallback/
# so the container NEVER crashes or enters a restart loop.
# ==============================================================================
SSL_MOUNT_CERT="/etc/nginx/ssl/server.crt"
SSL_MOUNT_KEY="/etc/nginx/ssl/server.key"
FALLBACK_CERT="/etc/nginx/ssl-fallback/server.crt"
FALLBACK_KEY="/etc/nginx/ssl-fallback/server.key"

if [ ! -r "$SSL_MOUNT_CERT" ] || [ ! -r "$SSL_MOUNT_KEY" ]; then
    echo "18-setup-redirect-template.sh: ⚠️ Host SSL certificates ($SSL_MOUNT_CERT or $SSL_MOUNT_KEY) are missing or not readable by nginx user (UID 101)."
    echo "18-setup-redirect-template.sh: 🛡️ Activating internal fallback certificates from ${FALLBACK_CERT} and ${FALLBACK_KEY} to prevent container crash loop."
    sed -i "s|/etc/nginx/ssl/server.crt|${FALLBACK_CERT}|g" /etc/nginx/templates/default.conf.template
    sed -i "s|/etc/nginx/ssl/server.key|${FALLBACK_KEY}|g" /etc/nginx/templates/default.conf.template
else
    echo "18-setup-redirect-template.sh: ✅ Host SSL certificates verified and readable at ${SSL_MOUNT_CERT} and ${SSL_MOUNT_KEY}"
fi
