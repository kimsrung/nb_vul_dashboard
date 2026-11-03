#!/bin/sh
set -e

# ==============================================================================
# Select Nginx template based on REDIRECT_TO_DOMAIN flag
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
