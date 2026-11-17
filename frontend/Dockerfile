# ==============================================================================
# Production Dockerfile for Threat Center Dashboard Frontend (React + Nginx)
# Hardened non-root unprivileged container (USER nginx, UID 101)
# ==============================================================================
# Build stage
FROM node:22-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine

# Apply security patches for alpine packages and install openssl for fallback cert generation
RUN apk upgrade --no-cache && \
    apk add --no-cache openssl

# Ensure SSL and template directories exist with fallback certificates readable by non-root nginx
RUN mkdir -p /etc/nginx/ssl /etc/nginx/templates /etc/nginx/template-sources /var/cache/nginx /var/log/nginx && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/server.key \
        -out /etc/nginx/ssl/server.crt \
        -subj "/C=KH/ST=Phnom Penh/O=National Bank of Cambodia/CN=alert-dashboard.nbc.gov.kh" 2>/dev/null && \
    chmod 644 /etc/nginx/ssl/server.key /etc/nginx/ssl/server.crt

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY nginx.direct.conf.template /etc/nginx/template-sources/nginx.direct.conf.template
COPY nginx.redirect.conf.template /etc/nginx/template-sources/nginx.redirect.conf.template
COPY 18-setup-redirect-template.sh /docker-entrypoint.d/18-setup-redirect-template.sh
RUN chmod +x /docker-entrypoint.d/18-setup-redirect-template.sh

# Reconfigure master nginx.conf:
# 1. Disable user directive (master process runs directly as unprivileged nginx user)
# 2. Relocate PID file from /run/nginx.pid to unprivileged /tmp/nginx.pid
RUN sed -i 's|user  nginx;|#user nginx;|g' /etc/nginx/nginx.conf && \
    sed -i 's|pid        /run/nginx.pid;|pid /tmp/nginx.pid;|g' /etc/nginx/nginx.conf

# Prepare permissions and runtime directories for non-root user (nginx:nginx, UID 101:GID 101)
RUN touch /tmp/nginx.pid && \
    mkdir -p /var/cache/nginx/client_temp /var/cache/nginx/proxy_temp /var/cache/nginx/fastcgi_temp /var/cache/nginx/uwsgi_temp /var/cache/nginx/scgi_temp && \
    chown -R nginx:nginx \
        /tmp/nginx.pid \
        /var/cache/nginx \
        /var/log/nginx \
        /etc/nginx \
        /usr/share/nginx/html \
        /docker-entrypoint.d

ENV DOMAIN_NAME=alert-dashboard.nbc.gov.kh
ENV REDIRECT_TO_DOMAIN=false

# Drop root privileges - run container exclusively as non-root unprivileged user 'nginx' (UID 101)
USER nginx

EXPOSE 8080 8443

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O - http://localhost:8080/nginx-health || exit 1

CMD ["nginx", "-g", "daemon off;"]
