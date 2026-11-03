# ==============================================================================
# Production Dockerfile for Risk Alert Dashboard Frontend (React + Nginx)
# ==============================================================================
# Build stage
FROM node:20-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine

# Apply security patches for alpine packages and install openssl for fallback cert generation
RUN apk upgrade --no-cache && apk add --no-cache openssl

# Ensure SSL directory exists with default fallback certificate so nginx always boots cleanly
RUN mkdir -p /etc/nginx/ssl /etc/nginx/templates && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/server.key \
        -out /etc/nginx/ssl/server.crt \
        -subj "/C=KH/ST=Phnom Penh/O=National Bank of Cambodia/CN=alert-dashboard.nbc.gov.kh" 2>/dev/null

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
RUN mkdir -p /etc/nginx/template-sources
COPY nginx.direct.conf.template /etc/nginx/template-sources/nginx.direct.conf.template
COPY nginx.redirect.conf.template /etc/nginx/template-sources/nginx.redirect.conf.template
COPY 18-setup-redirect-template.sh /docker-entrypoint.d/18-setup-redirect-template.sh
RUN chmod +x /docker-entrypoint.d/18-setup-redirect-template.sh

ENV DOMAIN_NAME=alert-dashboard.nbc.gov.kh
ENV REDIRECT_TO_DOMAIN=false

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O - http://localhost:80/nginx-health || exit 1

CMD ["nginx", "-g", "daemon off;"]
