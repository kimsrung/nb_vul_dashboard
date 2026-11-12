#!/usr/bin/env bash
# ==============================================================================
# Production Deployment Script for Threat Center Dashboard
# Usage:
#   ./scripts/deploy.sh               # Deploys :latest image tag
#   ./scripts/deploy.sh sha-a1b2c3d   # Deploys a specific commit SHA tag
#   ./scripts/deploy.sh v1.2.0        # Deploys a specific version tag
# ==============================================================================

set -eo pipefail

# Determine repository root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

echo "================================================================="
echo " 🚀 Deploying Threat Center Dashboard (Production)"
echo " Working Directory: ${ROOT_DIR}"
echo "================================================================="

# 1. Check for Help Flag
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  echo "Usage: ./scripts/deploy.sh [IMAGE_TAG]"
  echo ""
  echo "Arguments:"
  echo "  IMAGE_TAG   (Optional) Specific tag to pull and deploy."
  echo "              Examples: latest, sha-a1b2c3d, v1.0.0"
  echo "              Default:  latest"
  echo ""
  echo "Configuration:"
  echo "  Reads HARBOR_URL, HARBOR_PROJECT, HARBOR_USERNAME, and HARBOR_PASSWORD from .env.production"
  exit 0
fi

# 2. Determine Target Image Tag
TARGET_TAG="${1:-latest}"
export IMAGE_TAG="${TARGET_TAG}"
echo "📦 Target Image Tag: ${IMAGE_TAG}"

# 3. Locate and load .env.production file
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env.production}"
if [ ! -f "${ENV_FILE}" ]; then
  # Search standard server directories (e.g. when run from GitHub Actions runner workspace)
  for candidate in \
    "${ROOT_DIR}/.env" \
    "${HOME}/alert-dashboard/.env.production" \
    "${HOME}/dashboard_alert/.env.production" \
    "${HOME}/.env.production" \
    "/opt/alert-dashboard/.env.production" \
    "/opt/dashboard_alert/.env.production"; do
    if [ -f "${candidate}" ]; then
      echo "ℹ️ Found production configuration at: ${candidate}"
      cp "${candidate}" "${ROOT_DIR}/.env.production"
      ENV_FILE="${ROOT_DIR}/.env.production"
      break
    fi
  done
fi

if [ ! -f "${ENV_FILE}" ]; then
  echo "❌ Error: Production configuration file not found at ${ENV_FILE}"
  echo "   Please create it from .env.production.example or copy your server's .env.production before deploying."
  exit 1
fi

# Load environment variables from .env.production (excluding comments)
set -a
# shellcheck disable=SC1090
source <(grep -v '^[[:space:]]*#' "${ENV_FILE}" | grep -v '^[[:space:]]*$')
set +a

# 4. Clean Harbor URL (strip protocol schemes and trailing slashes)
if [ -n "${HARBOR_URL}" ]; then
  CLEAN_HARBOR_URL=$(echo "${HARBOR_URL}" | sed -e 's|^https://||' -e 's|^http://||' -e 's|/$||')
  export HARBOR_URL="${CLEAN_HARBOR_URL}"
fi

# Ensure .env is synchronized and sanitized for Docker Compose variable interpolation
if [ "${ENV_FILE}" != "${ROOT_DIR}/.env" ]; then
  rm -f "${ROOT_DIR}/.env"
  cp "${ENV_FILE}" "${ROOT_DIR}/.env"
fi

if [ -n "${CLEAN_HARBOR_URL:-}" ] && [ -f "${ROOT_DIR}/.env" ]; then
  sed -i.bak -E "s|^HARBOR_URL=.*|HARBOR_URL=${CLEAN_HARBOR_URL}|" "${ROOT_DIR}/.env" && rm -f "${ROOT_DIR}/.env.bak"
fi

# 5. Ensure Insecure HTTP Registry Support in Docker Daemon
ensure_insecure_registry() {
  local host="$1"
  if [ -z "${host}" ]; then return 0; fi

  # Check if host is already in /etc/docker/daemon.json
  if [ -f /etc/docker/daemon.json ] && grep -q "\"${host}\"" /etc/docker/daemon.json 2>/dev/null; then
    return 0
  fi

  echo "🔧 Registering ${host} as an insecure HTTP registry in /etc/docker/daemon.json..."
  SUDO_CMD=""
  if [ "$EUID" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    SUDO_CMD="sudo"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    $SUDO_CMD mkdir -p /etc/docker
    if [ -f /etc/docker/daemon.json ]; then
      if command -v jq >/dev/null 2>&1; then
        jq '.["insecure-registries"] = ((.["insecure-registries"] // []) + ["'"${host}"'"] | unique)' /etc/docker/daemon.json > /tmp/daemon.json && \
        $SUDO_CMD mv /tmp/daemon.json /etc/docker/daemon.json
      else
        python3 -c "
import json
try:
    with open('/etc/docker/daemon.json') as f:
        d = json.load(f)
except Exception:
    d = {}
regs = d.get('insecure-registries', [])
if '${host}' not in regs:
    regs.append('${host}')
d['insecure-registries'] = regs
with open('/tmp/daemon.json', 'w') as f:
    json.dump(d, f, indent=2)
" && $SUDO_CMD mv /tmp/daemon.json /etc/docker/daemon.json
      fi
    else
      echo "{\"insecure-registries\": [\"${host}\"]}" | $SUDO_CMD tee /etc/docker/daemon.json > /dev/null
    fi
    echo "   Restarting Docker daemon..."
    $SUDO_CMD systemctl restart docker || true
    echo "   ✅ Docker daemon updated with insecure-registries: ${host}"
  else
    echo "   ⚠️ Notice: Please ensure ${host} is added to insecure-registries in /etc/docker/daemon.json."
  fi
}

if [ -n "${CLEAN_HARBOR_URL}" ]; then
  ensure_insecure_registry "${CLEAN_HARBOR_URL}"
fi

# 6. Harbor Registry Authentication
echo "🔐 Checking Harbor authentication..."
IS_LOGGED_IN=false

# Check if docker credentials store already has an auth entry for HARBOR_URL
if [ -f "${HOME}/.docker/config.json" ] && [ -n "${HARBOR_URL}" ]; then
  if grep -qi "${HARBOR_URL}" "${HOME}/.docker/config.json"; then
    IS_LOGGED_IN=true
    echo "   ✅ Found existing Docker session for ${HARBOR_URL}"
  fi
fi

# If not already logged in, attempt login using credentials from .env.production
if [ "${IS_LOGGED_IN}" = false ]; then
  if [ -n "${HARBOR_URL}" ] && [ -n "${HARBOR_USERNAME}" ] && [ -n "${HARBOR_PASSWORD}" ]; then
    echo "   🔑 Logging into Harbor at ${HARBOR_URL} as ${HARBOR_USERNAME}..."
    echo "${HARBOR_PASSWORD}" | docker login "${HARBOR_URL}" -u "${HARBOR_USERNAME}" --password-stdin
    echo "   ✅ Successfully authenticated to Harbor!"
  else
    echo "   ⚠️ Notice: HARBOR_USERNAME or HARBOR_PASSWORD not set in .env.production."
    echo "      Proceeding with existing host docker credentials (or public project access)..."
  fi
fi

# 6.5. Ensure SSL Certificates Exist
if [ ! -f "${ROOT_DIR}/ssl/server.crt" ] || [ ! -f "${ROOT_DIR}/ssl/server.key" ]; then
  # Search standard persistent server directories
  for candidate_ssl in \
    "/opt/alert-dashboard/ssl" \
    "/opt/dashboard_alert/ssl" \
    "${HOME}/alert-dashboard/ssl" \
    "${HOME}/dashboard_alert/ssl"; do
    if [ -f "${candidate_ssl}/server.crt" ] && [ -f "${candidate_ssl}/server.key" ]; then
      echo "ℹ️ Found manual server certificates at ${candidate_ssl} -> copying to ${ROOT_DIR}/ssl"
      mkdir -p "${ROOT_DIR}/ssl"
      cp "${candidate_ssl}/server.crt" "${ROOT_DIR}/ssl/server.crt"
      cp "${candidate_ssl}/server.key" "${ROOT_DIR}/ssl/server.key"
      chmod 644 "${ROOT_DIR}/ssl/server.crt"
      chmod 600 "${ROOT_DIR}/ssl/server.key"
      break
    fi
  done
fi

if [ ! -f "${ROOT_DIR}/ssl/server.crt" ] || [ ! -f "${ROOT_DIR}/ssl/server.key" ]; then
  echo "⚠️ Warning: SSL certificates (server.crt, server.key) not found in ${ROOT_DIR}/ssl."
  echo "   Please upload your commercial certificates to ${ROOT_DIR}/ssl/ before serving HTTPS."
fi

# 7. Pull latest / target Docker images from Harbor
echo ""
echo "📥 Pulling backend and frontend images (${IMAGE_TAG})..."
if ! docker compose --env-file "${ROOT_DIR}/.env" -f docker-compose.prod.yml pull backend frontend; then
  echo "⚠️ Notice: Unable to pull latest images from registry (network issue or registry unreachable)."
  echo "   Attempting to use locally built/cached images or build on host..."
  docker compose --env-file "${ROOT_DIR}/.env" -f docker-compose.prod.yml build backend frontend || true
fi

# 8. Recreate and restart production containers
echo ""
echo "🔄 Updating running services (backend & frontend)..."
docker compose --env-file "${ROOT_DIR}/.env" -f docker-compose.prod.yml up -d --force-recreate backend frontend

# 9. Clean up dangling images to prevent disk exhaustion
echo ""
echo "🧹 Pruning obsolete/dangling docker images..."
docker image prune -f

# 10. Display current container status
echo ""
echo "================================================================="
echo " ✅ Deployment Completed Successfully!"
echo " Deployed Tag: ${IMAGE_TAG}"
echo "================================================================="
docker compose -f docker-compose.prod.yml ps
