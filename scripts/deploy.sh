#!/usr/bin/env bash
# ==============================================================================
# Production Deployment Script for Risk Alert Dashboard
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
echo " 🚀 Deploying Risk Alert Dashboard (Production)"
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

# 3. Check for .env.production file
ENV_FILE="${ROOT_DIR}/.env.production"
if [ ! -f "${ENV_FILE}" ]; then
  echo "❌ Error: Production configuration file not found at ${ENV_FILE}"
  echo "   Please create it from .env.production.example before deploying."
  exit 1
fi

# Load environment variables from .env.production (excluding comments)
set -a
# shellcheck disable=SC1090
source <(grep -v '^[[:space:]]*#' "${ENV_FILE}" | grep -v '^[[:space:]]*$')
set +a

# 3. Clean Harbor URL (strip protocol schemes)
if [ -n "${HARBOR_URL}" ]; then
  CLEAN_HARBOR_URL=$(echo "${HARBOR_URL}" | sed -e 's|^https://||' -e 's|^http://||' -e 's|/$||')
  export HARBOR_URL="${CLEAN_HARBOR_URL}"
fi

# 4. Harbor Registry Authentication
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

# 5. Pull latest / target Docker images from Harbor
echo ""
echo "📥 Pulling backend and frontend images (${IMAGE_TAG})..."
docker compose -f docker-compose.prod.yml pull backend frontend

# 6. Recreate and restart production containers
echo ""
echo "🔄 Updating running services (backend & frontend)..."
docker compose -f docker-compose.prod.yml up -d backend frontend

# 7. Clean up dangling images to prevent disk exhaustion
echo ""
echo "🧹 Pruning obsolete/dangling docker images..."
docker image prune -f

# 8. Display current container status
echo ""
echo "================================================================="
echo " ✅ Deployment Completed Successfully!"
echo " Deployed Tag: ${IMAGE_TAG}"
echo "================================================================="
docker compose -f docker-compose.prod.yml ps
