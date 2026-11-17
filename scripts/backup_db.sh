#!/usr/bin/env bash
# ==============================================================================
# Database Backup Utility for Threat Center Dashboard
# Creates a timestamped PostgreSQL dump from the production Docker container.
# Usage: ./scripts/backup_db.sh [destination_dir]
# ==============================================================================
set -euo pipefail

DEST_DIR="${1:-./backups}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="${DEST_DIR}/threat_center_db_${TIMESTAMP}.sql.gz"

mkdir -p "${DEST_DIR}"

# Locate script and project directory to read production env if present
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
if [ -f "${ROOT_DIR}/.env.production" ]; then
    # shellcheck disable=SC1090
    set -a; source "${ROOT_DIR}/.env.production"; set +a
elif [ -f "${ROOT_DIR}/.env" ]; then
    # shellcheck disable=SC1090
    set -a; source "${ROOT_DIR}/.env"; set +a
fi

CONTAINER_NAME="threat_center_prod_postgres"
DB_USER="${POSTGRES_USER:-threat_center_prod_user}"
DB_NAME="${POSTGRES_DB:-threat_center_prod_db}"

echo "==> Creating database backup from container '${CONTAINER_NAME}'..."
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "ERROR: Container '${CONTAINER_NAME}' is not running." >&2
    exit 1
fi

docker exec -t "${CONTAINER_NAME}" pg_dump -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists | gzip > "${BACKUP_FILE}"

FILE_SIZE="$(du -h "${BACKUP_FILE}" | cut -f1)"
echo "==> Backup completed successfully!"
echo "    File: ${BACKUP_FILE} (${FILE_SIZE})"
