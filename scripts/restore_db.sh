#!/usr/bin/env bash
# ==============================================================================
# Database Restore Utility for Threat Center Dashboard
# Restores a PostgreSQL dump into the production Docker container.
# Usage: ./scripts/restore_db.sh <path_to_backup.sql.gz>
# ==============================================================================
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <path_to_backup.sql.gz>" >&2
    exit 1
fi

BACKUP_FILE="$1"
if [ ! -f "${BACKUP_FILE}" ]; then
    echo "ERROR: Backup file '${BACKUP_FILE}' not found." >&2
    exit 1
fi

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

echo "==> Restoring database from '${BACKUP_FILE}' into '${CONTAINER_NAME}'..."
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "ERROR: Container '${CONTAINER_NAME}' is not running." >&2
    exit 1
fi

gunzip -c "${BACKUP_FILE}" | docker exec -i "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}"

echo "==> Database restore completed successfully!"
