#!/usr/bin/env bash
# ==============================================================================
# Database Backup Utility for Risk Alert Dashboard
# Creates a timestamped PostgreSQL dump from the production Docker container.
# Usage: ./scripts/backup_db.sh [destination_dir]
# ==============================================================================
set -euo pipefail

DEST_DIR="${1:-./backups}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="${DEST_DIR}/risk_alert_db_${TIMESTAMP}.sql.gz"

mkdir -p "${DEST_DIR}"

CONTAINER_NAME="risk_alert_prod_postgres"
DB_USER="risk_alert_user"
DB_NAME="risk_alert_db"

echo "==> Creating database backup from container '${CONTAINER_NAME}'..."
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "ERROR: Container '${CONTAINER_NAME}' is not running." >&2
    exit 1
fi

docker exec -t "${CONTAINER_NAME}" pg_dump -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists | gzip > "${BACKUP_FILE}"

FILE_SIZE="$(du -h "${BACKUP_FILE}" | cut -f1)"
echo "==> Backup completed successfully!"
echo "    File: ${BACKUP_FILE} (${FILE_SIZE})"
