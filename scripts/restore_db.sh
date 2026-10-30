#!/usr/bin/env bash
# ==============================================================================
# Database Restore Utility for Risk Alert Dashboard
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

CONTAINER_NAME="risk_alert_prod_postgres"
DB_USER="risk_alert_user"
DB_NAME="risk_alert_db"

echo "==> Restoring database from '${BACKUP_FILE}' into '${CONTAINER_NAME}'..."
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "ERROR: Container '${CONTAINER_NAME}' is not running." >&2
    exit 1
fi

gunzip -c "${BACKUP_FILE}" | docker exec -i "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}"

echo "==> Database restore completed successfully!"
