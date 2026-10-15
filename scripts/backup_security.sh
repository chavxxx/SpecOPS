#!/usr/bin/env bash
# ==============================================================================
# WISP Network & Data Solutions (WISPnet)
# Security Platform - Automated Database & Configuration Backup Script
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${PROJECT_ROOT}/backups/security"
TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
DB_FILE="${WISP_SECURITY_DB:-${PROJECT_ROOT}/wisp_security.db}"
RETENTION_DAYS=14

mkdir -p "${BACKUP_DIR}"

echo "[*] [${TIMESTAMP}] Starting WISP Security Platform Backup..."

if [ ! -f "${DB_FILE}" ]; then
    echo "[!] Error: SQLite database not found at ${DB_FILE}"
    exit 1
fi

TEMP_STAGE="${BACKUP_DIR}/stage_${TIMESTAMP}"
mkdir -p "${TEMP_STAGE}"

# 1. Atomic SQLite Online Backup (safe during live WAL mode operations)
echo "[*] Creating atomic SQLite online backup..."
sqlite3 "${DB_FILE}" ".backup '${TEMP_STAGE}/synchavxxx.db'"

# 2. Export Authoritative CGNAT Mappings to CSV for emergency offline lookup
echo "[*] Exporting CGNAT mappings to CSV..."
sqlite3 -header -csv "${DB_FILE}" "SELECT * FROM cgnat_mappings WHERE effective_to IS NULL OR effective_to > CURRENT_TIMESTAMP;" > "${TEMP_STAGE}/cgnat_mappings_${TIMESTAMP}.csv"

# 3. Export Active Detection Rules to JSON/CSV
echo "[*] Exporting Detection Rules..."
sqlite3 -header -csv "${DB_FILE}" "SELECT * FROM detection_rules;" > "${TEMP_STAGE}/detection_rules_${TIMESTAMP}.csv"

# 4. Export Active Subscriber Sessions
echo "[*] Exporting Subscriber Sessions Snapshot..."
sqlite3 -header -csv "${DB_FILE}" "SELECT * FROM subscriber_sessions WHERE ended_at IS NULL;" > "${TEMP_STAGE}/active_sessions_${TIMESTAMP}.csv"

# 5. Compress Archive
ARCHIVE_NAME="wisp_security_backup_${TIMESTAMP}.tar.gz"
ARCHIVE_PATH="${BACKUP_DIR}/${ARCHIVE_NAME}"

tar -czf "${ARCHIVE_PATH}" -C "${TEMP_STAGE}" .
rm -rf "${TEMP_STAGE}"

# 6. Generate SHA-256 Checksum for verification & forensics
shasum -a 256 "${ARCHIVE_PATH}" > "${ARCHIVE_PATH}.sha256"

echo "[✓] Backup completed successfully: ${ARCHIVE_PATH}"
echo "[✓] SHA-256: $(cat "${ARCHIVE_PATH}.sha256")"

# 7. Prune archives older than RETENTION_DAYS
echo "[*] Pruning backup archives older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -name "wisp_security_backup_*.tar.gz*" -mtime +"${RETENTION_DAYS}" -exec rm -f {} +

echo "[✓] Backup rotation complete."
