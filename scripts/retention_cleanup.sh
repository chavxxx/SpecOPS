#!/usr/bin/env bash
# ==============================================================================
# WISP Network & Data Solutions (WISPnet)
# Security Platform - Data Retention & Storage Pruning Policy Enforcement
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DB_FILE="${WISP_SECURITY_DB:-${PROJECT_ROOT}/wisp_security.db}"

# Retention Periods (in Days)
RAW_EVENTS_RETENTION_DAYS="${RAW_EVENTS_RETENTION_DAYS:-30}"
DELIVERED_QUEUE_RETENTION_DAYS="${DELIVERED_QUEUE_RETENTION_DAYS:-7}"
NOTIFICATION_LOGS_RETENTION_DAYS="${NOTIFICATION_LOGS_RETENTION_DAYS:-30}"
AUDIT_LOGS_RETENTION_DAYS="${AUDIT_LOGS_RETENTION_DAYS:-180}"

TIMESTAMP="$(date +"%Y-%m-%dT%H:%M:%SZ")"
echo "[*] [${TIMESTAMP}] Starting WISP Security Platform Data Retention Pruning..."

if [ ! -f "${DB_FILE}" ]; then
    echo "[!] Error: SQLite database not found at ${DB_FILE}"
    exit 1
fi

sqlite3 "${DB_FILE}" <<EOF
-- Set busy timeout to prevent locking conflicts
PRAGMA busy_timeout = 5000;

-- 1. Prune Raw Suricata JSON Payloads older than ${RAW_EVENTS_RETENTION_DAYS} days
DELETE FROM raw_events 
WHERE received_at < datetime('now', '-${RAW_EVENTS_RETENTION_DAYS} days');
SELECT 'Pruned raw_events older than ${RAW_EVENTS_RETENTION_DAYS} days: ' || changes();

-- 2. Prune Delivered OpenSearch Queue Records older than ${DELIVERED_QUEUE_RETENTION_DAYS} days
DELETE FROM opensearch_queue 
WHERE status = 'delivered' 
  AND created_at < datetime('now', '-${DELIVERED_QUEUE_RETENTION_DAYS} days');
SELECT 'Pruned delivered opensearch_queue items older than ${DELIVERED_QUEUE_RETENTION_DAYS} days: ' || changes();

-- 3. Prune Notification Logs older than ${NOTIFICATION_LOGS_RETENTION_DAYS} days
DELETE FROM notification_logs 
WHERE created_at < datetime('now', '-${NOTIFICATION_LOGS_RETENTION_DAYS} days');
SELECT 'Pruned notification_logs older than ${NOTIFICATION_LOGS_RETENTION_DAYS} days: ' || changes();

-- 4. Prune Expired Subscriber Sessions ended more than ${AUDIT_LOGS_RETENTION_DAYS} days ago
DELETE FROM subscriber_sessions 
WHERE ended_at IS NOT NULL 
  AND ended_at < datetime('now', '-${AUDIT_LOGS_RETENTION_DAYS} days');
SELECT 'Pruned stale historical subscriber sessions older than ${AUDIT_LOGS_RETENTION_DAYS} days: ' || changes();

-- 5. Reclaim free space and optimize SQLite query planner
PRAGMA optimize;
EOF

echo "[✓] Data retention maintenance completed successfully at $(date +"%Y-%m-%dT%H:%M:%SZ")."
