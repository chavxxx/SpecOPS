#!/usr/bin/env bash
# ==============================================================================
# WISPnet Carrier-Grade Security Operations & IP Reputation Intelligence Platform
# Uninstaller Script
# ==============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/opt/wispnet"
PURGE_DATA=false
OS_TYPE="$(uname -s)"

if [ "$OS_TYPE" = "Darwin" ] || [ "$EUID" -ne 0 ]; then
  INSTALL_DIR="${HOME}/wispnet"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --purge)
      PURGE_DATA=true
      shift
      ;;
    -h|--help)
      echo "Usage: sudo bash uninstall.sh [OPTIONS]"
      echo "  -d, --dir <PATH>   Target install directory to remove (default: /opt/wispnet)"
      echo "      --purge        Delete all databases, logs, and config files"
      exit 0
      ;;
    *)
      shift
      ;;
  esac
done

echo -e "${YELLOW}${BOLD}Uninstalling WISPnet Security Platform...${NC}"

# Stop systemd service if running
if command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files | grep -q "wispnet.service"; then
    echo "Stopping and disabling wispnet.service..."
    systemctl stop wispnet.service 2>/dev/null || true
    systemctl disable wispnet.service 2>/dev/null || true
    rm -f /etc/systemd/system/wispnet.service
    systemctl daemon-reload
    echo -e "${GREEN}✓ Removed wispnet.service.${NC}"
  fi
fi

# Remove files
if [ "$PURGE_DATA" = true ]; then
  if [ -d "${INSTALL_DIR}" ]; then
    echo "Purging installation directory ${INSTALL_DIR}..."
    rm -rf "${INSTALL_DIR}"
    echo -e "${GREEN}✓ Completely removed ${INSTALL_DIR}.${NC}"
  fi
else
  echo -e "${YELLOW}ℹ Kept databases and configuration in ${INSTALL_DIR}. (Use --purge to delete completely)${NC}"
fi

echo -e "${GREEN}${BOLD}✓ WISPnet uninstallation complete.${NC}"
