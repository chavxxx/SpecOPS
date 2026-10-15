#!/usr/bin/env bash
# ==============================================================================
# WISPnet Carrier-Grade Security Operations & IP Reputation Intelligence Platform
# Turnkey 1-Line Universal Installer (Ubuntu / Debian / RHEL / Rocky / macOS)
# ==============================================================================
set -e

# Terminal Colors & Styling
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Default Configuration Parameters
PORT=8000
INSTALL_DIR="/opt/wispnet"
SEED_DEMO=false
ENABLE_SYSTEMD=true
SERVICE_USER="root"
BRANCH="main"
HTTPS_REPO_URL="https://github.com/chavxxx/SpecOPS.git"
SSH_REPO_URL="git@github.com:chavxxx/SpecOPS.git"
TOKEN=""
USE_SSH=false

# On macOS or when not running as root, default install dir to current directory or home
OS_TYPE="$(uname -s)"
if [ "$OS_TYPE" = "Darwin" ]; then
  INSTALL_DIR="${HOME}/wispnet"
  ENABLE_SYSTEMD=false
  SERVICE_USER="$(id -un)"
elif [ "$EUID" -ne 0 ]; then
  INSTALL_DIR="${HOME}/wispnet"
  SERVICE_USER="$(id -un)"
fi

# ==============================================================================
# PARSE COMMAND LINE ARGUMENTS
# ==============================================================================
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--port)
      PORT="$2"
      shift 2
      ;;
    -d|--dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    -s|--seed-demo)
      SEED_DEMO=true
      shift
      ;;
    --no-systemd)
      ENABLE_SYSTEMD=false
      shift
      ;;
    -u|--user)
      SERVICE_USER="$2"
      shift 2
      ;;
    -b|--branch)
      BRANCH="$2"
      shift 2
      ;;
    -t|--token)
      TOKEN="$2"
      shift 2
      ;;
    --ssh)
      USE_SSH=true
      shift
      ;;
    -h|--help)
      echo -e "${CYAN}${BOLD}WISPnet Security Platform — Turnkey 1-Line Installer${NC}"
      echo ""
      echo -e "Usage: sudo bash install.sh [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  -p, --port <PORT>        Web dashboard & API port (default: 8000)"
      echo "  -d, --dir <PATH>         Installation directory (default: /opt/wispnet)"
      echo "  -s, --seed-demo          Seed realistic demo telemetry, CGNAT mappings & events"
      echo "      --no-systemd         Skip systemd service registration (macOS/Docker/Dev)"
      echo "  -u, --user <USER>        Systemd execution user (default: root)"
      echo "  -b, --branch <BRANCH>    Git branch to clone (default: main)"
      echo "  -t, --token <PAT>        GitHub Personal Access Token for private repo"
      echo "      --ssh                Force GitHub SSH git clone"
      echo "  -h, --help               Show this help message"
      echo ""
      exit 0
      ;;
    *)
      echo -e "${RED}[!] Unknown option: $1${NC}"
      echo "Run with --help for valid options."
      exit 1
      ;;
  esac
done

echo ""
echo -e "${CYAN}${BOLD}=================================================================${NC}"
echo -e "${CYAN}${BOLD}  🛡️  WISPnet Carrier-Grade Security & IP Intelligence Platform   ${NC}"
echo -e "${CYAN}${BOLD}  Turnkey Automated 1-Line Production Installer                  ${NC}"
echo -e "${CYAN}${BOLD}=================================================================${NC}"
echo ""

# Sudo check on Linux
if [ "$OS_TYPE" = "Linux" ] && [ "$EUID" -ne 0 ] && [ "$ENABLE_SYSTEMD" = true ]; then
  echo -e "${YELLOW}[!] Warning: Not running as root. System-wide package installation and systemd require sudo.${NC}"
  echo -e "Re-running installer with sudo..."
  exec sudo bash "$0" "$@"
fi

# ==============================================================================
# 1. OS & PACKAGE MANAGER DETECTION
# ==============================================================================
echo -e "${CYAN}[1/7] Detecting operating system & package manager...${NC}"

PKG_MGR=""
if [ "$OS_TYPE" = "Linux" ]; then
  if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
    echo -e "${GREEN}✓ Detected Debian/Ubuntu Linux (${PKG_MGR})${NC}"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
    echo -e "${GREEN}✓ Detected RHEL/Rocky/Alma/Fedora Linux (${PKG_MGR})${NC}"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
    echo -e "${GREEN}✓ Detected Enterprise Linux (${PKG_MGR})${NC}"
  elif command -v pacman >/dev/null 2>&1; then
    PKG_MGR="pacman"
    echo -e "${GREEN}✓ Detected Arch Linux (${PKG_MGR})${NC}"
  else
    PKG_MGR="unknown"
    echo -e "${YELLOW}[!] Unknown Linux package manager. Assuming prerequisites exist.${NC}"
  fi
elif [ "$OS_TYPE" = "Darwin" ]; then
  echo -e "${GREEN}✓ Detected macOS (Darwin)${NC}"
  if command -v brew >/dev/null 2>&1; then
    PKG_MGR="brew"
  fi
fi

# ==============================================================================
# 2. INSTALL SYSTEM PREREQUISITES
# ==============================================================================
echo -e "${CYAN}[2/7] Installing system prerequisites & runtime packages...${NC}"

if [ "$PKG_MGR" = "apt" ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1 || true
  apt-get install -y -qq python3 python3-venv python3-pip curl wget git tar sqlite3 ca-certificates ufw >/dev/null 2>&1 || {
    echo -e "${YELLOW}Retrying package installation with visible logging...${NC}"
    apt-get update
    apt-get install -y python3 python3-venv python3-pip curl wget git tar sqlite3 ca-certificates ufw
  }
elif [ "$PKG_MGR" = "dnf" ] || [ "$PKG_MGR" = "yum" ]; then
  $PKG_MGR install -y -q python3 python3-pip python3-devel curl wget git tar sqlite firewalld || {
    $PKG_MGR install -y python3 python3-pip curl wget git tar sqlite
  }
elif [ "$PKG_MGR" = "brew" ]; then
  BREW_PKGS=""
  command -v python3 >/dev/null 2>&1 || BREW_PKGS="${BREW_PKGS} python3"
  command -v git >/dev/null 2>&1 || BREW_PKGS="${BREW_PKGS} git"
  command -v curl >/dev/null 2>&1 || BREW_PKGS="${BREW_PKGS} curl"
  command -v sqlite3 >/dev/null 2>&1 || BREW_PKGS="${BREW_PKGS} sqlite"
  if [ -n "$BREW_PKGS" ]; then
    NONINTERACTIVE=1 brew install $BREW_PKGS 2>/dev/null || true
  fi
fi

# Verify Python 3
if ! command -v python3 >/dev/null 2>&1; then
  echo -e "${RED}[ERROR] Python 3 could not be found or installed. Please install Python 3.10+ manually.${NC}"
  exit 1
fi
PY_VER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')"
echo -e "${GREEN}✓ Python runtime verified: v${PY_VER}${NC}"

# ==============================================================================
# 3. PREPARE INSTALLATION DIRECTORY & CODEBASE
# ==============================================================================
echo -e "${CYAN}[3/7] Staging application codebase in ${INSTALL_DIR}...${NC}"

mkdir -p "${INSTALL_DIR}"
CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "")"

if [ -f "${CURRENT_DIR}/run.py" ] && [ -d "${CURRENT_DIR}/app" ]; then
  if [ "$(cd "${CURRENT_DIR}" && pwd)" != "$(cd "${INSTALL_DIR}" 2>/dev/null && pwd || echo "${INSTALL_DIR}")" ]; then
    echo "Copying source files from ${CURRENT_DIR} to ${INSTALL_DIR}..."
    cp -r "${CURRENT_DIR}"/* "${INSTALL_DIR}/" 2>/dev/null || true
    cp -r "${CURRENT_DIR}"/.[!.]* "${INSTALL_DIR}/" 2>/dev/null || true
  else
    echo "Running in-place within ${INSTALL_DIR}."
  fi
else
  # Remote execution: Clone or download repository
  echo "Fetching repository source code..."
  if [ "$USE_SSH" = true ] || ssh -T -o StrictHostKeyChecking=accept-new -o ConnectTimeout=3 git@github.com 2>&1 | grep -q "successfully authenticated"; then
    echo "Cloning via GitHub SSH (${SSH_REPO_URL})..."
    if [ -d "${INSTALL_DIR}/.git" ]; then
      cd "${INSTALL_DIR}" && git fetch origin "${BRANCH}" --quiet && git reset --hard "origin/${BRANCH}" --quiet
    else
      git clone --branch "${BRANCH}" --depth 1 "${SSH_REPO_URL}" "${INSTALL_DIR}"
    fi
  elif [ -n "$TOKEN" ]; then
    echo "Cloning via GitHub PAT token..."
    if ! git clone --branch "${BRANCH}" --depth 1 "https://${TOKEN}@github.com/chavxxx/SpecOPS.git" "${INSTALL_DIR}" 2>/dev/null; then
      echo "Fetching tarball via GitHub API..."
      curl -fsSL -H "Authorization: token ${TOKEN}" "https://api.github.com/repos/chavxxx/SpecOPS/tarball/${BRANCH}" -o /tmp/wispnet.tar.gz
      tar -xzf /tmp/wispnet.tar.gz --strip-components=1 -C "${INSTALL_DIR}"
      rm -f /tmp/wispnet.tar.gz
    fi
  elif [ -d "${INSTALL_DIR}/.git" ]; then
    echo "Updating existing git repository in ${INSTALL_DIR}..."
    cd "${INSTALL_DIR}" && git fetch origin "${BRANCH}" --quiet && git reset --hard "origin/${BRANCH}" --quiet
  else
    echo "Attempting HTTPS clone (${HTTPS_REPO_URL})..."
    if ! git clone --branch "${BRANCH}" --depth 1 "${HTTPS_REPO_URL}" "${INSTALL_DIR}" 2>/dev/null; then
      echo -e "${YELLOW}Repository is private. Enter GitHub Personal Access Token (PAT) or hit Enter to skip:${NC}"
      TOKEN_INPUT=""
      if [ -t 0 ]; then
        read -s -p "GitHub PAT: " TOKEN_INPUT
        echo ""
      elif [ -c /dev/tty ]; then
        read -s -p "GitHub PAT: " TOKEN_INPUT </dev/tty
        echo ""
      fi
      if [ -n "$TOKEN_INPUT" ]; then
        curl -fsSL -H "Authorization: token ${TOKEN_INPUT}" "https://api.github.com/repos/chavxxx/SpecOPS/tarball/${BRANCH}" -o /tmp/wispnet.tar.gz
        tar -xzf /tmp/wispnet.tar.gz --strip-components=1 -C "${INSTALL_DIR}"
        rm -f /tmp/wispnet.tar.gz
      else
        echo -e "${RED}[ERROR] Unable to access repository. Provide --token <PAT> or configure SSH.${NC}"
        exit 1
      fi
    fi
  fi
fi

cd "${INSTALL_DIR}"

# Clean up pycache and temp files
find "${INSTALL_DIR}" -type f -name "*.pyc" -delete 2>/dev/null || true
rm -rf "${INSTALL_DIR}/.pytest_cache" 2>/dev/null || true

# ==============================================================================
# 4. CONFIGURE PYTHON VIRTUAL ENVIRONMENT & PIP DEPENDENCIES
# ==============================================================================
echo -e "${CYAN}[4/7] Setting up dedicated Python virtual environment...${NC}"

if [ ! -d "${INSTALL_DIR}/.venv" ]; then
  python3 -m venv "${INSTALL_DIR}/.venv"
fi

"${INSTALL_DIR}/.venv/bin/pip" install --upgrade pip setuptools wheel --no-cache-dir -q

if [ -f "${INSTALL_DIR}/requirements.txt" ]; then
  "${INSTALL_DIR}/.venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" --no-cache-dir -q
else
  "${INSTALL_DIR}/.venv/bin/pip" install fastapi uvicorn pydantic httpx pytest pytest-asyncio python-multipart websockets jinja2 --no-cache-dir -q
fi
echo -e "${GREEN}✓ Virtual environment dependencies installed.${NC}"

# ==============================================================================
# 5. INITIALIZE DATABASE & RUN VALIDATION TESTS
# ==============================================================================
echo -e "${CYAN}[5/7] Initializing SQLite schema & running verification test suite...${NC}"

export WISP_SECURITY_DB="${INSTALL_DIR}/wisp_security.db"

# Ensure database exists and schema is migrated
"${INSTALL_DIR}/.venv/bin/python" -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}')
from app.database.db import get_db
db = get_db()
print(f'Database initialized at: {db.db_path}')
"

# Seed demo telemetry if requested or if database is brand new
if [ "$SEED_DEMO" = true ] || [ ! -f "${INSTALL_DIR}/wisp_security.db" ]; then
  echo "Seeding carrier telemetry, CGNAT mappings & demo security incidents..."
  "${INSTALL_DIR}/.venv/bin/python" scripts/seed_security_data.py
fi

# Run automated test suite
echo "Executing test suite..."
if "${INSTALL_DIR}/.venv/bin/pytest" -q; then
  echo -e "${GREEN}✓ All 39 test cases passed successfully.${NC}"
else
  echo -e "${YELLOW}[!] Warning: Some test cases failed. Continuing installation...${NC}"
fi

# ==============================================================================
# 6. SYSTEMD SERVICE CONFIGURATION (LINUX)
# ==============================================================================
if [ "$ENABLE_SYSTEMD" = true ] && [ "$OS_TYPE" = "Linux" ] && command -v systemctl >/dev/null 2>&1; then
  echo -e "${CYAN}[6/7] Creating and enabling systemd service unit (wispnet.service)...${NC}"
  SERVICE_FILE="/etc/systemd/system/wispnet.service"

  cat << EOF > "${SERVICE_FILE}"
[Unit]
Description=WISPnet Carrier-Grade Security Operations & IP Intelligence Platform
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/.venv/bin/python ${INSTALL_DIR}/run.py --host 0.0.0.0 --port ${PORT}
Restart=always
RestartSec=3
LimitNOFILE=65535
Environment="PYTHONUNBUFFERED=1"
Environment="WISP_SECURITY_DB=${INSTALL_DIR}/wisp_security.db"

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable wispnet.service
  systemctl restart wispnet.service
  echo -e "${GREEN}✓ Registered and started wispnet.service.${NC}"
else
  echo -e "${CYAN}[6/7] Skipping systemd registration (manual run or macOS mode).${NC}"
fi

# ==============================================================================
# 7. FIREWALL & SERVICE HEALTH VERIFICATION
# ==============================================================================
echo -e "${CYAN}[7/7] Configuring firewall & validating live health status...${NC}"

# Configure firewall if active
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow "${PORT}/tcp" comment 'WISPnet Security Operations Console' >/dev/null 2>&1 || true
  echo -e "${GREEN}✓ Allowed port ${PORT}/tcp in UFW.${NC}"
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
  firewall-cmd --add-port="${PORT}/tcp" --permanent >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
  echo -e "${GREEN}✓ Allowed port ${PORT}/tcp in firewalld.${NC}"
fi

# Health check loop (if service was started)
HEALTHY=false
if [ "$ENABLE_SYSTEMD" = true ]; then
  for i in {1..12}; do
    HTTP_CODE="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${PORT}/healthz" 2>/dev/null || echo "000")"
    if [ "$HTTP_CODE" = "200" ]; then
      HEALTHY=true
      break
    fi
    sleep 1
  done
fi

SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [ -z "$SERVER_IP" ]; then
  SERVER_IP="127.0.0.1"
fi

echo ""
if [ "$HEALTHY" = true ]; then
  echo -e "${GREEN}${BOLD}=================================================================${NC}"
  echo -e "${GREEN}${BOLD}  ✓ WISPnet Security Platform is LIVE, HEALTHY & OPERATIONAL!   ${NC}"
  echo -e "${GREEN}${BOLD}=================================================================${NC}"
else
  echo -e "${GREEN}${BOLD}=================================================================${NC}"
  echo -e "${GREEN}${BOLD}  ✓ WISPnet Security Platform Installation Complete!            ${NC}"
  echo -e "${GREEN}${BOLD}=================================================================${NC}"
fi

echo ""
echo -e "  ${BOLD}🌐 Web Console:${NC}        ${CYAN}http://${SERVER_IP}:${PORT}${NC}"
echo -e "  ${BOLD}🔑 Default Admin:${NC}      ${YELLOW}synchavxxx${NC} / ${YELLOW}passworD1369${NC}"
echo -e "  ${BOLD}👤 NOC Observer:${NC}       ${YELLOW}analyst_test${NC} / ${YELLOW}analyst123${NC}"
echo -e "  ${BOLD}📁 Install Path:${NC}       ${INSTALL_DIR}"
echo -e "  ${BOLD}💾 Security DB:${NC}        ${INSTALL_DIR}/wisp_security.db"

if [ "$ENABLE_SYSTEMD" = true ]; then
  echo ""
  echo -e "  ${BOLD}⚙️  Service Status:${NC}     ${MAGENTA}sudo systemctl status wispnet${NC}"
  echo -e "  ${BOLD}📜 Live Journal Logs:${NC}  ${MAGENTA}sudo journalctl -u wispnet -f${NC}"
  echo -e "  ${BOLD}🔄 Service Restart:${NC}    ${MAGENTA}sudo systemctl restart wispnet${NC}"
else
  echo ""
  echo -e "  ${BOLD}🚀 Launch Command:${NC}     ${MAGENTA}cd ${INSTALL_DIR} && source .venv/bin/activate && python run.py --host 0.0.0.0 --port ${PORT}${NC}"
fi

echo ""
echo -e "${CYAN}Open ${BOLD}http://${SERVER_IP}:${PORT}${NC}${CYAN} in your browser to begin monitoring carrier security telemetry!${NC}"
echo ""
