#!/usr/bin/env bash
# ==============================================================================
# Automated Provisioning Script for Blank Ubuntu / Debian Server
# Sets up Docker, Docker Compose, UFW Firewall, Production Environment Secrets,
# and optionally registers the GitHub Actions Self-Hosted Runner.
#
# Usage:
#   chmod +x scripts/init_server.sh
#   ./scripts/init_server.sh
# ==============================================================================

set -eo pipefail

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
NC="\033[0m"

echo -e "${BOLD}${BLUE}=================================================================${NC}"
echo -e "${BOLD}${BLUE} 🚀 Risk Alert Dashboard - Server Bootstrap & Provisioning${NC}"
echo -e "${BOLD}${BLUE}=================================================================${NC}"

# 1. Determine Privileges & Target User
SUDO=""
TARGET_USER="$(whoami)"
if [ "$EUID" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    echo -e "${RED}❌ Error: This script must be run as root or with sudo privileges.${NC}"
    exit 1
  fi
fi

# 2. Check Operating System Compatibility
if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  OS_ID="${ID:-ubuntu}"
  OS_VERSION_CODENAME="${VERSION_CODENAME:-jammy}"
else
  echo -e "${RED}❌ Error: Unable to detect Linux distribution from /etc/os-release.${NC}"
  exit 1
fi

if [[ "${OS_ID}" != "ubuntu" && "${OS_ID}" != "debian" ]]; then
  echo -e "${YELLOW}⚠️ Warning: Detected ${OS_ID}. This script is optimized for Ubuntu and Debian.${NC}"
fi

export DEBIAN_FRONTEND=noninteractive

# 3. System Packages Update & Essential Tools
echo ""
echo -e "${BOLD}[1/5] Updating APT repositories & installing base utilities...${NC}"
$SUDO apt-get update -y
$SUDO apt-get install -y --no-install-recommends \
  apt-transport-https \
  ca-certificates \
  curl \
  gnupg \
  lsb-release \
  git \
  jq \
  openssl \
  tar \
  ufw \
  htop \
  net-tools
echo -e "${GREEN}✅ System packages and base tools installed.${NC}"

# 4. Official Docker Engine & Docker Compose v2 Installation
echo ""
echo -e "${BOLD}[2/5] Installing official Docker Engine & Docker Compose Plugin...${NC}"

# Remove conflicting legacy packages if present
$SUDO apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

# Set up official Docker GPG key
$SUDO install -m 0755 -d /etc/apt/keyrings
if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
  curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" | $SUDO gpg --dearmor -o /etc/apt/keyrings/docker.gpg --yes
  $SUDO chmod a+r /etc/apt/keyrings/docker.gpg
fi

# Set up official Docker APT repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${OS_ID} \
  ${OS_VERSION_CODENAME} stable" | $SUDO tee /etc/apt/sources.list.d/docker.list > /dev/null

$SUDO apt-get update -y
$SUDO apt-get install -y --no-install-recommends \
  docker-ce \
  docker-ce-cli \
  containerd.io \
  docker-buildx-plugin \
  docker-compose-plugin

# Ensure Docker service is enabled and active
$SUDO systemctl enable --now docker

# Grant non-root user access to Docker
if [ "${TARGET_USER}" != "root" ]; then
  $SUDO usermod -aG docker "${TARGET_USER}"
  echo -e "${GREEN}✅ Added user '${TARGET_USER}' to the docker group.${NC}"
fi
echo -e "${GREEN}✅ Docker Engine $(docker --version) installed successfully.${NC}"

# 5. UFW Firewall Configuration
echo ""
echo -e "${BOLD}[3/5] Configuring UFW Firewall...${NC}"
# CRITICAL: Allow SSH port 22 first to prevent lockout
$SUDO ufw allow 22/tcp comment 'SSH Remote Access' >/dev/null 2>&1 || true
$SUDO ufw allow 80/tcp comment 'HTTP Web Dashboard' >/dev/null 2>&1 || true
$SUDO ufw allow 443/tcp comment 'HTTPS Web Dashboard' >/dev/null 2>&1 || true

# Enable UFW non-interactively
$SUDO ufw --force enable >/dev/null 2>&1 || true
echo -e "${GREEN}✅ UFW enabled with rules for ports 22 (SSH), 80 (HTTP), and 443 (HTTPS).${NC}"

# 6. Repository Working Directory & Secrets Generation
echo ""
echo -e "${BOLD}[4/5] Initializing production configuration & secure keys...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

ENV_PROD="${ROOT_DIR}/.env.production"
ENV_EXAMPLE="${ROOT_DIR}/.env.production.example"

if [ ! -f "${ENV_PROD}" ]; then
  if [ -f "${ENV_EXAMPLE}" ]; then
    cp "${ENV_EXAMPLE}" "${ENV_PROD}"
    echo -e "${BLUE}   Created .env.production from template.${NC}"
  else
    echo -e "${RED}❌ Error: ${ENV_EXAMPLE} not found.${NC}"
    exit 1
  fi

  # Generate cryptographically secure keys
  GEN_SECRET_KEY=$(openssl rand -hex 32)
  GEN_PG_PASS=$(openssl rand -base64 18 | tr -dc 'a-zA-Z0-9')
  GEN_ADMIN_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9')
  GEN_VIEWER_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9')
  GEN_DOCS_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9')

  # Replace placeholder strings in .env.production
  sed -i \
    -e "s|SECRET_KEY=.*|SECRET_KEY=${GEN_SECRET_KEY}|g" \
    -e "s|POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${GEN_PG_PASS}|g" \
    -e "s|DATABASE_URL=.*|DATABASE_URL=postgresql+asyncpg://risk_alert_prod_user:${GEN_PG_PASS}@postgres:5432/risk_alert_prod_db|g" \
    -e "s|ADMIN_PASSWORD=.*|ADMIN_PASSWORD=${GEN_ADMIN_PASS}|g" \
    -e "s|VIEWER_PASSWORD=.*|VIEWER_PASSWORD=${GEN_VIEWER_PASS}|g" \
    -e "s|DOCS_PASSWORD=.*|DOCS_PASSWORD=${GEN_DOCS_PASS}|g" \
    -e "s|FRONTEND_PORT=.*|FRONTEND_PORT=80|g" \
    "${ENV_PROD}"

  echo -e "${GREEN}✅ Generated cryptographic SECRET_KEY and PostgreSQL database credentials.${NC}"
  echo ""
  echo -e "${BOLD}${YELLOW}-----------------------------------------------------------------${NC}"
  echo -e "${BOLD}${YELLOW} 🔑 INITIAL DEFAULT ADMIN CREDENTIALS GENERATED:${NC}"
  echo -e "    Username: ${BOLD}admin${NC}"
  echo -e "    Password: ${BOLD}${GEN_ADMIN_PASS}${NC}"
  echo -e "    (Stored securely in ${ENV_PROD})${NC}"
  echo -e "${BOLD}${YELLOW}-----------------------------------------------------------------${NC}"
else
  echo -e "${GREEN}✅ Existing .env.production found. Preserving current secrets.${NC}"
fi

# Ensure .env symlinks to .env.production so standard docker compose commands load production vars automatically
ln -sf "${ENV_PROD}" "${ROOT_DIR}/.env"
echo -e "${GREEN}✅ Linked .env -> .env.production for seamless docker compose compatibility.${NC}"

# Check if Harbor is configured as an HTTP registry and configure Docker daemon insecure-registries
RAW_HARBOR=$(grep -E '^HARBOR_URL=' "${ENV_PROD}" | cut -d '=' -f2- | tr -d ' "' || true)
if [ -n "${RAW_HARBOR}" ]; then
  CLEAN_HARBOR=$(echo "${RAW_HARBOR}" | sed -e 's|^https://||' -e 's|^http://||' -e 's|/$||')
  if [ -n "${CLEAN_HARBOR}" ]; then
    echo -e "${BLUE}🔧 Ensuring Docker allows HTTP registry: ${CLEAN_HARBOR}...${NC}"
    $SUDO mkdir -p /etc/docker
    if [ -f /etc/docker/daemon.json ]; then
      if command -v jq >/dev/null 2>&1; then
        jq '.["insecure-registries"] = ((.["insecure-registries"] // []) + ["'"${CLEAN_HARBOR}"'"] | unique)' /etc/docker/daemon.json > /tmp/daemon.json && \
        $SUDO mv /tmp/daemon.json /etc/docker/daemon.json
      fi
    else
      echo "{\"insecure-registries\": [\"${CLEAN_HARBOR}\"]}" | $SUDO tee /etc/docker/daemon.json > /dev/null
    fi
    $SUDO systemctl restart docker || true
    echo -e "${GREEN}✅ Docker configured with insecure registry: ${CLEAN_HARBOR}${NC}"
  fi
fi

# 7. Server IP Address Detection
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

# 8. GitHub Actions Self-Hosted Runner Setup (Interactive / Optional)
echo ""
echo -e "${BOLD}[5/5] GitHub Actions Self-Hosted Runner Setup${NC}"
read -r -p "Do you want to configure and install the GitHub Actions Runner now? [y/N]: " RUNNER_CHOICE
RUNNER_CHOICE=${RUNNER_CHOICE:-N}

if [[ "${RUNNER_CHOICE}" =~ ^[Yy]$ ]]; then
  echo ""
  echo -e "${BLUE}Please find your runner registration token from:${NC}"
  echo -e "GitHub Repository → Settings → Actions → Runners → 'New self-hosted runner'"
  echo ""
  read -r -p "Enter GitHub Repository URL (e.g. https://github.com/org/repo): " REPO_URL
  read -r -p "Enter Runner Registration Token: " REG_TOKEN

  if [ -n "${REPO_URL}" ] && [ -n "${REG_TOKEN}" ]; then
    RUNNER_DIR="${HOME}/actions-runner"
    mkdir -p "${RUNNER_DIR}" && cd "${RUNNER_DIR}"

    echo -e "${BLUE}Downloading latest GitHub Actions Runner package...${NC}"
    RUNNER_VERSION="2.322.0"
    curl -o actions-runner-linux-x64.tar.gz -L \
      "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
    tar xzf ./actions-runner-linux-x64.tar.gz
    rm -f ./actions-runner-linux-x64.tar.gz

    echo -e "${BLUE}Configuring runner with GitHub...${NC}"
    ./config.sh --url "${REPO_URL}" --token "${REG_TOKEN}" --unattended --replace

    echo -e "${BLUE}Installing and starting runner systemd daemon...${NC}"
    $SUDO ./svc.sh install "${TARGET_USER}"
    $SUDO ./svc.sh start
    echo -e "${GREEN}✅ GitHub Actions Runner is ACTIVE and running as a systemd service!${NC}"
    cd "${ROOT_DIR}"
  else
    echo -e "${YELLOW}⚠️ Missing Repository URL or Token. Skipping runner registration.${NC}"
    echo -e "   You can register it later by following docs/SERVER_SETUP_GUIDE.md"
  fi
else
  echo -e "${BLUE}Skipping GitHub Actions Runner installation.${NC}"
  echo -e "You can configure it anytime later following docs/SERVER_SETUP_GUIDE.md"
fi

# 9. Completion Summary
echo ""
echo -e "${BOLD}${GREEN}=================================================================${NC}"
echo -e "${BOLD}${GREEN} 🎉 SERVER BOOTSTRAP COMPLETE!${NC}"
echo -e "${BOLD}${GREEN}=================================================================${NC}"
echo -e " Server Access: ${BOLD}http://${SERVER_IP}/${NC}"
echo -e " Configuration: ${BOLD}${ENV_PROD}${NC}"
echo ""
echo -e " Next Steps:"
echo -e " 1. Configure Harbor credentials, Qualys, and MISP keys in: ${BOLD}nano .env.production${NC}"
echo -e " 2. Deploy the application stack:"
echo -e "    ${BOLD}./scripts/deploy.sh${NC}        # Pulls & deploys images from Harbor"
echo -e "    OR"
echo -e "    ${BOLD}docker compose -f docker-compose.prod.yml up -d --build${NC}  # Builds locally"
echo ""
echo -e " If you were added to the docker group just now, run ${BOLD}'newgrp docker'${NC} or re-login."
echo -e "${BOLD}${GREEN}=================================================================${NC}"
