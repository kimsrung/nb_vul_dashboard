# Blank Server Provisioning & Deployment Guide

This guide walks you through setting up a **new, blank Ubuntu / Debian server** to host the **Risk Alert Dashboard** (HTTP port 80) and run the **GitHub Actions Self-Hosted Runner** daemon.

---

## 1. System Requirements & Recommendations

| Resource | Minimum Requirement | Recommended Production |
| :--- | :--- | :--- |
| **Operating System** | Ubuntu 22.04 LTS / Debian 12 | Ubuntu 24.04 LTS |
| **CPU** | 2 vCPU cores | 4 vCPU cores |
| **Memory (RAM)** | 4 GB | 8 GB |
| **Disk Space** | 30 GB SSD | 50+ GB SSD |
| **Network** | Outbound HTTPS (443) to GitHub & Harbor | Inbound HTTP (80) & SSH (22) |

---

## 2. Fast-Track Provisioning (Automated Script)

The repository provides an automated provisioning script [`scripts/init_server.sh`](file:///Users/kimsrung/workspace/nbc/dashboard_alert/scripts/init_server.sh) that configures Docker, firewall rules, cryptographic secrets, and the GitHub Actions Runner in one pass.

### Step 2.1: Clone or Copy the Repository to the Server
SSH into your blank server:
```bash
ssh user@<SERVER_IP>

# Clone repository (or copy repository files via SCP/Git)
git clone https://github.com/<YOUR_ORG>/dashboard_alert.git
cd dashboard_alert
```

### Step 2.2: Run the Provisioning Script
Make the script executable and run it:
```bash
chmod +x scripts/init_server.sh
./scripts/init_server.sh
```

**What the script does automatically**:
1. Updates APT repositories and installs system dependencies (`curl`, `git`, `jq`, `ufw`, `openssl`).
2. Installs the official **Docker Engine** and **Docker Compose v2** plugin.
3. Adds your current user to the `docker` group (enables non-root `docker` commands).
4. Configures **UFW Firewall**: Allows SSH (port 22) and Web HTTP (port 80).
5. Generates `.env.production` with secure cryptographic keys (`SECRET_KEY`, `POSTGRES_PASSWORD`, initial `ADMIN_PASSWORD`) and sets `FRONTEND_PORT=80`.
6. Interactively prompts to download and install the **GitHub Actions Runner** systemd service.

---

## 3. Configuring Production Secrets & External APIs

Open `.env.production` to insert your enterprise credentials:
```bash
nano .env.production
```

Key variables to verify:
```bash
# Web Port (Default: 80 for direct browser access)
FRONTEND_PORT=80

# Harbor Container Registry (for automated deployments)
# If Harbor uses plain HTTP (port 80), use http://<ip>/
HARBOR_URL=http://10.20.40.55/
HARBOR_PROJECT=alert-dashboard
HARBOR_USERNAME=itsec
HARBOR_PASSWORD=<your_harbor_token>

# Qualys Cloud Platform Credentials
QUALYS_API_URL=https://qualysguard.qg1.apps.qualys.in
QUALYS_USERNAME=your_qualys_username
QUALYS_PASSWORD=your_qualys_password
QUALYS_MOCK_MODE=false

# MISP Threat Intelligence (FS-ISAC) Integration
MISP_URL=https://misp-itsec.nbc.gov.kh
MISP_API_KEY=your_misp_auth_key
MISP_MOCK_MODE=false
MISP_ZMQ_ENABLED=true
MISP_ZMQ_HOST=misp-itsec.nbc.gov.kh
MISP_ZMQ_PORT=50000

# Telegram Bot (Optional)
TELEGRAM_ENABLED=false
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

---

## 4. Starting the Application Stack

### Option A: Deploy Pre-built Images from Harbor (Recommended)
Once your GitHub Actions pipeline has pushed images to Harbor:
```bash
./scripts/deploy.sh
```

### Option B: Build and Start Locally on the Server
If deploying before the CI/CD pipeline is active:
```bash
docker compose -f docker-compose.prod.yml up -d --build
```

### Verify Container Health
```bash
docker compose -f docker-compose.prod.yml ps
```
All three containers should be in `Up (healthy)` state:
- `risk_alert_prod_postgres` (PostgreSQL 16)
- `risk_alert_prod_backend` (FastAPI 4-worker application)
- `risk_alert_prod_frontend` (Alpine Nginx reverse proxy serving port 80)

---

## 5. GitHub Self-Hosted Runner Maintenance

If you installed the runner during `init_server.sh`, it is already running as a background systemd service.

### Useful Runner Management Commands:
```bash
cd ~/actions-runner

# Check runner service status
sudo ./svc.sh status

# Stop runner
sudo ./svc.sh stop

# Restart runner
sudo ./svc.sh start

# Uninstall runner service
sudo ./svc.sh uninstall
```

### Verifying Runner in GitHub UI:
1. Navigate to your repository on GitHub.
2. Go to **Settings** → **Actions** → **Runners**.
3. You should see your runner listed with a green **Idle** badge and tags `[self-hosted, linux]`.

---

## 6. Accessing the Dashboard & First Login

Open your web browser and navigate to:
```
http://<SERVER_IP>/
```

1. **Sign In**:
   - **Username**: `admin`
   - **Password**: Found in `.env.production` (or printed in the terminal during `init_server.sh`).
2. **Post-Setup Security**:
   - Once logged in, navigate to **Settings** to customize sync intervals and verify MISP ZeroMQ and Qualys API connections.
   - Update the default admin password under your account settings.

---

## 7. Future Upgrades: Enabling HTTPS / TLS (Port 443)

When you are ready to enable HTTPS:
1. Place your corporate SSL certificate (`cert.pem`) and private key (`key.pem`) into a directory, e.g., `/etc/ssl/dashboard/`.
2. Update `frontend/nginx.conf` with the TLS listening block:
   ```nginx
   listen 443 ssl http2;
   ssl_certificate /etc/ssl/dashboard/cert.pem;
   ssl_certificate_key /etc/ssl/dashboard/key.pem;
   ```
3. In `docker-compose.prod.yml`, add the volume and port mapping:
   ```yaml
   ports:
     - "80:80"
     - "443:443"
   volumes:
     - /etc/ssl/dashboard:/etc/ssl/dashboard:ro
   ```
4. Restart the frontend container:
   ```bash
   docker compose -f docker-compose.prod.yml up -d frontend
   ```
