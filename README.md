# Risk Alert Dashboard & KnowledgeBase Remediation Platform

An internal enterprise security operations dashboard that automatically ingests scanned assets from the **Qualys Host Detection API**, maps every finding to actionable fix guidance via the **Qualys KnowledgeBase (KB) API**, and proactively correlates exposure against **MISP (FS-ISAC)** threat intelligence feeds.

Tracks active findings by **raw Qualys Severity 1–5** (Sev 5 Critical to Sev 1 Info), features a **minimalist 3-KPI executive overview**, an **in-dashboard threat alert center**, an admin-only **MISP Threat Feed**, an optional **Telegram Bot notification channel**, interactive **remediation workflows**, and multi-role **Role-Based Access Control (RBAC)**.

---

## 🌟 Key Features

- **Qualys Host Detection Ingestion**: Automated ingestion of scanned hosts, IP/DNS/NetBIOS metadata, operating systems, asset tags, and vulnerability detections (`/api/2.0/fo/asset/host/vm/detection/`). Supports delta sync (`detection_updated_since`) and tag filters.
- **KnowledgeBase (KB) Fix Remediation**: Ingests and caches the Qualys KnowledgeBase (`/api/2.0/fo/knowledge_base/vuln/`). Maps findings to step-by-step fix instructions rendered in styled HTML, vendor patch links, temporary workarounds, CVE links, and scanner diagnostic proof.
- **MISP (FS-ISAC) Threat Intelligence**: Proactively evaluates emergency CVE advisories against discovered host software inventory (`AssetSoftware`), producing diagnostic evidence, confidence ratings, and shell verification commands before scanner signatures are published.
- **Raw Qualys Severity Tracking Engine**: Categorizes vulnerability counts directly by raw Qualys Severity 1–5 (Sev 5 Critical, Sev 4 High, Sev 3 Medium, Sev 2 Low, Sev 1 Info), eliminating artificial synthetic score calculations. Inventory defaults to sorting by Sev 5 descending.
- **Actionable Remediation Tracking**: Slide-over drawer allowing security teams to update vulnerability status (`Open`, `In Progress`, `Acknowledged`, `False Positive`, `Resolved`). Status updates immediately recalculate the parent asset's active severity counters in real-time.
- **Executive 3-KPI Overview**: Minimalist executive dashboard featuring Monitored Assets, Total Active Vulnerabilities (highlighting Critical & High numbers with direct navigation), and MISP Threat Intelligence advisories, alongside a dedicated Qualys Severity Distribution widget.
- **Telegram Bot Alert Integration**: Dispatches formatted HTML alert cards whenever MISP threat intelligence CVE advisories match monitored server infrastructure. Routine Qualys scan sync is excluded from Telegram alerts to prevent notification fatigue.
- **Centralized Ingestion Architecture**: Manual "Sync Feed" is hosted strictly in the admin-only **MISP Threat Feed** page (`/misp`), while the Alert Center (`/alerts`) provides a dedicated database Refresh button.
- **Role-Based Access Control (RBAC)**: Multi-role JWT authentication (`Admin`, `Analyst`, `Owner`, `Viewer`) with host ownership scoping.

---

## 💻 How to Run

You can run the application in three ways:
1. **Direct Local Run** (Python venv + Node Vite)
2. **Docker Compose Development Stack** (Hot-reloading backend & frontend inside Docker)
3. **Docker Compose Production Stack** (Hardened multi-worker backend & Nginx Alpine)

---

### Option 1: Direct Local Run (Host Machine)

The backend connects to PostgreSQL (`postgresql+asyncpg://risk_alert_user:risk_alert_secret_password@localhost:5432/risk_alert_db`).

#### Prerequisites
- **Python**: 3.11+ (`python3 --version`)
- **Node.js**: 18+ & npm (`node -v`, `npm -v`)

#### Step 1: Start the FastAPI Backend
Open a terminal:
```bash
cd backend

# Create virtual environment (if not already created)
python3 -m venv venv

# Activate virtual environment:
# On macOS / Linux:
source venv/bin/activate
# On Windows (cmd):
# .\venv\Scripts\activate

# Install dependencies:
pip install -r requirements.txt

# Start FastAPI backend server:
uvicorn app.main:app --reload --port 8000
```
- The backend starts on **`http://localhost:8000`**.
- It automatically initializes database tables and seeds default user accounts.
- Interactive Swagger API docs are available at **`http://localhost:8000/docs`** (HTTP Basic Auth: `docs_admin` / `docs123`).

#### Step 2: Start the React Frontend
Open a second terminal:
```bash
cd frontend

# Install frontend dependencies (if not already installed)
npm install

# Start the Vite development server
npm run dev
```
- The dashboard is accessible at: **`http://localhost:3000`**.
- Vite dev server automatically proxies `/api` and `/docs` to `http://127.0.0.1:8000`.

---

### Option 2: Docker Compose Development Stack (Live Hot-Reload)

Runs **PostgreSQL 16**, **FastAPI** with `uvicorn --reload`, and **Vite Dev Server** with Hot Module Replacement (HMR) inside Docker containers with local code volume bind-mounts.

```bash
# 1. Start the development stack with live reload
docker compose -f docker-compose.dev.yml up --build

# Or run in background:
docker compose -f docker-compose.dev.yml up -d --build

# 2. View live logs
docker compose -f docker-compose.dev.yml logs -f

# 3. Stop development stack
docker compose -f docker-compose.dev.yml down
```

#### Development Access Points:
- **Frontend Dashboard (Vite HMR)**: `http://localhost:3000`
- **Backend API & Swagger Docs**: `http://localhost:8000/docs`
- **PostgreSQL Database**: `localhost:5432` (User: `risk_alert_dev_user`, Password: `risk_alert_dev_password`, DB: `risk_alert_dev_db`)

---

### Option 3: Docker Compose Production Stack (Hardened & Multi-Worker)

Deploys the production stack with a **non-root multi-worker FastAPI** container, pre-compiled React assets served via **Alpine Nginx** with gzip compression and security headers, and an internal PostgreSQL network.

```bash
# 1. Prepare production environment variables
cp .env.production.example .env.production
# Edit .env.production and set your secure passwords & API keys:
# nano .env.production

# 2. Build and launch production containers
docker compose -f docker-compose.prod.yml up -d --build

# 3. Check container health status
docker compose -f docker-compose.prod.yml ps

# 4. View production logs
docker compose -f docker-compose.prod.yml logs -f

# 5. Stop production stack
docker compose -f docker-compose.prod.yml down
```

#### Production Access Points:
- **Frontend & Unified API (Nginx)**: `http://localhost:80` (or `http://localhost:${FRONTEND_PORT:-80}`)
- **Interactive API Documentation**: `http://localhost:80/docs`
- **Health Check Endpoint**: `http://localhost:80/health`
- **Database & Backend**: Kept internal to the Docker network for maximum security (not exposed to external host ports).

*Note: You can also use the default `docker compose up -d --build` command, which runs the production configuration.*

---

## 🔐 Default Login Credentials & Multi-Role RBAC

| Role | Username | Password | Privileges & Scoping |
|---|---|---|---|
| **Admin** | `admin` | `admin123` | Full access: user management, admin settings & integrations, API documentation, MISP threat feed & manual sync, server ownership assignment |
| **Analyst** | `analyst` | `analyst123` | Security Operations: triage all infrastructure, view MISP threat feed, assign server owners, update remediation status, resolve alerts |
| **Owner** | `owner_appcore` | `owner123` | Scoped Host Ownership: **only** sees and remediates vulnerabilities on their assigned servers (e.g. `bk-appcore-sit`) |
| **Viewer** | `viewer` | `viewer123` | Read-only audit access: view metrics, inspect assets, view KB fix guidance without edit privileges |

*Note: On the login page, you can click any of the 4 quick-login demo buttons (**Admin**, **Analyst**, **Server Owner**, or **Viewer**) to sign in instantly.*

---

## ⚙️ Configuration & Live Qualys Onboarding

### 1. Connecting to Live Qualys Cloud Platform
To configure your live Qualys account:
1. Log into the dashboard as **Admin** (`admin` / `admin123`).
2. Navigate to **Admin Settings** in the left sidebar.
3. In the **Qualys Cloud Platform API Configuration** card:
   - Enter your **Qualys API Endpoint** (e.g., `https://qualysapi.qualys.com` for US Platform 1, or `https://qualysapi.qg2.apps.qualys.com` for US Platform 2).
   - Enter your **Qualys API Username** and **Password**.
   - (Optional) Enter an **Asset Tag Filter** (e.g. `PCI, Production`) to restrict the ingestion scope.
4. Click **Test Qualys Connection** to verify your credentials.
5. Click **Save All Settings**.
6. Click **Sync Now** in the top navigation bar to trigger a live ingestion.

### 2. Enabling Telegram Bot Alerts
1. Open Telegram and message `@BotFather` to create a bot: `/newbot`.
2. Copy the generated HTTP API token.
3. Create a Telegram channel or group, add your bot as an administrator.
4. Retrieve the `Chat ID` (e.g., send a message to `@userinfobot` or check `/getUpdates` on the Telegram Bot API).
5. In **Admin Settings**:
   - Toggle **Alerts Enabled**.
   - Paste your **Telegram Bot Token** and **Chat ID**.
   - Set the **Alert Anti-Spam Cooldown** (default: 6 hours).
6. Click **Send Test Alert to Telegram** to verify delivery.
7. Click **Save All Settings**.

---

## 🧪 Testing

The platform includes a comprehensive 3-layer test suite covering **End-to-End Browser Integration (Playwright)**, **Backend API & VAPT Security (pytest)**, and **Frontend Production Bundling (Vite / TypeScript)**.

### 1. End-to-End (E2E) Browser Integration Tests (Playwright)

A 17-test browser automation suite validates complete end-user journeys across all 4 RBAC roles in a real Chromium browser with human-paced motion slowdown (`--slowmo 1000` by default).

#### Test Suites Overview

| Suite | File | Tests | Highlights |
|---|---|---|---|
| **01. Auth & RBAC** | `tests_e2e/test_01_auth_and_rbac.py` | 5 | Invalid credential alerts, Admin login & clean logout, Viewer sidebar restrictions & `/settings` redirect, Owner scoped host view, Analyst operational permissions & MISP access without API docs |
| **02. Assets & Remediation** | `tests_e2e/test_02_assets_and_remediation.py` | 4 | 3-KPI executive cards, Day/Night theme toggle, asset search, Qualys Sync popover (Smart Delta vs. Full Recon), software inventory tab, slide-over KB remediation drawer |
| **03. Alerts Lifecycle** | `tests_e2e/test_03_alerts_lifecycle.py` | 2 | Alert severity filtering (Critical / High / Medium), Active vs. Remediated status tabs, expandable detection details, alert resolution & reopening flow |
| **04. MISP Threat Intel** | `tests_e2e/test_04_misp_threat_intel.py` | 2 | MISP feed table navigation, FS-ISAC advisory details, CVE live search, proactive match tags & affected server correlation |
| **05. Admin Governance** | `tests_e2e/test_05_admin_governance.py` | 4 | User management role overview, new user creation & instant login verification, audit logs search & filtering, Admin settings (MISP connection & SSL verification toggle) |

#### Running E2E Tests via `./run_e2e.sh`

Ensure the application stack is running (e.g. `http://localhost:3000` or Docker stack on port 80):

#### On Linux, macOS, or Git Bash (`./run_e2e.sh`)

```bash
# Run all 17 E2E tests in visible desktop browser with human-paced slowdown (1000ms delay)
./run_e2e.sh

# Run with a custom slowdown pace (e.g. 1500ms or 500ms)
./run_e2e.sh --slowmo 1500

# Run in headless mode (ideal for CI/CD pipelines and automated background runs)
./run_e2e.sh --headless

# Run visible desktop browser at full speed (no delay)
./run_e2e.sh --fast

# Run specific test suites individually
./run_e2e.sh test_01    # Auth & Multi-Role RBAC Suite
./run_e2e.sh test_02    # Assets, KPIs & KB Remediation Suite
./run_e2e.sh test_03    # Alert Center Lifecycle Suite
./run_e2e.sh test_04    # MISP Threat Intelligence Feed Suite
./run_e2e.sh test_05    # Admin Governance & Settings Suite

# Point to a custom URL (e.g. staging or production Docker stack)
E2E_BASE_URL="http://localhost:80" ./run_e2e.sh --headless
```

#### On Windows (PowerShell `.\run_e2e.ps1` or Command Prompt)

In **PowerShell** (run from the root directory):
```powershell
# Run all 17 E2E tests in visible desktop browser with human-paced slowdown (1000ms delay)
.\run_e2e.ps1

# Run with a custom slowdown pace (e.g. 1500ms)
.\run_e2e.ps1 -SlowMo 1500

# Run in headless mode (ideal for CI/CD or background runs)
.\run_e2e.ps1 -Headless

# Run visible desktop browser at full speed
.\run_e2e.ps1 -Fast

# Run specific test suites individually
.\run_e2e.ps1 test_01    # Auth & Multi-Role RBAC Suite
.\run_e2e.ps1 test_02    # Assets, KPIs & KB Remediation Suite
.\run_e2e.ps1 test_03    # Alert Center Lifecycle Suite
.\run_e2e.ps1 test_04    # MISP Threat Intelligence Feed Suite
.\run_e2e.ps1 test_05    # Admin Governance & Settings Suite

# Point to custom URL
$env:E2E_BASE_URL="http://localhost:80"; .\run_e2e.ps1 -Headless
```
*(If using **Git Bash** on Windows, you can also run `./run_e2e.sh` directly; it auto-detects `backend\venv\Scripts\pytest.exe`).*

---

### 2. Backend & API Test Suite (pytest)

Run the comprehensive 67-test automated suite across all API endpoints, models, sync workflows, and VAPT security layers (including SQL injection fuzzing, Basic Auth protection for Swagger docs, and RBAC matrix enforcement):

```bash
cd backend
source venv/bin/activate

# Run all 67 backend unit, integration, and security tests
PYTHONPATH=. ./venv/bin/pytest

# Run the complete end-to-end happy path integration test
PYTHONPATH=. ./venv/bin/pytest tests/test_integration_happy_path.py

# Run VAPT security & penetration tests
PYTHONPATH=. ./venv/bin/pytest tests/test_vapt_security.py
```

---

### 3. Frontend Production Build & Typecheck

Verify TypeScript compilation, linting, and the Vite production asset bundle:

```bash
cd frontend
npm run build
```

---

## 📋 Architecture & Directory Overview

```
dashboard_alert/
├── README.md                  # This file
├── run_e2e.sh                 # Unified Playwright E2E browser test runner (Linux / macOS / Git Bash)
├── run_e2e.ps1                # Native Windows PowerShell E2E browser test runner
├── docker-compose.yml         # Containerized production stack
├── .env.example               # Environment variables template
├── docs/                      # Architectural & integration guides
│   ├── developer_guide.md     # Technical architecture & developer instructions
│   ├── overview.md            # System architecture, RBAC matrix & workflows
│   ├── Qualys.md              # Qualys Cloud Platform & raw severity guide
│   ├── MISP.md                # MISP & FS-ISAC threat intelligence guide
│   └── Qualys_MISP_work_together.md # Cross-platform synergy & conflict prevention
├── tests_e2e/                 # Playwright automated browser integration tests
│   ├── conftest.py            # Fixtures (authenticated pages, cleanup, browser viewport)
│   ├── test_01_auth_and_rbac.py
│   ├── test_02_assets_and_remediation.py
│   ├── test_03_alerts_lifecycle.py
│   ├── test_04_misp_threat_intel.py
│   └── test_05_admin_governance.py
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI entrypoint & lifespan
│   │   ├── core/              # Config, Database, Security
│   │   ├── models/            # SQLAlchemy ORM models (Asset, Detection, KB, Software, MispFeed, Alert, User)
│   │   ├── schemas/           # Pydantic v2 schemas
│   │   ├── services/          # QualysClient, MispClient, RiskEngine, SyncService, TelegramService
│   │   └── api/routes/        # REST API endpoints (Auth, Dashboard, Assets, Software, MISP, Detections, KB, Settings)
│   ├── tests/                 # Backend unit, integration, and VAPT test suites (67 tests)
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── api/client.ts      # Axios client with JWT interceptor
    │   ├── context/           # AuthContext (login, logout, RBAC)
    │   ├── components/        # RemediationDrawer, SeverityPills, SeverityTag, Navbar, Sidebar
    │   └── pages/             # DashboardPage, AssetsPage, AssetDetailPage, AlertsPage, MispPage, UsersPage, SettingsPage
    └── package.json
```
