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

## 💻 How to Run Locally

You can run the application either **directly on your machine** (using local PostgreSQL or SQLite) or using **Docker Compose** (PostgreSQL mode).

---

### Option 1: Direct Local Run (Recommended for Development)

The backend connects to PostgreSQL (`postgresql+asyncpg://qualys_user:qualys_secret_password@localhost:5432/qualys_alert_db`), with instant fallback to SQLite (`sqlite+aiosqlite:///./dashboard_alert.db`).

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
- The backend will start on **`http://localhost:8000`**.
- It will automatically initialize the database schema and seed the default `admin` and `viewer` accounts.
- Interactive Swagger API docs are available at **`http://localhost:8000/docs`** (protected by HTTP Basic Auth; default credentials: **`docs_admin`** / **`docs123`**, configurable in Admin Settings).

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
- The Vite development server automatically proxies all `/api` requests to `http://127.0.0.1:8000`.

---

### Option 2: Docker Compose Run (Production / PostgreSQL Mode)

To run the containerized stack with **PostgreSQL 16**, **FastAPI**, and **React on Nginx**:

#### Prerequisites
- **Docker** and **Docker Compose** installed and running.

#### Steps:
```bash
# 1. Clone repository & navigate to directory
cd dashboard_alert

# 2. Copy the environment template
cp .env.example .env

# 3. Build and launch all containers
docker compose up -d --build

# 4. Check container status
docker compose ps
```

#### Access Points:
- **Frontend Dashboard**: `http://localhost:3000`
- **Backend API Docs**: `http://localhost:8000/docs`
- **PostgreSQL Database**: `localhost:5432`

To view live logs:
```bash
docker compose logs -f
```

To stop all containers:
```bash
docker compose down
```

---

## 🔐 Default Login Credentials & Multi-Role RBAC

| Role | Username | Password | Privileges & Scoping |
|---|---|---|---|
| **Admin** | `admin` | `admin123` | Full access: manual sync, user account management, assign server owners, edit settings, test Telegram |
| **Analyst** | `analyst` | `analyst123` | Security Operations: triage all infrastructure, assign server owners, update remediation status, resolve alerts |
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

### Backend & API Test Suite
Run the comprehensive 48-test automated suite across 8 modules (including authentication, RBAC, asset inventory, raw severity recalculation, MISP FS-ISAC proactive assessment, alert feeds, and complete end-to-end happy path integration):
```bash
cd backend
source venv/bin/activate

# Run all 48 tests across 8 test suites
PYTHONPATH=. ./venv/bin/pytest

# Run the comprehensive end-to-end happy path integration test
PYTHONPATH=. ./venv/bin/pytest tests/test_integration_happy_path.py
```

### Frontend Production Build Test
Verify TypeScript compilation and the Vite production bundle:
```bash
cd frontend
npm run build
```

---

## 📋 Architecture & Directory Overview

```
dashboard_alert/
├── README.md                  # This file
├── docker-compose.yml         # Containerized production stack
├── .env.example               # Environment variables template
├── docs/                      # Architectural & integration guides
│   ├── developer_guide.md     # Technical architecture & developer instructions
│   ├── overview.md            # System architecture, RBAC matrix & workflows
│   ├── Qualys.md              # Qualys Cloud Platform & raw severity guide
│   ├── MISP.md                # MISP & FS-ISAC threat intelligence guide
│   └── Qualys_MISP_work_together.md # Cross-platform synergy & conflict prevention
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI entrypoint & lifespan
│   │   ├── core/              # Config, Database, Security
│   │   ├── models/            # SQLAlchemy ORM models (Asset, Detection, KB, Software, MispFeed, Alert, User)
│   │   ├── schemas/           # Pydantic v2 schemas
│   │   ├── services/          # QualysClient, MispClient, RiskEngine, SyncService, TelegramService
│   │   └── api/routes/        # REST API endpoints (Auth, Dashboard, Assets, Software, MISP, Detections, KB, Settings)
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── api/client.ts      # Axios client with JWT interceptor
    │   ├── context/           # AuthContext (login, logout, RBAC)
    │   ├── components/        # RemediationDrawer, SeverityPills, SeverityTag, Navbar, Sidebar
    │   └── pages/             # DashboardPage, AssetsPage, AssetDetailPage, AlertsPage, MispPage, UsersPage, SettingsPage
    └── package.json
```
