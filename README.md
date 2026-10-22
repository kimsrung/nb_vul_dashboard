# Risk Alert Dashboard & KnowledgeBase Remediation Platform

An internal enterprise security operations dashboard that automatically ingests scanned assets from the **Qualys Host Detection API**, computes real-time **composite risk scores**, and maps every finding to actionable fix guidance via the **Qualys KnowledgeBase (KB) API**.

Features an **in-dashboard alert center**, an optional **Telegram Bot notification channel**, interactive **remediation workflows**, and **Role-Based Access Control (RBAC)**.

---

## 🌟 Key Features

- **Qualys Host Detection Ingestion**: Automated ingestion of scanned hosts, IP/DNS/NetBIOS metadata, operating systems, asset tags, and vulnerability detections (`/api/2.0/fo/asset/host/vm/detection/`). Supports delta sync (`detection_updated_since`) and tag filters.
- **KnowledgeBase (KB) Fix Remediation**: Ingests and caches the Qualys KnowledgeBase (`/api/2.0/fo/knowledge_base/vuln/`). Maps findings to step-by-step fix instructions, vendor patch links, temporary workarounds, CVE links, and scanner diagnostic proof.
- **Composite Risk Scoring Engine**: Calculates real-time asset risk based on Qualys Severity 1–5, Real-Time Threat Intel (RTI: Ransomware, Active in Wild, Zero-Day, RCE, Public Exploit), and SLA age breach penalties.
- **Actionable Remediation Tracking**: Slide-over drawer allowing security teams to update vulnerability status (`Open`, `In Progress`, `Acknowledged`, `False Positive`, `Resolved`). Status updates immediately recalculate the parent asset's risk score in real-time.
- **Telegram Bot Alert Integration**: Dispatches formatted HTML alerts with emoji status, host metadata, top findings, and remediation links, backed by anti-spam cooldown logic.
- **Role-Based Access Control (RBAC)**: JWT authentication enforcing `Admin` (full write & sync) and `Viewer` (read-only audit) permissions.
- **Dual-Mode Operation**: Seamlessly switch between **Mock / Offline Demo Mode** (synthetic Qualys XML responses) and **Live Qualys Cloud API**.

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
- It will automatically create tables in `dashboard_alert.db`, seed the default `admin` and `viewer` accounts, and execute an initial mock Qualys sync.
- Interactive Swagger API docs are available at **`http://localhost:8000/docs`**.

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
By default, the platform runs in **Mock Demo Mode** to allow offline testing and development without live credentials.

To switch to your live Qualys account:
1. Log into the dashboard as **Admin** (`admin` / `admin123`).
2. Navigate to **Admin Settings** in the left sidebar.
3. In the **Qualys Cloud Platform API Configuration** card:
   - Enter your **Qualys API Endpoint** (e.g., `https://qualysapi.qualys.com` for US Platform 1, or `https://qualysapi.qg2.apps.qualys.com` for US Platform 2).
   - Enter your **Qualys API Username** and **Password**.
   - Uncheck **Enable Mock / Offline Demo Mode**.
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
Run the automated test suite verifying auth, RBAC, asset scoring, remediation workflow, and alert feeds:
```bash
cd backend
source venv/bin/activate
PYTHONPATH=. python -c "
import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app

async def test():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url='http://test') as client:
        res = await client.post('/api/v1/auth/login', json={'username': 'admin', 'password': 'admin123'})
        assert res.status_code == 200
        token = res.json()['access_token']
        headers = {'Authorization': f'Bearer {token}'}
        res = await client.get('/api/v1/dashboard/summary', headers=headers)
        assert res.status_code == 200
        print('All tests passed! Total assets:', res.json()['total_assets'])

asyncio.run(test())
"
```

### Frontend Production Build Test
Verify the TypeScript compilation and Vite production bundle:
```bash
cd frontend
npm run build
```

---

## 📋 Architecture & Directory Overview

```
dashboard_alert/
├── AGENTS.md                  # Developer & AI Agent instructions
├── README.md                  # This file
├── docker-compose.yml         # Containerized production stack
├── .env.example               # Environment variables template
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI entrypoint & lifespan
│   │   ├── core/              # Config, Database, Security
│   │   ├── models/            # SQLAlchemy ORM models (Asset, Detection, KB, Alert, User)
│   │   ├── schemas/           # Pydantic v2 schemas
│   │   ├── services/          # QualysClient, QualysMock, RiskEngine, SyncService, TelegramService
│   │   └── api/routes/        # REST API endpoints (Auth, Dashboard, Assets, Detections, KB, Settings)
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── api/client.ts      # Axios client with JWT interceptor
    │   ├── context/           # AuthContext (login, logout, RBAC)
    │   ├── components/        # RemediationDrawer, RiskBadge, SeverityTag, Navbar, Sidebar
    │   └── pages/             # DashboardPage, AssetsPage, AssetDetailPage, AlertsPage, SettingsPage
    └── package.json
```
