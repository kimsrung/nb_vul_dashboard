# AGENTS.md — Developer & AI Agent Guide

Welcome to the **Risk Alert Dashboard & KnowledgeBase Remediation Platform**. This document provides context, architectural decisions, and operational instructions for AI agents and developers working on this codebase.

---

## 1. Project Mission & Core Capabilities

The platform monitors infrastructure security posture by integrating with the **Qualys Cloud Platform** and **MISP (FS-ISAC) Threat Intelligence**:
1. **Host Detection Ingestion**: Queries `/api/2.0/fo/asset/host/vm/detection/?action=list` to pull scanned assets, network metadata, operating systems, asset tags, and vulnerability detections.
2. **KnowledgeBase (KB) Mapping**: Queries `/api/2.0/fo/knowledge_base/vuln/?action=list&details=All` to enrich findings with step-by-step fix guidance, vendor patch links, temporary workarounds, CVE references, and scanner diagnostic proof.
3. **MISP (FS-ISAC) Proactive Threat Assessment**: Ingests emergency CVE advisories filtered strictly for `FS-ISAC`. Assesses exposure even when Qualys has not detected them yet by comparing vulnerable software and version criteria against server software inventory (`AssetSoftware`), producing evidence, confidence ratings, and shell verification commands.
4. **Composite Risk Scoring Engine**: Calculates real-time asset risk based on Qualys Severity 1–5, Real-Time Threat Intel (RTI: Ransomware, Active in Wild, Zero-Day, RCE, Public Exploit), and SLA age breach penalties.
5. **Remediation Action Tracking**: Interactive slide-over drawer allowing security teams to update vulnerability status (`Open`, `In Progress`, `Acknowledged`, `False Positive`, `Resolved`). Status changes automatically recalculate the parent asset's risk score in real-time.
6. **Telegram Alerting**: Dispatches formatted HTML alert cards for both Qualys risk breaches and MISP FS-ISAC proactive threat advisories to designated Telegram channels.
7. **Role-Based Access Control (RBAC)**: Multi-role JWT authentication (`Admin`, `Analyst`, `Owner`, `Viewer`) with host ownership scoping.
8. **Dual Mode Operation**: Built-in mock mode (`QUALYS_MOCK_MODE=true`, `MISP_MOCK_MODE=true`) for offline development/demo without live external credentials.

---

## 2. Tech Stack & Key Technologies

| Tier | Technologies |
|---|---|
| **Backend** | Python 3.11+, FastAPI, Uvicorn, Pydantic v2, Pydantic-Settings |
| **Database & ORM** | SQLAlchemy 2.0 (Async), aiosqlite (local SQLite), asyncpg (PostgreSQL), Greenlet |
| **Background Jobs** | APScheduler (AsyncIOScheduler) |
| **HTTP & XML Parsing** | HTTPX (async client), DefusedXML (safe ElementTree XML parser) |
| **Security & Auth** | PyJWT, Bcrypt, OAuth2 Password Bearer |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons, Axios |
| **Containerization** | Docker, Docker Compose, Nginx Alpine |

---

## 3. Repository Architecture & Directory Map

```
dashboard_alert/
├── AGENTS.md                       # Agent & maintainer instructions (this file)
├── README.md                       # User-facing documentation & quickstart
├── docker-compose.yml              # Turnkey Docker deployment (PostgreSQL, Backend, Frontend)
├── .env.example                    # Environment template with documented defaults
├── .gitignore                      # Git exclusion rules
├── backend/
│   ├── Dockerfile                  # Python 3.11-slim container spec
│   ├── requirements.txt            # Python dependencies
│   ├── dashboard_alert.db          # Local SQLite database (when running locally)
│   ├── venv/                       # Local Python virtual environment
│   └── app/
│       ├── main.py                 # FastAPI application, startup lifespan, DB seeding
│       ├── core/
│       │   ├── config.py           # Pydantic BaseSettings (.env loading)
│       │   ├── database.py         # Async engine & sessionmaker (SQLite / PostgreSQL)
│       │   └── security.py         # Bcrypt password hashing & JWT encoding/decoding
│       ├── models/                 # SQLAlchemy async models
│       │   ├── user.py             # User model (admin, analyst, owner, viewer)
│       │   ├── asset.py            # Asset model (IP, FQDN, OS, tags, risk score, owner)
│       │   ├── software.py         # AssetSoftware model (installed packages, versions, ports)
│       │   ├── misp_feed.py        # MispCveAssessment model (FS-ISAC advisories, reports)
│       │   ├── knowledge_base.py   # KnowledgeBase model (QID, title, solution, patches)
│       │   ├── detection.py        # Detection model (QID, severity, status, proof, remediation)
│       │   ├── alert.py            # Alert model (risk alerts, telegram dispatch logs)
│       │   ├── audit_log.py        # AuditLog model (immutable administrative history trail)
│       │   └── setting.py          # SystemSetting model (key-value config store)
│       ├── schemas/                # Pydantic validation schemas
│       │   ├── auth.py             # Login, Token, User schemas
│       │   ├── asset.py            # AssetListItem, PaginatedAssetsResponse, filters
│       │   ├── software.py         # SoftwareItem, SoftwareCreate
│       │   ├── misp.py             # MispAssessmentListItem, MispAssessmentDetail, reports
│       │   ├── detection.py        # DetectionItem, RemediationUpdate
│       │   ├── knowledge_base.py   # KnowledgeBaseItem
│       │   ├── alert.py            # AlertItem, PaginatedAlertsResponse
│       │   ├── audit_log.py        # AuditLogItem, PaginatedAuditLogsResponse
│       │   ├── dashboard.py        # DashboardSummaryResponse, KPI metrics
│       │   └── settings.py         # SystemSettingsResponse, test requests
│       ├── services/
│       │   ├── qualys_client.py    # Qualys API v2 client & streaming XML parser
│       │   ├── qualys_mock.py      # High-fidelity mock XML generator
│       │   ├── misp_client.py      # MISP REST API client scoped to FS-ISAC
│       │   ├── misp_mock.py        # FS-ISAC emergency advisory mock generator
│       │   ├── proactive_assessment_engine.py # Pre-scan inventory matcher & evaluator
│       │   ├── risk_engine.py      # Composite risk scoring computation
│       │   ├── audit_service.py    # Structured audit event logger
│       │   ├── sync_service.py     # Ingestion & delta synchronization coordinator
│       │   ├── telegram_service.py # Telegram bot HTML dispatch (Qualys + FS-ISAC alerts)
│       │   └── scheduler.py        # Background periodic sync runner (APScheduler)
│       └── api/
│           ├── deps.py             # Auth dependencies & RBAC (admin, analyst, viewer)
│           └── routes/
│               ├── auth.py         # POST /auth/login, user CRUD, GET /auth/owners
│               ├── dashboard.py    # GET /dashboard/summary, POST /dashboard/sync
│               ├── assets.py       # GET /assets (paginated), GET /assets/{id}, PATCH owner, DELETE /{id}
│               ├── software.py     # GET /assets/{id}/software inventory management
│               ├── misp.py         # GET /misp/feed, GET /misp/summary, POST /misp/sync
│               ├── detections.py   # GET /detections/{id}, PATCH /detections/{id}/remediation
│               ├── knowledge_base.py# GET /kb/{qid}
│               ├── alerts.py       # GET /alerts (paginated), POST /alerts/{id}/resolve
│               ├── audit_logs.py   # GET /audit-logs (paginated history trail)
│               └── settings.py     # GET /settings, POST /settings, connection testers
└── frontend/
    ├── Dockerfile                  # Multi-stage Vite build + Nginx Alpine runner
    ├── nginx.conf                  # Nginx proxy forwarding /api to backend:8000
    ├── package.json                # React, Vite, Tailwind CSS, Lucide dependencies
    ├── tsconfig.json               # TypeScript configuration
    ├── vite.config.ts              # Vite config with local proxy to localhost:8000
    ├── tailwind.config.js          # Dark theme palette definition
    ├── index.html                  # HTML template
    └── src/
        ├── main.tsx                # React DOM root entrypoint
        ├── App.tsx                 # Root component orchestrating fixed layout & tab routing
        ├── index.css               # Global styles & Tailwind directives
        ├── api/
        │   └── client.ts           # Axios client with JWT interceptor & data interfaces
        ├── context/
        │   └── AuthContext.tsx     # Session state, login, logout, and role helpers
        ├── components/
        │   ├── layout/
        │   │   ├── Navbar.tsx      # Fixed top bar with collapse toggle & user session
        │   │   └── Sidebar.tsx     # Collapsible sidebar nav (w-64 <-> w-16)
        │   ├── common/
        │   │   ├── RiskBadge.tsx   # Visual indicator for Critical/High/Medium/Low
        │   │   ├── SeverityTag.tsx # Qualys Severity 1 to 5 badges
        │   │   └── RemediationStatusBadge.tsx # Status pill for Open/Resolved/etc.
        │   └── remediation/
        │       └── RemediationDrawer.tsx # Slide-over drawer with KB solutions & action form
        └── pages/
            ├── DashboardPage.tsx   # Executive overview, KPI widgets, RTI metrics
            ├── AssetsPage.tsx      # Paginated inventory table with server name, drag-resize, owner assignment, & admin delete
            ├── AssetDetailPage.tsx # Host dossier with detections, installed software, & admin delete
            ├── AlertsPage.tsx      # Threat alert center & FS-ISAC assessment report drawer (paginated)
            ├── AuditLogsPage.tsx   # Security audit trail & administrative history logs
            ├── UsersPage.tsx       # User role management (Admin, Analyst, Owner, Viewer)
            ├── SettingsPage.tsx    # Connection tester & settings editor
            └── LoginPage.tsx       # Sign-in page with preset demo credentials
```

---

## 4. How to Run Locally (Step-by-Step)

### Option A: Direct Local Run (Zero-Docker / Fast Development)

The backend uses PostgreSQL (`postgresql+asyncpg://qualys_user:qualys_secret_password@localhost:5432/qualys_alert_db`), with seamless fallback to SQLite (`sqlite+aiosqlite:///./dashboard_alert.db`).

#### 1. Backend Terminal:
```bash
cd /Users/kimsrung/workspace/nbc/dashboard_alert/backend

# Activate the virtual environment
source venv/bin/activate

# Install dependencies (already satisfied in venv, but for reference):
pip install -r requirements.txt

# Run FastAPI with auto-reload
uvicorn app.main:app --reload --port 8000
```
- The backend will automatically create database tables, seed default `admin` and `viewer` users, and execute an initial mock Qualys sync on startup.
- Swagger UI Documentation: `http://localhost:8000/docs`

#### 2. Frontend Terminal:
```bash
cd /Users/kimsrung/workspace/nbc/dashboard_alert/frontend

# Install dependencies (already installed)
npm install

# Start Vite dev server
npm run dev
```
- The dashboard is accessible at: **`http://localhost:3000`** (Vite proxies all `/api` requests to `http://127.0.0.1:8000`).

---

### Option B: Docker Compose Run

To run the containerized stack with PostgreSQL 16:

```bash
cd /Users/kimsrung/workspace/nbc/dashboard_alert

# Copy environment variables
cp .env.example .env

# Build and launch all services in background
docker compose up -d --build

# View logs
docker compose logs -f
```
- Frontend UI: `http://localhost:3000`
- Backend API Docs: `http://localhost:8000/docs`
- PostgreSQL Port: `5432`

---

## 5. Default Credentials & Role-Based Access Control (RBAC)

| Role | Username | Password | Permissions & Scoping |
|---|---|---|---|
| **Admin** | `admin` | `admin123` | Full access: trigger Qualys sync, manage user accounts & roles, assign server owners, edit settings, test Telegram |
| **Analyst** | `analyst` | `analyst123` | Triage & SecOps: inspect all infrastructure, assign server owners, update remediation status, mark alerts resolved |
| **Owner** | `owner_appcore` | `owner123` | Scoped Host Ownership: **only** sees and remediates vulnerabilities on their assigned servers (e.g. `bk-appcore-sit`) |
| **Viewer** | `viewer` | `viewer123` | Read-only audit access: view dashboard, inspect all assets and KB remediation advice without edit permissions |

---

## 6. How to Run Automated Tests

To run the comprehensive test suite covering Authentication, RBAC, Asset Inventory & PoC, Risk Engine recalculations, MISP Threat Intelligence & ZeroMQ simulation, Threat Alerts, Settings, and Telegram alert formatting:

```bash
cd /Users/kimsrung/workspace/nbc/dashboard_alert/backend

# Run full pytest suite (all 30 tests)
PYTHONPATH=. ./venv/bin/pytest

# Run a specific test module
PYTHONPATH=. ./venv/bin/pytest tests/test_assets_poc.py
PYTHONPATH=. ./venv/bin/pytest tests/test_auth_rbac.py
PYTHONPATH=. ./venv/bin/pytest tests/test_risk_remediation.py
PYTHONPATH=. ./venv/bin/pytest tests/test_misp_assessment.py
PYTHONPATH=. ./venv/bin/pytest tests/test_alerts.py
PYTHONPATH=. ./venv/bin/pytest tests/test_settings_audit.py
```

To verify the frontend build:
```bash
cd /Users/kimsrung/workspace/nbc/dashboard_alert/frontend
npm run build
```

---

## 7. Crucial Architectural Rules for AI Agents

When editing or extending this codebase, adhere to the following rules:

1. **Risk Recalculation Dependency**:
   Whenever a detection's remediation status changes (e.g. via `PATCH /api/v1/detections/{id}/remediation`), **always** recalculate the parent `Asset`'s `risk_score`, `risk_level`, and `is_risky` using `RiskEngine.calculate_asset_risk`. Never update a detection without refreshing the parent asset score.
2. **Qualys Mock vs Live**:
   Never remove `qualys_mock.py`. The mock generator guarantees that developers and CI/CD pipelines can run tests without real Qualys credentials or burning API rate limits. Ensure any new Qualys fields added to `qualys_client.py` are also mirrored in `qualys_mock.py`.
3. **Safe XML Parsing**:
   Always use `defusedxml.ElementTree` instead of Python's standard `xml.etree.ElementTree` to prevent XML entity expansion (Billion Laughs / XXE) attacks from external Qualys responses.
4. **RBAC Enforcement**:
   Every write endpoint (`POST`, `PATCH`, `PUT`, `DELETE`) must depend on `require_admin` from `app.api.deps`. Read-only endpoints (`GET`) must depend on `require_viewer`.
5. **Database Portability**:
   Maintain compatibility with both SQLite (`sqlite+aiosqlite`) and PostgreSQL (`postgresql+asyncpg`). Avoid database-specific raw SQL dialect syntax.
