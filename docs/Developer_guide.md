# Developer & Technical Architecture Guide

Welcome to the **Risk Alert Dashboard & KnowledgeBase Remediation Platform** engineering guide. This document provides core architectural context, component specifications, development workflows, and operational instructions for developers and maintainers working on this codebase.

---

## 1. Project Mission & Core Capabilities

The platform monitors enterprise infrastructure security posture by integrating with the **Qualys Cloud Platform** and **MISP (FS-ISAC) Threat Intelligence**:
1. **Host Detection Ingestion**: Queries `/api/2.0/fo/asset/host/vm/detection/?action=list` to pull scanned assets, network metadata, operating systems, asset tags, and vulnerability detections.
2. **KnowledgeBase (KB) Mapping**: Queries `/api/2.0/fo/knowledge_base/vuln/?action=list&details=All` to enrich findings with step-by-step fix guidance, vendor patch links, temporary workarounds, CVE references, and scanner diagnostic proof.
3. **MISP (FS-ISAC) Proactive Threat Assessment**: Ingests emergency CVE advisories filtered strictly for `FS-ISAC`. Consolidates 240+ raw FS-ISAC threat events into distinct unique CVE assessment records (tracking both original MISP event dates and platform ingestion timestamps). Assesses exposure even when Qualys has not detected them yet by comparing vulnerable software and version criteria against server software inventory (`AssetSoftware`), producing evidence, confidence ratings, and shell verification commands.
4. **Raw Qualys Severity Tracking**: Categorizes vulnerability counts directly by raw Qualys Severity 1–5 (Sev 5 Critical, Sev 4 High, Sev 3 Medium, Sev 2 Low, Sev 1 Info), eliminating artificial synthetic risk score calculations.
5. **Remediation Action Tracking**: Interactive slide-over drawer allowing security teams to update vulnerability status (`Open`, `In Progress`, `Acknowledged`, `False Positive`, `Resolved`). Status changes automatically recalculate the parent asset's active severity counters in real-time.
6. **Telegram Alerting**: Dispatches formatted HTML alert cards whenever MISP threat intelligence CVE advisories match monitored server infrastructure (regardless of whether Qualys has detected them yet). Routine Qualys scan sync is excluded to prevent notification spam.
7. **Role-Based Access Control (RBAC)**: Multi-role JWT authentication (`Admin`, `Analyst`, `Owner`, `Viewer`) with host ownership scoping.

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
├── README.md                       # User-facing documentation & quickstart
├── docker-compose.yml              # Turnkey Docker deployment (PostgreSQL, Backend, Frontend)
├── .env.example                    # Environment template with documented defaults
├── .gitignore                      # Git exclusion rules
├── docs/                           # Architectural & integration guides
│   ├── developer_guide.md          # Technical architecture & contributor instructions (this file)
│   ├── overview.md                 # System architecture, RBAC matrix & workflows
│   ├── Qualys.md                   # Qualys Cloud Platform & raw severity guide
│   ├── MISP.md                     # MISP & FS-ISAC threat intelligence guide
│   └── Qualys_MISP_work_together.md # Cross-platform synergy & conflict prevention
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
│       │   ├── misp_client.py      # MISP REST API client scoped to FS-ISAC
│       │   ├── proactive_assessment_engine.py # Pre-scan inventory matcher & evaluator
│       │   ├── risk_engine.py      # Raw Qualys severity counter & level evaluator
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
    ├── nginx.conf                  # Nginx proxy forwarding /api and /docs to backend:8000
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
        │   │   └── Sidebar.tsx     # Collapsible sidebar nav with RBAC links
        │   ├── common/
        │   │   ├── SeverityTag.tsx # Qualys Severity 1 to 5 badges
        │   │   └── RemediationStatusBadge.tsx # Status pill for Open/Resolved/etc.
        │   └── remediation/
        │       └── RemediationDrawer.tsx # Slide-over drawer with KB solutions & action form
        └── pages/
            ├── DashboardPage.tsx   # Executive overview, KPI widgets, RTI metrics
            ├── AssetsPage.tsx      # Paginated inventory table with server name, owner assignment, & admin delete
            ├── AssetDetailPage.tsx # Host dossier with detections, installed software, & admin delete
            ├── AlertsPage.tsx      # Threat alert center (strictly affecting monitored servers)
            ├── MispPage.tsx        # Comprehensive MISP Threat Feed & FS-ISAC CVE assessments
            ├── AuditLogsPage.tsx   # Security audit trail & administrative history logs
            ├── UsersPage.tsx       # User role management (Admin, Analyst, Owner, Viewer)
            ├── SettingsPage.tsx    # Connection tester & settings editor
            └── LoginPage.tsx       # Sign-in page with preset demo credentials
```

---

## 4. How to Run Locally

### Option A: Direct Local Run (Zero-Docker / Fast Development)

The backend uses PostgreSQL (`postgresql+asyncpg://qualys_user:qualys_secret_password@localhost:5432/qualys_alert_db`), with seamless fallback to SQLite (`sqlite+aiosqlite:///./dashboard_alert.db`).

#### 1. Backend Terminal:
```bash
cd backend

# Activate virtual environment
source venv/bin/activate

# Run FastAPI with auto-reload
uvicorn app.main:app --reload --port 8000
```
- Swagger UI Documentation: `http://localhost:8000/docs`

#### 2. Frontend Terminal:
```bash
cd frontend

# Start Vite dev server
npm run dev
```
- The dashboard is accessible at: **`http://localhost:3000`** (Vite proxies all `/api` and `/docs` requests to `http://127.0.0.1:8000`).

---

### Option B: Docker Compose Run

```bash
cd dashboard_alert
cp .env.example .env
docker compose up -d --build
docker compose logs -f
```
- Frontend UI: `http://localhost:3000`
- Backend API Docs: `http://localhost:8000/docs`
- PostgreSQL Port: `5432`

---

## 5. Automated Testing Guidelines

To run the full automated test suite (all 48 tests across 8 modules):
```bash
cd backend
PYTHONPATH=. ./venv/bin/pytest

# Run the complete end-to-end happy path integration test
PYTHONPATH=. ./venv/bin/pytest tests/test_integration_happy_path.py
```

To verify the frontend build:
```bash
cd frontend
npm run build
```

---

## 6. Crucial Architectural Rules

1. **Severity Count Recalculation Dependency**:
   Whenever a detection's remediation status changes (e.g. via `PATCH /api/v1/detections/{id}/remediation`), **always** recalculate the parent `Asset`'s active severity counters (`critical_vulns`, `high_vulns`, `medium_vulns`, `low_vulns`, `info_vulns`, and `total_vulns`) using `RiskEngine.count_asset_severities`. Never update a detection without refreshing the parent asset counters.
2. **API Rate Limiting & Concurrency Control**:
   Qualys Cloud Platform restricts API concurrency to 2 concurrent requests per subscription. The backend enforces `asyncio.Lock()` (`sync_lock`) in `SyncService` to prevent overlapping synchronization runs and preserves API quotas by prioritizing incremental delta sync.
3. **Safe XML Parsing**:
   Always use `defusedxml.ElementTree` instead of Python's standard `xml.etree.ElementTree` to prevent XML entity expansion (Billion Laughs / XXE) attacks from external Qualys responses.
4. **RBAC Enforcement**:
   Every write endpoint (`POST`, `PATCH`, `PUT`, `DELETE`) must depend on `require_admin` from `app.api.deps`. Read-only endpoints (`GET`) must depend on `require_viewer`.
5. **Database Portability**:
   Maintain compatibility with both SQLite (`sqlite+aiosqlite`) and PostgreSQL (`postgresql+asyncpg`). Avoid database-specific raw SQL dialect syntax.
6. **API Documentation Protection**:
   The interactive Swagger UI (`/docs`) and OpenAPI schema (`/openapi.json`) are secured using HTTP Basic Authentication (`verify_docs_credentials`). ReDoc (`/redoc`) is disabled. Default credentials (`DOCS_USERNAME="docs_admin"`, `DOCS_PASSWORD="docs123"`) can be customized via `.env` or updated dynamically by administrators via Admin Settings (`POST /api/v1/settings`).
