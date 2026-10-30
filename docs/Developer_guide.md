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
| **Database & ORM** | SQLAlchemy 2.0 (Async), asyncpg (PostgreSQL), Greenlet |
| **Background Jobs** | APScheduler (AsyncIOScheduler) |
| **HTTP & XML Parsing** | HTTPX (async client), DefusedXML (safe ElementTree XML parser) |
| **Security & Auth** | PyJWT, Bcrypt, OAuth2 Password Bearer |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons, Axios |
| **Containerization** | Docker, Docker Compose, Nginx Alpine |
| **Testing & Quality** | Pytest, Pytest-Asyncio, Playwright (Chromium E2E Browser Testing) |

---

## 3. Repository Architecture & Directory Map

```
dashboard_alert/
├── README.md                       # User-facing documentation & quickstart
├── run_e2e.sh                      # Unified Playwright E2E browser test runner (Linux / macOS / Git Bash)
├── run_e2e.ps1                     # Native Windows PowerShell E2E browser test runner
├── docker-compose.yml              # Default production deployment stack
├── docker-compose.dev.yml          # Live hot-reloading development stack
├── docker-compose.prod.yml         # Hardened multi-worker production stack
├── .env.example                    # Environment template with documented defaults
├── .env.development                # Development presets (mock mode enabled)
├── .env.production.example         # Production template with security guidelines
├── .gitignore                      # Git exclusion rules
├── docs/                           # Architectural & integration guides
│   ├── developer_guide.md          # Technical architecture & contributor instructions (this file)
│   ├── overview.md                 # System architecture, RBAC matrix & workflows
│   ├── Qualys.md                   # Qualys Cloud Platform & raw severity guide
│   ├── MISP.md                     # MISP & FS-ISAC threat intelligence guide
│   └── Qualys_MISP_work_together.md # Cross-platform synergy & conflict prevention
├── tests_e2e/                      # Playwright automated browser integration tests
│   ├── conftest.py                 # Fixtures (authenticated pages, cleanup, browser viewport)
│   ├── test_01_auth_and_rbac.py    # Multi-role RBAC, auth & scoping tests
│   ├── test_02_assets_and_remediation.py # KPIs, themes, assets, and KB remediation
│   ├── test_03_alerts_lifecycle.py # Alert center severity filters & status transitions
│   ├── test_04_misp_threat_intel.py # MISP threat intelligence feed & CVE search
│   └── test_05_admin_governance.py # User management, audit logs, and settings
├── backend/
│   ├── Dockerfile                  # Hardened production container spec (non-root, multi-worker)
│   ├── Dockerfile.dev              # Development container spec (uvicorn live reload)
│   ├── requirements.txt            # Python dependencies
│   ├── venv/                       # Local Python virtual environment
│   ├── tests/                      # Backend unit, integration, and VAPT test suites (67 tests)
│   └── app/
│       ├── main.py                 # FastAPI application, startup lifespan, DB seeding
│       ├── core/
│       │   ├── config.py           # Pydantic BaseSettings (.env loading)
│       │   ├── database.py         # Async engine & sessionmaker (PostgreSQL)
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
│       │   ├── setting.py          # SystemSetting model (key-value config store)
│       │   └── sync_job.py         # SyncJob model (background ingestion job lifecycle & telemetry)
│       ├── schemas/                # Pydantic validation schemas
│       │   ├── auth.py             # Login, Token, User schemas
│       │   ├── asset.py            # AssetListItem, PaginatedAssetsResponse, filters
│       │   ├── software.py         # SoftwareItem, SoftwareCreate
│       │   ├── misp.py             # MispAssessmentListItem, MispAssessmentDetail, reports
│       │   ├── sync.py             # SyncTriggerRequest, SyncJobResponse, SyncStatusResponse, CancelJob
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
│       │   ├── sync_service.py     # Ingestion & delta synchronization coordinator (Qualys)
│       │   ├── misp_sync_service.py# Ingestion & threat matching coordinator (MISP)
│       │   ├── sync_runner.py      # Background worker executor, DB locking & job lifecycle manager
│       │   ├── telegram_service.py # Telegram bot HTML dispatch (Qualys + FS-ISAC alerts)
│       │   └── scheduler.py        # Background periodic sync runner (APScheduler)
│       └── api/
│           ├── deps.py             # Auth dependencies & RBAC (require_admin, require_analyst_or_admin, require_viewer)
│           └── routes/
│               ├── auth.py         # POST /auth/login, user CRUD, GET /auth/owners
│               ├── dashboard.py    # GET /dashboard/summary (KPI overview)
│               ├── sync.py         # POST /sync/qualys, POST /sync/misp, GET /sync/status, GET /sync/jobs, POST /sync/jobs/{id}/cancel
│               ├── assets.py       # GET /assets (paginated), GET /assets/{id}, PATCH owner, DELETE /{id}
│               ├── software.py     # GET /assets/{id}/software inventory management
│               ├── misp.py         # GET /misp/feed, GET /misp/summary
│               ├── detections.py   # GET /detections/{id}, PATCH /detections/{id}/remediation
│               ├── knowledge_base.py# GET /kb/{qid}
│               ├── alerts.py       # GET /alerts (paginated), POST /alerts/{id}/resolve
│               ├── audit_logs.py   # GET /audit-logs (paginated history trail)
│               └── settings.py     # GET /settings, POST /settings, connection testers
└── frontend/
    ├── Dockerfile                  # Multi-stage production build + Nginx Alpine runner
    ├── Dockerfile.dev              # Development container spec (Vite HMR dev server)
    ├── nginx.conf                  # Nginx proxy forwarding /api, /docs, /health to backend:8000
    ├── package.json                # React, Vite, Tailwind CSS, Lucide dependencies
    ├── tsconfig.json               # TypeScript configuration
    ├── vite.config.ts              # Vite config with dynamic proxy to backend
    ├── tailwind.config.js          # Theme palette definition (Day & Night modes)
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

The backend uses PostgreSQL (`postgresql+asyncpg://risk_alert_user:risk_alert_secret_password@localhost:5432/risk_alert_db`).

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

### Option B: Docker Compose Development Stack (Live Hot-Reload)

Runs PostgreSQL 16, FastAPI (`uvicorn --reload`), and Vite Dev Server (HMR) with volume bind-mounts:

```bash
docker compose -f docker-compose.dev.yml up --build
```
- Frontend UI: `http://localhost:3000`
- Backend API & Swagger Docs: `http://localhost:8000/docs`
- PostgreSQL Port: `localhost:5432` (`risk_alert_dev_user` / `risk_alert_dev_password`)

---

### Option C: Docker Compose Production Stack (Hardened & Multi-Worker)

Deploys the production stack with a non-root multi-worker FastAPI backend and Alpine Nginx reverse proxy on port 80:

```bash
docker compose -f docker-compose.prod.yml up -d --build
# Or use standard default:
docker compose up -d --build
```
- Unified Web & API: `http://localhost:80`
- Interactive API Docs: `http://localhost:80/docs`
- Health Check Endpoint: `http://localhost:80/health`
- Database & Backend: Kept internal to the Docker network for maximum security.

---

## 5. Automated Testing Guidelines

### A. End-to-End (E2E) Browser Integration Tests (Playwright)

A comprehensive 17-test browser automation suite validates complete user journeys across all 4 RBAC roles in a real Chromium browser instance.

#### On Linux, macOS, or Git Bash (`./run_e2e.sh`):
```bash
# Run all 17 E2E tests in visible desktop browser with human-paced slowdown (1000ms delay)
./run_e2e.sh

# Run with a custom slowdown pace (e.g. 1500ms or 500ms)
./run_e2e.sh --slowmo 1500

# Run in headless mode (ideal for CI/CD and background runners)
./run_e2e.sh --headless

# Run visible desktop browser at full speed (no delay)
./run_e2e.sh --fast

# Run specific test suites individually
./run_e2e.sh test_01    # Auth & Multi-Role RBAC Suite (5 tests)
./run_e2e.sh test_02    # Assets, KPIs & KB Remediation Suite (4 tests)
./run_e2e.sh test_03    # Alert Center Lifecycle Suite (2 tests)
./run_e2e.sh test_04    # MISP Threat Intelligence Feed Suite (2 tests)
./run_e2e.sh test_05    # Admin Governance & Settings Suite (4 tests)

# Point to custom URL
E2E_BASE_URL="http://localhost:80" ./run_e2e.sh --headless
```

#### On Windows (PowerShell `.\run_e2e.ps1`):
```powershell
# Run all 17 E2E tests with human-paced slowdown (1000ms delay)
.\run_e2e.ps1

# Custom slowdown or headless
.\run_e2e.ps1 -SlowMo 1500
.\run_e2e.ps1 -Headless

# Run specific suite
.\run_e2e.ps1 test_01
```
*(If using **Git Bash** on Windows, you can also run `./run_e2e.sh` directly as it auto-detects `backend\venv\Scripts\pytest.exe`).*

### B. Backend Unit, Integration & Security Test Suite (pytest)

The automated backend test suite (78 tests across 11 modules including VAPT security and penetration testing) enforces strict database isolation:
- `backend/tests/conftest.py` automatically binds to `risk_alert_test_db` (or `TEST_DATABASE_URL`), ensuring that primary/production databases (`risk_alert_db`) are **never wiped or overwritten with mock data**.
- A hard runtime safety guard in `conftest.py` aborts with `RuntimeError` if tests are pointed at any non-test database.

```bash
cd backend
source venv/bin/activate

# Run all 78 backend unit, integration, and security tests
PYTHONPATH=. ./venv/bin/pytest

# Run the complete end-to-end happy path integration test
PYTHONPATH=. ./venv/bin/pytest tests/test_integration_happy_path.py

# Run background synchronization & concurrency locking tests
PYTHONPATH=. ./venv/bin/pytest tests/test_background_sync.py

# Run VAPT security, fuzzing, and penetration tests
PYTHONPATH=. ./venv/bin/pytest tests/test_vapt_security.py
```

### C. Frontend Production Build & Typecheck

To verify TypeScript compilation, linting, and the Vite production asset bundle:
```bash
cd frontend
npm run build
```

---

## 6. Background Synchronization Engine Architecture

The platform implements an asynchronous, non-blocking background synchronization engine managed by [`SyncRunner`](file:///Users/kimsrung/workspace/nbc/dashboard_alert/backend/app/services/sync_runner.py) and backed by PostgreSQL [`SyncJob`](file:///Users/kimsrung/workspace/nbc/dashboard_alert/backend/app/models/sync_job.py) records.

### A. Architectural Workflow

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Admin User (Browser / CLI)
    participant API as FastAPI Router (/api/v1/sync/*)
    participant Runner as SyncRunner (Worker Engine)
    participant DB as PostgreSQL (sync_jobs & audit_logs)
    participant Upstream as External APIs (Qualys / MISP)
    participant UI as Frontend Poller

    Admin->>API: POST /api/v1/sync/qualys?mode=delta (Admin JWT)
    API->>Runner: acquire_sync_lock(db, source="qualys")
    alt Another Sync Job is Active (RUNNING)
        Runner-->>API: Conflict: Active job in progress
        API-->>Admin: HTTP 409 Conflict {"detail": "Job #X already running"}
    else Lock Acquired
        Runner->>DB: INSERT SyncJob(status='RUNNING', started_at=NOW())
        API-->>Admin: HTTP 202 Accepted {"job_id": 12, "status": "running"}
        Note over API,Runner: FastAPI BackgroundTasks executes runner in background
        par Background Ingestion
            Runner->>Upstream: Request Delta XML / MISP Feed
            Upstream-->>Runner: Return Findings / Threat Events
            Runner->>DB: Upsert Assets, Detections, KB & Proactive Matches
            Runner->>DB: UPDATE SyncJob(status='SUCCESS', progress=100)
            Runner->>DB: INSERT AuditLog(action='QUALYS_DELTA_SYNC')
        and Frontend Polling
            loop Every 3-5 seconds while status == RUNNING
                UI->>API: GET /api/v1/sync/status?source=qualys
                API->>DB: Query latest SyncJob
                DB-->>API: Return status, progress, duration, details
                API-->>UI: HTTP 200 {"status": "running", "progress": 45}
            end
            UI->>API: GET /api/v1/sync/status?source=qualys
            API-->>UI: HTTP 200 {"status": "idle", "last_job": {"status": "success"}}
        end
    end
```

### B. REST API Endpoints (`/api/v1/sync/*`)

| Method | Endpoint | Access | Response Codes | Description |
|---|---|---|---|---|
| `POST` | `/api/v1/sync/qualys?mode=delta\|full` | Admin | `202 Accepted`<br>`409 Conflict`<br>`401/403` | Triggers background Qualys host detection and KB ingestion in delta or full reconciliation mode. Returns immediately with `job_id`. |
| `POST` | `/api/v1/sync/misp` | Admin | `202 Accepted`<br>`409 Conflict`<br>`401/403` | Triggers background MISP threat intelligence feed sync and proactive inventory exposure evaluation. |
| `GET` | `/api/v1/sync/status?source=qualys\|misp` | Viewer / Any Authenticated | `200 OK`<br>`400 Bad Request` | Returns current worker state (`idle` or `running`), active job progress, and summary of the most recently finished job. |
| `GET` | `/api/v1/sync/jobs?source=...&limit=20` | Viewer / Any Authenticated | `200 OK` | Paginated chronological list of past sync jobs with duration, errors, and outcome metrics. |
| `POST` | `/api/v1/sync/jobs/{job_id}/cancel` | Admin | `200 OK`<br>`400 Bad Request`<br>`404 Not Found` | Cancels an actively running sync job, releases the lock, and sets job status to `CANCELLED`. |

### C. Job Lifecycle States & State Machine

Every synchronization execution is tracked as a [`SyncJob`](file:///Users/kimsrung/workspace/nbc/dashboard_alert/backend/app/models/sync_job.py) record through the following lifecycle:

- `PENDING`: Initial state upon creation before worker dispatch.
- `RUNNING`: Job is actively running. Concurrency lock is held; periodic heartbeats update `updated_at`.
- `SUCCESS`: Ingestion and evaluation finished cleanly with telemetry recorded in `details`.
- `FAILED`: Execution failed due to network errors, API quota limits, or invalid XML. Error trace stored in `error_message`.
- `CANCELLED`: Interrupted by an administrator via `POST /api/v1/sync/jobs/{id}/cancel`.

### D. Concurrency Locking & Stale Job Auto-Recovery

1. **Atomic Concurrency Lock**:
   To prevent exceeding the Qualys subscription limit (max 2 concurrent API connections) and database race conditions during asset inventory sweeps, `SyncRunner.acquire_sync_lock()` checks for any existing job in `RUNNING` status for the target source. If found, new trigger requests are immediately rejected with `HTTP 409 Conflict`.
2. **Stale Job Auto-Recovery**:
   If a container or worker process crashes while executing a sync, the job could remain orphaned in `RUNNING` status. `SyncRunner.cleanup_stale_jobs()` automatically detects jobs in `RUNNING` status whose `updated_at` heartbeat has not progressed for **>15 minutes**, safely transitioning them to `FAILED` with message `Job timed out or worker terminated unexpectedly` and releasing the concurrency lock.

---

## 7. Operational Runbook: Sync Troubleshooting

### A. Diagnosing a Stuck Sync Job
If the frontend navigation spinner remains in a continuous "Syncing" state:
1. Inspect the active sync status:
   ```bash
   curl -s -H "Authorization: Bearer <TOKEN>" \
     "http://localhost:8000/api/v1/sync/status?source=qualys" | jq .
   ```
2. If `status` is `"running"`, note the `active_job.id` and `active_job.started_at`.
3. Check recent backend application logs:
   ```bash
   docker logs risk_alert_prod_backend --tail 50
   ```

### B. Manually Cancelling a Stuck Job
If a job is blocked due to an upstream network timeout, trigger an administrative cancellation:
```bash
curl -X POST -H "Authorization: Bearer <ADMIN_TOKEN>" \
  "http://localhost:8000/api/v1/sync/jobs/{job_id}/cancel"
```
The job status is immediately set to `CANCELLED`, freeing the concurrency lock for subsequent runs.

---

## 8. Crucial Architectural Rules

1. **Severity Count Recalculation Dependency**:
   Whenever a detection's remediation status changes (e.g. via `PATCH /api/v1/detections/{id}/remediation`), **always** recalculate the parent `Asset`'s active severity counters (`critical_vulns`, `high_vulns`, `medium_vulns`, `low_vulns`, `info_vulns`, and `total_vulns`) using `RiskEngine.count_asset_severities`. Never update a detection without refreshing the parent asset counters.
2. **API Rate Limiting & Concurrency Control**:
   Qualys Cloud Platform restricts API concurrency to 2 concurrent requests per subscription. The backend enforces database-backed concurrency locking (`acquire_sync_lock` in `SyncRunner`) to reject overlapping sync requests with `HTTP 409 Conflict` and preserves API quotas by prioritizing incremental delta sync.
3. **Safe XML Parsing**:
   Always use `defusedxml.ElementTree` instead of Python's standard `xml.etree.ElementTree` to prevent XML entity expansion (Billion Laughs / XXE) attacks from external Qualys responses.
4. **RBAC Enforcement**:
   - Write endpoints (`POST`, `PATCH`, `PUT`, `DELETE`) require `require_admin`, with the exception of alert resolution (`POST /alerts/{id}/resolve`) and remediation status updates (`PATCH /detections/{id}/remediation`) which permit `require_analyst_or_admin` (and scoped owner permissions on assigned hosts).
   - System settings (`/settings` UI, `GET /api/v1/settings`, `POST /api/v1/settings`) and API documentation (`/docs` UI) are strictly restricted to `require_admin`.
   - Threat intelligence feed endpoints (`GET /misp/summary`, `GET /misp/feed`, `GET /misp/assessments/{id}`) permit `require_analyst_or_admin`, while manual synchronization (`POST /api/v1/sync/misp` and `POST /api/v1/sync/qualys`) strictly requires `require_admin`.
   - General read-only endpoints (`GET`) require `require_viewer`.
5. **Database Standard & Safe Deployment**:
   Standardize on PostgreSQL (`postgresql+asyncpg`) across all deployment environments. Ensure queries use standard async SQLAlchemy ORM practices. When deploying or updating production, **never use `docker compose down -v`** (as `-v` destroys the persistent database volume). Always create a pre-deployment snapshot with `./scripts/backup_db.sh`.
6. **API Documentation Protection**:
   The interactive Swagger UI (`/docs`) and OpenAPI schema (`/openapi.json`) are secured using HTTP Basic Authentication (`verify_docs_credentials`). ReDoc (`/redoc`) is disabled. Default credentials (`DOCS_USERNAME="docs_admin"`, `DOCS_PASSWORD="docs123"`) can be customized via `.env` or updated dynamically by administrators via Admin Settings (`POST /api/v1/settings`).
7. **Strict Live Integrity & No Mock Fallback**:
   In live production mode (`QUALYS_MOCK_MODE=false` and `MISP_MOCK_MODE=false`), external API errors (e.g. network timeouts, TLS handshakes, upstream HTTP 500s) **must never fall back to mock data**. Live failures must raise an exception and fail the background sync job cleanly, preserving existing database records intact without injecting mock CVEs or synthetic assets.
8. **Multi-Worker Coordinator Process Coordination**:
   In multi-worker production configurations (`WORKERS=4`), Uvicorn spins up multiple parallel processes. The application coordinates startup via a POSIX file mutex (`/tmp/risk_alert_worker_coordinator.lock`) using `fcntl.flock`. Exactly one worker is designated as the Primary Coordinator (handling DB migrations, APScheduler cron jobs, and ZeroMQ listeners), while replica workers immediately serve HTTP traffic without spawning duplicate schedulers or racing on startup migrations.
