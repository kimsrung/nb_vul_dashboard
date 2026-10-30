import os
import logging
import secrets
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from sqlalchemy import select, func

from app.core.config import settings
from app.core.database import engine, Base, AsyncSessionLocal
from app.core.security import hash_password
from app.models.user import User
from app.models.asset import Asset
from app.models.setting import SystemSetting
from app.models.software import AssetSoftware
from app.models.misp_feed import MispCveAssessment
from app.services.misp_client import MispClient
from app.services.proactive_assessment_engine import ProactiveAssessmentEngine
from app.services.scheduler import start_scheduler, stop_scheduler
from app.services.sync_service import SyncService

from app.api.routes import auth, dashboard, assets, detections, knowledge_base, alerts, settings as settings_routes, misp, software, audit_logs, sync

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("qualys-dashboard-alert")


async def init_db_and_seed():
    """Create database tables and seed default accounts & initial sync."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Safe migration for existing SQLite / Postgres installations
        try:
            from sqlalchemy import text
            from app.core.database import is_sqlite
            if is_sqlite:
                await conn.execute(text("ALTER TABLE assets ADD COLUMN is_active BOOLEAN DEFAULT 1"))
            else:
                await conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE"))
        except Exception:
            pass

        # Safe migration for poc_name, poc_email, and severity count columns
        for col_def_sqlite, col_def_pg in [
            ("poc_name VARCHAR(150)", "poc_name VARCHAR(150)"),
            ("poc_email VARCHAR(255)", "poc_email VARCHAR(255)"),
            ("medium_vulns INTEGER DEFAULT 0", "medium_vulns INTEGER DEFAULT 0"),
            ("low_vulns INTEGER DEFAULT 0", "low_vulns INTEGER DEFAULT 0"),
            ("info_vulns INTEGER DEFAULT 0", "info_vulns INTEGER DEFAULT 0"),
        ]:
            try:
                from sqlalchemy import text
                from app.core.database import is_sqlite
                if is_sqlite:
                    await conn.execute(text(f"ALTER TABLE assets ADD COLUMN {col_def_sqlite}"))
                else:
                    await conn.execute(text(f"ALTER TABLE assets ADD COLUMN IF NOT EXISTS {col_def_pg}"))
            except Exception:
                pass

        # Safe migration for misp_cve_assessments (misp_event_id, misp_event_date)
        for col_def_sqlite, col_def_pg in [
            ("misp_event_id VARCHAR(50)", "misp_event_id VARCHAR(50)"),
            ("misp_event_date TIMESTAMP", "misp_event_date TIMESTAMP WITH TIME ZONE"),
        ]:
            try:
                from sqlalchemy import text
                from app.core.database import is_sqlite
                if is_sqlite:
                    await conn.execute(text(f"ALTER TABLE misp_cve_assessments ADD COLUMN {col_def_sqlite}"))
                else:
                    await conn.execute(text(f"ALTER TABLE misp_cve_assessments ADD COLUMN IF NOT EXISTS {col_def_pg}"))
            except Exception:
                pass

    async with AsyncSessionLocal() as session:
        # Restore persisted settings from DB if present
        settings_res = await session.execute(select(SystemSetting))
        for row in settings_res.scalars().all():
            k, v = row.key, row.value
            if k == "qualys_api_url" and v:
                settings.QUALYS_API_URL = v
            elif k == "qualys_username" and v:
                settings.QUALYS_USERNAME = v
            elif k == "qualys_password" and v:
                settings.QUALYS_PASSWORD = v
            elif k == "qualys_mock_mode":
                settings.QUALYS_MOCK_MODE = v.lower() in ("true", "1")
            elif k == "qualys_sync_interval_hours" and v.isdigit():
                settings.QUALYS_SYNC_INTERVAL_HOURS = int(v)
            elif k == "qualys_tag_filter":
                settings.QUALYS_TAG_FILTER = v
            elif k == "misp_url" and v:
                settings.MISP_URL = v
            elif k == "misp_api_key" and v:
                settings.MISP_API_KEY = v
            elif k == "misp_creator_org" and v:
                settings.MISP_CREATOR_ORG = v
            elif k == "misp_tag_filter" and v:
                settings.MISP_TAG_FILTER = v
            elif k == "misp_feed_tag" and v:
                settings.MISP_FEED_TAG = v
            elif k == "misp_enabled":
                settings.MISP_ENABLED = v.lower() in ("true", "1")
            elif k == "misp_verify_ssl":
                settings.MISP_VERIFY_SSL = v.lower() in ("true", "1")
            elif k == "misp_mock_mode":
                settings.MISP_MOCK_MODE = v.lower() in ("true", "1")
            elif k == "misp_sync_interval_hours" and v.isdigit():
                settings.MISP_SYNC_INTERVAL_HOURS = int(v)
            elif k == "misp_zmq_enabled":
                settings.MISP_ZMQ_ENABLED = v.lower() in ("true", "1")
            elif k == "misp_zmq_host" and v:
                settings.MISP_ZMQ_HOST = v
            elif k == "misp_zmq_port" and v.isdigit():
                settings.MISP_ZMQ_PORT = int(v)
            elif k == "misp_zmq_username":
                settings.MISP_ZMQ_USERNAME = v
            elif k == "misp_zmq_password":
                settings.MISP_ZMQ_PASSWORD = v
            elif k == "telegram_enabled":
                settings.TELEGRAM_ENABLED = v.lower() in ("true", "1")
            elif k == "telegram_bot_token" and v:
                settings.TELEGRAM_BOT_TOKEN = v
            elif k == "telegram_chat_id" and v:
                settings.TELEGRAM_CHAT_ID = v
            elif k == "telegram_cooldown_hours" and v.isdigit():
                settings.TELEGRAM_COOLDOWN_HOURS = int(v)
            elif k == "docs_username" and v:
                settings.DOCS_USERNAME = v
            elif k == "docs_password" and v:
                settings.DOCS_PASSWORD = v

        # Check Admin account
        admin_res = await session.execute(select(User).where(User.username == settings.ADMIN_USERNAME))
        if not admin_res.scalar_one_or_none():
            admin_user = User(
                username=settings.ADMIN_USERNAME,
                email=settings.ADMIN_EMAIL,
                full_name="System Administrator",
                hashed_password=hash_password(settings.ADMIN_PASSWORD),
                role="admin",
                is_active=True,
            )
            session.add(admin_user)
            logger.info(f"Seeded default Admin user: {settings.ADMIN_USERNAME}")

        # Check Security Analyst account
        analyst_res = await session.execute(select(User).where(User.username == "analyst"))
        if not analyst_res.scalar_one_or_none():
            analyst_user = User(
                username="analyst",
                email="analyst@internal.security",
                full_name="Security Operations Analyst",
                hashed_password=hash_password("analyst123"),
                role="analyst",
                is_active=True,
            )
            session.add(analyst_user)
            logger.info("Seeded default Security Analyst user: analyst")

        # Check Asset Owner account
        owner_res = await session.execute(select(User).where(User.username == "owner_appcore"))
        owner_user = owner_res.scalar_one_or_none()
        if not owner_user:
            owner_user = User(
                username="owner_appcore",
                email="appcore_owner@internal.corp",
                full_name="Core Banking App Owner",
                hashed_password=hash_password("owner123"),
                role="owner",
                is_active=True,
            )
            session.add(owner_user)
            logger.info("Seeded default Asset Owner user: owner_appcore")

        # Check Viewer account
        viewer_res = await session.execute(select(User).where(User.username == settings.VIEWER_USERNAME))
        if not viewer_res.scalar_one_or_none():
            viewer_user = User(
                username=settings.VIEWER_USERNAME,
                email=settings.VIEWER_EMAIL,
                full_name="Compliance Auditor",
                hashed_password=hash_password(settings.VIEWER_PASSWORD),
                role="viewer",
                is_active=True,
            )
            session.add(viewer_user)
            logger.info(f"Seeded default Viewer user: {settings.VIEWER_USERNAME}")

        await session.commit()

        # Check if assets exist; if empty, run initial sync in mock mode only
        asset_res = await session.execute(select(Asset))
        if not asset_res.scalars().first():
            if settings.QUALYS_MOCK_MODE:
                logger.info("Database empty on startup in mock mode. Triggering initial Qualys mock sync...")
                try:
                    await SyncService.run_sync(session, manual_trigger=False)
                except Exception as e:
                    logger.error(f"Initial mock sync failed: {e}")
            else:
                logger.info("Database empty on startup in live mode. Awaiting scheduled sync or manual trigger.")

        # Ensure existing assets have clean server_name and mock PoCs (mock mode only)
        assets_all = (await session.execute(select(Asset))).scalars().all()
        for a in assets_all:
            if not a.server_name:
                a.server_name = a.fqdn.split(".")[0] if a.fqdn else a.netbios_name or a.ip_address
            if settings.QUALYS_MOCK_MODE:
                if owner_user and not a.owner_id and ("appcore" in (a.server_name or "").lower() or a.ip_address in ("10.20.6.190", "10.0.1.5")):
                    a.owner_id = owner_user.id
                    a.owner_username = owner_user.username
                # Seed sample PoCs if not yet assigned (mock mode only)
                if not a.poc_name:
                    s_name = (a.server_name or "").lower()
                    if "appcore" in s_name or a.ip_address in ("10.20.6.190", "10.0.1.5"):
                        a.poc_name = "Chan Vanna"
                        a.poc_email = "chan.vanna@nbc.gov.kh"
                    elif "db" in s_name or "sql" in s_name:
                        a.poc_name = "Sok Dara"
                        a.poc_email = "sok.dara@nbc.gov.kh"
                    elif "sit" in s_name or "web" in s_name:
                        a.poc_name = "Keo Pich"
                        a.poc_email = "keo.pich@nbc.gov.kh"
                    elif a.owner_id:
                        a.poc_name = "Samnang Tep"
                        a.poc_email = "samnang.tep@nbc.gov.kh"
        # Seed baseline Asset Software inventory if empty (Mock mode only)
        if settings.QUALYS_MOCK_MODE:
            sw_res = await session.execute(select(func.count(AssetSoftware.id)))
            sw_count = sw_res.scalar() or 0
            if sw_count == 0 and assets_all:
                logger.info("Seeding initial server software package inventory for mock mode...")
                sw_profiles = [
                    # Product, vendor, version, package, path, port, target IP / host criteria
                    ("openssh", "OpenBSD", "8.9p1", "openssh-server", "/usr/sbin/sshd", 22, lambda a: True),
                    ("openssl", "OpenSSL", "3.0.2", "libssl3", "/usr/lib/x86_64-linux-gnu/libssl.so.3", None, lambda a: a.os_family == "Linux"),
                    ("nginx", "F5", "1.24.0", "nginx-core", "/usr/sbin/nginx", 443, lambda a: "sit" in (a.server_name or "").lower() or a.ip_address in ("10.20.6.190", "172.16.50.8", "10.20.6.20")),
                    ("xz-utils", "Tukaani", "5.6.0", "liblzma5", "/usr/lib/x86_64-linux-gnu/liblzma.so.5", None, lambda a: a.ip_address == "10.20.6.128"),
                    ("runc", "OpenContainers", "1.1.7", "runc", "/usr/bin/runc", None, lambda a: "webhook" in (a.server_name or "").lower() or a.ip_address == "10.20.6.128"),
                    ("php", "PHP Group", "8.1.12", "php-cgi", "/usr/bin/php-cgi", 80, lambda a: a.ip_address == "10.20.6.20"),
                    ("log4j", "Apache", "2.14.1", "log4j-core", "/opt/analytics/lib/log4j-core.jar", 8080, lambda a: a.ip_address in ("10.20.6.190", "10.0.1.5")),
                    ("postgresql", "PostgreSQL", "14.5", "postgresql-14", "/usr/lib/postgresql/14/bin/postgres", 5432, lambda a: "db" in (a.server_name or "").lower()),
                ]
                for a in assets_all:
                    for prod, vend, ver, pkg, path, port, predicate in sw_profiles:
                        if predicate(a):
                            session.add(AssetSoftware(
                                asset_id=a.id,
                                product_name=prod,
                                vendor=vend,
                                version=ver,
                                package_name=pkg,
                                install_path=path,
                                port=port,
                            ))
                await session.commit()
                logger.info("Server software inventory populated.")

        # Seed initial MISP FS-ISAC assessments if empty (Mock mode only)
        if settings.MISP_MOCK_MODE:
            misp_res = await session.execute(select(func.count(MispCveAssessment.id)))
            if (misp_res.scalar() or 0) == 0:
                logger.info("Evaluating MISP FS-ISAC advisories against inventory (mock mode)...")
                try:
                    misp_client = MispClient(mock_mode=True)
                    advisories = await misp_client.fetch_fs_isac_events()
                    for adv in advisories:
                        await ProactiveAssessmentEngine.assess_cve(session, adv)
                    logger.info(f"Assessed {len(advisories)} mock FS-ISAC advisories.")
                except Exception as e:
                    logger.error(f"Initial mock MISP assessment failed: {e}")

        await session.commit()


_coordinator_lock_file = None
_is_coordinator_worker = False


def acquire_coordinator_lock() -> bool:
    """Acquire process-level lock to designate a single coordinator worker for schedulers and migrations."""
    global _coordinator_lock_file, _is_coordinator_worker
    try:
        import fcntl
        lock_path = "/tmp/risk_alert_worker_coordinator.lock"
        _coordinator_lock_file = open(lock_path, "a+")
        fcntl.flock(_coordinator_lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        _is_coordinator_worker = True
        return True
    except (BlockingIOError, OSError):
        _is_coordinator_worker = False
        return False


def release_coordinator_lock():
    """Release coordinator lock file."""
    global _coordinator_lock_file, _is_coordinator_worker
    if _coordinator_lock_file and _is_coordinator_worker:
        try:
            import fcntl
            fcntl.flock(_coordinator_lock_file.fileno(), fcntl.LOCK_UN)
            _coordinator_lock_file.close()
        except Exception:
            pass
        _is_coordinator_worker = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing Risk Alert Dashboard Backend...")
    is_coordinator = acquire_coordinator_lock()

    if is_coordinator:
        logger.info(f"Worker PID {os.getpid()} designated as Primary Coordinator. Initializing database schema, scheduler, and background services...")
        await init_db_and_seed()
        start_scheduler()
        if settings.MISP_ZMQ_ENABLED and settings.MISP_ZMQ_HOST:
            from app.services.misp_zmq_subscriber import start_misp_zmq_task
            start_misp_zmq_task(
                settings.MISP_ZMQ_HOST,
                settings.MISP_ZMQ_PORT,
                username=settings.MISP_ZMQ_USERNAME,
                password=settings.MISP_ZMQ_PASSWORD,
            )
    else:
        logger.info(f"Worker PID {os.getpid()} is an HTTP-serving replica (coordinator services active on primary worker).")
        # Ensure schema migrations completed by coordinator before replica handles requests
        import asyncio
        for _ in range(30):
            try:
                async with engine.connect() as conn:
                    from sqlalchemy import text
                    await conn.execute(text("SELECT 1 FROM system_settings LIMIT 1"))
                    break
            except Exception:
                await asyncio.sleep(0.5)

    yield

    # Shutdown
    logger.info("Shutting down backend...")
    if _is_coordinator_worker:
        if settings.MISP_ZMQ_ENABLED and settings.MISP_ZMQ_HOST:
            from app.services.misp_zmq_subscriber import stop_misp_zmq_task
            stop_misp_zmq_task()
        stop_scheduler()
        release_coordinator_lock()
    await engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="Custom internal dashboard flagging risky assets in Qualys, proactive MISP FS-ISAC assessment, and KB remediation.",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

docs_security = HTTPBasic()


def verify_docs_credentials(credentials: HTTPBasicCredentials = Depends(docs_security)):
    correct_user = secrets.compare_digest(credentials.username, settings.DOCS_USERNAME)
    correct_pass = secrets.compare_digest(credentials.password, settings.DOCS_PASSWORD)
    if not (correct_user and correct_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect API documentation credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


@app.get("/docs", include_in_schema=False)
async def get_swagger_documentation(username: str = Depends(verify_docs_credentials)):
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title=f"{settings.PROJECT_NAME} - API Reference",
    )


@app.get("/openapi.json", include_in_schema=False)
async def get_open_api_endpoint(username: str = Depends(verify_docs_credentials)):
    if app.openapi_schema:
        return app.openapi_schema
    app.openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    return app.openapi_schema

# CORS setup - Parse allowed origins and enforce secure credential handling
_raw_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
if "*" in _raw_origins:
    cors_origins = ["*"]
    cors_credentials = False
else:
    cors_origins = _raw_origins
    cors_credentials = True

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=cors_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(dashboard.router, prefix=settings.API_V1_STR)
app.include_router(assets.router, prefix=settings.API_V1_STR)
app.include_router(detections.router, prefix=settings.API_V1_STR)
app.include_router(knowledge_base.router, prefix=settings.API_V1_STR)
app.include_router(alerts.router, prefix=settings.API_V1_STR)
app.include_router(settings_routes.router, prefix=settings.API_V1_STR)
app.include_router(misp.router, prefix=settings.API_V1_STR)
app.include_router(software.router, prefix=settings.API_V1_STR)
app.include_router(audit_logs.router, prefix=settings.API_V1_STR)
app.include_router(sync.router, prefix=settings.API_V1_STR)


@app.get("/health")
async def health_check():
    return {"status": "ok", "app": settings.PROJECT_NAME}
