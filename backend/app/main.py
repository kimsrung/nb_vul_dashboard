import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.core.config import settings
from app.core.database import engine, Base, AsyncSessionLocal
from app.core.security import hash_password
from app.models.user import User
from app.models.asset import Asset
from app.models.setting import SystemSetting
from app.services.scheduler import start_scheduler, stop_scheduler
from app.services.sync_service import SyncService

from app.api.routes import auth, dashboard, assets, detections, knowledge_base, alerts, settings as settings_routes

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("qualys-dashboard-alert")


async def init_db_and_seed():
    """Create database tables and seed default accounts & initial sync."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

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
            elif k == "telegram_enabled":
                settings.TELEGRAM_ENABLED = v.lower() in ("true", "1")
            elif k == "telegram_bot_token" and v:
                settings.TELEGRAM_BOT_TOKEN = v
            elif k == "telegram_chat_id" and v:
                settings.TELEGRAM_CHAT_ID = v
            elif k == "telegram_cooldown_hours" and v.isdigit():
                settings.TELEGRAM_COOLDOWN_HOURS = int(v)
            elif k == "risk_threshold_critical" and v.isdigit():
                settings.RISK_THRESHOLD_CRITICAL = int(v)
            elif k == "risk_threshold_high" and v.isdigit():
                settings.RISK_THRESHOLD_HIGH = int(v)
            elif k == "sla_critical_days" and v.isdigit():
                settings.SLA_CRITICAL_DAYS = int(v)
            elif k == "sla_high_days" and v.isdigit():
                settings.SLA_HIGH_DAYS = int(v)

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

        # Check if assets exist; if empty, run initial sync
        asset_res = await session.execute(select(Asset))
        if not asset_res.scalars().first():
            logger.info("Database empty on startup. Triggering initial Qualys data sync...")
            try:
                await SyncService.run_sync(session, manual_trigger=False)
            except Exception as e:
                logger.error(f"Initial sync failed: {e}")

        # Ensure existing assets have clean server_name and demo owner assigned
        assets_all = (await session.execute(select(Asset))).scalars().all()
        for a in assets_all:
            if not a.server_name:
                a.server_name = a.fqdn.split(".")[0] if a.fqdn else a.netbios_name or a.ip_address
            if owner_user and not a.owner_id and ("appcore" in (a.server_name or "").lower() or a.ip_address in ("10.20.6.190", "10.0.1.5")):
                a.owner_id = owner_user.id
                a.owner_username = owner_user.username
        await session.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing Risk Alert Dashboard Backend...")
    await init_db_and_seed()
    start_scheduler()
    yield
    # Shutdown
    logger.info("Shutting down backend...")
    stop_scheduler()
    await engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="Custom internal dashboard flagging risky assets in Qualys and mapping KnowledgeBase remediation guidance with Telegram alerts and RBAC.",
    lifespan=lifespan,
)

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
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


@app.get("/health")
async def health_check():
    return {"status": "ok", "app": settings.PROJECT_NAME}
