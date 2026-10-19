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
        # Check Admin account
        admin_res = await session.execute(select(User).where(User.username == settings.ADMIN_USERNAME))
        if not admin_res.scalar_one_or_none():
            admin_user = User(
                username=settings.ADMIN_USERNAME,
                email=settings.ADMIN_EMAIL,
                hashed_password=hash_password(settings.ADMIN_PASSWORD),
                role="admin",
                is_active=True,
            )
            session.add(admin_user)
            logger.info(f"Seeded default Admin user: {settings.ADMIN_USERNAME}")

        # Check Viewer account
        viewer_res = await session.execute(select(User).where(User.username == settings.VIEWER_USERNAME))
        if not viewer_res.scalar_one_or_none():
            viewer_user = User(
                username=settings.VIEWER_USERNAME,
                email=settings.VIEWER_EMAIL,
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing Qualys Risk Alert Dashboard Backend...")
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
