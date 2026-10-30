import os
import sys

# ==============================================================================
# Dedicated Test Database Isolation & Safety Guard
# Strictly prevents automated tests from modifying, dropping, or polluting
# the primary development or production database (risk_alert_db).
# ==============================================================================
test_db_url = os.environ.get("TEST_DATABASE_URL")
if not test_db_url:
    current_db = os.environ.get("DATABASE_URL", "")
    if "risk_alert_db" in current_db and "test" not in current_db.lower():
        test_db_url = current_db.replace("risk_alert_db", "risk_alert_test_db")
    elif not current_db:
        test_db_url = "postgresql+asyncpg://risk_alert_user:risk_alert_secret_password@localhost:5432/risk_alert_test_db"
    else:
        test_db_url = current_db

os.environ["DATABASE_URL"] = test_db_url

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.main import app, init_db_and_seed
from app.core.database import engine, Base, AsyncSessionLocal


@pytest_asyncio.fixture(scope="session", autouse=True)
async def initialize_test_database():
    """Ensure database schema and default seed data are clean and ready before tests run."""
    # Critical Safety Guard: Never allow pytest to drop tables on a production / non-test DB
    db_url_str = str(engine.url).lower()
    if "risk_alert_db" in db_url_str and "test" not in db_url_str:
        raise RuntimeError(
            f"CRITICAL SAFETY ABORT: pytest detected target database is '{engine.url}', "
            "which lacks 'test' in its database name! Tests are strictly prohibited from dropping "
            "or seeding primary/production databases. Ensure TEST_DATABASE_URL or risk_alert_test_db is used."
        )

    # Ensure automated tests run in self-contained mock mode without requiring live cloud APIs
    settings.QUALYS_MOCK_MODE = True
    settings.MISP_MOCK_MODE = True

    # Drop and recreate clean tables on dedicated test database for deterministic test session isolation
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await init_db_and_seed()
    yield
    # Session teardown: cleanly stop background ZeroMQ task if spawned during tests
    from app.services.misp_zmq_subscriber import stop_misp_zmq_task
    stop_misp_zmq_task()


@pytest_asyncio.fixture
async def client():
    """Async HTTP test client bound to FastAPI application."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def db_session():
    """Direct database session fixture for inspecting or asserting DB state."""
    async with AsyncSessionLocal() as session:
        yield session


async def _get_auth_headers(client: AsyncClient, username: str, password: str) -> dict:
    res = await client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, f"Login failed for {username}: {res.text}"
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def admin_headers(client: AsyncClient) -> dict:
    return await _get_auth_headers(client, "admin", "admin123")


@pytest_asyncio.fixture
async def analyst_headers(client: AsyncClient) -> dict:
    return await _get_auth_headers(client, "analyst", "analyst123")


@pytest_asyncio.fixture
async def owner_headers(client: AsyncClient) -> dict:
    return await _get_auth_headers(client, "owner_appcore", "owner123")


@pytest_asyncio.fixture
async def viewer_headers(client: AsyncClient) -> dict:
    return await _get_auth_headers(client, "viewer", "viewer123")
