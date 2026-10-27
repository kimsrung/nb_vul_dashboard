import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.main import app, init_db_and_seed
from app.core.database import AsyncSessionLocal


@pytest_asyncio.fixture(scope="session", autouse=True)
async def initialize_test_database():
    """Ensure database schema and default seed data are clean and ready before tests run."""
    from app.core.database import engine, Base

    # Ensure automated tests run in self-contained mock mode without requiring live cloud APIs
    settings.QUALYS_MOCK_MODE = True
    settings.MISP_MOCK_MODE = True

    # Drop and recreate clean tables for deterministic test session isolation
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
