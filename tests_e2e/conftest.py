import os
import pytest
import httpx
from playwright.sync_api import Browser, BrowserContext, Page, Playwright, expect


@pytest.fixture(scope="session")
def base_url() -> str:
    """Target application URL (defaults to running local stack on port 3000)."""
    return os.getenv("E2E_BASE_URL", "http://localhost:3000").rstrip("/")


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Set standard desktop viewport size for consistent UI layout."""
    return {
        **browser_context_args,
        "viewport": {
            "width": 1440,
            "height": 900,
        },
        "ignore_https_errors": True,
    }


def _purge_e2e_test_users(base_url: str):
    """Purge temporary e2e test users from the database."""
    try:
        res = httpx.post(
            f"{base_url}/api/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
            timeout=5.0,
        )
        if res.status_code == 200:
            token = res.json().get("access_token")
            headers = {"Authorization": f"Bearer {token}"}
            users_res = httpx.get(f"{base_url}/api/v1/auth/users", headers=headers, timeout=5.0)
            if users_res.status_code == 200:
                for u in users_res.json():
                    if u.get("username", "").startswith("e2e_"):
                        uid = u.get("id")
                        httpx.delete(f"{base_url}/api/v1/auth/users/{uid}", headers=headers, timeout=5.0)
    except Exception:
        pass


@pytest.fixture(autouse=True, scope="module")
def cleanup_e2e_users_module(base_url: str):
    """Auto-clean temporary e2e users before and after test module execution."""
    _purge_e2e_test_users(base_url)
    yield
    _purge_e2e_test_users(base_url)


def _login_with_credentials(page: Page, base_url: str, username: str, password: str) -> Page:
    """Helper to perform UI login and wait for authentication redirect."""
    page.goto(f"{base_url}/login")
    page.fill('input[placeholder="Username"]', username)
    page.fill('input[placeholder="Password"]', password)
    page.click('button[type="submit"]')
    page.wait_for_url(lambda u: "/login" not in u, timeout=10000)
    expect(page.locator("header")).to_be_visible()
    return page


@pytest.fixture
def admin_page(page: Page, base_url: str) -> Page:
    """Authenticated page logged in as System Administrator."""
    return _login_with_credentials(page, base_url, "admin", "admin123")


@pytest.fixture
def viewer_page(page: Page, base_url: str) -> Page:
    """Authenticated page logged in as Read-only Viewer."""
    return _login_with_credentials(page, base_url, "viewer", "viewer123")


@pytest.fixture
def owner_page(page: Page, base_url: str) -> Page:
    """Authenticated page logged in as Asset Owner (owner_appcore)."""
    return _login_with_credentials(page, base_url, "owner_appcore", "owner123")


@pytest.fixture
def analyst_page(page: Page, base_url: str) -> Page:
    """Authenticated page logged in as Security Analyst."""
    return _login_with_credentials(page, base_url, "analyst", "analyst123")
