import pytest
from playwright.sync_api import Page, expect


class TestAuthAndRBACSuite:
    """Multi-Role RBAC & Session Security Test Suite.
    Verifies that system access, navigation visibility, and data scoping
    strictly comply with Role-Based Access Control (Admin, Analyst, Owner, Viewer).
    """

    def test_01_invalid_login_credentials_shows_error(self, page: Page, base_url: str):
        """Verify submitting invalid credentials renders an error alert without authenticating."""
        page.goto(f"{base_url}/login")
        expect(page.locator("h1")).to_contain_text("Risk Alert Dashboard")

        page.fill('input[placeholder="Username"]', "invalid_operator")
        page.fill('input[placeholder="Password"]', "WrongPassword999!")
        page.click('button[type="submit"]')

        error_banner = page.locator(".text-red-400")
        expect(error_banner).to_be_visible(timeout=5000)
        expect(error_banner).to_contain_text("Incorrect username or password")

    def test_02_admin_login_and_logout_flow(self, admin_page: Page, base_url: str):
        """Verify Admin can log in, view full administration options, and cleanly log out."""
        page = admin_page
        expect(page.locator("header")).to_be_visible()
        expect(page.locator("header")).to_contain_text("admin")

        # Admin must see privileged management options in sidebar
        expect(page.locator('nav button:has-text("Executive Overview")')).to_be_visible()
        expect(page.locator('nav button:has-text("Asset Inventory")')).to_be_visible()
        expect(page.locator('nav button:has-text("Alert Center")')).to_be_visible()
        expect(page.locator('nav button:has-text("Audit & History Logs")')).to_be_visible()
        expect(page.locator('nav button:has-text("User Management")')).to_be_visible()
        expect(page.locator('nav button:has-text("MISP Feed")')).to_be_visible()
        expect(page.locator('nav button:has-text("Admin Settings")')).to_be_visible()
        expect(page.locator('nav button:has-text("API Documentation")')).to_be_visible()

        # Click Logout in Navbar
        logout_btn = page.locator('button[title="Log out"]')
        expect(logout_btn).to_be_visible()
        logout_btn.click()

        # Assert returned to Login screen with credentials form
        expect(page.locator('input[placeholder="Username"]')).to_be_visible(timeout=5000)
        expect(page.locator('input[placeholder="Password"]')).to_be_visible()
        expect(page.locator('button[type="submit"]')).to_contain_text("Sign In")

    def test_03_viewer_role_sidebar_restrictions(self, viewer_page: Page, base_url: str):
        """Verify Viewer role has read access but cannot see administrative navigation links and is redirected from /settings."""
        page = viewer_page
        expect(page.locator("header")).to_contain_text("viewer")

        # Permitted sidebar options for Viewer
        expect(page.locator('nav button:has-text("Executive Overview")')).to_be_visible()
        expect(page.locator('nav button:has-text("Asset Inventory")')).to_be_visible()
        expect(page.locator('nav button:has-text("Alert Center")')).to_be_visible()
        expect(page.locator('nav button:has-text("Audit & History Logs")')).to_be_visible()

        # Strictly forbidden administrative links must NOT exist in the DOM for Viewer
        expect(page.locator('nav button:has-text("Admin Settings")')).to_have_count(0)
        expect(page.locator('nav button:has-text("User Management")')).to_have_count(0)
        expect(page.locator('nav button:has-text("MISP Feed")')).to_have_count(0)
        expect(page.locator('nav button:has-text("API Documentation")')).to_have_count(0)

        # Direct navigation to /settings must redirect to /dashboard
        page.goto(f"{base_url}/settings")
        page.wait_for_url("**/dashboard*", timeout=10000)
        expect(page.locator("h2")).to_contain_text("Internal Risk Alert Dashboard")

    def test_04_owner_role_scoping_in_browser(self, owner_page: Page):
        """Verify Asset Owner is scoped strictly to their assigned servers in Asset Inventory."""
        page = owner_page
        expect(page.locator("header")).to_contain_text("owner_appcore")

        # Navigate to Asset Inventory
        page.locator('nav button:has-text("Asset Inventory")').click()
        page.wait_for_url("**/assets*", timeout=10000)
        expect(page.locator("text=Asset Inventory").first).to_be_visible()

        # Asset Owner banner scoping indication
        expect(page.locator("text=Owner View (Scoped to your hosts)")).to_be_visible()

        # Assert assigned host is rendered and shows owner_appcore PoC
        expect(page.get_by_text("owner_appcore").first).to_be_visible(timeout=10000)
        expect(page.get_by_text("Bakong SIT").first).to_be_visible()

        # Asset Owner cannot see Admin Settings, User Management, MISP Feed, or API Documentation
        expect(page.locator('nav button:has-text("Admin Settings")')).to_have_count(0)
        expect(page.locator('nav button:has-text("User Management")')).to_have_count(0)
        expect(page.locator('nav button:has-text("MISP Feed")')).to_have_count(0)
        expect(page.locator('nav button:has-text("API Documentation")')).to_have_count(0)

    def test_05_analyst_role_operational_permissions(self, analyst_page: Page):
        """Verify Analyst role can triage alerts and assets, access MISP Feed, but cannot access Admin Settings, User Management or API docs."""
        page = analyst_page
        expect(page.locator("header")).to_contain_text("analyst")

        # Permitted operational links for Analyst
        expect(page.locator('nav button:has-text("Executive Overview")')).to_be_visible()
        expect(page.locator('nav button:has-text("Asset Inventory")')).to_be_visible()
        expect(page.locator('nav button:has-text("Alert Center")')).to_be_visible()
        expect(page.locator('nav button:has-text("Audit & History Logs")')).to_be_visible()
        expect(page.locator('nav button:has-text("MISP Feed")')).to_be_visible()

        # Admin-only links must be hidden
        expect(page.locator('nav button:has-text("Admin Settings")')).to_have_count(0)
        expect(page.locator('nav button:has-text("User Management")')).to_have_count(0)
        expect(page.locator('nav button:has-text("API Documentation")')).to_have_count(0)
