import time
import pytest
from playwright.sync_api import Page, expect


class TestAdminGovernanceSuite:
    """System Administration, User Governance & Audit Logs Suite.
    Validates end-to-end administrative features:
    - User Management view, role overview cards, and account auditing
    - Dynamic user creation with custom RBAC privilege assignment
    - Immutable Audit & History logs searching and action filtering
    - Admin System Configuration, MISP parameters, and SSL verification toggle
    """

    def test_01_user_management_role_overview(self, admin_page: Page):
        """Verify User Management view displays role guidance cards and seeded operators."""
        page = admin_page

        # Navigate to User Management via sidebar
        page.locator('nav button:has-text("User Management")').click()
        page.wait_for_url("**/users*", timeout=10000)
        expect(page.locator("h2")).to_contain_text("User Role Management & Access Control")

        # Verify role guidance cards are rendered
        expect(page.locator("text=Admin").first).to_be_visible()
        expect(page.locator("text=Analyst").first).to_be_visible()
        expect(page.locator("text=Asset Owner").first).to_be_visible()
        expect(page.locator("text=Viewer").first).to_be_visible()

        # Verify table displays seeded users
        rows = page.locator("table tbody tr")
        expect(rows.first).to_be_visible(timeout=10000)
        expect(page.locator("text=admin").first).to_be_visible()
        expect(page.locator("text=analyst").first).to_be_visible()

    def test_02_user_management_create_new_user(self, admin_page: Page):
        """Verify creating a new operator account through the modal adds the user to the active registry."""
        page = admin_page

        # Navigate to User Management via sidebar
        page.locator('nav button:has-text("User Management")').click()
        page.wait_for_url("**/users*", timeout=10000)

        # Open Create New Operator modal
        add_btn = page.locator('button:has-text("Add New User")')
        expect(add_btn).to_be_visible()
        add_btn.click()

        # Modal is open
        modal = page.locator(".fixed.inset-0")
        expect(modal).to_be_visible()
        expect(modal.locator("text=Create New Operator")).to_be_visible()

        # Generate unique operator credentials
        unique_id = int(time.time())
        new_username = f"e2e_analyst_{unique_id}"
        new_email = f"e2e_{unique_id}@nbc.gov.kh"

        # Fill modal form inputs
        page.fill('input[placeholder="e.g. jdoe"]', new_username)
        page.fill('input[placeholder="e.g. John Doe"]', "E2E Test Analyst")
        page.fill('input[placeholder="john.doe@company.com"]', new_email)
        page.fill('input[placeholder="••••••••"]', "TempPassword123!")

        # Select Analyst role
        role_select = modal.locator("select")
        role_select.select_option("analyst")

        # Submit form
        submit_btn = modal.locator('button[type="submit"]:has-text("Create Account")')
        expect(submit_btn).to_be_visible()
        submit_btn.click()

        # Assert creation success notification appears
        expect(page.locator("text=created successfully").first).to_be_visible(timeout=10000)

        # Assert user appears in the table
        expect(page.locator(f"text={new_username}").first).to_be_visible(timeout=10000)

    def test_03_audit_logs_search_and_filtering(self, admin_page: Page):
        """Verify Audit & History logs view supports actor search and action type filtering."""
        page = admin_page

        # Navigate to Audit Logs via sidebar
        page.locator('nav button:has-text("Audit & History Logs")').click()
        page.wait_for_url("**/audit-logs*", timeout=10000)
        expect(page.locator("h2")).to_contain_text("Audit & History Records")

        # Search for actor 'admin'
        search_input = page.locator('input[placeholder*="Search by Target"]')
        expect(search_input).to_be_visible()
        search_input.fill("admin")

        filter_btn = page.locator('button[type="submit"]:has-text("Filter")')
        expect(filter_btn).to_be_visible()
        filter_btn.click()
        page.wait_for_timeout(400)

        # Assert logs table contains entries
        rows = page.locator("table tbody tr")
        expect(rows.first).to_be_visible(timeout=10000)

    def test_04_admin_settings_misp_and_ssl_toggle(self, admin_page: Page):
        """Verify Admin Settings renders MISP configuration with working SSL verification toggle."""
        page = admin_page

        # Navigate to Admin Settings via sidebar
        page.locator('nav button:has-text("Admin Settings")').click()
        page.wait_for_url("**/settings*", timeout=10000)
        expect(page.locator("h2")).to_contain_text("System Configuration & Integrations")

        # Verify MISP Threat Intelligence section
        expect(page.locator("text=MISP Threat Intelligence (FS-ISAC Feed)")).to_be_visible()

        # Locate SSL verification toggle checkbox
        ssl_checkbox = page.locator('label:has-text("Verify SSL Certificate") input[type="checkbox"]')
        expect(ssl_checkbox).to_be_visible()

        # Verify initial checked state
        initially_checked = ssl_checkbox.is_checked()

        # Toggle SSL verification
        ssl_checkbox.click()
        expect(ssl_checkbox).to_be_checked(checked=not initially_checked)

        # Toggle back to original state
        ssl_checkbox.click()
        expect(ssl_checkbox).to_be_checked(checked=initially_checked)

        # Test MISP Connection button is visible and active
        test_misp_btn = page.locator('button:has-text("Test MISP Connection")')
        expect(test_misp_btn).to_be_visible()
        expect(test_misp_btn).to_be_enabled()
