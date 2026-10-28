import pytest
from playwright.sync_api import Page, expect


class TestAssetsAndRemediationSuite:
    """Asset Inventory, Host Details & KnowledgeBase Remediation Guidance Suite.
    Validates end-to-end user workflows for:
    - Executive Dashboard KPIs & Day/Night theme toggling
    - Asset search, filtering, and Qualys synchronization popover
    - Detailed host inspection including installed software inventory
    - KnowledgeBase remediation drawer with threat intelligence and fix guidance
    """

    def test_01_dashboard_kpis_and_theme_toggle(self, admin_page: Page):
        """Verify Executive Overview renders core KPI metrics and supports dynamic day/night theme toggle."""
        page = admin_page
        expect(page.locator("h2")).to_contain_text("Internal Risk Alert Dashboard")

        # Verify key executive KPI cards
        expect(page.locator("text=Assets Monitored").first).to_be_visible()
        expect(page.locator("text=Total Vulnerabilities").first).to_be_visible()
        expect(page.locator("text=MISP Threat Intelligence").first).to_be_visible()
        expect(page.locator("text=Qualys Severity Distribution").first).to_be_visible()

        # Theme toggle interaction
        theme_btn = page.locator('button[aria-label="Toggle theme mode"]')
        expect(theme_btn).to_be_visible()

        html_elem = page.locator("html")
        initial_theme = html_elem.get_attribute("class") or ""

        # Toggle theme mode
        theme_btn.click()
        toggled_theme = html_elem.get_attribute("class") or ""
        assert toggled_theme != initial_theme, f"Theme did not toggle: was {initial_theme}, now {toggled_theme}"

        # Toggle back to original state
        theme_btn.click()
        restored_theme = html_elem.get_attribute("class") or ""
        assert restored_theme == initial_theme, f"Theme did not restore: {restored_theme} != {initial_theme}"

    def test_02_asset_inventory_search_and_sync_popover(self, admin_page: Page):
        """Verify Asset Inventory search filtering and Qualys sync mode popover."""
        page = admin_page

        # Navigate to Asset Inventory
        page.locator('nav button:has-text("Asset Inventory")').click()
        page.wait_for_url("**/assets*", timeout=10000)
        expect(page.locator("h2")).to_contain_text("Asset Inventory & Risk Scoring")

        # Search for known host
        search_input = page.locator('input[placeholder*="Search by Server Name"]')
        expect(search_input).to_be_visible()
        search_input.fill("Bakong")
        page.keyboard.press("Enter")

        # Verify filtered asset card (using .first to avoid strict mode violation if multiple exist)
        expect(page.locator("h3:has-text('Bakong SIT')").first).to_be_visible(timeout=5000)

        # Clear search filter
        search_input.fill("")
        page.keyboard.press("Enter")

        # Open Qualys Sync Popover
        sync_menu_btn = page.locator('button[title="Choose Qualys Sync Mode"]')
        expect(sync_menu_btn).to_be_visible()
        sync_menu_btn.click()

        # Assert popover displays both Smart Delta and Full Reconciliation options
        expect(page.locator("text=Smart Delta Sync")).to_be_visible()
        expect(page.locator("text=Full Reconciliation Sync")).to_be_visible()

        # Close popover by clicking outside
        page.locator(".fixed.inset-0").click()
        expect(page.locator("text=Smart Delta Sync")).to_have_count(0)

    def test_03_asset_detail_navigation_and_software_tab(self, admin_page: Page):
        """Verify navigation into Asset Detail view and inspect installed software inventory."""
        page = admin_page

        # Navigate to Asset Inventory
        page.locator('nav button:has-text("Asset Inventory")').click()
        page.wait_for_url("**/assets*", timeout=10000)

        # Click Detail button on first asset card
        detail_btn = page.locator('button:has-text("Detail")').first
        expect(detail_btn).to_be_visible(timeout=10000)
        detail_btn.click()

        # Assert Asset Detail view loaded
        page.wait_for_url("**/assets/*", timeout=10000)
        expect(page.locator("text=Back to Assets")).to_be_visible()
        expect(page.locator("text=Sev 5 (Crit)").first).to_be_visible()
        expect(page.locator("text=Detected Vulnerabilities & KnowledgeBase Remediation Guidance")).to_be_visible()

        # Verify Installed Software Inventory section
        software_heading = page.locator("text=Installed Software & Packages Inventory")
        expect(software_heading).to_be_visible()

        # Check that installed software table has package entries
        software_table = page.locator("table").last
        expect(software_table).to_be_visible()

    def test_04_kb_remediation_drawer(self, admin_page: Page):
        """Verify KnowledgeBase Remediation slide-over drawer with diagnosis, CVSS, and proof."""
        page = admin_page

        # Navigate to Asset Inventory and open first asset detail
        page.locator('nav button:has-text("Asset Inventory")').click()
        page.wait_for_url("**/assets*", timeout=10000)
        page.locator('button:has-text("Detail")').first.click()
        page.wait_for_url("**/assets/*", timeout=10000)

        # Click Fix Guidance button on first detection row
        guidance_btn = page.locator('button:has-text("View Fix Guidance")').first
        expect(guidance_btn).to_be_visible(timeout=10000)
        guidance_btn.click()

        # Assert slide-out drawer appears
        drawer = page.locator(".fixed.inset-0")
        expect(drawer).to_be_visible()
        expect(page.locator("text=Remediation Action Status")).to_be_visible()
        expect(page.locator("text=Remediation Notes & Audit Log")).to_be_visible()

        # Close the drawer
        close_btn = page.locator('.fixed.inset-0 button:has(svg.lucide-x)').first
        expect(close_btn).to_be_visible()
        close_btn.click()

        # Navigate back to Assets
        back_btn = page.locator('button:has-text("Back to Assets")')
        expect(back_btn).to_be_visible()
        back_btn.click()
        page.wait_for_url("**/assets", timeout=10000)
