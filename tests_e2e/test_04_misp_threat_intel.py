import pytest
from playwright.sync_api import Page, expect


class TestMispThreatIntelSuite:
    """MISP Threat Intelligence Feed & Proactive Correlation Suite.
    Validates end-to-end workflows for:
    - Navigating MISP Threat Intelligence Feed (Admin-only)
    - Verifying proactive inventory match KPI metrics
    - Searching specific CVE advisories (e.g. CVE-2024-6387 OpenSSH regreSSHion)
    - Inspecting match classification tags (Proactive Pre-Scan vs Qualys Confirmed)
    - Opening and dismissing threat advisory dossier drawer
    """

    def test_01_misp_feed_navigation_and_table(self, admin_page: Page):
        """Verify MISP Feed view loads advisories table and executive KPI counters."""
        page = admin_page

        # Navigate to MISP Feed via sidebar
        page.locator('nav button:has-text("MISP Feed")').click()
        page.wait_for_url("**/misp*", timeout=10000)
        expect(page.locator("h1, h2").filter(has_text="MISP Threat Intelligence Feed")).to_be_visible()

        # Verify summary KPI widgets
        expect(page.locator("text=Evaluated CVE Advisories").first).to_be_visible()
        expect(page.locator("text=Proactive Pre-Scan Matches").first).to_be_visible()

        # Verify advisory table rows load
        rows = page.locator("table tbody tr")
        expect(rows.first).to_be_visible(timeout=10000)

    def test_02_misp_cve_search_and_proactive_match_tags(self, admin_page: Page):
        """Verify searching CVE-2024-6387 displays proactive server match badge and opens dossier drawer."""
        page = admin_page

        # Navigate to MISP Feed via sidebar
        page.locator('nav button:has-text("MISP Feed")').click()
        page.wait_for_url("**/misp*", timeout=10000)

        # Search by CVE ID
        search_input = page.locator('input[placeholder*="Search by CVE ID"]')
        expect(search_input).to_be_visible()
        search_input.fill("CVE-2024-6387")
        page.keyboard.press("Enter")
        page.wait_for_timeout(400)

        # Assert filtered row contains the specific CVE
        row = page.locator("table tbody tr").filter(has_text="CVE-2024-6387")
        expect(row.first).to_be_visible(timeout=10000)

        # Assert Proactive Pre-Scan badge is present in the row
        expect(row.locator("text=Proactive Pre-Scan").first).to_be_visible()

        # Assert affected infrastructure count badge
        expect(row.locator("text=servers").first).to_be_visible()

        # Click Details button on the matching row
        detail_btn = row.locator('button:has-text("Details")').first
        expect(detail_btn).to_be_visible()
        detail_btn.click()

        # Assert slide-over threat dossier drawer is rendered
        drawer = page.locator(".fixed.inset-0")
        expect(drawer).to_be_visible()
        expect(drawer.locator("text=CVE-2024-6387").first).to_be_visible()
        expect(drawer.locator("text=OpenSSH Server regreSSHion").first).to_be_visible()

        # Close the drawer
        close_btn = drawer.locator('button:has(svg.lucide-x)').first
        expect(close_btn).to_be_visible()
        close_btn.click()
        expect(drawer).to_have_count(0)
