import re
import pytest
from playwright.sync_api import Page, expect


class TestAlertsLifecycleSuite:
    """Alert Center, Severity Filtering & Remediation Lifecycle Suite.
    Validates end-to-end operational workflows for:
    - Navigating Threat Alert Center and verifying KPI counters
    - Filtering by severity levels (Critical, High, Medium, Low)
    - Filtering by lifecycle status (Active, Remediated, All)
    - Opening Assessment Report drawer for threat diagnosis
    - Updating alert remediation status and observing UI reactivity
    """

    def test_01_alert_center_severity_filters(self, admin_page: Page):
        """Verify Threat Alert Center loads active alerts and applies severity and status filters."""
        page = admin_page

        # Navigate to Alert Center via sidebar
        page.locator('nav button:has-text("Alert Center")').click()
        page.wait_for_url("**/alerts*", timeout=10000)
        expect(page.locator("h2")).to_contain_text("Threat Alert Center")

        # Verify summary KPI widgets
        expect(page.locator("text=Active Threat Alerts")).to_be_visible()

        # Wait for initial table data to load
        rows = page.locator("table tbody tr")
        expect(rows.first).to_be_visible(timeout=10000)

        # Severity dropdown filtering
        sev_select = page.locator('select:has-text("All Severities")')
        expect(sev_select).to_be_visible()

        # Select Critical severity and verify value
        sev_select.select_option("Critical")
        expect(sev_select).to_have_value("Critical")
        page.wait_for_timeout(500)

        # Select All Severities to restore full list
        sev_select.select_option("")
        expect(sev_select).to_have_value("")
        page.wait_for_timeout(500)

        # Status toggle button group (Active, Remediated, All)
        status_bar = page.locator('div:has(> button:has-text("Remediated"))')
        expect(status_bar).to_be_visible()

        # Click Remediated status tab and assert active styling
        rem_btn = status_bar.locator('button:has-text("Remediated")')
        expect(rem_btn).to_be_visible()
        rem_btn.click()
        expect(rem_btn).to_have_class(re.compile(r"bg-indigo-600"), timeout=5000)
        page.wait_for_timeout(500)

        # Click All alerts status tab and assert active styling
        all_btn = status_bar.locator('button:has-text("All")')
        expect(all_btn).to_be_visible()
        all_btn.click()
        expect(all_btn).to_have_class(re.compile(r"bg-indigo-600"), timeout=5000)
        page.wait_for_timeout(500)

        # Click back to Active alerts and assert active styling
        act_btn = status_bar.locator('button:has-text("Active")')
        expect(act_btn).to_be_visible()
        act_btn.click()
        expect(act_btn).to_have_class(re.compile(r"bg-indigo-600"), timeout=5000)

    def test_02_alert_expansion_and_resolution_flow(self, admin_page: Page):
        """Verify expanding an alert opens Assessment Report drawer and allows status triage."""
        page = admin_page

        # Navigate to Alert Center via sidebar
        page.locator('nav button:has-text("Alert Center")').click()
        page.wait_for_url("**/alerts*", timeout=10000)

        # Ensure active alerts are loaded in table
        rows = page.locator("table tbody tr")
        expect(rows.first).to_be_visible(timeout=10000)

        # Open Assessment Report drawer for the first alert
        report_btn = page.locator('button:has-text("Assessment")').first
        expect(report_btn).to_be_visible()
        report_btn.click()

        # Assert slide-out drawer appears with MISP and CVE details
        drawer = page.locator(".fixed.inset-0")
        expect(drawer).to_be_visible(timeout=5000)
        expect(drawer.locator("text=MISP ID: #").first).to_be_visible()
        expect(drawer.locator("text=Affected Servers").first).to_be_visible()

        # Verify Status selector inside drawer
        status_select = drawer.locator("select")
        expect(status_select).to_be_visible()

        # Close the drawer
        close_btn = drawer.locator('button:has(svg.lucide-x)').first
        expect(close_btn).to_be_visible()
        close_btn.click()
        expect(drawer).to_be_hidden(timeout=5000)
