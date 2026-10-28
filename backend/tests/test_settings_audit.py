import pytest
from httpx import AsyncClient

from app.models.asset import Asset
from app.models.misp_feed import MispCveAssessment
from app.services.telegram_service import TelegramService


class TestSettingsAuditAndTelegram:
    @pytest.mark.asyncio
    async def test_get_settings_masks_secrets(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/settings", headers=admin_headers)
        assert res.status_code == 200
        settings_data = res.json()
        assert "qualys_api_url" in settings_data
        assert "misp_api_key_masked" in settings_data
        assert "telegram_bot_token_masked" in settings_data
        # Ensure no legacy webhook secret remains
        assert "misp_webhook_secret" not in settings_data
        assert "misp_zmq_enabled" in settings_data
        assert "misp_zmq_host" in settings_data
        assert "misp_zmq_port" in settings_data

    @pytest.mark.asyncio
    async def test_update_settings_persistence(self, client: AsyncClient, admin_headers: dict):
        update_payload = {
            "misp_sync_interval_hours": 3,
            "telegram_cooldown_hours": 8,
        }
        post_res = await client.post("/api/v1/settings", headers=admin_headers, json=update_payload)
        assert post_res.status_code == 200
        updated = post_res.json()
        assert updated["misp_sync_interval_hours"] == 3
        assert updated["telegram_cooldown_hours"] == 8

        # Verify GET returns updated values
        get_res = await client.get("/api/v1/settings", headers=admin_headers)
        assert get_res.status_code == 200
        assert get_res.json()["misp_sync_interval_hours"] == 3
        assert get_res.json()["telegram_cooldown_hours"] == 8

    @pytest.mark.asyncio
    async def test_audit_logs_pagination_and_search(self, client: AsyncClient, admin_headers: dict):
        res = await client.get("/api/v1/audit-logs?page=1&page_size=10", headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert len(data["items"]) > 0

        first_log = data["items"][0]
        assert "id" in first_log
        assert "action" in first_log
        assert "actor_username" in first_log
        assert "target_type" in first_log
        assert "details" in first_log

    def test_telegram_asset_alert_formatting_with_poc(self):
        asset = Asset(
            ip_address="10.20.6.190",
            fqdn="bk-appcore-sit.internal.corp",
            server_name="bk-appcore-sit",
            owner_username="owner_appcore",
            poc_name="Chan Vanna",
            poc_email="chan.vanna@nbc.gov.kh",
            critical_vulns=2,
            high_vulns=3,
            total_vulns=5,
        )
        msg = TelegramService.format_asset_alert(asset, [], {})
        assert "bk-appcore-sit" in msg
        assert "10.20.6.190" in msg
        assert "owner_appcore" in msg
        assert "Chan Vanna" in msg
        assert "chan.vanna@nbc.gov.kh" in msg
        assert "Vulnerabilities:" in msg
        assert "Crit (Sev 5)" in msg

    def test_telegram_misp_advisory_formatting(self):
        assessment = MispCveAssessment(
            cve_id="CVE-2024-6387",
            title="OpenSSH Remote Code Execution (regreSSHion)",
            severity="Critical",
            cvss_score=8.1,
            match_type="INVENTORY_PROACTIVE",
            affected_product="openssh",
            vulnerable_versions="< 9.8p1",
            assessment_report={
                "affected_assets": [
                    {
                        "server_name": "bk-appcore-sit",
                        "ip_address": "10.20.6.190",
                        "evidence": "Installed openssh 8.9p1",
                        "confidence": "High"
                    }
                ],
                "recommended_actions": "Upgrade openssh to 9.8p1 or later.",
                "verification_command": "dpkg -l openssh-server",
            }
        )
        msg = TelegramService.format_misp_assessment_alert(assessment)
        assert "CVE-2024-6387" in msg
        assert "bk-appcore-sit" in msg
        assert "10.20.6.190" in msg
        assert "PROACTIVE PRE-SCAN MATCH" in msg
        assert "dpkg -l openssh-server" in msg

    def test_telegram_chat_id_normalization(self):
        # Channel/supergroup ID missing -100 prefix
        assert TelegramService.normalize_chat_id("-2142256980") == "-1002142256980"
        # Already normalized channel ID
        assert TelegramService.normalize_chat_id("-1002142256980") == "-1002142256980"
        # Public channel username handle
        assert TelegramService.normalize_chat_id("@sec_alerts") == "@sec_alerts"
        # Personal user direct chat ID (positive int)
        assert TelegramService.normalize_chat_id("2142256980") == "2142256980"
        # Empty or None
        assert TelegramService.normalize_chat_id(None) == ""
        assert TelegramService.normalize_chat_id("") == ""

    @pytest.mark.asyncio
    async def test_update_settings_normalizes_telegram_chat_id(self, client: AsyncClient, admin_headers: dict):
        update_payload = {
            "telegram_chat_id": "-2142256980",
        }
        res = await client.post("/api/v1/settings", headers=admin_headers, json=update_payload)
        assert res.status_code == 200
        # Check that it auto-normalized to -100 format in response and DB
        assert res.json()["telegram_chat_id"] == "-1002142256980"
