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
    async def test_update_settings_audit_logging(self, client: AsyncClient, admin_headers: dict):
        # 1. Update settings with changed fields
        payload = {
            "qualys_sync_interval_hours": 12,
            "misp_api_key": "new_secret_key_12345",
        }
        res = await client.post("/api/v1/settings", headers=admin_headers, json=payload)
        assert res.status_code == 200

        # Verify audit log recorded UPDATE_SETTINGS
        audit_res = await client.get("/api/v1/audit-logs?action=UPDATE_SETTINGS", headers=admin_headers)
        assert audit_res.status_code == 200
        items = audit_res.json()["items"]
        assert len(items) > 0
        latest_log = items[0]
        assert latest_log["action"] == "UPDATE_SETTINGS"
        assert latest_log["target_type"] == "Settings"
        assert latest_log["actor_username"] == "admin"
        assert "changes" in latest_log["details"]

        # Sensitive key was masked
        misp_key_change = latest_log["details"]["changes"].get("misp_api_key")
        assert misp_key_change is not None
        assert "new_secret_key_12345" not in misp_key_change["new"]  # Never stored in plaintext!
        assert "..." in misp_key_change["new"]

        # Non-sensitive key recorded clean diff
        assert latest_log["details"]["changes"]["qualys_sync_interval_hours"]["new"] == 12

        # 2. Resubmit identical settings -> No new audit log generated (no noise)
        before_count = audit_res.json()["total"]
        res_dup = await client.post("/api/v1/settings", headers=admin_headers, json=payload)
        assert res_dup.status_code == 200

        audit_res2 = await client.get("/api/v1/audit-logs?action=UPDATE_SETTINGS", headers=admin_headers)
        assert audit_res2.json()["total"] == before_count

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

    def test_parse_chat_and_topic(self):
        # Direct with separate topic
        assert TelegramService.parse_chat_and_topic("-1002142256980", 42) == ("-1002142256980", 42)
        # Composite slash with normalization
        assert TelegramService.parse_chat_and_topic("-2142256980/42") == ("-1002142256980", 42)
        assert TelegramService.parse_chat_and_topic("-1002142256980/105") == ("-1002142256980", 105)
        # Composite colon
        assert TelegramService.parse_chat_and_topic("-1002142256980:88") == ("-1002142256980", 88)
        # Plain chat without topic
        assert TelegramService.parse_chat_and_topic("-1002142256980") == ("-1002142256980", None)
        # None and empty
        assert TelegramService.parse_chat_and_topic(None) == ("", None)
        assert TelegramService.parse_chat_and_topic("", 12) == ("", 12)

    @pytest.mark.asyncio
    async def test_update_settings_normalizes_telegram_chat_id(self, client: AsyncClient, admin_headers: dict):
        update_payload = {
            "telegram_chat_id": "-2142256980/42",
        }
        res = await client.post("/api/v1/settings", headers=admin_headers, json=update_payload)
        assert res.status_code == 200
        # Check that it auto-normalized chat_id and extracted topic_id
        assert res.json()["telegram_chat_id"] == "-1002142256980"
        assert res.json()["telegram_topic_id"] == 42

    @pytest.mark.asyncio
    async def test_telegram_send_message_read_timeout_resilience(self, monkeypatch):
        from unittest.mock import AsyncMock
        import httpx

        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.ReadTimeout("The read operation timed out")
        mock_client.__aenter__.return_value = mock_client

        monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: mock_client)

        res = await TelegramService.send_message(
            text="Test alert",
            bot_token="123456:ABC-DEF",
            chat_id="-1002142256980",
            topic_id=42,
        )
        assert res["success"] is True
        assert "timed out after 25s" in res["message"]

    @pytest.mark.asyncio
    async def test_telegram_send_message_includes_topic_id(self, monkeypatch):
        sent_payloads = []

        class MockResp:
            status_code = 200
            def json(self):
                return {"ok": True, "result": {"message_id": 999}}

        class MockClient:
            def __init__(self, *args, **kwargs):
                pass
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            async def post(self, url, json=None):
                sent_payloads.append(json)
                return MockResp()

        monkeypatch.setattr("httpx.AsyncClient", MockClient)

        res = await TelegramService.send_message(
            text="Test alert",
            bot_token="123456:ABC-DEF",
            chat_id="-1002142256980/77",
        )
        assert res["success"] is True
        assert len(sent_payloads) == 1
        assert sent_payloads[0]["chat_id"] == "-1002142256980"
        assert sent_payloads[0]["message_thread_id"] == 77

    @pytest.mark.asyncio
    async def test_user_management_audit_logging(self, client: AsyncClient, admin_headers: dict):
        # 1. Create User
        create_payload = {
            "username": "audit_test_user",
            "email": "audit_test_user@internal.security",
            "password": "Password123!",
            "role": "analyst",
            "full_name": "Audit Test Analyst",
        }
        create_res = await client.post("/api/v1/auth/users", headers=admin_headers, json=create_payload)
        assert create_res.status_code == 200
        user_id = create_res.json()["id"]

        # Verify CREATE_USER in audit logs
        log_res = await client.get("/api/v1/audit-logs?action=CREATE_USER", headers=admin_headers)
        assert log_res.status_code == 200
        create_logs = log_res.json()["items"]
        assert len(create_logs) > 0
        assert create_logs[0]["target_id"] == str(user_id)
        assert create_logs[0]["actor_username"] == "admin"

        # 2. Update User Email & Role
        update_payload = {
            "email": "updated_audit_email@internal.security",
            "role": "viewer",
        }
        patch_res = await client.patch(f"/api/v1/auth/users/{user_id}", headers=admin_headers, json=update_payload)
        assert patch_res.status_code == 200

        # Verify UPDATE_USER in audit logs
        log_res2 = await client.get("/api/v1/audit-logs?action=UPDATE_USER", headers=admin_headers)
        assert log_res2.status_code == 200
        update_logs = log_res2.json()["items"]
        assert len(update_logs) > 0
        assert update_logs[0]["target_id"] == str(user_id)
        assert "changes" in update_logs[0]["details"]
        assert update_logs[0]["details"]["changes"]["email"]["new"] == "updated_audit_email@internal.security"
        assert update_logs[0]["details"]["changes"]["role"]["new"] == "viewer"

        # 3. Delete User
        del_res = await client.delete(f"/api/v1/auth/users/{user_id}", headers=admin_headers)
        assert del_res.status_code == 200

        # Verify DELETE_USER in audit logs
        log_res3 = await client.get("/api/v1/audit-logs?action=DELETE_USER", headers=admin_headers)
        assert log_res3.status_code == 200
        del_logs = log_res3.json()["items"]
        assert len(del_logs) > 0
        assert del_logs[0]["target_id"] == str(user_id)
