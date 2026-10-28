import html
import logging
from typing import Optional, Dict, Any, List
import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class TelegramService:
    @staticmethod
    def normalize_chat_id(chat_id: Optional[str]) -> str:
        """
        Normalize Telegram Chat ID.
        - Telegram channels and supergroups require the '-100' prefix.
        - If an administrator supplies a 9-11 digit group ID with a single leading hyphen (e.g. -2142256980)
          without the '100' prefix, automatically prepend '100' after the hyphen (-1002142256980).
        """
        if not chat_id:
            return ""
        cid = str(chat_id).strip()
        if cid.startswith("@"):
            return cid
        import re
        if re.match(r"^-[1-9]\d{8,11}$", cid) and not cid.startswith("-100"):
            return f"-100{cid[1:]}"
        return cid

    @staticmethod
    async def send_message(
        text: str,
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None,
        parse_mode: str = "HTML",
    ) -> Dict[str, Any]:
        """Send message via Telegram Bot API with automatic channel ID normalization and fallback."""
        token = bot_token or settings.TELEGRAM_BOT_TOKEN
        raw_cid = chat_id or settings.TELEGRAM_CHAT_ID

        if not token or not raw_cid:
            return {"success": False, "message": "Telegram Bot Token or Chat ID not configured."}

        # Try normalized chat ID first (auto-resolves missing -100 for channels/supergroups)
        cid = TelegramService.normalize_chat_id(raw_cid)
        url = f"https://api.telegram.org/bot{token}/sendMessage"

        async def _do_post(target_cid: str):
            payload = {
                "chat_id": target_cid,
                "text": text,
                "parse_mode": parse_mode,
                "disable_web_page_preview": True,
            }
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=payload)
                data = resp.json()
                return resp.status_code, data

        try:
            status_code, data = await _do_post(cid)
            if status_code == 200 and data.get("ok"):
                note = " (auto-normalized to -100 channel format)" if cid != str(raw_cid).strip() else ""
                return {"success": True, "message": f"Telegram alert dispatched successfully.{note}"}

            # If normalized failed with chat not found and differed from raw_cid, attempt raw_cid
            if cid != str(raw_cid).strip():
                status_code, data = await _do_post(str(raw_cid).strip())
                if status_code == 200 and data.get("ok"):
                    return {"success": True, "message": "Telegram alert dispatched successfully."}

            err_desc = data.get("description", str(data))
            if "chat not found" in err_desc.lower():
                err_desc += " (Tip: Channels & supergroups require '-100' prefix, e.g. -1002142256980, and the bot must be an Admin. Personal chats require clicking /start first.)"
            return {"success": False, "message": f"Telegram API error: {err_desc}"}
        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")
            return {"success": False, "message": f"Network error sending Telegram message: {str(e)}"}

    @classmethod
    def format_asset_alert(
        cls,
        asset: Any,
        top_detections: List[Any],
        kb_map: Dict[int, Any],
    ) -> str:
        """Format an alert message with HTML formatting for Telegram."""
        ip = html.escape(asset.ip_address or "Unknown IP")
        fqdn = html.escape(asset.fqdn or "No FQDN")
        os_name = html.escape(asset.os_name or "Unknown OS")
        risk_level = (getattr(asset, "risk_level", "Critical") or "Critical").upper()
        risk_score = getattr(asset, "risk_score", 0.0)
        tags = [html.escape(t) for t in (asset.tags or [])]
        tags_str = ", ".join([f"<code>{t}</code>" for t in tags]) if tags else "<i>None</i>"

        server_name = html.escape(getattr(asset, "server_name", None) or (asset.fqdn.split(".")[0] if asset.fqdn else "Unknown-Server"))
        icon = "🚨" if risk_level == "CRITICAL" else "⚠️"

        owner_username = html.escape(getattr(asset, "owner_username", None) or "Unassigned")
        poc_name = getattr(asset, "poc_name", None)
        poc_email = getattr(asset, "poc_email", None)
        owner_info = f"<code>{owner_username}</code>"
        if poc_name:
            poc_str = f"{html.escape(poc_name)}"
            if poc_email:
                poc_str += f" &lt;{html.escape(poc_email)}&gt;"
            owner_info += f" (PoC: {poc_str})"

        crit_v = getattr(asset, "critical_vulns", 0)
        high_v = getattr(asset, "high_vulns", 0)
        total_v = getattr(asset, "total_vulns", 0)

        lines = [
            f"{icon} <b>Risk Alert: {server_name} ({ip})</b>",
            "",
            f"🖥 <b>Server Name:</b> <code>{server_name}</code>",
            f"🌐 <b>IP Address:</b> <code>{ip}</code> ({fqdn})",
            f"👤 <b>Ownership:</b> {owner_info}",
            f"💻 <b>OS:</b> {os_name}",
            f"📊 <b>Vulnerabilities:</b> 🔴 <b>{crit_v}</b> Crit (Sev 5) | 🟠 <b>{high_v}</b> High (Sev 4) | <b>{total_v}</b> Total",
            "",
            "<b>Top Critical / High Detections:</b>",
        ]

        for det in top_detections[:3]:
            qid = getattr(det, "qid", None)
            sev = getattr(det, "severity", 1)
            kb = kb_map.get(qid)
            title = html.escape(getattr(kb, "title", f"Qualys QID {qid}") if kb else f"Qualys QID {qid}")
            cve_list = getattr(kb, "cve_list", []) if kb else []
            cve_str = f" | <i>CVE:</i> {', '.join(cve_list[:2])}" if cve_list else ""

            # Solution snippet
            sol = getattr(kb, "solution", "") if kb else ""
            sol_snippet = html.escape(sol[:120] + "..." if len(sol) > 120 else sol) if sol else "Check dashboard for fix details"

            lines.append(f"• <b>QID {qid}:</b> {title}")
            lines.append(f"  ├ <i>Severity:</i> {sev}{cve_str}")
            lines.append(f"  └ <i>Fix:</i> {sol_snippet}")

        lines.extend([
            "",
            "🔧 <b>Action Required:</b> Review findings and apply vendor patches.",
            "🛡 <i>Risk Alert Dashboard</i>",
        ])

        return "\n".join(lines)

    @classmethod
    def format_misp_assessment_alert(cls, assessment: Any) -> str:
        """Format an FS-ISAC proactive threat intelligence assessment alert for Telegram."""
        cve_id = html.escape(getattr(assessment, "cve_id", "CVE-UNKNOWN"))
        title = html.escape(getattr(assessment, "title", "FS-ISAC Threat Advisory"))
        severity = getattr(assessment, "severity", "High").upper()
        cvss = getattr(assessment, "cvss_score", None)
        cvss_str = f" (CVSS: {cvss})" if cvss else ""
        match_type = getattr(assessment, "match_type", "INVENTORY_PROACTIVE")
        report = getattr(assessment, "assessment_report", {}) or {}
        affected_assets = report.get("affected_assets", [])
        product = html.escape(getattr(assessment, "affected_product", "software"))
        vuln_ver = html.escape(getattr(assessment, "vulnerable_versions", ""))
        rec_action = html.escape(report.get("recommended_actions", "Apply security update."))
        verification_cmd = html.escape(report.get("verification_command", ""))

        if match_type == "QUALYS_CONFIRMED":
            badge = "🛡️ <b>[QUALYS SCANNER CONFIRMED]</b>"
            status_desc = "Qualys scanner has already detected this vulnerability on active hosts."
        elif match_type == "INVENTORY_PROACTIVE":
            badge = "⚡ <b>[PROACTIVE PRE-SCAN MATCH]</b>"
            status_desc = "⚠️ <b>Warning:</b> Qualys has not flagged this yet! Identified proactively via server software inventory."
        else:
            badge = "ℹ️ <b>[CLEAN / NO EXPOSURE]</b>"
            status_desc = "No assets running vulnerable versions."

        sev_icon = "🔴" if severity == "CRITICAL" else ("🟠" if severity == "HIGH" else "🟡")

        source_name = html.escape(str(getattr(assessment, "source", "THREAT INTELLIGENCE") or "THREAT INTELLIGENCE")).upper()

        lines = [
            f"🛡️ <b>[{source_name} THREAT INTELLIGENCE ADVISORY]</b>",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"<b>Advisory:</b> <code>{cve_id}</code>",
            f"<b>Threat:</b> {title}",
            f"<b>Severity:</b> {sev_icon} <b>{severity}{cvss_str}</b>",
            f"<b>Assessment Status:</b> {badge}",
            f"<i>{status_desc}</i>",
            "",
            f"📦 <b>Target Product:</b> <code>{product}</code> (Criteria: <code>{vuln_ver}</code>)",
            f"💻 <b>Affected Infrastructure ({len(affected_assets)} Server{'s' if len(affected_assets) != 1 else ''}):</b>",
        ]

        for a in affected_assets[:4]:
            s_name = html.escape(a.get("server_name") or a.get("ip_address") or "Server")
            ip = html.escape(a.get("ip_address") or "N/A")
            ev = html.escape(a.get("evidence") or "")
            conf = html.escape(a.get("confidence") or "High")
            lines.append(f"• <b>{s_name}</b> (<code>{ip}</code>)")
            lines.append(f"  └ <i>Evidence:</i> {ev}")
            lines.append(f"  └ <i>Confidence:</i> <b>{conf}</b>")

        if len(affected_assets) > 4:
            lines.append(f"<i>...and {len(affected_assets) - 4} more server(s). Check dashboard.</i>")

        if verification_cmd:
            lines.extend([
                "",
                "🔍 <b>Recommended Verification Command:</b>",
                f"<code>{verification_cmd}</code>",
            ])

        lines.extend([
            "",
            f"🔧 <b>Remediation Guidance:</b> {rec_action}",
            "🛡 <i>Qualys & FS-ISAC Proactive Threat Engine</i>",
        ])

        return "\n".join(lines)
