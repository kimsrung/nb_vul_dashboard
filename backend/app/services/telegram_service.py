import html
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta
import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class TelegramService:
    @staticmethod
    async def send_message(
        text: str,
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None,
        parse_mode: str = "HTML",
    ) -> Dict[str, Any]:
        """Send message via Telegram Bot API."""
        token = bot_token or settings.TELEGRAM_BOT_TOKEN
        cid = chat_id or settings.TELEGRAM_CHAT_ID

        if not token or not cid:
            return {"success": False, "message": "Telegram Bot Token or Chat ID not configured."}

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": cid,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=payload)
                data = resp.json()
                if resp.status_code == 200 and data.get("ok"):
                    return {"success": True, "message": "Telegram alert dispatched successfully."}
                else:
                    err_desc = data.get("description", resp.text)
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
        risk_level = getattr(asset, "risk_level", "Critical").upper()
        risk_score = getattr(asset, "risk_score", 0.0)
        tags = [html.escape(t) for t in (asset.tags or [])]
        tags_str = ", ".join([f"<code>{t}</code>" for t in tags]) if tags else "<i>None</i>"

        server_name = html.escape(getattr(asset, "server_name", None) or (asset.fqdn.split(".")[0] if asset.fqdn else "Unknown-Server"))
        icon = "🚨" if risk_level == "CRITICAL" else "⚠️"

        lines = [
            f"{icon} <b>QUALYS RISK ALERT: {server_name} ({ip})</b>",
            "",
            f"🖥 <b>Server Name:</b> <code>{server_name}</code>",
            f"🌐 <b>IP Address:</b> <code>{ip}</code> ({fqdn})",
            f"💻 <b>OS:</b> {os_name}",
            f"📊 <b>Risk Score:</b> <b>{risk_score}</b> (Level: {risk_level})",
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
            "🛡 <i>Qualys Risk Alert Dashboard</i>",
        ])

        return "\n".join(lines)
