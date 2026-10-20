import logging
from typing import List, Dict, Any, Optional
import httpx
from app.core.config import settings
from app.services.misp_mock import MOCK_FS_ISAC_EVENTS

logger = logging.getLogger(__name__)


class MispClient:
    """MISP Threat Intelligence Client strictly scoped to FS-ISAC feeds."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        feed_tag: Optional[str] = None,
        mock_mode: Optional[bool] = None,
    ):
        self.base_url = (base_url or settings.MISP_URL).rstrip("/")
        self.api_key = api_key or settings.MISP_API_KEY
        self.feed_tag = feed_tag or settings.MISP_FEED_TAG or "FS-ISAC"
        self.mock_mode = mock_mode if mock_mode is not None else settings.MISP_MOCK_MODE

    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to the MISP API endpoint."""
        if self.mock_mode:
            return {
                "success": True,
                "mode": "mock",
                "message": f"Mock Mode active: Connected to simulated MISP server with {len(MOCK_FS_ISAC_EVENTS)} FS-ISAC advisories available.",
            }

        if not self.base_url:
            return {"success": False, "mode": "live", "message": "MISP API Endpoint is required."}
        if not self.api_key:
            return {"success": False, "mode": "live", "message": "MISP Auth Key is required."}

        endpoint = f"{self.base_url}/servers/getVersion"
        headers = {
            "Authorization": self.api_key,
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    ver = data.get("version", "Unknown")
                    return {
                        "success": True,
                        "mode": "live",
                        "message": f"Successfully connected to live MISP server (Version {ver}). FS-ISAC feed tag: '{self.feed_tag}'.",
                    }
                else:
                    search_endpoint = f"{self.base_url}/events/restSearch"
                    search_resp = await client.post(
                        search_endpoint,
                        headers={"Authorization": self.api_key, "Accept": "application/json", "Content-Type": "application/json"},
                        json={"limit": 1, "tags": [self.feed_tag]},
                    )
                    if search_resp.status_code == 200:
                        return {
                            "success": True,
                            "mode": "live",
                            "message": f"Successfully authenticated with MISP API. FS-ISAC feed accessible.",
                        }
                    return {
                        "success": False,
                        "mode": "live",
                        "message": f"MISP API error HTTP {resp.status_code}: {resp.text[:200]}",
                    }
        except Exception as exc:
            return {
                "success": False,
                "mode": "live",
                "message": f"Connection error reaching {self.base_url}: {str(exc)}",
            }

    async def fetch_fs_isac_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch threat intelligence advisories from MISP filtered strictly by FS-ISAC tag."""
        if self.mock_mode:
            logger.info("Using MISP Mock FS-ISAC Threat Intelligence Feed")
            return self._parse_misp_events(MOCK_FS_ISAC_EVENTS)

        endpoint = f"{self.base_url}/events/restSearch"
        headers = {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        # Strictly query events tagged with FS-ISAC
        payload = {
            "tags": [self.feed_tag],
            "enforceWarninglist": True,
            "limit": limit,
            "quickFilter": "CVE",
        }

        try:
            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                resp = await client.post(endpoint, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                raw_events = data.get("response", []) if isinstance(data, dict) else data
                return self._parse_misp_events(raw_events)
        except Exception as e:
            logger.error(f"Failed to fetch live MISP FS-ISAC events ({e}). Falling back to mock feed.")
            return self._parse_misp_events(MOCK_FS_ISAC_EVENTS)

    def _parse_misp_events(self, raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize MISP event objects into standard FS-ISAC advisory records."""
        parsed_advisories = []

        for item in raw_events:
            ev = item.get("Event", item)
            tags = [t.get("name", "") if isinstance(t, dict) else str(t) for t in ev.get("Tag", [])]
            
            # Enforce that the advisory is from FS-ISAC
            is_fs_isac = any("fs-isac" in t.lower() for t in tags)
            if not is_fs_isac and not self.mock_mode:
                continue

            # Extract fields
            cve_id = ev.get("cve_id")
            if not cve_id:
                # Attempt to extract CVE from attributes
                for attr in ev.get("Attribute", []):
                    val = str(attr.get("value", ""))
                    if val.upper().startswith("CVE-"):
                        cve_id = val.upper().strip()
                        break
            
            if not cve_id:
                continue

            title = ev.get("title") or ev.get("info", f"FS-ISAC Advisory for {cve_id}")
            desc = ev.get("description", "")
            if not desc and ev.get("Attribute"):
                for attr in ev.get("Attribute", []):
                    if attr.get("type") in ("text", "comment"):
                        desc = attr.get("value", "")
                        break

            product = ev.get("affected_product", "software")
            vuln_ver = ev.get("vulnerable_versions", "")
            fixed_ver = ev.get("fixed_versions", "")
            
            # Severity mapping from threat level if not direct
            sev = ev.get("severity")
            if not sev:
                tl = str(ev.get("threat_level_id", "2"))
                if tl == "1":
                    sev = "Critical"
                elif tl == "2":
                    sev = "High"
                elif tl == "3":
                    sev = "Medium"
                else:
                    sev = "Low"

            cvss = ev.get("cvss_score")

            parsed_advisories.append({
                "cve_id": cve_id,
                "source": "FS-ISAC",
                "title": title,
                "description": desc or title,
                "severity": sev,
                "cvss_score": float(cvss) if cvss is not None else None,
                "affected_product": product,
                "vulnerable_versions": vuln_ver,
                "fixed_versions": fixed_ver,
                "recommended_actions": ev.get("recommended_actions", "Apply latest vendor patches or workarounds."),
                "verification_command": ev.get("verification_command", f"# Verify {product} package version on host"),
            })

        return parsed_advisories
