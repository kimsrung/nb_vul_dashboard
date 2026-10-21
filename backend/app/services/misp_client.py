import logging
import re
from typing import List, Dict, Any, Optional
import httpx
from app.core.config import settings
from app.services.misp_mock import MOCK_FS_ISAC_EVENTS

logger = logging.getLogger(__name__)


class MispClient:
    """MISP Threat Intelligence Client strictly scoped to Creator Org FS-ISAC and vulnerability tags."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        creator_org: Optional[str] = None,
        tag_filter: Optional[str] = None,
        feed_tag: Optional[str] = None,
        mock_mode: Optional[bool] = None,
    ):
        self.base_url = (base_url or settings.MISP_URL).rstrip("/")
        self.api_key = api_key or settings.MISP_API_KEY
        self.creator_org = (creator_org or settings.MISP_CREATOR_ORG or "FS-ISAC").strip()
        self.tag_filter = (tag_filter or settings.MISP_TAG_FILTER or "vulnerability:CVE%").strip()
        self.feed_tag = (feed_tag or settings.MISP_FEED_TAG or "FS-ISAC").strip()
        self.mock_mode = mock_mode if mock_mode is not None else settings.MISP_MOCK_MODE

    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to the MISP API endpoint and verify creator org / tag filtering."""
        if self.mock_mode:
            return {
                "success": True,
                "mode": "mock",
                "message": (
                    f"Mock Mode active: Connected to simulated MISP server with {len(MOCK_FS_ISAC_EVENTS)} "
                    f"advisories matching Creator Org '{self.creator_org}' and tag filter '{self.tag_filter}'."
                ),
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
                        "message": (
                            f"Successfully connected to live MISP server (v{ver}). "
                            f"Creator Org: '{self.creator_org}', Tag Filter: '{self.tag_filter}'."
                        ),
                    }
                else:
                    # Fallback test with /events/restSearch
                    search_endpoint = f"{self.base_url}/events/restSearch"
                    search_payload: Dict[str, Any] = {
                        "limit": 1,
                        "orgc": self.creator_org,
                        "quickFilter": "CVE",
                    }
                    if self.tag_filter:
                        search_payload["tags"] = [self.tag_filter]

                    search_resp = await client.post(
                        search_endpoint,
                        headers={"Authorization": self.api_key, "Accept": "application/json", "Content-Type": "application/json"},
                        json=search_payload,
                    )
                    if search_resp.status_code == 200:
                        return {
                            "success": True,
                            "mode": "live",
                            "message": f"Successfully authenticated with MISP API /events/restSearch for Creator Org '{self.creator_org}'.",
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
        """Fetch threat intelligence advisories from MISP using /events/restSearch filtered by Creator Org & CVE tags."""
        if self.mock_mode:
            logger.info("Using MISP Mock FS-ISAC Threat Intelligence Feed")
            return self._parse_misp_events(MOCK_FS_ISAC_EVENTS)

        endpoint = f"{self.base_url}/events/restSearch"
        headers = {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        
        # Server-side query with Creator Org (orgc) and vulnerability tags
        payload: Dict[str, Any] = {
            "orgc": self.creator_org,
            "enforceWarninglist": True,
            "limit": limit,
            "quickFilter": "CVE",
        }
        if self.tag_filter:
            payload["tags"] = [self.tag_filter]

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
        """Normalize MISP event objects into standard FS-ISAC advisory records.
        Strictly enforces:
        1. Creator Org (Event.Orgc.name) matches configured creator org (default: FS-ISAC)
        2. Event tags contain vulnerability:CVE**** (extracts distinct CVE IDs)
        """
        parsed_advisories: List[Dict[str, Any]] = []
        cve_tag_pattern = re.compile(r"^vulnerability:(cve-\d{4}-\d{4,})$", re.IGNORECASE)

        for item in raw_events:
            ev = item.get("Event", item)
            
            # Condition 1: Enforce Creator Org (Orgc)
            orgc = ev.get("Orgc", {})
            orgc_name = orgc.get("name", "") if isinstance(orgc, dict) else str(orgc)
            if not self.mock_mode:
                if not (self.creator_org.lower() in orgc_name.lower()):
                    logger.debug(f"Skipping MISP event {ev.get('id')}: Creator Org '{orgc_name}' does not match '{self.creator_org}'")
                    continue

            # Condition 2: Extract CVEs from tags matching vulnerability:CVE****
            raw_tags = ev.get("Tag", [])
            tag_names = [t.get("name", "") if isinstance(t, dict) else str(t) for t in raw_tags]
            
            cve_ids: List[str] = []
            for t_name in tag_names:
                m = cve_tag_pattern.match(t_name.strip())
                if m:
                    cid = m.group(1).upper()
                    if cid not in cve_ids:
                        cve_ids.append(cid)

            # Fallback for mock mode or events with attributes if no tag regex matched
            if not cve_ids:
                direct_cve = ev.get("cve_id")
                if direct_cve and direct_cve.upper().startswith("CVE-"):
                    cve_ids.append(direct_cve.upper().strip())
                else:
                    for attr in ev.get("Attribute", []):
                        val = str(attr.get("value", "")).strip().upper()
                        if val.startswith("CVE-") and val not in cve_ids:
                            cve_ids.append(val)
                            break

            # If no CVE was identified or tags lacked vulnerability:CVE*, skip event
            if not cve_ids:
                logger.debug(f"Skipping MISP event {ev.get('id')}: No matching vulnerability:CVE tags found")
                continue

            # Extract advisory metadata
            title = ev.get("title") or ev.get("info", f"FS-ISAC Advisory for {cve_ids[0]}")
            desc = ev.get("description", "")
            if not desc and ev.get("Attribute"):
                for attr in ev.get("Attribute", []):
                    if attr.get("type") in ("text", "comment"):
                        desc = attr.get("value", "")
                        break

            product = ev.get("affected_product", "software")
            vuln_ver = ev.get("vulnerable_versions", "")
            fixed_ver = ev.get("fixed_versions", "")

            # Severity mapping from threat level
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
            rec_actions = ev.get("recommended_actions", "Apply latest vendor patches or workarounds.")
            verif_cmd = ev.get("verification_command", f"# Verify {product} package version on host")

            # Assess each distinct CVE tagged in the event
            for cve_id in cve_ids:
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
                    "recommended_actions": rec_actions,
                    "verification_command": verif_cmd,
                })

        return parsed_advisories
