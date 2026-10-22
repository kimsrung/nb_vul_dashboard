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
                    zmq_info = "Disabled"
                    if settings.MISP_ZMQ_ENABLED and settings.MISP_ZMQ_HOST:
                        import socket
                        try:
                            s = socket.create_connection((settings.MISP_ZMQ_HOST, settings.MISP_ZMQ_PORT), timeout=2.0)
                            s.close()
                            zmq_info = f"Active (tcp://{settings.MISP_ZMQ_HOST}:{settings.MISP_ZMQ_PORT})"
                        except Exception:
                            zmq_info = f"Port {settings.MISP_ZMQ_PORT} Refused/Closed"
                    return {
                        "success": True,
                        "mode": "live",
                        "message": (
                            f"Successfully connected to live MISP server (v{ver}). "
                            f"ZeroMQ Watcher: {zmq_info}. Creator Org: '{self.creator_org}'."
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

    async def fetch_fs_isac_events(self, limit: int = 1000) -> List[Dict[str, Any]]:
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
        
        # Server-side query with Creator Org (org) and vulnerability tags
        payload: Dict[str, Any] = {
            "org": self.creator_org,
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
        Applies flexible FS-ISAC matching and comprehensive CVE extraction:
        1. Source Org / Creator Org / Tag / Title matches FS-ISAC
        2. CVEs extracted from tags, attributes, direct field, and title/description
        """
        parsed_advisories: List[Dict[str, Any]] = []

        for item in raw_events:
            ev = item.get("Event", item)
            
            # Condition 1: Enforce Creator Org (Orgc) / Source flexibility
            orgc = ev.get("Orgc", {})
            orgc_name = orgc.get("name", "") if isinstance(orgc, dict) else str(orgc)
            org = ev.get("Org", {})
            org_name = org.get("name", "") if isinstance(org, dict) else str(org)
            
            raw_tags = ev.get("Tag", [])
            tag_names = [t.get("name", "") if isinstance(t, dict) else str(t) for t in raw_tags]
            title = ev.get("title") or ev.get("info", "")
            desc = ev.get("description", "")
            
            if not self.mock_mode and self.creator_org and self.creator_org != "*":
                target_org = self.creator_org.lower()
                matches_org = (
                    target_org in orgc_name.lower()
                    or target_org in org_name.lower()
                    or target_org in title.lower()
                    or target_org in desc.lower()
                    or any(target_org in t.lower() for t in tag_names)
                )
                if not matches_org:
                    logger.debug(f"Skipping MISP event {ev.get('id')}: Source does not match '{self.creator_org}'")
                    continue

            # Condition 2: Extract distinct CVE IDs from tags, attributes, direct field, and text
            cve_ids: List[str] = []
            
            # A. Check tags: vulnerability:CVE-**** and direct CVE-**** tags
            for t_name in tag_names:
                for match in re.findall(r"\b(CVE-\d{4}-\d{4,})\b", t_name, re.IGNORECASE):
                    cid = match.upper()
                    if cid not in cve_ids:
                        cve_ids.append(cid)
            
            # B. Check direct cve_id field
            direct_cve = ev.get("cve_id")
            if direct_cve:
                for match in re.findall(r"\b(CVE-\d{4}-\d{4,})\b", str(direct_cve), re.IGNORECASE):
                    cid = match.upper()
                    if cid not in cve_ids:
                        cve_ids.append(cid)

            # C. Check attributes (values and comments)
            for attr in ev.get("Attribute", []):
                val = str(attr.get("value", "")).strip()
                comment = str(attr.get("comment", "")).strip()
                for text_to_check in (val, comment):
                    for match in re.findall(r"\b(CVE-\d{4}-\d{4,})\b", text_to_check, re.IGNORECASE):
                        cid = match.upper()
                        if cid not in cve_ids:
                            cve_ids.append(cid)

            # D. Check title/info and description text
            for match in re.findall(r"\b(CVE-\d{4}-\d{4,})\b", f"{title} {desc}", re.IGNORECASE):
                cid = match.upper()
                if cid not in cve_ids:
                    cve_ids.append(cid)

            # If no CVE was identified, skip event
            if not cve_ids:
                logger.debug(f"Skipping MISP event {ev.get('id')}: No matching CVEs found")
                continue

            # Extract advisory metadata
            if not desc and ev.get("Attribute"):
                for attr in ev.get("Attribute", []):
                    if attr.get("type") in ("text", "comment"):
                        desc = attr.get("value", "")
                        break
            if not title:
                title = f"FS-ISAC Advisory for {cve_ids[0]}"

            product = ev.get("affected_product")
            if not product or product.lower() in ("software", "unknown", "n/a"):
                full_text = f"{title} {desc} {' '.join(tag_names)}".lower()
                for candidate in [
                    "openssh", "openssl", "nginx", "apache", "httpd",
                    "php", "postgresql", "postgres", "mysql", "mariadb",
                    "oracle", "weblogic", "tomcat", "cisco", "fortios", "fortinet",
                    "exchange", "sharepoint", "confluence", "jira", "netscaler", "citrix",
                    "sonicos", "sonicwall", "winrar", "windows", "microsoft",
                    "esxi", "vmware", "vcenter", "screenconnect", "connectwise",
                    "solaris", "aix", "linux", "kernel", "sudo", "curl", "bind",
                    "dnsmasq", "check point", "checkpoint", "ivanti", "pulse secure",
                    "palo alto", "pan-os", "f5", "big-ip", "log4j", "log4shell",
                    "xz", "xz-utils", "runc", "docker", "kubernetes", "k8s",
                    "gitlab", "jenkins", "spring", "struts"
                ]:
                    if candidate in full_text:
                        product = candidate
                        break
            if not product:
                product = "software"

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

            m_event_id = str(ev.get("id") or "")

            # Assess each distinct CVE tagged in the event
            for cve_id in cve_ids:
                parsed_advisories.append({
                    "misp_event_id": m_event_id,
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
