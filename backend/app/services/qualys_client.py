import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import defusedxml.ElementTree as ET
import httpx

from app.core.config import settings
from app.services.qualys_mock import MOCK_KB_XML, MOCK_HOST_DETECTION_XML

logger = logging.getLogger(__name__)


class QualysApiClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        mock_mode: Optional[bool] = None,
    ):
        self.base_url = (base_url or settings.QUALYS_API_URL).rstrip("/")
        self.username = username if username is not None else settings.QUALYS_USERNAME
        self.password = password if password is not None else settings.QUALYS_PASSWORD
        self.mock_mode = mock_mode if mock_mode is not None else settings.QUALYS_MOCK_MODE

    def _get_headers(self) -> Dict[str, str]:
        return {
            "X-Requested-With": "QualysDashboardAlert",
            "Accept": "text/xml, application/xml",
        }

    async def test_connection(self) -> Dict[str, Any]:
        """Verify API credentials or mock availability."""
        if self.mock_mode:
            return {
                "success": True,
                "mode": "mock",
                "message": "Mock mode active. Successfully simulated Qualys API endpoint.",
            }

        if not self.username or not self.password:
            return {
                "success": False,
                "mode": "live",
                "message": "Qualys API username or password is missing.",
            }

        endpoint = f"{self.base_url}/api/2.0/fo/session/"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    endpoint,
                    data={"action": "login", "username": self.username, "password": self.password},
                    headers=self._get_headers(),
                )
                if response.status_code == 200 and "Logged in" in response.text:
                    # Cleanly logout
                    try:
                        await client.post(
                            endpoint,
                            data={"action": "logout"},
                            headers=self._get_headers(),
                            cookies=response.cookies,
                        )
                    except Exception:
                        pass
                    return {
                        "success": True,
                        "mode": "live",
                        "message": f"Successfully authenticated with Qualys API at {self.base_url}",
                    }
                else:
                    return {
                        "success": False,
                        "mode": "live",
                        "message": f"Qualys authentication failed with status {response.status_code}: {response.text[:200]}",
                    }
        except Exception as exc:
            return {
                "success": False,
                "mode": "live",
                "message": f"Connection error reaching {self.base_url}: {str(exc)}",
            }

    async def fetch_knowledge_base_xml(self, details: str = "All") -> str:
        """Fetch KnowledgeBase XML from live API or mock."""
        if self.mock_mode:
            logger.info("Using Qualys Mock KnowledgeBase XML")
            return MOCK_KB_XML

        endpoint = f"{self.base_url}/api/2.0/fo/knowledge_base/vuln/"
        params = {"action": "list", "details": details}
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(
                endpoint,
                params=params,
                auth=(self.username, self.password),
                headers=self._get_headers(),
            )
            resp.raise_for_status()
            return resp.text

    async def fetch_host_detections_xml(
        self,
        updated_since: Optional[str] = None,
        tag_set_include: Optional[str] = None,
        severities: str = "3,4,5",
    ) -> str:
        """Fetch Host VM Detections XML from live API or mock."""
        if self.mock_mode:
            logger.info("Using Qualys Mock Host Detections XML")
            return MOCK_HOST_DETECTION_XML

        endpoint = f"{self.base_url}/api/2.0/fo/asset/host/vm/detection/"
        params: Dict[str, Any] = {
            "action": "list",
            "show_igs": "0",  # Don't pull information gathering by default
            "status": "Active,New,Re-Opened",
            "severities": severities,
            "show_tags": "1",
            "output_format": "XML",
        }
        if updated_since:
            params["detection_updated_since"] = updated_since
        if tag_set_include:
            params["tag_set_by"] = "name"
            params["tag_set_include"] = tag_set_include

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.get(
                endpoint,
                params=params,
                auth=(self.username, self.password),
                headers=self._get_headers(),
            )
            resp.raise_for_status()
            return resp.text

    def parse_knowledge_base_xml(self, xml_content: str) -> List[Dict[str, Any]]:
        """Parse Qualys KnowledgeBase XML into structured dicts."""
        root = ET.fromstring(xml_content)
        parsed_qids = []

        for vuln_el in root.findall(".//VULN"):
            qid_str = vuln_el.findtext("QID")
            if not qid_str:
                continue

            try:
                qid = int(qid_str)
            except ValueError:
                continue

            title = vuln_el.findtext("TITLE", "").strip()
            category = vuln_el.findtext("CATEGORY", "").strip()
            vuln_type = vuln_el.findtext("VULN_TYPE", "Vulnerability").strip()
            
            sev_str = vuln_el.findtext("SEVERITY_LEVEL", "1")
            try:
                severity = int(sev_str)
            except ValueError:
                severity = 1

            # CVSS
            cvss3_str = vuln_el.findtext(".//CVSS_V3/BASE")
            cvss3 = float(cvss3_str) if cvss3_str else None

            cvss2_str = vuln_el.findtext(".//CVSS_BASE")
            cvss2 = float(cvss2_str) if cvss2_str else None

            diagnosis = vuln_el.findtext("DIAGNOSIS")
            consequence = vuln_el.findtext("CONSEQUENCE")
            solution = vuln_el.findtext("SOLUTION")
            workaround = vuln_el.findtext("WORKAROUND")

            # Patches
            patches = []
            for patch_el in vuln_el.findall(".//PATCH"):
                url = patch_el.findtext("URL")
                desc = patch_el.findtext("DESCRIPTION")
                if url or desc:
                    patches.append({"url": url, "description": desc})

            # CVEs
            cves = []
            for cve_el in vuln_el.findall(".//CVE/ID"):
                if cve_el.text:
                    cves.append(cve_el.text.strip())

            # Threat Intel / RTIs
            threat_intel = {}
            for ti_el in vuln_el.findall(".//THREAT_INTEL_VALUE"):
                ti_id = ti_el.attrib.get("id")
                if ti_id:
                    threat_intel[ti_id] = ti_el.text == "1"

            parsed_qids.append({
                "qid": qid,
                "title": title,
                "category": category,
                "vuln_type": vuln_type,
                "severity": severity,
                "cvss_v2": cvss2,
                "cvss_v3": cvss3,
                "diagnosis": diagnosis,
                "consequence": consequence,
                "solution": solution,
                "patches": patches,
                "workaround": workaround,
                "cve_list": cves,
                "threat_intel_flags": threat_intel,
            })

        return parsed_qids

    def parse_host_detections_xml(self, xml_content: str) -> List[Dict[str, Any]]:
        """Parse Qualys Host Detection XML into hosts with nested detections."""
        root = ET.fromstring(xml_content)
        parsed_hosts = []

        for host_el in root.findall(".//HOST"):
            qualys_id = host_el.findtext("ID")
            if not qualys_id:
                continue

            ip_address = host_el.findtext("IP")
            ipv6_address = host_el.findtext("IPV6")
            fqdn = host_el.findtext("DNS")
            netbios_name = host_el.findtext("NETBIOS")
            os_name = host_el.findtext("OS")
            
            # Categorize OS Family
            os_family = "Other"
            if os_name:
                os_lower = os_name.lower()
                if "windows" in os_lower:
                    os_family = "Windows"
                elif "linux" in os_lower or "ubuntu" in os_lower or "red hat" in os_lower or "debian" in os_lower or "centos" in os_lower or "alpine" in os_lower:
                    os_family = "Linux"
                elif "mac" in os_lower or "darwin" in os_lower:
                    os_family = "macOS"
                elif "cisco" in os_lower or "juniper" in os_lower or "network" in os_lower:
                    os_family = "Network"

            # Parse tags
            tags = []
            for tag_el in host_el.findall(".//TAG/NAME"):
                if tag_el.text:
                    tags.append(tag_el.text.strip())

            # Last scan datetime
            scan_dt_str = host_el.findtext("LAST_SCAN_DATETIME")
            last_scan_date = None
            if scan_dt_str:
                try:
                    last_scan_date = datetime.fromisoformat(scan_dt_str.replace("Z", "+00:00"))
                except Exception:
                    pass

            # Parse detections
            detections = []
            for det_el in host_el.findall(".//DETECTION"):
                qid_str = det_el.findtext("QID")
                if not qid_str:
                    continue
                try:
                    qid = int(qid_str)
                except ValueError:
                    continue

                det_type = det_el.findtext("TYPE", "Confirmed")
                sev_str = det_el.findtext("SEVERITY", "1")
                try:
                    sev = int(sev_str)
                except ValueError:
                    sev = 1

                status = det_el.findtext("STATUS", "Active")
                
                first_dt_str = det_el.findtext("FIRST_FOUND_DATETIME")
                first_found_date = None
                if first_dt_str:
                    try:
                        first_found_date = datetime.fromisoformat(first_dt_str.replace("Z", "+00:00"))
                    except Exception:
                        pass

                last_dt_str = det_el.findtext("LAST_FOUND_DATETIME")
                last_found_date = None
                if last_dt_str:
                    try:
                        last_found_date = datetime.fromisoformat(last_dt_str.replace("Z", "+00:00"))
                    except Exception:
                        pass

                times_found_str = det_el.findtext("TIMES_FOUND", "1")
                try:
                    times_found = int(times_found_str)
                except ValueError:
                    times_found = 1

                port_str = det_el.findtext("PORT")
                port = int(port_str) if port_str and port_str.isdigit() else None
                protocol = det_el.findtext("PROTOCOL")
                results = det_el.findtext("RESULTS")

                detections.append({
                    "qid": qid,
                    "detection_type": det_type,
                    "severity": sev,
                    "status": status,
                    "first_found_date": first_found_date,
                    "last_found_date": last_found_date,
                    "times_found": times_found,
                    "port": port,
                    "protocol": protocol,
                    "scanner_results": results,
                })

            parsed_hosts.append({
                "qualys_id": qualys_id,
                "ip_address": ip_address,
                "ipv6_address": ipv6_address,
                "fqdn": fqdn,
                "netbios_name": netbios_name,
                "os_name": os_name,
                "os_family": os_family,
                "tags": tags,
                "last_scan_date": last_scan_date,
                "detections": detections,
            })

        return parsed_hosts
