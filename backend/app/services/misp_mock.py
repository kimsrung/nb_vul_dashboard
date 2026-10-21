"""High-fidelity Mock MISP (FS-ISAC) Feed Generator for Offline Dev/Testing.
Provides realistic threat advisories published via FS-ISAC with creator org and vulnerability tags.
"""

from typing import List, Dict, Any

MOCK_FS_ISAC_EVENTS: List[Dict[str, Any]] = [
    {
        "Event": {
            "id": "1001",
            "uuid": "4c9e830e-1111-42ab-873d-f515ac000101",
            "info": "[FS-ISAC Advisory] Critical Remote Code Execution in OpenSSH (regreSSHion)",
            "date": "2026-10-18",
            "threat_level_id": "1",  # High
            "analysis": "2",  # Completed
            "Orgc": {
                "id": "101",
                "name": "FS-ISAC",
                "uuid": "4c9e830e-0000-42ab-873d-f515ac000000",
            },
            "Org": {
                "id": "1",
                "name": "Internal SOC",
                "uuid": "4c9e830e-9999-42ab-873d-f515ac000999",
            },
            "Tag": [
                {"name": "vulnerability:CVE-2024-6387", "colour": "#0088cc"},
                {"name": "FS-ISAC", "colour": "#0088cc"},
                {"name": "tlp:amber", "colour": "#ffc107"},
                {"name": "sector:finance", "colour": "#28a745"},
                {"name": "type:emergency-cve-alert", "colour": "#dc3545"},
            ],
            "cve_id": "CVE-2024-6387",
            "title": "OpenSSH Server regreSSHion Unauthenticated Remote Code Execution",
            "description": "Signal handler race condition in OpenSSH's server (sshd) allows unauthenticated remote attackers to execute arbitrary code as root on glibc-based Linux systems.",
            "severity": "Critical",
            "cvss_score": 8.1,
            "affected_product": "openssh",
            "vulnerable_versions": "< 9.8p1",
            "fixed_versions": ">= 9.8p1",
            "recommended_actions": "Upgrade OpenSSH to version 9.8p1 or newer immediately. Alternatively, set LoginGraceTime 0 in sshd_config as a temporary workaround (note: exposes sshd to DoS).",
            "verification_command": "ssh -V && (dpkg -l | grep openssh-server || rpm -qa | grep openssh-server)",
        }
    },
    {
        "Event": {
            "id": "1002",
            "uuid": "4c9e830e-2222-42ab-873d-f515ac000102",
            "info": "[FS-ISAC Advisory] Malicious Backdoor Identified in Upstream XZ Utils",
            "date": "2026-10-19",
            "threat_level_id": "1",  # High / Critical
            "analysis": "2",
            "Orgc": {
                "id": "101",
                "name": "FS-ISAC",
                "uuid": "4c9e830e-0000-42ab-873d-f515ac000000",
            },
            "Org": {
                "id": "1",
                "name": "Internal SOC",
                "uuid": "4c9e830e-9999-42ab-873d-f515ac000999",
            },
            "Tag": [
                {"name": "vulnerability:CVE-2024-3094", "colour": "#0088cc"},
                {"name": "FS-ISAC", "colour": "#0088cc"},
                {"name": "tlp:red", "colour": "#dc3545"},
                {"name": "sector:finance", "colour": "#28a745"},
                {"name": "type:supply-chain-backdoor", "colour": "#6f42c1"},
            ],
            "cve_id": "CVE-2024-3094",
            "title": "Malicious Code Injection in XZ Utils / liblzma Data Compression Library",
            "description": "Upstream tarballs of xz-utils contain obfuscated malicious test code that hijacks OpenSSH authentication routines (RSA_public_decrypt) to grant unauthorized remote pre-auth access.",
            "severity": "Critical",
            "cvss_score": 10.0,
            "affected_product": "xz-utils",
            "vulnerable_versions": "5.6.0, 5.6.1",
            "fixed_versions": "5.6.2, 5.4.6",
            "recommended_actions": "Downgrade xz-utils to 5.4.6 or upgrade to patched vendor package 5.6.2. Terminate running sshd processes linked against liblzma.",
            "verification_command": "xz --version && ldd $(which sshd) | grep liblzma",
        }
    },
    {
        "Event": {
            "id": "1003",
            "uuid": "4c9e830e-3333-42ab-873d-f515ac000103",
            "info": "[FS-ISAC Advisory] NGINX HTTP/2 Rapid Reset Distributed Denial of Service",
            "date": "2026-10-15",
            "threat_level_id": "2",  # Medium
            "analysis": "2",
            "Orgc": {
                "id": "101",
                "name": "FS-ISAC",
                "uuid": "4c9e830e-0000-42ab-873d-f515ac000000",
            },
            "Org": {
                "id": "1",
                "name": "Internal SOC",
                "uuid": "4c9e830e-9999-42ab-873d-f515ac000999",
            },
            "Tag": [
                {"name": "vulnerability:CVE-2023-44487", "colour": "#0088cc"},
                {"name": "FS-ISAC", "colour": "#0088cc"},
                {"name": "tlp:green", "colour": "#28a745"},
                {"name": "sector:finance", "colour": "#28a745"},
            ],
            "cve_id": "CVE-2023-44487",
            "title": "HTTP/2 Protocol Stream Cancellation Flooding (Rapid Reset DoS)",
            "description": "Flaw in HTTP/2 stream multiplexing allows clients to request rapid stream cancellations via RST_STREAM, consuming high CPU without triggering connection limits.",
            "severity": "High",
            "cvss_score": 7.5,
            "affected_product": "nginx",
            "vulnerable_versions": "< 1.25.3",
            "fixed_versions": ">= 1.25.3",
            "recommended_actions": "Update NGINX to 1.25.3 or newer, or configure rate limits on RST_STREAM in nginx.conf.",
            "verification_command": "nginx -v",
        }
    },
    {
        "Event": {
            "id": "1004",
            "uuid": "4c9e830e-4444-42ab-873d-f515ac000104",
            "info": "[FS-ISAC Advisory] PHP-CGI Windows Argument Injection RCE",
            "date": "2026-10-12",
            "threat_level_id": "1",
            "analysis": "2",
            "Orgc": {
                "id": "101",
                "name": "FS-ISAC",
                "uuid": "4c9e830e-0000-42ab-873d-f515ac000000",
            },
            "Org": {
                "id": "1",
                "name": "Internal SOC",
                "uuid": "4c9e830e-9999-42ab-873d-f515ac000999",
            },
            "Tag": [
                {"name": "vulnerability:CVE-2024-4577", "colour": "#0088cc"},
                {"name": "FS-ISAC", "colour": "#0088cc"},
                {"name": "tlp:amber", "colour": "#ffc107"},
            ],
            "cve_id": "CVE-2024-4577",
            "title": "PHP-CGI Windows Character Encoding Best-Fit Bypass Remote Code Execution",
            "description": "Best-fit character encoding conversion in Windows locale handlers allows attackers to bypass CVE-2012-1823 protections and pass command-line arguments to PHP engines.",
            "severity": "Critical",
            "cvss_score": 9.8,
            "affected_product": "php",
            "vulnerable_versions": "< 8.1.29, < 8.2.20, < 8.3.8",
            "fixed_versions": ">= 8.3.8",
            "recommended_actions": "Upgrade PHP runtime to 8.3.8, 8.2.20, or 8.1.29. Avoid exposing php-cgi directly to web endpoints.",
            "verification_command": "php -v",
        }
    },
    {
        "Event": {
            "id": "1005",
            "uuid": "4c9e830e-5555-42ab-873d-f515ac000105",
            "info": "[FS-ISAC Advisory] runc Leaky Vessels Container Escape to Host",
            "date": "2026-10-10",
            "threat_level_id": "2",
            "analysis": "2",
            "Orgc": {
                "id": "101",
                "name": "FS-ISAC",
                "uuid": "4c9e830e-0000-42ab-873d-f515ac000000",
            },
            "Org": {
                "id": "1",
                "name": "Internal SOC",
                "uuid": "4c9e830e-9999-42ab-873d-f515ac000999",
            },
            "Tag": [
                {"name": "vulnerability:CVE-2024-21626", "colour": "#0088cc"},
                {"name": "FS-ISAC", "colour": "#0088cc"},
                {"name": "tlp:amber", "colour": "#ffc107"},
            ],
            "cve_id": "CVE-2024-21626",
            "title": "runc Working Directory File Descriptor Leak Leading to Host Root Breakout",
            "description": "An internal file descriptor leakage in runc during process execution allows malicious containers to overwrite host binaries and gain root privileges on the underlying host operating system.",
            "severity": "High",
            "cvss_score": 8.6,
            "affected_product": "runc",
            "vulnerable_versions": "< 1.1.12",
            "fixed_versions": ">= 1.1.12",
            "recommended_actions": "Upgrade runc package to 1.1.12 or newer across all container worker nodes. Restart containerd/docker daemon.",
            "verification_command": "runc --version",
        }
    },
    {
        "Event": {
            "id": "1006",
            "uuid": "4c9e830e-6666-42ab-873d-f515ac000106",
            "info": "[FS-ISAC Advisory] Palo Alto PAN-OS Management Interface Command Injection Zero-Day",
            "date": "2026-10-17",
            "threat_level_id": "1",
            "analysis": "2",
            "Orgc": {
                "id": "101",
                "name": "FS-ISAC",
                "uuid": "4c9e830e-0000-42ab-873d-f515ac000000",
            },
            "Org": {
                "id": "1",
                "name": "Internal SOC",
                "uuid": "4c9e830e-9999-42ab-873d-f515ac000999",
            },
            "Tag": [
                {"name": "vulnerability:CVE-2025-0108", "colour": "#0088cc"},
                {"name": "FS-ISAC", "colour": "#0088cc"},
                {"name": "tlp:amber", "colour": "#ffc107"},
            ],
            "cve_id": "CVE-2025-0108",
            "title": "Palo Alto Networks PAN-OS Web Management Authentication Bypass & RCE",
            "description": "A flaw in the PAN-OS web interface allows unauthenticated remote attackers to execute commands with root privileges on the management interface.",
            "severity": "Critical",
            "cvss_score": 9.3,
            "affected_product": "pan-os",
            "vulnerable_versions": "< 11.1.2",
            "fixed_versions": ">= 11.1.2-h1",
            "recommended_actions": "Restrict web management interface to trusted internal jump hosts. Apply PAN-OS emergency hotfix.",
            "verification_command": "show system info",
        }
    },
]
