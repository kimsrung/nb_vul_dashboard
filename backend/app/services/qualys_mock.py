"""
Qualys Mock Service
Generates realistic Qualys API v2 XML responses for offline development,
testing, and demonstration without requiring active Qualys subscription credentials.
"""

MOCK_KB_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE KNOWLEDGE_BASE_VULN_LIST_OUTPUT SYSTEM "https://qualysapi.qualys.com/kno_base.dtd">
<KNOWLEDGE_BASE_VULN_LIST_OUTPUT>
  <RESPONSE>
    <DATETIME>2026-10-20T04:00:00Z</DATETIME>
    <VULN_LIST>
      <VULN>
        <QID>378291</QID>
        <VULN_TYPE>Vulnerability</VULN_TYPE>
        <SEVERITY_LEVEL>5</SEVERITY_LEVEL>
        <TITLE>OpenSSL Remote Code Execution and Memory Corruption Vulnerability</TITLE>
        <CATEGORY>Security</CATEGORY>
        <LAST_CUSTOMIZATION_DATETIME>2026-09-15T00:00:00Z</LAST_CUSTOMIZATION_DATETIME>
        <CVSS_V3>
          <BASE>9.8</BASE>
        </CVSS_V3>
        <THREAT_INTEL>
          <THREAT_INTEL_VALUE id="exploit_public">1</THREAT_INTEL_VALUE>
          <THREAT_INTEL_VALUE id="active_in_wild">1</THREAT_INTEL_VALUE>
          <THREAT_INTEL_VALUE id="ransomware">1</THREAT_INTEL_VALUE>
        </THREAT_INTEL>
        <DIAGNOSIS>OpenSSL contains a critical buffer overflow vulnerability in its X.509 certificate verification routines. An unauthenticated attacker can supply a specially crafted email or certificate chain to trigger remote code execution.</DIAGNOSIS>
        <CONSEQUENCE>Successful exploitation allows attackers to execute arbitrary code with privileges of the vulnerable application, potentially compromising the host.</CONSEQUENCE>
        <SOLUTION>Upgrade OpenSSL to version 3.0.8 / 1.1.1t or later. Apply distributor patches immediately.</SOLUTION>
        <PATCH_LIST>
          <PATCH>
            <URL>https://www.openssl.org/news/secadv/20230207.txt</URL>
            <DESCRIPTION>OpenSSL Security Advisory [07-Feb-2023]</DESCRIPTION>
          </PATCH>
        </PATCH_LIST>
        <WORKAROUND>Disable TLS client certificate verification if not strictly required, or apply network perimeter filtering for unauthenticated TLS endpoints.</WORKAROUND>
        <CVE_LIST>
          <CVE>
            <ID>CVE-2023-0286</ID>
          </CVE>
        </CVE_LIST>
      </VULN>

      <VULN>
        <QID>376241</QID>
        <VULN_TYPE>Vulnerability</VULN_TYPE>
        <SEVERITY_LEVEL>5</SEVERITY_LEVEL>
        <TITLE>Apache Log4j Remote Code Execution Vulnerability (Log4Shell)</TITLE>
        <CATEGORY>Java</CATEGORY>
        <CVSS_V3>
          <BASE>10.0</BASE>
        </CVSS_V3>
        <THREAT_INTEL>
          <THREAT_INTEL_VALUE id="exploit_public">1</THREAT_INTEL_VALUE>
          <THREAT_INTEL_VALUE id="active_in_wild">1</THREAT_INTEL_VALUE>
          <THREAT_INTEL_VALUE id="ransomware">1</THREAT_INTEL_VALUE>
          <THREAT_INTEL_VALUE id="remote_code_execution">1</THREAT_INTEL_VALUE>
        </THREAT_INTEL>
        <DIAGNOSIS>Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.</DIAGNOSIS>
        <CONSEQUENCE>An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.</CONSEQUENCE>
        <SOLUTION>Upgrade to log4j-core 2.17.1 or higher for Java 8. For Java 7 upgrade to 2.12.4.</SOLUTION>
        <PATCH_LIST>
          <PATCH>
            <URL>https://logging.apache.org/log4j/2.x/security.html</URL>
            <DESCRIPTION>Apache Log4j Security Vulnerabilities</DESCRIPTION>
          </PATCH>
        </PATCH_LIST>
        <WORKAROUND>Set system property log4j2.formatMsgNoLookups=true or remove JndiLookup class from classpath.</WORKAROUND>
        <CVE_LIST>
          <CVE>
            <ID>CVE-2021-44228</ID>
          </CVE>
        </CVE_LIST>
      </VULN>

      <VULN>
        <QID>91942</QID>
        <VULN_TYPE>Vulnerability</VULN_TYPE>
        <SEVERITY_LEVEL>5</SEVERITY_LEVEL>
        <TITLE>Microsoft Windows Active Directory Kerberos Privilege Escalation Vulnerability</TITLE>
        <CATEGORY>Windows</CATEGORY>
        <CVSS_V3>
          <BASE>8.8</BASE>
        </CVSS_V3>
        <THREAT_INTEL>
          <THREAT_INTEL_VALUE id="exploit_public">1</THREAT_INTEL_VALUE>
          <THREAT_INTEL_VALUE id="active_in_wild">1</THREAT_INTEL_VALUE>
        </THREAT_INTEL>
        <DIAGNOSIS>A privilege escalation vulnerability exists when the Kerberos Key Distribution Center (KDC) improperly handles certificate validation.</DIAGNOSIS>
        <CONSEQUENCE>An authenticated attacker with valid standard domain user credentials could elevate privileges to Domain Administrator.</CONSEQUENCE>
        <SOLUTION>Apply the relevant Microsoft Cumulative Security Update for Windows Server.</SOLUTION>
        <PATCH_LIST>
          <PATCH>
            <URL>https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-37967</URL>
            <DESCRIPTION>Microsoft Security Update Guide</DESCRIPTION>
          </PATCH>
        </PATCH_LIST>
        <WORKAROUND>Enable Full Enforcement mode in KDC registry keys after verifying client support.</WORKAROUND>
        <CVE_LIST>
          <CVE>
            <ID>CVE-2022-37967</ID>
          </CVE>
        </CVE_LIST>
      </VULN>

      <VULN>
        <QID>150682</QID>
        <VULN_TYPE>Vulnerability</VULN_TYPE>
        <SEVERITY_LEVEL>4</SEVERITY_LEVEL>
        <TITLE>OpenSSH Remote Code Execution Vulnerability (regreSSHion)</TITLE>
        <CATEGORY>Security</CATEGORY>
        <CVSS_V3>
          <BASE>8.1</BASE>
        </CVSS_V3>
        <THREAT_INTEL>
          <THREAT_INTEL_VALUE id="exploit_public">1</THREAT_INTEL_VALUE>
        </THREAT_INTEL>
        <DIAGNOSIS>A signal handler race condition in OpenSSH server (sshd) allows unauthenticated remote code execution as root on glibc-based Linux systems.</DIAGNOSIS>
        <CONSEQUENCE>An attacker can achieve unauthenticated root code execution on the target server via SSH port 22.</CONSEQUENCE>
        <SOLUTION>Upgrade OpenSSH to 9.8p1 or newer, or apply operating system package updates.</SOLUTION>
        <PATCH_LIST>
          <PATCH>
            <URL>https://www.openssh.com/txt/release-9.8</URL>
            <DESCRIPTION>OpenSSH 9.8 Release Notes</DESCRIPTION>
          </PATCH>
        </PATCH_LIST>
        <WORKAROUND>Set LoginGraceTime 0 in sshd_config (Note: this exposes sshd to Denial of Service).</WORKAROUND>
        <CVE_LIST>
          <CVE>
            <ID>CVE-2024-6387</ID>
          </CVE>
        </CVE_LIST>
      </VULN>

      <VULN>
        <QID>38914</QID>
        <VULN_TYPE>Vulnerability</VULN_TYPE>
        <SEVERITY_LEVEL>4</SEVERITY_LEVEL>
        <TITLE>NGINX HTTP/2 Rapid Reset Denial of Service Vulnerability</TITLE>
        <CATEGORY>Web Server</CATEGORY>
        <CVSS_V3>
          <BASE>7.5</BASE>
        </CVSS_V3>
        <THREAT_INTEL>
          <THREAT_INTEL_VALUE id="active_in_wild">1</THREAT_INTEL_VALUE>
        </THREAT_INTEL>
        <DIAGNOSIS>The HTTP/2 protocol allows a client to request a stream reset (RST_STREAM frame). Flooding RST_STREAM frames causes severe CPU exhaustion.</DIAGNOSIS>
        <CONSEQUENCE>Attacker can saturate web server CPU and render public websites unavailable.</CONSEQUENCE>
        <SOLUTION>Upgrade NGINX to 1.25.3 or apply keepalive_requests and limit_req rate limiting.</SOLUTION>
        <PATCH_LIST>
          <PATCH>
            <URL>https://www.nginx.com/blog/http-2-rapid-reset-attack-impacting-f5-nginx-products/</URL>
            <DESCRIPTION>F5 NGINX Security Advisory</DESCRIPTION>
          </PATCH>
        </PATCH_LIST>
        <WORKAROUND>Disable HTTP/2 support or configure rate limits on RST_STREAM.</WORKAROUND>
        <CVE_LIST>
          <CVE>
            <ID>CVE-2023-44487</ID>
          </CVE>
        </CVE_LIST>
      </VULN>

      <VULN>
        <QID>105822</QID>
        <VULN_TYPE>Vulnerability</VULN_TYPE>
        <SEVERITY_LEVEL>3</SEVERITY_LEVEL>
        <TITLE>TLS/SSL Server Supports Weak Cipher Suites (SWEET32)</TITLE>
        <CATEGORY>SSL/TLS</CATEGORY>
        <CVSS_V3>
          <BASE>5.9</BASE>
        </CVSS_V3>
        <DIAGNOSIS>The target host supports 64-bit block ciphers like 3DES and Blowfish in SSL/TLS.</DIAGNOSIS>
        <CONSEQUENCE>An attacker capable of sniffing traffic and inducing millions of requests can decrypt session cookies.</CONSEQUENCE>
        <SOLUTION>Disable 3DES and CBC mode ciphers; enforce AES-GCM and ChaCha20-Poly1305.</SOLUTION>
        <WORKAROUND>Configure web server SSL cipher suite to exclude 3DES.</WORKAROUND>
        <CVE_LIST>
          <CVE>
            <ID>CVE-2016-2183</ID>
          </CVE>
        </CVE_LIST>
      </VULN>
    </VULN_LIST>
  </RESPONSE>
</KNOWLEDGE_BASE_VULN_LIST_OUTPUT>"""


MOCK_HOST_DETECTION_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT SYSTEM "https://qualysapi.qualys.com/host_list_vm_detection_output.dtd">
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <DATETIME>2026-10-20T04:15:00Z</DATETIME>
    <HOST_LIST>
      <HOST>
        <ID>100101</ID>
        <IP>192.168.10.45</IP>
        <TRACKING_METHOD>IP</TRACKING_METHOD>
        <DNS>srv-db-prod01.internal.corp</DNS>
        <NETBIOS>SRV-DB-PROD01</NETBIOS>
        <OS>Ubuntu Linux 22.04 LTS</OS>
        <LAST_SCAN_DATETIME>2026-10-19T22:30:00Z</LAST_SCAN_DATETIME>
        <TAG_LIST>
          <TAG><NAME>PCI-DSS</NAME></TAG>
          <TAG><NAME>Production</NAME></TAG>
          <TAG><NAME>Database</NAME></TAG>
          <TAG><NAME>Linux</NAME></TAG>
        </TAG_LIST>
        <DETECTION_LIST>
          <DETECTION>
            <QID>378291</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>5</SEVERITY>
            <STATUS>Active</STATUS>
            <FIRST_FOUND_DATETIME>2026-09-01T10:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2026-10-19T22:30:00Z</LAST_FOUND_DATETIME>
            <TIMES_FOUND>18</TIMES_FOUND>
            <PORT>443</PORT>
            <PROTOCOL>tcp</PROTOCOL>
            <RESULTS>Vulnerable OpenSSL package detected: libssl3 3.0.2-0ubuntu1.7. Expected patched version >= 3.0.2-0ubuntu1.8 or 3.0.8.</RESULTS>
          </DETECTION>
          <DETECTION>
            <QID>150682</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>4</SEVERITY>
            <STATUS>Active</STATUS>
            <FIRST_FOUND_DATETIME>2026-09-10T11:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2026-10-19T22:30:00Z</LAST_FOUND_DATETIME>
            <TIMES_FOUND>12</TIMES_FOUND>
            <PORT>22</PORT>
            <PROTOCOL>tcp</PROTOCOL>
            <RESULTS>OpenSSH version string: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6. Affected by regreSSHion race condition.</RESULTS>
          </DETECTION>
          <DETECTION>
            <QID>105822</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>3</SEVERITY>
            <STATUS>Active</STATUS>
            <FIRST_FOUND_DATETIME>2026-08-15T08:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2026-10-19T22:30:00Z</LAST_FOUND_DATETIME>
            <TIMES_FOUND>30</TIMES_FOUND>
            <PORT>5432</PORT>
            <PROTOCOL>tcp</PROTOCOL>
            <RESULTS>PostgreSQL SSL listener accepts TLS_RSA_WITH_3DES_EDE_CBC_SHA.</RESULTS>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>

      <HOST>
        <ID>100102</ID>
        <IP>192.168.20.12</IP>
        <TRACKING_METHOD>IP</TRACKING_METHOD>
        <DNS>dc01.corp.domain</DNS>
        <NETBIOS>CORP-DC01</NETBIOS>
        <OS>Windows Server 2022 Datacenter</OS>
        <LAST_SCAN_DATETIME>2026-10-19T21:00:00Z</LAST_SCAN_DATETIME>
        <TAG_LIST>
          <TAG><NAME>Domain-Controller</NAME></TAG>
          <TAG><NAME>Windows</NAME></TAG>
          <TAG><NAME>Critical-Infra</NAME></TAG>
        </TAG_LIST>
        <DETECTION_LIST>
          <DETECTION>
            <QID>91942</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>5</SEVERITY>
            <STATUS>Active</STATUS>
            <FIRST_FOUND_DATETIME>2026-09-05T09:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2026-10-19T21:00:00Z</LAST_FOUND_DATETIME>
            <TIMES_FOUND>15</TIMES_FOUND>
            <PORT>88</PORT>
            <PROTOCOL>tcp</PROTOCOL>
            <RESULTS>Kerberos KDC missing Security Update KB5019966. Registry key StrongCertificateBindingEnforcement is set to 0 (disabled).</RESULTS>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>

      <HOST>
        <ID>100103</ID>
        <IP>10.20.6.190</IP>
        <TRACKING_METHOD>IP</TRACKING_METHOD>
        <DNS>bk-appcore-sit.internal.corp</DNS>
        <NETBIOS>BK-APPCORE-SIT</NETBIOS>
        <OS>Red Hat Enterprise Linux 8.8</OS>
        <LAST_SCAN_DATETIME>2026-10-20T01:15:00Z</LAST_SCAN_DATETIME>
        <TAG_LIST>
          <TAG><NAME>Production</NAME></TAG>
          <TAG><NAME>Java</NAME></TAG>
          <TAG><NAME>Analytics</NAME></TAG>
        </TAG_LIST>
        <DETECTION_LIST>
          <DETECTION>
            <QID>376241</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>5</SEVERITY>
            <STATUS>Active</STATUS>
            <FIRST_FOUND_DATETIME>2026-09-15T14:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2026-10-20T01:15:00Z</LAST_FOUND_DATETIME>
            <TIMES_FOUND>25</TIMES_FOUND>
            <PORT>8080</PORT>
            <PROTOCOL>tcp</PROTOCOL>
            <RESULTS>Vulnerable log4j-core-2.14.1.jar identified in /opt/analytics/lib/. JndiLookup class present in archive.</RESULTS>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>

      <HOST>
        <ID>100104</ID>
        <IP>172.16.50.8</IP>
        <TRACKING_METHOD>IP</TRACKING_METHOD>
        <DNS>lb-edge01.dmz.corp</DNS>
        <NETBIOS>LB-EDGE01</NETBIOS>
        <OS>Alpine Linux 3.18</OS>
        <LAST_SCAN_DATETIME>2026-10-19T23:45:00Z</LAST_SCAN_DATETIME>
        <TAG_LIST>
          <TAG><NAME>DMZ</NAME></TAG>
          <TAG><NAME>Internet-Facing</NAME></TAG>
          <TAG><NAME>Web</NAME></TAG>
        </TAG_LIST>
        <DETECTION_LIST>
          <DETECTION>
            <QID>38914</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>4</SEVERITY>
            <STATUS>Active</STATUS>
            <FIRST_FOUND_DATETIME>2026-09-20T12:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2026-10-19T23:45:00Z</LAST_FOUND_DATETIME>
            <TIMES_FOUND>10</TIMES_FOUND>
            <PORT>443</PORT>
            <PROTOCOL>tcp</PROTOCOL>
            <RESULTS>nginx/1.24.0 with HTTP/2 enabled. Vulnerable to HTTP/2 Rapid Reset DoS attack.</RESULTS>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>

      <HOST>
        <ID>100105</ID>
        <IP>192.168.30.55</IP>
        <TRACKING_METHOD>IP</TRACKING_METHOD>
        <DNS>ws-dev04.internal.corp</DNS>
        <NETBIOS>WS-DEV04</NETBIOS>
        <OS>macOS Sonoma 14.4</OS>
        <LAST_SCAN_DATETIME>2026-10-18T16:00:00Z</LAST_SCAN_DATETIME>
        <TAG_LIST>
          <TAG><NAME>Workstation</NAME></TAG>
          <TAG><NAME>Internal</NAME></TAG>
        </TAG_LIST>
        <DETECTION_LIST>
          <DETECTION>
            <QID>105822</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>3</SEVERITY>
            <STATUS>Active</STATUS>
            <FIRST_FOUND_DATETIME>2026-10-01T10:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2026-10-18T16:00:00Z</LAST_FOUND_DATETIME>
            <TIMES_FOUND>3</TIMES_FOUND>
            <PORT>8443</PORT>
            <PROTOCOL>tcp</PROTOCOL>
            <RESULTS>Local development server accepts 3DES cipher suites.</RESULTS>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>"""


MOCK_HOST_DETECTION_DELTA_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT SYSTEM "https://qualysapi.qualys.com/host_list_vm_detection_output.dtd">
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <DATETIME>2026-10-22T04:15:00Z</DATETIME>
    <HOST_LIST>
      <HOST>
        <ID>100101</ID>
        <IP>192.168.10.45</IP>
        <TRACKING_METHOD>IP</TRACKING_METHOD>
        <DNS>srv-db-prod01.internal.corp</DNS>
        <NETBIOS>SRV-DB-PROD01</NETBIOS>
        <OS>Ubuntu Linux 22.04 LTS</OS>
        <LAST_SCAN_DATETIME>2026-10-22T03:30:00Z</LAST_SCAN_DATETIME>
        <TAG_LIST>
          <TAG><NAME>PCI-DSS</NAME></TAG>
          <TAG><NAME>Production</NAME></TAG>
          <TAG><NAME>Database</NAME></TAG>
          <TAG><NAME>Linux</NAME></TAG>
        </TAG_LIST>
        <DETECTION_LIST>
          <DETECTION>
            <QID>150682</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>4</SEVERITY>
            <STATUS>Fixed</STATUS>
            <FIRST_FOUND_DATETIME>2026-09-10T11:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2026-10-22T03:30:00Z</LAST_FOUND_DATETIME>
            <TIMES_FOUND>13</TIMES_FOUND>
            <PORT>22</PORT>
            <PROTOCOL>tcp</PROTOCOL>
            <RESULTS>OpenSSH upgraded to 9.8p1. Vulnerability resolved and verified fixed by scanner.</RESULTS>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>

      <HOST>
        <ID>100103</ID>
        <IP>10.20.6.190</IP>
        <TRACKING_METHOD>IP</TRACKING_METHOD>
        <DNS>bk-appcore-sit.internal.corp</DNS>
        <NETBIOS>BK-APPCORE-SIT</NETBIOS>
        <OS>Red Hat Enterprise Linux 8.8</OS>
        <LAST_SCAN_DATETIME>2026-10-22T04:00:00Z</LAST_SCAN_DATETIME>
        <TAG_LIST>
          <TAG><NAME>Production</NAME></TAG>
          <TAG><NAME>Java</NAME></TAG>
          <TAG><NAME>Analytics</NAME></TAG>
        </TAG_LIST>
        <DETECTION_LIST>
          <DETECTION>
            <QID>376241</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>5</SEVERITY>
            <STATUS>Active</STATUS>
            <FIRST_FOUND_DATETIME>2026-09-15T14:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2026-10-22T04:00:00Z</LAST_FOUND_DATETIME>
            <TIMES_FOUND>26</TIMES_FOUND>
            <PORT>8080</PORT>
            <PROTOCOL>tcp</PROTOCOL>
            <RESULTS>Vulnerable log4j-core-2.14.1.jar identified in /opt/analytics/lib/. JndiLookup class present in archive.</RESULTS>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>"""

