#!/usr/bin/env python3
"""
Generate a comprehensive, executive-ready System Design & Proposal Word Document (.docx)
for ThreatCenter (https://threatcenter-itsec.nbc.gov.kh).
Combines docs/overview.md, docs/Qualys_MISP_work_together.md, and OWASP compliance auditing.
"""

import os
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import qn, nsdecls

def create_proposal_document():
    doc = docx.Document()

    # Configure Margins (1 inch everywhere)
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    # Color Palette Constants
    COLOR_PRIMARY = RGBColor(15, 41, 66)      # NBC Navy #0F2942
    COLOR_SECONDARY = RGBColor(2, 132, 199)   # Accent Blue #0284C7
    COLOR_TEXT = RGBColor(30, 41, 59)         # Slate Charcoal #1E293B
    COLOR_MUTED = RGBColor(100, 116, 139)     # Slate Gray #64748B
    HEX_HEADER_BG = "0F2942"                  # Dark Navy Hex
    HEX_LIGHT_BG = "F1F5F9"                   # Light Slate Hex
    HEX_ALT_ROW = "F8FAFC"                    # Very light row Hex
    HEX_BORDER = "CBD5E1"                     # Border Gray Hex
    HEX_PLACEHOLDER_BG = "F8FAFC"             # Box background
    HEX_PLACEHOLDER_BORDER = "0284C7"         # Border accent

    # Helper: Set Cell Shading
    def set_cell_background(cell, hex_color):
        shading_xml = f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>'
        cell._tc.get_or_add_tcPr().append(parse_xml(shading_xml))

    # Helper: Set Cell Margins (Padding)
    def set_cell_margins(cell, top=140, bottom=140, left=180, right=180):
        tcPr = cell._tc.get_or_add_tcPr()
        tcMar = OxmlElement('w:tcMar')
        for margin_name, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
            m = OxmlElement(f'w:{margin_name}')
            m.set(qn('w:w'), str(val))
            m.set(qn('w:type'), 'dxa')
            tcMar.append(m)
        tcPr.append(tcMar)

    # Helper: Table Borders
    def set_table_borders(table, border_color=HEX_BORDER):
        tblPr = table._tbl.tblPr
        borders_xml = f'''
        <w:tblBorders {nsdecls("w")}>
            <w:top w:val="single" w:sz="4" w:space="0" w:color="{border_color}"/>
            <w:bottom w:val="single" w:sz="6" w:space="0" w:color="{border_color}"/>
            <w:left w:val="none"/>
            <w:right w:val="none"/>
            <w:insideH w:val="single" w:sz="4" w:space="0" w:color="{border_color}"/>
            <w:insideV w:val="none"/>
        </w:tblBorders>
        '''
        tblPr.append(parse_xml(borders_xml))

    # Helper: Add Heading 1
    def add_h1(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(18)
        p.paragraph_format.space_after = Pt(8)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.font.name = "Calibri"
        run.font.size = Pt(18)
        run.font.bold = True
        run.font.color.rgb = COLOR_PRIMARY
        return p

    # Helper: Add Heading 2
    def add_h2(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(14)
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.font.name = "Calibri"
        run.font.size = Pt(14)
        run.font.bold = True
        run.font.color.rgb = COLOR_SECONDARY
        return p

    # Helper: Add Heading 3
    def add_h3(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(10)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.font.name = "Calibri"
        run.font.size = Pt(12)
        run.font.bold = True
        run.font.color.rgb = COLOR_TEXT
        return p

    # Helper: Add Body Paragraph
    def add_p(text, bold=False, italic=False):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.line_spacing = 1.15
        run = p.add_run(text)
        run.font.name = "Calibri"
        run.font.size = Pt(11)
        run.font.bold = bold
        run.font.italic = italic
        run.font.color.rgb = COLOR_TEXT
        return p

    # Helper: Add Bullet
    def add_bullet(lead, text):
        p = doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_before = Pt(1)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.line_spacing = 1.15
        run_lead = p.add_run(lead)
        run_lead.font.name = "Calibri"
        run_lead.font.size = Pt(11)
        run_lead.font.bold = True
        run_lead.font.color.rgb = COLOR_PRIMARY
        run_text = p.add_run(f" {text}")
        run_text.font.name = "Calibri"
        run_text.font.size = Pt(11)
        run_text.font.color.rgb = COLOR_TEXT
        return p

    # Helper: Add Callout Box / Alert
    def add_callout(title, body, border_color="0284C7", bg_color="F0F9FF"):
        tbl = doc.add_table(rows=1, cols=1)
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        tbl.autofit = False
        tbl.columns[0].width = Inches(6.5)
        cell = tbl.cell(0, 0)
        set_cell_background(cell, bg_color)
        set_cell_margins(cell, top=140, bottom=140, left=180, right=180)
        borders_xml = f'''
        <w:tcBorders {nsdecls("w")}>
            <w:top w:val="none"/>
            <w:left w:val="single" w:sz="24" w:space="0" w:color="{border_color}"/>
            <w:bottom w:val="none"/>
            <w:right w:val="none"/>
        </w:tcBorders>
        '''
        cell._tc.get_or_add_tcPr().append(parse_xml(borders_xml))
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(4)
        run_title = p.add_run(title + "\n")
        run_title.font.name = "Calibri"
        run_title.font.size = Pt(11)
        run_title.font.bold = True
        run_title.font.color.rgb = COLOR_PRIMARY
        run_body = p.add_run(body)
        run_body.font.name = "Calibri"
        run_body.font.size = Pt(10.5)
        run_body.font.color.rgb = COLOR_TEXT
        doc.add_paragraph().paragraph_format.space_after = Pt(4)

    # Helper: Screenshot Placeholder Box
    def add_screenshot_placeholder(module_title, description, figure_num):
        tbl = doc.add_table(rows=1, cols=1)
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        tbl.autofit = False
        tbl.columns[0].width = Inches(6.5)
        cell = tbl.cell(0, 0)
        set_cell_background(cell, HEX_PLACEHOLDER_BG)
        set_cell_margins(cell, top=240, bottom=240, left=200, right=200)

        box_border_xml = f'''
        <w:tcBorders {nsdecls("w")}>
            <w:top w:val="dashed" w:sz="12" w:space="0" w:color="{HEX_PLACEHOLDER_BORDER}"/>
            <w:left w:val="dashed" w:sz="12" w:space="0" w:color="{HEX_PLACEHOLDER_BORDER}"/>
            <w:bottom w:val="dashed" w:sz="12" w:space="0" w:color="{HEX_PLACEHOLDER_BORDER}"/>
            <w:right w:val="dashed" w:sz="12" w:space="0" w:color="{HEX_PLACEHOLDER_BORDER}"/>
        </w:tcBorders>
        '''
        cell._tc.get_or_add_tcPr().append(parse_xml(box_border_xml))

        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(8)
        p.paragraph_format.space_after = Pt(4)
        run_cam = p.add_run("📷 [SCREENSHOT PLACEHOLDER]\n")
        run_cam.font.name = "Calibri"
        run_cam.font.size = Pt(11)
        run_cam.font.bold = True
        run_cam.font.color.rgb = COLOR_SECONDARY

        run_title = p.add_run(f"Figure {figure_num}: {module_title}\n")
        run_title.font.name = "Calibri"
        run_title.font.size = Pt(11)
        run_title.font.bold = True
        run_title.font.color.rgb = COLOR_PRIMARY

        p_desc = cell.add_paragraph()
        p_desc.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_desc.paragraph_format.space_before = Pt(2)
        p_desc.paragraph_format.space_after = Pt(8)
        run_desc = p_desc.add_run(f"(Instruction: Take a screenshot of {description} and paste it into this box)")
        run_desc.font.name = "Calibri"
        run_desc.font.size = Pt(9.5)
        run_desc.font.italic = True
        run_desc.font.color.rgb = COLOR_MUTED

        # Add space after table
        sp = doc.add_paragraph()
        sp.paragraph_format.space_after = Pt(8)

    # --------------------------------------------------------------------------
    # COVER PAGE
    # --------------------------------------------------------------------------
    p_cov_org = doc.add_paragraph()
    p_cov_org.paragraph_format.space_before = Pt(36)
    p_cov_org.paragraph_format.space_after = Pt(6)
    r_org = p_cov_org.add_run("NATIONAL BANK OF CAMBODIA")
    r_org.font.name = "Calibri"
    r_org.font.size = Pt(16)
    r_org.font.bold = True
    r_org.font.color.rgb = COLOR_PRIMARY

    p_cov_dept = doc.add_paragraph()
    p_cov_dept.paragraph_format.space_before = Pt(0)
    p_cov_dept.paragraph_format.space_after = Pt(30)
    r_dept = p_cov_dept.add_run("IT SECURITY DEPARTMENT — CYBERSECURITY OPERATIONS CENTER")
    r_dept.font.name = "Calibri"
    r_dept.font.size = Pt(12)
    r_dept.font.bold = True
    r_dept.font.color.rgb = COLOR_SECONDARY

    # Project Title
    p_title = doc.add_paragraph()
    p_title.paragraph_format.space_before = Pt(20)
    p_title.paragraph_format.space_after = Pt(10)
    r_title = p_title.add_run("THREATCENTER")
    r_title.font.name = "Calibri"
    r_title.font.size = Pt(32)
    r_title.font.bold = True
    r_title.font.color.rgb = COLOR_PRIMARY

    # Subtitle
    p_sub = doc.add_paragraph()
    p_sub.paragraph_format.space_before = Pt(0)
    p_sub.paragraph_format.space_after = Pt(24)
    r_sub = p_sub.add_run("Enterprise Threat Intelligence Correlation, Vulnerability Management & Proactive Remediation Platform\nSystem Design, Architecture & Operational Proposal")
    r_sub.font.name = "Calibri"
    r_sub.font.size = Pt(14)
    r_sub.font.italic = True
    r_sub.font.color.rgb = COLOR_MUTED

    # Metadata Grid Table
    meta_tbl = doc.add_table(rows=6, cols=2)
    meta_tbl.autofit = False
    meta_tbl.columns[0].width = Inches(2.2)
    meta_tbl.columns[1].width = Inches(4.3)
    set_table_borders(meta_tbl)

    meta_data = [
        ("Production Host URL", "https://threatcenter-itsec.nbc.gov.kh"),
        ("Project Identifier", "NBC-TC-ITSEC-2026"),
        ("Current System Status", "Operational / Hardened Dual TLS 1.2/1.3"),
        ("Integrations", "Qualys Cloud VMDR, MISP (FS-ISAC ZeroMQ), Telegram Incident Bot"),
        ("Compliance Benchmark", "OWASP Top 10/12, NIST CSF, ISO 27001, FS-ISAC Standards"),
        ("Document Classification", "CONFIDENTIAL — STRICTLY FOR INTERNAL NBC OPERATIONS")
    ]
    for row_idx, (label, val) in enumerate(meta_data):
        row = meta_tbl.rows[row_idx]
        cell_lbl, cell_val = row.cells[0], row.cells[1]
        set_cell_background(cell_lbl, HEX_LIGHT_BG)
        set_cell_margins(cell_lbl, top=100, bottom=100, left=140, right=140)
        set_cell_margins(cell_val, top=100, bottom=100, left=140, right=140)
        p1 = cell_lbl.paragraphs[0]
        r1 = p1.add_run(label)
        r1.font.name = "Calibri"
        r1.font.bold = True
        r1.font.size = Pt(10)
        r1.font.color.rgb = COLOR_PRIMARY
        p2 = cell_val.paragraphs[0]
        r2 = p2.add_run(val)
        r2.font.name = "Calibri"
        r2.font.size = Pt(10)
        r2.font.color.rgb = COLOR_TEXT

    # Page Break after Cover
    doc.add_page_break()

    # --------------------------------------------------------------------------
    # TABLE OF CONTENTS / EXECUTIVE OUTLINE
    # --------------------------------------------------------------------------
    add_h1("Table of Contents & Executive Document Outline")
    toc_items = [
        "1. Executive Summary & Strategic Business Value",
        "2. The Cybersecurity Operations Dilemma (Scanners vs. Threat Feeds)",
        "3. ThreatCenter Unified System Architecture & Data Pipelines",
        "4. Qualys & MISP (FS-ISAC) Coexistence & Conflict-Prevention Architecture",
        "5. Real-World Zero-Day Incident Walkthrough: OpenSSH regreSSHion (CVE-2024-6387)",
        "6. In-Depth Operational Modules & Visual Screenshot References",
        "   6.1 Module 1: Executive Overview Dashboard",
        "   6.2 Module 2: Asset Inventory & Two-Tier Contact Host Profile",
        "   6.3 Module 3: Threat Center & Remediation Triage Queue",
        "   6.4 Module 4: MISP Threat Intelligence Explorer & Central Ingestion",
        "   6.5 Module 5: MITRE ATT&CK Matrix & Compensating Controls Navigator",
        "   6.6 Module 6: User Management & Enterprise RBAC Enforcement",
        "   6.7 Module 7: Immutable Audit Trail & Regulatory Compliance Engine",
        "   6.8 Module 8: System Administration & Integration Diagnostic Hub",
        "7. Technical Specifications, Container Hardening & OWASP Top 12 Compliance",
        "8. Phased Implementation Roadmap & Governance Milestones",
        "9. Infrastructure Sizing, Hosting Specifications & Operational Budget",
        "10. Steering Committee Approval & Recommendation Sign-Off"
    ]
    for item in toc_items:
        p_toc = doc.add_paragraph()
        p_toc.paragraph_format.space_before = Pt(2)
        p_toc.paragraph_format.space_after = Pt(2)
        p_toc.paragraph_format.line_spacing = 1.15
        r_toc = p_toc.add_run(item)
        r_toc.font.name = "Calibri"
        r_toc.font.size = Pt(10.5)
        if item.startswith("   "):
            r_toc.font.color.rgb = COLOR_MUTED
        else:
            r_toc.font.bold = True
            r_toc.font.color.rgb = COLOR_PRIMARY

    doc.add_page_break()

    # --------------------------------------------------------------------------
    # SECTION 1: EXECUTIVE SUMMARY
    # --------------------------------------------------------------------------
    add_h1("1. Executive Summary & Strategic Business Value")
    add_p("The National Bank of Cambodia (NBC) serves as the monetary and banking authority of the Kingdom of Cambodia, overseeing vital financial payment gateways, interbank clearing networks, and central banking digital services. The operational availability and integrity of these assets are paramount to the nation's financial stability.")
    add_p("ThreatCenter (accessible at https://threatcenter-itsec.nbc.gov.kh) is an enterprise cybersecurity platform designed to unify reactive vulnerability scanning with real-time proactive threat intelligence into a centralized, single pane of glass for NBC SecOps engineers, server system owners, and bank executives.")

    add_callout(
        "CORE VALUE PROPOSITION: PROACTIVE DEFENSE AT ZERO INCREMENTAL LICENSING COST",
        "ThreatCenter connects NBC's existing enterprise investments in Qualys Cloud Platform VMDR and MISP (FS-ISAC) Threat Sharing without purchasing costly third-party commercial SOAR platforms. By correlating real-time threat intelligence with live host software inventories, the platform identifies exposed servers within 5 seconds of zero-day advisory publications."
    )

    add_h2("1.1 Quantitative Return on Investment (ROI)")
    add_bullet("Mean Time to Detect (MTTD) Reduction:", "Slashed from days or weeks (waiting for active scanner signature authoring and scheduled sweeps) to under 5 seconds via native ZeroMQ threat streaming.")
    add_bullet("Mean Time to Remediate (MTTR) Improvement:", "Reduced by over 60% through a self-service Asset Owner portal, automated remediation checklists, and direct Point of Contact (PoC) accountability.")
    add_bullet("Elimination of False Sense of Security:", "Scanners only report what they have an explicit signature for. ThreatCenter compares raw software package telemetry (OpenSSH, Nginx, Apache, PHP, Linux Kernel) against emergency CVE version criteria before a scanner signature even exists.")
    add_bullet("Zero Operational Notification Fatigue:", "Routine Qualys scanner discoveries are cleanly separated from critical emergency advisories. Emergency alerts routed via Telegram incident bot enforce a strict 6-hour deduplication window per host.")

    # --------------------------------------------------------------------------
    # SECTION 2: THE DILEMMA
    # --------------------------------------------------------------------------
    add_h1("2. The Cybersecurity Operations Dilemma")
    add_p("Security operations teams in financial institutions face a persistent, fundamental operational dilemma between active vulnerability scanners and threat intelligence feeds:")

    dilemma_tbl = doc.add_table(rows=5, cols=3)
    dilemma_tbl.autofit = False
    dilemma_tbl.columns[0].width = Inches(2.0)
    dilemma_tbl.columns[1].width = Inches(2.25)
    dilemma_tbl.columns[2].width = Inches(2.25)
    set_table_borders(dilemma_tbl)

    headers = ["Evaluation Metric", "Active Scanners (Qualys VMDR)", "Threat Feeds (MISP / FS-ISAC)"]
    for i, h in enumerate(headers):
        cell = dilemma_tbl.rows[0].cells[i]
        set_cell_background(cell, HEX_HEADER_BG)
        set_cell_margins(cell, 120, 120, 140, 140)
        p = cell.paragraphs[0]
        r = p.add_run(h)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(10)
        r.font.color.rgb = RGBColor(255, 255, 255)

    rows_data = [
        ("Detection Timing", "Inherently Reactive (Day 1 to 7)\nRequires signature authoring and scan scheduling.", "Instantaneous (Day 0)\nAdvisories received seconds after disclosure."),
        ("Verification Proof", "Diagnostic Proof (Port/Service Level)\nDefinitive scanner evidence and compliance audit proof.", "Theoretical Criteria\nThreat feeds cannot verify if a specific host is exposed."),
        ("Actionability", "High for Known Issues\nProvides vendor solutions and patch instructions.", "Urgent Early Warning\nFlags active zero-day exploitation in the wild."),
        ("Coverage Blind Spot", "Zero-Day Window Vulnerability\nLeaves a dangerous lag before signature release.", "Inventory Disconnect\nFeeds lack context of NBC's internal server fleet.")
    ]
    for row_idx, rdata in enumerate(rows_data):
        row = dilemma_tbl.rows[row_idx + 1]
        for col_idx, text in enumerate(rdata):
            cell = row.cells[col_idx]
            if row_idx % 2 == 1:
                set_cell_background(cell, HEX_ALT_ROW)
            set_cell_margins(cell, 100, 100, 140, 140)
            p = cell.paragraphs[0]
            r = p.add_run(text)
            r.font.name = "Calibri"
            r.font.size = Pt(9.5)
            r.font.color.rgb = COLOR_TEXT

    add_p("")
    add_h2("2.1 The Two-Tier Host Contact & Ownership Model")
    add_p("A recurring breakdown in enterprise remediation is the disconnect between shared service accounts and actual system engineers. ThreatCenter solves this through a decoupled Two-Tier Contact Model:")
    add_bullet("Tier 1: Group Ownership Account (owner_username / owner_id):", "Represents the responsible administrative team (e.g., owner_appcore, db_team). Strictly mapped to RBAC role 'owner' for login scoping. When this account logs in, the user strictly sees assets assigned to their team.")
    add_bullet("Tier 2: Individual Human Point of Contact (poc_name / poc_email):", "Represents the active primary engineer (e.g., Chan Vanna, chan.vanna@nbc.gov.kh). Displayed on all incident cards and Telegram alerts so on-call analysts know exactly which engineer to call during emergencies.")

    # --------------------------------------------------------------------------
    # SECTION 3: SYSTEM ARCHITECTURE & DATA PIPELINES
    # --------------------------------------------------------------------------
    add_h1("3. ThreatCenter Unified System Architecture & Data Pipelines")
    add_p("ThreatCenter is designed as a modular, event-driven, asynchronous platform capable of handling multi-source telemetry without performance degradation.")

    add_h2("3.1 Architectural Tiers")
    add_bullet("1. Ingestion & Polling Tier:", "Scheduled background workers and real-time ZeroMQ subscribers connect to Qualys Cloud APIs and MISP message brokers. Asynchronous lock managers (SyncRunner) prevent overlapping jobs.")
    add_bullet("2. Processing & Correlation Tier:", "FastAPI ASGI engine parses scanner diagnostic proofs to discover installed software packages, extracts CVE version ranges, and calculates raw Qualys Severity 1–5 counters.")
    add_bullet("3. Persistence & Integrity Tier:", "PostgreSQL 16 relational database with strictly partitioned tables, foreign key cascades, and append-only audit logging.")
    add_bullet("4. Presentation & Response Tier:", "React 18 + Vite SPA communicating with RESTful endpoints, complemented by a Telegram bot for automated emergency dispatch.")

    # --------------------------------------------------------------------------
    # SECTION 4: QUALYS & MISP COEXISTENCE
    # --------------------------------------------------------------------------
    add_h1("4. Qualys & MISP Coexistence & Conflict-Prevention")
    add_p("A core architectural achievement of ThreatCenter is the mathematical guarantee that Qualys scanner findings and MISP threat advisories operate concurrently without competing for state or corrupting risk metrics.")

    add_h2("4.1 Proof 1: Database Table & Responsibility Separation")
    add_p("Qualys and MISP write to completely separate tables. MISP treats Qualys host data as an authoritative, read-only baseline:")
    add_bullet("Table `assets` & `detections` (Qualys Sync Only):", "Maintains discovered hosts, operating systems, verified QIDs, ports, and raw severity counters.")
    add_bullet("Table `asset_software` (Populated by Qualys, Read by MISP):", "Stores package names, versions, and install paths parsed from Qualys discovery diagnostics.")
    add_bullet("Table `misp_cve_assessments` (MISP Engine Only):", "Maintains threat advisories, vendor criteria, matching evidence, and proactive evaluation states.")
    add_bullet("Table `alerts` (Unified Action Queue):", "Centralizes high-priority remediation tickets across both systems.")

    add_h2("4.2 Proof 2: Non-Conflicting Severity Calculation")
    add_p("ThreatCenter completely eliminates artificial synthetic risk scores (e.g., 85/100) and formulaic SLA penalties. Host risk is categorized directly by native Qualys Severity 1 to 5:")
    add_bullet("Severity 5 (Critical):", "Immediate remote compromise / remote code execution.")
    add_bullet("Severity 4 (High):", "Privilege escalation / data leakage.")
    add_bullet("Severity 3 (Medium):", "Denial of service / sensitive configuration flaw.")
    add_bullet("Severity 2 (Low) & Severity 1 (Info):", "Informational service disclosures.")
    add_p("When MISP identifies an at-risk server on Day 0, it creates a Threat Alert, but does NOT artificially inflate Qualys detection counts. Once Qualys scans the server on Day 3, the detection enters the official counter organically.")

    add_h2("4.3 Proof 3: Seamless State Machine Elevation (PROACTIVE -> CONFIRMED)")
    add_p("When an advisory is evaluated against an asset, it follows an immutable three-step evaluation chain:")
    add_bullet("Step 1 (Scanner Check):", "Has Qualys confirmed an active detection for this CVE? If YES -> Set match_type = 'QUALYS_CONFIRMED' (Confidence: High).")
    add_bullet("Step 2 (Software Inventory Check):", "If NO, compare installed packages in `asset_software` against advisory criteria. If MATCH -> Set match_type = 'INVENTORY_PROACTIVE' (Confidence: High).")
    add_bullet("Step 3 (Platform Check):", "If installed package is absent, check host operating system. If MATCH -> Set match_type = 'INVENTORY_PROACTIVE' (Confidence: Medium).")
    add_p("If an advisory was already marked QUALYS_CONFIRMED, subsequent proactive syncs never downgrade the confidence.")

    # --------------------------------------------------------------------------
    # SECTION 5: REAL-WORLD INCIDENT CASE STUDY
    # --------------------------------------------------------------------------
    add_h1("5. Real-World Zero-Day Incident Walkthrough: OpenSSH regreSSHion")
    add_p("To visualize how ThreatCenter operates in a production banking crisis, consider the disclosure of CVE-2024-6387 (OpenSSH Remote Code Execution):")

    add_h2("5.1 Phase 1: Pre-Incident Telemetry Gathering (Day -1)")
    add_p("Qualys executes routine scans across 74 NBC servers. During synchronization, ThreatCenter regex-parses SSH discovery diagnostic output and records into `asset_software`:")
    add_bullet("Target Server:", "bk-appcore-sit (10.10.20.15)")
    add_bullet("Discovered Software:", "OpenSSH_8.2p1 Ubuntu-4ubuntu0.13 (/usr/sbin/sshd on port 22)")
    add_bullet("Assigned Contacts:", "Owner Group: AppCore_Team | PoC: Chan Vanna <chan.vanna@nbc.gov.kh>")

    add_h2("5.2 Phase 2: Emergency Threat Arrival via MISP ZeroMQ (Day 0, 09:00 UTC)")
    add_p("FS-ISAC broadcasts emergency advisory CVE-2024-6387 (Criterion: OpenSSH < 9.8p1). Qualys has not released a signature yet.")
    add_bullet("Engine Evaluation:", "ThreatCenter compares installed version '8.2p1' against '< 9.8p1'. Match confirmed vulnerable.")
    add_bullet("Instant Alert:", "ThreatCenter creates a Threat Alert flagged INVENTORY_PROACTIVE and dispatches an incident card to the SecOps Telegram channel within 4 seconds.")
    add_bullet("Immediate Mitigation:", "Chan Vanna receives the Telegram alert containing the exact host IP and recommended fix, applying 'LoginGraceTime 0' within 30 minutes.")

    add_h2("5.3 Phase 3: Scanner Signature Release & State Elevation (Day 3)")
    add_p("Qualys authors QID 379982 and scans the subnet. The detection is recorded, and ThreatCenter automatically elevates the alert match state to QUALYS_CONFIRMED.")

    add_h2("5.4 Phase 4: Patch Deployment & Automated Resolution (Day 4)")
    add_p("AppCore_Team upgrades the package to OpenSSH 9.8p1. The next Qualys Delta Sync detects status 'Fixed'. ThreatCenter decrements the active Critical severity count and marks the threat alert as Remediated.")

    # --------------------------------------------------------------------------
    # SECTION 6: IN-DEPTH CORE MODULES & SCREENSHOT PLACEHOLDERS
    # --------------------------------------------------------------------------
    add_h1("6. In-Depth Breakdown of Core System Modules")
    add_p("ThreatCenter is organized into eight specialized operational modules, providing role-based workflows for executives, analysts, and system administrators.")

    # Module 1
    add_h2("6.1 Module 1: Executive Overview Dashboard (DashboardPage)")
    add_p("Serves as the high-level operational command center for CISO briefings and daily SecOps triage:")
    add_bullet("Minimalist 3-KPI Cards:", "Total Assets Monitored (74 hosts), Total Open Vulnerabilities (with live Sev 5 to Sev 1 pill breakdown), and MISP Threat Advisories count.")
    add_bullet("Visual Analytics:", "Raw Qualys Severity 1–5 distribution bars, Top Operating Systems breakdown, and Real-Time Threat Intelligence (RTI) indicators (Ransomware, In the Wild, Public Exploit, Zero-Day).")
    add_bullet("Priority Action Queue:", "Most Affected Infrastructure table ranking servers by Critical (Sev 5) and High (Sev 4) findings.")
    add_bullet("Asynchronous Sync Controls:", "Dropdown trigger for Incremental Delta Sync or Full Reconciliation Sync with live background progress polling.")
    add_screenshot_placeholder(
        "Executive Overview Dashboard",
        "the main dashboard showing the 3 top KPI cards, Qualys Severity Distribution, RTI flags, and Most Affected Infrastructure table",
        1
    )

    # Module 2
    add_h2("6.2 Module 2: Asset Inventory & Two-Tier Host Profile (AssetsPage)")
    add_p("The foundational repository of all enterprise servers and hardware profiles:")
    add_bullet("Paginated Fleet Directory:", "Lists IP addresses, hostnames, OS families, full datetime scan timestamps (Asia/Phnom_Penh), and raw severity pills.")
    add_bullet("Host Edit Modal:", "Assigns Group Ownership (strictly role 'owner') and human Point of Contact (PoC name and email).")
    add_bullet("Asset Detail Page (AssetDetailPage):", "Full host metadata, discovered software packages (`AssetSoftware`), and catalog of all active and fixed detections.")
    add_bullet("Slide-Over Remediation Drawer:", "Displays Qualys KnowledgeBase vendor solutions, workarounds, CVSS vectors, and status transitions (Open, In_Progress, Acknowledged, False_Positive, Resolved).")
    add_screenshot_placeholder(
        "Asset Inventory & Software Profiler",
        "the Asset Inventory table with raw severity pills, and the slide-over Asset Detail drawer showing discovered packages and remediation notes",
        2
    )

    # Module 3
    add_h2("6.3 Module 3: Threat Center & Remediation Triage Queue (AlertsPage)")
    add_p("Dedicated triage workbench consolidating zero-day alerts and proactive inventory matches:")
    add_bullet("Dual-Source Indicator:", "Highlights whether an alert is QUALYS_CONFIRMED or an early-warning INVENTORY_PROACTIVE pre-scan match.")
    add_bullet("Slide-Over Threat Advisory Report:", "CVE technical details, CVSS scores, vulnerable criteria, and list of affected NBC servers with their assigned PoCs.")
    add_bullet("Shell Verification Command:", "One-click copyable bash command for administrators to verify package versions on the target server.")
    add_screenshot_placeholder(
        "Threat Center & Advisory Report Drawer",
        "the Threat Alert Center queue and the slide-over threat advisory report displaying affected server inventory and verification commands",
        3
    )

    # Module 4
    add_h2("6.4 Module 4: MISP Threat Intelligence Explorer (MispPage)")
    add_p("Central repository for threat feeds ingested from FS-ISAC and external CIRCL instances:")
    add_bullet("Central Ingestion Control:", "Houses the primary 'Sync Feed' action to pull advisories on-demand and trigger inventory evaluation.")
    add_bullet("Full Feed Visibility:", "Displays both matched CVEs and clean advisories where NBC infrastructure is unexposed (NO_ASSETS_AFFECTED).")
    add_screenshot_placeholder(
        "MISP Threat Intelligence Feed Explorer",
        "the MISP threat intelligence feed catalog showing CVE listings, FS-ISAC source tags, and the Sync Feed button",
        4
    )

    # Module 5
    add_h2("6.5 Module 5: MITRE ATT&CK Matrix & Compensating Controls Navigator")
    add_p("Translates technical vulnerability alerts into tactical cyber defense heatmaps:")
    add_bullet("Tactical Matrix Navigator:", "Visualizes adversary tactics (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Lateral Movement).")
    add_bullet("Compensating Controls Auditing:", "Audits defensive safeguards (WAF rules, Endpoint Detection & Response, Network Segmentation) to evaluate net residual risk.")
    add_screenshot_placeholder(
        "MITRE ATT&CK Matrix & Compensating Controls",
        "the MITRE ATT&CK tactical heatmap and compensating controls audit panel",
        5
    )

    # Module 6
    add_h2("6.6 Module 6: User Management & Enterprise RBAC (UsersPage)")
    add_p("Manages user identity, account provisioning, and access enforcement:")
    add_bullet("Role Segmentation:", "Strict permission segregation across Administrator (admin), Security Analyst (analyst), Host Owner (owner), and Leadership Viewer (viewer).")
    add_bullet("Owner Scoping:", "Guarantees that server administrators (role 'owner') can only access infrastructure assigned to their user ID.")
    add_screenshot_placeholder(
        "User Management & RBAC Permissions",
        "the User Management table showing active user accounts, role badges, and the Create User modal",
        6
    )

    # Module 7
    add_h2("6.7 Module 7: Immutable Audit Trail & Regulatory Compliance Engine (AuditLogsPage)")
    add_p("Provides an append-only, tamper-evident audit record for external and internal regulators:")
    add_bullet("Comprehensive Event Tracking:", "Captures logins, role modifications, settings changes, asset deletions, sync runs, and status disposition updates.")
    add_bullet("Structured Diff Modal:", "Clicking any log entry opens a JSON inspector displaying exact before-and-after values with actor IP address and UTC timestamp.")
    add_screenshot_placeholder(
        "Immutable Audit Trail & JSON Diff Modal",
        "the Audit Logs table and the JSON Details modal displaying before-and-after parameter modification diffs",
        7
    )

    # Module 8
    add_h2("6.8 Module 8: System Administration & Integration Diagnostic Hub (SettingsPage)")
    add_p("Central configuration center for enterprise connectors:")
    add_bullet("Connector Diagnostics:", "Test buttons for Qualys Cloud API, MISP REST API, MISP ZeroMQ TCP streaming, and Telegram Bot dispatch.")
    add_bullet("API Documentation Security:", "Configures HTTP Basic Authentication credentials for interactive Swagger UI (/docs) and OpenAPI JSON (/openapi.json).")
    add_screenshot_placeholder(
        "Admin Settings & Integration Diagnostic Hub",
        "the Admin Settings page displaying connector cards for Qualys, MISP ZeroMQ, Telegram bot, and Swagger docs auth",
        8
    )

    # --------------------------------------------------------------------------
    # SECTION 7: TECHNICAL SPECIFICATIONS & OWASP
    # --------------------------------------------------------------------------
    add_h1("7. Technical Specifications, Security Hardening & OWASP Compliance")
    add_p("ThreatCenter is engineered in strict compliance with the OWASP Top 10 / 12 Web Application and Software Development Security Standards:")

    tech_tbl = doc.add_table(rows=7, cols=3)
    tech_tbl.autofit = False
    tech_tbl.columns[0].width = Inches(1.8)
    tech_tbl.columns[1].width = Inches(2.3)
    tech_tbl.columns[2].width = Inches(2.4)
    set_table_borders(tech_tbl)

    t_headers = ["Layer / Domain", "Technology Stack", "Security Hardening Control"]
    for i, h in enumerate(t_headers):
        cell = tech_tbl.rows[0].cells[i]
        set_cell_background(cell, HEX_HEADER_BG)
        set_cell_margins(cell, 120, 120, 140, 140)
        p = cell.paragraphs[0]
        r = p.add_run(h)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(10)
        r.font.color.rgb = RGBColor(255, 255, 255)

    t_rows = [
        ("Web Framework", "FastAPI (Python 3.11) ASGI", "Type-safe Pydantic request models, asynchronous non-blocking connection pooling."),
        ("Frontend Application", "React 18, TypeScript, Tailwind, Vite", "Compiled static assets, DOMPurify XSS sanitization, 0 client-side eval vulnerabilities."),
        ("Database Engine", "PostgreSQL 16 Alpine", "ACID compliance, parameterized ORM queries, foreign key cascading integrity."),
        ("Reverse Proxy & SSL", "Nginx Alpine (Dual HTTP/HTTPS)", "DigiCert Wildcard SSL (*.nbc.gov.kh), TLS 1.2/1.3, auto HTTP-to-HTTPS 301 redirection."),
        ("Container Isolation", "Docker Compose Multi-Container Stack", "Unprivileged non-root user (appuser:10001), build compilers excluded from production."),
        ("Authentication & RBAC", "JWT (HMAC-SHA256) + Bcrypt", "Salted password hashing, sliding-window LoginRateLimiter (10 attempts / 60s).")
    ]
    for row_idx, rdata in enumerate(t_rows):
        row = tech_tbl.rows[row_idx + 1]
        for col_idx, text in enumerate(rdata):
            cell = row.cells[col_idx]
            if row_idx % 2 == 1:
                set_cell_background(cell, HEX_ALT_ROW)
            set_cell_margins(cell, 100, 100, 140, 140)
            p = cell.paragraphs[0]
            r = p.add_run(text)
            r.font.name = "Calibri"
            r.font.size = Pt(9.5)
            r.font.color.rgb = COLOR_TEXT

    add_p("")
    add_h2("7.1 Automated Security Verification & VAPT Testing Suite")
    add_p("The ThreatCenter codebase includes an automated 94-test security test suite covering Broken Access Control (RBAC), SQL Injection evasion, Broken Object-Level Authorization (BOLA/IDOR), SSRF mitigation, and Swagger API documentation protection:")
    add_bullet("SQL Injection Protection:", "100% parameterized SQLAlchemy queries tested against malicious payloads (' OR '1'='1, 1; DROP TABLE assets; --). All safely sanitized.")
    add_bullet("SSRF Shielding:", "The `validate_external_url()` filter enforces HTTP/HTTPS and blocks cloud metadata (169.254.169.254, metadata.google.internal) and link-local ranges.")
    add_bullet("Automated Pytest Results:", "94 passed in 30.89s (100% passing rate, 0 failures).")

    # --------------------------------------------------------------------------
    # SECTION 8: IMPLEMENTATION ROADMAP
    # --------------------------------------------------------------------------
    add_h1("8. Phased Implementation Roadmap & Governance Milestones")
    add_p("The rollout of ThreatCenter is structured across four strategic operational phases:")

    add_bullet("Phase 1: Core Architecture & Ingestion Engines (Delivered / Complete):", "Database schema modeling, Qualys delta sync engine, MISP ZeroMQ ingestion pipeline, and RiskEngine severity counter recalculation.")
    add_bullet("Phase 2: Platform Hardening & Commercial TLS Deployment (Delivered / Production-Ready):", "Domain activation (threatcenter-itsec.nbc.gov.kh), DigiCert commercial wildcard SSL installation, OWASP Top 12 compliance audit, and automated CI/CD preservation.")
    add_bullet("Phase 3: Cross-Departmental Rollout & Asset Owner Onboarding (Immediate — Next 30 Days):", "Conduct training sessions for server administrators (role 'owner'), establish automated Telegram alerting escalation policies, and enforce remediation SLAs.")
    add_bullet("Phase 4: Predictive Cyber Defense & ITSM Automation (Q1–Q2 2027):", "Incorporate Exploit Prediction Scoring System (EPSS) machine-learning weights and automate bi-directional incident ticket synchronization with the NBC IT Service Desk.")

    # --------------------------------------------------------------------------
    # SECTION 9: HOSTING & RESOURCE REQUIREMENTS
    # --------------------------------------------------------------------------
    add_h1("9. Infrastructure Sizing & Operational Requirements")
    add_p("ThreatCenter operates efficiently on standard virtualized infrastructure within the NBC on-premises datacenter:")

    add_bullet("Target Virtual Machine:", "1 dedicated VM running Ubuntu 22.04 LTS or RHEL 9 (64-bit).")
    add_bullet("Compute Sizing:", "4 vCPUs, 8 GB RAM, 80 GB SSD enterprise storage.")
    add_bullet("Network Accessibility:", "Inbound HTTPS port 443 (threatcenter-itsec.nbc.gov.kh), internal TCP port 50000 to MISP ZeroMQ (10.20.40.19), outbound HTTPS to Qualys API (qualysapi.qg2.apps.qualys.com).")
    add_bullet("Software Licensing:", "100% open-source software stack (Python FastAPI, React, PostgreSQL, Nginx) with $0 recurring software license overhead.")

    # --------------------------------------------------------------------------
    # SECTION 10: APPROVAL & SIGN-OFF
    # --------------------------------------------------------------------------
    add_h1("10. Steering Committee Approval & Recommendation Sign-Off")
    add_p("The ThreatCenter platform bridges critical visibility gaps, transforms reactive scanning into proactive defense, and provides NBC leadership with an audit-ready cybersecurity command center.")

    add_p("RECOMMENDATION: Formalize the adoption of ThreatCenter as the primary threat intelligence correlation and vulnerability triage platform across all NBC departments, and proceed with the Phase 3 cross-departmental owner onboarding.")

    add_p("")
    sign_tbl = doc.add_table(rows=3, cols=2)
    sign_tbl.autofit = False
    sign_tbl.columns[0].width = Inches(3.25)
    sign_tbl.columns[1].width = Inches(3.25)
    set_table_borders(sign_tbl)

    s_headers = ["Submitted By: ThreatCenter Project Team", "Approved By: Cybersecurity Steering Committee"]
    for i, h in enumerate(s_headers):
        cell = sign_tbl.rows[0].cells[i]
        set_cell_background(cell, HEX_HEADER_BG)
        set_cell_margins(cell, 120, 120, 140, 140)
        p = cell.paragraphs[0]
        r = p.add_run(h)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(10)
        r.font.color.rgb = RGBColor(255, 255, 255)

    sign_data = [
        ("Signature: ___________________________\n\nName: IT Security Project Lead\nDate: ____ / ____ / 2026",
         "Signature: ___________________________\n\nName: Chief Information Security Officer (CISO)\nDate: ____ / ____ / 2026"),
        ("Title: Lead Security Systems Engineer\nDepartment: IT Security Department",
         "Title: Head of IT Security / Executive Director\nOrganization: National Bank of Cambodia")
    ]
    for row_idx, rdata in enumerate(sign_data):
        row = sign_tbl.rows[row_idx + 1]
        for col_idx, text in enumerate(rdata):
            cell = row.cells[col_idx]
            set_cell_margins(cell, 120, 120, 140, 140)
            p = cell.paragraphs[0]
            r = p.add_run(text)
            r.font.name = "Calibri"
            r.font.size = Pt(9.5)
            r.font.color.rgb = COLOR_TEXT

    # Save Output Document
    output_dir = "docs"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "ThreatCenter_System_Design_and_Proposal.docx")
    doc.save(output_path)
    print(f"✅ ThreatCenter Proposal Document successfully generated at: {output_path}")

if __name__ == "__main__":
    create_proposal_document()
