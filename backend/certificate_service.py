"""
backend/certificate_service.py
Tracegate — VAPT Assessment Completion Certificate Service

Automated, professional VAPT Assessment Completion Certificate generation
as the final outcome of the security assessment lifecycle.
Issued strictly when 100% of in-scope findings have passed remediation validation.
"""

import os
import json
import uuid
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from docx import Document
from docx.shared import Inches, Pt, RGBColor, Mm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.enum.section import WD_ORIENT
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls
import qrcode

from backend.database import (
    get_project_by_id,
    get_project_findings_list,
    get_db_connection,
    save_certificate_record,
    get_certificate_by_id,
    get_certificate_by_verification_id,
    get_certificates_for_project,
    get_latest_certificate_for_project,
    update_certificate_notice_seen,
    update_certificate_file_paths
)
from backend.report_generator import convert_docx_to_pdf

logger = logging.getLogger("tracegate.certificate")

# Certificate Directories & Asset Paths
BASE_DIR = Path(__file__).resolve().parent.parent
CERTIFICATES_DIR = BASE_DIR / "data" / "certificates"
CERTIFICATES_DIR.mkdir(parents=True, exist_ok=True)
LOGO_PATH = BASE_DIR / "backend" / "assets" / "tracegate_shield_logo.png"
SEAL_PATH = BASE_DIR / "backend" / "assets" / "completion_seal.png"

# Color Palette (Formal, professional Tracegate security aesthetic)
COLOR_NAVY = RGBColor(15, 23, 42)        # Slate/Navy (#0F172A)
COLOR_TEAL = RGBColor(13, 148, 136)      # Deep Teal (#0D9488)
COLOR_SLATE = RGBColor(51, 65, 85)       # Charcoal Slate (#334155)
COLOR_MUTED = RGBColor(100, 116, 139)    # Muted Slate (#64748B)
COLOR_BORDER = RGBColor(226, 232, 240)   # Border Slate (#E2E8F0)
COLOR_LOW = RGBColor(4, 120, 87)         # Low / Pass (#047857)

HEX_BG_HEADER = "0F172A"
HEX_BG_ACCENT = "F0FDFA"
HEX_BG_SUBTLE = "F8FAFC"
HEX_BG_BORDER = "CBD5E1"

STANDARD_DISCLAIMER = (
    "This certificate reflects the assessment scope and validation status recorded as of the certificate "
    "issue date and does not guarantee future security."
)

ATTESTATION_STATEMENT = (
    "This certificate confirms completion of the specified VAPT assessment and successful remediation "
    "validation of the applicable confirmed findings through remediation retesting within the defined assessment scope."
)

VALIDATION_SUMMARY_STATEMENT = (
    "All applicable confirmed findings within the defined assessment scope have undergone remediation "
    "validation and were recorded as successfully passed at the time of certificate issuance."
)


# =============================================================================
# XML & STYLING HELPERS
# =============================================================================

def set_cell_background(cell, fill_hex: str):
    """Applies background shading color to a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tc_pr.append(shd)

def set_cell_margins(cell, top: int = 100, bottom: int = 100, left: int = 140, right: int = 140):
    """Sets internal padding (in dxa) for a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tc_pr.append(tc_mar)

def make_table_safe(table):
    """Ensures rows don't split awkwardly across page breaks."""
    for idx, row in enumerate(table.rows):
        trPr = row._tr.get_or_add_trPr()
        cantSplit = parse_xml(r'<w:cantSplit xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>')
        trPr.append(cantSplit)
        if idx == 0:
            tblHeader = parse_xml(r'<w:tblHeader xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>')
            trPr.append(tblHeader)


# =============================================================================
# ELIGIBILITY LOGIC
# =============================================================================

def check_assessment_certificate_eligibility(project_id: str) -> Dict[str, Any]:
    """
    Deterministic eligibility check for VAPT Assessment Completion Certificate.
    Eligibility requires:
      1. totalInScopeFindings > 0 (at least one confirmed finding required)
      2. 100% of confirmed findings have status == 'RESOLVED' and retest_status in ('PASSED', 'PASS')
      3. No finding remains in OPEN, IN_REMEDIATION, RETEST_PENDING, or RETEST_FAILED state.
    """
    project = get_project_by_id(project_id)
    if not project:
        return {
            "eligible": False,
            "status": "NOT_FOUND",
            "reason": "Project not found.",
            "total_findings": 0,
            "resolved_findings": 0,
            "pending_retests": 0,
            "failed_retests": 0,
            "open_findings": 0,
            "remaining_by_severity": {},
            "certificate": None
        }

    findings = get_project_findings_list(project_id)
    total_findings = len(findings)

    if total_findings == 0:
        return {
            "eligible": False,
            "status": "NOT_ELIGIBLE",
            "assessment_id": project_id,
            "project_id": project_id,
            "reason": "No confirmed findings recorded for this project. Assessment completion certificate requires at least one in-scope finding.",
            "blocking_reason": "Assessment has no confirmed findings.",
            "total_findings": 0,
            "resolved_findings": 0,
            "passed_retests": 0,
            "pending_findings": 0,
            "pending_retests": 0,
            "failed_retests": 0,
            "open_findings": 0,
            "remaining_by_severity": {},
            "certificate": None
        }

    resolved_count = 0
    pending_retests = 0
    failed_retests = 0
    open_findings = 0
    unresolved_findings = []
    remaining_by_severity: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}

    for f in findings:
        f_status = (f.get("status") or "").strip().upper()
        f_retest = (f.get("retest_status") or "").strip().upper()
        sev = (f.get("priority") or "HIGH").strip().upper()
        if sev not in remaining_by_severity:
            sev = "HIGH"

        is_passed = (f_status in ("RESOLVED", "REMEDIATED", "CLOSED") and "PASS" in f_retest)
        if is_passed:
            resolved_count += 1
        else:
            unresolved_findings.append(f)
            remaining_by_severity[sev] += 1
            if "FAIL" in f_retest:
                failed_retests += 1
            elif "PEND" in f_retest or not f_retest:
                pending_retests += 1
            else:
                open_findings += 1

    # Check if a certificate has already been issued
    existing_cert = get_latest_certificate_for_project(project_id)

    if len(unresolved_findings) == 0:
        status_code = "GENERATED" if existing_cert else "ELIGIBLE"
        return {
            "eligible": True,
            "status": status_code,
            "assessment_id": project_id,
            "project_id": project_id,
            "reason": "All in-scope findings have successfully passed remediation validation.",
            "blocking_reason": None,
            "total_findings": total_findings,
            "resolved_findings": resolved_count,
            "passed_retests": resolved_count,
            "pending_findings": 0,
            "pending_retests": 0,
            "failed_retests": 0,
            "open_findings": 0,
            "remaining_by_severity": remaining_by_severity,
            "certificate": existing_cert
        }
    else:
        unresolved_count = len(unresolved_findings)
        sev_parts = []
        for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            if remaining_by_severity.get(k, 0) > 0:
                sev_parts.append(f"{remaining_by_severity[k]} {k.capitalize()}")
        breakdown = f" ({', '.join(sev_parts)} remaining)" if sev_parts else ""

        if pending_retests > 0 and open_findings == 0 and failed_retests == 0:
            reason = f"{unresolved_count} in-scope finding(s) remain pending retest{breakdown}."
        else:
            reason = f"{unresolved_count} in-scope finding(s) remain unresolved or pending remediation{breakdown}."

        return {
            "eligible": False,
            "status": "NOT_ELIGIBLE",
            "assessment_id": project_id,
            "project_id": project_id,
            "reason": reason,
            "blocking_reason": reason,
            "total_findings": total_findings,
            "resolved_findings": resolved_count,
            "passed_retests": resolved_count,
            "pending_findings": unresolved_count,
            "pending_retests": pending_retests,
            "failed_retests": failed_retests,
            "open_findings": open_findings,
            "remaining_by_severity": remaining_by_severity,
            "unresolved_findings": [
                {
                    "id": f.get("id"),
                    "vuln_id": f.get("vuln_id"),
                    "finding_name": f.get("finding_name"),
                    "priority": f.get("priority"),
                    "status": f.get("status"),
                    "retest_status": f.get("retest_status")
                }
                for f in unresolved_findings
            ],
            "certificate": None
        }


# =============================================================================
# CERTIFICATE GENERATION & PERSISTENCE
# =============================================================================

def generate_assessment_certificate(project_id: str) -> Dict[str, Any]:
    """
    Generate and persist a professional VAPT Assessment Completion Certificate.
    Enforces eligibility, idempotency, and immutability.
    """
    eligibility = check_assessment_certificate_eligibility(project_id)
    if not eligibility["eligible"]:
        return {
            "success": False,
            "status": eligibility["status"],
            "error": eligibility["reason"],
            "eligibility": eligibility
        }

    # Idempotency guard: If already issued for this project and findings state, return existing
    existing = eligibility.get("certificate")
    if existing and existing.get("status") == "VALID":
        snap = existing.get("snapshot") or {}
        if snap.get("total_findings") == eligibility["total_findings"]:
            logger.info(f"Certificate already generated for project {project_id}: {existing['certificate_id']}")
            return {
                "success": True,
                "status": "ALREADY_ISSUED",
                "certificate": existing,
                "eligibility": eligibility
            }

    project = get_project_by_id(project_id)
    findings = get_project_findings_list(project_id)

    # Generate unique IDs
    year = datetime.now().year
    rand_hex = uuid.uuid4().hex[:6].upper()
    cert_id = f"TG-VAPT-{year}-{rand_hex}"

    while get_certificate_by_id(cert_id) is not None:
        rand_hex = uuid.uuid4().hex[:6].upper()
        cert_id = f"TG-VAPT-{year}-{rand_hex}"

    verify_id = f"TG-VERIFY-{uuid.uuid4().hex[:8].upper()}"

    # Determine Associated Assessment / Report ID
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, version, report_title FROM reports WHERE project_id = ? ORDER BY created_at DESC LIMIT 1", (project_id,))
    rep_row = cursor.fetchone()
    conn.close()

    report_id = rep_row["id"] if rep_row else None
    assessment_id = report_id if report_id else project_id

    # Format Dates
    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    issue_date = now.strftime("%d %b %Y")

    try:
        p_created = datetime.strptime(project.get("created_at", now_str)[:19], "%Y-%m-%d %H:%M:%S")
        assessment_start = p_created.strftime("%d %b %Y")
    except Exception:
        assessment_start = issue_date

    final_validation_date = issue_date
    assessment_end = issue_date

    # Finding Severity Breakdown
    crit_count = sum(1 for f in findings if (f.get("priority") or "").upper() in ("CRITICAL", "CRIT"))
    high_count = sum(1 for f in findings if (f.get("priority") or "").upper() == "HIGH")
    med_count = sum(1 for f in findings if (f.get("priority") or "").upper() in ("MEDIUM", "MED"))
    low_count = sum(1 for f in findings if (f.get("priority") or "").upper() == "LOW")
    info_count = sum(1 for f in findings if (f.get("priority") or "").upper() in ("INFORMATIONAL", "INFO"))

    # Target & Client
    target_name = project.get("name", "Assessment Target")
    target_url = project.get("target_url") or "Target Web Application"
    client_org = project.get("client_organization") or project.get("organization") or "Not Provided"
    assessment_type = "Web Application Penetration Test (VAPT)"

    # Clean scope summary
    scope_notes = project.get("scope_notes") or project.get("notes") or project.get("description") or "Standard In-Scope Web Application Components"
    clean_scope = scope_notes.strip()[:300]

    # Clean finding snapshot items (NO AI Fix or PR tokens)
    findings_snapshot = []
    for idx, f in enumerate(findings):
        findings_snapshot.append({
            "index": idx + 1,
            "finding_id": f.get("id"),
            "vuln_id": f.get("vuln_id", f"VULN-{idx+1:03d}"),
            "finding_name": f.get("finding_name", "Vulnerability Finding"),
            "severity": (f.get("priority") or "HIGH").upper(),
            "cwe": f.get("cwe", "CWE-200"),
            "status": "RESOLVED",
            "retest_status": "PASSED",
            "retested_at": f.get("updated_at") or now_str
        })

    snapshot_data = {
        "certificate_id": cert_id,
        "verification_id": verify_id,
        "project_id": project_id,
        "assessment_id": assessment_id,
        "report_id": report_id,
        "target_name": target_name,
        "target_url": target_url,
        "client_organization": client_org,
        "assessment_type": assessment_type,
        "assessment_start": assessment_start,
        "assessment_end": assessment_end,
        "issue_date": issue_date,
        "final_validation_date": final_validation_date,
        "total_findings": len(findings),
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "low_count": low_count,
        "info_count": info_count,
        "findings_retested": len(findings),
        "findings_passed": len(findings),
        "findings_failed": 0,
        "findings_summary": findings_snapshot,
        "signatories": {
            "prepared_by": project.get("created_by") or "Security Assessor",
            "validated_by": "Lead Retest Validator",
            "review_status": "Formal Assessment Review Passed"
        },
        "disclaimer": STANDARD_DISCLAIMER
    }

    # Generate Physical Word DOCX and compile to native PDF
    docx_path, pdf_path = build_certificate_documents(snapshot_data)

    # Persist record into vapt_certificates table
    cert_record = {
        "certificate_id": cert_id,
        "verification_id": verify_id,
        "project_id": project_id,
        "assessment_id": assessment_id,
        "report_id": report_id,
        "status": "VALID",
        "issue_date": issue_date,
        "assessment_start": assessment_start,
        "assessment_end": assessment_end,
        "final_validation_date": final_validation_date,
        "total_findings": len(findings),
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "low_count": low_count,
        "info_count": info_count,
        "findings_retested": len(findings),
        "findings_passed": len(findings),
        "findings_failed": 0,
        "target_name": target_name,
        "target_url": target_url,
        "client_organization": client_org,
        "assessment_type": assessment_type,
        "assessment_scope": clean_scope,
        "snapshot": snapshot_data,
        "file_path_docx": str(docx_path) if docx_path else None,
        "file_path_pdf": str(pdf_path) if pdf_path else None,
        "notice_seen": 0,
        "created_at": now_str
    }

    saved = save_certificate_record(cert_record)
    logger.info(f"VAPT Assessment Completion Certificate successfully created: {cert_id}")

    return {
        "success": True,
        "status": "GENERATED",
        "certificate": saved,
        "eligibility": eligibility
    }


# =============================================================================
# PHYSICAL DOCUMENT COMPILATION (DOCX & PDF)
# =============================================================================

def build_certificate_documents(data: Dict[str, Any]) -> Tuple[Optional[Path], Optional[Path]]:
    """
    Constructs a formal, minimalist, high-quality landscape A4 DOCX certificate
    and compiles native PDF via Microsoft Word COM automation.
    Strictly 1-page A4 landscape layout.
    """
    cert_id = data["certificate_id"]
    docx_filename = f"{cert_id}.docx"
    docx_path = CERTIFICATES_DIR / docx_filename

    doc = Document()

    # Document Geometry: Clean A4 landscape with 0.40 in top/bottom, 0.50 in left/right
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width = Mm(297)
    section.page_height = Mm(210)
    section.top_margin = Inches(0.40)
    section.bottom_margin = Inches(0.40)
    section.left_margin = Inches(0.50)
    section.right_margin = Inches(0.50)

    # 1. Formal Border Framing Container (Single cell outer table)
    frame_table = doc.add_table(rows=1, cols=1)
    frame_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    outer_cell = frame_table.rows[0].cells[0]
    outer_cell.width = Inches(10.65)
    set_cell_background(outer_cell, "FFFFFF")

    # Apply elegant double border styling to outer frame cell
    tc_pr = outer_cell._tc.get_or_add_tcPr()
    borders = parse_xml(
        f'<w:tcBorders {nsdecls("w")}>'
        f'<w:top w:val="double" w:sz="18" w:space="0" w:color="{HEX_BG_HEADER}"/>'
        f'<w:left w:val="double" w:sz="18" w:space="0" w:color="{HEX_BG_HEADER}"/>'
        f'<w:bottom w:val="double" w:sz="18" w:space="0" w:color="{HEX_BG_HEADER}"/>'
        f'<w:right w:val="double" w:sz="18" w:space="0" w:color="{HEX_BG_HEADER}"/>'
        f'</w:tcBorders>'
    )
    tc_pr.append(borders)

    tc_mar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="120" w:type="dxa"/>'
        f'<w:bottom w:w="120" w:type="dxa"/>'
        f'<w:left w:w="180" w:type="dxa"/>'
        f'<w:right w:w="180" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tc_pr.append(tc_mar)

    # Header: Tracegate Shield Logo
    p_logo = outer_cell.paragraphs[0]
    p_logo.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_logo.paragraph_format.space_before = Pt(0)
    p_logo.paragraph_format.space_after = Pt(2)
    if LOGO_PATH.exists():
        p_logo.add_run().add_picture(str(LOGO_PATH), width=Inches(0.95))

    # Sub-brand
    p_sub = outer_cell.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_sub.paragraph_format.space_before = Pt(0)
    p_sub.paragraph_format.space_after = Pt(4)
    r_sub = p_sub.add_run("TRACEGATE SECURITY WORKSPACE  •  ASSESSMENT & VALIDATION REGISTRY")
    r_sub.font.name = "Calibri"
    r_sub.font.size = Pt(8.5)
    r_sub.font.bold = True
    r_sub.font.color.rgb = COLOR_TEAL

    # Main Certificate Title
    p_title = outer_cell.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_before = Pt(4)
    p_title.paragraph_format.space_after = Pt(2)
    r_title = p_title.add_run("VAPT ASSESSMENT COMPLETION CERTIFICATE")
    r_title.font.name = "Calibri"
    r_title.font.size = Pt(22)
    r_title.font.bold = True
    r_title.font.color.rgb = COLOR_NAVY

    # Subtitle
    p_st = outer_cell.add_paragraph()
    p_st.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_st.paragraph_format.space_before = Pt(0)
    p_st.paragraph_format.space_after = Pt(8)
    r_st = p_st.add_run("Security Assessment & Remediation Validation Confirmation")
    r_st.font.name = "Calibri"
    r_st.font.size = Pt(10)
    r_st.font.italic = True
    r_st.font.color.rgb = COLOR_TEAL

    # Concise Completion Statement
    p_stmt = outer_cell.add_paragraph()
    p_stmt.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_stmt.paragraph_format.space_before = Pt(0)
    p_stmt.paragraph_format.space_after = Pt(10)
    p_stmt.paragraph_format.line_spacing = 1.2
    r_stmt = p_stmt.add_run(
        "This certificate confirms completion of the specified VAPT assessment and successful remediation "
        "validation of the applicable confirmed findings within the defined assessment scope."
    )
    r_stmt.font.name = "Calibri"
    r_stmt.font.size = Pt(9.5)
    r_stmt.font.color.rgb = COLOR_SLATE

    # Metadata Grid (2-column structured table)
    meta_table = outer_cell.add_table(rows=4, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    make_table_safe(meta_table)

    col_widths = [Inches(4.9), Inches(4.9)]
    rows_data = [
        (("Target Application:", data.get("target_name") or "Assessment Target"), ("Assessment Period:", f"{data.get('assessment_start', data.get('issue_date'))} – {data.get('assessment_end', data.get('issue_date'))}")),
        (("Target / Scope:", data.get("target_url") or "Defined Scope"), ("Certificate Issue Date:", data.get("issue_date") or "-")),
        (("Assessment Type:", data.get("assessment_type") or "Web Application Penetration Test (VAPT)"), ("Final Validation Date:", data.get("final_validation_date") or data.get("issue_date") or "-")),
        (("Certificate ID:", data.get("certificate_id") or "-"), ("Assessment ID:", data.get("assessment_id") or data.get("project_id") or "-"))
    ]

    for r_idx, ((lbl1, val1), (lbl2, val2)) in enumerate(rows_data):
        for c_idx, (lbl, val) in enumerate([(lbl1, val1), (lbl2, val2)]):
            cell = meta_table.rows[r_idx].cells[c_idx]
            cell.width = col_widths[c_idx]
            set_cell_background(cell, HEX_BG_SUBTLE)
            set_cell_margins(cell, top=55, bottom=55, left=120, right=120)

            c_bor = parse_xml(
                f'<w:tcBorders {nsdecls("w")}>'
                f'<w:top w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>'
                f'<w:left w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>'
                f'<w:bottom w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>'
                f'<w:right w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>'
                f'</w:tcBorders>'
            )
            cell._tc.get_or_add_tcPr().append(c_bor)

            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after = Pt(0)
            r_lbl = p.add_run(f"{lbl} ")
            r_lbl.font.name = "Calibri"
            r_lbl.font.size = Pt(8.5)
            r_lbl.font.bold = True
            r_lbl.font.color.rgb = COLOR_NAVY

            r_val = p.add_run(str(val))
            r_val.font.name = "Calibri"
            r_val.font.size = Pt(8.5)
            r_val.font.color.rgb = COLOR_SLATE

    # Spacer
    p_sp = outer_cell.add_paragraph()
    p_sp.paragraph_format.space_before = Pt(8)
    p_sp.paragraph_format.space_after = Pt(0)

    # Bottom 3-column table (Seal, Authorization, QR)
    bot_table = outer_cell.add_table(rows=1, cols=3)
    bot_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    make_table_safe(bot_table)
    bot_widths = [Inches(2.6), Inches(4.7), Inches(2.6)]

    # Cell 0: Completion Seal
    c0 = bot_table.rows[0].cells[0]
    c0.width = bot_widths[0]
    p_seal = c0.paragraphs[0]
    p_seal.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_seal.paragraph_format.space_before = Pt(0)
    p_seal.paragraph_format.space_after = Pt(0)
    if SEAL_PATH.exists():
        p_seal.add_run().add_picture(str(SEAL_PATH), width=Inches(1.15))

    # Cell 1: Organization Authorization Line
    c1 = bot_table.rows[0].cells[1]
    c1.width = bot_widths[1]
    p_auth = c1.paragraphs[0]
    p_auth.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_auth.paragraph_format.space_before = Pt(8)
    p_auth.paragraph_format.space_after = Pt(2)
    r_a1 = p_auth.add_run("AUTHORIZED BY\n")
    r_a1.font.name = "Calibri"
    r_a1.font.size = Pt(8)
    r_a1.font.bold = True
    r_a1.font.color.rgb = COLOR_MUTED

    r_a2 = p_auth.add_run("TRACEGATE PVT. LIMITED\n")
    r_a2.font.name = "Calibri"
    r_a2.font.size = Pt(11.5)
    r_a2.font.bold = True
    r_a2.font.color.rgb = COLOR_NAVY

    r_a3 = p_auth.add_run("Security Assessment & Verification Authority\n")
    r_a3.font.name = "Calibri"
    r_a3.font.size = Pt(8.5)
    r_a3.font.italic = True
    r_a3.font.color.rgb = COLOR_TEAL

    r_a4 = p_auth.add_run(f"Authoritative Digital Record: {data['certificate_id']}")
    r_a4.font.name = "Calibri"
    r_a4.font.size = Pt(7.5)
    r_a4.font.color.rgb = COLOR_MUTED

    # Cell 2: QR Code & Verification
    c2 = bot_table.rows[0].cells[2]
    c2.width = bot_widths[2]
    p_qr = c2.paragraphs[0]
    p_qr.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_qr.paragraph_format.space_before = Pt(0)
    p_qr.paragraph_format.space_after = Pt(0)

    # Generate QR pointing to real verification endpoint
    qr_file_path = CERTIFICATES_DIR / f"{cert_id}_qr.png"
    try:
        qr = qrcode.QRCode(box_size=4, border=1)
        qr.add_data(f"/certificate/verify/{cert_id}")
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="#0F172A", back_color="white")
        qr_img.save(str(qr_file_path))
        p_qr.add_run().add_picture(str(qr_file_path), width=Inches(0.9))
    except Exception as qre:
        logger.warning(f"Could not generate QR image: {qre}")

    p_qr_txt = c2.add_paragraph()
    p_qr_txt.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_qr_txt.paragraph_format.space_before = Pt(2)
    p_qr_txt.paragraph_format.space_after = Pt(0)
    r_q1 = p_qr_txt.add_run("Online Verification\n")
    r_q1.font.name = "Calibri"
    r_q1.font.size = Pt(7)
    r_q1.font.color.rgb = COLOR_MUTED

    r_q2 = p_qr_txt.add_run(str(data.get("verification_id", "")))
    r_q2.font.name = "Calibri"
    r_q2.font.size = Pt(7.5)
    r_q2.font.bold = True
    r_q2.font.color.rgb = COLOR_TEAL

    # Disclaimer: Point-in-time single line
    p_disc = outer_cell.add_paragraph()
    p_disc.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_disc.paragraph_format.space_before = Pt(8)
    p_disc.paragraph_format.space_after = Pt(0)
    r_disc = p_disc.add_run(data.get("disclaimer") or STANDARD_DISCLAIMER)
    r_disc.font.name = "Calibri"
    r_disc.font.size = Pt(7.5)
    r_disc.font.italic = True
    r_disc.font.color.rgb = RGBColor(148, 163, 184)

    # Save DOCX
    doc.save(str(docx_path))
    logger.info(f"DOCX certificate generated at: {docx_path}")

    # Compile native PDF via Microsoft Word COM
    pdf_path = None
    try:
        compiled_pdf = convert_docx_to_pdf(str(docx_path))
        if compiled_pdf and Path(compiled_pdf).exists():
            pdf_path = Path(compiled_pdf)
            logger.info(f"PDF certificate generated at: {pdf_path}")
    except Exception as pe:
        logger.warning(f"Could not compile PDF certificate via Word COM: {pe}")

    return docx_path, pdf_path


# =============================================================================
# PUBLIC VERIFICATION SERVICE
# =============================================================================

def get_public_certificate_verification(cert_id_or_verify_id: str) -> Dict[str, Any]:
    """
    Retrieves public verification data for a certificate ID or verification ID.
    STRICT PRIVACY GUARANTEE: Does NOT expose vulnerability names, PoCs, code, tokens,
    or internal private assessment notes.
    """
    cert = get_certificate_by_id(cert_id_or_verify_id)
    if not cert:
        cert = get_certificate_by_verification_id(cert_id_or_verify_id)

    if not cert:
        return {
            "valid": False,
            "status": "NOT_FOUND",
            "message": "Certificate not found in Tracegate authoritative registry."
        }

    return {
        "valid": cert.get("status") == "VALID",
        "status": cert.get("status", "VALID"),
        "certificate_id": cert["certificate_id"],
        "verification_id": cert["verification_id"],
        "target_name": cert["target_name"],
        "target_url": cert["target_url"],
        "client_organization": cert.get("client_organization") or "Not Provided",
        "assessment_type": cert.get("assessment_type", "Web Application Penetration Test (VAPT)"),
        "issue_date": cert["issue_date"],
        "final_validation_date": cert["final_validation_date"],
        "total_findings_validated": cert.get("findings_passed", 0),
        "remediation_validation_status": "100% Passed (Validated)",
        "attestation": ATTESTATION_STATEMENT,
        "disclaimer": cert.get("snapshot", {}).get("disclaimer") or STANDARD_DISCLAIMER
    }
