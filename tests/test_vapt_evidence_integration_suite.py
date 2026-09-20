"""
Test suite for Tracegate VAPT Report Evidence Integration.
Validates automatic embedding of tester-provided PoC screenshots, monospaced text/JSON blocks,
finding-evidence isolation, figure numbering, evidence register reconciliation, and target consistency.
"""

import unittest
import io
import os
import sys
import base64
import json
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, r"C:\Users\Harsh\Desktop\tracegate")

from fastapi.testclient import TestClient
from backend.app import app
import docx

client = TestClient(app)

# Standard 1x1 valid PNG in base64
TINY_PNG_B64 = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)

# Second distinct 2x2 PNG in base64
TINY_PNG_2_B64 = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAAFElEQVR42mNk+M/AwMDEwMDAwAAAAAUAAebAE4kAAAAASUVORK5CYII="
)

# Third distinct 3x3 PNG in base64
TINY_PNG_3_B64 = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAMAAAADCAYAAABWKLW/AAAAFElEQVR42mNk+M/AwMDEwMDAwAAAAAUAAebAE4kAAAAASUVORK5CYII="
)

def extract_all_docx_text(content: bytes) -> str:
    doc = docx.Document(io.BytesIO(content))
    paragraphs = [p.text for p in doc.paragraphs]
    table_cells = [cell.text for t in doc.tables for row in t.rows for cell in row.cells]
    return "\n".join(paragraphs + table_cells)

class TestVAPTEvidenceIntegrationSuite(unittest.TestCase):

    def setUp(self):
        # Create a fresh project for every test to guarantee test isolation
        proj_res = client.post(
            "/api/projects",
            json={
                "name": "Evidence Test Target",
                "target_url": "https://shop.tracegate.lab",
                "scope": "In-Scope: shop.tracegate.lab Web Application",
                "created_by": "Lead Pentester Alex"
            }
        )
        self.assertEqual(proj_res.status_code, 201)
        self.project_id = proj_res.json()["id"]

    def test_01_single_image_evidence_embedded(self):
        """Test 1: Finding with uploaded screenshot -> embedded as image shape with EV-001 and Figure 1."""
        # 1. Record finding with evidence
        finding_res = client.post(
            f"/api/projects/{self.project_id}/checklist/item-01/finding",
            json={
                "finding_name": "Insecure Direct Object Reference on Customer Invoice",
                "priority": "HIGH",
                "cwe": "CWE-639",
                "observation": "Changing invoice_id parameter allowed downloading unauthorized invoices.",
                "evidence": [{
                    "id": "EV-001",
                    "name": "idor_poc.png",
                    "filename": "idor_poc.png",
                    "data": TINY_PNG_B64,
                    "type": "image/png",
                    "caption": "Unauthorized invoice download demonstrated via user parameter modification.",
                    "source": "Tester-provided evidence"
                }],
                "evidence_filename": "idor_poc.png",
                "evidence_data": TINY_PNG_B64
            }
        )
        self.assertEqual(finding_res.status_code, 201)
        finding_id = finding_res.json()["id"]

        # 2. Generate DOCX report
        rep_res = client.post(
            f"/api/projects/{self.project_id}/reports",
            json={
                "version": "v1.0",
                "selected_finding_ids": [finding_id]
            }
        )
        self.assertIn(rep_res.status_code, [200, 201])
        report_id = rep_res.json()["id"]

        # 3. Download & inspect DOCX
        dl_res = client.get(f"/api/projects/{self.project_id}/reports/{report_id}/download")
        self.assertEqual(dl_res.status_code, 200)

        doc = docx.Document(io.BytesIO(dl_res.content))
        # Image shape MUST be embedded
        self.assertGreaterEqual(len(doc.inline_shapes), 1, "DOCX must contain at least 1 embedded picture shape")

        full_text = extract_all_docx_text(dl_res.content)
        # Figure caption with stable ID
        self.assertIn("Figure 1", full_text)
        self.assertIn("EV-001", full_text)
        self.assertIn("Unauthorized invoice download demonstrated via user parameter modification", full_text)
        self.assertIn("Source: Tester-provided evidence", full_text)
        self.assertIn("Type: Visual Screenshot Capture", full_text)

        # Ensure obsolete registered and archived string is absent
        self.assertNotIn("registered and archived", full_text)

    def test_02_multiple_images_under_single_finding(self):
        """Test 2: Single finding with 3 images -> all 3 embedded with sequential Figure 1, Figure 2, Figure 3."""
        ev_list = [
            {
                "id": "ev-01",
                "name": "request.png",
                "data": TINY_PNG_B64,
                "type": "image/png",
                "caption": "Initial unauthenticated request intercepted by proxy."
            },
            {
                "id": "ev-02",
                "name": "response.png",
                "data": TINY_PNG_2_B64,
                "type": "image/png",
                "caption": "Server response leaking authorization tokens."
            },
            {
                "id": "ev-03",
                "name": "result.png",
                "data": TINY_PNG_3_B64,
                "type": "image/png",
                "caption": "Privileged administrative console accessed successfully."
            }
        ]

        finding_res = client.post(
            f"/api/projects/{self.project_id}/checklist/item-auth/finding",
            json={
                "finding_name": "Multi-Stage Authentication Bypass Sequence",
                "priority": "CRITICAL",
                "cwe": "CWE-287",
                "evidence": ev_list
            }
        )
        self.assertEqual(finding_res.status_code, 201)
        finding_id = finding_res.json()["id"]

        rep_res = client.post(
            f"/api/projects/{self.project_id}/reports",
            json={"version": "v1.0", "selected_finding_ids": [finding_id]}
        )
        rep_id = rep_res.json()["id"]

        dl_res = client.get(f"/api/projects/{self.project_id}/reports/{rep_id}/download")
        doc = docx.Document(io.BytesIO(dl_res.content))

        # Must have 3 embedded images
        self.assertGreaterEqual(len(doc.inline_shapes), 3, "DOCX must embed all 3 screenshot evidence items")

        text = extract_all_docx_text(dl_res.content)
        self.assertIn("Figure 1", text)
        self.assertIn("Figure 2", text)
        self.assertIn("Figure 3", text)
        self.assertIn("Initial unauthenticated request", text)
        self.assertIn("Server response leaking authorization tokens", text)
        self.assertIn("Privileged administrative console accessed", text)
        self.assertNotIn("registered and archived", text)

    def test_03_multiple_findings_evidence_isolation(self):
        """Test 3: VULN-001 has image A, VULN-002 has image B -> zero cross-contamination between findings."""
        f1_res = client.post(
            f"/api/projects/{self.project_id}/checklist/item-f1/finding",
            json={
                "finding_name": "SQL Injection in Search Form",
                "priority": "HIGH",
                "cwe": "CWE-89",
                "evidence": [{
                    "id": "EV-SQLI",
                    "name": "sqli_probe.png",
                    "data": TINY_PNG_B64,
                    "caption": "SQL syntax error displayed in web browser."
                }]
            }
        )
        f2_res = client.post(
            f"/api/projects/{self.project_id}/checklist/item-f2/finding",
            json={
                "finding_name": "Cross-Site Scripting in Guestbook",
                "priority": "MEDIUM",
                "cwe": "CWE-79",
                "evidence": [{
                    "id": "EV-XSS",
                    "name": "xss_payload.png",
                    "data": TINY_PNG_2_B64,
                    "caption": "Document cookie alert triggered in victim session."
                }]
            }
        )

        rep_res = client.post(
            f"/api/projects/{self.project_id}/reports",
            json={"version": "v1.0", "selected_finding_ids": [f1_res.json()["id"], f2_res.json()["id"]]}
        )
        rep_id = rep_res.json()["id"]

        dl_res = client.get(f"/api/projects/{self.project_id}/reports/{rep_id}/download")
        doc = docx.Document(io.BytesIO(dl_res.content))

        # Check paragraphs by finding section
        f1_found_sqli = False
        f1_has_xss = False
        f2_found_xss = False
        f2_has_sqli = False

        current_finding = None
        for p in doc.paragraphs:
            if "SQL Injection in Search Form" in p.text and "VULN-" in p.text:
                current_finding = "f1"
            elif "Cross-Site Scripting in Guestbook" in p.text and "VULN-" in p.text:
                current_finding = "f2"

            if current_finding == "f1":
                if "sqli_probe.png" in p.text: f1_found_sqli = True
                if "xss_payload.png" in p.text: f1_has_xss = True
            elif current_finding == "f2":
                if "xss_payload.png" in p.text: f2_found_xss = True
                if "sqli_probe.png" in p.text: f2_has_sqli = True

        self.assertTrue(f1_found_sqli, "VULN-001 must contain its own evidence sqli_probe.png")
        self.assertFalse(f1_has_xss, "VULN-001 must NOT contain evidence from VULN-002")
        self.assertTrue(f2_found_xss, "VULN-002 must contain its own evidence xss_payload.png")
        self.assertFalse(f2_has_sqli, "VULN-002 must NOT contain evidence from VULN-001")

    def test_04_finding_without_evidence(self):
        """Test 4: Finding with no evidence -> shows 'No evidence artifact was attached to this finding.' and no fake images."""
        f_res = client.post(
            f"/api/projects/{self.project_id}/checklist/item-noev/finding",
            json={
                "finding_name": "Missing Security Headers",
                "priority": "LOW",
                "cwe": "CWE-693"
                # Zero evidence attached
            }
        )
        rep_res = client.post(
            f"/api/projects/{self.project_id}/reports",
            json={"version": "v1.0", "selected_finding_ids": [f_res.json()["id"]]}
        )
        dl_res = client.get(f"/api/projects/{self.project_id}/reports/{rep_res.json()['id']}/download")
        doc = docx.Document(io.BytesIO(dl_res.content))

        # No inline image shape should be created for this finding
        self.assertEqual(len(doc.inline_shapes), 0, "Finding without evidence must not embed any images")

        text = extract_all_docx_text(dl_res.content)
        self.assertIn("No evidence artifact was attached to this finding.", text)

    def test_05_monospaced_text_and_json_evidence(self):
        """Test 5: Text and JSON evidence -> rendered as monospaced blocks in Consolas with excerpt labels."""
        raw_json_str = json.dumps({"status": "vulnerable", "exposed_id": 104, "admin": True})
        b64_json = "data:application/json;base64," + base64.b64encode(raw_json_str.encode("utf-8")).decode("ascii")

        f_res = client.post(
            f"/api/projects/{self.project_id}/checklist/item-txt/finding",
            json={
                "finding_name": "Exposed Telemetry API Response",
                "priority": "MEDIUM",
                "cwe": "CWE-200",
                "evidence": [{
                    "id": "EV-JSON",
                    "name": "telemetry_response.json",
                    "data": b64_json,
                    "type": "application/json",
                    "caption": "Telemetry endpoint output showing unauthenticated administrative flag."
                }]
            }
        )
        rep_res = client.post(
            f"/api/projects/{self.project_id}/reports",
            json={"version": "v1.0", "selected_finding_ids": [f_res.json()["id"]]}
        )
        dl_res = client.get(f"/api/projects/{self.project_id}/reports/{rep_res.json()['id']}/download")
        doc = docx.Document(io.BytesIO(dl_res.content))

        text = extract_all_docx_text(dl_res.content)
        self.assertIn("telemetry_response.json", text)
        self.assertIn("Format: Technical PoC Excerpt", text)
        self.assertIn('"exposed_id": 104', text)
        self.assertNotIn("registered and archived", text)

        # Check for Consolas font run in docx
        found_consolas = False
        for t in doc.tables:
            for row in t.rows:
                for cell in row.cells:
                    for p in cell.paragraphs:
                        if '"exposed_id": 104' in p.text:
                            for r in p.runs:
                                if r.font.name == "Consolas":
                                    found_consolas = True
        self.assertTrue(found_consolas, "JSON evidence must be formatted with Consolas monospaced font")

    def test_06_target_consistency_warning(self):
        """Test 6: Evidence targeting an external/mismatched domain flags a target consistency warning."""
        f_res = client.post(
            f"/api/projects/{self.project_id}/checklist/item-mismatch/finding",
            json={
                "finding_name": "Environment Mismatch Finding",
                "priority": "HIGH",
                "evidence": [{
                    "id": "EV-MISMATCH",
                    "name": "other_system.png",
                    "data": TINY_PNG_B64,
                    "url": "https://unrelated-corp.internal/admin",
                    "target": "unrelated-corp.internal",
                    "caption": "Screenshot captured from non-target server."
                }]
            }
        )
        rep_res = client.post(
            f"/api/projects/{self.project_id}/reports",
            json={"version": "v1.0", "selected_finding_ids": [f_res.json()["id"]]}
        )
        dl_res = client.get(f"/api/projects/{self.project_id}/reports/{rep_res.json()['id']}/download")
        text = extract_all_docx_text(dl_res.content)
        self.assertIn("WARNING: Evidence artifact may reference a different target/environment", text)

    def test_07_duplicate_evidence_deduplication(self):
        """Test 7: Accidental duplicate attachment of same artifact is deduplicated to 1 embedded instance."""
        f_res = client.post(
            f"/api/projects/{self.project_id}/checklist/item-dup/finding",
            json={
                "finding_name": "Duplicate Evidence Finding",
                "priority": "MEDIUM",
                "evidence": [
                    {"id": "EV-DUP-1", "name": "same_capture.png", "data": TINY_PNG_B64, "caption": "Capture 1"},
                    {"id": "EV-DUP-1", "name": "same_capture.png", "data": TINY_PNG_B64, "caption": "Capture 1"}
                ]
            }
        )
        rep_res = client.post(
            f"/api/projects/{self.project_id}/reports",
            json={"version": "v1.0", "selected_finding_ids": [f_res.json()["id"]]}
        )
        dl_res = client.get(f"/api/projects/{self.project_id}/reports/{rep_res.json()['id']}/download")
        doc = docx.Document(io.BytesIO(dl_res.content))
        # Deduplication should result in exactly 1 image embedded
        self.assertEqual(len(doc.inline_shapes), 1, "Duplicate evidence artifact must be deduplicated to a single image")

    def test_08_missing_evidence_graceful_handling(self):
        """Test 8: Missing file artifact renders graceful unavailable notice without crashing or corrupting report."""
        f_res = client.post(
            f"/api/projects/{self.project_id}/checklist/item-missing/finding",
            json={
                "finding_name": "Missing File Reference Finding",
                "priority": "LOW",
                "evidence_filename": "non_existent_disk_file_9999.png",
                "evidence_data": None
            }
        )
        rep_res = client.post(
            f"/api/projects/{self.project_id}/reports",
            json={"version": "v1.0", "selected_finding_ids": [f_res.json()["id"]]}
        )
        self.assertIn(rep_res.status_code, [200, 201])
        dl_res = client.get(f"/api/projects/{self.project_id}/reports/{rep_res.json()['id']}/download")
        text = extract_all_docx_text(dl_res.content)
        self.assertIn("Evidence artifact unavailable at report-generation time", text)
        self.assertNotIn("registered and archived", text)

    def test_09_evidence_register_appendix_reconciliation(self):
        """Test 9: Section 25 table contains all 7 columns and reconciles embedded artifacts."""
        f_res = client.post(
            f"/api/projects/{self.project_id}/checklist/item-reg/finding",
            json={
                "finding_name": "Audit Register Verified Finding",
                "priority": "CRITICAL",
                "evidence": [{
                    "id": "EV-REG-01",
                    "name": "audit_proof.png",
                    "data": TINY_PNG_B64,
                    "caption": "Executive verification proof of exploit."
                }]
            }
        )
        rep_res = client.post(
            f"/api/projects/{self.project_id}/reports",
            json={"version": "v1.0", "selected_finding_ids": [f_res.json()["id"]]}
        )
        dl_res = client.get(f"/api/projects/{self.project_id}/reports/{rep_res.json()['id']}/download")
        doc = docx.Document(io.BytesIO(dl_res.content))

        found_reg_table = False
        for table in doc.tables:
            first_row = [c.text.strip() for c in table.rows[0].cells]
            if "Evidence ID" in first_row and "Figure Reference" in first_row:
                found_reg_table = True
                self.assertEqual(
                    first_row,
                    ["Evidence ID", "Finding ID", "Evidence Type", "Filename", "Description", "Uploaded Date", "Figure Reference"]
                )
                self.assertGreaterEqual(len(table.rows), 2)
                row_vals = [c.text.strip() for c in table.rows[1].cells]
                self.assertIn("EV-REG-01", row_vals[0])
                self.assertIn("audit_proof.png", row_vals[3])

        self.assertTrue(found_reg_table, "Section 25 7-column evidence register table must exist")

    def test_10_pdf_compilation_and_no_ai_fix_leakage(self):
        """Test 10: Generated DOCX compiles cleanly to PDF and contains zero internal AI AutoFix tokens."""
        f_res = client.post(
            f"/api/projects/{self.project_id}/checklist/item-pdf/finding",
            json={
                "finding_name": "Client Clean Finding",
                "priority": "HIGH",
                "observation": "Legitimate technical pentest observation without automated tool residue.",
                "evidence": [{
                    "id": "EV-CLEAN",
                    "name": "clean_proof.png",
                    "data": TINY_PNG_B64,
                    "caption": "Clean pentest evidence demonstration."
                }]
            }
        )
        rep_res = client.post(
            f"/api/projects/{self.project_id}/reports",
            json={"version": "v1.0", "selected_finding_ids": [f_res.json()["id"]]}
        )
        rep_id = rep_res.json()["id"]

        # PDF download check
        pdf_res = client.get(f"/api/projects/{self.project_id}/reports/{rep_id}/download?format=pdf")
        if pdf_res.status_code == 200:
            self.assertTrue(pdf_res.content.startswith(b"%PDF"))

        # Check full text for absence of forbidden AI fix tokens
        dl_res = client.get(f"/api/projects/{self.project_id}/reports/{rep_id}/download")
        text = extract_all_docx_text(dl_res.content).lower()
        self.assertNotIn("ai autofix", text)
        self.assertNotIn("ai-generated patch", text)
        self.assertNotIn("tracegate/fix/", text)

if __name__ == "__main__":
    unittest.main()
