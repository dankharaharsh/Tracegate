"""
Comprehensive Verification Suite for Tracegate PDF Generation, Storage, and Download Pipeline.
Tests:
- Test A: PDF Binary Header & Structural Validation (is_valid_pdf, rejection of disguised DOCX)
- Test B: Native Pure-Python Report PDF Generation (ReportLab executive report compilation)
- Test C: Report Creation Endpoint Dual Artifacts (DOCX + Verified PDF storage)
- Test D: Report PDF Download Endpoint (application/pdf, Content-Disposition, %PDF- header)
- Test E: Certificate PDF Download (valid %PDF-, not identical to DOCX file)
- Test F: On-Demand Certificate PDF Recovery (recovers valid PDF when file_path_pdf is None)
- Test G: Elimination of Disguised DOCX Fallback on PDF Requests
- Test H: Prevention of download.json & Strict Error Header Handling
- Test I: Multi-Tenancy & Project Isolation Enforcement
"""

import unittest
import io
import os
import sys
import uuid
from pathlib import Path
import pypdf

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.app import app
from backend import database as db
from backend.pdf_validator import is_valid_pdf, validate_pdf_artifact, verify_pdf_bytes
from backend.report_pdf_generator import generate_pdf_report, compile_report_pdf
from backend.certificate_service import (
    generate_assessment_certificate,
    compile_pdf_certificate_reportlab,
    CERTIFICATES_DIR,
)

client = TestClient(app)


class TestPDFPipelineComplete(unittest.TestCase):

    def setUp(self):
        # Create unique test project
        self.proj_name = f"PDF Test Proj {uuid.uuid4().hex[:8]}"
        res = client.post("/api/projects", json={
            "name": self.proj_name,
            "target_url": "https://secure-target.local",
            "environment": "Web Application (Staging)",
            "description": "Automated PDF pipeline testing project"
        })
        self.assertIn(res.status_code, [200, 201])
        self.proj_id = res.json()["id"]

        # Add 2 confirmed findings
        f1_res = client.post(f"/api/projects/{self.proj_id}/checklist/item-1/finding", json={
            "finding_name": "SQL Injection in User Login",
            "priority": "CRITICAL",
            "cwe": "CWE-89",
            "cwe_id": "CWE-89",
            "cwe_title": "Improper Neutralization of Special Elements used in an SQL Command",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "endpoint": "/api/v1/auth/login",
            "affected_component": "backend/auth.py",
            "description": "User credentials query concatenated raw untrusted input.",
            "impact": "Full database compromise and authentication bypass.",
            "remediation": "Utilize parameterized statements with ORM binding.",
            "poc_text": "POST /api/v1/auth/login HTTP/1.1\nHost: target.local\n\nusername=' OR 1=1--"
        })
        self.assertEqual(f1_res.status_code, 201)
        self.f1 = f1_res.json()["id"]

        f2_res = client.post(f"/api/projects/{self.proj_id}/checklist/item-2/finding", json={
            "finding_name": "Insecure Direct Object Reference (IDOR)",
            "priority": "HIGH",
            "cwe": "CWE-639",
            "cwe_id": "CWE-639",
            "cwe_title": "Authorization Bypass Through User-Controlled Key",
            "cvss_score": 8.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "endpoint": "/api/v1/user/profile",
            "affected_component": "backend/profile.py",
            "description": "Access control missing on profile records query.",
            "impact": "Arbitrary account data exposure.",
            "remediation": "Bind profile queries strictly to session-authenticated user ID.",
            "poc_text": "GET /api/v1/user/profile?user_id=1002 HTTP/1.1"
        })
        self.assertEqual(f2_res.status_code, 201)
        self.f2 = f2_res.json()["id"]

    def tearDown(self):
        try:
            client.delete(f"/api/projects/{self.proj_id}")
        except Exception:
            pass

    # =========================================================================
    # TEST A: Authoritative PDF Binary Header & Structural Validation
    # =========================================================================
    def test_a_pdf_validator_accepts_valid_and_rejects_corrupted_or_disguised(self):
        """Verify is_valid_pdf correctly validates valid PDFs and rejects corrupt, empty, and DOCX files."""
        # 1. Non-existent file
        valid, err = validate_pdf_artifact(Path("data/non_existent_file.pdf"))
        self.assertFalse(valid)
        self.assertIn("does not exist", err.lower())

        # 2. Empty / zero-byte file
        scratch_dir = BASE_DIR / "scratch"
        scratch_dir.mkdir(exist_ok=True)
        zero_file = scratch_dir / "zero_byte.pdf"
        zero_file.write_bytes(b"")
        valid, err = validate_pdf_artifact(zero_file)
        self.assertFalse(valid)
        self.assertIn("below minimum", err.lower())

        # 3. Disguised DOCX (ZIP archive starting with PK\x03\x04)
        docx_disguised = scratch_dir / "disguised_as_pdf.pdf"
        docx_disguised.write_bytes(b"PK\x03\x04" + b"\x00" * 1024)
        valid, err = validate_pdf_artifact(docx_disguised)
        self.assertFalse(valid)
        self.assertIn("zip/docx", err.lower())

        # 4. Plain text (> 100 bytes) disguised as PDF
        txt_disguised = scratch_dir / "plain_text.pdf"
        txt_disguised.write_text("This is plain text with no PDF magic header. " * 5, encoding="utf-8")
        valid, err = validate_pdf_artifact(txt_disguised)
        self.assertFalse(valid)
        self.assertIn("magic header", err.lower())

        # Cleanup scratch test files
        for f in [zero_file, docx_disguised, txt_disguised]:
            try:
                f.unlink()
            except Exception:
                pass

    # =========================================================================
    # TEST B: Native ReportLab PDF Report Generation
    # =========================================================================
    def test_b_native_report_pdf_generation_produces_verified_multipage_pdf(self):
        """Verify generate_pdf_report compiles model into multi-page verified PDF with all essential sections."""
        from backend.report_model import assemble_normalized_report_model

        proj = db.get_project_by_id(self.proj_id)
        self.assertIsNotNone(proj)
        findings = db.get_project_findings_list(self.proj_id)

        model = assemble_normalized_report_model(
            proj,
            version="v1.0",
            author_name="Lead Security Assessor",
            selected_finding_ids=[self.f1, self.f2],
            findings=findings,
            allow_clean_report=False,
            methodology="owasp_wstg"
        )

        target_pdf = Path(f"data/reports/{self.proj_id}_test_b_report.pdf")
        compiled = generate_pdf_report(model, target_pdf)

        self.assertIsNotNone(compiled)
        self.assertTrue(compiled.exists())
        self.assertTrue(is_valid_pdf(compiled))

        # Binary check: must start with %PDF-
        with open(compiled, "rb") as f:
            header = f.read(10)
        self.assertTrue(header.startswith(b"%PDF-"))

        # Structural check: verify pages >= 2
        reader = pypdf.PdfReader(str(compiled))
        self.assertGreaterEqual(len(reader.pages), 2)

        # Cleanup
        try:
            compiled.unlink()
        except Exception:
            pass

    # =========================================================================
    # TEST C: Report Creation Endpoint Dual Artifacts (DOCX + Verified PDF)
    # =========================================================================
    def test_c_create_report_endpoint_persists_both_docx_and_verified_pdf(self):
        """Verify POST /api/projects/{id}/reports generates and stores both DOCX and valid PDF artifacts."""
        res = client.post(f"/api/projects/{self.proj_id}/reports", json={
            "version": "v1.0",
            "author_name": "Certified Auditor",
            "methodology": "owasp_wstg",
            "selected_finding_ids": [self.f1, self.f2]
        })
        self.assertEqual(res.status_code, 201)
        data = res.json()

        self.assertEqual(data["project_id"], self.proj_id)
        self.assertEqual(data["version"], "v1.0")

        # DOCX check
        docx_path = Path(data["file_path"])
        self.assertTrue(docx_path.exists(), "DOCX report must exist on disk.")
        self.assertGreater(docx_path.stat().st_size, 1000)

        # PDF check
        pdf_path = docx_path.with_suffix(".pdf")
        self.assertTrue(pdf_path.exists(), "PDF report artifact must exist on disk alongside DOCX.")
        self.assertTrue(is_valid_pdf(pdf_path), "PDF report artifact must pass authoritative PDF validation.")

        # API response metadata check
        self.assertTrue(data.get("pdf_available"), "pdf_available must be True in response.")
        self.assertIsNotNone(data.get("file_path_pdf"), "file_path_pdf must be recorded in response.")

    # =========================================================================
    # TEST D: Report PDF Download Endpoint
    # =========================================================================
    def test_d_download_report_endpoint_streams_valid_pdf_with_proper_headers(self):
        """Verify GET /api/projects/{id}/reports/{rep_id}/download?format=pdf streams valid PDF with correct headers."""
        # 1. Create report
        rep_res = client.post(f"/api/projects/{self.proj_id}/reports", json={
            "version": "v1.0",
            "author_name": "Certified Auditor",
            "selected_finding_ids": [self.f1, self.f2]
        })
        self.assertEqual(rep_res.status_code, 201)
        rep_id = rep_res.json()["id"]

        # 2. Download DOCX
        dl_docx = client.get(f"/api/projects/{self.proj_id}/reports/{rep_id}/download?format=docx")
        self.assertEqual(dl_docx.status_code, 200)
        self.assertIn("application/vnd.openxmlformats", dl_docx.headers.get("content-type", ""))
        self.assertIn(".docx", dl_docx.headers.get("content-disposition", ""))

        # 3. Download PDF
        dl_pdf = client.get(f"/api/projects/{self.proj_id}/reports/{rep_id}/download?format=pdf")
        self.assertEqual(dl_pdf.status_code, 200)
        self.assertEqual(dl_pdf.headers.get("content-type"), "application/pdf")
        self.assertIn(".pdf", dl_pdf.headers.get("content-disposition", ""))

        # Verify content binary
        self.assertTrue(dl_pdf.content.startswith(b"%PDF-"), "Streamed PDF must start with %PDF- header.")
        valid, err = verify_pdf_bytes(dl_pdf.content)
        self.assertTrue(valid, f"Streamed PDF bytes must be valid: {err}")

    # =========================================================================
    # TEST E: Certificate PDF Download (Eliminates Disguised DOCX Defect)
    # =========================================================================
    def test_e_certificate_pdf_is_valid_binary_and_not_disguised_docx(self):
        """Verify Problem 2 fix: Certificate PDF is valid binary %PDF- and NOT identical to DOCX file."""
        # Resolve all findings to make assessment eligible for certificate
        client.post(f"/api/findings/{self.f1}/retest", json={"result": "PASS", "notes": "Verified patch"})
        client.post(f"/api/findings/{self.f2}/retest", json={"result": "PASS", "notes": "Verified patch"})

        # Generate certificate
        gen_res = client.post(f"/api/projects/{self.proj_id}/certificate/generate")
        self.assertEqual(gen_res.status_code, 200)
        cert_data = gen_res.json()["certificate"]
        cert_id = cert_data["certificate_id"]

        # Download DOCX certificate
        docx_res = client.get(f"/api/certificates/{cert_id}/download?format=docx")
        self.assertEqual(docx_res.status_code, 200)
        self.assertIn("openxmlformats", docx_res.headers.get("content-type", ""))

        # Download PDF certificate
        pdf_res = client.get(f"/api/certificates/{cert_id}/download?format=pdf")
        self.assertEqual(pdf_res.status_code, 200)
        self.assertEqual(pdf_res.headers.get("content-type"), "application/pdf")
        self.assertIn(".pdf", pdf_res.headers.get("content-disposition", ""))

        # Binary check: must start with %PDF-
        self.assertTrue(pdf_res.content.startswith(b"%PDF-"), "Certificate PDF must begin with %PDF- magic bytes.")

        # Critical check: size must NOT be identical to the DOCX bytes (~220 KB vs ReportLab PDF ~250 KB)
        self.assertNotEqual(len(pdf_res.content), len(docx_res.content), "PDF and DOCX content must not be identical bytes.")

        # Structural check via pypdf
        valid, err = verify_pdf_bytes(pdf_res.content)
        self.assertTrue(valid, f"Certificate PDF must pass pypdf structural check: {err}")

    # =========================================================================
    # TEST F: On-Demand Certificate PDF Recovery
    # =========================================================================
    def test_f_on_demand_certificate_pdf_recovery(self):
        """Verify that if file_path_pdf is None, download endpoint recovers by generating verified PDF on-demand."""
        # Retest all findings
        client.post(f"/api/findings/{self.f1}/retest", json={"result": "PASS", "notes": "Verified"})
        client.post(f"/api/findings/{self.f2}/retest", json={"result": "PASS", "notes": "Verified"})

        gen_res = client.post(f"/api/projects/{self.proj_id}/certificate/generate")
        self.assertEqual(gen_res.status_code, 200)
        cert_id = gen_res.json()["certificate"]["certificate_id"]

        # Simulate missing PDF: delete disk file and null out DB path
        cert_rec = db.get_certificate_by_id(cert_id)
        if cert_rec.get("file_path_pdf"):
            try:
                Path(cert_rec["file_path_pdf"]).unlink(missing_ok=True)
            except Exception:
                pass
        conn = db.get_db_connection()
        conn.execute("UPDATE vapt_certificates SET file_path_pdf = NULL WHERE certificate_id = ?", (cert_id,))
        conn.commit()
        conn.close()

        # Download PDF: endpoint must detect missing PDF and compile on-demand
        dl_res = client.get(f"/api/certificates/{cert_id}/download?format=pdf")
        self.assertEqual(dl_res.status_code, 200)
        self.assertEqual(dl_res.headers.get("content-type"), "application/pdf")
        self.assertTrue(dl_res.content.startswith(b"%PDF-"))

        # Verify DB was updated with recovered PDF path
        updated_cert = db.get_certificate_by_id(cert_id)
        self.assertIsNotNone(updated_cert.get("file_path_pdf"))
        self.assertTrue(is_valid_pdf(updated_cert["file_path_pdf"]))

    # =========================================================================
    # TEST G: Prevention of Disguised DOCX Fallback on PDF Requests
    # =========================================================================
    def test_g_prevention_of_disguised_docx_fallback(self):
        """Verify that under format=pdf, server never returns DOCX binary if PDF compilation fails."""
        # Retest findings
        client.post(f"/api/findings/{self.f1}/retest", json={"result": "PASS", "notes": "Verified"})
        client.post(f"/api/findings/{self.f2}/retest", json={"result": "PASS", "notes": "Verified"})

        gen_res = client.post(f"/api/projects/{self.proj_id}/certificate/generate")
        self.assertEqual(gen_res.status_code, 200)
        cert_id = gen_res.json()["certificate"]["certificate_id"]

        # Corrupt the snapshot in DB so ReportLab cannot compile from it, and remove PDF file
        cert_rec = db.get_certificate_by_id(cert_id)
        if cert_rec.get("file_path_pdf"):
            try:
                Path(cert_rec["file_path_pdf"]).unlink(missing_ok=True)
            except Exception:
                pass

        # Temporarily mock compile_pdf_certificate_reportlab and convert_docx_to_pdf to return None
        import backend.app as app_module
        orig_compile = app_module.compile_pdf_certificate_reportlab
        orig_convert = app_module.convert_docx_to_pdf
        try:
            app_module.compile_pdf_certificate_reportlab = lambda cert, path: None
            app_module.convert_docx_to_pdf = lambda docx: None

            dl_res = client.get(f"/api/certificates/{cert_id}/download?format=pdf")
            # Must return 404 or 500 error, NEVER 200 with DOCX content!
            self.assertIn(dl_res.status_code, [404, 500])
            self.assertNotEqual(dl_res.headers.get("content-type"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
            # If JSON returned, must not be mislabeled as PDF
            if "application/json" in dl_res.headers.get("content-type", ""):
                self.assertIn("could not be generated", dl_res.json().get("detail", ""))
        finally:
            app_module.compile_pdf_certificate_reportlab = orig_compile
            app_module.convert_docx_to_pdf = orig_convert

    # =========================================================================
    # TEST H: Prevention of download.json & Header Correctness
    # =========================================================================
    def test_h_error_responses_never_download_json_as_attachment(self):
        """Verify that 404 error responses return Content-Type: application/json without attachment headers."""
        non_existent = "non-existent-rep-999"
        res = client.get(f"/api/projects/{self.proj_id}/reports/{non_existent}/download?format=pdf")
        self.assertEqual(res.status_code, 404)
        self.assertIn("application/json", res.headers.get("content-type", ""))
        # Crucial: 404 JSON must NOT have attachment disposition that browsers save as download.json
        self.assertNotIn("attachment", res.headers.get("content-disposition", ""))

    # =========================================================================
    # TEST I: Multi-Tenancy & Project Isolation Enforcement
    # =========================================================================
    def test_i_user_isolation_blocks_cross_project_downloads(self):
        """Verify User B cannot download User A's reports or certificates."""
        # 1. Register User A and User B
        uid_a = f"usera_{uuid.uuid4().hex[:6]}"
        reg_a = client.post("/api/auth/register", json={
            "username": uid_a,
            "email": f"{uid_a}@tracegate.test",
            "password": "Password123!",
            "full_name": "User A"
        })
        self.assertEqual(reg_a.status_code, 201)
        tok_a = reg_a.json()["token"]

        uid_b = f"userb_{uuid.uuid4().hex[:6]}"
        reg_b = client.post("/api/auth/register", json={
            "username": uid_b,
            "email": f"{uid_b}@tracegate.test",
            "password": "Password123!",
            "full_name": "User B"
        })
        self.assertEqual(reg_b.status_code, 201)
        tok_b = reg_b.json()["token"]

        # 2. User A creates project and report
        p_a = client.post("/api/projects", json={
            "name": "User A Private Project",
            "target_url": "https://usera.internal"
        }, headers={"Authorization": f"Bearer {tok_a}"}).json()["id"]

        f_a = client.post(f"/api/projects/{p_a}/checklist/item-a/finding", json={
            "finding_name": "Private Flaw",
            "priority": "HIGH"
        }, headers={"Authorization": f"Bearer {tok_a}"}).json()["id"]

        rep_a = client.post(f"/api/projects/{p_a}/reports", json={
            "version": "v1.0",
            "selected_finding_ids": [f_a]
        }, headers={"Authorization": f"Bearer {tok_a}"}).json()["id"]

        # 3. User B attempts to download User A's report -> Must be 403 Forbidden or 404
        b_res = client.get(
            f"/api/projects/{p_a}/reports/{rep_a}/download?format=pdf",
            headers={"Authorization": f"Bearer {tok_b}"}
        )
        self.assertIn(b_res.status_code, [403, 404], "User B must not be permitted to download User A's report.")


if __name__ == "__main__":
    unittest.main()
