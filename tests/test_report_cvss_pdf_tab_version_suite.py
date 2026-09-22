"""
Tracegate Report Integrity & Concurrency Test Suite
Validates:
1. Issue A: CVSS / Severity Consistency, Sourcing, and "Not Scored" Truthfulness (no spurious v4.0).
2. Issue B: PDF /Title Document Information Dictionary, Inline Disposition Header, and /view Endpoint.
3. Issue C: Server-Authoritative Sequential Versioning (v1.0 -> v2.0 -> v3.0) and Concurrency Protection.
"""

import unittest
import os
import io
import re
import tempfile
import threading
from pathlib import Path
from pypdf import PdfReader
from fastapi.testclient import TestClient

from backend.app import app
from backend.report_model import (
    is_cvss_consistent_with_severity,
    parse_and_calculate_cvss_v31,
    format_cvss_vector,
    assemble_normalized_report_model,
)
from backend.report_pdf_generator import (
    ensure_pdf_title_metadata,
    generate_pdf_report,
    compile_report_pdf,
)
from backend.database import (
    create_project,
    delete_project,
    get_project_reports,
    get_next_report_version,
    save_report_record,
    get_db_connection,
)

client = TestClient(app)

class TestReportCvssPdfTabVersionSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Register test user & obtain JWT token
        cls.username = f"test_rep_user_{os.urandom(4).hex()}"
        cls.password = "SecTestPass123!"
        cls.email = f"{cls.username}@tracegate-audit.local"
        reg_resp = client.post("/api/auth/register", json={
            "username": cls.username,
            "password": cls.password,
            "email": cls.email,
            "full_name": "Lead Pentester"
        })
        if reg_resp.status_code == 201:
            cls.token = reg_resp.json()["access_token"]
        else:
            login_resp = client.post("/api/auth/login", json={"username": cls.username, "password": cls.password})
            cls.token = login_resp.json()["access_token"]
        cls.auth_headers = {"Authorization": f"Bearer {cls.token}"}

    def create_test_project(self, name=None):
        p_name = name or f"Test Proj {os.urandom(3).hex()}"
        res = client.post("/api/projects", json={
            "name": p_name,
            "target_url": "https://audit-target.local",
            "environment": "Web Application (Staging)",
            "description": "Test Project"
        }, headers=self.auth_headers)
        self.assertEqual(res.status_code, 201)
        return res.json()

    # =========================================================================
    # ISSUE A: CVSS / SEVERITY CONSISTENCY TESTS
    # =========================================================================

    def test_cvss_consistency_validation_boundaries(self):
        """Validates CVSS v3.1 qualitative severity score boundaries."""
        # CRITICAL: 9.0 to 10.0
        self.assertTrue(is_cvss_consistent_with_severity(9.0, "CRITICAL"))
        self.assertTrue(is_cvss_consistent_with_severity(9.8, "CRITICAL"))
        self.assertTrue(is_cvss_consistent_with_severity(10.0, "CRITICAL"))
        self.assertFalse(is_cvss_consistent_with_severity(8.9, "CRITICAL"))
        self.assertFalse(is_cvss_consistent_with_severity(7.5, "CRITICAL"))

        # HIGH: 7.0 to 8.9
        self.assertTrue(is_cvss_consistent_with_severity(7.0, "HIGH"))
        self.assertTrue(is_cvss_consistent_with_severity(7.5, "HIGH"))
        self.assertTrue(is_cvss_consistent_with_severity(8.9, "HIGH"))
        self.assertFalse(is_cvss_consistent_with_severity(9.0, "HIGH"))
        self.assertFalse(is_cvss_consistent_with_severity(6.9, "HIGH"))

        # MEDIUM: 4.0 to 6.9
        self.assertTrue(is_cvss_consistent_with_severity(4.0, "MEDIUM"))
        self.assertTrue(is_cvss_consistent_with_severity(5.5, "MEDIUM"))
        self.assertTrue(is_cvss_consistent_with_severity(6.9, "MEDIUM"))
        self.assertFalse(is_cvss_consistent_with_severity(7.0, "MEDIUM"))
        self.assertFalse(is_cvss_consistent_with_severity(3.9, "MEDIUM"))

        # LOW: 0.1 to 3.9
        self.assertTrue(is_cvss_consistent_with_severity(0.1, "LOW"))
        self.assertTrue(is_cvss_consistent_with_severity(2.5, "LOW"))
        self.assertTrue(is_cvss_consistent_with_severity(3.9, "LOW"))
        self.assertFalse(is_cvss_consistent_with_severity(9.0, "LOW"))
        self.assertFalse(is_cvss_consistent_with_severity(0.0, "LOW"))

        # INFORMATIONAL / NONE: 0.0
        self.assertTrue(is_cvss_consistent_with_severity(0.0, "INFORMATIONAL"))
        self.assertTrue(is_cvss_consistent_with_severity(0.0, "NONE"))
        self.assertFalse(is_cvss_consistent_with_severity(1.0, "INFORMATIONAL"))

    def test_parse_and_calculate_cvss_v31(self):
        """Validates accurate mathematical calculation of CVSS v3.1 Base Scores from vectors."""
        # Critical SQLi / RCE
        sqli_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self.assertEqual(parse_and_calculate_cvss_v31(sqli_vec), 9.8)

        # Medium Reflected XSS
        xss_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        self.assertEqual(parse_and_calculate_cvss_v31(xss_vec), 6.1)

        # Invalid vector returns None
        self.assertIsNone(parse_and_calculate_cvss_v31("INVALID_VECTOR"))

    def test_format_cvss_vector_truthfulness(self):
        """Ensures format_cvss_vector never produces spurious CVSS v4.0 label on unvalidated data."""
        res_none = format_cvss_vector(None, None, "HIGH")
        self.assertNotIn("CVSS v4.0", res_none)
        self.assertIn("Not scored", res_none)

        res_v31 = format_cvss_vector(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "HIGH")
        self.assertTrue(res_v31.startswith("CVSS v3.1") or res_v31.startswith("CVSS:3.1"))

    def test_model_normalization_contradiction_handling(self):
        """Validates that assemble_normalized_report_model nullifies contradictory CVSS scores."""
        proj = {"id": "proj-cvss-test", "name": "CVSS Test Proj", "target_url": "https://test.local"}
        contradictory_findings = [
            {
                "id": "f-1",
                "finding_name": "Low Sev Finding With High CVSS",
                "priority": "LOW",
                "cvss_score": 9.0, # Contradiction!
                "cwe": "CWE-200",
                "description": "Sensitive info in comments"
            },
            {
                "id": "f-2",
                "finding_name": "High Sev Finding With High CVSS",
                "priority": "HIGH",
                "cvss_score": 8.5, # Consistent!
                "cwe": "CWE-89",
                "description": "SQL Injection"
            },
            {
                "id": "f-3",
                "finding_name": "Medium Finding Without CVSS",
                "priority": "MEDIUM",
                "cvss_score": None, # Unscored
                "cwe": "CWE-79",
                "description": "Stored XSS"
            }
        ]

        model = assemble_normalized_report_model(
            project=proj,
            version="v1.0",
            findings=contradictory_findings,
            allow_clean_report=False
        )

        f1 = next(f for f in model["findings"] if f.get("id") == "f-1" or f.get("raw_id") == "f-1")
        f2 = next(f for f in model["findings"] if f.get("id") == "f-2" or f.get("raw_id") == "f-2")
        f3 = next(f for f in model["findings"] if f.get("id") == "f-3" or f.get("raw_id") == "f-3")

        # f-1 was contradictory: cvss_score must be None, cvss_display must be "Not Scored", cvss_consistent must be False
        self.assertIsNone(f1["cvss_score"])
        self.assertEqual(f1["cvss_display"], "Not Scored")
        self.assertFalse(f1["cvss_consistent"])

        # f-2 was consistent: cvss_score preserved
        self.assertEqual(f2["cvss_score"], 8.5)
        self.assertEqual(f2["cvss_display"], "8.5")
        self.assertTrue(f2["cvss_consistent"])

        # f-3 was unscored: cvss_display must be "Not Scored"
        self.assertIsNone(f3["cvss_score"])
        self.assertEqual(f3["cvss_display"], "Not Scored")

    # =========================================================================
    # ISSUE B: PDF /TITLE METADATA & INLINE VIEW ENDPOINT TESTS
    # =========================================================================

    def test_ensure_pdf_title_metadata(self):
        """Validates that ensure_pdf_title_metadata writes /Title into PDF Info dictionary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_path = Path(tmpdir) / "test_report.pdf"

            # Create a simple ReportLab PDF
            model = {
                "title": "Tracegate VAPT Report - Document Title Test",
                "project_name": "Metadata Test Project",
                "version": "v1.0",
                "findings": [],
                "target_url": "https://audit.local"
            }
            res = generate_pdf_report(model, pdf_path)
            self.assertIsNotNone(res)
            self.assertTrue(pdf_path.exists())

            # Check PDF /Title via pypdf
            reader = PdfReader(str(pdf_path))
            title = reader.metadata.get("/Title")
            self.assertEqual(title, "Tracegate VAPT Report - Document Title Test")

            # Test updating title with ensure_pdf_title_metadata
            updated = ensure_pdf_title_metadata(pdf_path, title="Custom Updated Tab Title", author="Assessor")
            self.assertTrue(updated)

            reader2 = PdfReader(str(pdf_path))
            self.assertEqual(reader2.metadata.get("/Title"), "Custom Updated Tab Title")

    def test_report_inline_view_endpoint(self):
        """Validates that GET /api/projects/{id}/reports/{rep_id}/view returns inline PDF with Content-Disposition."""
        proj = self.create_test_project()
        proj_id = proj["id"]
        try:
            # Create a finding via API
            f_resp = client.post(
                f"/api/projects/{proj_id}/checklist/item-auth-test/finding",
                json={
                    "finding_name": "Authentication Bypass",
                    "priority": "HIGH",
                    "cvss_score": 8.2,
                    "description": "Direct parameter manipulation bypasses login."
                },
                headers=self.auth_headers
            )
            self.assertEqual(f_resp.status_code, 201)

            # Generate Report
            rep_res = client.post(
                f"/api/projects/{proj_id}/reports",
                json={"title": "Inline View Verification Report"},
                headers=self.auth_headers
            )
            self.assertEqual(rep_res.status_code, 201)
            rep_data = rep_res.json()
            rep_id = rep_data["id"]

            # Call /view endpoint
            view_res = client.get(
                f"/api/projects/{proj_id}/reports/{rep_id}/view",
                headers=self.auth_headers
            )
            self.assertEqual(view_res.status_code, 200)
            self.assertEqual(view_res.headers.get("content-type"), "application/pdf")
            content_disp = view_res.headers.get("content-disposition", "")
            self.assertTrue(content_disp.startswith("inline;"))
            self.assertIn(".pdf", content_disp)

            # Validate that the returned PDF bytes have /Title metadata
            pdf_bytes = io.BytesIO(view_res.content)
            reader = PdfReader(pdf_bytes)
            self.assertTrue(len(reader.pages) > 0)
            doc_title = reader.metadata.get("/Title")
            self.assertTrue(bool(doc_title))
            self.assertIn("Inline View Verification Report", doc_title)

        finally:
            delete_project(proj_id)

    # =========================================================================
    # ISSUE C: REPORT VERSION HISTORY & SEQUENTIAL NUMBERING TESTS
    # =========================================================================

    def test_get_next_report_version_logic(self):
        """Validates get_next_report_version across various historical state cases."""
        proj = self.create_test_project()
        proj_id = proj["id"]
        try:
            # Case 1: No reports -> v1.0
            self.assertEqual(get_next_report_version(proj_id), "v1.0")

            # Case 2: Save v1.0 -> Next must be v2.0
            save_report_record({
                "project_id": proj_id,
                "version": "v1.0",
                "report_title": "Report 1",
                "file_path": "fake1.docx",
            })
            self.assertEqual(get_next_report_version(proj_id), "v2.0")

            # Case 3: Simulate historical duplicate bug (another v1.0 in DB) -> Next must still be v2.0
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO reports (id, project_id, version, report_title, file_path, created_at)
                VALUES (?, ?, ?, ?, ?, datetime('now'))
            """, ("rep-dupe-test", proj_id, "v1.0", "Report Duplicate", "fake_dupe.docx"))
            conn.commit()
            conn.close()

            # Max major is 1 -> next is v2.0
            self.assertEqual(get_next_report_version(proj_id), "v2.0")

            # Case 4: Save v2.0 -> Next must be v3.0
            save_report_record({
                "project_id": proj_id,
                "version": "v2.0",
                "report_title": "Report 2",
                "file_path": "fake2.docx",
            })
            self.assertEqual(get_next_report_version(proj_id), "v3.0")

        finally:
            delete_project(proj_id)

    def test_next_version_api_endpoint(self):
        """Validates GET /api/projects/{id}/reports/next-version endpoint."""
        proj = self.create_test_project()
        proj_id = proj["id"]
        try:
            res = client.get(f"/api/projects/{proj_id}/reports/next-version", headers=self.auth_headers)
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["next_version"], "v1.0")
        finally:
            delete_project(proj_id)

    def test_sequential_report_generations_prevent_duplicate_v1(self):
        """
        Validates that consecutive report generations for the same project receive
        sequential version numbers (v1.0 -> v2.0 -> v3.0) even if frontend sends v1.0.
        """
        proj = self.create_test_project()
        proj_id = proj["id"]
        try:
            # Create a finding via API
            f_resp = client.post(
                f"/api/projects/{proj_id}/checklist/item-csrf-test/finding",
                json={
                    "finding_name": "Missing Anti-CSRF Token",
                    "priority": "MEDIUM",
                    "cvss_score": 5.4,
                    "description": "Sensitive state-changing request lacks token."
                },
                headers=self.auth_headers
            )
            self.assertEqual(f_resp.status_code, 201)

            # Report 1: Client sends default "v1.0"
            r1 = client.post(
                f"/api/projects/{proj_id}/reports",
                json={"version": "v1.0"},
                headers=self.auth_headers
            )
            self.assertEqual(r1.status_code, 201)
            self.assertEqual(r1.json()["version"], "v1.0")

            # Report 2: Client sends default "v1.0" again (the exact bug scenario)
            r2 = client.post(
                f"/api/projects/{proj_id}/reports",
                json={"version": "v1.0"},
                headers=self.auth_headers
            )
            self.assertEqual(r2.status_code, 201)
            # Server-authoritative sequential versioning advances to v2.0!
            self.assertEqual(r2.json()["version"], "v2.0")

            # Report 3: Client sends empty version
            r3 = client.post(
                f"/api/projects/{proj_id}/reports",
                json={},
                headers=self.auth_headers
            )
            self.assertEqual(r3.status_code, 201)
            self.assertEqual(r3.json()["version"], "v3.0")

            # Check history in DB
            reports = get_project_reports(proj_id)
            versions = [rep["version"] for rep in reports]
            self.assertEqual(versions, ["v3.0", "v2.0", "v1.0"])

        finally:
            delete_project(proj_id)

    def test_concurrent_save_report_record_protection(self):
        """Simulates concurrent report record saves and verifies no duplicate versions occur."""
        proj = create_project({"name": f"Concurrent Ver Test {os.urandom(3).hex()}", "target_url": "https://conc.local"})
        proj_id = proj["id"]
        try:
            results = []
            errors = []

            def worker(worker_id):
                try:
                    rec = save_report_record({
                        "project_id": proj_id,
                        "version": "v1.0", # All workers request v1.0
                        "report_title": f"Concurrent Worker Report {worker_id}",
                        "file_path": f"fake_{worker_id}.docx"
                    })
                    results.append(rec["version"])
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(len(errors), 0, f"Encountered errors during concurrency test: {errors}")
            self.assertEqual(len(results), 4)
            # All 4 assigned versions must be strictly distinct
            self.assertEqual(len(set(results)), 4, f"Found duplicate versions in concurrent saves: {results}")

        finally:
            delete_project(proj_id)

if __name__ == "__main__":
    unittest.main()
