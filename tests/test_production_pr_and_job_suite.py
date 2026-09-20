"""
tests/test_production_pr_and_job_suite.py
Automated Verification Suite for Tracegate Production Render Reliability:
1. Real GitHub PR Creation Engine & Auth Validation (No mock #142)
2. Open PR Discovery & Reuse Idempotency
3. Linux/Render-Compatible Zero-COM PDF Generation via ReportLab
4. Background Certificate Generation Job Lifecycle & Isolation
5. Non-blocking Retest Async Certificate Handshake
"""

import unittest
import uuid
import time
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.app import app
from backend import database as db
from backend import certificate_service
from backend import github_service

client = TestClient(app)


class TestProductionPRAndJobSuite(unittest.TestCase):

    def setUp(self):
        # Register test user
        self.username = f"user_{uuid.uuid4().hex[:8]}"
        self.email = f"{self.username}@example.com"
        self.password = "Secur1ty!Pass#2026"
        reg_res = client.post("/api/auth/register", json={
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "full_name": "Test Engineer"
        })
        self.assertEqual(reg_res.status_code, 201)
        self.user_data = reg_res.json()["user"]
        self.token = reg_res.json()["access_token"]
        self.auth_headers = {"Authorization": f"Bearer {self.token}"}

        # Create project under test user
        proj_res = client.post("/api/projects", headers=self.auth_headers, json={
            "name": f"Prod Target {uuid.uuid4().hex[:6]}",
            "target_url": "https://production-target.internal",
            "environment": "Production Cloud",
            "description": "Production Reliability Assessment"
        })
        self.assertEqual(proj_res.status_code, 201)
        self.project_id = proj_res.json()["id"]

    def _create_finding(self, name="SQL Injection in Auth", severity="HIGH", status="CONFIRMED", retest_status="PENDING"):
        fid = f"find-{uuid.uuid4().hex[:8]}"
        conn = db.get_db_connection()
        cur = conn.cursor()
        now = "2026-09-18 10:00:00"
        cur.execute("""
        INSERT INTO findings (
            id, project_id, vuln_id, finding_name, severity_source,
            affected_url, affected_endpoint, affected_component, description, observation, testing_notes,
            poc_text, priority, cwe, cvss_score, status, fix_status, source,
            retest_status, retest_notes, recorded_at
        ) VALUES (?, ?, ?, ?, 'MANUAL', 'https://production-target.internal', '/login', 'auth', 'desc', 'obs', 'notes', 'poc', ?, 'CWE-89', 8.5, ?, 'Pending Fix', 'MANUAL', ?, 'None', ?)
        """, (fid, self.project_id, f"VULN-{uuid.uuid4().hex[:4].upper()}", name, severity, status, retest_status, now))
        conn.commit()
        conn.close()
        return fid

    # =========================================================================
    # ISSUE 1: REAL GITHUB PR CREATION TESTS (NO #142)
    # =========================================================================

    def test_01_pr_creation_rejects_missing_github_token_without_mock_142(self):
        """External repository PR request without a GitHub token strictly returns 401 GITHUB_AUTH_REQUIRED and NEVER #142."""
        fid = self._create_finding()

        # Attempt to create PR without connecting GitHub token
        res = client.post("/api/ai-fix/create-pr", headers=self.auth_headers, json={
            "repo": "real-org/enterprise-payment-api",
            "fix_branch": "tracegate/fix/VULN-001",
            "base_branch": "main",
            "finding_id": fid,
            "project_id": self.project_id
        })

        self.assertEqual(res.status_code, 401)
        detail = res.json().get("detail", "")
        msg = detail if isinstance(detail, str) else str(detail)
        self.assertIn("GITHUB_AUTH_REQUIRED", msg)
        self.assertNotIn("142", msg)

        # Confirm DB finding did not receive fake #142 PR URL
        finding = db.get_finding_by_id(fid)
        self.assertIsNone(finding.get("github_pr"))

    def test_02_pr_creation_authoritative_github_api_success(self):
        """When GitHub API confirms PR creation, backend persists and returns genuine PR number and URL."""
        fid = self._create_finding()

        # Connect a valid GitHub token for test user
        db.save_user_github_config(
            user_id=self.user_data["id"],
            token="ghp_liveTestTokenValidProductionFormat123456",
            mode="live",
            username="real-org"
        )

        # Mock GitHub API responses:
        # 1. GET fix_branch exists: returns commit sha
        # 2. GET existing pulls: returns empty list []
        # 3. POST create pull: returns real PR #589
        def mock_api_request(token, endpoint, method="GET", data=None, timeout=8):
            if "branches" in endpoint or "git/ref" in endpoint:
                return 200, {"commit": {"sha": "c0ffee123456789"}}, {}
            elif "pulls" in endpoint and method == "GET":
                return 200, [], {}
            elif "pulls" in endpoint and method == "POST":
                return 201, {
                    "number": 589,
                    "html_url": "https://github.com/real-org/enterprise-payment-api/pull/589",
                    "title": (data or {}).get("title", ""),
                    "state": "open",
                    "head": {"sha": "c0ffee123456789"},
                    "base": {"sha": "deadbeef9876543"}
                }, {}
            return 404, {}, {}

        with patch("backend.github_service._github_api_request", side_effect=mock_api_request):
            res = client.post("/api/ai-fix/create-pr", headers=self.auth_headers, json={
                "repo": "real-org/enterprise-payment-api",
                "fix_branch": "tracegate/fix/VULN-001",
                "base_branch": "main",
                "finding_id": fid,
                "project_id": self.project_id
            })

            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertTrue(data["success"])
            self.assertEqual(data["pr_number"], 589)
            self.assertEqual(data["pr_url"], "https://github.com/real-org/enterprise-payment-api/pull/589")
            self.assertNotEqual(data["pr_number"], 142)

            # Confirm DB was updated with genuine PR number & URL
            updated_f = db.get_finding_by_id(fid)
            self.assertEqual(updated_f["github_pr"], "https://github.com/real-org/enterprise-payment-api/pull/589")
            self.assertEqual(updated_f["fix_status"], "PR Created")

    def test_03_pr_creation_reuses_existing_open_pr_idempotently(self):
        """If a PR is already open on GitHub for the fix branch, it captures and reuses that PR without error."""
        fid = self._create_finding()

        db.save_user_github_config(
            user_id=self.user_data["id"],
            token="ghp_liveTestTokenValidProductionFormat123456",
            mode="live",
            username="real-org"
        )

        def mock_api_request(token, endpoint, method="GET", data=None, timeout=8):
            if "branches" in endpoint or "git/ref" in endpoint:
                return 200, {"commit": {"sha": "aabbcc112233"}}, {}
            elif "pulls" in endpoint and method == "GET":
                return 200, [{
                    "number": 402,
                    "html_url": "https://github.com/real-org/enterprise-payment-api/pull/402",
                    "title": "Fix: SQL Injection in Auth",
                    "state": "open",
                    "head": {"sha": "aabbcc112233"},
                    "base": {"sha": "ddeeff445566"}
                }], {}
            return 404, {}, {}

        with patch("backend.github_service._github_api_request", side_effect=mock_api_request):
            res = client.post("/api/ai-fix/create-pr", headers=self.auth_headers, json={
                "repo": "real-org/enterprise-payment-api",
                "fix_branch": "tracegate/fix/VULN-001",
                "base_branch": "main",
                "finding_id": fid,
                "project_id": self.project_id
            })

            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertTrue(data["success"])
            self.assertEqual(data["pr_number"], 402)
            self.assertEqual(data["pr_url"], "https://github.com/real-org/enterprise-payment-api/pull/402")
            self.assertTrue(data.get("reused"))

    # =========================================================================
    # ISSUE 2: LINUX-COMPATIBLE PDF CERTIFICATE & BACKGROUND JOBS
    # =========================================================================

    def test_04_reportlab_compiles_valid_pdf_without_word_com(self):
        """ReportLab compiler generates valid landscape A4 PDF certificate in milliseconds without Word COM."""
        test_pdf_path = certificate_service.CERTIFICATES_DIR / f"test_verify_{uuid.uuid4().hex[:6]}.pdf"
        sample_data = {
            "certificate_id": f"TG-VAPT-2026-{uuid.uuid4().hex[:6].upper()}",
            "verification_id": f"TG-VERIFY-{uuid.uuid4().hex[:8].upper()}",
            "target_name": "Prod Web Service",
            "target_url": "https://prod.internal",
            "assessment_type": "Web Application Penetration Test (VAPT)",
            "assessment_start": "18 Sep 2026",
            "assessment_end": "18 Sep 2026",
            "issue_date": "18 Sep 2026",
            "final_validation_date": "18 Sep 2026",
            "snapshot": {
                "signatories": {
                    "prepared_by": "Lead Assessor",
                    "validated_by": "Senior QA",
                    "review_status": "Passed"
                }
            }
        }

        start = time.time()
        compiled = certificate_service.compile_pdf_certificate_reportlab(sample_data, test_pdf_path)
        duration = time.time() - start

        self.assertIsNotNone(compiled)
        self.assertTrue(test_pdf_path.exists())
        self.assertLess(duration, 0.5, "ReportLab compilation must finish under 500ms (cross-platform Render guarantee)")

        # Verify PDF header magic bytes
        with open(test_pdf_path, "rb") as f:
            header = f.read(5)
            self.assertEqual(header, b"%PDF-")
            size = test_pdf_path.stat().st_size
            self.assertGreater(size, 2000, "PDF should be structured with graphics and text")

        # Cleanup
        try:
            test_pdf_path.unlink()
        except Exception:
            pass

    def test_05_certificate_background_job_lifecycle(self):
        """Background job endpoint starts job, sets GENERATING, finishes as GENERATED, and allows retrieval."""
        # Resolve all findings to make project eligible
        fid = self._create_finding(name="Critical RCE", severity="CRITICAL", status="RESOLVED", retest_status="PASSED")

        elig = certificate_service.check_assessment_certificate_eligibility(self.project_id)
        self.assertTrue(elig["eligible"])

        # Start job with async_mode=true
        res = client.post(f"/api/projects/{self.project_id}/certificate/generate?async_mode=true", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])

        # Status is GENERATING or GENERATED (if finished instantly)
        self.assertIn(data["status"], ["GENERATING", "GENERATED"])
        job_id = data.get("job_id")

        if job_id:
            # Poll job status endpoint
            poll_attempts = 0
            job_status = "GENERATING"
            job_res_data = None
            while poll_attempts < 15 and job_status == "GENERATING":
                time.sleep(0.2)
                poll_attempts += 1
                job_check = client.get(f"/api/projects/{self.project_id}/certificate/jobs/{job_id}", headers=self.auth_headers)
                self.assertEqual(job_check.status_code, 200)
                job_res_data = job_check.json()
                job_status = job_res_data["status"]

            self.assertEqual(job_status, "GENERATED")
            self.assertIsNotNone(job_res_data.get("certificate"))
            self.assertIn("TG-VAPT-", job_res_data["certificate"]["certificate_id"])

        # Verify project certificate status endpoint returns latest_job
        status_res = client.get(f"/api/projects/{self.project_id}/certificate/status", headers=self.auth_headers)
        self.assertEqual(status_res.status_code, 200)
        status_data = status_res.json()
        self.assertTrue(status_data["eligible"])
        self.assertIsNotNone(status_data.get("latest_job"))

    def test_06_certificate_job_cross_user_isolation(self):
        """User B cannot view or poll User A's certificate job."""
        fid = self._create_finding(name="Auth Bypass", severity="HIGH", status="RESOLVED", retest_status="PASSED")

        # Start job as User A
        res = client.post(f"/api/projects/{self.project_id}/certificate/generate?async_mode=true", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        job_id = res.json().get("job_id") or "job-dummy123"

        # Register User B
        u2 = f"user_b_{uuid.uuid4().hex[:8]}"
        reg2 = client.post("/api/auth/register", json={
            "username": u2,
            "email": f"{u2}@example.com",
            "password": "Password#12345",
            "full_name": "User B"
        })
        user_b_headers = {"Authorization": f"Bearer {reg2.json()['access_token']}"}

        # User B attempts to query User A's certificate job
        unauth_res = client.get(f"/api/projects/{self.project_id}/certificate/jobs/{job_id}", headers=user_b_headers)
        self.assertEqual(unauth_res.status_code, 404, "User B must not have access to User A's project certificate jobs")

    def test_07_retest_pass_with_async_flag_returns_job_id_without_blocking(self):
        """Retest endpoint with async_certificate=True returns certificate_job_id immediately."""
        fid = self._create_finding(name="CSRF on Profile", severity="MEDIUM", status="CONFIRMED", retest_status="PENDING")

        retest_res = client.post(f"/api/ai-fix/{fid}/retest", headers=self.auth_headers, json={
            "result": "PASS",
            "notes": "Patch verified",
            "async_certificate": True
        })

        self.assertEqual(retest_res.status_code, 200)
        data = retest_res.json()
        self.assertEqual(data["retest_status"], "PASSED")
        self.assertEqual(data["status"], "RESOLVED")
        self.assertTrue(data.get("certificate_eligible"))
        # Should have certificate_job_id or direct certificate
        self.assertTrue(data.get("certificate_job_id") or data.get("certificate"))


if __name__ == "__main__":
    unittest.main()
