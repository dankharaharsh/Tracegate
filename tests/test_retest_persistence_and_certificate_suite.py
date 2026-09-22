"""
Unit and integration test suite verifying:
1. Retest persistence and status transitions (PASS -> RESOLVED, FAIL -> REOPENED)
2. Authentication enforcement (401 for unauthenticated requests on user-owned projects)
3. Multi-user isolation (404 for cross-user retest attempts)
4. Server-side idempotency (repeated identical PASS requests)
5. Non-final finding retest (does not trigger certificate, returns blocking reason)
6. Final finding retest (auto-triggers certificate generation)
7. Certificate generation failure isolation (certificate issue does not fail retest)
8. Tester notes persistence and reload fidelity
"""

import sys
import uuid
import unittest
from pathlib import Path

BASE_DIR = Path(r"C:\Users\Harsh\Desktop\tracegate")
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.app import app
from backend import database as db
from backend import certificate_service


class TestRetestPersistenceAndCertificateSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        db.init_db()

        # Register User A
        cls.uid_a = uuid.uuid4().hex[:6]
        reg_a = cls.client.post("/api/auth/register", json={
            "username": f"retest_user_a_{cls.uid_a}",
            "email": f"retest_a_{cls.uid_a}@tracegate.test",
            "password": "Password123!",
            "full_name": "Retest Tester A",
            "role": "Security Tester"
        })
        assert reg_a.status_code == 201, f"User A registration failed: {reg_a.text}"
        cls.user_a = reg_a.json()
        cls.auth_headers_a = {"Authorization": f"Bearer {cls.user_a['access_token']}"}

        # Register User B (for cross-user isolation tests)
        cls.uid_b = uuid.uuid4().hex[:6]
        reg_b = cls.client.post("/api/auth/register", json={
            "username": f"retest_user_b_{cls.uid_b}",
            "email": f"retest_b_{cls.uid_b}@tracegate.test",
            "password": "Password123!",
            "full_name": "Retest Tester B",
            "role": "Security Tester"
        })
        assert reg_b.status_code == 201, f"User B registration failed: {reg_b.text}"
        cls.user_b = reg_b.json()
        cls.auth_headers_b = {"Authorization": f"Bearer {cls.user_b['access_token']}"}

    def _create_project_and_finding(self, headers, finding_name="SQL Injection in Order API", priority="HIGH"):
        p_res = self.client.post("/api/projects", headers=headers, json={
            "name": f"Retest Test Project {uuid.uuid4().hex[:6]}",
            "target_url": "https://target.tracegate.local",
            "description": "Project for retest verification tests",
            "assessment_type": "web"
        })
        self.assertEqual(p_res.status_code, 201)
        proj = p_res.json()
        proj_id = proj["id"]

        f_res = self.client.post(
            f"/api/projects/{proj_id}/checklist/item-test/finding",
            headers=headers,
            json={
                "finding_name": finding_name,
                "priority": priority,
                "cwe": "CWE-89",
                "affected_endpoint": "/orders",
                "description": "SQL injection in order parameter",
                "poc_text": "' OR 1=1 --",
                "remediation": "Use parameterized queries"
            }
        )
        self.assertEqual(f_res.status_code, 201)
        finding = f_res.json()
        return proj_id, finding["id"]

    def test_01_logged_out_retest_rejected_with_401(self):
        """Unauthenticated PASS request on user-owned project must return 401 Unauthorized."""
        proj_id, finding_id = self._create_project_and_finding(self.auth_headers_a)

        # No Authorization header
        res = self.client.post(
            f"/api/ai-fix/{finding_id}/retest",
            json={"finding_id": finding_id, "result": "PASS", "notes": "all tests done"}
        )
        self.assertEqual(res.status_code, 401)
        self.assertIn("Authentication required", res.text)

        # Confirm finding status was NOT modified
        finding = db.get_finding_by_id(finding_id)
        self.assertNotEqual(finding["status"].upper(), "RESOLVED")

    def test_02_logged_in_own_finding_pass_retest_success(self):
        """Authenticated PASS request on own finding transitions to RESOLVED and retest_status PASSED."""
        proj_id, finding_id = self._create_project_and_finding(self.auth_headers_a)

        res = self.client.post(
            f"/api/ai-fix/{finding_id}/retest",
            headers=self.auth_headers_a,
            json={
                "finding_id": finding_id,
                "result": "PASS",
                "notes": "all tests done"
            }
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data["status"], "RESOLVED")
        self.assertEqual(data["retest_status"], "PASSED")
        self.assertEqual(data["notes"], "all tests done")

        # Confirm persisted in database
        persisted = db.get_finding_by_id(finding_id)
        self.assertEqual(persisted["status"], "RESOLVED")
        self.assertEqual(persisted["retest_status"], "PASSED")
        self.assertEqual(persisted["retest_notes"], "all tests done")

    def test_03_cross_user_retest_rejected_with_404(self):
        """User B cannot retest User A's finding (returns 404 Not Found)."""
        proj_id, finding_id_a = self._create_project_and_finding(self.auth_headers_a)

        # User B attempts to retest User A's finding
        res = self.client.post(
            f"/api/ai-fix/{finding_id_a}/retest",
            headers=self.auth_headers_b,
            json={"finding_id": finding_id_a, "result": "PASS", "notes": "unauthorized retest"}
        )
        self.assertEqual(res.status_code, 404)

        # Confirm User A's finding is untouched
        finding_a = db.get_finding_by_id(finding_id_a)
        self.assertNotEqual(finding_a["status"].upper(), "RESOLVED")
        self.assertNotEqual(finding_a["retest_notes"], "unauthorized retest")

    def test_04_server_side_idempotency_duplicate_pass_retest(self):
        """Repeated identical PASS retest requests succeed idempotently without duplicate records."""
        proj_id, finding_id = self._create_project_and_finding(self.auth_headers_a)

        # First PASS
        res1 = self.client.post(
            f"/api/ai-fix/{finding_id}/retest",
            headers=self.auth_headers_a,
            json={"finding_id": finding_id, "result": "PASS", "notes": "initial pass"}
        )
        self.assertEqual(res1.status_code, 200)

        # Rapid duplicate PASS 1
        res2 = self.client.post(
            f"/api/ai-fix/{finding_id}/retest",
            headers=self.auth_headers_a,
            json={"finding_id": finding_id, "result": "PASS", "notes": "duplicate pass 1"}
        )
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.json()["status"], "RESOLVED")

        # Rapid duplicate PASS 2
        res3 = self.client.post(
            f"/api/ai-fix/{finding_id}/retest",
            headers=self.auth_headers_a,
            json={"finding_id": finding_id, "result": "PASS", "notes": "duplicate pass 2"}
        )
        self.assertEqual(res3.status_code, 200)
        self.assertEqual(res3.json()["status"], "RESOLVED")

        # Verify only one finding exists in project
        findings = db.get_project_findings_list(proj_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "RESOLVED")
        self.assertEqual(findings[0]["retest_status"], "PASSED")

    def test_05_single_finding_pass_retest_triggers_certificate(self):
        """In a 1-finding project, PASS retest triggers 100% eligibility and generates certificate."""
        proj_id, finding_id = self._create_project_and_finding(self.auth_headers_a)

        res = self.client.post(
            f"/api/ai-fix/{finding_id}/retest",
            headers=self.auth_headers_a,
            json={"finding_id": finding_id, "result": "PASS", "notes": "all tests done"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("certificate_eligible"))
        self.assertIsNotNone(data.get("certificate"))
        cert = data["certificate"]
        self.assertIn("TG-VAPT-", cert["certificate_id"])
        self.assertEqual(cert["status"], "VALID")
        self.assertEqual(cert["findings_passed"], 1)

    def test_06_multi_finding_partial_retest_does_not_trigger_cert(self):
        """In a 2-finding project, passing only finding 1 leaves certificate NOT eligible with reason."""
        proj_id, f1 = self._create_project_and_finding(self.auth_headers_a, finding_name="Finding 1", priority="CRITICAL")

        # Add second finding
        f2_res = self.client.post(
            f"/api/projects/{proj_id}/checklist/item-test2/finding",
            headers=self.auth_headers_a,
            json={
                "finding_name": "Finding 2 - Stored XSS",
                "priority": "HIGH",
                "cwe": "CWE-79",
                "affected_endpoint": "/comments",
                "description": "Stored XSS in user comments"
            }
        )
        f2 = f2_res.json()["id"]

        # Retest finding 1 only
        res = self.client.post(
            f"/api/ai-fix/{f1}/retest",
            headers=self.auth_headers_a,
            json={"finding_id": f1, "result": "PASS", "notes": "Finding 1 retested"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "RESOLVED")
        self.assertEqual(data["retest_status"], "PASSED")
        self.assertFalse(data.get("certificate_eligible"))
        self.assertIsNone(data.get("certificate"))
        self.assertIn("1 in-scope finding(s) remain", data.get("blocking_reason", ""))

    def test_07_multi_finding_final_pass_retest_triggers_cert(self):
        """Passing the final remaining finding triggers certificate generation."""
        proj_id, f1 = self._create_project_and_finding(self.auth_headers_a, finding_name="Finding 1", priority="CRITICAL")
        f2_res = self.client.post(
            f"/api/projects/{proj_id}/checklist/item-test2/finding",
            headers=self.auth_headers_a,
            json={
                "finding_name": "Finding 2 - Stored XSS",
                "priority": "HIGH",
                "cwe": "CWE-79",
                "affected_endpoint": "/comments"
            }
        )
        f2 = f2_res.json()["id"]

        # Pass finding 1
        self.client.post(
            f"/api/ai-fix/{f1}/retest",
            headers=self.auth_headers_a,
            json={"finding_id": f1, "result": "PASS"}
        )

        # Pass finding 2 (final finding)
        res = self.client.post(
            f"/api/ai-fix/{f2}/retest",
            headers=self.auth_headers_a,
            json={"finding_id": f2, "result": "PASS", "notes": "all tests completed"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("certificate_eligible"))
        self.assertIsNotNone(data.get("certificate"))
        cert = data["certificate"]
        self.assertEqual(cert["total_findings"], 2)
        self.assertEqual(cert["findings_passed"], 2)

    def test_08_fail_retest_transitions_to_reopened(self):
        """Retest with result="FAIL" transitions finding to REOPENED and does not generate certificate."""
        proj_id, finding_id = self._create_project_and_finding(self.auth_headers_a)

        res = self.client.post(
            f"/api/ai-fix/{finding_id}/retest",
            headers=self.auth_headers_a,
            json={"finding_id": finding_id, "result": "FAIL", "notes": "Exploit still works"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "REOPENED")
        self.assertEqual(data["retest_status"], "FAILED")
        self.assertFalse(data.get("certificate_eligible"))
        self.assertIsNone(data.get("certificate"))

        persisted = db.get_finding_by_id(finding_id)
        self.assertEqual(persisted["status"], "REOPENED")
        self.assertEqual(persisted["retest_status"], "FAILED")
        self.assertEqual(persisted["retest_notes"], "Exploit still works")

    def test_09_certificate_generation_failure_does_not_block_retest(self):
        """If certificate generation encounters an error, retest must remain successful (PASSED / RESOLVED)."""
        proj_id, finding_id = self._create_project_and_finding(self.auth_headers_a)

        # Monkey-patch generate_assessment_certificate to simulate a failure
        import backend.app as b_app
        orig_app_gen = b_app.generate_assessment_certificate
        orig_svc_gen = certificate_service.generate_assessment_certificate

        def mock_failing_gen(p_id):
            return {"success": False, "error": "Simulated PDF generation service unavailable"}

        try:
            b_app.generate_assessment_certificate = mock_failing_gen
            certificate_service.generate_assessment_certificate = mock_failing_gen

            res = self.client.post(
                f"/api/ai-fix/{finding_id}/retest",
                headers=self.auth_headers_a,
                json={"finding_id": finding_id, "result": "PASS", "notes": "tests passed"}
            )
            self.assertEqual(res.status_code, 200)
            data = res.json()
            # Retest MUST be successful
            self.assertEqual(data["result"], "PASSED")
            self.assertEqual(data["status"], "RESOLVED")
            self.assertEqual(data["retest_status"], "PASSED")
            self.assertIsNone(data.get("certificate"))
            self.assertIn("Simulated PDF generation service unavailable", data.get("blocking_reason", ""))

            # Confirm DB state is genuinely RESOLVED
            persisted = db.get_finding_by_id(finding_id)
            self.assertEqual(persisted["status"], "RESOLVED")
            self.assertEqual(persisted["retest_status"], "PASSED")
        finally:
            b_app.generate_assessment_certificate = orig_app_gen
            certificate_service.generate_assessment_certificate = orig_svc_gen

    def test_10_tester_notes_persisted_correctly(self):
        """Tester notes entered by user ('all tests done') are persisted and preserved."""
        proj_id, finding_id = self._create_project_and_finding(self.auth_headers_a)

        res = self.client.post(
            f"/api/ai-fix/{finding_id}/retest",
            headers=self.auth_headers_a,
            json={"finding_id": finding_id, "result": "PASS", "notes": "all tests done"}
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["notes"], "all tests done")

        finding = db.get_finding_by_id(finding_id)
        self.assertEqual(finding["retest_notes"], "all tests done")


if __name__ == "__main__":
    unittest.main()
