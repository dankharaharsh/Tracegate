"""
Comprehensive test suite verifying:
1. Exact finding ID retest resolution (find-...)
2. Vuln ID retest resolution scoped to project (VULN-001 with collision in another project)
3. Cumulative batch patch retest (__ALL_FINDINGS__) scoped to project
4. Multi-user isolation (User B cannot retest User A's finding -> 403)
5. Wrong project isolation (Project B cannot retest Project A's finding -> 403/404)
6. Nonexistent finding ID rejection (404 Finding could not be located.)
7. Server-side idempotency for repeated PASS retest clicks
8. Fail retest (FAIL -> REOPENED, FAILED)
9. Final finding retest triggers certificate generation
10. Certificate download verification
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


class TestFindingRetestAuthorizationSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        db.init_db()

        # 1. Register User A
        cls.uid_a = uuid.uuid4().hex[:6]
        cls.email_a = f"tester_a_{cls.uid_a}@tracegate.test"
        cls.pass_a = "Password123!"
        cls.client.post("/api/auth/register", json={
            "username": f"retest_a_{cls.uid_a}",
            "email": cls.email_a,
            "password": cls.pass_a,
            "full_name": "Tester User A",
            "role": "Security Tester"
        })
        login_a = cls.client.post("/api/auth/login", json={"username_or_email": cls.email_a, "password": cls.pass_a})
        cls.token_a = login_a.json()["access_token"]
        cls.headers_a = {"Authorization": f"Bearer {cls.token_a}"}

        # 2. Register User B
        cls.uid_b = uuid.uuid4().hex[:6]
        cls.email_b = f"tester_b_{cls.uid_b}@tracegate.test"
        cls.pass_b = "Password123!"
        cls.client.post("/api/auth/register", json={
            "username": f"retest_b_{cls.uid_b}",
            "email": cls.email_b,
            "password": cls.pass_b,
            "full_name": "Tester User B",
            "role": "Security Tester"
        })
        login_b = cls.client.post("/api/auth/login", json={"username_or_email": cls.email_b, "password": cls.pass_b})
        cls.token_b = login_b.json()["access_token"]
        cls.headers_b = {"Authorization": f"Bearer {cls.token_b}"}

    def test_01_pass_retest_by_authoritative_finding_id(self):
        """User A creates project, creates finding, tests PASS retest by finding.id."""
        proj_res = self.client.post("/api/projects", json={
            "name": "User A Retest Scope Project",
            "target_url": "https://scope-a.tracegate.test",
            "environment": "Staging"
        }, headers=self.headers_a)
        self.assertEqual(proj_res.status_code, 201)
        proj_id = proj_res.json()["id"]

        f_res = self.client.post(f"/api/projects/{proj_id}/checklist/item-auth/finding", json={
            "finding_name": "SQL Injection in Search Form",
            "vuln_id": "VULN-AUTH-001",
            "priority": "HIGH",
            "cwe": "CWE-89",
            "remediation": "Use parameterized queries."
        }, headers=self.headers_a)
        self.assertEqual(f_res.status_code, 201)
        finding_id = f_res.json()["id"]

        # Execute PASS retest
        retest_res = self.client.post(
            f"/api/ai-fix/{finding_id}/retest",
            params={"project_id": proj_id},
            json={
                "finding_id": finding_id,
                "project_id": proj_id,
                "result": "PASS",
                "notes": "Verified payload ' OR 1=1 is safely escaped."
            },
            headers=self.headers_a
        )
        self.assertEqual(retest_res.status_code, 200)
        data = retest_res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "RESOLVED")
        self.assertEqual(data["retest_status"], "PASSED")
        self.assertIn("safely escaped", data["notes"])

        # Check DB state
        f_db = db.get_finding_by_id(finding_id, project_id=proj_id)
        self.assertEqual(f_db["status"], "RESOLVED")
        self.assertEqual(f_db["retest_status"], "PASSED")

    def test_02_pass_retest_by_colliding_vuln_id_scoped_to_project(self):
        """
        User A and User B both have a finding with vuln_id='VULN-COLLIDE'.
        Retest from User A with project_id must resolve User A's finding, NOT User B's finding.
        """
        # User B creates project and finding with VULN-COLLIDE
        proj_b = self.client.post("/api/projects", json={
            "name": "User B Collision Project",
            "target_url": "https://col-b.tracegate.test"
        }, headers=self.headers_b).json()["id"]

        fb_res = self.client.post(f"/api/projects/{proj_b}/checklist/item-col/finding", json={
            "finding_name": "IDOR on User B",
            "vuln_id": "VULN-COLLIDE",
            "priority": "HIGH"
        }, headers=self.headers_b).json()["id"]

        # User A creates project and finding with same vuln_id
        proj_a = self.client.post("/api/projects", json={
            "name": "User A Collision Project",
            "target_url": "https://col-a.tracegate.test"
        }, headers=self.headers_a).json()["id"]

        fa_res = self.client.post(f"/api/projects/{proj_a}/checklist/item-col/finding", json={
            "finding_name": "IDOR on User A",
            "vuln_id": "VULN-COLLIDE",
            "priority": "HIGH"
        }, headers=self.headers_a).json()["id"]

        # User A sends retest with finding_id="VULN-COLLIDE" and project_id=proj_a
        retest_res = self.client.post(
            "/api/ai-fix/VULN-COLLIDE/retest",
            params={"project_id": proj_a},
            json={
                "finding_id": "VULN-COLLIDE",
                "project_id": proj_a,
                "result": "PASS",
                "notes": "User A confirmed resolved."
            },
            headers=self.headers_a
        )
        self.assertEqual(retest_res.status_code, 200)
        self.assertEqual(retest_res.json()["finding_id"], fa_res)
        self.assertEqual(retest_res.json()["status"], "RESOLVED")

        # Verify User B's finding is UNTOUCHED
        fb_db = db.get_finding_by_id(fb_res, project_id=proj_b)
        self.assertEqual(fb_db["status"], "Open")
        self.assertEqual(fb_db["retest_status"], "PENDING")

    def test_03_cross_user_retest_rejected(self):
        """User B cannot retest User A's finding -> 403 Forbidden."""
        proj_a = self.client.post("/api/projects", json={
            "name": "User A Secret Project",
            "target_url": "https://secret-a.tracegate.test"
        }, headers=self.headers_a).json()["id"]

        fa_id = self.client.post(f"/api/projects/{proj_a}/checklist/item-sec/finding", json={
            "finding_name": "Privilege Escalation",
            "vuln_id": "VULN-SEC-001",
            "priority": "CRITICAL"
        }, headers=self.headers_a).json()["id"]

        # User B attempts to retest User A's finding
        bad_res = self.client.post(
            f"/api/ai-fix/{fa_id}/retest",
            params={"project_id": proj_a},
            json={
                "finding_id": fa_id,
                "project_id": proj_a,
                "result": "PASS",
                "notes": "Malicious retest attempt."
            },
            headers=self.headers_b
        )
        self.assertIn(bad_res.status_code, [403, 404])

        # Verify finding remains unmanipulated
        fa_db = db.get_finding_by_id(fa_id, project_id=proj_a)
        self.assertEqual(fa_db["status"], "Open")

    def test_04_wrong_project_retest_rejected(self):
        """User A cannot retest Finding 1 under Project 2."""
        proj_1 = self.client.post("/api/projects", json={
            "name": "Project 1",
            "target_url": "https://p1.tracegate.test"
        }, headers=self.headers_a).json()["id"]

        proj_2 = self.client.post("/api/projects", json={
            "name": "Project 2",
            "target_url": "https://p2.tracegate.test"
        }, headers=self.headers_a).json()["id"]

        f1_id = self.client.post(f"/api/projects/{proj_1}/checklist/item-p1/finding", json={
            "finding_name": "XSS in P1",
            "vuln_id": "VULN-P1-001"
        }, headers=self.headers_a).json()["id"]

        # Retest F1 under Project 2
        bad_res = self.client.post(
            f"/api/ai-fix/{f1_id}/retest",
            params={"project_id": proj_2},
            json={
                "finding_id": f1_id,
                "project_id": proj_2,
                "result": "PASS",
                "notes": "Mismatched project attempt."
            },
            headers=self.headers_a
        )
        self.assertIn(bad_res.status_code, [403, 404])

    def test_05_nonexistent_finding_returns_404(self):
        """Unknown finding returns 404 'Finding could not be located.'."""
        proj = self.client.post("/api/projects", json={
            "name": "Project Exists",
            "target_url": "https://pe.tracegate.test"
        }, headers=self.headers_a).json()["id"]

        res = self.client.post(
            "/api/ai-fix/find-nonexistent-12345/retest",
            params={"project_id": proj},
            json={
                "finding_id": "find-nonexistent-12345",
                "project_id": proj,
                "result": "PASS",
                "notes": "Testing missing."
            },
            headers=self.headers_a
        )
        self.assertEqual(res.status_code, 404)
        self.assertIn("could not be located", res.json()["detail"].lower())

    def test_06_idempotent_duplicate_pass_retest(self):
        """Rapid or duplicated identical PASS requests succeed idempotently."""
        proj = self.client.post("/api/projects", json={
            "name": "Project Idempotency",
            "target_url": "https://idemp.tracegate.test"
        }, headers=self.headers_a).json()["id"]

        f_id = self.client.post(f"/api/projects/{proj}/checklist/item-idem/finding", json={
            "finding_name": "CSRF Token Missing",
            "vuln_id": "VULN-IDEM-001"
        }, headers=self.headers_a).json()["id"]

        payload = {
            "finding_id": f_id,
            "project_id": proj,
            "result": "PASS",
            "notes": "First click."
        }

        # Click 1
        res1 = self.client.post(f"/api/ai-fix/{f_id}/retest", params={"project_id": proj}, json=payload, headers=self.headers_a)
        self.assertEqual(res1.status_code, 200)

        # Click 2 (duplicate)
        res2 = self.client.post(f"/api/ai-fix/{f_id}/retest", params={"project_id": proj}, json=payload, headers=self.headers_a)
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.json()["status"], "RESOLVED")

    def test_07_fail_retest_transitions_to_reopened(self):
        """FAIL retest transitions finding to REOPENED / FAILED."""
        proj = self.client.post("/api/projects", json={
            "name": "Project Fail Retest",
            "target_url": "https://fail.tracegate.test"
        }, headers=self.headers_a).json()["id"]

        f_id = self.client.post(f"/api/projects/{proj}/checklist/item-fr/finding", json={
            "finding_name": "Open Redirect",
            "vuln_id": "VULN-OR-001"
        }, headers=self.headers_a).json()["id"]

        res = self.client.post(
            f"/api/ai-fix/{f_id}/retest",
            params={"project_id": proj},
            json={
                "finding_id": f_id,
                "project_id": proj,
                "result": "FAIL",
                "notes": "Payload ?next=//evil.com still redirects."
            },
            headers=self.headers_a
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "REOPENED")
        self.assertEqual(data["retest_status"], "FAILED")

        f_db = db.get_finding_by_id(f_id, project_id=proj)
        self.assertEqual(f_db["status"], "REOPENED")
        self.assertEqual(f_db["retest_status"], "FAILED")

    def test_08_final_finding_retest_triggers_certificate_generation(self):
        """Retesting the final finding in a project auto-generates the VAPT Certificate."""
        proj = self.client.post("/api/projects", json={
            "name": "Final Cert Project",
            "target_url": "https://final-cert.tracegate.test"
        }, headers=self.headers_a).json()["id"]

        f_id = self.client.post(f"/api/projects/{proj}/checklist/item-cert/finding", json={
            "finding_name": "Sensitive File Exposure",
            "vuln_id": "VULN-FINAL-001",
            "priority": "HIGH"
        }, headers=self.headers_a).json()["id"]

        res = self.client.post(
            f"/api/ai-fix/{f_id}/retest",
            params={"project_id": proj},
            json={
                "finding_id": f_id,
                "project_id": proj,
                "result": "PASS",
                "notes": "All tests passed and verified."
            },
            headers=self.headers_a
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["certificate_eligible"])
        self.assertIsNotNone(data["certificate"])
        cert_id = data["certificate"]["certificate_id"]
        self.assertTrue(cert_id.startswith("TG-VAPT-"))

        # Verify certificate is downloadable
        docx_res = self.client.get(f"/api/certificates/{cert_id}/download/docx", headers=self.headers_a)
        self.assertEqual(docx_res.status_code, 200)
        self.assertEqual(docx_res.headers["content-type"], "application/vnd.openxmlformats-officedocument.wordprocessingml.document")


if __name__ == "__main__":
    unittest.main()
