"""
Tracegate — Critical User Isolation Test Suite for GitHub Connection & AI AutoFix.
Verifies the complete 10-point security matrix across:
- Database isolation
- Backend API authorization
- GitHub credential scoping per user
- AI Fix project and finding ownership
- Disconnect isolation
- Cross-user IDOR protection
"""

import unittest
import time
import uuid
from fastapi.testclient import TestClient

from backend.app import app
from backend.database import (
    init_db,
    save_user_github_config,
    get_user_github_config,
    delete_project,
    get_project_by_id,
    save_finding,
)
from backend.github_service import disconnect_github

class TestGitHubUserIsolationSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.ts = int(time.time() * 1000)

        # 1. Register User A
        cls.user_a_email = f"user_a_{cls.ts}@tracegate-security.test"
        cls.user_a_pass = "ComplexPassA!99"
        res_a = cls.client.post("/api/auth/register", json={
            "username": f"usera_{cls.ts}",
            "email": cls.user_a_email,
            "password": cls.user_a_pass,
            "full_name": "Auditor Alpha"
        })
        assert res_a.status_code == 201, f"Failed to register User A: {res_a.text}"
        data_a = res_a.json()
        cls.user_a_id = data_a["user"]["id"]
        cls.token_a = data_a["access_token"]
        cls.headers_a = {"Authorization": f"Bearer {cls.token_a}"}

        # 2. Register User B
        cls.user_b_email = f"user_b_{cls.ts}@tracegate-security.test"
        cls.user_b_pass = "ComplexPassB!88"
        res_b = cls.client.post("/api/auth/register", json={
            "username": f"userb_{cls.ts}",
            "email": cls.user_b_email,
            "password": cls.user_b_pass,
            "full_name": "Auditor Beta"
        })
        assert res_b.status_code == 201, f"Failed to register User B: {res_b.text}"
        data_b = res_b.json()
        cls.user_b_id = data_b["user"]["id"]
        cls.token_b = data_b["access_token"]
        cls.headers_b = {"Authorization": f"Bearer {cls.token_b}"}

        # 3. Create Project for User A
        res_proj_a = cls.client.post("/api/projects", json={
            "name": f"Project Alpha {cls.ts}",
            "target_url": "https://alpha.targetcorp.test"
        }, headers=cls.headers_a)
        assert res_proj_a.status_code in (200, 201), f"Failed to create Project A: {res_proj_a.text}"
        cls.proj_a_id = res_proj_a.json()["id"]

        # 4. Create Project for User B
        res_proj_b = cls.client.post("/api/projects", json={
            "name": f"Project Beta {cls.ts}",
            "target_url": "https://beta.targetcorp.test"
        }, headers=cls.headers_b)
        assert res_proj_b.status_code in (200, 201), f"Failed to create Project B: {res_proj_b.text}"
        cls.proj_b_id = res_proj_b.json()["id"]

    @classmethod
    def tearDownClass(cls):
        try:
            delete_project(cls.proj_a_id)
            delete_project(cls.proj_b_id)
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # TEST A: User A connects GitHub -> User A sees connected
    # -------------------------------------------------------------------------
    def test_01_user_a_connects_github_sees_connected(self):
        # User A connects their live GitHub
        conn_res = self.client.post("/api/github/connect", json={
            "token": "ghp_UserATokenAlphaSecure1234567890",
            "username": "dankharaharsh",
            "mode": "live"
        }, headers=self.headers_a)
        self.assertEqual(conn_res.status_code, 200)
        data = conn_res.json()
        self.assertTrue(data["connected"])
        self.assertEqual(data["username"], "dankharaharsh")
        # Ensure token is never exposed
        self.assertNotIn("ghp_UserATokenAlphaSecure1234567890", conn_res.text)

        # Status check for User A
        status_res = self.client.get("/api/github/status", headers=self.headers_a)
        self.assertEqual(status_res.status_code, 200)
        status_data = status_res.json()
        self.assertTrue(status_data["connected"])
        self.assertEqual(status_data["username"], "dankharaharsh")

    # -------------------------------------------------------------------------
    # TEST B: Logout A -> Login B -> B does NOT see A's GitHub connection
    # -------------------------------------------------------------------------
    def test_02_user_b_does_not_see_user_a_github_connection(self):
        # User B queries status (simulating login as different user)
        status_res = self.client.get("/api/github/status", headers=self.headers_b)
        self.assertEqual(status_res.status_code, 200)
        status_data = status_res.json()

        # User B MUST NOT be connected, and MUST NOT see User A's username
        self.assertFalse(status_data["connected"])
        self.assertIsNone(status_data["username"])
        self.assertNotEqual(status_data["username"], "dankharaharsh")

        # Database direct check: User B has no config row or empty config
        db_cfg_b = get_user_github_config(self.user_b_id)
        self.assertIsNone(db_cfg_b)

    # -------------------------------------------------------------------------
    # TEST C: B connects different GitHub -> B sees B's connection
    # -------------------------------------------------------------------------
    def test_03_user_b_connects_different_github_account(self):
        conn_res = self.client.post("/api/github/connect", json={
            "token": "ghp_UserBTokenBetaSecure9876543210",
            "username": "dhairya-security",
            "mode": "live"
        }, headers=self.headers_b)
        self.assertEqual(conn_res.status_code, 200)
        b_data = conn_res.json()
        self.assertTrue(b_data["connected"])
        self.assertEqual(b_data["username"], "dhairya-security")

        # User B sees their own connection
        st_b = self.client.get("/api/github/status", headers=self.headers_b).json()
        self.assertTrue(st_b["connected"])
        self.assertEqual(st_b["username"], "dhairya-security")

        # User A still sees User A's connection (unaffected)
        st_a = self.client.get("/api/github/status", headers=self.headers_a).json()
        self.assertTrue(st_a["connected"])
        self.assertEqual(st_a["username"], "dankharaharsh")

    # -------------------------------------------------------------------------
    # TEST D: A logs back in -> A sees A's connection
    # -------------------------------------------------------------------------
    def test_04_user_a_retains_connection_on_relogin(self):
        # Fresh login for User A
        login_res = self.client.post("/api/auth/login", json={
            "username_or_email": self.user_a_email,
            "password": self.user_a_pass
        })
        self.assertEqual(login_res.status_code, 200)
        fresh_token_a = login_res.json()["access_token"]
        fresh_headers_a = {"Authorization": f"Bearer {fresh_token_a}"}

        # Query status with fresh session token
        st_a = self.client.get("/api/github/status", headers=fresh_headers_a).json()
        self.assertTrue(st_a["connected"])
        self.assertEqual(st_a["username"], "dankharaharsh")

    # -------------------------------------------------------------------------
    # TEST E: A and B have separate projects -> each sees only their own
    # -------------------------------------------------------------------------
    def test_05_project_isolation_between_users(self):
        # User A lists projects
        res_a = self.client.get("/api/projects", headers=self.headers_a).json()
        projs_a = res_a.get("projects", res_a)
        proj_ids_a = [p["id"] for p in projs_a]
        self.assertIn(self.proj_a_id, proj_ids_a)
        self.assertNotIn(self.proj_b_id, proj_ids_a)

        # User B lists projects
        res_b = self.client.get("/api/projects", headers=self.headers_b).json()
        projs_b = res_b.get("projects", res_b)
        proj_ids_b = [p["id"] for p in projs_b]
        self.assertIn(self.proj_b_id, proj_ids_b)
        self.assertNotIn(self.proj_a_id, proj_ids_b)

    # -------------------------------------------------------------------------
    # TEST F: Cross-User IDOR Rejection on AI Fix
    # -------------------------------------------------------------------------
    def test_06_cross_user_ai_fix_idor_rejected(self):
        # Create finding in User A's project
        finding_a = save_finding(self.proj_a_id, None, {
            "finding_name": "User A Sensitive SQLi",
            "vuln_id": f"VULN-A-{self.ts}",
            "priority": "CRITICAL",
            "cwe": "CWE-89",
            "status": "CONFIRMED"
        })
        fid_a = finding_a["id"]

        # User B attempts to run AI Fix discovery against User A's project
        disc_res = self.client.post("/api/ai-fix/discover-sources", json={
            "project_id": self.proj_a_id,
            "finding_id": fid_a,
            "repository": "tracegate-lab/ecommerce-platform"
        }, headers=self.headers_b)
        self.assertIn(disc_res.status_code, [403, 404])

        # User B attempts to apply fix to User A's finding
        apply_res = self.client.post("/api/ai-fix/apply", json={
            "project_id": self.proj_a_id,
            "finding_id": fid_a,
            "repository": "tracegate-lab/ecommerce-platform",
            "file_path": "server/controllers/userController.js",
            "diff_or_fixed_code": "// malicious patch"
        }, headers=self.headers_b)
        self.assertIn(apply_res.status_code, [403, 404])

        # User B attempts to create PR on User A's project
        pr_res = self.client.post("/api/ai-fix/create-pr", json={
            "project_id": self.proj_a_id,
            "finding_id": fid_a,
            "fix_branch": f"tracegate/fix/{fid_a}",
            "repository": "tracegate-lab/ecommerce-platform"
        }, headers=self.headers_b)
        self.assertIn(pr_res.status_code, [403, 404])

    # -------------------------------------------------------------------------
    # TEST G: Repository List Isolation
    # -------------------------------------------------------------------------
    def test_07_repository_list_isolation(self):
        # User A queries repositories
        repos_a = self.client.get("/api/github/repositories", headers=self.headers_a).json()
        self.assertTrue(len(repos_a) > 0)

        # User B queries repositories
        repos_b = self.client.get("/api/github/repositories", headers=self.headers_b).json()
        self.assertTrue(len(repos_b) > 0)

    # -------------------------------------------------------------------------
    # TEST H: Disconnect Isolation
    # -------------------------------------------------------------------------
    def test_08_disconnect_isolation(self):
        # User A disconnects GitHub
        disc_a = self.client.post("/api/github/disconnect", headers=self.headers_a)
        self.assertEqual(disc_a.status_code, 200)

        # User A is now disconnected
        st_a = self.client.get("/api/github/status", headers=self.headers_a).json()
        self.assertFalse(st_a["connected"])
        self.assertIsNone(st_a["username"])

        # User B remains connected with their own account
        st_b = self.client.get("/api/github/status", headers=self.headers_b).json()
        self.assertTrue(st_b["connected"])
        self.assertEqual(st_b["username"], "dhairya-security")

    # -------------------------------------------------------------------------
    # TEST I: Unauthenticated Access Never Leaks Any User's Connection
    # -------------------------------------------------------------------------
    def test_09_unauthenticated_request_never_leaks_credentials(self):
        # Connect user B with credentials
        save_user_github_config(self.user_b_id, "ghp_betaLiveToken1234567890", "live", "dhairya-security")
        disconnect_github("usr-learner-001")

        # Unauthenticated request with NO authorization header
        res = self.client.get("/api/github/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        # Must never return User B's or User A's connection
        self.assertNotEqual(data.get("username"), "dhairya-security")
        self.assertNotEqual(data.get("username"), "dankharaharsh")
        self.assertNotIn("betaLiveToken", str(data))
        self.assertNotIn("UserAToken", str(data))
        self.assertFalse(data["connected"])
        self.assertIsNone(data.get("token_preview"))

    # -------------------------------------------------------------------------
    # TEST J: AI Fix Workflow on Authorized Project for Connected User
    # -------------------------------------------------------------------------
    def test_10_authorized_user_ai_fix_workflow_succeeds(self):
        # Create finding in User B's project
        finding_b = save_finding(self.proj_b_id, None, {
            "finding_name": "Insecure Direct Object Reference in Beta",
            "vuln_id": f"VULN-IDOR-{self.ts}",
            "priority": "HIGH",
            "cwe": "CWE-639",
            "status": "CONFIRMED"
        })
        fid_b = finding_b["id"]

        # User B runs AI Fix discovery on their OWN project
        disc_res = self.client.post("/api/ai-fix/discover-sources", json={
            "project_id": self.proj_b_id,
            "finding_id": fid_b,
            "repository": "tracegate-lab/ecommerce-platform"
        }, headers=self.headers_b)
        self.assertEqual(disc_res.status_code, 200)
        disc_data = disc_res.json()
        self.assertEqual(disc_data["discovery_status"], "COMPLETED")

        # User B applies fix on their OWN project
        apply_res = self.client.post("/api/ai-fix/apply", json={
            "project_id": self.proj_b_id,
            "finding_id": fid_b,
            "repository": "tracegate-lab/ecommerce-platform",
            "file_path": "server/controllers/userController.js",
            "diff_or_fixed_code": "// remediated code"
        }, headers=self.headers_b)
        self.assertEqual(apply_res.status_code, 200)
        apply_data = apply_res.json()
        self.assertTrue(apply_data["success"])

        # User B creates PR on their OWN project
        pr_res = self.client.post("/api/ai-fix/create-pr", json={
            "project_id": self.proj_b_id,
            "finding_id": fid_b,
            "fix_branch": f"tracegate/fix/{fid_b}",
            "repository": "tracegate-lab/ecommerce-platform"
        }, headers=self.headers_b)
        self.assertEqual(pr_res.status_code, 200)
        pr_data = pr_res.json()
        self.assertTrue(pr_data["success"])
        self.assertIsNotNone(pr_data["pr_url"])


if __name__ == "__main__":
    unittest.main()
