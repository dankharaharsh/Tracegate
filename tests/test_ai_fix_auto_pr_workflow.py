"""
Test Suite for AI Fix Auto Pull Request Workflow & Token Fallback Resolution.
Verifies that confirming & committing a fix automatically generates the GitHub PR,
updates database state, links the PR URL, and strictly protects real repos.
"""

import unittest
import time
import uuid
from fastapi.testclient import TestClient

from backend.app import app
from backend.database import (
    get_db_connection,
    create_project,
    save_finding,
    save_user_github_config,
    get_user_github_config
)
from backend.github_service import (
    _MOCK_BRANCH_FILES,
    _MOCK_BRANCHES_STORE,
    _MOCK_PR_STORE,
    create_finding_pull_request
)


class TestAIFixAutoPRWorkflow(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.ts = int(time.time() * 1000)
        self.uid = uuid.uuid4().hex[:6]

        # Register test user
        reg_resp = self.client.post("/api/auth/register", json={
            "username": f"pr_user_{self.uid}",
            "email": f"pr_{self.uid}@tracegate.test",
            "password": "Password123!Secure",
            "full_name": "PR Test User"
        })
        self.assertEqual(reg_resp.status_code, 201)
        self.user_data = reg_resp.json()
        self.token = self.user_data.get("access_token") or self.user_data.get("token")
        self.user_id = self.user_data["user"]["id"]
        self.headers = {"Authorization": f"Bearer {self.token}"}

        # Create user project
        self.proj = create_project({
            "name": f"PR Test Assessment {self.ts}",
            "target_url": "https://api.tracegate.test",
            "environment": "Production",
            "owner_id": self.user_id
        })
        self.proj_id = self.proj["id"]

        # Default lab repo for tests
        self.repo = "tracegate-lab/ecommerce-platform"
        self.branch = "main"

    def test_01_auto_pr_on_apply_creates_pr_and_updates_db(self):
        """1. Calling /api/ai-fix/apply with create_pr=True automatically opens the PR and returns pr_url."""
        # Create confirmed finding
        finding = save_finding(self.proj_id, None, {
            "finding_name": "SQL Injection in Search Endpoint",
            "vuln_id": "VULN-SQLI-001",
            "cwe": "CWE-89",
            "affected_url": "/api/search",
            "file_path": "backend/controllers/searchController.js",
            "priority": "HIGH",
            "status": "CONFIRMED"
        })
        f_id = finding["id"]

        fix_branch_name = f"fix/VULN-SQLI-AUTO-{self.ts}"
        remediated_code = (
            "const db = require('../db');\n"
            "exports.search = async (req, res) => {\n"
            "  const q = req.query.q;\n"
            "  const results = await db.query('SELECT * FROM items WHERE name = $1', [q]);\n"
            "  return res.json(results.rows);\n"
            "};\n"
        )

        # Call apply with create_pr=True
        ap_resp = self.client.post("/api/ai-fix/apply", json={
            "finding_id": f_id,
            "project_id": self.proj_id,
            "repo": self.repo,
            "target_branch": self.branch,
            "fix_branch": fix_branch_name,
            "file_path": "backend/controllers/searchController.js",
            "diff_or_fixed_code": remediated_code,
            "create_pr": True
        }, headers=self.headers)

        self.assertEqual(ap_resp.status_code, 200)
        data = ap_resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["branch_name"], fix_branch_name)
        self.assertIsNotNone(data["pr_url"])
        self.assertIsNotNone(data["pr_number"])
        self.assertIn("pull", data["pr_url"].lower())

        # Verify DB findings record updated to 'PR Created' with github_pr
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT fix_status, github_branch, github_pr FROM findings WHERE id = ?", (f_id,))
        row = c.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["fix_status"], "PR Created")
        self.assertEqual(row["github_branch"], fix_branch_name)
        self.assertEqual(row["github_pr"], data["pr_url"])

    def test_02_apply_with_create_pr_false_does_not_open_pr(self):
        """2. Calling /api/ai-fix/apply with create_pr=False only commits code and sets Fix Applied."""
        finding = save_finding(self.proj_id, None, {
            "finding_name": "Insecure Direct Object Reference",
            "vuln_id": "VULN-IDOR-002",
            "cwe": "CWE-639",
            "affected_url": "/api/users/profile",
            "file_path": "server/controllers/userController.js",
            "priority": "HIGH",
            "status": "CONFIRMED"
        })
        f_id = finding["id"]

        fix_branch_name = f"fix/VULN-IDOR-MANUAL-{self.ts}"
        remediated_code = (
            "exports.getProfile = (req, res) => {\n"
            "  const userId = req.user.id;\n"
            "  return res.json({ id: userId, verified: true });\n"
            "};\n"
        )

        ap_resp = self.client.post("/api/ai-fix/apply", json={
            "finding_id": f_id,
            "project_id": self.proj_id,
            "repo": self.repo,
            "target_branch": self.branch,
            "fix_branch": fix_branch_name,
            "file_path": "server/controllers/userController.js",
            "diff_or_fixed_code": remediated_code,
            "create_pr": False
        }, headers=self.headers)

        self.assertEqual(ap_resp.status_code, 200)
        data = ap_resp.json()
        self.assertTrue(data["success"])
        self.assertIsNone(data.get("pr_url"))

        # Check DB finding is 'Fix Applied'
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT fix_status, github_pr FROM findings WHERE id = ?", (f_id,))
        row = c.fetchone()
        conn.close()

        self.assertEqual(row["fix_status"], "Fix Applied")
        self.assertIsNone(row["github_pr"])

        # Now call create-pr endpoint manually
        pr_resp = self.client.post("/api/ai-fix/create-pr", json={
            "finding_id": f_id,
            "project_id": self.proj_id,
            "repo": self.repo,
            "fix_branch": fix_branch_name,
            "base_branch": self.branch
        }, headers=self.headers)

        self.assertEqual(pr_resp.status_code, 200)
        pr_data = pr_resp.json()
        self.assertTrue(pr_data["success"])
        self.assertIsNotNone(pr_data["pr_url"])

    def test_03_github_config_strict_user_isolation(self):
        """3. get_user_github_config strictly isolates credentials per user; unconfigured user gets None."""
        # Save config under user A
        user_a_id = f"user-a-{self.ts}"
        save_user_github_config(user_a_id, "ghp_userAToken1234567890", "live", "usera-git")

        # Query config for an arbitrary unconfigured user
        cfg_unconfigured = get_user_github_config(f"unconfigured-user-{self.ts}")
        self.assertIsNone(cfg_unconfigured)

        # Query config for user A
        cfg_a = get_user_github_config(user_a_id)
        self.assertIsNotNone(cfg_a)
        self.assertEqual(cfg_a["username"], "usera-git")
        self.assertEqual(cfg_a["token"], "ghp_userAToken1234567890")

    def test_04_real_repo_strictly_blocks_unauthenticated_mock_commits(self):
        """4. Targeting a real repository without valid live GitHub credentials raises GITHUB_AUTH_REQUIRED."""
        # Ensure test user has no live token
        save_user_github_config(self.user_id, None, "mock", None)

        finding = save_finding(self.proj_id, None, {
            "finding_name": "XSS in Comments",
            "vuln_id": "VULN-XSS-003",
            "cwe": "CWE-79",
            "priority": "HIGH",
            "status": "CONFIRMED"
        })

        # Try to apply fix on an external real repository without valid live token
        # Using a mock repo name that is NOT tracegate-lab/*
        real_repo = "some-external-org/production-app"
        ap_resp = self.client.post("/api/ai-fix/apply", json={
            "finding_id": finding["id"],
            "project_id": self.proj_id,
            "repo": real_repo,
            "target_branch": "main",
            "fix_branch": "fix/test",
            "file_path": "app.js",
            "diff_or_fixed_code": "console.log('safe');"
        }, headers=self.headers)

        # Should fail with 400 or 401 or 403 requiring authentication
        self.assertIn(ap_resp.status_code, [400, 401, 403])
        detail = str(ap_resp.json())
        self.assertTrue(
            "GITHUB_AUTH_REQUIRED" in detail or "permission" in detail.lower() or "token" in detail.lower() or "connect" in detail.lower()
        )

    def test_05_duplicate_pr_returns_clean_reused_status(self):
        """5. Calling create_finding_pull_request twice for same branch pair returns cleanly without error."""
        finding = {
            "id": "F-TEST-DUP",
            "vuln_id": "VULN-DUP",
            "finding_name": "Duplicate PR Test",
            "priority": "MEDIUM",
            "cwe": "CWE-20"
        }
        res1 = create_finding_pull_request(
            user_id=self.user_id,
            repo=self.repo,
            fix_branch=f"fix/dup-{self.ts}",
            base_branch="main",
            finding=finding
        )
        self.assertTrue(res1.success)
        pr_num1 = res1.pr_number

        res2 = create_finding_pull_request(
            user_id=self.user_id,
            repo=self.repo,
            fix_branch=f"fix/dup-{self.ts}",
            base_branch="main",
            finding=finding
        )
        self.assertTrue(res2.success)
        self.assertEqual(res2.pr_number, pr_num1)


if __name__ == "__main__":
    unittest.main()
