"""
Tracegate - GitHub Repository Visibility, Automatic Discovery, and User Isolation Suite.
Verifies:
1. Disconnected user sees empty repository list ([]), never demo fallbacks.
2. Disconnected user cannot access repository tree (empty tree, error).
3. Disconnected user cannot access repository files (empty, error).
4. Disconnected user cannot list branches ([]).
5. Disconnect clears user state immediately and enforces isolation.
6. Live mode returns only authenticated user's real repos (never tracegate-lab/* demo fixtures).
7. Custom repository flow routes to user-specified repo without demo fallbacks.
8. Automatic discovery endpoints reject disconnected user (NOT_CONNECTED, confidence=0).
9. User A logout -> User B login isolation (User B has zero leakage of User A's repositories).
10. Relogin restores user-specific connection only.
"""

import unittest
import time
from unittest.mock import patch
from fastapi.testclient import TestClient

from backend.app import app
from backend.database import (
    init_db,
    save_user_github_config,
    get_user_github_config,
    delete_project,
    save_finding,
)
from backend.github_service import disconnect_github


class TestGitHubRepoVisibilityAndDiscoverySuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.ts = int(time.time() * 1000)

        # 1. Register User A (Auditor Alpha)
        cls.user_a_email = f"alpha_vis_{cls.ts}@tracegate.test"
        cls.user_a_pass = "AlphaSecure!Pass99"
        res_a = cls.client.post("/api/auth/register", json={
            "username": f"alpha_{cls.ts}",
            "email": cls.user_a_email,
            "password": cls.user_a_pass,
            "full_name": "Alpha Auditor"
        })
        assert res_a.status_code == 201, f"Failed to register User A: {res_a.text}"
        data_a = res_a.json()
        cls.user_a_id = data_a["user"]["id"]
        cls.token_a = data_a["access_token"]
        cls.headers_a = {"Authorization": f"Bearer {cls.token_a}"}

        # 2. Register User B (Auditor Beta)
        cls.user_b_email = f"beta_vis_{cls.ts}@tracegate.test"
        cls.user_b_pass = "BetaSecure!Pass88"
        res_b = cls.client.post("/api/auth/register", json={
            "username": f"beta_{cls.ts}",
            "email": cls.user_b_email,
            "password": cls.user_b_pass,
            "full_name": "Beta Auditor"
        })
        assert res_b.status_code == 201, f"Failed to register User B: {res_b.text}"
        data_b = res_b.json()
        cls.user_b_id = data_b["user"]["id"]
        cls.token_b = data_b["access_token"]
        cls.headers_b = {"Authorization": f"Bearer {cls.token_b}"}

        # 3. Create Project for User A
        res_proj_a = cls.client.post("/api/projects", json={
            "name": f"Project Alpha Vis {cls.ts}",
            "target_url": "https://alpha.corp.test"
        }, headers=cls.headers_a)
        assert res_proj_a.status_code in (200, 201)
        cls.proj_a_id = res_proj_a.json()["id"]

        # 4. Create Project for User B
        res_proj_b = cls.client.post("/api/projects", json={
            "name": f"Project Beta Vis {cls.ts}",
            "target_url": "https://beta.corp.test"
        }, headers=cls.headers_b)
        assert res_proj_b.status_code in (200, 201)
        cls.proj_b_id = res_proj_b.json()["id"]

    @classmethod
    def tearDownClass(cls):
        try:
            delete_project(cls.proj_a_id)
            delete_project(cls.proj_b_id)
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # TEST 1: Disconnected User Sees Empty Repository List
    # -------------------------------------------------------------------------
    def test_01_disconnected_user_sees_empty_repository_list(self):
        # User B starts disconnected
        disconnect_github(self.user_b_id)
        res = self.client.get("/api/github/repositories", headers=self.headers_b)
        self.assertEqual(res.status_code, 200)
        repos = res.json()
        self.assertEqual(repos, [], "Disconnected user must see 0 repositories")
        # Ensure no tracegate-lab demo repos are returned
        repo_names = [r.get("full_name", "") for r in repos]
        self.assertNotIn("tracegate-lab/ecommerce-platform", repo_names)
        self.assertNotIn("tracegate-lab/identity-auth-service", repo_names)

    # -------------------------------------------------------------------------
    # TEST 2: Disconnected User Cannot Access Repository Tree
    # -------------------------------------------------------------------------
    def test_02_disconnected_user_cannot_access_repository_tree(self):
        disconnect_github(self.user_b_id)
        res = self.client.get(
            "/api/github/tree?repo=tracegate-lab/ecommerce-platform&branch=main",
            headers=self.headers_b
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("tree", []), [])
        self.assertIn("error", data)

    # -------------------------------------------------------------------------
    # TEST 3: Disconnected User Cannot Access Repository File
    # -------------------------------------------------------------------------
    def test_03_disconnected_user_cannot_access_repository_file(self):
        disconnect_github(self.user_b_id)
        res = self.client.get(
            "/api/github/file?repository=tracegate-lab/ecommerce-platform&branch=main&path=backend/services/catalogService.py",
            headers=self.headers_b
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("content", ""), "")
        self.assertIn("error", data)

    # -------------------------------------------------------------------------
    # TEST 4: Disconnected User Cannot List Branches
    # -------------------------------------------------------------------------
    def test_04_disconnected_user_cannot_list_branches(self):
        disconnect_github(self.user_b_id)
        res = self.client.get(
            "/api/github/branches?repo=tracegate-lab/ecommerce-platform",
            headers=self.headers_b
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        branches = data.get("branches", data if isinstance(data, list) else [])
        self.assertEqual(branches, [])

    # -------------------------------------------------------------------------
    # TEST 5: Disconnect Clears State Immediately
    # -------------------------------------------------------------------------
    def test_05_disconnect_clears_user_state_and_enforces_isolation(self):
        # Connect User A
        self.client.post("/api/github/connect", json={
            "token": "ghp_TestTokenAlphaActive12345678",
            "username": "alpha-tester",
            "mode": "mock"
        }, headers=self.headers_a)

        # Confirm connected
        st = self.client.get("/api/github/status", headers=self.headers_a).json()
        self.assertTrue(st["connected"])

        # Disconnect User A
        disc_res = self.client.post("/api/github/disconnect", headers=self.headers_a)
        self.assertEqual(disc_res.status_code, 200)

        # Verify disconnected
        st_after = self.client.get("/api/github/status", headers=self.headers_a).json()
        self.assertFalse(st_after["connected"])
        self.assertIsNone(st_after.get("username"))

        # Verify repository list is now empty
        repos = self.client.get("/api/github/repositories", headers=self.headers_a).json()
        self.assertEqual(repos, [])

    # -------------------------------------------------------------------------
    # TEST 6: Live Mode Returns Only Authenticated User Repos (Never Demo Repos)
    # -------------------------------------------------------------------------
    def test_06_live_mode_returns_only_authenticated_user_repos(self):
        # Mock GitHub API returning two user repos
        mock_user_repos = [
            {"name": "production-api", "full_name": "acme/production-api", "default_branch": "main", "private": True, "description": "Acme API"},
            {"name": "frontend-web", "full_name": "acme/frontend-web", "default_branch": "main", "private": False, "description": "Acme Frontend"}
        ]

        with patch("backend.github_service._github_api_request") as mock_api:
            mock_api.side_effect = lambda token, path, method="GET", body=None, timeout=10: (
                (200, mock_user_repos, {}) if "/user/repos" in path else (200, {"login": "acme-auditor"}, {})
            )

            # Connect User A in live mode
            conn_res = self.client.post("/api/github/connect", json={
                "token": "ghp_LiveRealUserToken999988887777",
                "username": "acme-auditor",
                "mode": "live"
            }, headers=self.headers_a)
            self.assertEqual(conn_res.status_code, 200)

            # Fetch repositories
            repos_res = self.client.get("/api/github/repositories", headers=self.headers_a)
            self.assertEqual(repos_res.status_code, 200)
            repos = repos_res.json()
            self.assertEqual(len(repos), 2)
            names = [r["full_name"] for r in repos]
            self.assertIn("acme/production-api", names)
            self.assertIn("acme/frontend-web", names)
            # Must NEVER contain tracegate-lab/* demo repos
            self.assertNotIn("tracegate-lab/ecommerce-platform", names)
            self.assertNotIn("tracegate-lab/identity-auth-service", names)

    # -------------------------------------------------------------------------
    # TEST 7: Custom Repository Flow Routes to Custom Repo Without Fallbacks
    # -------------------------------------------------------------------------
    def test_07_custom_repository_flow_validation(self):
        custom_repo = "org-enterprise/custom-core-service"
        custom_tree = [
            {"path": "src/api/auth.py", "mode": "100644", "type": "blob", "sha": "sha123", "size": 512},
            {"path": "src/db/queries.py", "mode": "100644", "type": "blob", "sha": "sha456", "size": 1024}
        ]

        with patch("backend.github_service._github_api_request") as mock_api:
            def api_dispatch(token, path, method="GET", body=None, timeout=10):
                if f"/repos/{custom_repo}/git/trees" in path:
                    return (200, {"tree": custom_tree, "truncated": False}, {})
                if f"/repos/{custom_repo}/branches" in path:
                    return (200, [{"name": "main"}, {"name": "staging"}], {})
                return (200, {"login": "acme-auditor"}, {})

            mock_api.side_effect = api_dispatch

            # Query tree for custom repository
            tree_res = self.client.get(
                f"/api/github/tree?repo={custom_repo}&branch=main",
                headers=self.headers_a
            )
            self.assertEqual(tree_res.status_code, 200)
            tree_data = tree_res.json()
            paths = [item["path"] for item in tree_data.get("tree", [])]
            self.assertIn("src/api/auth.py", paths)
            self.assertNotIn("server/controllers/userController.js", paths)

    # -------------------------------------------------------------------------
    # TEST 8: Automatic Discovery Endpoint Rejects Disconnected User
    # -------------------------------------------------------------------------
    def test_08_automatic_discovery_endpoint_rejects_disconnected_user(self):
        # Disconnect User B
        disconnect_github(self.user_b_id)

        # Save a finding for User B
        finding_b = save_finding(self.proj_b_id, None, {
            "finding_name": "SQL Injection in Search",
            "vuln_id": f"VULN-DISC-{self.ts}",
            "priority": "CRITICAL",
            "cwe": "CWE-89",
            "status": "CONFIRMED"
        })
        fid_b = finding_b["id"]

        # Call discover-sources
        res_sources = self.client.post("/api/ai-fix/discover-sources", json={
            "project_id": self.proj_b_id,
            "finding_id": fid_b,
            "repository": "tracegate-lab/ecommerce-platform"
        }, headers=self.headers_b)
        self.assertEqual(res_sources.status_code, 200)
        data_sources = res_sources.json()
        self.assertEqual(data_sources["discovery_status"], "NOT_CONNECTED")
        self.assertEqual(data_sources["selected_sources"], [])
        self.assertEqual(data_sources["candidate_sources"], [])

        # Call discover-file
        res_file = self.client.post("/api/ai-fix/discover-file", json={
            "finding_id": fid_b,
            "repository": "tracegate-lab/ecommerce-platform"
        }, headers=self.headers_b)
        self.assertEqual(res_file.status_code, 200)
        data_file = res_file.json()
        self.assertEqual(data_file["discovery_status"], "NOT_CONNECTED")
        self.assertIsNone(data_file["file_path"])
        self.assertEqual(data_file["confidence"], 0.0)

    # -------------------------------------------------------------------------
    # TEST 9: User A Logout -> User B Login Isolation
    # -------------------------------------------------------------------------
    def test_09_user_a_logout_user_b_login_isolation(self):
        # User A is connected with Acme credentials
        st_a = self.client.get("/api/github/status", headers=self.headers_a).json()
        self.assertTrue(st_a["connected"])

        # User B queries status and repos (simulating B logging in)
        st_b = self.client.get("/api/github/status", headers=self.headers_b).json()
        self.assertFalse(st_b["connected"])
        self.assertIsNone(st_b.get("username"))

        repos_b = self.client.get("/api/github/repositories", headers=self.headers_b).json()
        self.assertEqual(repos_b, [])

    # -------------------------------------------------------------------------
    # TEST 10: Relogin Restores User-Specific Connection Only
    # -------------------------------------------------------------------------
    def test_10_relogin_restores_user_specific_connection_only(self):
        # Relogin User A
        login_a = self.client.post("/api/auth/login", json={
            "username_or_email": self.user_a_email,
            "password": self.user_a_pass
        }).json()
        fresh_token_a = login_a["access_token"]
        fresh_headers_a = {"Authorization": f"Bearer {fresh_token_a}"}

        # User A still has their connection
        st_a = self.client.get("/api/github/status", headers=fresh_headers_a).json()
        self.assertTrue(st_a["connected"])
        self.assertEqual(st_a["username"], "acme-auditor")

        # User B remains completely disconnected
        st_b = self.client.get("/api/github/status", headers=self.headers_b).json()
        self.assertFalse(st_b["connected"])
        self.assertIsNone(st_b.get("username"))


if __name__ == "__main__":
    unittest.main()
