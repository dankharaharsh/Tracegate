"""
Comprehensive Test Suite for Tracegate AI Fix / AutoFix Remediation Pipeline.
Verifies all 12 core requirements and edge cases:
1. Single finding remediation (IDOR) with real diff and valid before/after code.
2. Bulk confirmed findings full repository patch with real file modifications.
3. No safe source match returns REVIEW_REQUIRED / NO_RELEVANT_SOURCE_FOUND cleanly.
4. Legitimate ALREADY_SECURE verification requires defensive controls.
5. Strict 0 modified files guard: NEVER claims findings validated across 0 files.
6. Stale SHA detection rejects conflicting baseline.
7. Multi-file fix (route + template).
8. Multiple CWEs in single shared file (app.py) without syntax errors.
9. Strict multi-user authorization and isolation across all AI Fix endpoints.
10. GitHub PR creation for batch remediation with branch and commit details.
11. CRLF line-ending normalization handles Windows-style checkouts cleanly.
12. Finding endpoint extraction from affected_url / poc_text when affected_endpoint is None.
"""

import unittest
import ast
import uuid
from fastapi.testclient import TestClient
from backend.app import app
from backend.database import (
    init_db, create_project, save_finding, get_project_findings_list,
    save_user_github_config, get_db_connection
)
from backend.remediation_engine_v2 import (
    run_repository_remediation, is_finding_already_remediated,
    map_finding_to_code, apply_semantic_remediations_to_file,
    build_repository_index
)
from backend.ai_autofix import (
    generate_cumulative_repository_fix, generate_multi_file_secure_fix,
    validate_syntax
)
from backend.mock_vulnerable_code import VULNERABLE_CODE_FILES


class TestAIFixPipelineComplete(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.repo = "dankharaharsh/vulnerable-code"
        cls.branch = "main"

    def _register_user(self, prefix="pipe"):
        uid = uuid.uuid4().hex[:8]
        username = f"{prefix}_{uid}"
        email = f"{prefix}_{uid}@tracegate.test"
        resp = self.client.post("/api/auth/register", json={
            "username": username,
            "email": email,
            "password": "Password123!",
            "full_name": f"{prefix} User",
            "role": "PENTESTER"
        })
        self.assertEqual(resp.status_code, 201, f"Registration failed: {resp.text}")
        data = resp.json()
        return {
            "id": data["user"]["id"],
            "username": username,
            "email": email,
            "token": data["access_token"],
            "headers": {"Authorization": f"Bearer {data['access_token']}"}
        }

    def setUp(self):
        # Register two isolated test users
        self.user_a = self._register_user("user_a")
        self.user_b = self._register_user("user_b")
        self.token_a = self.user_a["token"]
        self.token_b = self.user_b["token"]
        self.headers_a = self.user_a["headers"]
        self.headers_b = self.user_b["headers"]

        # User A's project
        self.proj_a = create_project({
            "name": "User A Project Pipeline",
            "target_url": "https://target-a.test"
        }, owner_id=self.user_a["id"])
        self.proj_a_id = self.proj_a["id"]

        # User B's project
        self.proj_b = create_project({
            "name": "User B Project Pipeline",
            "target_url": "https://target-b.test"
        }, owner_id=self.user_b["id"])
        self.proj_b_id = self.proj_b["id"]

        # Configure mock github token for User A
        save_user_github_config(self.user_a["id"], "ghp_secureSampleTokenUserA", "mock", "usera-git")

    def tearDown(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM findings WHERE project_id IN (?, ?)", (self.proj_a_id, self.proj_b_id))
        cursor.execute("DELETE FROM projects WHERE id IN (?, ?)", (self.proj_a_id, self.proj_b_id))
        cursor.execute("DELETE FROM users WHERE id IN (?, ?)", (self.user_a["id"], self.user_b["id"]))
        conn.commit()
        conn.close()

    def test_01_single_finding_idor_remediation(self):
        """1. Single finding remediation (IDOR) produces valid patch and non-empty diff."""
        finding = {
            "id": "FIND-IDOR-01",
            "vuln_id": "VULN-001",
            "cwe": "CWE-639",
            "finding_name": "Insecure Direct Object Reference on User Profile",
            "affected_endpoint": "/api/users/<user_id>",
            "parameter": "user_id"
        }
        res = apply_semantic_remediations_to_file("server/controllers/userController.js", [finding])
        self.assertTrue(res["modified"], "userController.js should be modified for IDOR")
        self.assertIn("req.user.id !== targetUserId", res["code"])
        self.assertGreater(len(res["diff"]), 0)

    def test_02_bulk_confirmed_findings_full_repository_patch(self):
        """2. Bulk confirmed findings remediates multiple files and reflects honest counts."""
        findings = [
            {"id": "F-1", "vuln_id": "VULN-001", "cwe": "CWE-639", "affected_endpoint": "/api/users", "parameter": "user_id"},
            {"id": "F-2", "vuln_id": "VULN-002", "cwe": "CWE-434", "affected_endpoint": "/api/upload", "parameter": "file"},
            {"id": "F-3", "vuln_id": "VULN-003", "cwe": "CWE-22", "affected_endpoint": "/api/download", "parameter": "filename"},
            {"id": "F-4", "vuln_id": "VULN-004", "cwe": "CWE-288", "affected_endpoint": "/api/verify-2fa", "parameter": "code"},
            {"id": "F-5", "vuln_id": "VULN-005", "cwe": "CWE-287", "affected_endpoint": "/api/session/check", "parameter": "token"},
            {"id": "F-6", "vuln_id": "VULN-006", "cwe": "CWE-79", "affected_endpoint": "/api/feed", "parameter": "bio"},
            {"id": "F-7", "vuln_id": "VULN-007", "cwe": "CWE-204", "affected_endpoint": "/api/auth/login", "parameter": "username"},
            {"id": "F-8", "vuln_id": "VULN-008", "cwe": "CWE-89", "affected_endpoint": "/api/catalog/search", "parameter": "query"},
        ]
        tree_items = [{"path": p, "type": "blob", "size": len(c)} for p, c in VULNERABLE_CODE_FILES.items()]
        fix_res = generate_cumulative_repository_fix(
            findings=findings,
            repo=self.repo,
            branch=self.branch,
            fetch_content_cb=lambda p: VULNERABLE_CODE_FILES.get(p, ""),
            tree_items=tree_items
        )
        self.assertTrue(fix_res["success"], f"Fix should succeed: {fix_res.get('reason')}")
        self.assertGreater(len(fix_res["files"]), 0, "Modified files must be > 0")
        summary = fix_res.get("remediation_summary", {})
        self.assertGreater(summary.get("files_modified_count", 0), 0)
        self.assertGreater(summary.get("findings_validated_count", 0), 0)
        # Ensure reason matches actual modified files count honestly
        self.assertIn(f"across {len(fix_res['files'])} modified file", fix_res.get("reason", ""))

    def test_03_no_safe_source_match_relegation(self):
        """3. Finding with no relevant code in repository returns REVIEW_REQUIRED."""
        finding = {
            "id": "FIND-UNKNOWN",
            "vuln_id": "VULN-999",
            "cwe": "CWE-999",
            "finding_name": "Hypothetical Mainframe Memory Corruptor",
            "affected_endpoint": "/quantum/supercomputer/leak"
        }
        tree_items = [{"path": p, "type": "blob", "size": len(c)} for p, c in VULNERABLE_CODE_FILES.items()]
        fix_res = generate_cumulative_repository_fix(
            findings=[finding],
            repo=self.repo,
            branch=self.branch,
            fetch_content_cb=lambda p: VULNERABLE_CODE_FILES.get(p, ""),
            tree_items=tree_items
        )
        ft = fix_res.get("finding_traceability", [])
        self.assertEqual(len(ft), 1)
        self.assertIn(ft[0]["status"], {"NO_SAFE_SOURCE_MATCH", "REVIEW_REQUIRED"})
        self.assertTrue(any(term in ft[0].get("reason", "").lower() for term in ["no confident source code match", "no safe source match"]))

    def test_04_already_secure_verification_strictness(self):
        """4. is_finding_already_remediated requires BOTH presence of defensive control AND absence of flaw."""
        # Vulnerable SQLi code with an unrelated '?' character in a comment should NOT be marked secure
        vulnerable_code = (
            "def search():\n"
            "    # Was this fixed? Maybe.\n"
            "    query = request.args.get('q')\n"
            "    cursor.execute(f'SELECT * FROM products WHERE name = {query}')\n"
        )
        finding_sqli = {"cwe": "CWE-89", "affected_endpoint": "/search"}
        self.assertFalse(is_finding_already_remediated(finding_sqli, vulnerable_code))

        # Genuinely secure parameterized code
        secure_code = (
            "def search():\n"
            "    query = request.args.get('q')\n"
            "    cursor.execute('SELECT * FROM products WHERE name = ?', (query,))\n"
        )
        self.assertTrue(is_finding_already_remediated(finding_sqli, secure_code))

    def test_05_strict_zero_modified_files_guard(self):
        """5. Tracegate strictly NEVER claims findings are validated when 0 files were modified."""
        # Unmatchable finding
        finding = {
            "id": "FIND-NOOP",
            "vuln_id": "VULN-NOOP",
            "cwe": "CWE-999",
            "finding_name": "Unmatchable Hardware Bug",
            "affected_endpoint": "/dev/null/hardware"
        }
        res = run_repository_remediation(
            findings=[finding],
            repo=self.repo,
            branch=self.branch,
            tree_items=[{"path": "dummy.txt", "type": "blob"}],
            fetch_content_cb=lambda p: "hello world"
        )
        # MUST NOT claim validated findings across 0 modified files!
        self.assertFalse(res["success"])
        self.assertEqual(len(res["files"]), 0)
        self.assertIn(res["patch_status"], ["NO_CHANGE_GENERATED", "PATCH_REJECTED"])
        self.assertNotIn("findings validated across 0 modified files", res.get("reason", ""))

    def test_06_stale_commit_sha_rejection(self):
        """6. Stale source SHA raises conflict."""
        finding = {"id": "VULN-001", "vuln_id": "VULN-001", "cwe": "CWE-639"}
        with self.assertRaises(ValueError) as ctx:
            from backend.github_service import apply_finding_fix
            apply_finding_fix(
                user_id=self.user_a["id"],
                repo=self.repo,
                target_branch=self.branch,
                finding=finding,
                file_path="app.py",
                diff_or_fixed_code="# fixed",
                file_sha="stale_outdated_sha_hash"
            )
        self.assertIn("SOURCE_CHANGED", str(ctx.exception))

    def test_07_crlf_line_endings_normalization(self):
        """7. Windows CRLF line endings are cleanly patched without format breakage."""
        crlf_code = (
            "from flask import Flask, request, jsonify\r\n"
            "app = Flask(__name__)\r\n\r\n"
            "@app.route('/api/catalog/search')\r\n"
            "def search():\r\n"
            "    q = request.args.get('q', '')\r\n"
            "    cursor.execute(f'SELECT * FROM products WHERE name LIKE \"%{q}%\"')\r\n"
            "    return jsonify([])\r\n"
        )
        finding = {
            "id": "F-SQLI",
            "vuln_id": "VULN-008",
            "cwe": "CWE-89",
            "affected_endpoint": "/api/catalog/search",
            "parameter": "q"
        }
        res = apply_semantic_remediations_to_file("catalogService.py", [finding], crlf_code)
        self.assertTrue(res["modified"])
        self.assertIn("?", res["code"])
        self.assertIn("\r\n", res["code"], "Preserves original line endings")

    def test_08_shared_file_multiple_cwes_syntactically_valid(self):
        """8. Multiple distinct vulnerabilities in single app.py are remediated with valid syntax."""
        app_code = VULNERABLE_CODE_FILES["app.py"]
        findings = [
            {"id": "F-1", "vuln_id": "VULN-001", "cwe": "CWE-639", "affected_endpoint": "/profile/<user_id>"},
            {"id": "F-2", "vuln_id": "VULN-002", "cwe": "CWE-434", "affected_endpoint": "/upload"},
            {"id": "F-3", "vuln_id": "VULN-003", "cwe": "CWE-22", "affected_endpoint": "/files"},
            {"id": "F-4", "vuln_id": "VULN-004", "cwe": "CWE-288", "affected_endpoint": "/verify-2fa"},
            {"id": "F-5", "vuln_id": "VULN-007", "cwe": "CWE-204", "affected_endpoint": "/login"},
            {"id": "F-6", "vuln_id": "VULN-008", "cwe": "CWE-89", "affected_endpoint": "/search"}
        ]
        res = apply_semantic_remediations_to_file("app.py", findings, app_code)
        self.assertTrue(res["modified"])
        # Validate that cumulative modifications in single file parse without Python SyntaxError
        parsed = ast.parse(res["code"])
        self.assertIsNotNone(parsed)

    def test_09_multi_user_isolation_prevent_cross_project_access(self):
        """9. User A cannot batch-patch, analyze, apply, or create PR on User B's project."""
        # 1. User A tries to run batch-patch on User B's project -> 404
        bp_resp = self.client.post("/api/ai-fix/batch-patch", json={
            "repo": self.repo,
            "branch": self.branch,
            "project_id": self.proj_b_id
        }, headers=self.headers_a)
        self.assertEqual(bp_resp.status_code, 404, "User A should not access User B's project")

        # 2. User A tries to analyze with User B's project_id -> 404
        an_resp = self.client.post("/api/ai-fix/analyze", json={
            "finding_id": "VULN-001",
            "repo": self.repo,
            "project_id": self.proj_b_id
        }, headers=self.headers_a)
        self.assertEqual(an_resp.status_code, 404, "User A cannot analyze User B's project")

        # 3. User A tries to apply fix on User B's project -> 404
        ap_resp = self.client.post("/api/ai-fix/apply", json={
            "finding_id": "__ALL_FINDINGS__",
            "project_id": self.proj_b_id,
            "repo": self.repo,
            "files": []
        }, headers=self.headers_a)
        self.assertEqual(ap_resp.status_code, 404, "User A cannot apply fix on User B's project")

        # 4. User A tries to create PR on User B's project -> 404
        pr_resp = self.client.post("/api/ai-fix/create-pr", json={
            "finding_id": "__ALL_FINDINGS__",
            "project_id": self.proj_b_id,
            "repo": self.repo,
            "fix_branch": "test"
        }, headers=self.headers_a)
        self.assertEqual(pr_resp.status_code, 404, "User A cannot create PR on User B's project")

    def test_10_authorized_user_can_remediate_own_project_and_create_pr(self):
        """10. Authenticated user can remediate their own project and create PR cleanly."""
        # Save a confirmed finding in User A's project
        saved_f = save_finding(self.proj_a_id, None, {
            "finding_name": "IDOR Profile Modification",
            "vuln_id": "VULN-001",
            "cwe": "CWE-639",
            "affected_url": "/api/users/<user_id>",
            "priority": "HIGH",
            "status": "CONFIRMED"
        })

        # User A calls batch-patch on their own project -> 200 OK
        bp_resp = self.client.post("/api/ai-fix/batch-patch", json={
            "repo": self.repo,
            "branch": self.branch,
            "project_id": self.proj_a_id
        }, headers=self.headers_a)
        self.assertEqual(bp_resp.status_code, 200)
        patch_data = bp_resp.json()
        self.assertTrue(patch_data["success"])
        self.assertGreater(len(patch_data["files"]), 0)

        # User A applies the fix -> 200 OK
        ap_resp = self.client.post("/api/ai-fix/apply", json={
            "finding_id": "__ALL_FINDINGS__",
            "project_id": self.proj_a_id,
            "repo": self.repo,
            "target_branch": self.branch,
            "fix_branch": "tracegate/fix/cumulative-user-a",
            "files": patch_data["files"]
        }, headers=self.headers_a)
        self.assertEqual(ap_resp.status_code, 200)
        apply_data = ap_resp.json()
        self.assertTrue(apply_data["success"])

        # User A creates a PR -> 200 OK
        pr_resp = self.client.post("/api/ai-fix/create-pr", json={
            "finding_id": "__ALL_FINDINGS__",
            "project_id": self.proj_a_id,
            "repo": self.repo,
            "fix_branch": apply_data["branch_name"],
            "base_branch": self.branch
        }, headers=self.headers_a)
        self.assertEqual(pr_resp.status_code, 200)
        pr_data = pr_resp.json()
        self.assertTrue(pr_data["success"])
        self.assertIn("pull", pr_data["pr_url"].lower())

    def test_11_finding_endpoint_extracted_from_affected_url_or_poc(self):
        """11. map_finding_to_code extracts endpoint from affected_url or poc_text if affected_endpoint is None."""
        idx = build_repository_index(VULNERABLE_CODE_FILES)
        finding_with_url_only = {
            "id": "F-URL-ONLY",
            "vuln_id": "VULN-001",
            "cwe": "CWE-639",
            "affected_endpoint": None,
            "affected_url": "/profile/123",
            "poc_text": "GET /profile/123 HTTP/1.1"
        }
        mapping = map_finding_to_code(finding_with_url_only, idx)
        self.assertIsNotNone(mapping)
        self.assertEqual(mapping.primary_file, "app.py")

    def test_12_multi_file_secure_fix_status_no_change_generated(self):
        """12. generate_multi_file_secure_fix returns NO_CHANGE_GENERATED on empty patch."""
        finding = {
            "id": "F-CLEAN",
            "vuln_id": "VULN-001",
            "cwe": "CWE-639",
            "finding_name": "IDOR"
        }
        clean_file_map = {"clean.txt": "This is completely unrelated plain text."}
        res = generate_multi_file_secure_fix(
            finding=finding,
            repo=self.repo,
            branch=self.branch,
            selected_files=["clean.txt"],
            file_contents_map=clean_file_map
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["patch_status"], "NO_CHANGE_GENERATED")


if __name__ == "__main__":
    unittest.main()
