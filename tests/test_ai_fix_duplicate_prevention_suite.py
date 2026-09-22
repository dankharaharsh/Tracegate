"""
Tracegate AI Fix: Duplicate Code Prevention & Authoritative Modified-File Counting Test Suite.
Verifies:
1. Patch Engine Idempotency: Re-applying or multi-finding patching against the same file never duplicates security guards.
2. IDOR (CWE-639) and 2FA (CWE-288) deduplication in JS and Python.
3. Authoritative Modified-File Calculation: +0/-0 files NEVER count as modified.
4. ALREADY_SECURE behavior: 0 modified files returned when code is already remediated.
5. Third-party package dependency handling: REVIEW_REQUIRED with 0 selected files, no bogus app.py fallback.
6. Cumulative multi-file repository remediation with strict diff counting.
"""

import unittest
from backend.ai_autofix import (
    generate_semantic_patch,
    analyze_root_cause,
    generate_secure_fix,
    generate_multi_file_secure_fix,
    detect_and_prune_duplicate_blocks,
    discover_repository_sources
)
from backend.remediation_engine_v2 import (
    is_finding_already_remediated,
    apply_semantic_remediations_to_file,
    generate_cumulative_repository_fix,
    build_repository_index,
    map_finding_to_code
)
from backend.github_service import analyze_finding_code


class TestAiFixDuplicatePreventionSuite(unittest.TestCase):

    def test_44_idor_javascript_patch_idempotency(self):
        """
        Scenario 1: Repeatedly patching userController.js for IDOR (CWE-639)
        must NEVER duplicate the security check guard.
        """
        original_js = (
            "exports.getUserProfile = async (req, res) => {\n"
            "    const targetUserId = req.params.id;\n"
            "    const user = await User.findById(targetUserId);\n"
            "    return res.json(user);\n"
            "};"
        )
        finding_idor = {
            "id": "FINDING-IDOR-01",
            "cwe": "CWE-639",
            "title": "Insecure Direct Object Reference in User Profile",
            "affected_component": "controllers/userController.js"
        }

        root_cause = analyze_root_cause(finding_idor, original_js, "controllers/userController.js")
        patched_1, changes_1, _, _, _ = generate_semantic_patch(
            source_code=original_js,
            root_cause_info=root_cause,
            finding=finding_idor,
            file_path="controllers/userController.js"
        )

        # First patch must insert the guard
        self.assertIn("targetUserId", patched_1)
        self.assertIn("403", patched_1)
        count_guard_1 = patched_1.count("targetUserId")
        count_403_1 = patched_1.count("403")

        # Second patch run on already patched code must NOT duplicate guard
        patched_2, changes_2, _, _, _ = generate_semantic_patch(
            source_code=patched_1,
            root_cause_info=root_cause,
            finding=finding_idor,
            file_path="controllers/userController.js"
        )
        count_guard_2 = patched_2.count("targetUserId")
        count_403_2 = patched_2.count("403")

        self.assertEqual(count_guard_1, count_guard_2, "IDOR guard must not be duplicated on second run")
        self.assertEqual(count_403_1, count_403_2, "403 response must not be duplicated on second run")
        self.assertEqual(patched_1.strip(), patched_2.strip(), "Patch must be strictly idempotent")

    def test_45_two_factor_auth_python_idempotency(self):
        """
        Scenario 2: Patching 2FA bypass in app.py repeatedly must never duplicate
        session checks or 2FA redirection blocks.
        """
        original_py = (
            "from flask import Flask, request, session, redirect, url_for\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/login', methods=['POST'])\n"
            "def login():\n"
            "    user = authenticate(request.form['user'], request.form['pass'])\n"
            "    if user:\n"
            "        session['user_id'] = user['id']\n"
            "        session['authenticated'] = True\n"
            "        return redirect(url_for('dashboard'))\n"
        )
        finding_2fa = {
            "id": "FINDING-2FA-01",
            "cwe": "CWE-288",
            "title": "Missing 2FA Enforcement Bypass",
            "affected_component": "app.py"
        }

        root_cause = analyze_root_cause(finding_2fa, original_py, "app.py")
        patched_1, _, _, _, _ = generate_semantic_patch(
            source_code=original_py,
            root_cause_info=root_cause,
            finding=finding_2fa,
            file_path="app.py"
        )

        self.assertIn("2fa_required", patched_1)
        count_2fa_1 = patched_1.count("2fa_required")

        # Second patch run
        patched_2, _, _, _, _ = generate_semantic_patch(
            source_code=patched_1,
            root_cause_info=root_cause,
            finding=finding_2fa,
            file_path="app.py"
        )
        count_2fa_2 = patched_2.count("2fa_required")

        self.assertEqual(count_2fa_1, count_2fa_2, "2FA session check must not be duplicated")
        self.assertEqual(patched_1.strip(), patched_2.strip())

    def test_46_detect_and_prune_duplicate_blocks(self):
        """
        Scenario 3: detect_and_prune_duplicate_blocks must eliminate consecutive duplicate blocks
        and duplicate authorization checks.
        """
        duplicate_code = (
            "if (req.user && req.user.id !== targetUserId) {\n"
            "    return res.status(403).json({ error: 'Forbidden' });\n"
            "}\n"
            "if (req.user && req.user.id !== targetUserId) {\n"
            "    return res.status(403).json({ error: 'Forbidden' });\n"
            "}\n"
            "const profile = await getUser(targetUserId);\n"
        )
        pruned = detect_and_prune_duplicate_blocks(duplicate_code, "userController.js")
        self.assertEqual(pruned.count("403"), 1, "Duplicate 403 block must be pruned to exactly 1")
        self.assertIn("const profile = await getUser(targetUserId);", pruned)

    def test_47_authoritative_modified_file_count_zero_diff_elimination(self):
        """
        Scenario 4: Authoritative modified-file calculation. Zero-diff (+0/-0) files
        must NEVER be included in the modified files list or file traceability table.
        """
        file_a_before = "def index():\n    return 'OK'\n"
        file_b_before = (
            "def search(q):\n"
            "    sql = f'SELECT * FROM items WHERE name = \"{q}\"'\n"
            "    return db.execute(sql)\n"
        )
        # In a multi-file run where file_a has NO diff and file_b is modified
        finding_sqli = {
            "id": "FINDING-SQLI-01",
            "cwe": "CWE-89",
            "title": "SQL Injection in Search",
            "affected_component": "services/search.py"
        }

        res = generate_multi_file_secure_fix(
            finding=finding_sqli,
            repo="org/repo",
            branch="main",
            selected_files=["app.py", "services/search.py"],
            file_contents_map={
                "app.py": file_a_before,
                "services/search.py": file_b_before
            }
        )

        self.assertTrue(res["success"])
        # Exactly 1 file modified (services/search.py), app.py must NOT be present!
        modified_paths = [f["path"] for f in res["files"]]
        self.assertEqual(len(modified_paths), 1, "Only genuinely changed files must be in files array")
        self.assertIn("services/search.py", modified_paths)
        self.assertNotIn("app.py", modified_paths)

        # Check GitHub service analysis wrapper
        gh_res = analyze_finding_code(
            finding=finding_sqli,
            repo="org/repo",
            branch="main",
            file_contents_map={
                "app.py": file_a_before,
                "services/search.py": file_b_before
            }
        )
        self.assertEqual(gh_res.remediation_summary.get("files_modified_count"), 1)
        self.assertEqual(len(gh_res.files), 1)
        self.assertEqual(len(gh_res.file_traceability), 1)
        self.assertEqual(gh_res.file_traceability[0]["path"], "services/search.py")
        self.assertGreater(gh_res.file_traceability[0]["lines_added"] + gh_res.file_traceability[0]["lines_removed"], 0)

    def test_48_already_secure_returns_zero_modified_files(self):
        """
        Scenario 5: When running remediation against already secure code,
        patch_status must be ALREADY_SECURE, success=True, and files=[] (0 modified files).
        """
        already_secure_code = (
            "def search(q):\n"
            "    cursor.execute('SELECT * FROM items WHERE name = ?', (q,))\n"
            "    return cursor.fetchall()\n"
        )
        finding_sqli = {
            "id": "FINDING-SQLI-ALREADY-SAFE",
            "cwe": "CWE-89",
            "title": "SQL Injection in Search",
            "affected_component": "services/search.py"
        }

        fix_res = generate_secure_fix(
            finding=finding_sqli,
            repo="org/repo",
            branch="main",
            file_path="services/search.py",
            source_code=already_secure_code
        )

        self.assertTrue(fix_res["success"])
        self.assertEqual(fix_res["patch_status"], "ALREADY_SECURE")
        self.assertEqual(len(fix_res["files"]), 0, "ALREADY_SECURE must return 0 modified files")
        self.assertEqual(fix_res["diff_unified"], "")

    def test_49_no_artificial_app_py_fallback_for_package_dependency(self):
        """
        Scenario 6: Third-party package/dependency finding must return REVIEW_REQUIRED
        with selected_files=[] and NEVER artificially target app.py.
        """
        package_finding = {
            "id": "FINDING-PKG-01",
            "cwe": "CWE-1104",
            "title": "Vulnerable Third-Party Package Dependency: requests < 2.31.0",
            "description": "Upgrade package dependency in requirements.txt",
            "affected_component": "requests < 2.31.0"
        }
        tree = [
            {"path": "app.py", "type": "blob", "size": 500},
            {"path": "static/app.js", "type": "blob", "size": 300}
        ]
        disc = discover_repository_sources(package_finding, tree, lambda p: "import flask\n")
        self.assertEqual(len(disc["selected_sources"]), 0, "Package finding must not match unrelated app.py")

        # Test mapping in remediation engine
        index = build_repository_index({
            "app.py": "import flask\n",
            "static/app.js": "console.log('hi');\n"
        })
        mapped = map_finding_to_code(package_finding, index)
        self.assertEqual(mapped.status, "REVIEW_REQUIRED")
        self.assertEqual(len(mapped.selected_files), 0, "No files should be auto-selected for package dependency")

    def test_50_cumulative_repository_remediation_strict_diff_tracking(self):
        """
        Scenario 7: Cumulative remediation across 8 findings ensures only files with true
        diffs are listed in files_modified.
        """
        repo_files = {
            "controllers/userController.js": (
                "exports.getProfile = async (req, res) => {\n"
                "    const targetUserId = req.params.id;\n"
                "    const user = await User.findById(targetUserId);\n"
                "    return res.json(user);\n"
                "};\n"
            ),
            "backend/catalogService.py": (
                "def search_catalog_items(query: str, category_id: int):\n"
                "    sql = f\"SELECT id, title, price, stock FROM products WHERE category_id = {category_id} AND title LIKE '%{query}%'\"\n"
                "    cursor.execute(sql)\n"
                "    return cursor.fetchall()\n"
            ),
            "static/2fa-vuln.py": "# Unrelated static asset file\n",
            "static/js/app.js": "// Client side bundle\nconsole.log('init');\n",
            "app.py": "from flask import Flask\napp = Flask(__name__)\n"
        }

        index = build_repository_index(repo_files)
        findings = [
            {
                "vuln_id": "FINDING-IDOR",
                "cwe": "CWE-639",
                "title": "IDOR in User Controller",
                "affected_component": "controllers/userController.js"
            },
            {
                "vuln_id": "FINDING-SQLI",
                "cwe": "CWE-89",
                "title": "SQL Injection in Catalog Service",
                "affected_component": "backend/catalogService.py"
            },
            {
                "vuln_id": "FINDING-DEP",
                "cwe": "CWE-1104",
                "title": "Outdated third-party library",
                "affected_component": "lodash"
            }
        ]

        result = generate_cumulative_repository_fix(findings, index)
        modified_paths = [fm["path"] for fm in result["files_modified"]]

        # Only the 2 genuinely modified files must be present
        self.assertEqual(len(modified_paths), 2)
        self.assertIn("controllers/userController.js", modified_paths)
        self.assertIn("backend/catalogService.py", modified_paths)
        self.assertNotIn("static/2fa-vuln.py", modified_paths)
        self.assertNotIn("static/js/app.js", modified_paths)
        self.assertNotIn("app.py", modified_paths)

        for fm in result["files_modified"]:
            self.assertGreater(fm["lines_added"] + fm["lines_removed"], 0)
            self.assertTrue(bool(fm["diff_unified"].strip()))


if __name__ == "__main__":
    unittest.main()
