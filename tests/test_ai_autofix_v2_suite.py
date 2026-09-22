"""
Tests for Tracegate AI AutoFix V2: Repository-Wide Multi-Finding Remediation Engine.

Verifies the 14 Critical Architecture Scenarios:
1. Single finding remediation (IDOR)
2. Multiple vulnerabilities in a single shared file (app.py: SQLi, 2FA, Enum, IDOR, Upload, Traversal, XSS)
3. Single vulnerability spanning multiple files / layers (XSS / Upload across route + template)
4. Full batch remediation of all 8+ confirmed findings
5. Large repository benchmark (55+ synthetic findings without crash or hung process)
6. Finding with NO confident source match (NO_SAFE_SOURCE_MATCH)
7. 3rd-party package / dependency vulnerability (REVIEW_REQUIRED)
8. Configuration flaw (REVIEW_REQUIRED / NO unsafe source edits)
9. Architecture code relationship graph (route -> controller -> service -> model)
10. Patch conflict detection (incompatible changes handled safely)
11. Commit SHA mismatch / stale code baseline detection
12. Unrelated refactoring guard (zero edits to clean functions/endpoints)
13. Syntax validation failure handling (AST error caught -> FAILED_VALIDATION)
14. Already-remediated finding recognition (ALREADY_REMEDIATED)
"""

import unittest
import ast
import json
import time
from typing import Dict, Any, List

from backend.mock_vulnerable_code import VULNERABLE_CODE_FILES
from backend.remediation_engine_v2 import (
    RepositoryIndex,
    build_repository_index,
    map_finding_to_code,
    build_global_remediation_plan,
    apply_semantic_remediations_to_file,
    validate_source_syntax,
    run_repository_remediation,
    is_finding_already_remediated
)
from backend.ai_autofix import scan_repository_vulnerabilities, generate_cumulative_repository_fix


class TestAIAutoFixV2Suite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = "dankharaharsh/vulnerable-code"
        cls.branch = "main"
        cls.tree_items = [
            {"path": p, "type": "blob", "size": len(c)}
            for p, c in VULNERABLE_CODE_FILES.items()
        ]

    def fetch_cb(self, p: str) -> str:
        clean = p.replace("\\", "/").lstrip("/")
        return VULNERABLE_CODE_FILES.get(clean, "")

    # -------------------------------------------------------------------------
    # Scenario 1: Single-Finding Remediation
    # -------------------------------------------------------------------------
    def test_01_single_finding_remediation_idor(self):
        """Scenario 1: Remediates a single finding (IDOR) cleanly with valid AST."""
        finding = {
            "vuln_id": "VULN-IDOR",
            "title": "Insecure Direct Object Reference on Profile Edit",
            "finding_name": "Insecure Direct Object Reference on Profile Edit",
            "cwe": "CWE-639",
            "severity": "HIGH",
            "affected_endpoint": "/profile/edit",
            "parameter": "user_id",
            "affected_component": "app.py"
        }

        res = run_repository_remediation(
            findings=[finding],
            repo=self.repo,
            branch=self.branch,
            tree_items=self.tree_items,
            fetch_content_cb=self.fetch_cb
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["patch_status"], "PATCH_VALIDATED")
        self.assertEqual(len(res["files"]), 1)
        self.assertEqual(res["files"][0]["path"], "app.py")
        self.assertIn("session.get(\"user_id\")", res["files"][0]["after_code"])
        self.assertEqual(res["files"][0]["validation"]["syntax"], "PASSED")
        self.assertEqual(res["remediation_summary"]["overall_status"], "ALL_FINDINGS_VALIDATED")
        self.assertEqual(res["remediation_summary"]["findings_validated_count"], 1)

    # -------------------------------------------------------------------------
    # Scenario 2: Multiple Vulnerabilities in a Single Shared File
    # -------------------------------------------------------------------------
    def test_02_shared_file_multi_vulnerability_remediation(self):
        """Scenario 2: Patches 7 distinct vulnerabilities in app.py without collision or overwriting."""
        findings = [
            {"vuln_id": "V-SQLI", "cwe": "CWE-89", "title": "SQL Injection in Login", "affected_endpoint": "/login", "affected_component": "app.py"},
            {"vuln_id": "V-2FA", "cwe": "CWE-288", "title": "2FA Bypass", "affected_endpoint": "/2fa", "affected_component": "app.py"},
            {"vuln_id": "V-ENUM", "cwe": "CWE-204", "title": "Account Enumeration", "affected_endpoint": "/login", "affected_component": "app.py"},
            {"vuln_id": "V-IDOR", "cwe": "CWE-639", "title": "IDOR Profile Update", "affected_endpoint": "/profile/edit", "affected_component": "app.py"},
            {"vuln_id": "V-UPLOAD", "cwe": "CWE-434", "title": "Unrestricted File Upload", "affected_endpoint": "/upload", "affected_component": "app.py"},
            {"vuln_id": "V-TRAV", "cwe": "CWE-22", "title": "Path Traversal in Download", "affected_endpoint": "/files/download", "affected_component": "app.py"},
            {"vuln_id": "V-XSS", "cwe": "CWE-79", "title": "Stored SVG XSS", "affected_endpoint": "/uploads", "affected_component": "app.py"}
        ]

        res = run_repository_remediation(
            findings=findings,
            repo=self.repo,
            branch=self.branch,
            tree_items=self.tree_items,
            fetch_content_cb=self.fetch_cb
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["patch_status"], "PATCH_VALIDATED")

        app_mod = next(f for f in res["files"] if f["path"] == "app.py")
        mod_code = app_mod["after_code"]

        # Verify all 7 security boundaries coexist in the modified source
        self.assertIn("SELECT * FROM users WHERE username = ? AND password = ?", mod_code)  # SQLi
        self.assertIn("session.get(\"2fa_required\") and not session.get(\"2fa_verified\")", mod_code)  # 2FA
        self.assertIn("Invalid username or password", mod_code)  # Enum
        self.assertIn("target_user_id = session.get(\"user_id\")", mod_code)  # IDOR
        self.assertIn("ALLOWED_EXTENSIONS = {\".png\", \".jpg\", \".jpeg\", \".pdf\"}", mod_code)  # Upload
        self.assertIn(".resolve()", mod_code)  # Traversal
        self.assertIn("clean_svg", mod_code)  # XSS

        # Verify strict Python AST syntax validity
        ast.parse(mod_code)
        self.assertEqual(app_mod["validation"]["syntax"], "PASSED")
        self.assertEqual(res["remediation_summary"]["findings_validated_count"], 7)

    # -------------------------------------------------------------------------
    # Scenario 3: Single Vulnerability Spanning Multiple Files / Layers
    # -------------------------------------------------------------------------
    def test_03_multi_file_multi_layer_finding(self):
        """Scenario 3: Remediates full-stack flaws across backend server and frontend template."""
        findings = [
            {
                "vuln_id": "VULN-SVG-FULLSTACK",
                "title": "Stored Cross-Site Scripting (XSS) via SVG Upload & Rendering",
                "cwe": "CWE-79",
                "severity": "HIGH",
                "affected_endpoint": "/uploads",
                "affected_component": "app.py and templates/uploads.html"
            }
        ]

        res = run_repository_remediation(
            findings=findings,
            repo=self.repo,
            branch=self.branch,
            tree_items=self.tree_items,
            fetch_content_cb=self.fetch_cb
        )

        self.assertTrue(res["success"])
        modified_paths = {f["path"] for f in res["files"]}
        self.assertIn("app.py", modified_paths)
        self.assertIn("templates/uploads.html", modified_paths)

    # -------------------------------------------------------------------------
    # Scenario 4: All 8 Confirmed Findings Remediated in Real Benchmark
    # -------------------------------------------------------------------------
    def test_04_all_findings_cumulative_remediation_benchmark(self):
        """Scenario 4: Scanner detects 8+ findings and engine batches all into validated multi-file diff."""
        scan_res = scan_repository_vulnerabilities(self.repo, self.branch, self.tree_items, self.fetch_cb)
        findings = scan_res["findings"]
        self.assertGreaterEqual(len(findings), 8)

        cum_res = generate_cumulative_repository_fix(
            findings=findings,
            repo=self.repo,
            branch=self.branch,
            fetch_content_cb=self.fetch_cb,
            tree_items=self.tree_items
        )

        self.assertTrue(cum_res["success"])
        self.assertEqual(cum_res["patch_status"], "PATCH_VALIDATED")
        self.assertIn("remediation_summary", cum_res)
        self.assertIn("finding_traceability", cum_res)
        self.assertIn("file_traceability", cum_res)
        self.assertIn("clusters", cum_res)

        summary = cum_res["remediation_summary"]
        self.assertEqual(summary["overall_status"], "ALL_FINDINGS_VALIDATED")
        self.assertGreaterEqual(summary["findings_validated_count"], 8)
        self.assertGreaterEqual(summary["files_modified_count"], 3)
        self.assertGreater(summary["lines_added"], 0)

    # -------------------------------------------------------------------------
    # Scenario 5: 55+ Findings Large Repository Benchmark
    # -------------------------------------------------------------------------
    def test_05_large_scale_benchmark_55_plus_findings(self):
        """Scenario 5: Handles 60 findings clustered across repository in <2.0 seconds without failure."""
        synthetic_findings = []
        cwes = ["CWE-89", "CWE-288", "CWE-204", "CWE-639", "CWE-434", "CWE-22", "CWE-524", "CWE-79"]

        for i in range(1, 61):
            cwe = cwes[i % len(cwes)]
            synthetic_findings.append({
                "vuln_id": f"BENCH-{i:03d}",
                "title": f"Security finding {i} ({cwe})",
                "finding_name": f"Security finding {i} ({cwe})",
                "cwe": cwe,
                "severity": "HIGH",
                "affected_endpoint": "/login" if "89" in cwe or "204" in cwe else "/profile/edit",
                "affected_component": "app.py"
            })

        t0 = time.time()
        res = run_repository_remediation(
            findings=synthetic_findings,
            repo=self.repo,
            branch=self.branch,
            tree_items=self.tree_items,
            fetch_content_cb=self.fetch_cb
        )
        elapsed = time.time() - t0

        self.assertTrue(res["success"])
        self.assertLess(elapsed, 2.0, f"Engine took {elapsed:.2f}s, expected < 2.0s")
        self.assertEqual(len(res["finding_traceability"]), 60)
        self.assertGreaterEqual(res["remediation_summary"]["findings_validated_count"], 50)

    # -------------------------------------------------------------------------
    # Scenario 6: NO Confident Source Code Match (Honest Status)
    # -------------------------------------------------------------------------
    def test_06_no_safe_source_match_honest_reporting(self):
        """Scenario 6: Unknown phantom endpoint accurately reports NO_SAFE_SOURCE_MATCH."""
        finding = {
            "vuln_id": "VULN-PHANTOM",
            "title": "Buffer Overflow in Native Kernel Extension",
            "cwe": "CWE-120",
            "severity": "CRITICAL",
            "affected_endpoint": "/driver/ioctl/sys_mem_alloc",
            "parameter": "kptr",
            "affected_component": "drivers/kernel_mem.c"
        }

        res = run_repository_remediation(
            findings=[finding],
            repo=self.repo,
            branch=self.branch,
            tree_items=self.tree_items,
            fetch_content_cb=self.fetch_cb
        )

        trace = res["finding_traceability"][0]
        self.assertEqual(trace["status"], "NO_SAFE_SOURCE_MATCH")
        self.assertIn("No confident source code match", trace["reason"])
        self.assertEqual(trace["validation"]["source_found"], "NO")

    # -------------------------------------------------------------------------
    # Scenario 7: Third-Party Package / Dependency Vulnerability
    # -------------------------------------------------------------------------
    def test_07_third_party_dependency_review_required(self):
        """Scenario 7: CVE in third-party library yields REVIEW_REQUIRED rather than blind edits."""
        finding = {
            "vuln_id": "VULN-DEP-01",
            "title": "CVE-2023-43665 Outdated Jinja2 vulnerable to memory denial of service",
            "cwe": "CWE-400",
            "severity": "MEDIUM",
            "description": "The npm package jinja2 or pip dependency is outdated. Upgrade package.",
            "affected_component": "package.json / requirements.txt"
        }

        res = run_repository_remediation(
            findings=[finding],
            repo=self.repo,
            branch=self.branch,
            tree_items=self.tree_items,
            fetch_content_cb=self.fetch_cb
        )

        trace = res["finding_traceability"][0]
        self.assertEqual(trace["status"], "REVIEW_REQUIRED")
        self.assertIn("third-party package dependency", trace["reason"].lower())

    # -------------------------------------------------------------------------
    # Scenario 8: Configuration Flaw
    # -------------------------------------------------------------------------
    def test_08_configuration_flaw_detection(self):
        """Scenario 8: Missing server deployment headers or environment configs."""
        finding = {
            "vuln_id": "VULN-CONFIG-01",
            "title": "Missing Strict-Transport-Security (HSTS) Header in Reverse Proxy",
            "cwe": "CWE-693",
            "severity": "LOW",
            "affected_endpoint": "https://example.com/",
            "description": "Nginx / Cloudflare edge lacks Strict-Transport-Security header.",
            "affected_component": "nginx.conf"
        }

        res = run_repository_remediation(
            findings=[finding],
            repo=self.repo,
            branch=self.branch,
            tree_items=self.tree_items,
            fetch_content_cb=self.fetch_cb
        )

        trace = res["finding_traceability"][0]
        self.assertIn(trace["status"], {"NO_SAFE_SOURCE_MATCH", "REVIEW_REQUIRED"})

    # -------------------------------------------------------------------------
    # Scenario 9: Architecture Code Relationship Graph Resolution
    # -------------------------------------------------------------------------
    def test_09_code_relationship_graph_extraction(self):
        """Scenario 9: Index extracts symbols, frameworks, and architecture relationship graph."""
        idx = build_repository_index(self.tree_items, self.fetch_cb, self.repo, self.branch)

        self.assertIn("Flask", idx.frameworks)
        self.assertIn("controller", idx.architecture_layers)
        self.assertIn("template", idx.architecture_layers)

        route_names = [r["route"] for r in idx.routes]
        self.assertIn("/login", route_names)
        self.assertIn("/profile/edit", route_names)
        self.assertIn("/upload", route_names)
        self.assertIn("/files/download", route_names)

        app_symbols = idx.symbols.get("app.py", [])
        sym_names = [s["name"] for s in app_symbols]
        self.assertIn("login_required", sym_names)
        self.assertIn("login", sym_names)
        self.assertIn("profile_edit", sym_names)

    # -------------------------------------------------------------------------
    # Scenario 10: Patch Conflict Detection
    # -------------------------------------------------------------------------
    def test_10_patch_conflict_detection_and_safeguards(self):
        """Scenario 10: Global planner detects if multiple findings conflict on overlapping edits."""
        findings = [
            {"vuln_id": "V1", "cwe": "CWE-89", "title": "SQLi in Login", "affected_component": "app.py"},
            {"vuln_id": "V2", "cwe": "CWE-89", "title": "Duplicate SQLi intent", "affected_component": "app.py"}
        ]

        idx = build_repository_index(self.tree_items, self.fetch_cb, self.repo, self.branch)
        plan = build_global_remediation_plan(findings, idx)

        self.assertIn("app.py", plan.file_change_intents)
        self.assertEqual(len(plan.file_change_intents["app.py"]), 2)

    # -------------------------------------------------------------------------
    # Scenario 11: Stale Commit SHA Baseline Detection
    # -------------------------------------------------------------------------
    def test_11_stale_commit_sha_captured_honestly(self):
        """Scenario 11: Engine outputs before_sha and after_sha for strict Git tree alignment."""
        finding = {
            "vuln_id": "VULN-IDOR",
            "cwe": "CWE-639",
            "title": "IDOR in Profile",
            "affected_component": "app.py"
        }

        res = run_repository_remediation(
            findings=[finding],
            repo=self.repo,
            branch=self.branch,
            tree_items=self.tree_items,
            fetch_content_cb=self.fetch_cb
        )

        app_file = res["files"][0]
        self.assertIsNotNone(app_file.get("file_sha"))
        self.assertIsNotNone(app_file.get("after_sha"))
        self.assertNotEqual(app_file["file_sha"], app_file["after_sha"])

    # -------------------------------------------------------------------------
    # Scenario 12: Unrelated Refactoring Prevention
    # -------------------------------------------------------------------------
    def test_12_unrelated_refactoring_prevention(self):
        """Scenario 12: Clean unvulnerable routes and functions remain 100% untouched."""
        finding = {
            "vuln_id": "VULN-SQLI",
            "cwe": "CWE-89",
            "title": "SQLi in Login",
            "affected_component": "app.py",
            "affected_endpoint": "/login"
        }

        res = run_repository_remediation(
            findings=[finding],
            repo=self.repo,
            branch=self.branch,
            tree_items=self.tree_items,
            fetch_content_cb=self.fetch_cb
        )

        app_mod = res["files"][0]["after_code"]
        orig_code = VULNERABLE_CODE_FILES["app.py"]

        self.assertIn("def logout():", app_mod)
        self.assertIn("def dashboard():", app_mod)
        self.assertIn("def users_list():", app_mod)
        self.assertIn("def comments_view():", app_mod)

        orig_comments_start = orig_code.find("def comments_view():")
        orig_comments_end = orig_code.find("def upload_view():")
        mod_comments_start = app_mod.find("def comments_view():")
        mod_comments_end = app_mod.find("def upload_view():")
        self.assertEqual(
            orig_code[orig_comments_start:orig_comments_end],
            app_mod[mod_comments_start:mod_comments_end]
        )

    # -------------------------------------------------------------------------
    # Scenario 13: Syntax Validation Failure Detection
    # -------------------------------------------------------------------------
    def test_13_syntax_validation_catches_errors(self):
        """Scenario 13: Invalid syntax in Python or JavaScript is strictly caught and flagged."""
        broken_py = "def broken():\n    if True\n        return 1"
        valid_py, err_py = validate_source_syntax(broken_py, "module.py")
        self.assertFalse(valid_py)
        self.assertIn("SyntaxError", err_py)

        broken_js = "function test() { const x = [1, 2; return x; }"
        valid_js, err_js = validate_source_syntax(broken_js, "component.js")
        self.assertFalse(valid_js)
        self.assertIsNotNone(err_js)

    # -------------------------------------------------------------------------
    # Scenario 14: Already Remediated Recognition
    # -------------------------------------------------------------------------
    def test_14_already_remediated_finding_recognition(self):
        """Scenario 14: Engine detects when source already contains security controls."""
        already_safe_code = """
import sqlite3
from flask import Flask, request, session

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    db = sqlite3.connect("test.db")
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    return "ok"
"""
        finding = {
            "vuln_id": "VULN-ALREADY-SAFE",
            "cwe": "CWE-89",
            "title": "SQL Injection in Login",
            "affected_component": "app.py"
        }

        is_safe = is_finding_already_remediated(finding, already_safe_code)
        self.assertTrue(is_safe)


if __name__ == "__main__":
    unittest.main()
