"""
TRACEGATE — PROJECT SECURITY ANALYTICS TEST SUITE
==================================================
Validates all acceptance criteria from the specification:
- Test 1: API Endpoint Schema & Data Contract
- Test 2: Severity Distribution Calculation & Consistency (Crit 4, High 2, Med 1, Low 1 -> Total 8)
- Test 3: Coverage Semantics Reconciliation (11 planned, 6 evaluated -> 54.5%)
- Test 4: Status Lifecycle Aggregation (7 open, 1 resolved)
- Test 5: Dynamic State Transition (New Finding increments severity count & total)
- Test 6: Retest State Transition (Retest PASS moves finding from Open to Resolved)
- Test 7: Strict Project Isolation (Project A findings do not leak to Project B)
- Test 8: Empty Project Handling (0 findings, clean empty state, no fake charts)
- Test 9: Large Project Scale (50+ findings handled gracefully)
- Test 10: Authorization & User Isolation (Invalid token / unauthorized access handled)
- Test 11: DOM Static Structure Integrity (Scope, Nav, Cert, Danger Zone untouched)
- Test 12: Analytics Card & Modal Markup (Pills, Buttons, Viewport, Summary, Table)
- Test 13: Frontend JavaScript Logic & Event Bindings
"""

import os
import re
import sys
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app import app
from backend.database import (
    get_db_connection,
    create_project as db_create_project,
    save_finding as db_save_finding,
    add_custom_checklist_item as db_add_checklist_item,
    record_finding_retest,
    delete_project as db_delete_project,
)

HTML_PATH = BASE_DIR / "frontend" / "index.html"
JS_PATH = BASE_DIR / "frontend" / "js" / "app.js"
CSS_PATH = BASE_DIR / "frontend" / "css" / "style.css"

with open(HTML_PATH, "r", encoding="utf-8") as f:
    HTML_CONTENT = f.read()

with open(JS_PATH, "r", encoding="utf-8") as f:
    JS_CONTENT = f.read()

with open(CSS_PATH, "r", encoding="utf-8") as f:
    CSS_CONTENT = f.read()


class TestProjectSecurityAnalyticsSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.created_project_ids = []

    @classmethod
    def tearDownClass(cls):
        for pid in cls.created_project_ids:
            try:
                db_delete_project(pid)
            except Exception:
                pass

    def test_01_api_endpoint_schema_contract(self):
        """Verify GET /api/projects/{id}/analytics conforms to data contract."""
        proj = db_create_project({
            "name": "Analytics Contract Test Proj",
            "target_url": "https://contract.local",
            "environment": "Production",
            "description": "Test contract",
            "scope_notes": "Scope notes"
        })
        self.created_project_ids.append(proj["id"])

        res = self.client.get(f"/api/projects/{proj['id']}/analytics")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertIn("project_id", data)
        self.assertIn("project_name", data)
        self.assertIn("findings", data)
        self.assertIn("coverage", data)
        self.assertIn("status", data)

        findings = data["findings"]
        for key in ["total", "critical", "high", "medium", "low", "informational"]:
            self.assertIn(key, findings)
            self.assertIsInstance(findings[key], int)

        coverage = data["coverage"]
        for key in ["planned", "evaluated", "clean", "with_findings", "not_tested", "not_applicable", "percentage"]:
            self.assertIn(key, coverage)

        status_dict = data["status"]
        for key in ["open", "in_remediation", "retest_pending", "resolved", "closed"]:
            self.assertIn(key, status_dict)
            self.assertIsInstance(status_dict[key], int)

    def test_02_severity_distribution_exact_counts(self):
        """Acceptance Test 72: Critical 4, High 2, Med 1, Low 1, Info 0 -> Total 8."""
        proj = db_create_project({
            "name": "Acceptance Test 72 Proj",
            "target_url": "https://sev.local"
        })
        self.created_project_ids.append(proj["id"])
        pid = proj["id"]

        severities = ["CRITICAL"] * 4 + ["HIGH"] * 2 + ["MEDIUM"] * 1 + ["LOW"] * 1
        for idx, sev in enumerate(severities):
            db_save_finding(pid, f"item-sev-{idx}", {
                "finding_name": f"Vulnerability {idx + 1}",
                "priority": sev,
                "status": "Open"
            })

        res = self.client.get(f"/api/projects/{pid}/analytics")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        f = data["findings"]
        self.assertEqual(f["total"], 8)
        self.assertEqual(f["critical"], 4)
        self.assertEqual(f["high"], 2)
        self.assertEqual(f["medium"], 1)
        self.assertEqual(f["low"], 1)
        self.assertEqual(f["informational"], 0)

    def test_03_coverage_semantics_reconciliation(self):
        """Acceptance Test 73: 11 planned, 6 evaluated, 5 not tested, 0 clean, 6 findings -> 54.5%."""
        proj = db_create_project({
            "name": "Acceptance Test 73 Coverage Proj",
            "target_url": "https://cov.local"
        })
        self.created_project_ids.append(proj["id"])
        pid = proj["id"]

        # Add 11 checklist items and record their IDs
        item_ids = []
        for i in range(11):
            chk = db_add_checklist_item(pid, {
                "title": f"Security Verification Test #{i+1}",
                "category": "Authentication",
                "status": "NOT_TESTED"
            })
            item_ids.append(chk["id"])

        # Record findings for 6 items (marking them evaluated with findings)
        for i in range(6):
            db_save_finding(pid, item_ids[i], {
                "finding_name": f"Finding #{i+1}",
                "priority": "HIGH",
                "status": "Open"
            })

        res = self.client.get(f"/api/projects/{pid}/analytics")
        self.assertEqual(res.status_code, 200)
        cov = res.json()["coverage"]

        self.assertEqual(cov["with_findings"], 6)
        self.assertEqual(cov["evaluated"], 6)
        self.assertEqual(cov["planned"], 11)
        self.assertEqual(cov["percentage"], 54.5)

    def test_04_status_lifecycle_aggregation(self):
        """Acceptance Test 74: 7 open, 1 resolved."""
        proj = db_create_project({
            "name": "Acceptance Test 74 Status Proj",
            "target_url": "https://status.local"
        })
        self.created_project_ids.append(proj["id"])
        pid = proj["id"]

        # 7 open findings
        for i in range(7):
            db_save_finding(pid, f"chk-stat-{i}", {
                "finding_name": f"Open Defect {i+1}",
                "priority": "HIGH",
                "status": "Open"
            })

        # 1 resolved finding
        db_save_finding(pid, "chk-stat-res", {
            "finding_name": "Resolved Vulnerability",
            "priority": "CRITICAL",
            "status": "RESOLVED"
        })

        res = self.client.get(f"/api/projects/{pid}/analytics")
        self.assertEqual(res.status_code, 200)
        st = res.json()["status"]

        self.assertEqual(st["open"], 7)
        self.assertEqual(st["resolved"], 1)
        self.assertEqual(res.json()["findings"]["total"], 8)

    def test_05_dynamic_new_finding_increment(self):
        """Acceptance Test 75: Adding new High finding increments High count and Total."""
        proj = db_create_project({
            "name": "Acceptance Test 75 New Finding Proj",
            "target_url": "https://newfind.local"
        })
        self.created_project_ids.append(proj["id"])
        pid = proj["id"]

        db_save_finding(pid, "chk-init", {"finding_name": "Init Defect", "priority": "HIGH"})
        res1 = self.client.get(f"/api/projects/{pid}/analytics").json()
        self.assertEqual(res1["findings"]["high"], 1)
        self.assertEqual(res1["findings"]["total"], 1)

        # Add new High finding
        db_save_finding(pid, "chk-new", {"finding_name": "Second High Defect", "priority": "HIGH"})
        res2 = self.client.get(f"/api/projects/{pid}/analytics").json()
        self.assertEqual(res2["findings"]["high"], 2)
        self.assertEqual(res2["findings"]["total"], 2)

    def test_06_retest_pass_lifecycle_transition(self):
        """Acceptance Test 76: Retest PASS transitions finding from Open to Resolved."""
        proj = db_create_project({
            "name": "Acceptance Test 76 Retest Proj",
            "target_url": "https://retest.local"
        })
        self.created_project_ids.append(proj["id"])
        pid = proj["id"]

        f1 = db_save_finding(pid, "chk-retest-1", {"finding_name": "Defect 1", "status": "Open"})
        f2 = db_save_finding(pid, "chk-retest-2", {"finding_name": "Defect 2", "status": "Open"})

        before = self.client.get(f"/api/projects/{pid}/analytics").json()["status"]
        self.assertEqual(before["open"], 2)
        self.assertEqual(before["resolved"], 0)

        # Tester verifies fix with PASS
        record_finding_retest(finding_id=f1["id"], result="PASS", notes="Verified patched in production.")

        after = self.client.get(f"/api/projects/{pid}/analytics").json()["status"]
        self.assertEqual(after["open"], 1)
        self.assertEqual(after["resolved"], 1)

    def test_07_strict_project_isolation(self):
        """Acceptance Test 77: Project A has 8 findings, Project B has 2 findings. No leakage."""
        projA = db_create_project({"name": "Project A Isolated", "target_url": "https://a.local"})
        projB = db_create_project({"name": "Project B Isolated", "target_url": "https://b.local"})
        self.created_project_ids.extend([projA["id"], projB["id"]])

        for i in range(8):
            db_save_finding(projA["id"], f"item-a-{i}", {"finding_name": f"A Finding {i}"})
        for i in range(2):
            db_save_finding(projB["id"], f"item-b-{i}", {"finding_name": f"B Finding {i}"})

        resA = self.client.get(f"/api/projects/{projA['id']}/analytics").json()
        resB = self.client.get(f"/api/projects/{projB['id']}/analytics").json()

        self.assertEqual(resA["findings"]["total"], 8)
        self.assertEqual(resB["findings"]["total"], 2)

    def test_08_empty_project_state(self):
        """Acceptance Test 78: 0 findings returns clean 0 counts and 0.0 coverage without error."""
        proj = db_create_project({"name": "Clean Empty Assessment", "target_url": "https://empty.local"})
        self.created_project_ids.append(proj["id"])

        res = self.client.get(f"/api/projects/{proj['id']}/analytics")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["findings"]["total"], 0)
        self.assertEqual(data["coverage"]["planned"], 0)
        self.assertEqual(data["coverage"]["percentage"], 0.0)
        self.assertEqual(data["status"]["open"], 0)
        self.assertEqual(data["status"]["resolved"], 0)

    def test_09_large_project_scale(self):
        """Acceptance Test 79: Project with 55 findings aggregates accurately."""
        proj = db_create_project({"name": "Large Enterprise Assessment", "target_url": "https://large.local"})
        self.created_project_ids.append(proj["id"])
        pid = proj["id"]

        for i in range(55):
            db_save_finding(pid, f"scale-item-{i}", {
                "finding_name": f"Enterprise Finding #{i+1}",
                "priority": "MEDIUM" if i % 2 == 0 else "HIGH"
            })

        res = self.client.get(f"/api/projects/{pid}/analytics")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["findings"]["total"], 55)

    def test_10_authorization_and_user_isolation(self):
        """Acceptance Test 85: Non-existent project returns 404; invalid auth header handled."""
        res_404 = self.client.get("/api/projects/non-existent-proj-xyz/analytics")
        self.assertEqual(res_404.status_code, 404)

        proj = db_create_project({"name": "Auth Project", "target_url": "https://auth.local"})
        self.created_project_ids.append(proj["id"])

        # Invalid token format returns 401
        res_invalid = self.client.get(f"/api/projects/{proj['id']}/analytics", headers={"Authorization": "TokenBad"})
        self.assertEqual(res_invalid.status_code, 401)

    def test_11_dom_existing_cards_preserved(self):
        """Acceptance Test 84: Existing Overview cards remain completely intact."""
        # 1. Project Scope & Objectives intact
        self.assertIn("Project Scope & Objectives", HTML_CONTENT)
        self.assertIn('id="wsOverviewDescription"', HTML_CONTENT)
        self.assertIn('id="wsOverviewNotes"', HTML_CONTENT)

        # 2. Workspace Navigation intact
        self.assertIn("Workspace Navigation", HTML_CONTENT)
        self.assertIn("switchWorkspaceTab('checklist')", HTML_CONTENT)
        self.assertIn("switchWorkspaceTab('findings')", HTML_CONTENT)
        self.assertIn("switchWorkspaceTab('report')", HTML_CONTENT)
        self.assertIn("switchWorkspaceTab('autofix')", HTML_CONTENT)

        # 3. VAPT Assessment Completion Certificate card intact
        self.assertIn('id="wsCertificateStatusCard"', HTML_CONTENT)
        self.assertIn('id="wsCertStatusBadge"', HTML_CONTENT)
        self.assertIn('id="wsCertContentArea"', HTML_CONTENT)

        # 4. Danger Zone card intact
        self.assertIn('id="btnDeleteProject"', HTML_CONTENT)
        self.assertIn("Danger Zone", HTML_CONTENT)

    def test_12_analytics_card_and_modal_markup(self):
        """Acceptance Tests 71, 80, 81: Compact card and interactive modal elements exist."""
        # Compact card in right column
        self.assertIn('id="wsSecurityAnalyticsCard"', HTML_CONTENT)
        self.assertIn('id="wsAnalyticsLoading"', HTML_CONTENT)
        self.assertIn('id="wsAnalyticsError"', HTML_CONTENT)
        self.assertIn('id="wsAnalyticsEmpty"', HTML_CONTENT)
        self.assertIn('id="wsAnalyticsContent"', HTML_CONTENT)
        self.assertIn('id="wsCompactDonutContainer"', HTML_CONTENT)
        self.assertIn('id="wsCompactCountersGrid"', HTML_CONTENT)
        self.assertIn('id="btnRetryAnalytics"', HTML_CONTENT)

        # Interactive Modal
        self.assertIn('id="modalProjectSecurityAnalytics"', HTML_CONTENT)
        self.assertIn('id="btnCloseSecurityAnalyticsModal"', HTML_CONTENT)
        self.assertIn('id="btnCloseSecurityAnalyticsModalFooter"', HTML_CONTENT)

        # Metric Selectors
        self.assertIn('data-metric="severity"', HTML_CONTENT)
        self.assertIn('data-metric="coverage"', HTML_CONTENT)
        self.assertIn('data-metric="status"', HTML_CONTENT)

        # Chart Type Selectors
        self.assertIn('data-chart="donut"', HTML_CONTENT)
        self.assertIn('data-chart="bar"', HTML_CONTENT)
        self.assertIn('data-chart="table"', HTML_CONTENT)

        # Modal Viewport & Summary
        self.assertIn('id="modalAnalyticsChartViewport"', HTML_CONTENT)
        self.assertIn('id="modalAnalyticsSummarySection"', HTML_CONTENT)

    def test_13_frontend_js_functions_and_lifecycle_hooks(self):
        """Verify JavaScript analytics controller functions and hooks are wired."""
        self.assertIn("function fetchProjectAnalytics(", JS_CONTENT)
        self.assertIn("function refreshProjectSecurityAnalytics(", JS_CONTENT)
        self.assertIn("function renderCompactOverviewChart(", JS_CONTENT)
        self.assertIn("function openSecurityAnalyticsModal(", JS_CONTENT)
        self.assertIn("function renderModalAnalyticsContent(", JS_CONTENT)
        self.assertIn("refreshProjectSecurityAnalytics(proj.id)", JS_CONTENT)
        self.assertIn("window.refreshProjectSecurityAnalytics = refreshProjectSecurityAnalytics", JS_CONTENT)
        self.assertIn("window.openSecurityAnalyticsModal = openSecurityAnalyticsModal", JS_CONTENT)


if __name__ == "__main__":
    unittest.main()
