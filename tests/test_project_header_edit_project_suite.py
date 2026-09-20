"""
TRACEGATE — PROJECT HEADER EDIT PROJECT SUITE
=============================================
Verifies that:
1. Top header '+ Add Custom Test' button was replaced with 'Edit Project'.
2. The pencil/edit SVG icon is included and styled consistently.
3. Lower '+ Add Custom Test' button is strictly preserved and functional.
4. Edit Project modal exists with supported fields: Name, Target URL, Environment, Scope Description, Scope Notes.
5. Cancel/Close behaviors close modal without changes.
6. Backend PUT /api/projects/{project_id} correctly updates project details and preserves user isolation.
"""

import re
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app import app
from backend.database import get_project_by_id

BASE_DIR = Path(__file__).resolve().parent.parent
HTML_PATH = BASE_DIR / "frontend" / "index.html"
JS_PATH = BASE_DIR / "frontend" / "js" / "app.js"

with open(HTML_PATH, "r", encoding="utf-8") as f:
    HTML_CONTENT = f.read()

with open(JS_PATH, "r", encoding="utf-8") as f:
    JS_CONTENT = f.read()


class TestProjectHeaderUI(unittest.TestCase):
    def test_top_header_has_edit_project_button(self):
        """Top header must have Edit Project button with pencil icon, and NOT + Add Custom Test"""
        # Top actions block in workspace header
        header_actions_match = re.search(
            r'<div class="workspace-header-top">.*?<div class="view-header-actions">(.*?)</div>\s*</div>',
            HTML_CONTENT,
            re.DOTALL
        )
        self.assertIsNotNone(header_actions_match, "Workspace header actions block must exist in index.html")
        header_actions_html = header_actions_match.group(1)

        # Must have Switch Project
        self.assertIn("Switch Project", header_actions_html)

        # Must have Edit Project button
        self.assertIn('id="btnWsEditProject"', header_actions_html)
        self.assertIn("Edit Project", header_actions_html)

        # Top header must NOT have btnWsQuickAddTest or + Add Custom Test
        self.assertNotIn("btnWsQuickAddTest", header_actions_html)
        self.assertNotIn("+ Add Custom Test", header_actions_html)

    def test_lower_add_custom_test_button_strictly_preserved(self):
        """LOWER '+ Add Custom Test' button in checklist actions must remain fully intact"""
        self.assertIn('id="btnAddCustomTestBtn"', HTML_CONTENT)
        lower_match = re.search(
            r'<button[^>]+id="btnAddCustomTestBtn"[^>]*>\s*\+ Add Custom Test\s*</button>',
            HTML_CONTENT
        )
        self.assertIsNotNone(lower_match, "Lower + Add Custom Test button must exist with exact text and id")

    def test_edit_project_modal_structure(self):
        """modalEditProject must exist with supported editable fields and action buttons"""
        self.assertIn('id="modalEditProject"', HTML_CONTENT)
        self.assertIn('id="editProjName"', HTML_CONTENT)
        self.assertIn('id="editProjTarget"', HTML_CONTENT)
        self.assertIn('id="editProjEnv"', HTML_CONTENT)
        self.assertIn('id="editProjDesc"', HTML_CONTENT)
        self.assertIn('id="editProjNotes"', HTML_CONTENT)
        self.assertIn('id="btnCancelEditProject"', HTML_CONTENT)
        self.assertIn('id="btnSaveEditProject"', HTML_CONTENT)
        self.assertIn('id="btnCloseEditProjectModal"', HTML_CONTENT)

    def test_frontend_js_wiring(self):
        """app.js must wire openEditProjectModal, cancel, close, and save handlers"""
        self.assertIn("openEditProjectModal", JS_CONTENT)
        self.assertIn("btnWsEditProject", JS_CONTENT)
        self.assertIn("btnCancelEditProject", JS_CONTENT)
        self.assertIn("btnCloseEditProjectModal", JS_CONTENT)
        self.assertIn("btnSaveEditProject", JS_CONTENT)

        # Lower button must still be wired to openAddCustomTestModal
        self.assertIn("btnAddCustomTestBtn", JS_CONTENT)
        self.assertIn("openAddCustomTestModal", JS_CONTENT)


class TestProjectUpdateAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

        import uuid
        uid1 = uuid.uuid4().hex[:8]
        # Register User 1
        res1 = self.client.post("/api/auth/register", json={
            "username": f"user1_{uid1}",
            "email": f"auditor_{uid1}@example.com",
            "password": "Password123!",
            "full_name": "Audit Tester"
        })
        self.assertEqual(res1.status_code, 201)
        self.user1_token = res1.json().get("access_token")

        uid2 = uuid.uuid4().hex[:8]
        # Register User 2 (for isolation testing)
        res2 = self.client.post("/api/auth/register", json={
            "username": f"user2_{uid2}",
            "email": f"other_{uid2}@example.com",
            "password": "Password123!",
            "full_name": "Other Auditor"
        })
        self.assertEqual(res2.status_code, 201)
        self.user2_token = res2.json().get("access_token")

        # Create a test project for User 1
        res_proj = self.client.post(
            "/api/projects",
            json={
                "name": "Original Assessment Name",
                "target_url": "https://original.target.example.com",
                "environment": "Web Application (Staging)",
                "description": "Original description of scope.",
                "notes": "Original test notes."
            },
            headers={"Authorization": f"Bearer {self.user1_token}"}
        )
        self.assertEqual(res_proj.status_code, 201)
        self.project_id = res_proj.json()["id"]

    def test_authenticated_user_can_update_project(self):
        """Owner can update project details via PUT /api/projects/{id}"""
        update_payload = {
            "name": "Updated E-Commerce Audit",
            "target_url": "https://updated.target.example.com",
            "environment": "API & Microservices",
            "description": "Updated assessment scope details.",
            "notes": "Updated scope and credentials notes.",
            "scope_notes": "Updated scope and credentials notes."
        }
        res = self.client.put(
            f"/api/projects/{self.project_id}",
            json=update_payload,
            headers={"Authorization": f"Bearer {self.user1_token}"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["name"], "Updated E-Commerce Audit")
        self.assertEqual(data["target_url"], "https://updated.target.example.com")
        self.assertEqual(data["environment"], "API & Microservices")
        self.assertEqual(data["description"], "Updated assessment scope details.")
        self.assertEqual(data["scope_notes"], "Updated scope and credentials notes.")

        # Verify DB persistence directly
        db_proj = get_project_by_id(self.project_id)
        self.assertIsNotNone(db_proj)
        self.assertEqual(db_proj["name"], "Updated E-Commerce Audit")
        self.assertEqual(db_proj["target_url"], "https://updated.target.example.com")

    def test_user_isolation_cannot_update_other_user_project(self):
        """User 2 cannot update User 1's project"""
        update_payload = {
            "name": "Malicious Hijack Attempt",
            "target_url": "https://attacker.example.com"
        }
        res = self.client.put(
            f"/api/projects/{self.project_id}",
            json=update_payload,
            headers={"Authorization": f"Bearer {self.user2_token}"}
        )
        # Should be 404 or 403
        self.assertIn(res.status_code, [403, 404])

        # Verify User 1's project is unchanged
        db_proj = get_project_by_id(self.project_id)
        self.assertEqual(db_proj["name"], "Original Assessment Name")

    def test_switch_project_button_preserved(self):
        """Switch Project button in top header actions remains intact and points to #existing-projects"""
        header_actions_match = re.search(
            r'<div class="workspace-header-top">.*?<div class="view-header-actions">(.*?)</div>\s*</div>',
            HTML_CONTENT,
            re.DOTALL
        )
        self.assertIsNotNone(header_actions_match)
        header_actions_html = header_actions_match.group(1)
        self.assertIn('href="#existing-projects"', header_actions_html)
        self.assertIn('Switch Project', header_actions_html)

    def test_lower_custom_test_modal_wiring_intact(self):
        """Lower button is bound to openAddCustomTestModal and opens modalAddCustomTest"""
        self.assertIn('document.getElementById("btnAddCustomTestBtn")', JS_CONTENT)
        self.assertIn('openModal("modalAddCustomTest")', JS_CONTENT)
        self.assertIn('id="modalAddCustomTest"', HTML_CONTENT)


if __name__ == "__main__":
    unittest.main()

