"""
TRACEGATE CHECKLIST GENERATION AUTHENTICATION & MULTI-USER ISOLATION TEST SUITE
================================================================================
Comprehensive verification for Checklist Generation:
- TEST A: Logged out / unauthenticated request to user project returns 401
- TEST B: Logged in + own project succeeds (200) with generated checklist
- TEST C: Logged in + another user's project rejected with 404 (IDOR prevention)
- TEST D: Logged in + no screenshot generates Page Type-specific checklist
- TEST E: Logged in + screenshot uploaded generates checklist with visual context
- TEST F: User switch A -> B maintains strict isolation (zero cross-user leakage)
- TEST G: Authenticated session persistence allows repeatable generation
- TEST H: Logout / invalidated session rejected with 401
- TEST I: Checklist status update and custom items require project ownership
- TEST J: Database persistence correctly attaches checklist & items to authorized project
- TEST K: Backward compatibility preserved for unauthenticated headless analyzer runs
"""

import unittest
import sys
import uuid
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.app import app
from backend import database as db

client = TestClient(app)

class TestChecklistAuthIsolationSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        db.init_db()
        db.seed_default_users_if_empty()

    def _register_user(self, prefix="chkuser"):
        uid = uuid.uuid4().hex[:8]
        username = f"{prefix}_{uid}"
        email = f"{prefix}_{uid}@tracegate.lab"
        password = "SecurePassword123!"
        resp = client.post("/api/auth/register", json={
            "username": username,
            "email": email,
            "password": password,
            "full_name": f"Tester {prefix.capitalize()}",
            "role": "Security Tester"
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

    def _create_project(self, user, name="Checklist Target"):
        resp = client.post("/api/projects", json={
            "name": f"{name} {uuid.uuid4().hex[:6]}",
            "target_url": "https://secure-target.local",
            "environment": "Staging",
            "description": "Checklist test target"
        }, headers=user["headers"])
        self.assertIn(resp.status_code, [200, 201])
        return resp.json()

    # =========================================================================
    # TEST A: Logged out -> checklist request to user project returns 401
    # =========================================================================
    def test_a_logged_out_checklist_request_returns_401(self):
        """Logged out user attempting to generate a checklist for a user project receives 401."""
        user = self._register_user("owner_a")
        proj = self._create_project(user)

        # Call /api/analyze-screenshot with project_id WITHOUT Authorization header
        resp = client.post("/api/analyze-screenshot", data={
            "page_type": "File Upload / Resource Management Page",
            "project_id": proj["id"]
        })
        self.assertEqual(resp.status_code, 401, f"Expected 401, got {resp.status_code}: {resp.text}")
        detail = resp.json().get("detail", "")
        self.assertIn("authentication", detail.lower())

    # =========================================================================
    # TEST B: Logged in + own project -> 200 OK and successful checklist generation
    # =========================================================================
    def test_b_logged_in_own_project_succeeds(self):
        """Authenticated user generating checklist for their own project succeeds with 200 OK."""
        user = self._register_user("owner_b")
        proj = self._create_project(user)

        resp = client.post("/api/analyze-screenshot", data={
            "page_type": "File Upload / Resource Management Page",
            "project_id": proj["id"]
        }, headers=user["headers"])
        self.assertEqual(resp.status_code, 200, f"Expected 200, got {resp.status_code}: {resp.text}")
        data = resp.json()
        self.assertIn("checklist", data)
        self.assertTrue(len(data["checklist"]) >= 4, "Checklist should contain security tests")

        # Verify checklist is persisted to project in DB
        chk_resp = client.get(f"/api/projects/{proj['id']}/checklist", headers=user["headers"])
        self.assertEqual(chk_resp.status_code, 200)
        chk_items = chk_resp.json().get("checklist", [])
        self.assertTrue(len(chk_items) >= 4, "Checklist items should be persisted in database")

    # =========================================================================
    # TEST C: Logged in + another user's project -> 404 (IDOR prevention)
    # =========================================================================
    def test_c_logged_in_another_user_project_returns_404(self):
        """Authenticated user cannot generate checklist for another user's project (404 IDOR)."""
        user_victim = self._register_user("victim_c")
        user_attacker = self._register_user("attacker_c")
        victim_proj = self._create_project(user_victim, "Victim Project")

        # Attacker attempts to target victim's project with attacker's token
        resp = client.post("/api/analyze-screenshot", data={
            "page_type": "Login / Sign-in Page",
            "project_id": victim_proj["id"]
        }, headers=user_attacker["headers"])
        self.assertEqual(resp.status_code, 404, f"Expected 404, got {resp.status_code}: {resp.text}")

    # =========================================================================
    # TEST D: Logged in + no screenshot (Page Type authoritative) -> 200 OK
    # =========================================================================
    def test_d_logged_in_no_screenshot_authoritative_page_type(self):
        """Checklist generation succeeds without a screenshot using authoritative Page Type."""
        user = self._register_user("user_d")
        proj = self._create_project(user)

        resp = client.post("/api/analyze-screenshot", data={
            "page_type": "File Upload / Resource Management Page",
            "project_id": proj["id"],
            "user_context": "App accepts PDF and SVG documents."
        }, headers=user["headers"])
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data.get("visual_analysis_available", True))
        self.assertIn("File Upload", data.get("page_type"))

        # Confirm file upload security test content
        test_names = [item["name"].lower() for item in data["checklist"]]
        self.assertTrue(any("upload" in name or "extension" in name or "mime" in name or "malicious" in name for name in test_names))

    # =========================================================================
    # TEST E: Logged in + screenshot uploaded -> 200 OK with visual context
    # =========================================================================
    def test_e_logged_in_with_screenshot_uploaded(self):
        """Checklist generation succeeds with uploaded screenshot image file."""
        user = self._register_user("user_e")
        proj = self._create_project(user)

        # 1x1 transparent PNG bytes
        png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"

        resp = client.post("/api/analyze-screenshot", files={
            "image": ("file_upload.png", png_bytes, "image/png")
        }, data={
            "page_type": "File Upload / Resource Management Page",
            "project_id": proj["id"]
        }, headers=user["headers"])
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("File Upload", data.get("page_type"))
        self.assertTrue(len(data.get("checklist", [])) > 0)

    # =========================================================================
    # TEST F: User Switch A -> B maintains strict isolation
    # =========================================================================
    def test_f_user_switch_maintains_isolation(self):
        """User A generates checklist on Project A; User B logs in and cannot see or access Project A's checklist."""
        user_a = self._register_user("switch_a")
        proj_a = self._create_project(user_a, "Alpha Project")

        # User A generates checklist
        resp_a = client.post("/api/analyze-screenshot", data={
            "page_type": "Login / Sign-in Page",
            "project_id": proj_a["id"]
        }, headers=user_a["headers"])
        self.assertEqual(resp_a.status_code, 200)

        # User A logs out
        client.post("/api/auth/logout", headers=user_a["headers"])

        # User B logs in / registers
        user_b = self._register_user("switch_b")
        proj_b = self._create_project(user_b, "Beta Project")

        # User B generates checklist on Beta
        resp_b = client.post("/api/analyze-screenshot", data={
            "page_type": "Checkout / Payment Page",
            "project_id": proj_b["id"]
        }, headers=user_b["headers"])
        self.assertEqual(resp_b.status_code, 200)

        # User B CANNOT read User A's checklist
        chk_a_b = client.get(f"/api/projects/{proj_a['id']}/checklist", headers=user_b["headers"])
        self.assertEqual(chk_a_b.status_code, 404)

        # User B CAN read User B's checklist
        chk_b_b = client.get(f"/api/projects/{proj_b['id']}/checklist", headers=user_b["headers"])
        self.assertEqual(chk_b_b.status_code, 200)

    # =========================================================================
    # TEST G: Page refresh / token persistence allows repeated generation
    # =========================================================================
    def test_g_token_persistence_allows_repeated_generation(self):
        """User can generate and regenerate checklists repeatedly with valid token."""
        user = self._register_user("repeat_user")
        proj = self._create_project(user)

        # Initial generation
        r1 = client.post("/api/analyze-screenshot", data={
            "page_type": "Login / Sign-in Page",
            "project_id": proj["id"]
        }, headers=user["headers"])
        self.assertEqual(r1.status_code, 200)

        # Subsequent generation on same project
        r2 = client.post("/api/analyze-screenshot", data={
            "page_type": "Administration / Dashboard Page",
            "project_id": proj["id"]
        }, headers=user["headers"])
        self.assertEqual(r2.status_code, 200)
        self.assertIn("Dashboard", r2.json()["page_type"])

    # =========================================================================
    # TEST H: Logout / invalidated session -> 401 Unauthorized
    # =========================================================================
    def test_h_logout_invalidates_session_for_checklist_generation(self):
        """After logging out, using the old token returns 401."""
        user = self._register_user("logout_user")
        proj = self._create_project(user)

        # Log out
        client.post("/api/auth/logout", headers=user["headers"])

        # Attempt generation with revoked token
        resp = client.post("/api/analyze-screenshot", data={
            "page_type": "Login / Sign-in Page",
            "project_id": proj["id"]
        }, headers=user["headers"])
        self.assertEqual(resp.status_code, 401)

    # =========================================================================
    # TEST I: Checklist status update and custom items require project ownership
    # =========================================================================
    def test_i_checklist_child_items_require_ownership(self):
        """Status updates and custom test creation enforce project ownership."""
        user_owner = self._register_user("item_owner")
        user_attacker = self._register_user("item_attacker")
        proj = self._create_project(user_owner)

        # Owner generates checklist
        client.post("/api/analyze-screenshot", data={
            "page_type": "Login / Sign-in Page",
            "project_id": proj["id"]
        }, headers=user_owner["headers"])

        chk = client.get(f"/api/projects/{proj['id']}/checklist", headers=user_owner["headers"]).json()
        item_id = chk["checklist"][0]["id"]

        # Owner updates status -> 200
        up_res = client.put(f"/api/checklist/{item_id}/status", json={
            "status": "TESTED_NOT_FOUND"
        }, headers=user_owner["headers"])
        self.assertEqual(up_res.status_code, 200)

        # Attacker tries to update status -> 404
        bad_up = client.put(f"/api/checklist/{item_id}/status", json={
            "status": "VULNERABILITY_FOUND"
        }, headers=user_attacker["headers"])
        self.assertEqual(bad_up.status_code, 404)

        # Attacker tries to add custom test to victim project -> 404
        bad_custom = client.post(f"/api/projects/{proj['id']}/checklist/custom", json={
            "name": "Malicious Custom Test",
            "priority": "HIGH"
        }, headers=user_attacker["headers"])
        self.assertEqual(bad_custom.status_code, 404)

    # =========================================================================
    # TEST J: Database persistence links checklist to project owner
    # =========================================================================
    def test_j_database_persistence_linked_to_authorized_project(self):
        """Database verification: checklist and items are strictly bound to project.owner_id."""
        user = self._register_user("db_check_user")
        proj = self._create_project(user, "DB Linked Proj")

        client.post("/api/analyze-screenshot", data={
            "page_type": "Search / Query Results Page",
            "project_id": proj["id"]
        }, headers=user["headers"])

        conn = db.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT owner_id FROM projects WHERE id = ?", (proj["id"],))
        db_owner = cursor.fetchone()[0]
        self.assertEqual(db_owner, user["id"])

        cursor.execute("SELECT project_id FROM checklists WHERE project_id = ?", (proj["id"],))
        self.assertIsNotNone(cursor.fetchone())

        cursor.execute("SELECT COUNT(*) FROM checklist_items WHERE project_id = ?", (proj["id"],))
        count = cursor.fetchone()[0]
        self.assertTrue(count >= 3)
        conn.close()

    # =========================================================================
    # TEST K: Backward compatibility for unauthenticated headless tests
    # =========================================================================
    def test_k_backward_compatibility_headless_analyzer(self):
        """Unauthenticated requests without project_id continue to work for algorithmic testing."""
        resp = client.post("/api/analyze-screenshot", data={
            "page_type": "Login / Sign-in Page"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["page_type"], "Login / Sign-in Page")
        self.assertTrue(len(data["checklist"]) > 0)

if __name__ == '__main__':
    unittest.main()
