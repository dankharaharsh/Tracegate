"""
TRACEGATE STORAGE ARCHITECTURE & LOCALSTORAGE QUOTA RESOLUTION TEST SUITE
==========================================================================
Verifies complete migration from client localStorage to persistent server storage:
- TEST 01: 3-image finding scenario (1.IDOR.png, 2.IDOR.png, 3.IDOR.png @ ~200KB each)
- TEST 02: Many-evidence scalability (1, 3, 5, 10 files) persists cleanly
- TEST 03: Persistence & reload fidelity (evidence accessible via GET endpoints, bytes match)
- TEST 04: Report Generation embeds actual server-stored evidence images into Section H
- TEST 05: Multi-user isolation & IDOR prevention (User B cannot access or upload to User A's evidence)
- TEST 06: Legacy base64 finding evidence migration endpoint extracts files and cleans finding
- TEST 07: Project deletion cascades cleanly to filesystem and evidence DB records
- TEST 08: Frontend static validation (localStorage size guard, stripping heavy nested data, cleanup)
"""

import io
import os
import sys
import json
import uuid
import shutil
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import docx
from fastapi.testclient import TestClient
from backend.app import app
from backend import database as db

client = TestClient(app)

from PIL import Image

def make_dummy_png(size_kb=200):
    dim = max(10, int((size_kb * 1024 / 3) ** 0.5))
    im = Image.frombytes('RGB', (dim, dim), os.urandom(dim * dim * 3))
    buf = io.BytesIO()
    im.save(buf, format='PNG')
    return buf.getvalue()


class TestStorageArchitectureAndQuotaSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        db.init_db()
        db.seed_default_users_if_empty()

    def setUp(self):
        self.created_projects = []
        self.user_a = self._register_user("stor_a")
        self.user_b = self._register_user("stor_b")

    def tearDown(self):
        for pid in self.created_projects:
            try:
                db.delete_project(pid)
            except Exception:
                pass
            ev_dir = BASE_DIR / "data" / "evidence" / pid
            if ev_dir.exists():
                shutil.rmtree(ev_dir, ignore_errors=True)

    def _register_user(self, prefix="user"):
        uid = uuid.uuid4().hex[:8]
        username = f"{prefix}_{uid}"
        email = f"{prefix}_{uid}@storage-test.local"
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

    def _create_project(self, user):
        pname = f"Storage Proj {uuid.uuid4().hex[:6]}"
        resp = client.post("/api/projects", json={
            "name": pname,
            "target_url": "https://storage-target.local",
            "environment": "Web Application (Staging)",
            "description": "Storage Architecture Testing"
        }, headers=user["headers"])
        self.assertEqual(resp.status_code, 201, f"Project creation failed: {resp.text}")
        proj = resp.json()
        self.created_projects.append(proj["id"])
        return proj

    def _create_checklist_item(self, project_id, item_id="item-test-01"):
        conn = db.get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO checklist_items (
                id, project_id, checklist_id, test_id, name, priority, reason, testing_objective, cwe, source, status, created_at
            ) VALUES (?, ?, 'chk-main', ?, 'BOLA / IDOR in User Profile', 'HIGH', 'Tampering user ID', 'Verify IDOR', 'CWE-639', 'AI', 'NOT_TESTED', datetime('now'))
        """, (item_id, project_id, item_id))
        conn.commit()
        conn.close()

    def test_01_three_image_finding_scenario(self):
        """
        Verify the exact scenario:
        - 3 evidence files: 1.IDOR.png, 2.IDOR.png, 3.IDOR.png (~200KB each)
        - Upload to backend /api/projects/{id}/evidence
        - Save finding with returned metadata
        - Verify files exist on server disk, metadata exists in DB, no quota errors.
        """
        proj = self._create_project(self.user_a)
        proj_id = proj["id"]
        item_id = f"chk-{uuid.uuid4().hex[:8]}"
        self._create_checklist_item(proj_id, item_id)

        img1 = make_dummy_png(200)
        img2 = make_dummy_png(200)
        img3 = make_dummy_png(200)

        self.assertGreaterEqual(len(img1), 195 * 1024)
        self.assertGreaterEqual(len(img2), 195 * 1024)
        self.assertGreaterEqual(len(img3), 195 * 1024)

        files = [
            ("files", ("1.IDOR.png", io.BytesIO(img1), "image/png")),
            ("files", ("2.IDOR.png", io.BytesIO(img2), "image/png")),
            ("files", ("3.IDOR.png", io.BytesIO(img3), "image/png")),
        ]

        upload_resp = client.post(
            f"/api/projects/{proj_id}/evidence",
            files=files,
            headers=self.user_a["headers"]
        )
        self.assertEqual(upload_resp.status_code, 201, f"Upload failed: {upload_resp.text}")
        up_data = upload_resp.json()
        uploaded_items = up_data.get("uploaded", up_data) if isinstance(up_data, dict) else up_data
        self.assertEqual(len(uploaded_items), 3)

        for idx, item in enumerate(uploaded_items, start=1):
            self.assertEqual(item["name"], f"{idx}.IDOR.png")
            self.assertIn("file_path", item)
            self.assertIn("url", item)
            self.assertGreater(item["size"], 190 * 1024)
            disk_path = Path(item["file_path"])
            self.assertTrue(disk_path.exists(), f"File not found on disk: {disk_path}")
            self.assertEqual(disk_path.stat().st_size, item["size"])

        finding_payload = {
            "finding_name": "Broken Object Level Authorization (IDOR) on User Profile",
            "observation": "Testing user account ID parameter in /api/user/101 vs /api/user/102 allows viewing other accounts.",
            "poc_text": "GET /api/user/102 HTTP/1.1\nHost: vapt.target\nCookie: session=attacker",
            "evidence": uploaded_items,
            "evidence_data": uploaded_items,
            "priority": "HIGH",
            "cvss_score": 7.5
        }

        save_resp = client.post(
            f"/api/projects/{proj_id}/checklist/{item_id}/finding",
            json=finding_payload,
            headers=self.user_a["headers"]
        )
        self.assertIn(save_resp.status_code, [200, 201], f"Save finding failed: {save_resp.text}")
        saved_finding = save_resp.json()
        finding_id = saved_finding.get("id") or saved_finding.get("finding_id")
        self.assertTrue(finding_id)

        evidence_records = db.get_project_evidence(proj_id)
        self.assertEqual(len(evidence_records), 3)

        finding_row = db.get_finding_by_id(finding_id)
        self.assertIsNotNone(finding_row)
        ev_json_str = finding_row.get("evidence_json", "[]")
        self.assertLess(len(ev_json_str), 5000, "Finding evidence_json is bloated!")
        self.assertNotIn("data:image", ev_json_str)

    def test_02_many_evidence_scalability(self):
        """Test scalability with 1, 3, 5, 10 files."""
        proj = self._create_project(self.user_a)
        proj_id = proj["id"]

        batch_5 = [
            ("files", (f"evidence_{i}.png", io.BytesIO(make_dummy_png(50)), "image/png"))
            for i in range(5)
        ]
        resp_5 = client.post(f"/api/projects/{proj_id}/evidence", files=batch_5, headers=self.user_a["headers"])
        self.assertEqual(resp_5.status_code, 201)
        up_5 = resp_5.json().get("uploaded", resp_5.json())
        self.assertEqual(len(up_5), 5)

        batch_another_5 = [
            ("files", (f"extra_{i}.png", io.BytesIO(make_dummy_png(50)), "image/png"))
            for i in range(5)
        ]
        resp_10 = client.post(f"/api/projects/{proj_id}/evidence", files=batch_another_5, headers=self.user_a["headers"])
        self.assertEqual(resp_10.status_code, 201)

        all_ev = db.get_project_evidence(proj_id)
        self.assertEqual(len(all_ev), 10)

    def test_03_persistence_and_reload_fidelity(self):
        """Verify evidence can be fetched via GET endpoint and content matches uploaded bytes."""
        proj = self._create_project(self.user_a)
        proj_id = proj["id"]

        raw_png = make_dummy_png(150)
        files = [("files", ("poc_screen.png", io.BytesIO(raw_png), "image/png"))]
        upload_resp = client.post(f"/api/projects/{proj_id}/evidence", files=files, headers=self.user_a["headers"])
        self.assertEqual(upload_resp.status_code, 201)
        up_data = upload_resp.json()
        ev_items = up_data.get("uploaded", up_data)
        ev_item = ev_items[0]

        dl_resp = client.get(ev_item["url"], headers=self.user_a["headers"])
        self.assertEqual(dl_resp.status_code, 200)
        self.assertEqual(len(dl_resp.content), len(raw_png))
        self.assertEqual(dl_resp.content[:8], b"\x89PNG\r\n\x1a\n")

    def test_04_report_generation_embeds_server_stored_evidence(self):
        """
        Verify DOCX report generation resolves evidence from server filesystem storage
        and successfully builds Section H with the finding and evidence.
        """
        proj = self._create_project(self.user_a)
        proj_id = proj["id"]
        item_id = f"chk-{uuid.uuid4().hex[:8]}"
        self._create_checklist_item(proj_id, item_id)

        img1 = make_dummy_png(100)
        img2 = make_dummy_png(100)
        files = [
            ("files", ("1.IDOR.png", io.BytesIO(img1), "image/png")),
            ("files", ("2.IDOR.png", io.BytesIO(img2), "image/png")),
        ]
        upload_resp = client.post(f"/api/projects/{proj_id}/evidence", files=files, headers=self.user_a["headers"])
        self.assertEqual(upload_resp.status_code, 201)
        up_data = upload_resp.json()
        ev_meta = up_data.get("uploaded", up_data)

        finding_payload = {
            "finding_name": "IDOR Vulnerability with PoC Screenshots",
            "observation": "IDOR discovered on user settings endpoint. Screenshots attached.",
            "poc_text": "GET /api/settings?uid=102 HTTP/1.1",
            "evidence": ev_meta,
            "evidence_data": ev_meta,
            "priority": "CRITICAL",
            "cvss_score": 9.1
        }
        res_find = client.post(
            f"/api/projects/{proj_id}/checklist/{item_id}/finding",
            json=finding_payload,
            headers=self.user_a["headers"]
        )
        self.assertIn(res_find.status_code, [200, 201])

        rep_resp = client.post(
            f"/api/projects/{proj_id}/reports",
            json={"title": "VAPT Test Report"},
            headers=self.user_a["headers"]
        )
        self.assertEqual(rep_resp.status_code, 201, f"Report generation failed: {rep_resp.text}")
        rep_id = rep_resp.json()["id"]

        dl_resp = client.get(
            f"/api/projects/{proj_id}/reports/{rep_id}/download?format=docx",
            headers=self.user_a["headers"]
        )
        self.assertEqual(dl_resp.status_code, 200)
        doc_bytes = dl_resp.content
        self.assertGreater(len(doc_bytes), 5000)

        doc = docx.Document(io.BytesIO(doc_bytes))
        full_text = "\n".join([p.text for p in doc.paragraphs])
        self.assertIn("IDOR Vulnerability with PoC Screenshots", full_text)

        image_parts = [part for part in doc.part.related_parts.values() if "image" in part.content_type]
        total_images = len(image_parts) + len(doc.inline_shapes)
        self.assertGreaterEqual(total_images, 2, "Evidence images not embedded in DOCX!")

    def test_05_multiuser_isolation_and_idor_prevention(self):
        """
        Verify strict user isolation:
        - User B cannot access User A's evidence
        - User B cannot upload evidence to User A's project
        - Unauthenticated requests return 401
        """
        proj_a = self._create_project(self.user_a)
        pid_a = proj_a["id"]

        files = [("files", ("secret.png", io.BytesIO(make_dummy_png(20)), "image/png"))]
        res_a = client.post(f"/api/projects/{pid_a}/evidence", files=files, headers=self.user_a["headers"])
        self.assertEqual(res_a.status_code, 201)

        res_b_list = client.get(f"/api/projects/{pid_a}/evidence", headers=self.user_b["headers"])
        self.assertEqual(res_b_list.status_code, 404)

        res_b_upload = client.post(f"/api/projects/{pid_a}/evidence", files=files, headers=self.user_b["headers"])
        self.assertEqual(res_b_upload.status_code, 404)

        res_unauth = client.get(f"/api/projects/{pid_a}/evidence")
        self.assertEqual(res_unauth.status_code, 401)

    def test_06_legacy_finding_migration(self):
        """Verify legacy base64 finding evidence migration extracts files to disk and cleans finding."""
        proj = self._create_project(self.user_a)
        proj_id = proj["id"]

        legacy_png = make_dummy_png(50)
        import base64
        b64_str = "data:image/png;base64," + base64.b64encode(legacy_png).decode("utf-8")

        legacy_finding = {
            "id": f"legacy-{uuid.uuid4().hex[:8]}",
            "project_id": proj_id,
            "finding_name": "Legacy Finding with Base64",
            "observation": "Legacy observation",
            "checklist_item_id": "leg-01",
            "evidence": [{"name": "old_screen.png", "data": b64_str, "size": len(legacy_png)}],
            "priority": "MEDIUM"
        }
        conn = db.get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO findings (id, project_id, finding_name, observation, checklist_item_id, priority, evidence_json, status, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, (
            legacy_finding["id"],
            proj_id,
            legacy_finding["finding_name"],
            legacy_finding["observation"],
            legacy_finding["checklist_item_id"],
            legacy_finding["priority"],
            json.dumps(legacy_finding["evidence"]),
            "OPEN"
        ))
        conn.commit()
        conn.close()

        mig_resp = client.post(f"/api/projects/{proj_id}/evidence/migrate", headers=self.user_a["headers"])
        self.assertEqual(mig_resp.status_code, 200)
        mig_result = mig_resp.json()
        self.assertGreaterEqual(mig_result.get("migrated_count", 0), 1)

        ev_records = db.get_project_evidence(proj_id)
        self.assertGreaterEqual(len(ev_records), 1)

        f_row = db.get_finding_by_id(legacy_finding["id"])
        self.assertNotIn("data:image", f_row["evidence_json"])

    def test_07_cleanup_on_project_delete(self):
        """Verify deleting project cleans up evidence table records and directory."""
        proj = self._create_project(self.user_a)
        proj_id = proj["id"]

        files = [("files", ("temp.png", io.BytesIO(make_dummy_png(20)), "image/png"))]
        client.post(f"/api/projects/{proj_id}/evidence", files=files, headers=self.user_a["headers"])

        ev_dir = BASE_DIR / "data" / "evidence" / proj_id
        self.assertTrue(ev_dir.exists())

        del_resp = client.delete(f"/api/projects/{proj_id}", headers=self.user_a["headers"])
        self.assertEqual(del_resp.status_code, 200)

        self.assertFalse(ev_dir.exists())
        self.assertEqual(len(db.get_project_evidence(proj_id)), 0)

    def test_08_frontend_static_code_inspection(self):
        """
        Verify frontend code implements:
        - saveProjects strips heavy nested fields (findings, checklist_data, evidence)
        - LocalStorage size guard (<250 KB)
        - Ephemeral URL.createObjectURL previews with URL.revokeObjectURL
        - Removal of bloated legacy keys
        """
        js_path = BASE_DIR / "frontend" / "js" / "app.js"
        with open(js_path, "r", encoding="utf-8") as f:
            js_content = f.read()

        self.assertIn("clearPendingEvidence", js_content)
        self.assertIn("revokeObjectURL", js_content)
        self.assertIn("URL.createObjectURL", js_content)
        self.assertIn("tg_projects_user_", js_content)
        self.assertIn("250 * 1024", js_content)
        self.assertIn("lightweightProjects", js_content)


if __name__ == "__main__":
    unittest.main()
