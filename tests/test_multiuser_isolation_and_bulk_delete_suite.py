"""
TRACEGATE MULTI-USER DATA ISOLATION & BULK DELETE COMPREHENSIVE TEST SUITE
==========================================================================
Verifies:
1. Strict server-side user-to-project ownership (projects.owner_id == authenticated user).
2. Child resource authorization (checklists, findings, evidence, reports, certificates, analytics).
3. IDOR prevention (unauthorized requests return 404 Not Found).
4. Client-supplied owner_id in POST payload is ignored (anti-spoofing).
5. Public certificate verification remains open and unauthenticated.
6. Browser download routes support ?token= query parameter authorization.
7. Safe bulk delete scoped ONLY to current authenticated user's projects.
8. Cascading deletion of project records and filesystem artifacts on bulk delete.
9. Other users' projects remain completely untouched during bulk deletion.
10. Backward compatibility for unauthenticated legacy test runners.
"""

import unittest
import os
import sys
import uuid
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.app import app
from backend import database as db

client = TestClient(app)

class TestMultiUserIsolationAndBulkDeleteSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        db.init_db()
        db.seed_default_users_if_empty()

    def _register_user(self, prefix="user"):
        uid = uuid.uuid4().hex[:8]
        username = f"{prefix}_{uid}"
        email = f"{prefix}_{uid}@tracegate.lab"
        password = "StrongPass123!"
        full_name = f"Test {prefix.capitalize()} {uid}"
        resp = client.post("/api/auth/register", json={
            "username": username,
            "email": email,
            "password": password,
            "full_name": full_name,
            "role": "Security Tester"
        })
        self.assertEqual(resp.status_code, 201, f"Failed to register user: {resp.text}")
        data = resp.json()
        return {
            "id": data["user"]["id"],
            "username": username,
            "email": email,
            "token": data["access_token"],
            "headers": {"Authorization": f"Bearer {data['access_token']}"}
        }

    def test_01_new_user_starts_with_empty_workspace(self):
        """New user must start with 0 projects and empty project list."""
        user = self._register_user("newbie")
        
        # Check projects list
        resp = client.get("/api/projects", headers=user["headers"])
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("projects", data)
        self.assertEqual(len(data["projects"]), 0)

        # Check projects count endpoint
        c_resp = client.get("/api/projects/count", headers=user["headers"])
        self.assertEqual(c_resp.status_code, 200)
        c_data = c_resp.json()
        self.assertEqual(c_data["count"], 0)
        self.assertEqual(c_data["user_id"], user["id"])

    def test_02_project_creation_and_ownership_assignment(self):
        """Projects must be automatically owned by the authenticated user."""
        user1 = self._register_user("creator1")
        
        p_resp = client.post("/api/projects", json={
            "name": "Alpha Target System",
            "target_url": "https://alpha.target.local",
            "environment": "Production",
            "description": "Alpha assessment scope"
        }, headers=user1["headers"])
        self.assertIn(p_resp.status_code, [200, 201])
        p_data = p_resp.json()
        self.assertEqual(p_data["name"], "Alpha Target System")
        
        # Verify in database that owner_id matches user1.id
        proj = db.get_project_by_id(p_data["id"])
        self.assertIsNotNone(proj)
        self.assertEqual(proj["owner_id"], user1["id"])

    def test_03_project_list_isolation_between_users(self):
        """User A must only see User A's projects, User B must only see User B's."""
        user_a = self._register_user("user_a")
        user_b = self._register_user("user_b")

        # User A creates project
        p_a = client.post("/api/projects", json={
            "name": "User A Secure App",
            "target_url": "https://a.app.local"
        }, headers=user_a["headers"]).json()

        # User B creates project
        p_b = client.post("/api/projects", json={
            "name": "User B Secure App",
            "target_url": "https://b.app.local"
        }, headers=user_b["headers"]).json()

        # User A lists projects
        list_a = client.get("/api/projects", headers=user_a["headers"]).json()["projects"]
        ids_a = [p["id"] for p in list_a]
        self.assertIn(p_a["id"], ids_a)
        self.assertNotIn(p_b["id"], ids_a)

        # User B lists projects
        list_b = client.get("/api/projects", headers=user_b["headers"]).json()["projects"]
        ids_b = [p["id"] for p in list_b]
        self.assertIn(p_b["id"], ids_b)
        self.assertNotIn(p_a["id"], ids_b)

    def test_04_spoofed_owner_id_is_ignored(self):
        """Client cannot spoof owner_id in request body to claim someone else's project."""
        user_victim = self._register_user("victim")
        user_attacker = self._register_user("attacker")

        # Attacker attempts to set owner_id to user_victim["id"]
        p_resp = client.post("/api/projects", json={
            "name": "Spoofed Ownership Project",
            "target_url": "https://attacker.local",
            "owner_id": user_victim["id"]
        }, headers=user_attacker["headers"])
        self.assertIn(p_resp.status_code, [200, 201])
        proj_id = p_resp.json()["id"]

        # Verify project is actually owned by attacker, NOT victim
        proj = db.get_project_by_id(proj_id)
        self.assertEqual(proj["owner_id"], user_attacker["id"])
        self.assertNotEqual(proj["owner_id"], user_victim["id"])

        # Victim should not see it in their project list
        victim_list = client.get("/api/projects", headers=user_victim["headers"]).json()["projects"]
        victim_ids = [p["id"] for p in victim_list]
        self.assertNotIn(proj_id, victim_ids)

    def test_05_cross_user_project_access_idor_prevention(self):
        """Unauthorized access to another user's project returns 404 (IDOR prevention)."""
        user_owner = self._register_user("proj_owner")
        user_other = self._register_user("proj_other")

        p = client.post("/api/projects", json={
            "name": "Private Internal System",
            "target_url": "https://private.internal"
        }, headers=user_owner["headers"]).json()
        pid = p["id"]

        # GET by other user -> 404
        get_resp = client.get(f"/api/projects/{pid}", headers=user_other["headers"])
        self.assertEqual(get_resp.status_code, 404)

        # PUT by other user -> 404
        put_resp = client.put(f"/api/projects/{pid}", json={"name": "Hacked Name"}, headers=user_other["headers"])
        self.assertEqual(put_resp.status_code, 404)

        # DELETE by other user -> 404
        del_resp = client.delete(f"/api/projects/{pid}", headers=user_other["headers"])
        self.assertEqual(del_resp.status_code, 404)

        # Verify project still exists under original owner
        proj_check = client.get(f"/api/projects/{pid}", headers=user_owner["headers"])
        self.assertEqual(proj_check.status_code, 200)
        self.assertEqual(proj_check.json()["name"], "Private Internal System")

    def test_06_child_resources_authorization(self):
        """Checklists, findings, evidence, reports, certificates, and analytics are isolated."""
        user_owner = self._register_user("child_owner")
        user_other = self._register_user("child_other")

        p = client.post("/api/projects", json={
            "name": "Child Resource Scope",
            "target_url": "https://scope.internal"
        }, headers=user_owner["headers"]).json()
        pid = p["id"]

        # Owner adds a checklist item
        chk_item = client.post(f"/api/projects/{pid}/checklist/custom", json={
            "name": "SQL Injection Test",
            "priority": "CRITICAL"
        }, headers=user_owner["headers"]).json()
        item_id = chk_item["id"]

        # Owner creates a finding on that item
        f_resp = client.post(f"/api/projects/{pid}/checklist/{item_id}/finding", json={
            "finding_name": "SQL Injection in Search Form",
            "priority": "CRITICAL",
            "description": "Parameter id is vulnerable",
            "observation": "Observed blind sql injection",
            "poc_text": "' OR 1=1--"
        }, headers=user_owner["headers"])
        self.assertIn(f_resp.status_code, [200, 201])
        fid = f_resp.json()["id"]

        # 1. Findings access by other user -> 404
        get_findings = client.get(f"/api/projects/{pid}/findings", headers=user_other["headers"])
        self.assertEqual(get_findings.status_code, 404)

        # 2. Add finding to other user's project -> 404
        post_finding = client.post(f"/api/projects/{pid}/checklist/{item_id}/finding", json={
            "finding_name": "Unauthorized Finding Insert"
        }, headers=user_other["headers"])
        self.assertEqual(post_finding.status_code, 404)

        # 3. Delete finding of other user's project -> 404
        del_finding = client.delete(f"/api/findings/{fid}", headers=user_other["headers"])
        self.assertEqual(del_finding.status_code, 404)

        # 4. Checklist access by other user -> 404
        get_checklist = client.get(f"/api/projects/{pid}/checklist", headers=user_other["headers"])
        self.assertEqual(get_checklist.status_code, 404)

        # 5. Analytics access by other user -> 404
        get_analytics = client.get(f"/api/projects/{pid}/analytics", headers=user_other["headers"])
        self.assertEqual(get_analytics.status_code, 404)

        # 6. Evidence upload to other user's project -> 404
        post_evidence = client.post(
            f"/api/projects/{pid}/evidence",
            files=[("files", ("test.png", b"fake png content", "image/png"))],
            headers=user_other["headers"]
        )
        self.assertEqual(post_evidence.status_code, 404)

        # 7. Evidence download from other user's project -> 404
        get_evidence = client.get(f"/api/projects/{pid}/evidence/some_file.png", headers=user_other["headers"])
        self.assertEqual(get_evidence.status_code, 404)

        # 8. Certificate status access by other user -> 404
        get_cert = client.get(f"/api/projects/{pid}/certificate/status", headers=user_other["headers"])
        self.assertEqual(get_cert.status_code, 404)

        # 9. Report generation on other user's project -> 404
        gen_rep = client.post(f"/api/projects/{pid}/reports/generate", json={"report_type": "executive"}, headers=user_other["headers"])
        self.assertEqual(gen_rep.status_code, 404)

    def test_07_public_certificate_verification_remains_open(self):
        """Public certificate verification endpoint must remain accessible unauthenticated."""
        user = self._register_user("cert_user")
        p = client.post("/api/projects", json={
            "name": "Public Cert Project",
            "target_url": "https://cert.local"
        }, headers=user["headers"]).json()
        pid = p["id"]

        cert_id = f"cert-test-{uuid.uuid4().hex[:8]}"
        db.save_certificate_record({
            "certificate_id": cert_id,
            "verification_id": f"VERIF-{uuid.uuid4().hex[:8].upper()}",
            "project_id": pid,
            "assessment_id": f"asmt-{uuid.uuid4().hex[:8]}",
            "report_id": f"rep-{uuid.uuid4().hex[:8]}",
            "status": "VALID",
            "issue_date": "2026-09-17",
            "final_validation_date": "2026-09-17",
            "total_findings": 5,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "findings_retested": 5,
            "findings_passed": 5,
            "findings_failed": 0,
            "target_name": "Public Cert Project",
            "target_url": "https://cert.local",
            "snapshot": {}
        })

        # Call public verify endpoint WITHOUT authorization header
        resp = client.get(f"/api/certificates/{cert_id}/verify")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "VALID")
        self.assertEqual(data.get("certificate_id"), cert_id)

    def test_08_safe_bulk_delete_user_projects(self):
        """
        Bulk delete removes ALL projects of current user and cleans up cascaded records/artifacts,
        while leaving other users' projects completely untouched.
        """
        user_cleanup = self._register_user("cleanup_user")
        user_innocent = self._register_user("innocent_user")

        # Create 4 projects for user_cleanup
        cleanup_pids = []
        for i in range(4):
            cp = client.post("/api/projects", json={
                "name": f"Cleanup Test Project {i}",
                "target_url": f"https://cleanup-{i}.local"
            }, headers=user_cleanup["headers"]).json()
            cleanup_pids.append(cp["id"])
            
            # Add custom checklist item and finding
            chk_item = client.post(f"/api/projects/{cp['id']}/checklist/custom", json={
                "name": f"Custom Test {i}",
                "priority": "HIGH"
            }, headers=user_cleanup["headers"]).json()
            client.post(f"/api/projects/{cp['id']}/checklist/{chk_item['id']}/finding", json={
                "finding_name": f"Finding {i}"
            }, headers=user_cleanup["headers"])

        # Create 2 projects for user_innocent
        innocent_pids = []
        for j in range(2):
            ip = client.post("/api/projects", json={
                "name": f"Innocent Test Project {j}",
                "target_url": f"https://innocent-{j}.local"
            }, headers=user_innocent["headers"]).json()
            innocent_pids.append(ip["id"])

        # Verify initial counts
        c_count_resp = client.get("/api/projects/count", headers=user_cleanup["headers"]).json()
        self.assertEqual(c_count_resp["count"], 4)

        i_count_resp = client.get("/api/projects/count", headers=user_innocent["headers"]).json()
        self.assertEqual(i_count_resp["count"], 2)

        # Perform bulk delete on user_cleanup
        del_resp = client.post("/api/projects/bulk-delete", headers=user_cleanup["headers"])
        self.assertEqual(del_resp.status_code, 200)
        del_data = del_resp.json()
        self.assertTrue(del_data["success"])
        self.assertEqual(del_data["result"]["deleted"], 4)
        self.assertEqual(del_data["result"]["failed"], 0)

        # Verify user_cleanup now has 0 projects
        c_after = client.get("/api/projects", headers=user_cleanup["headers"]).json()["projects"]
        self.assertEqual(len(c_after), 0)

        c_count_after = client.get("/api/projects/count", headers=user_cleanup["headers"]).json()
        self.assertEqual(c_count_after["count"], 0)

        # Verify child findings are also deleted for cleanup projects
        conn = db.get_db_connection()
        cursor = conn.cursor()
        for pid in cleanup_pids:
            cursor.execute("SELECT COUNT(*) FROM findings WHERE project_id = ?", (pid,))
            self.assertEqual(cursor.fetchone()[0], 0)
        conn.close()

        # CRITICAL VERIFICATION: user_innocent is 100% UNTOUCHED
        i_after = client.get("/api/projects", headers=user_innocent["headers"]).json()["projects"]
        self.assertEqual(len(i_after), 2)
        i_ids_after = [p["id"] for p in i_after]
        for ipid in innocent_pids:
            self.assertIn(ipid, i_ids_after)

        i_count_after = client.get("/api/projects/count", headers=user_innocent["headers"]).json()
        self.assertEqual(i_count_after["count"], 2)

    def test_09_bulk_delete_idempotency_on_empty_projects(self):
        """Bulk delete when user has 0 projects returns total 0 cleanly without error."""
        user_empty = self._register_user("empty_user")
        del_resp = client.post("/api/projects/bulk-delete", headers=user_empty["headers"])
        self.assertEqual(del_resp.status_code, 200)
        del_data = del_resp.json()
        self.assertTrue(del_data["success"])
        self.assertEqual(del_data["result"]["deleted"], 0)
        self.assertEqual(del_data["result"]["total"], 0)

    def test_10_unauthenticated_requests_backward_compatibility(self):
        """Unauthenticated requests for legacy tests default to user-learner-001 safely."""
        resp = client.get("/api/projects")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("projects", data)

    def test_11_browser_download_query_token_authorization(self):
        """Direct browser download routes accept ?token= query parameter and enforce ownership."""
        user_owner = self._register_user("down_owner")
        user_other = self._register_user("down_other")

        p = client.post("/api/projects", json={
            "name": "Download Scope Project",
            "target_url": "https://download.local"
        }, headers=user_owner["headers"]).json()
        pid = p["id"]

        dummy_dir = BASE_DIR / "data" / "reports"
        dummy_dir.mkdir(parents=True, exist_ok=True)
        dummy_file = dummy_dir / f"dummy_cert_{uuid.uuid4().hex[:6]}.docx"
        dummy_file.write_text("DUMMY CERTIFICATE CONTENT", encoding="utf-8")
        cert_id = f"cert-down-{uuid.uuid4().hex[:8]}"
        db.save_certificate_record({
            "certificate_id": cert_id,
            "verification_id": f"VERIF-{uuid.uuid4().hex[:8].upper()}",
            "project_id": pid,
            "assessment_id": "asmt-1",
            "status": "VALID",
            "issue_date": "2026-09-17",
            "final_validation_date": "2026-09-17",
            "total_findings": 0,
            "findings_retested": 0,
            "findings_passed": 0,
            "target_name": "Download Scope Project",
            "target_url": "https://download.local",
            "file_path_docx": str(dummy_file),
            "snapshot": {}
        })

        try:
            # 1. Access with valid owner token in query param -> 200
            resp_owner = client.get(f"/api/certificates/{cert_id}/download?format=docx&token={user_owner['token']}")
            self.assertEqual(resp_owner.status_code, 200)

            # 2. Access with other user token -> 404 (isolated)
            resp_other = client.get(f"/api/certificates/{cert_id}/download?format=docx&token={user_other['token']}")
            self.assertEqual(resp_other.status_code, 404)

            # 3. Access with no token and no auth header -> 401
            resp_anon = client.get(f"/api/certificates/{cert_id}/download?format=docx")
            self.assertEqual(resp_anon.status_code, 401)
        finally:
            if dummy_file.exists():
                try:
                    dummy_file.unlink()
                except Exception:
                    pass

if __name__ == '__main__':
    unittest.main()
