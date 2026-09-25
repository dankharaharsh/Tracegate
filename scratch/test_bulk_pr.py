import sys
import os
import uuid
import time
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath("."))
from backend.app import app
from backend.database import get_db_connection, create_project, save_finding, save_user_github_config

client = TestClient(app)

def test_bulk():
    print("=== Bulk PR Trace ===")
    uid = uuid.uuid4().hex[:6]
    reg_resp = client.post("/api/auth/register", json={
        "username": f"bulk_tester_{uid}",
        "email": f"bulk_{uid}@tracegate.io",
        "password": "Password123!",
        "full_name": "Bulk Tester"
    })
    token = reg_resp.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}

    proj = create_project({
        "name": f"Bulk PR Test {uid}",
        "target_url": "https://shop.tracegate.internal",
        "environment": "Production",
        "owner_id": reg_resp.json()["user"]["id"]
    })
    proj_id = proj["id"]

    client.post("/api/github/connect", json={
        "token": "ghp_secureSampleTokenForVAPTTesting12345678",
        "repository": "tracegate-lab/ecommerce-platform"
    }, headers=headers)

    # Create 8 findings
    finding_defs = [
        ("VULN-SQLI-001", "SQL Injection in Search", "backend/controllers/searchController.js"),
        ("VULN-AUTH-002", "2FA Bypass Vulnerability", "backend/controllers/authController.js"),
        ("VULN-IDOR-003", "IDOR in Order History", "backend/controllers/orderController.js"),
        ("VULN-UPLD-004", "Unrestricted File Upload", "backend/controllers/uploadController.js"),
        ("VULN-XSS-005", "Stored XSS in Reviews", "backend/controllers/reviewController.js"),
        ("VULN-TRAV-006", "Path Traversal in Static Downloads", "backend/controllers/downloadController.js"),
        ("VULN-AUTO-007", "Credential Autocomplete Enabled", "backend/views/login.html"),
        ("VULN-SSRF-008", "SSRF in Webhook Delivery", "backend/controllers/webhookController.js")
    ]
    created_findings = []
    for vid, name, fpath in finding_defs:
        f = save_finding(proj_id, None, {
            "finding_name": name,
            "vuln_id": vid,
            "cwe": "CWE-89",
            "file_path": fpath,
            "priority": "HIGH",
            "status": "CONFIRMED"
        })
        created_findings.append(f)

    print(f"Created {len(created_findings)} findings.")

    # Call batch-patch
    batch_resp = client.post("/api/ai-fix/batch-patch", json={
        "project_id": proj_id,
        "repo": "tracegate-lab/ecommerce-platform",
        "branch": "main",
        "finding_ids": [f["id"] for f in created_findings]
    }, headers=headers)
    print(f"Batch patch status: {batch_resp.status_code}")
    batch_data = batch_resp.json()
    print("Batch patch patch_status:", batch_data.get("patch_status"))
    print("Batch patch files modified:", len(batch_data.get("files", [])))

    # Now apply bulk fix
    apply_resp = client.post("/api/ai-fix/apply", json={
        "finding_id": "__ALL_FINDINGS__",
        "project_id": proj_id,
        "repo": "tracegate-lab/ecommerce-platform",
        "base_branch": "main",
        "target_branch": "main",
        "fix_branch": "tracegate/fix/cumulative-security-patch",
        "file_path": batch_data.get("file_path") or "multi-file",
        "diff_or_fixed_code": batch_data.get("fixed_code") or batch_data.get("proposed_code"),
        "commit_message": "security: remediate confirmed VAPT findings across repository",
        "files": batch_data.get("files", []),
        "create_pr": True
    }, headers=headers)
    print(f"Bulk apply status: {apply_resp.status_code}")
    apply_data = apply_resp.json()
    print("Bulk apply data:", apply_data)

    # Check findings update
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, vuln_id, fix_status, github_branch, github_pr FROM findings WHERE project_id = ?", (proj_id,))
    rows = c.fetchall()
    print("\nFindings in DB after bulk apply:")
    for r in rows:
        print(dict(r))

    # Check ai_fixes
    c.execute("SELECT id, finding_id, repository, fix_branch, pr_number, pr_url, status FROM ai_fixes WHERE project_id = ?", (proj_id,))
    fixes = c.fetchall()
    print("\nai_fixes in DB:")
    for fx in fixes:
        print(dict(fx))
    conn.close()

if __name__ == "__main__":
    test_bulk()
