import sys
import os
import unittest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath("."))
from backend.app import app
from backend.database import get_db_connection, init_db, save_user_github_config

client = TestClient(app)

def run_trace():
    print("=== Step 1: User Registration & Project Setup ===")
    import uuid
    uid = uuid.uuid4().hex[:6]
    reg_resp = client.post("/api/auth/register", json={
        "username": f"pr_tester_{uid}",
        "email": f"pr_tester_{uid}@tracegate.io",
        "password": "Password123!",
        "full_name": "PR Tester"
    })
    token = reg_resp.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}
    print("User registered, token received.")

    # Create project
    proj_resp = client.post("/api/projects", json={
        "name": "E-Commerce Audit",
        "target_url": "https://shop.tracegate.internal",
        "scope": "Web Application"
    }, headers=headers)
    project = proj_resp.json()
    project_id = project["id"]
    print(f"Project created: {project_id}")

    # Connect github token (sandbox / mock repo or live)
    client.post("/api/github/connect", json={
        "token": "ghp_secureSampleTokenForVAPTTesting12345678",
        "repository": "tracegate-lab/ecommerce-platform"
    }, headers=headers)
    print("GitHub connected.")

    from backend.database import save_finding
    target_finding = save_finding(project_id, None, {
        "finding_name": "SQL Injection in Search Endpoint",
        "vuln_id": "VULN-SQLI-001",
        "cwe": "CWE-89",
        "affected_url": "/api/search",
        "file_path": "backend/controllers/searchController.js",
        "priority": "HIGH",
        "status": "CONFIRMED"
    })
    print(f"Target finding: {target_finding['vuln_id']} - {target_finding['finding_name']}")
    if not target_finding:
        # Create a finding
        from backend.database import get_project_checklist_items
        items = get_project_checklist_items(project_id)
        print(f"Checklist items count: {len(items)}")
        if items:
            c_resp = client.post(f"/api/projects/{project_id}/checklist/{items[0]['id']}/finding", headers=headers)
            print("Created finding from checklist item:", c_resp.status_code)
            findings_resp = client.get(f"/api/projects/{project_id}/findings", headers=headers)
            findings = findings_resp.json()
            target_finding = findings[0]

    print(f"Target finding: {target_finding['vuln_id']} - {target_finding['finding_name']}")

    print("\n=== Step 2: AI Fix Analyze ===")
    analyze_resp = client.post("/api/ai-fix/analyze", json={
        "finding_id": target_finding["id"],
        "project_id": project_id,
        "repo": "tracegate-lab/ecommerce-platform",
        "branch": "main"
    }, headers=headers)
    print(f"Analyze status code: {analyze_resp.status_code}")
    analysis_data = analyze_resp.json()
    print(f"Patch status: {analysis_data.get('patch_status')}")
    print(f"Success: {analysis_data.get('success')}")
    print(f"Files modified: {len(analysis_data.get('files', []))}")
    print(f"File path: {analysis_data.get('file_path')}")
    print(f"Proposed code length: {len(analysis_data.get('proposed_code', ''))}")

    print("\n=== Step 3: Apply Fix & Create PR ===")
    apply_resp = client.post("/api/ai-fix/apply", json={
        "finding_id": target_finding["id"],
        "project_id": project_id,
        "repo": "tracegate-lab/ecommerce-platform",
        "base_branch": "main",
        "target_branch": "main",
        "fix_branch": f"tracegate/autofix/{target_finding['vuln_id'].lower()}",
        "file_path": analysis_data.get("file_path"),
        "file_sha": analysis_data.get("file_sha"),
        "diff_or_fixed_code": analysis_data.get("proposed_code"),
        "commit_message": f"fix(security): remediate {target_finding['vuln_id']}",
        "files": analysis_data.get("files", []),
        "create_pr": True
    }, headers=headers)
    print(f"Apply response status: {apply_resp.status_code}")
    apply_data = apply_resp.json()
    print("Apply result:", apply_data)

    print("\n=== Step 4: Check ai_fixes and findings in DB ===")
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, finding_id, repository, base_branch, fix_branch, commit_sha, pr_number, pr_url, status FROM ai_fixes WHERE project_id = ?", (project_id,))
    ai_fixes = c.fetchall()
    print(f"AI Fixes count: {len(ai_fixes)}")
    for f in ai_fixes:
        print("ai_fix row:", dict(f))

    c.execute("SELECT id, vuln_id, fix_status, github_branch, github_commit, github_pr FROM findings WHERE id = ?", (target_finding["id"],))
    f_row = c.fetchone()
    print("finding row:", dict(f_row) if f_row else None)
    conn.close()

if __name__ == "__main__":
    run_trace()
