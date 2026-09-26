from backend.ai_autofix import discover_repository_sources
from backend.remediation_engine_v2 import build_repository_index, map_finding_to_code

files = {
    'README.md': '# Mixed Project',
    'app.py': 'from flask import Flask\napp = Flask(__name__)\n@app.route("/hello")\ndef hello():\n    return "Hello World"\n',
    'sql_vulnerable.py': 'import sqlite3\ndef get_account_data(account_id):\n    conn = sqlite3.connect("db.sqlite")\n    cursor = conn.cursor()\n    query = "SELECT * FROM accounts WHERE id = \'" + account_id + "\'"\n    cursor.execute(query)\n    return cursor.fetchall()\n'
}
tree = [{'path': p, 'type': 'blob', 'size': len(c)} for p, c in files.items()]

finding = {
    'id': 'VULN-SQL',
    'finding_name': 'SQL Injection in Account Query',
    'title': 'SQL Injection',
    'cwe': 'CWE-89',
    'affected_endpoint': '/account',
    'observation': 'Raw query execution in account search leads to SQL injection',
    'file_path': 'app.py',
    'affected_component': 'app.py'
}

res = discover_repository_sources(finding, tree, lambda p: files.get(p, ''))
print('Discovery selected_sources:', [s['path'] for s in res.get('selected_sources', [])])
for c in res.get('selected_sources', []) + res.get('candidate_sources', []):
    print(f'Candidate: {c["path"]} score={c["relevance_score"]} reasons={c["reasons"]}')

idx = build_repository_index(tree, lambda p: files.get(p, ''), 'test-repo', 'main')
m = map_finding_to_code(finding, idx)
print('map_finding_to_code selected_files:', m.get('selected_files'))
