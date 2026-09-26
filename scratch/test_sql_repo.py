from backend.remediation_engine_v2 import map_finding_to_code, build_repository_index, run_repository_remediation

repo = {
    'README.md': '# Project\n',
    'sql_vulnerable.py': (
        'def get_user(username):\n'
        '    sql = f"SELECT * FROM users WHERE username = \'{username}\'"\n'
        '    db.execute(sql)\n'
    )
}
tree_items = [{'path': p, 'type': 'blob', 'size': len(c)} for p, c in repo.items()]
idx = build_repository_index(tree_items, lambda p: repo.get(p, ''), 'test-sql-repo', 'main')

f = {
    'id': 'FIND-SQL-01',
    'title': 'SQL Injection in user lookup',
    'cwe': 'CWE-89',
    'description': 'SQL injection vulnerability in user query'
}
mapping = map_finding_to_code(f, idx)
print('Mapping selected_files:', mapping.get('selected_files'))
print('Mapping status:', mapping.get('status'))
print('Mapping candidate_files:', mapping.get('candidate_files'))

res = run_repository_remediation([f], 'test-sql-repo', 'main', tree_items, lambda p: repo.get(p, ''))
print('Remediation modified files:', [fm['path'] for fm in res.get('files', [])])
print('Remediation file_path:', res.get('file_path'))
print('Remediation patch_status:', res.get('patch_status'))
print('Remediation overall_status:', res.get('overall_status'))
for fin in res.get('findings', []):
    print('Finding status:', fin.get('status'), 'mappedFiles:', fin.get('mappedFiles'), 'modifiedFiles:', fin.get('modifiedFiles'))
