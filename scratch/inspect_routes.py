import re

with open('backend/app.py', 'r', encoding='utf-8') as f:
    text = f.read()

routes = re.findall(r'@app\.(?:get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]', text)
print("Routes related to fix/pr/github:")
for r in routes:
    if any(k in r for k in ['fix', 'pr', 'pull', 'branch', 'patch', 'apply', 'github']):
        print(" -", r)
