import re

with open('backend/database.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find all cursor.execute and conn.execute occurrences
lines = content.splitlines()
exec_lines = []
for i, line in enumerate(lines, 1):
    if 'cursor.execute' in line or 'conn.execute' in line:
        exec_lines.append((i, line))

print(f"Total execute lines: {len(exec_lines)}")

# Check for SQLite-specific patterns
sqlite_patterns = [
    (r'\bPRAGMA\b', "PRAGMA"),
    (r'\bsqlite_master\b', "sqlite_master"),
    (r'\bINSERT\s+OR\s+IGNORE\b', "INSERT OR IGNORE"),
    (r'\bINSERT\s+OR\s+REPLACE\b', "INSERT OR REPLACE"),
    (r'\bstrftime\b', "strftime"),
    (r'\bAUTOINCREMENT\b', "AUTOINCREMENT"),
    (r'\bEXCLUDED\b', "EXCLUDED"),
    (r'\bRANDOM\(\)', "RANDOM()")
]

for pat, name in sqlite_patterns:
    found = []
    for i, line in enumerate(lines, 1):
        if re.search(pat, line, re.IGNORECASE):
            found.append((i, line.strip()))
    print(f"Pattern {name}: {len(found)} matches")
    for line_num, text in found[:5]:
        print(f"   Line {line_num}: {text}")
