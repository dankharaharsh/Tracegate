import re
from pathlib import Path
from backend.database import _translate_sqlite_to_postgres

sql_queries = []
for p in Path("backend").glob("*.py"):
    content = p.read_text(encoding="utf-8")
    # match execute("...") or execute('''...''')
    matches = re.findall(r'cursor\.execute\(\s*([fF]?["\'][\s\S]*?["\'])\s*[,)]', content)
    for m in matches:
        # cleanup quotes
        cleaned = m.strip()
        if cleaned.startswith(('f"', "f'", 'F"', "F'")):
            cleaned = cleaned[2:-1]
        elif cleaned.startswith(('"""', "'''")):
            cleaned = cleaned[3:-3]
        elif cleaned.startswith(('"', "'")):
            cleaned = cleaned[1:-1]
        sql_queries.append((p.name, cleaned.strip()))

print(f"Total execute calls found: {len(sql_queries)}")
failures = []
for fname, sql in sql_queries:
    try:
        translated = _translate_sqlite_to_postgres(sql)
        # Check if any SQLite-specific syntax remains that postgres would choke on
        if "sqlite_master" in translated.lower() and "select" not in translated.lower():
            failures.append((fname, sql, translated, "sqlite_master issue"))
        if "pragma" in translated.lower() and "select" not in translated.lower():
            failures.append((fname, sql, translated, "pragma issue"))
    except Exception as e:
        failures.append((fname, sql, "", str(e)))

print(f"Failures or warnings: {len(failures)}")
for fname, sql, trans, reason in failures[:10]:
    print(f"[{fname}] {reason}: {sql[:60]}... -> {trans[:60]}...")
