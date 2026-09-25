import sqlite3
from pathlib import Path

for p in [Path("data/tracegate.db"), Path("tracegate.db")]:
    if p.exists():
        print(f"=== Checking {p} ===")
        conn = sqlite3.connect(p)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [r[0] for r in cur.fetchall()]
        print(f"Tables in {p}: {len(tables)}")
        for t in tables:
            try:
                cur.execute(f'SELECT COUNT(*) FROM "{t}"')
                cnt = cur.fetchone()[0]
                print(f"  {t}: {cnt} rows")
            except Exception as e:
                print(f"  {t}: error {e}")
        conn.close()
