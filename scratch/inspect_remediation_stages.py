with open('backend/remediation_engine_v2.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

for i, l in enumerate(lines):
    if any(k in l for k in ['RUN_FINALIZED', 'FINALIZED', 'COMPLETED', 'PATCH_VALIDATED']):
        if 'logger' in l or 'return' in l or 'status =' in l or 'status":' in l:
            print(f"{i+1}: {l.strip()[:120]}")
