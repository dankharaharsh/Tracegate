import re

with open("frontend/js/app.js", encoding="utf-8") as f:
    lines = f.readlines()

print("All lines with 'download' and ('report' or 'docx' or 'pdf') in frontend/js/app.js:")
for idx, line in enumerate(lines, 1):
    l_lower = line.lower()
    if 'download' in l_lower and any(k in l_lower for k in ['report', 'docx', 'pdf', 'history']):
        safe_line = line.strip().encode('ascii', errors='replace').decode()
        print(f"Line {idx}: {safe_line[:120]}")
