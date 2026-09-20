import re

with open("frontend/js/app.js", encoding="utf-8") as f:
    js = f.read()

# find all functions that mention download
functions = re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\([^)]*\)\s*\{[^}]*download[^}]*\}', js, re.I | re.DOTALL)
print("Functions mentioning download:")
for fn in set(functions):
    print(" ", fn)

# Check all click event listeners related to reports
print("\nEvent listeners with report or download:")
for m in re.finditer(r'([a-zA-Z0-9_\.]+)\.addEventListener\s*\(\s*["\']click["\']\s*,\s*(?:async\s*)?\([^)]*\)\s*=>', js):
    target = m.group(1)
    if any(k in target.lower() for k in ["report", "docx", "pdf", "download"]):
        print(" ", target)
