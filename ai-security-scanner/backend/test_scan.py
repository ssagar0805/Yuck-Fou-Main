"""
Test script: POST the vulnerable-agent.json to the scan endpoint and print detection methods.
Run from: backend/
Usage: python test_scan.py
"""
import urllib.request
import urllib.parse
import json
import mimetypes
import uuid
import os

TARGET = "http://localhost:8001/api/scan"
FILE   = r"d:\Yuck Fou Bootcamp Project\ai-security-scanner\demo-configs\vulnerable-agent.json"

# ── Build multipart/form-data manually ─────────────────────────────────────
boundary = uuid.uuid4().hex
with open(FILE, "rb") as f:
    file_data = f.read()

filename = os.path.basename(FILE)
body = (
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
    f"Content-Type: application/json\r\n"
    f"\r\n"
).encode() + file_data + f"\r\n--{boundary}--\r\n".encode()

req = urllib.request.Request(
    TARGET,
    data=body,
    method="POST",
    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
)

print(f"Scanning: {filename}")
print(f"Endpoint: {TARGET}")
print("=" * 60)

try:
    with urllib.request.urlopen(req, timeout=90) as resp:
        result = json.loads(resp.read().decode())

    print(f"Risk Score  : {result['risk_score']}  ({result['risk_level']})")
    print(f"Total Findings : {result['total_findings']}")
    print(f"Scan Duration  : {result['scan_duration']}s")
    print()
    print("FINDINGS:")
    print("-" * 60)

    rule_count = 0
    ai_count   = 0
    for f in result.get("findings", []):
        method = f.get("detection_method", "?")
        icon   = "🤖 AI  " if "llm" in method else "⚡ Rule"
        if "llm" in method:
            ai_count += 1
        else:
            rule_count += 1
        print(f"  [{icon}] [{f['severity']:8}] {f['category']} — {f['description'][:60]}")

    print()
    print(f"Rule-based findings : {rule_count}")
    print(f"AI-powered findings : {ai_count}  ← should be > 0 after fix")

except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")
