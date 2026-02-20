"""
ASCII-safe test script for 10-category scan verification.
Run from: backend/
Usage: python test_10_categories.py
"""
import urllib.request
import json
import uuid
import os
import sys

# Use port 8002 (new server with updated 10-category code), fallback to 8001, 8000
for port in [8002, 8001, 8000]:
    TARGET = f"http://localhost:{port}/api/scan"
    FILE   = r"d:\Yuck Fou Bootcamp Project\ai-security-scanner\demo-configs\vulnerable-agent.json"

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
        TARGET, data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )

    print(f"Scanning: {filename}")
    print(f"Endpoint: {TARGET}")
    print("=" * 70)

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read().decode())
        break  # success
    except urllib.error.URLError:
        if port == 8000:
            print("ERROR: Both ports 8001 and 8000 unreachable. Is the server running?")
            sys.exit(1)
        print(f"Port {port} unreachable, trying 8000...")
        continue

print(f"Risk Score    : {result['risk_score']}  ({result['risk_level']})")
print(f"Total Findings: {result['total_findings']}")
print(f"Scan Duration : {result['scan_duration']}s")
print()

findings = result.get("findings", [])
rule_count = 0
ai_count   = 0

print("--- FINDINGS ---")
for f in findings:
    method = f.get("detection_method", "?")
    icon   = "[AI  ]" if "llm" in method else "[Rule]"
    if "llm" in method:
        ai_count += 1
    else:
        rule_count += 1
    desc = f["description"][:65].replace("\n", " ")
    print(f"  {icon} [{f['severity']:8}] {f['category']} -- {desc}")

print()
print(f"Rule-based findings : {rule_count}")
print(f"AI-powered findings : {ai_count}")
print()

print("--- CATEGORY BREAKDOWN ---")
breakdown = result.get("breakdown_by_category", {})
ALL_10 = ["LLM01:2025","LLM02:2025","LLM03:2025","LLM04:2025","LLM05:2025",
          "LLM06:2025","LLM07:2025","LLM08:2025","LLM09:2025","LLM10:2025"]
for cat in ALL_10:
    score = breakdown.get(cat, 0.0)
    has_finding = any(f["category"] == cat for f in findings)
    flag = " <-- NEW!" if cat in ["LLM03:2025","LLM04:2025","LLM07:2025","LLM08:2025","LLM09:2025","LLM10:2025"] else ""
    status = "VULN" if has_finding else "clean"
    print(f"  {cat}: {status:5}  score_contrib={score:5.2f}{flag}")
