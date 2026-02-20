"""
Batch verification test for all 6 new OWASP categories.
Tests each file against port 8003 (server with fixed 10-category code).
Run from: backend/
Usage: python test_6_new_categories.py
"""
import urllib.request
import json
import uuid
import os
import sys

PORT = 8003    # New server with all fixes
BASE_DIR = r"d:\Yuck Fou Bootcamp Project\ai-security-scanner\demo-configs"

TEST_CASES = [
    ("llm03_supply_chain_vuln.json",             "LLM03:2025", "Supply Chain"),
    ("llm04_data_model_poisoning_vuln.yaml",     "LLM04:2025", "Data/Model Poisoning"),
    ("llm07_system_prompt_leakage_vuln.txt",     "LLM07:2025", "System Prompt Leakage"),
    ("llm08_vector_embedding_weaknesses_vuln.json", "LLM08:2025", "Vector/Embedding"),
    ("llm09_misinformation_vuln.txt",            "LLM09:2025", "Misinformation"),
    ("llm10_unbounded_consumption_vuln.json",    "LLM10:2025", "Unbounded Consumption"),
]

TARGET_BASE = f"http://localhost:{PORT}/api/scan"


def scan_file(filepath: str) -> dict:
    filename = os.path.basename(filepath)
    ext = filename.rsplit(".", 1)[-1].lower()
    content_types = {"json": "application/json", "yaml": "text/x-yaml", "txt": "text/plain"}
    ctype = content_types.get(ext, "text/plain")

    boundary = uuid.uuid4().hex
    with open(filepath, "rb") as f:
        file_data = f.read()

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {ctype}\r\n\r\n"
    ).encode() + file_data + f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        TARGET_BASE, data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode())


print("=" * 70)
print(f"OWASP 6 NEW CATEGORIES VERIFICATION  (port {PORT})")
print("=" * 70)

passed = 0
failed = 0

for filename, expected_cat, cat_name in TEST_CASES:
    filepath = os.path.join(BASE_DIR, filename)
    if not os.path.exists(filepath):
        print(f"\nSKIP: {filename} (file not found)")
        continue

    print(f"\nTesting: {filename}")
    print(f"  Expected category: {expected_cat} ({cat_name})")

    try:
        result = scan_file(filepath)
    except Exception as e:
        print(f"  ERROR: {e}")
        failed += 1
        continue

    findings = result.get("findings", [])
    cats_found = [f["category"] for f in findings]
    methods = {f["category"]: f.get("detection_method", "?") for f in findings}

    target_findings = [f for f in findings if f["category"] == expected_cat]
    passed_test = len(target_findings) > 0

    if passed_test:
        print(f"  PASS - Found {len(target_findings)} finding(s) in {expected_cat}")
        for tf in target_findings:
            method = tf.get("detection_method", "?")
            method_icon = "[Rule]" if method == "rule_based" else "[AI  ]"
            print(f"         {method_icon} [{tf['severity']:8}] {tf['description'][:60]}")
        passed += 1
    else:
        print(f"  FAIL - No findings in {expected_cat}!")
        if cats_found:
            print(f"         Findings were in: {list(set(cats_found))}")
        else:
            print(f"         No findings at all (risk_score={result.get('risk_score', 0)})")
        failed += 1

    # Show all findings for this file
    if findings:
        print(f"  All findings ({len(findings)} total):")
        for f in findings:
            method = "[Rule]" if f.get("detection_method") == "rule_based" else "[AI  ]"
            print(f"    {method} {f['category']} [{f['severity']:8}] {f['description'][:55]}")

print()
print("=" * 70)
print(f"RESULTS: {passed} PASSED / {passed + failed} TOTAL ({failed} FAILED)")
print("=" * 70)
if failed == 0:
    print("ALL TESTS PASSED!")
else:
    print(f"FAILING: {failed} test(s) need investigation")
