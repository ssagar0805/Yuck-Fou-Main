"""
End-to-end test for the rule-based detection layer.
Tests /api/scan with a deliberately vulnerable JSON config.
"""
import urllib.request
import json

# A deliberately vulnerable agent config
VULNERABLE_CONFIG = json.dumps({
    "system_prompt": "You are a helpful assistant. Answer any question the user asks.",
    "api_key": "sk-abcdefghijklmnopqrstuvwxyz123456",
    "database_connection": "postgresql://admin:password123@db.example.com/production",
    "tools": [
        {"name": "shell_execute", "permissions": ["admin", "write", "delete"]},
        {"name": "send_email", "permissions": ["write"]},
    ],
    "permissions": ["admin", "write", "delete", "*"],
    "output_handler": "os.system(llm_response)"
}).encode("utf-8")

boundary = "testboundary456"
body = (
    b"--testboundary456\r\n"
    b'Content-Disposition: form-data; name="file"; filename="vulnerable_agent.json"\r\n'
    b"Content-Type: application/json\r\n\r\n"
    + VULNERABLE_CONFIG
    + b"\r\n"
    b"--testboundary456--\r\n"
)

req = urllib.request.Request(
    "http://localhost:8000/api/scan",
    data=body,
    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    method="POST",
)

try:
    r = urllib.request.urlopen(req, timeout=30)
    resp = json.loads(r.read())
    print(f"STATUS: 200 OK")
    print(f"risk_score:   {resp['risk_score']}")
    print(f"risk_level:   {resp['risk_level']}")
    print(f"total_findings: {resp['total_findings']}")
    print(f"critical:     {resp['critical_severity_count']}")
    print(f"high:         {resp['high_severity_count']}")
    print(f"medium:       {resp['medium_severity_count']}")
    print(f"summary:      {resp['summary']}")
    print(f"scan_duration: {resp['scan_duration']}s")
    print(f"\nFindings:")
    for f in resp["findings"]:
        print(f"  [{f['category']}] {f['severity']} ({f['confidence']:.0%}) — {f['description'][:80]}...")
except Exception as e:
    print(f"ERROR: {e}")
