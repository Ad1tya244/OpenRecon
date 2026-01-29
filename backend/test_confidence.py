
import sys
import os

# Verify path setup
sys.path.append(os.getcwd())

from app.modules import attack_surface_intelligence

dummy_data = {
    "subdomains": [{"hostname": "admin.example.com"}, {"hostname": "vpn.example.com"}],
    "ports": {"open_ports": [{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}]},
    # This should trigger Admin Exposure -> High Severity
}

findings = attack_surface_intelligence.generate_intelligence(dummy_data)

print(f"Findings Count: {len(findings)}")
for f in findings:
    print(f"Title: {f.get('title')}")
    print(f"Severity: {f.get('severity')}")
    print(f"Confidence: {f.get('confidence')}")
    print(f"Evidence: {f.get('evidence')}")
    print("-" * 20)

if not findings:
    print("No findings generated.")
