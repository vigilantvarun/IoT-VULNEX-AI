
from types import SimpleNamespace

from vulnerability_scanner.scanner import assess_device


test_device = SimpleNamespace(
    device_code="ESP32_TEST",
    device_type="ESP32",
    firmware_version="debug-build-1.0"
)

result = assess_device(test_device)

print("\n========== VULNEX AI SCANNER ==========")

print("Device:", result["device_code"])
print("Type:", result["device_type"])
print("Firmware:", result["firmware_version"])

print("Total Findings:", result["total_findings"])

for finding in result["findings"]:

    print("\nFinding:", finding["vulnerability_name"])
    print("Severity:", finding["severity"])
    print("Description:", finding["description"])
    print("Recommendation:", finding["recommendation"])

print("\nScan Status:", result["status"])
