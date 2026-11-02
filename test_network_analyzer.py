
from vulnerability_scanner.network_analyzer import analyze_network_scan

test_data = {
    "success": True,
    "ports": [
        {"port": 80, "state": "open", "service": "http"},
        {"port": 443, "state": "open", "service": "http"},
        {"port": 8443, "state": "open", "service": "ssl/http"}
    ]
}

result = analyze_network_scan(test_data)

print("\nNETWORK ANALYZER TEST RESULTS")
print("-----------------------------")

for finding in result["findings"]:
    print(f"Port {finding['port']}: {finding['title']}")

print("\nTotal findings:", result["total_findings"])
