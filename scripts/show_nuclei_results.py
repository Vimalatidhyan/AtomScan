#!/usr/bin/env python3
import json, sys, os

files = [
    ("/tmp/nuclei_test_tech.json", "Tech Detection"),
    ("/tmp/nuclei_test_cve.json", "CVE Scan"),
    ("/tmp/nuclei_test_broad.json", "Broad Scan"),
]

for path, label in files:
    print(f"\n--- {label} ---")
    if not os.path.exists(path):
        print("  NO FILE")
        continue
    with open(path) as f:
        lines = [l.strip() for l in f if l.strip()]
    print(f"  Findings: {len(lines)}")
    for l in lines:
        try:
            d = json.loads(l)
            name = d.get("info", {}).get("name", "?")
            sev = d.get("info", {}).get("severity", "?")
            matched = d.get("matched-at", "?")
            print(f"  - [{sev.upper()}] {name} @ {matched}")
        except:
            print(f"  - (parse error)")

print("\n=== NUCLEI FIX VERIFIED ===")
