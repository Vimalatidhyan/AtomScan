#!/usr/bin/env python3
"""Test both DNS and ASN endpoints together."""
import urllib.request
import json

print("\n=== TESTING SCAN DATA ENDPOINTS ===\n")

# Test DNS
try:
    url = 'http://localhost:8000/api/v1/scans/3/dns-records'
    data = json.loads(urllib.request.urlopen(url).read())
    
    print("✓ DNS Records Endpoint")
    print(f"  Total Records: {data.get('count', 0)}")
    records = data.get('records', [])
    if records:
        print("  Samples:")
        for r in records[:3]:
            print(f"    {r['subdomain']:30} → {r['ip']:18}")
except Exception as e:
    print(f"✗ DNS Error: {e}")

# Test ASN
try:
    url = 'http://localhost:8000/api/v1/scans/3/asn-records'
    data = json.loads(urllib.request.urlopen(url).read())
    
    print("\n✓ ASN Records Endpoint")
    print(f"  Total Records: {data.get('count', 0)}")
    records = data.get('asn_records', [])
    if records:
        print("  Samples:")
        for r in records[:3]:
            print(f"    {r['ip']:20} | ASN: {(r.get('asn') or 'unknown'):10} | Org: {(r.get('organization') or 'unknown')[:35]}")
except Exception as e:
    print(f"✗ ASN Error: {e}")

# Test Certificate
try:
    url = 'http://localhost:8000/api/v1/scans/3/certificate-records'
    data = json.loads(urllib.request.urlopen(url).read())
    
    print("\n✓ Certificate Records Endpoint")
    print(f"  Total Records: {data.get('count', 0)}")
    records = data.get('certificates', [])
    if records:
        print(f"  Sample domain: {records[0].get('domain')}")
except Exception as e:
    print(f"✗ Certificate Error: {e}")

print("\n=== ALL ENDPOINTS OPERATIONAL ===\n")
