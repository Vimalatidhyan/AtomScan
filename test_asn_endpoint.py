#!/usr/bin/env python3
"""Test the ASN records endpoint."""
import urllib.request
import json
import time

time.sleep(3)  # Wait for API

try:
    url = 'http://localhost:8000/api/v1/scans/3/asn-records'
    response = urllib.request.urlopen(url)
    data = json.loads(response.read())
    
    print(f"\n✓ ASN Records Endpoint")
    print(f"  Scan ID: {data.get('scan_id')}")
    print(f"  Target: {data.get('target')}")
    print(f"  Total Count: {data.get('count', 0)}")
    
    records = data.get('asn_records', [])
    if records:
        print(f"\n  Sample Records (first 5):")
        for r in records[:5]:
            print(f"    {r['ip']:20} | {(r.get('asn') or 'unknown'):15} | {(r.get('organization') or 'unknown')[:40]}")
    else:
        print("  No records found")
        
except urllib.error.URLError as e:
    print(f"✗ Connection error: {e}")
except json.JSONDecodeError as e:
    print(f"✗ JSON error: {e}")
except Exception as e:
    print(f"✗ Error: {e}")
