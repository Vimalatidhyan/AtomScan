#!/usr/bin/env python3
"""Test the new API endpoints."""
import urllib.request
import json
import time

time.sleep(5)  # Wait for API to start

def test_endpoint(path):
    """Test an endpoint and print results."""
    url = f"http://localhost:8000/api/v1{path}"
    try:
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
            print(f"\n=== {path} ===")
            print(f"Scan ID: {data.get('scan_id')}")
            print(f"Target: {data.get('target')}")
            if 'records' in data:
                print(f"DNS Records Count: {len(data.get('records', []))}")
                if data.get('records'):
                    print(f"Sample: {json.dumps(data['records'][0], indent=2)[:200]}...")
            elif 'certificates' in data:
                print(f"Certificates Count: {len(data.get('certificates', []))}")
                if data.get('certificates'):
                    print(f"Sample: {json.dumps(data['certificates'][0], indent=2)[:200]}...")
            elif 'assets' in data:
                print(f"Assets Count: {data.get('count', len(data.get('assets', [])))}")
                if data.get('assets'):
                    print(f"Sample: {json.dumps(data['assets'][0], indent=2)[:200]}...")
            else:
                print(f"Response keys: {list(data.keys())}")
    except Exception as e:
        print(f"\nERROR testing {path}: {e}")

# Test endpoints
test_endpoint('/scans/3/dns-records')
test_endpoint('/scans/3/certificate-records')
test_endpoint('/scans/3/asn-records')
test_endpoint('/scans/3/scan-details')
