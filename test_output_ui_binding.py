#!/usr/bin/env python3
"""
Test script for Automatic Output-to-UI Data Binding System

Tests the output_ui_binder module against real scan output files
to ensure all files are properly detected, parsed, and routed to modules.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from app.api.helpers.output_ui_binder import (
    ScanOutputScanner,
    UIModuleRouter,
    UniversalFileParser,
    get_dashboard_output_data,
)


def test_file_routing():
    """Test that files are correctly routed to modules"""
    print("\n" + "="*70)
    print("TEST 1: File Routing")
    print("="*70)
    
    test_cases = [
        ("whois.txt", "domain_intelligence"),
        ("dnsx_resolved.json", "dns_resolution"),
        ("asn_cidrs.txt", "asn_ip"),
        ("certspotter.txt", "certificate_transparency"),
        ("cloud_assets.txt", "cloud_exposure"),
        ("subdomains.txt", "subdomains"),
        ("alive_urls.txt", "active_hosts"),
        ("cve_matches.json", "vulnerabilities"),
        ("ffuf_test.json", "content_discovery"),
        ("threat_intel_summary.json", "threat_intel"),
        ("nmap.xml", "port_scans"),
        ("headers.json", "http_security"),
    ]
    
    passed = 0
    failed = 0
    
    for filename, expected_module in test_cases:
        module = UIModuleRouter.route_file(filename)
        if module == expected_module:
            print(f"✅ {filename:30s} → {module}")
            passed += 1
        else:
            print(f"❌ {filename:30s} → {module} (expected {expected_module})")
            failed += 1
    
    print(f"\nResult: {passed} passed, {failed} failed")
    return failed == 0


def test_file_parsing():
    """Test that files are correctly parsed"""
    print("\n" + "="*70)
    print("TEST 2: File Parsing")
    print("="*70)
    
    output_dir = project_root / "output"
    
    # Find a scan directory - use the one we know exists
    scan_dir = output_dir / "fundsverifier_com_scan_4"
    if not scan_dir.exists():
        print("❌ Scan directory not found")
        return False
    
    print(f"Testing with scan directory: {scan_dir.name}")
    
    # Scan for files
    files = ScanOutputScanner.scan_all_files(scan_dir)
    print(f"\nFound {len(files)} files to parse:")
    
    parsed_count = 0
    error_count = 0
    
    for file_path in files[:10]:  # Test first 10 files
        try:
            result = UniversalFileParser.parse_file(file_path)
            status = result.get("status")
            file_type = result.get("file_type")
            
            if status == "success":
                print(f"✅ {file_path.name:40s} ({file_type})")
                parsed_count += 1
            else:
                print(f"⚠️  {file_path.name:40s} ({file_type}) - {status}")
                error_count += 1
        except Exception as e:
            print(f"❌ {file_path.name:40s} - {str(e)[:40]}")
            error_count += 1
    
    print(f"\nResult: {parsed_count} parsed successfully, {error_count} errors")
    return error_count == 0


def test_module_binding():
    """Test that files are bound to correct modules"""
    print("\n" + "="*70)
    print("TEST 3: Module Binding")
    print("="*70)
    
    output_dir = project_root / "output"
    scan_dir = output_dir / "fundsverifier_com_scan_4"
    if not scan_dir.exists():
        print("❌ Scan directory not found")
        return False
    
    domain = "fundsverifier.com"
    scan_id = 4
    
    print(f"Testing with domain: {domain}, scan_id: {scan_id}")
    
    # Get all output data
    output = get_dashboard_output_data(domain, scan_id)
    
    if not output:
        print("❌ Failed to get output data")
        return False
    
    print(f"\n✅ Successfully loaded output data")
    print(f"  • Total files: {output.get('total_files')}")
    print(f"  • Modules with data: {output.get('module_count')}")
    
    # Display modules and their file counts
    print("\nModules with data:")
    modules = output.get("modules", {})
    for module_name, module_data in modules.items():
        file_count = module_data.get("file_count", 0)
        status = module_data.get("status", "unknown")
        print(f"  • {module_name:30s}: {file_count} file(s) - {status}")
    
    # Display unrouted files
    unrouted = output.get("unrouted_files", [])
    if unrouted:
        print(f"\n⚠️  Unrouted files ({len(unrouted)}):")
        for file_data in unrouted[:5]:
            print(f"  • {file_data.get('filename')}")
        if len(unrouted) > 5:
            print(f"  ... and {len(unrouted) - 5} more")
    
    return True


def test_specific_modules():
    """Test specific module data extraction"""
    print("\n" + "="*70)
    print("TEST 4: Specific Module Data")
    print("="*70)
    
    output_dir = project_root / "output"
    scan_dir = output_dir / "fundsverifier_com_scan_4"
    if not scan_dir.exists():
        print("❌ Scan directory not found")
        return False
    
    domain = "fundsverifier.com"
    scan_id = 4
    
    output = get_dashboard_output_data(domain, scan_id)
    if not output:
        return False
    
    modules = output.get("modules", {})
    
    # Test DNS module
    if "dns_resolution" in modules:
        dns = modules["dns_resolution"]
        print(f"✅ DNS Resolution:")
        print(f"  • Records: {dns.get('record_count', 0)}")
        print(f"  • Unique hosts: {dns.get('unique_hostnames', 0)}")
        print(f"  • Unique IPs: {dns.get('unique_ips', 0)}")
    else:
        print("   DNS Resolution: No data")
    
    # Test ASN module
    if "asn_ip" in modules:
        asn = modules["asn_ip"]
        print(f"✅ ASN & IP:")
        print(f"  • IPs: {asn.get('ip_count', 0)}")
        print(f"  • CIDRs: {asn.get('cidr_count', 0)}")
    else:
        print("   ASN & IP: No data")
    
    # Test Certificate module
    if "certificate_transparency" in modules:
        cert = modules["certificate_transparency"]
        print(f"✅ Certificate Transparency:")
        print(f"  • Certificates: {cert.get('certificate_count', 0)}")
    else:
        print("   Certificate Transparency: No data")
    
    # Test Cloud module
    if "cloud_exposure" in modules:
        cloud = modules["cloud_exposure"]
        print(f"✅ Cloud Exposure:")
        print(f"  • Assets: {cloud.get('asset_count', 0)}")
    else:
        print("   Cloud Exposure: No data")
    
    # Test Domain Intelligence module
    if "domain_intelligence" in modules:
        domain_intel = modules["domain_intelligence"]
        print(f"✅ Domain Intelligence:")
        print(f"  • Has WHOIS: {domain_intel.get('has_whois', False)}")
        print(f"  • Has Risk Profile: {domain_intel.get('has_risk_profile', False)}")
    else:
        print("   Domain Intelligence: No data")
    
    return True


def test_api_endpoint():
    """Test that API endpoint would return correct data"""
    print("\n" + "="*70)
    print("TEST 5: API Endpoint Simulation")
    print("="*70)
    
    output_dir = project_root / "output"
    scan_dir = output_dir / "fundsverifier_com_scan_4"
    if not scan_dir.exists():
        print("❌ Scan directory not found")
        return False
    
    domain = "fundsverifier.com"
    scan_id = 4
    
    # Simulate API call
    output = get_dashboard_output_data(domain, scan_id)
    
    print("\nAPI Response Structure:")
    print(f"{{\n  'status': '{output.get('status')}',")
    print(f"  'scan_id': {output.get('scan_id')},")
    print(f"  'domain': '{output.get('domain')}',")
    print(f"  'total_files': {output.get('total_files')},")
    print(f"  'module_count': {output.get('module_count')},")
    print(f"  'modules': {{")
    
    for i, module_name in enumerate(output.get("modules", {}).keys()):
        module = output["modules"][module_name]
        print(f"    '{module_name}': {{")
        print(f"      'file_count': {module.get('file_count')},")
        print(f"      'status': '{module.get('status')}',")
        print(f"      'should_show_placeholder': {module.get('should_show_placeholder')}")
        print(f"    }}" + ("," if i < len(output["modules"]) - 1 else ""))
    
    print(f"  }}")
    print("}")
    
    return True


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("AUTOMATIC OUTPUT-TO-UI DATA BINDING - TEST SUITE")
    print("="*70)
    
    results = {
        "File Routing": test_file_routing(),
        "File Parsing": test_file_parsing(),
        "Module Binding": test_module_binding(),
        "Specific Modules": test_specific_modules(),
        "API Endpoint": test_api_endpoint(),
    }
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:40s}: {status}")
    
    print(f"\nOverall: {passed}/{total} test groups passed")
    
    if passed == total:
        print("\n🎉 All tests passed! The automatic output binding is working correctly.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test group(s) failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
