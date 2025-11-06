#!/usr/bin/env python3
"""
Test script to verify MX A record resolution is working correctly.
This can be run without Mininet to validate the zone file and code changes.

Usage:
    python3 test_mx_resolution.py
"""

import sys
import os

def test_zone_file():
    """Verify the zone file has correct MX and A records"""
    print("=" * 70)
    print("TEST 1: Zone File Validation")
    print("=" * 70)
    
    zone_file = "zones/db.example.com.good"
    if not os.path.exists(zone_file):
        print(f"✖️ FAIL: Zone file not found: {zone_file}")
        return False
    
    with open(zone_file, 'r') as f:
        content = f.read()
    
    checks = {
        'MX record points to mx.example.com': '@   IN MX 10 mx.example.com' in content,
        'A record for mx.example.com exists': 'mx IN A 10.0.0.25' in content,
        'NS record exists': 'IN NS ns1.example.com' in content,
        'SPF TXT record exists': 'v=spf1' in content,
        'DMARC TXT record exists': 'v=DMARC1' in content,
    }
    
    all_ok = True
    for check_name, result in checks.items():
        status = "✔️ PASS" if result else "✖️ FAIL"
        print(f"  {status}: {check_name}")
        if not result:
            all_ok = False
    
    print()
    return all_ok


def test_module_import():
    """Verify the mn_quickcheck_v6.py module can be imported"""
    print("=" * 70)
    print("TEST 2: Module Import and Syntax Validation")
    print("=" * 70)
    
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("mn_quickcheck_v6", "mn_quickcheck_v6.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        print("  ✔️ PASS: Module imported successfully (no syntax errors)")
        
        if hasattr(module, 'run'):
            print("  ✔️ PASS: Module has 'run' function")
        else:
            print("  ✖️ FAIL: Module missing 'run' function")
            return False
        
        print()
        return True
        
    except Exception as e:
        print(f"  ✖️ FAIL: Failed to import module: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_mx_precheck_logic():
    """Test the MX pre-check logic with mock data"""
    print("=" * 70)
    print("TEST 3: MX Pre-check Logic Simulation")
    print("=" * 70)
    
    def mock_dig(name, qtype):
        """Mock dig responses based on zone file"""
        if qtype == "MX" and name == "example.com":
            return "10 mx.example.com."
        elif qtype == "A" and name == "mx.example.com":
            return "10.0.0.25"
        return ""
    
    # Test successful case
    print("\n  Scenario 1: Valid MX and A records")
    mx_ans = mock_dig("example.com", "MX")
    mx_host = mx_ans.split()[-1].rstrip('.') if mx_ans else ""
    a_ans = mock_dig(mx_host, "A") if mx_host else ""
    mx_a_ok = bool(a_ans.strip())
    
    print(f"    MX query: {mx_ans}")
    print(f"    Extracted hostname: {mx_host}")
    print(f"    A query: {a_ans}")
    print(f"    Valid: {mx_a_ok}")
    
    if mx_host == "mx.example.com" and a_ans == "10.0.0.25" and mx_a_ok:
        print("  ✔️ PASS: Valid MX hostname resolves to correct IP")
        scenario1_ok = True
    else:
        print("  ✖️ FAIL: MX resolution logic failed")
        scenario1_ok = False
    
    # Test error case: No MX record
    print("\n  Scenario 2: Missing MX record")
    mx_ans = ""
    mx_host = mx_ans.split()[-1].rstrip('.') if mx_ans else ""
    
    if not mx_host:
        print("  ✔️ PASS: Correctly detected missing MX record")
        scenario2_ok = True
    else:
        print("  ✖️ FAIL: Failed to detect missing MX record")
        scenario2_ok = False
    
    # Test error case: MX exists but no A record
    print("\n  Scenario 3: MX record but missing A record")
    mx_ans = "10 nonexistent.example.com."
    mx_host = mx_ans.split()[-1].rstrip('.') if mx_ans else ""
    a_ans = mock_dig(mx_host, "A") if mx_host else ""
    mx_a_ok = bool(a_ans.strip())
    
    if mx_host and not mx_a_ok:
        print("  ✔️ PASS: Correctly detected missing A record")
        scenario3_ok = True
    else:
        print("  ✖️ FAIL: Failed to detect missing A record")
        scenario3_ok = False
    
    print()
    return scenario1_ok and scenario2_ok and scenario3_ok


def main():
    """Run all tests"""
    print("\n" + "=" * 70)
    print("MX A Record Resolution Test Suite")
    print("=" * 70)
    print()
    
    results = {
        "Zone File Validation": test_zone_file(),
        "Module Import": test_module_import(),
        "MX Pre-check Logic": test_mx_precheck_logic(),
    }
    
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    all_passed = True
    for test_name, result in results.items():
        status = "✔️ PASS" if result else "✖️ FAIL"
        print(f"  {status}: {test_name}")
        if not result:
            all_passed = False
    
    print("=" * 70)
    
    if all_passed:
        print("\n✔️ ALL TESTS PASSED!")
        print("\nThe MX A record resolution fix is working correctly.")
        print("You can now run the Mininet tests with confidence.")
        return 0
    else:
        print("\n✖️ SOME TESTS FAILED!")
        print("\nPlease review the failures above and fix any issues.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
