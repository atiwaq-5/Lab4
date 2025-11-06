#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integration test for SPF/DMARC - extends the quick check with automated tests.
Run from Mininet CLI after starting the topology.
"""

def run_spf_dmarc_tests(net):
    """Run the SPF/DMARC test script from h1 host after DNS is set up."""
    import os
    
    print("\n" + "="*60)
    print("Running SPF/DMARC Automated Tests")
    print("="*60 + "\n")
    
    # Get the current directory where the script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up one level since we're in tests/ directory
    repo_dir = os.path.dirname(script_dir)
    test_script = os.path.join(repo_dir, "tests", "test_spf_dmarc.sh")
    
    # Ensure DNS is set to point to the good DNS server
    h1 = net.get('h1')
    h1.cmd('bash -lc \'printf "nameserver 10.0.0.53\n" > /etc/resolv.conf\'')
    
    # Run the test script
    print("Executing test script from h1 host...\n")
    result = h1.cmd(f"bash {test_script}")
    print(result)
    
    return result

if __name__ == "__main__":
    print("This module should be imported and run from the Mininet environment.")
    print("Example usage in mn_quickcheck_v6.py:")
    print("  from test_integration import run_spf_dmarc_tests")
    print("  run_spf_dmarc_tests(net)")
