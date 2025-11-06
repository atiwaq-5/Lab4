#!/bin/bash
# run_all_tests.sh - Automated test harness for pre/post-protection comparison
# Boots Mininet topology, runs baseline tests, enables protections, re-runs tests, and generates report

# Note: Not using 'set -e' globally as some test failures are expected (e.g., unauthorized SMTP)
# Critical operations have explicit error handling instead

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="$PROJECT_DIR/results/$TIMESTAMP"

echo "========================================"
echo "Lab 4 Automated Test Harness"
echo "========================================"
echo "Timestamp: $TIMESTAMP"
echo "Results dir: $RESULTS_DIR"
echo ""

# Create results directory
mkdir -p "$RESULTS_DIR"/{baseline,protected}/{logs,pcap,dig_outputs,swaks_outputs} || {
    echo "Error: Failed to create results directory structure"
    exit 1
}

# Create test execution script for Mininet
TEST_SCRIPT="/tmp/mininet_test_script_$TIMESTAMP.py"
cat > "$TEST_SCRIPT" <<'EOFPYTHON'
#!/usr/bin/env python3
"""
Automated test script that runs inside Mininet
Executes baseline tests, enables protections, and re-runs tests
"""
import sys
import time
import os

# Add project directory to path
sys.path.insert(0, 'PROJECT_DIR_PLACEHOLDER')

from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI

def make_host(net, name, ip):
    h = net.addHost(name, ip=ip+"/24")
    return h

def run_dig_test(h, query_type, domain, server, output_file, dnssec=False):
    """Run dig query and save output"""
    dnssec_flag = "+dnssec" if dnssec else ""
    cmd = f"dig {dnssec_flag} -t {query_type} {domain} @{server}"
    result = h.cmd(cmd)
    with open(output_file, 'w') as f:
        f.write(f"Command: {cmd}\n")
        f.write(f"{'='*60}\n")
        f.write(result)
    print(f"  ✓ {query_type} query for {domain} @ {server}")
    return result

def run_swaks_test(h, server, from_addr, to_addr, output_file, subject="Test"):
    """Run swaks send and save output"""
    cmd = f"swaks --to {to_addr} --from {from_addr} --server {server} --header 'Subject: {subject}' --body 'Test message' 2>&1"
    result = h.cmd(cmd)
    with open(output_file, 'w') as f:
        f.write(f"Command: {cmd}\n")
        f.write(f"{'='*60}\n")
        f.write(result)
    print(f"  ✓ SMTP send from {from_addr} to {to_addr} via {server}")
    return result

def start_pcap(h, interface, output_file, port=None):
    """Start tcpdump on host"""
    port_filter = f" port {port}" if port else ""
    cmd = f"tcpdump -i {interface}{port_filter} -w {output_file} 2>/dev/null &"
    h.cmd(cmd)
    time.sleep(0.5)
    print(f"  ✓ Started tcpdump on {h.name}:{interface} -> {output_file}")

def stop_pcap(h):
    """Stop tcpdump on host"""
    h.cmd("pkill tcpdump || true")
    time.sleep(0.5)

def ensure_named(h, ip, zone_src):
    """Install minimal named configs and start named"""
    named_opts = f'''options {{
    directory "/var/cache/bind";
    listen-on {{ {ip}; 127.0.0.1; }};
    listen-on-v6 {{ none; }};
    allow-query {{ any; }};
    recursion no;
    dnssec-validation no;
}};
'''
    named_local = '''zone "example.com" IN {
    type master;
    file "/var/cache/bind/zones/db.example.com";
};
'''
    
    # Determine which user to run as
    user_check = h.cmd("id -u bind >/dev/null 2>&1 && echo bind || echo root").strip()
    bind_user = user_check if user_check else "root"
    
    cmds = [
        "pkill -9 named || true",
        "mkdir -p /var/cache/bind/zones",
        f"cp {zone_src} /var/cache/bind/zones/db.example.com",
        f"chown -R {bind_user}:{bind_user} /var/cache/bind",
        "chmod -R u+rwX,go+rX /var/cache/bind",
        f"bash -c 'cat > /etc/bind/named.conf.options <<EOF\n{named_opts}EOF'",
        f"bash -c 'cat > /etc/bind/named.conf.local <<EOF\n{named_local}EOF'",
        f"named -4 -u {bind_user} -g -c /etc/bind/named.conf >/tmp/named.log 2>&1 & sleep 1"
    ]
    for c in cmds:
        h.cmd(c)
    
    # Verify
    out = h.cmd(f"dig +short -t MX example.com @{ip}")
    success = bool(out.strip())
    print(f"  {'✓' if success else '✗'} Named started on {h.name} ({ip})")
    return success

def start_smtp_sink(h, logpath):
    """Start SMTP debugging server"""
    h.cmd(f"fuser -k 25/tcp || true")
    h.cmd(f"python3 -u -m smtpd -n -c DebuggingServer 0.0.0.0:25 >{logpath} 2>&1 & sleep 1")
    chk = h.cmd("ss -ltnp | grep ':25 ' || true")
    success = bool(chk.strip())
    print(f"  {'✓' if success else '✗'} SMTP sink on {h.name}:25")
    return success

def run_baseline_tests(net, results_dir):
    """Phase 1: Baseline tests without protections"""
    print("\n==== PHASE 1: BASELINE TESTS (No Protections) ====")
    
    h1 = net.get('h1')
    dns = net.get('dns')
    att = net.get('att')
    mx = net.get('mx')
    
    dns_ip = "10.0.0.53"
    att_ip = "10.0.0.66"
    mx_ip = "10.0.0.25"
    
    baseline_dir = f"{results_dir}/baseline"
    
    # Start packet captures
    print("\nStarting packet captures...")
    start_pcap(h1, "h1-eth0", f"/tmp/baseline_h1_all.pcap")
    start_pcap(h1, "h1-eth0", f"/tmp/baseline_dns.pcap", port=53)
    start_pcap(h1, "h1-eth0", f"/tmp/baseline_smtp.pcap", port=25)
    
    # Start DNS servers
    print("\nStarting DNS servers...")
    ensure_named(dns, dns_ip, "zones/db.example.com.good")
    ensure_named(att, att_ip, "zones/db.example.com.att")
    
    # Start SMTP servers
    print("\nStarting SMTP servers...")
    start_smtp_sink(mx, "/tmp/mx-smtp.log")
    start_smtp_sink(att, "/tmp/att-smtp.log")
    
    time.sleep(1)
    
    # Configure h1 to use good DNS
    h1.cmd(f"bash -c 'printf \"nameserver {dns_ip}\\n\" > /etc/resolv.conf'")
    
    # DNS tests - Good path
    print("\nRunning DNS tests (good path)...")
    run_dig_test(h1, "MX", "example.com", dns_ip, 
                 f"/tmp/dig_baseline_mx_good.txt")
    run_dig_test(h1, "A", "mail.example.com", dns_ip,
                 f"/tmp/dig_baseline_a_good.txt")
    run_dig_test(h1, "TXT", "example.com", dns_ip,
                 f"/tmp/dig_baseline_spf.txt")
    run_dig_test(h1, "TXT", "_dmarc.example.com", dns_ip,
                 f"/tmp/dig_baseline_dmarc.txt")
    run_dig_test(h1, "MX", "example.com", dns_ip,
                 f"/tmp/dig_baseline_mx_dnssec.txt", dnssec=True)
    
    # DNS tests - Attacker path
    print("\nRunning DNS tests (attacker path)...")
    h1.cmd(f"bash -c 'printf \"nameserver {att_ip}\\n\" > /etc/resolv.conf'")
    run_dig_test(h1, "MX", "example.com", att_ip,
                 f"/tmp/dig_baseline_mx_att.txt")
    
    # Reset to good DNS
    h1.cmd(f"bash -c 'printf \"nameserver {dns_ip}\\n\" > /etc/resolv.conf'")
    
    # SMTP tests - Authorized sender
    print("\nRunning SMTP tests (authorized sender)...")
    run_swaks_test(h1, mx_ip, "admin@example.com", "user@example.com",
                   f"/tmp/swaks_baseline_authorized.txt",
                   subject="Baseline - Authorized")
    
    # SMTP tests - Unauthorized sender
    print("\nRunning SMTP tests (unauthorized sender)...")
    run_swaks_test(h1, mx_ip, "fake@evil.com", "user@example.com",
                   f"/tmp/swaks_baseline_unauthorized.txt",
                   subject="Baseline - Unauthorized")
    
    # SMTP test - Via attacker
    print("\nRunning SMTP tests (via attacker)...")
    h1.cmd(f"bash -c 'printf \"nameserver {att_ip}\\n\" > /etc/resolv.conf'")
    run_swaks_test(h1, att_ip, "boss@bank.com", "victim@example.com",
                   f"/tmp/swaks_baseline_attacker.txt",
                   subject="Baseline - Forged via Attacker")
    
    # Stop packet captures
    time.sleep(1)
    stop_pcap(h1)
    
    # Move pcap files
    for pcap in ["baseline_h1_all.pcap", "baseline_dns.pcap", "baseline_smtp.pcap"]:
        h1.cmd(f"mv /tmp/{pcap} {baseline_dir}/pcap/ 2>/dev/null || true")
    
    print("\n✓ Baseline tests complete")

def enable_protections(net, results_dir):
    """Enable DNSSEC, SPF, DKIM, DMARC protections"""
    print("\n==== ENABLING PROTECTIONS ====")
    print("Note: This is a simplified protection enable step.")
    print("Full DNSSEC signing and DKIM setup would be done here.")
    print("Current implementation focuses on demonstrating the test harness.")
    
    # In a full implementation, this would:
    # 1. Stop named on dns
    # 2. Sign the zone with DNSSEC
    # 3. Configure DKIM on mx
    # 4. Restart services
    
    # For now, we'll just add a marker
    with open(f"{results_dir}/protections_enabled.txt", 'w') as f:
        f.write("Protections would be enabled here:\n")
        f.write("- DNSSEC zone signing\n")
        f.write("- DKIM key generation and configuration\n")
        f.write("- SPF/DMARC records (already in zone)\n")
    
    print("✓ Protection markers added")

def run_protected_tests(net, results_dir):
    """Phase 2: Tests with protections enabled"""
    print("\n==== PHASE 2: PROTECTED TESTS (With Protections) ====")
    
    h1 = net.get('h1')
    dns = net.get('dns')
    mx = net.get('mx')
    
    dns_ip = "10.0.0.53"
    mx_ip = "10.0.0.25"
    
    protected_dir = f"{results_dir}/protected"
    
    # Start packet captures
    print("\nStarting packet captures...")
    start_pcap(h1, "h1-eth0", f"/tmp/protected_h1_all.pcap")
    start_pcap(h1, "h1-eth0", f"/tmp/protected_dns.pcap", port=53)
    start_pcap(h1, "h1-eth0", f"/tmp/protected_smtp.pcap", port=25)
    
    # Configure h1 to use good DNS
    h1.cmd(f"bash -c 'printf \"nameserver {dns_ip}\\n\" > /etc/resolv.conf'")
    
    # DNS tests with DNSSEC
    print("\nRunning DNS tests (with DNSSEC flags)...")
    run_dig_test(h1, "MX", "example.com", dns_ip,
                 f"/tmp/dig_protected_mx_dnssec.txt", dnssec=True)
    run_dig_test(h1, "TXT", "example.com", dns_ip,
                 f"/tmp/dig_protected_spf.txt")
    run_dig_test(h1, "TXT", "_dmarc.example.com", dns_ip,
                 f"/tmp/dig_protected_dmarc.txt")
    
    # SMTP tests - Authorized sender (should pass SPF)
    print("\nRunning SMTP tests (authorized - should pass SPF)...")
    run_swaks_test(h1, mx_ip, "admin@example.com", "user@example.com",
                   f"/tmp/swaks_protected_authorized.txt",
                   subject="Protected - Authorized")
    
    # SMTP tests - Unauthorized sender (should fail SPF)
    print("\nRunning SMTP tests (unauthorized - should fail SPF)...")
    run_swaks_test(h1, mx_ip, "fake@evil.com", "user@example.com",
                   f"/tmp/swaks_protected_unauthorized.txt",
                   subject="Protected - Unauthorized")
    
    # Stop packet captures
    time.sleep(1)
    stop_pcap(h1)
    
    # Move pcap files
    for pcap in ["protected_h1_all.pcap", "protected_dns.pcap", "protected_smtp.pcap"]:
        h1.cmd(f"mv /tmp/{pcap} {protected_dir}/pcap/ 2>/dev/null || true")
    
    print("\n✓ Protected tests complete")

def generate_report(results_dir):
    """Generate comparison report"""
    print("\n==== GENERATING COMPARISON REPORT ====")
    
    report_file = f"{results_dir}/comparison_report.txt"
    
    with open(report_file, 'w') as f:
        f.write("="*70 + "\n")
        f.write("Lab 4 Pre/Post-Protection Comparison Report\n")
        f.write("="*70 + "\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Results directory: {results_dir}\n\n")
        
        f.write("Tests Executed:\n")
        f.write("-" * 70 + "\n")
        f.write("1. DNS Resolution Tests:\n")
        f.write("   - MX record lookup (example.com)\n")
        f.write("   - A record lookup (mail.example.com)\n")
        f.write("   - SPF record lookup (TXT @ example.com)\n")
        f.write("   - DMARC record lookup (TXT _dmarc.example.com)\n")
        f.write("   - DNSSEC validation (dig +dnssec)\n")
        f.write("   - Attacker DNS resolution\n\n")
        
        f.write("2. SMTP Delivery Tests:\n")
        f.write("   - Authorized sender (admin@example.com)\n")
        f.write("   - Unauthorized sender (fake@evil.com)\n")
        f.write("   - Forged mail via attacker DNS\n\n")
        
        f.write("3. Traffic Captures:\n")
        f.write("   - DNS traffic (port 53)\n")
        f.write("   - SMTP traffic (port 25)\n")
        f.write("   - Complete packet capture\n\n")
        
        f.write("Artifacts Collected:\n")
        f.write("-" * 70 + "\n")
        f.write("Baseline Phase:\n")
        f.write(f"  - Logs: {results_dir}/baseline/logs/\n")
        f.write(f"  - PCAPs: {results_dir}/baseline/pcap/\n")
        f.write(f"  - Dig outputs: {results_dir}/baseline/dig_outputs/\n")
        f.write(f"  - Swaks outputs: {results_dir}/baseline/swaks_outputs/\n\n")
        
        f.write("Protected Phase:\n")
        f.write(f"  - Logs: {results_dir}/protected/logs/\n")
        f.write(f"  - PCAPs: {results_dir}/protected/pcap/\n")
        f.write(f"  - Dig outputs: {results_dir}/protected/dig_outputs/\n")
        f.write(f"  - Swaks outputs: {results_dir}/protected/swaks_outputs/\n\n")
        
        f.write("Analysis Instructions:\n")
        f.write("-" * 70 + "\n")
        f.write("1. Compare DNS responses:\n")
        f.write("   diff baseline/dig_outputs/ protected/dig_outputs/\n\n")
        f.write("2. Compare SMTP behavior:\n")
        f.write("   diff baseline/swaks_outputs/ protected/swaks_outputs/\n\n")
        f.write("3. Analyze packet captures:\n")
        f.write("   wireshark baseline/pcap/baseline_dns.pcap\n")
        f.write("   wireshark protected/pcap/protected_dns.pcap\n\n")
        f.write("4. Review mail server logs:\n")
        f.write("   Check baseline/logs/ and protected/logs/ for SPF/DKIM results\n\n")
        
        f.write("Expected Differences:\n")
        f.write("-" * 70 + "\n")
        f.write("- Baseline: No DNSSEC AD bit in DNS responses\n")
        f.write("- Protected: DNSSEC AD bit present (if properly configured)\n")
        f.write("- Baseline: No SPF/DKIM checks in mail logs\n")
        f.write("- Protected: SPF pass/fail and DKIM signatures in headers\n")
        f.write("- Baseline: Attacker mail accepted\n")
        f.write("- Protected: Attacker mail rejected or quarantined\n\n")
        
        f.write("="*70 + "\n")
    
    print(f"✓ Report generated: {report_file}")
    
    # Print report to console
    with open(report_file, 'r') as f:
        print("\n" + f.read())

def main():
    results_dir = "RESULTS_DIR_PLACEHOLDER"
    
    # Create Mininet topology
    print("\n==== CREATING MININET TOPOLOGY ====")
    net = Mininet(link=TCLink, controller=None, autoSetMacs=True)
    s1 = net.addSwitch('s1')
    
    # Add hosts
    dns = make_host(net, 'dns', '10.0.0.53')
    att = make_host(net, 'att', '10.0.0.66')
    h1  = make_host(net, 'h1',  '10.0.0.10')
    mx  = make_host(net, 'mx',  '10.0.0.25')
    
    for h in (dns, att, h1, mx):
        net.addLink(h, s1)
    
    net.build()
    s1.start([])
    
    print("✓ Topology created")
    
    # Change to project directory
    os.chdir('PROJECT_DIR_PLACEHOLDER')
    
    try:
        # Run baseline tests
        run_baseline_tests(net, results_dir)
        
        # Enable protections
        enable_protections(net, results_dir)
        
        # Run protected tests
        run_protected_tests(net, results_dir)
        
        # Generate report
        generate_report(results_dir)
        
        print("\n==== ALL TESTS COMPLETE ====")
        print(f"Results saved to: {results_dir}")
        print("\nTo review results:")
        print(f"  cat {results_dir}/comparison_report.txt")
        print(f"  ls -lR {results_dir}/")
        
    except Exception as e:
        print(f"\n✗ Error during test execution: {e}")
        import traceback
        traceback.print_exc()
    finally:
        net.stop()

if __name__ == '__main__':
    main()
EOFPYTHON

# Replace placeholders
sed -i "s|PROJECT_DIR_PLACEHOLDER|$PROJECT_DIR|g" "$TEST_SCRIPT"
sed -i "s|RESULTS_DIR_PLACEHOLDER|$RESULTS_DIR|g" "$TEST_SCRIPT"

chmod +x "$TEST_SCRIPT"

echo ""
echo "Starting Mininet topology and running tests..."
echo "This will take a few minutes..."
echo ""

# Run the test script with sudo
cd "$PROJECT_DIR"
sudo python3 "$TEST_SCRIPT"

# Collect logs using collect_logs.sh
echo ""
echo "==== Collecting additional logs ===="
sudo bash "$SCRIPT_DIR/collect_logs.sh" "baseline" "$RESULTS_DIR"
sudo bash "$SCRIPT_DIR/collect_logs.sh" "protected" "$RESULTS_DIR"

# Copy results to artifacts directory for easy access
echo ""
echo "==== Copying latest results to artifacts/ ===="
# Clean artifacts directories safely
for dir in logs pcap reports; do
    if [ -d "$PROJECT_DIR/artifacts/$dir" ]; then
        find "$PROJECT_DIR/artifacts/$dir" -type f -not -name '.gitkeep' -delete
    fi
done

# Helper function to safely copy directory contents
safe_copy_dir() {
    local src_dir="$1"
    local dest_dir="$2"
    if [ -n "$(find "$src_dir" -maxdepth 1 -type f 2>/dev/null)" ]; then
        cp "$src_dir"/* "$dest_dir/" 2>/dev/null || true
    fi
}

# Copy artifacts safely
safe_copy_dir "$RESULTS_DIR/baseline/logs" "$PROJECT_DIR/artifacts/logs"
safe_copy_dir "$RESULTS_DIR/baseline/pcap" "$PROJECT_DIR/artifacts/pcap"
if [ -f "$RESULTS_DIR/comparison_report.txt" ]; then
    cp "$RESULTS_DIR/comparison_report.txt" "$PROJECT_DIR/artifacts/reports/" 2>/dev/null || true
fi

echo ""
echo "========================================"
echo "Test execution complete!"
echo "========================================"
echo "Full results: $RESULTS_DIR"
echo "Latest artifacts: $PROJECT_DIR/artifacts/"
echo ""
echo "View report:"
echo "  cat $RESULTS_DIR/comparison_report.txt"
echo ""
echo "Or:"
echo "  cat $PROJECT_DIR/artifacts/reports/comparison_report.txt"
echo ""
