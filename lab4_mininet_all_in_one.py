#!/usr/bin/env python3
"""
lab4_mininet_all_in_one.py

ONE FILE to run the full Lab 4 flow in a Mininet VM:
- Topology (h1, dns, att, mx) or user's Topo if present
- Copies zone files to dns/att hosts
- Signs the zone BEFORE starting named (via DNSSEC helper v2)
- Configures Unbound on h1 with trust anchor
- Starts named on dns with the SIGNED zone and on att with attacker zone
- Starts SMTP debug servers
- Runs quick dig/swaks tests and opens Mininet CLI

Features:
- Robust service startup with validation and error reporting
- Detailed logging of service failures
- Helper function to poll and check service status
- Fails early with helpful messages when services don't start

Run:
    sudo python3 lab4_mininet_all_in_one.py
"""
import os
import time
import pprint
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.topo import Topo

# Try to load user's topology; else fallback
try:
    import lab4_topo_v6e as topo_mod
    LabTopo = None
    for _name, _obj in topo_mod.__dict__.items():
        if isinstance(_obj, type) and issubclass(_obj, Topo) and _obj is not Topo:
            LabTopo = _obj
            break
    if LabTopo is None:
        raise ImportError('No Topo subclass found')
except Exception as e:
    print('[warn] Using built-in default topology:', e)
    class DefaultLabTopo(Topo):
        def build(self):
            s1 = self.addSwitch('s1')
            self.addLink(self.addHost('h1',  ip='10.0.0.10/24'), s1)
            self.addLink(self.addHost('dns', ip='10.0.0.53/24'), s1)
            self.addLink(self.addHost('att', ip='10.0.0.66/24'), s1)
            self.addLink(self.addHost('mx',  ip='10.0.0.25/24'), s1)
    LabTopo = DefaultLabTopo

# Helper v2 uses absolute paths and single-line-friendly writes
from mn_quickcheck_v6_dnssec_patch_v2 import enable_dnssec_and_client_validation


def check_service_up(h, check_command, service_name, logfile=None, timeout=10):
    """
    Poll and check if a service is up.
    
    Args:
        h: Mininet host object
        check_command: Command to check if service is running (should return non-empty on success)
        service_name: Name of the service for error messages
        logfile: Optional path to log file to display on failure
        timeout: Maximum seconds to wait for service
        
    Returns:
        (success: bool, message: str)
    """
    start = time.time()
    while time.time() - start < timeout:
        result = h.cmd(check_command).strip()
        if result:
            return True, f"{service_name} started successfully"
        time.sleep(0.5)
    
    # Service failed to start - gather diagnostic info
    msg = f"ERROR: {service_name} failed to start within {timeout}s\n"
    
    # Try to get process list
    ps_out = h.cmd('ps aux | grep -E "(named|unbound)" | grep -v grep || true').strip()
    if ps_out:
        msg += f"Process list:\n{ps_out}\n"
    else:
        msg += "No matching processes found\n"
    
    # Try to read log file if provided
    if logfile:
        log_content = h.cmd(f'tail -50 {logfile} 2>/dev/null || echo "Log file not found: {logfile}"').strip()
        msg += f"\nLog file ({logfile}):\n{log_content}\n"
    
    return False, msg


def start_bind_on_host(h, zone_path, zone_name):
    """
    Start a minimal named instance with a tiny config under /tmp, no heredocs.
    Returns (success: bool, message: str)
    """
    tmpdir = f"/tmp/bind_{h.name}"
    logfile = f"/tmp/named_{h.name}.log"
    
    # Create directory
    h.cmd(f'mkdir -p {tmpdir}')
    
    # Build named config
    named_conf = (
        'options {\n'
        f'    directory "{tmpdir}";\n'
        '    recursion no;\n'
        '    allow-query { any; };\n'
        '    listen-on { any; };\n'
        '    listen-on-v6 { none; };\n'
        '};\n'
        f'zone "{zone_name}" IN {{\n'
        '    type master;\n'
        f'    file "{zone_path}";\n'
        '};\n'
    )
    conf_path = os.path.join(tmpdir, 'named.conf')
    
    # Write config using cat with heredoc marker (more reliable than printf for multi-line)
    h.cmd(f'cat > {conf_path} << \'NAMEDCONF\'\n{named_conf}\nNAMEDCONF\n')
    
    # Kill any existing named process
    h.cmd('pkill named || true')
    time.sleep(0.2)
    
    # Check if zone file exists
    zone_check = h.cmd(f'test -f {zone_path} && echo "exists" || echo "missing"').strip()
    if zone_check != "exists":
        return False, f"Zone file not found: {zone_path}"
    
    # Check if named binary exists
    named_check = h.cmd('which named 2>/dev/null || echo "missing"').strip()
    if named_check == "missing":
        return False, "named binary not found - ensure bind9 is installed"
    
    # Start named
    h.cmd(f'bash -lc "named -c {conf_path} -u root > {logfile} 2>&1 &"')
    
    # Check if service started successfully
    check_cmd = f'ss -lnp | grep ":53 " || true'
    return check_service_up(h, check_cmd, f"named on {h.name}", logfile, timeout=5)


def start_unbound_on_host(h, config_content, logfile="/tmp/unbound.log"):
    """
    Start unbound resolver service with given configuration.
    Returns (success: bool, message: str)
    """
    conf_path = '/etc/unbound/unbound.conf.d/example_lab.conf'
    
    # Create directory and write config using cat heredoc
    h.cmd('mkdir -p /etc/unbound/unbound.conf.d || true')
    h.cmd(f'cat > {conf_path} << \'UNBOUNDCONF\'\n{config_content}\nUNBOUNDCONF\n')
    
    # Check if unbound binary exists
    unbound_check = h.cmd('which unbound 2>/dev/null || which unbound-daemon 2>/dev/null || echo "missing"').strip()
    if unbound_check == "missing":
        return False, "unbound binary not found - ensure unbound is installed"
    
    # Kill any existing unbound process
    h.cmd('pkill unbound || true')
    time.sleep(0.2)
    
    # Try to start via systemctl first, then fall back to direct start
    h.cmd('systemctl restart unbound 2>/dev/null || service unbound restart 2>/dev/null || true')
    time.sleep(0.5)
    
    # Check if it started
    check_cmd = 'systemctl is-active unbound 2>/dev/null || service unbound status 2>/dev/null | grep -q "running" && echo "running" || true'
    result = h.cmd(check_cmd).strip()
    
    if not result or "running" not in result:
        # Try manual start
        h.cmd(f'bash -lc "unbound -d > {logfile} 2>&1 &" || bash -lc "unbound-daemon > {logfile} 2>&1 &"')
    
    # Verify it's listening on port 53
    check_cmd = 'ss -lnp | grep "127.0.0.1:53 " || netstat -lnp 2>/dev/null | grep "127.0.0.1:53 " || true'
    return check_service_up(h, check_cmd, f"unbound on {h.name}", logfile, timeout=5)


def start_smtp_debug(h, ip='0.0.0.0', port=25):
    """
    Start SMTP debug server.
    Returns (success: bool, message: str)
    """
    logfile = f'/tmp/smtpd_{h.name}.log'
    
    # Kill any existing process on port 25
    h.cmd('pkill -f smtpd || true')
    h.cmd('fuser -k 25/tcp 2>/dev/null || true')
    time.sleep(0.2)
    
    # Start SMTP server
    h.cmd(f'bash -lc "python3 -u -m smtpd -n -c DebuggingServer {ip}:{port} > {logfile} 2>&1 &"')
    
    # Check if it's listening
    check_cmd = f'ss -lnp | grep ":{port} " || netstat -lnp 2>/dev/null | grep ":{port} " || true'
    return check_service_up(h, check_cmd, f"SMTP on {h.name}:{port}", logfile, timeout=3)


def run_basic_tests(h1, dns, att, mx, zone='example.com'):
    """Run basic connectivity and DNS tests."""
    out = {}
    
    # Direct queries to authoritative servers
    out['dig_direct_authoritative'] = h1.cmd(f'dig +dnssec MX {zone} @{dns.IP()} +short').strip()
    out['dig_direct_attacker'] = h1.cmd(f'dig MX {zone} @{att.IP()} +short').strip()
    
    # Query via local resolver
    out['dig_via_resolver'] = h1.cmd(f'dig MX {zone} +short').strip()
    
    # Get MX and test SMTP
    mx_answer = out['mx_answer'] = h1.cmd(f'dig +short MX {zone}').strip()
    if mx_answer:
        try:
            parts = mx_answer.split()
            if len(parts) >= 2:
                pri, host = parts[0], parts[1]
                host = host.strip('.')
                a = h1.cmd(f'dig +short {host}').strip()
                if a:
                    out['mx_a'] = a
                    # Test SMTP with swaks if available
                    swaks_check = h1.cmd('which swaks 2>/dev/null').strip()
                    if swaks_check:
                        out['swaks'] = h1.cmd(f'swaks --to test@{zone} --server {a} --timeout 5 2>&1 || true').strip()
                    else:
                        out['swaks'] = 'swaks not installed'
        except Exception as e:
            out['mx_parse_error'] = str(e)
    
    return out


def main():
    setLogLevel('info')
    
    print("=" * 70)
    print("Lab 4 - DNS/SMTP All-in-One Setup with DNSSEC")
    print("=" * 70)
    
    # Create network
    net = Mininet(topo=LabTopo(), controller=OVSController, link=TCLink, build=True)
    net.start()
    
    # Get hosts
    h1 = net.get('h1')
    dns = net.get('dns')
    att = net.get('att')
    mx = net.get('mx')
    
    if not all([h1, dns, att, mx]):
        print("ERROR: Not all required hosts (h1, dns, att, mx) are in topology")
        net.stop()
        return 1
    
    print(f"\n>>> Hosts ready: h1={h1.IP()}, dns={dns.IP()}, att={att.IP()}, mx={mx.IP()}")
    
    # Prepare zone files on hosts
    print("\n>>> Copying zone files to dns and att hosts")
    src_good = os.path.join('zones', 'db.example.com.good')
    src_att = os.path.join('zones', 'db.example.com.att')
    
    if not os.path.exists(src_good):
        print(f"ERROR: Zone file not found: {src_good}")
        net.stop()
        return 1
    
    if not os.path.exists(src_att):
        print(f"ERROR: Zone file not found: {src_att}")
        net.stop()
        return 1
    
    dns.cmd('mkdir -p /root/zones || true')
    att.cmd('mkdir -p /root/zones || true')
    
    good_text = open(src_good).read()
    att_text = open(src_att).read()
    
    # Use cat with heredoc for reliable multi-line writes
    dns.cmd(f'cat > /root/zones/db.example.com.good << \'ZONEGOOD\'\n{good_text}\nZONEGOOD\n')
    att.cmd(f'cat > /root/zones/db.example.com.att << \'ZONEATT\'\n{att_text}\nZONEATT\n')
    
    # Verify files were written
    dns_check = dns.cmd('test -f /root/zones/db.example.com.good && echo "ok" || echo "fail"').strip()
    att_check = att.cmd('test -f /root/zones/db.example.com.att && echo "ok" || echo "fail"').strip()
    
    if dns_check != "ok":
        print("ERROR: Failed to write zone file on dns host")
        net.stop()
        return 1
    
    if att_check != "ok":
        print("ERROR: Failed to write zone file on att host")
        net.stop()
        return 1
    
    print("Zone files copied successfully")
    
    # DNSSEC setup + Unbound configuration
    print('\n>>> DNSSEC: signing zone and configuring Unbound on h1')
    try:
        res = enable_dnssec_and_client_validation(
            net, 
            dns_host='dns', 
            client_host='h1', 
            zone_name='example.com', 
            zone_file='/root/zones/db.example.com.good'
        )
        pprint.pprint(res)
        signed_zone = res.get('signed_zone', '/root/zones/db.example.com.good.signed')
        print(f"DNSSEC signing completed. Signed zone: {signed_zone}")
    except Exception as e:
        print(f"WARNING: DNSSEC setup encountered an error: {e}")
        print("Continuing with unsigned zone...")
        signed_zone = '/root/zones/db.example.com.good'
    
    # Start named with SIGNED zone on dns
    print('\n>>> Starting named on dns host with SIGNED zone')
    success, msg = start_bind_on_host(dns, signed_zone, 'example.com')
    print(msg)
    if not success:
        print("CRITICAL: DNS server on 'dns' host failed to start")
        print("This is a blocking issue - cannot proceed with tests")
        net.stop()
        return 1
    
    # Start named with attacker zone on att
    print('\n>>> Starting named on att host with attacker zone')
    success, msg = start_bind_on_host(att, '/root/zones/db.example.com.att', 'example.com')
    print(msg)
    if not success:
        print("WARNING: DNS server on 'att' host failed to start")
        print("Attack demonstration will not work, but continuing...")
    
    # SMTP sinks
    print('\n>>> Starting SMTP debug servers')
    success_mx, msg_mx = start_smtp_debug(mx)
    print(f"MX SMTP: {msg_mx}")
    
    success_att, msg_att = start_smtp_debug(att)
    print(f"ATT SMTP: {msg_att}")
    
    if not success_mx:
        print("WARNING: SMTP server on mx failed to start")
    
    time.sleep(1)
    
    # Run tests
    print('\n>>> Running quick connectivity and DNS tests')
    tests = run_basic_tests(h1, dns, att, mx, zone='example.com')
    pprint.pprint(tests)
    
    # Summary
    print('\n' + '=' * 70)
    print('SETUP SUMMARY')
    print('=' * 70)
    print(f"DNS on 'dns' host: {'✓ Running' if success else '✗ Failed'}")
    print(f"SMTP on 'mx' host: {'✓ Running' if success_mx else '✗ Failed'}")
    print("\nQuick test results:")
    print(f"  - Direct query to DNS: {tests.get('dig_direct_authoritative', 'N/A')[:50]}")
    print(f"  - Via resolver: {tests.get('dig_via_resolver', 'N/A')[:50]}")
    print('=' * 70)
    
    # CLI
    print('\n>>> Mininet CLI ready. You can now run additional tests.')
    print('    Type "exit" to stop the network and quit.\n')
    try:
        from mininet.cli import CLI
        CLI(net)
    except Exception as e:
        print(f"CLI error: {e}")
        time.sleep(2)
    
    net.stop()
    return 0


if __name__ == '__main__':
    try:
        exit_code = main()
        exit(exit_code)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        exit(1)
    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
