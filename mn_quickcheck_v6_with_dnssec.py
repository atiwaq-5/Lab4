#!/usr/bin/env python3
"""
mn_quickcheck_v6_with_dnssec_v3.py
- Uses user's topology if available, else a default h1/dns/att/mx on one switch
- Copies zone files to dns/att
- **Signs the zone BEFORE starting named** (via helper v2) and configures Unbound on h1
- Starts named on dns with the **SIGNED** zone and on att with attacker zone
- Starts SMTP debug servers
- Runs quick dig/swaks tests and opens Mininet CLI

Run:
    sudo python3 mn_quickcheck_v6_with_dnssec_v3.py
"""
import os, time, pprint
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
            LabTopo = _obj; break
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

# Helper (v2 uses absolute paths and single-line-friendly writes)
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
    
    h.cmd(f'mkdir -p {tmpdir}')
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
    # Write using cat with unique heredoc marker
    h.cmd(f'cat > {conf_path} << \'EOF_NAMED_CONFIG_8a9b2c\'\n{named_conf}\nEOF_NAMED_CONFIG_8a9b2c\n')
    
    # Check if zone file exists before starting
    zone_check = h.cmd(f'test -f {zone_path} && echo "exists" || echo "missing"').strip()
    if zone_check != "exists":
        return False, f"Zone file not found: {zone_path}"
    
    # Check if named binary exists
    named_check = h.cmd('which named 2>/dev/null || echo "missing"').strip()
    if named_check == "missing":
        return False, "named binary not found - ensure bind9 is installed"
    
    h.cmd('pkill named || true')
    time.sleep(0.2)
    h.cmd(f'bash -lc "named -c {conf_path} -u root > {logfile} 2>&1 &"')
    
    # Check if service started successfully
    check_cmd = 'ss -lnp | grep ":53 " || true'
    return check_service_up(h, check_cmd, f"named on {h.name}", logfile, timeout=5)


def start_smtp_debug(h, ip='0.0.0.0', port=25):
    """
    Start SMTP debug server.
    Returns (success: bool, message: str)
    """
    logfile = f'/tmp/smtpd_{h.name}.log'
    h.cmd('pkill -f smtpd || true')
    h.cmd('fuser -k 25/tcp 2>/dev/null || true')
    time.sleep(0.2)
    h.cmd(f'bash -lc "python3 -u -m smtpd -n -c DebuggingServer {ip}:{port} > {logfile} 2>&1 &"')
    
    # Check if it's listening
    check_cmd = f'ss -lnp | grep ":{port} " || netstat -lnp 2>/dev/null | grep ":{port} " || true'
    return check_service_up(h, check_cmd, f"SMTP on {h.name}:{port}", logfile, timeout=3)


def run_basic_tests(h1, dns, att, mx, zone='example.com'):
    out = {}
    out['dig_direct_authoritative'] = h1.cmd(f'dig +dnssec MX {zone} @{dns.IP()} +short').strip()
    out['dig_direct_attacker'] = h1.cmd(f'dig MX {zone} @{att.IP()} +short').strip()
    out['dig_via_resolver'] = h1.cmd(f'dig MX {zone} +short').strip()
    mx_answer = out['mx_answer'] = h1.cmd(f'dig +short MX {zone}').strip()
    if mx_answer:
        try:
            pri, host = mx_answer.split()[:2]
            host = host.strip('.')
            a = h1.cmd(f'dig +short {host}').strip()
            if a:
                out['mx_a'] = a
                out['swaks'] = h1.cmd(f'swaks --to test@{zone} --server {a} --timeout 5 2>&1 || true').strip()
        except Exception as e:
            out['mx_parse_error'] = str(e)
    return out


def main():
    setLogLevel('info')
    net = Mininet(topo=LabTopo(), controller=OVSController, link=TCLink, build=True)
    net.start()
    h1, dns, att, mx = net.get('h1'), net.get('dns'), net.get('att'), net.get('mx')

    if not all([h1, dns, att, mx]):
        print("ERROR: Not all required hosts (h1, dns, att, mx) are in topology")
        net.stop()
        return 1

    # Prepare zone files on hosts (copy user's zones/zones/*.good|att into /root/zones on dns/att)
    src_good = os.path.join('zones','db.example.com.good')
    src_att  = os.path.join('zones','db.example.com.att')
    
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
    att_text  = open(src_att).read()
    # Write using cat with unique heredoc markers
    dns.cmd(f'cat > /root/zones/db.example.com.good << \'EOF_ZONE_GOOD_7c8d9e\'\n{good_text}\nEOF_ZONE_GOOD_7c8d9e\n')
    att.cmd(f'cat > /root/zones/db.example.com.att << \'EOF_ZONE_ATT_6b7c8d\'\n{att_text}\nEOF_ZONE_ATT_6b7c8d\n')

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

    # DNSSEC + Unbound BEFORE named
    print('>>> DNSSEC: signing zone and configuring Unbound on h1')
    try:
        res = enable_dnssec_and_client_validation(net, dns_host='dns', client_host='h1', zone_name='example.com', zone_file='/root/zones/db.example.com.good')
        pprint.pprint(res)
        signed_zone = res.get('signed_zone', '/root/zones/db.example.com.good.signed')
    except Exception as e:
        print(f"WARNING: DNSSEC setup encountered an error: {e}")
        print("Continuing with unsigned zone...")
        signed_zone = '/root/zones/db.example.com.good'

    # Start named with SIGNED zone on dns and attacker zone on att
    print('>>> Starting named on dns (SIGNED) and att (attacker)')
    success_dns, msg_dns = start_bind_on_host(dns, signed_zone, 'example.com')
    print(msg_dns)
    if not success_dns:
        print("CRITICAL: DNS server on 'dns' host failed to start")
        print("This is a blocking issue - cannot proceed with tests")
        net.stop()
        return 1
    
    success_att, msg_att = start_bind_on_host(att, '/root/zones/db.example.com.att', 'example.com')
    print(msg_att)
    if not success_att:
        print("WARNING: DNS server on 'att' host failed to start")
        print("Attack demonstration will not work, but continuing...")

    # SMTP sinks
    print('>>> Starting SMTP debug sinks on mx and att')
    success_mx, msg_mx = start_smtp_debug(mx)
    print(f"MX SMTP: {msg_mx}")
    
    success_att_smtp, msg_att_smtp = start_smtp_debug(att)
    print(f"ATT SMTP: {msg_att_smtp}")
    
    if not success_mx:
        print("WARNING: SMTP server on mx failed to start")
    
    time.sleep(1)

    # Tests
    print('>>> Running quick tests')
    tests = run_basic_tests(h1, dns, att, mx, zone='example.com')
    pprint.pprint(tests)

    # Summary
    print('\n' + '=' * 70)
    print('SETUP SUMMARY')
    print('=' * 70)
    print(f"DNS on 'dns' host: {'✓ Running' if success_dns else '✗ Failed'}")
    print(f"DNS on 'att' host: {'✓ Running' if success_att else '✗ Failed'}")
    print(f"SMTP on 'mx' host: {'✓ Running' if success_mx else '✗ Failed'}")
    print(f"SMTP on 'att' host: {'✓ Running' if success_att_smtp else '✗ Failed'}")
    print('=' * 70)

    # CLI
    print('>>> Mininet CLI ready (type exit to quit)')
    try:
        from mininet.cli import CLI
        CLI(net)
    except Exception:
        time.sleep(1)

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
