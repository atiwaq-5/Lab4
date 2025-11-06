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

def start_bind_on_host(h, zone_path, zone_name):
    """Start a minimal named instance with a tiny config under /tmp, no heredocs."""
    tmpdir = f"/tmp/bind_{h.name}"
    h.cmd(f'mkdir -p {tmpdir}')
    named_conf = (
        'options {\n'
        f'    directory "{tmpdir}";\n'
        '    recursion no;\n'
        '    allow-query { any; };\n'
        '};\n'
        f'zone "{zone_name}" IN {{\n'
        '    type master;\n'
        f'    file "{zone_path}";\n'
        '};\n'
    )
    conf_path = os.path.join(tmpdir, 'named.conf')
    # single-line write
    h.cmd('bash -lc "printf %s %s > %s"' % ("%s", repr(named_conf)[1:-1], conf_path))
    h.cmd('pkill named || true')
    h.cmd(f'named -c {conf_path} -u root 2>/tmp/named_{h.name}.log &')
    time.sleep(0.5)


def start_smtp_debug(h, ip='0.0.0.0', port=25):
    h.cmd('pkill -f smtpd || true')
    h.cmd(f'python3 -u -m smtpd -n -c DebuggingServer {ip}:{port} > /tmp/smtpd_{h.name}.log 2>&1 &')
    time.sleep(0.2)


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

    # Prepare zone files on hosts (copy user's zones/zones/*.good|att into /root/zones on dns/att)
    src_good = os.path.join('zones','db.example.com.good')
    src_att  = os.path.join('zones','db.example.com.att')
    dns.cmd('mkdir -p /root/zones || true'); att.cmd('mkdir -p /root/zones || true')
    good_text = open(src_good).read() if os.path.exists(src_good) else ''
    att_text  = open(src_att).read()  if os.path.exists(src_att)  else ''
    dns.cmd('bash -lc "printf %s %s > /root/zones/db.example.com.good"' % ("%s", repr(good_text)[1:-1]))
    att.cmd('bash -lc "printf %s %s > /root/zones/db.example.com.att"'  % ("%s", repr(att_text)[1:-1]))

    # DNSSEC + Unbound BEFORE named
    print('>>> DNSSEC: signing zone and configuring Unbound on h1')
    res = enable_dnssec_and_client_validation(net, dns_host='dns', client_host='h1', zone_name='example.com', zone_file='/root/zones/db.example.com.good')
    pprint.pprint(res)
    signed_zone = res.get('signed_zone', '/root/zones/db.example.com.good.signed')

    # Start named with SIGNED zone on dns and attacker zone on att
    print('>>> Starting named on dns (SIGNED) and att (attacker)')
    start_bind_on_host(dns, signed_zone, 'example.com')
    start_bind_on_host(att, '/root/zones/db.example.com.att', 'example.com')

    # SMTP sinks
    print('>>> Starting SMTP debug sinks on mx and att')
    start_smtp_debug(mx); start_smtp_debug(att)
    time.sleep(1)

    # Tests
    print('>>> Running quick tests')
    tests = run_basic_tests(h1, dns, att, mx, zone='example.com')
    pprint.pprint(tests)

    # CLI
    print('>>> Mininet CLI ready (type exit to quit)')
    try:
        from mininet.cli import CLI
        CLI(net)
    except Exception:
        time.sleep(1)

    net.stop()

if __name__ == '__main__':
    main()
