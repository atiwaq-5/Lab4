#!/usr/bin/env python3
"""
lab4_mininet_all_in_one.py

ONE FILE to run the full Lab 4 flow in a Mininet VM:
- Topology (h1, dns, att, mx) or user's Topo if present
- Copy/compose DNS zones (good + attacker), add SPF & DMARC, (optionally) DKIM DNS record
- **DNSSEC**: sign the good zone on dns; configure Unbound validator on h1
- Start minimal named on dns (SIGNED) and att (attacker)
- DKIM: try to generate DKIM key (opendkim-genkey) and publish TXT; attempt basic verification
- SMTP sinks on mx & att; basic delivery tests with swaks
- Compare insecure vs protected behavior

Run:
    sudo python3 lab4_mininet_all_in_one.py

Notes:
- This script will attempt to install missing host packages automatically when run as root:
  bind9, bind9utils, dnsutils, unbound, opendkim, opendkim-tools, swaks
- Mininet namespaces share the same filesystem; packages installed on the VM are visible to hosts.
"""
import os
import time
import pprint
import re
import shlex
import subprocess
import sys
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.topo import Topo

# ---------------------- Utilities ----------------------

def _run(h, cmd):
    return h.cmd(cmd)

# Single-line safe file write: content is Python string; we escape via repr

def write_file(h, path, content):
    _run(h, 'bash -lc "printf %s %s > %s"' % ("%s", repr(content)[1:-1], shlex.quote(path)))

# ---------------------- Package installation ----------------------

REQUIRED_PACKAGES = [
    'bind9',
    'bind9utils',
    'dnsutils',
    'unbound',
    'opendkim',
    'opendkim-tools',
    'swaks',
]

def _is_package_installed(pkg):
    """Return True if dpkg reports the package installed."""
    try:
        res = subprocess.run(['dpkg', '-s', pkg],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def install_missing_packages(packages):
    """Install packages via apt-get if running as root and any are missing.
    This will perform apt-get update and apt-get install -y for missing packages.
    """
    if os.geteuid() != 0:
        print('Not running as root; skipping automatic package installation.')
        missing = [p for p in packages if not _is_package_installed(p)]
        if missing:
            print('To install missing packages manually run:')
            print('sudo apt update && sudo apt install -y ' + ' '.join(missing))
        else:
            print('All required packages appear installed (checked as non-root).')
        return

    missing = [p for p in packages if not _is_package_installed(p)]
    if not missing:
        print('All required packages already installed:', ', '.join(packages))
        return

    print('Installing missing packages:', ', '.join(missing))
    try:
        env = os.environ.copy()
        env['DEBIAN_FRONTEND'] = 'noninteractive'
        # update first
        subprocess.run(['apt-get', 'update'], check=False, env=env)
        cmd = ['apt-get', 'install', '-y'] + missing
        subprocess.run(cmd, check=True, env=env)
        print('Package installation finished.')
    except subprocess.CalledProcessError as e:
        print('Package installation failed with code', e.returncode)
        print('You can install packages manually: sudo apt update && sudo apt install -y ' + ' '.join(missing))

# ---------------------- Topology ----------------------

def load_or_default_topo():
    try:
        import lab4_topo_v6e as topo_mod
        T = None
        for n, o in topo_mod.__dict__.items():
            if isinstance(o, type) and issubclass(o, Topo) and o is not Topo:
                T = o; break
        if T: return T
        raise ImportError('No Topo subclass found in lab4_topo_v6e.py')
    except Exception:
        class DefaultTopo(Topo):
            def build(self):
                s1 = self.addSwitch('s1')
                self.addLink(self.addHost('h1', ip='10.0.0.10/24'), s1)
                self.addLink(self.addHost('dns', ip='10.0.0.53/24'), s1)
                self.addLink(self.addHost('att', ip='10.0.0.66/24'), s1)
                self.addLink(self.addHost('mx',  ip='10.0.0.25/24'), s1)
        return DefaultTopo

# ---------------------- DNS Zones ----------------------

DEFAULT_GOOD_ZONE = (
    "; example.com zone (GOOD)\n"
    "$TTL 300\n"
    "@   IN SOA ns.example.com. admin.example.com. ( 2025010101 3600 900 604800 300 )\n"
    "    IN NS ns.example.com.\n"
    "ns  IN A 10.0.0.53\n"
    "@   IN MX 10 mail.example.com.\n"
    "mail IN A 10.0.0.25\n"
    "@   IN A 10.0.0.25\n"
    "; SPF: only mx\n"
    "@   IN TXT \"v=spf1 ip4:10.0.0.25 -all\"\n"
    "; DMARC: quarantine failures (report to postmaster)\n"
    "_dmarc IN TXT \"v=DMARC1; p=quarantine; rua=mailto:postmaster@example.com; pct=100\"\n"
)

DEFAULT_ATT_ZONE = (
    "; example.com zone (ATTACKER)\n"
    "$TTL 300\n"
    "@   IN SOA ns.example.com. admin.example.com. ( 2025010101 3600 900 604800 300 )\n"
    "    IN NS ns.example.com.\n"
    "ns  IN A 10.0.0.66\n"
    "@   IN MX 10 att.example.com.\n"
    "att IN A 10.0.0.66\n"
    "@   IN A 10.0.0.66\n"
)

# ---------------------- Services ----------------------

def start_named_authoritative(h, zone_name, zone_path):
    tmp = f"/tmp/bind_{h.name}"
    _run(h, f'mkdir -p {tmp}')
    named_conf = (
        "options\n"
        "{{\n"
        "    directory \"{tmp}\";\n"
        "    recursion no;\n"
        "    allow-query {{ any; }};\n"
        "}}\n"
        "zone \"{zone_name}\" IN\n"
        "{{\n"
        "    type master;\n"
        "    file \"{zone_path}\";\n"
        "}}\n"
    ).format(tmp=tmp, zone_name=zone_name, zone_path=zone_path)
    conf = f"{tmp}/named.conf"
    write_file(h, conf, named_conf)
    _run(h, 'pkill named || true')
    # Start named in the host namespace (the mininet host will see the binary)
    _run(h, f'named -c {conf} -u root 2>/tmp/named_{h.name}.log &')
    time.sleep(0.4)


def start_smtp_sink(h, ip='0.0.0.0', port=25):
    _run(h, 'pkill -f smtpd || true')
    _run(h, f'python3 -u -m smtpd -n -c DebuggingServer {ip}:{port} > /tmp/smtpd_{h.name}.log 2>&1 &')
    time.sleep(0.2)

# ---------------------- DNSSEC ----------------------

def dnssec_sign_and_client_validate(net, zone_file='/root/zones/db.example.com.good', zone_name='example.com', dns_host='dns', client_host='h1'):
    dns = net.get(dns_host); h1 = net.get(client_host)
    res = {}
    _run(dns, 'mkdir -p $(dirname %s) || true' % shlex.quote(zone_file))

    # Use command -v to detect dnssec tools (do not hardcode /usr/sbin path)
    kk = _run(dns, 'bash -lc "command -v dnssec-keygen || echo MISSING"').strip()
    sz = _run(dns, 'bash -lc "command -v dnssec-signzone || echo MISSING"').strip()
    if kk.endswith('MISSING') or sz.endswith('MISSING'):
        res['dnssec_tools'] = 'missing'; return res

    # keys if absent
    pattern = re.sub(r"\W+", "_", zone_name)
    has_keys = _run(dns, 'bash -lc "cd $(dirname %s) && ls K%s.+*.key 2>/dev/null || true"' % (shlex.quote(zone_file), pattern)).strip()
    if not has_keys:
        _run(dns, 'bash -lc "cd $(dirname %s) && dnssec-keygen -a RSASHA256 -b 2048 -n ZONE -f KSK %s"' % (shlex.quote(zone_file), shlex.quote(zone_name)))
        _run(dns, 'bash -lc "cd $(dirname %s) && dnssec-keygen -a RSASHA256 -b 2048 -n ZONE %s"' % (shlex.quote(zone_file), shlex.quote(zone_name)))
    # pick keys
    keys = _run(dns, 'bash -lc "cd $(dirname %s) && ls K%s.+*.key 2>/dev/null"' % (shlex.quote(zone_file), pattern)).split()
    if not keys: res['keys'] = 'none'; return res
    ksk = zsk = None
    for k in keys:
        content = _run(dns, 'bash -lc "cd $(dirname %s) && cat %s"' % (shlex.quote(zone_file), shlex.quote(k)))
        if ' DNSKEY 257 ' in content: ksk = k
        elif ' DNSKEY 256 ' in content: zsk = k
    if not ksk: ksk = keys[0]
    if not zsk: zsk = keys[-1]
    res['ksk_file'] = ksk; res['zsk_file'] = zsk
    signed = zone_file + '.signed'
    _run(dns, 'bash -lc "cd $(dirname %s) && dnssec-signzone -o %s -N INCREMENT -k %s %s %s >/tmp/dnssec_sign.out 2>&1"' % (
        shlex.quote(zone_file), shlex.quote(zone_name), shlex.quote(ksk.replace('.key', '')), shlex.quote(zone_file), shlex.quote(zsk.replace('.key', ''))))
    res['signed_zone'] = signed
    # KSK b64 -> Unbound trust anchor
    ksk_content = _run(dns, 'bash -lc "cd $(dirname %s) && cat %s"' % (shlex.quote(zone_file), shlex.quote(ksk)))
    m = re.search(r"DNSKEY\s+257\s+3\s+8\s+([A-Za-z0-9+/=]+)", ksk_content)
    if not m: res['ksk_b64'] = ''; return res
    b64 = m.group(1); res['ksk_b64'] = b64
    conf = (
        'server:\n'
        '    verbosity: 1\n'
        '    interface: 0.0.0.0\n'
        '    access-control: 0.0.0.0/0 allow\n'
        '    val-permissive-mode: no\n'
        '    harden-dnssec-stripped: yes\n'
        '    qname-minimisation: yes\n'
        '    auto-trust-anchor-file: ""\n'
        f'    trust-anchor: "{zone_name}. 257 3 8 {b64}"\n\n'
        'stub-zone:\n'
        f'    name: "{zone_name}"\n'
        f'    stub-addr: {net.get(dns_host).IP()} 53\n'
    )
    write_file(h1, '/etc/unbound/unbound.conf.d/example_lab.conf', conf)
    _run(h1, 'systemctl restart unbound || service unbound restart || true')
    _run(h1, 'bash -lc "echo nameserver 127.0.0.1 > /etc/resolv.conf"')
    res['dig_signed_direct'] = _run(h1, f'dig +dnssec MX {zone_name} @{net.get(dns_host).IP()} +short').strip()
    res['dig_validated'] = _run(h1, f'dig MX {zone_name} +short').strip()
    try:
        att = net.get('att'); res['attacker_answer_direct'] = _run(h1, f'dig MX {zone_name} @{att.IP()} +short').strip()
    except Exception:
        res['attacker_answer_direct'] = ''
    return res

# ---------------------- DKIM (best-effort) ----------------------

def try_generate_dkim_and_publish(net, dns_host='dns', zone_file='/root/zones/db.example.com.good', zone_name='example.com', selector='s1'):
    """Attempt to generate a DKIM keypair on dns and add the public key to the zone.
    If opendkim-genkey not present, skip gracefully. Returns (added, dkim_dns_txt)."""
    dns = net.get(dns_host)
    ok = _run(dns, 'bash -lc "command -v opendkim-genkey || echo MISSING"').strip()
    if ok.endswith('MISSING'):
        return {'dkim': 'skipped (opendkim-genkey missing)'}
    zone_dir_cmd = 'bash -lc "dirname %s"' % shlex.quote(zone_file)
    zdir = _run(dns, zone_dir_cmd).strip() or '/root/zones'
    _run(dns, f'bash -lc "cd {shlex.quote(zdir)} && opendkim-genkey -s {selector} -d {zone_name} >/dev/null 2>&1 || true"')
    pub = _run(dns, f'bash -lc "cd {shlex.quote(zdir)} && cat {selector}.txt 2>/dev/null || true"')
    # The .txt file is already a DNS TXT record line; we insert into zone file if not present
    if not pub.strip():
        return {'dkim': 'failed to gen key'}
    # sanitize: ensure it ends with newline
    if not pub.endswith('\n'): pub += '\n'
    # Append to zone file
    append_cmd = 'bash -lc "printf %s %s >> %s"' % ("%s", repr(pub)[1:-1], shlex.quote(zone_file))
    _run(dns, append_cmd)
    return {'dkim': 'published', 'record': pub.strip()}

# ---------------------- Tests ----------------------

def run_quick_tests(h1, dns, att, mx, zone='example.com'):
    out = {}
    out['dig_direct_authoritative'] = _run(h1, f'dig +dnssec MX {zone} @{dns.IP()} +short').strip()
    out['dig_direct_attacker'] = _run(h1, f'dig MX {zone} @{att.IP()} +short').strip()
    out['dig_via_resolver'] = _run(h1, f'dig MX {zone} +short').strip()
    mx_answer = out['mx_answer'] = _run(h1, f'dig +short MX {zone}').strip()
    if mx_answer:
        try:
            pri, host = mx_answer.split()[:2]
            host = host.strip('.')
            a = _run(h1, f'dig +short {host}').strip()
            # Only run swaks if 'a' looks like an IPv4 address
            if a and re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', a.split()[0]):
                ip = a.split()[0]
                out['mx_a'] = ip
                out['swaks'] = _run(h1, f'swaks --to test@{zone} --server {ip} --timeout 5 2>&1 || true').strip()
            else:
                out['mx_a'] = a
                out['swaks'] = 'skipped (invalid MX A record)'
        except Exception as e:
            out['mx_parse_error'] = str(e)
    return out

# ---------------------- Main ----------------------

def main():
    setLogLevel('info')

    # Try to ensure required packages are installed on the VM host (only when running as root)
    install_missing_packages(REQUIRED_PACKAGES)

    net = Mininet(topo=load_or_default_topo()(), controller=OVSController, link=TCLink, build=True)
    net.start()
    h1, dns, att, mx = net.get('h1'), net.get('dns'), net.get('att'), net.get('mx')

    # Prepare zone files on dns/att from user's ./zones or defaults
    src_good = os.path.join('zones', 'db.example.com.good')
    src_att  = os.path.join('zones', 'db.example.com.att')
    dns.cmd('mkdir -p /root/zones || true'); att.cmd('mkdir -p /root/zones || true')
    good_text = open(src_good).read() if os.path.exists(src_good) else DEFAULT_GOOD_ZONE
    att_text  = open(src_att).read()  if os.path.exists(src_att)  else DEFAULT_ATT_ZONE
    write_file(dns, '/root/zones/db.example.com.good', good_text)
    write_file(att, '/root/zones/db.example.com.att', att_text)

    # DKIM publish (best effort) BEFORE signing so it gets into the signed zone
    dkim_info = try_generate_dkim_and_publish(net, dns_host='dns', zone_file='/root/zones/db.example.com.good', zone_name='example.com', selector='s1')

    # DNSSEC sign + Unbound validator
    print('>>> DNSSEC: signing zone and configuring Unbound')
    dnssec = dnssec_sign_and_client_validate(net, zone_file='/root/zones/db.example.com.good', zone_name='example.com', dns_host='dns', client_host='h1')

    # Start authoritative named with SIGNED zone on dns, attacker on att
    signed_path = dnssec.get('signed_zone', '/root/zones/db.example.com.good.signed')
    print('>>> Starting named on dns (SIGNED) and att (attacker)')
    start_named_authoritative(dns, 'example.com', signed_path)
    start_named_authoritative(att,  'example.com', '/root/zones/db.example.com.att')

    # SMTP debug sinks
    print('>>> Starting SMTP sinks on mx and att')
    start_smtp_sink(mx); start_smtp_sink(att)
    time.sleep(1)

    # Quick tests
    print('>>> Quick tests')
    tests = run_quick_tests(h1, dns, att, mx, zone='example.com')

    # Summaries
    summary = {
        'dkim': dkim_info,
        'dnssec': dnssec,
        'tests': tests,
        'notes': 'If dnssec_tools==missing, install bind9utils on VM. DKIM publish requires opendkim-tools. SPF/DMARC already included in default zone.'
    }
    pprint.pprint(summary)

    # CLI for screenshots
    print('>>> Mininet CLI ready (type exit to quit)')
    try:
        from mininet.cli import CLI
        CLI(net)
    except Exception:
        time.sleep(1)

    net.stop()

if __name__ == '__main__':
    main()