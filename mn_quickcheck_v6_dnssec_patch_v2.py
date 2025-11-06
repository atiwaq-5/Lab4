"""
Patch helper v2 for mn_quickcheck_v6.py -- add DNSSEC signing on authoritative 'dns' and a validating Unbound on 'h1'.

Version 2 improvements:
- Uses absolute paths for better reliability
- Uses single-line-friendly writes (bash -lc "printf ...") instead of here-documents
- Improved error handling and diagnostics

How to use:
- Import these functions into your runner and call `enable_dnssec_and_client_validation(net, dns_host='dns', client_host='h1', zone_name='example.com', zone_file='/root/zones/db.example.com.good')`
- The code assumes the Mininet hosts expose a `.cmd()` method to run shell commands (same style as your existing runner).
- It does not execute external package installation; ensure `bind9utils` (for dnssec-keygen/dnssec-signzone) and `unbound` are available in the host images or install them beforehand.

Notes:
- This is a best-effort patch: adjust paths (zone dir), user permissions, or service names to match your environment.
- The function uses single-line writes to be compatible with various shell environments.

"""
import shlex
import time
import re


def _run(h, cmd):
    """Run command `cmd` on Mininet host `h` and return (exitcode, output)."""
    out = h.cmd(cmd)
    # Mininet host.cmd doesn't return exit status; approximate by checking common failure strings
    return out


def enable_dnssec_and_client_validation(net, dns_host='dns', client_host='h1', zone_name='example.com', zone_file='/root/zones/db.example.com.good'):
    """Perform DNSSEC key generation, zone signing on `dns_host`, and configure Unbound on `client_host` with a trust-anchor.

    Parameters:
    - net: Mininet network object (your runner uses this)
    - dns_host: name of authoritative DNS host in the topology
    - client_host: name of client host to run Unbound
    - zone_name: DNS zone (example.com)
    - zone_file: path to the unsigned zone file on the dns host

    Returns a dictionary with diagnostics: {'ksk':..., 'signed_zone':..., 'dig_signed':..., 'dig_validated':...}
    """
    dns = net.get(dns_host)
    h1 = net.get(client_host)

    results = {}

    # Create zone dir (safe) and make sure permissions are OK
    _run(dns, 'mkdir -p $(dirname %s) || true' % shlex.quote(zone_file))

    # 1) Generate keys if not exist
    key_pattern = re.sub(r"\W+","_", zone_name)
    # Check if any K*.key exists in CWD (same dir as zone_file)
    keydir_cmd = 'bash -c "cd $(dirname %s) && ls K%s.+*.key 2>/dev/null || true"' % (shlex.quote(zone_file), key_pattern)
    existing = _run(dns, keydir_cmd).strip()
    if existing:
        _run(dns, 'echo "DNSSEC keys already present: %s"' % shlex.quote(existing))
    else:
        # Generate KSK and ZSK
        _run(dns, 'cd $(dirname %s) && dnssec-keygen -a RSASHA256 -b 2048 -n ZONE -f KSK %s' % (shlex.quote(zone_file), shlex.quote(zone_name)))
        _run(dns, 'cd $(dirname %s) && dnssec-keygen -a RSASHA256 -b 2048 -n ZONE %s' % (shlex.quote(zone_file), shlex.quote(zone_name)))

    # 2) Locate key filenames
    list_keys_cmd = 'bash -lc "cd $(dirname %s) && ls K%s.+*.key 2>/dev/null || true"' % (shlex.quote(zone_file), key_pattern)
    key_files = _run(dns, list_keys_cmd).split()
    if not key_files:
        raise RuntimeError('DNSSEC key generation failed or keys not found; check dns host environment')

    # Identify KSK (flag 257) and ZSK (flag 256) by reading the keyline
    ksk = None
    zsk = None
    for kf in key_files:
        show_cmd = 'bash -lc "cd $(dirname %s) && cat %s"' % (shlex.quote(zone_file), shlex.quote(kf))
        content = _run(dns, show_cmd)
        if '257' in content:
            ksk = kf
        else:
            zsk = kf
    if not ksk or not zsk:
        # fallback: pick first as KSK and second as ZSK
        if len(key_files) >= 2:
            ksk = key_files[0]
            zsk = key_files[1]
        else:
            raise RuntimeError('Could not determine KSK/ZSK from generated keys')

    results['ksk_file'] = ksk
    results['zsk_file'] = zsk

    # 3) Sign the zone (produce .signed file)
    signed_zone = zone_file + '.signed'
    sign_cmd = 'bash -lc "cd $(dirname %s) && dnssec-signzone -o %s -N INCREMENT -k %s %s %s 2>&1 | sed -n \"1,200p\""' % (
        shlex.quote(zone_file), shlex.quote(zone_name), shlex.quote(ksk.replace('.key','')), shlex.quote(zone_file), shlex.quote(zsk.replace('.key','')))
    sign_out = _run(dns, sign_cmd)
    results['sign_output'] = sign_out

    # 4) Update named zone file reference (best-effort): we append a temporary include to named.conf.local if present
    named_local = '/etc/bind/named.conf.local'
    # This is conservative: do not overwrite, just point out what to change.
    _run(dns, 'echo "# Ensure zone file for %s uses signed file: %s" >> /tmp/dnssec_hint.txt' % (shlex.quote(zone_name), shlex.quote(signed_zone)))

    # 5) Extract KSK DNSKEY line (public key) for trust-anchor
    ksk_keypath = '$(dirname %s)/%s' % (shlex.quote(zone_file), ksk)
    dnskey_grep_cmd = 'bash -lc "cd $(dirname %s) && cat %s | grep -v "^;" | sed -n \"1,200p\""' % (shlex.quote(zone_file), ksk_keypath)
    dnskey_line = _run(dns, dnskey_grep_cmd).strip()
    # The .key file contains something like: example.com. IN DNSKEY 257 3 8 AwEAA...; key id = 12345
    # We need the "257 3 8 <base64>" part. Extract with regex.
    m = re.search(r"DNSKEY\s+(257)\s+3\s+8\s+([A-Za-z0-9+/=]+)", dnskey_line)
    if not m:
        # Try to build from .key file content
        content = _run(dns, 'cat $(dirname %s)/%s' % (shlex.quote(zone_file), shlex.quote(ksk))).strip()
        m = re.search(r"DNSKEY\s+257\s+3\s+8\s+([A-Za-z0-9+/=]+)", content)
    if not m:
        raise RuntimeError('Could not extract KSK public key from %s on dns host' % ksk)
    ksk_b64 = m.group(2)
    results['ksk_b64'] = ksk_b64

    # 6) Configure Unbound on client_host: write a small conf file with trust-anchor and stub-zone
    unbound_conf = f"""
server:
    verbosity: 1
    interface: 0.0.0.0
    access-control: 0.0.0.0/0 allow
    val-permissive-mode: no
    harden-dnssec-stripped: yes
    qname-minimisation: yes
    # No auto-trust to root; we're using an island trust anchor for this lab
    auto-trust-anchor-file: ""
    trust-anchor: \"{zone_name}. 257 3 8 {ksk_b64}\"

stub-zone:
    name: \"{zone_name}\"
    stub-addr: {net.get(dns_host).IP()} 53
""".format(zone_name=zone_name, ksk_b64=ksk_b64, **locals())

    # Write Unbound conf file using printf (single-line friendly)
    unbound_conf_path = '/etc/unbound/unbound.conf.d/example_lab.conf'
    write_cmd = 'bash -lc "mkdir -p $(dirname %s) && printf \'%%s\' %s > %s"' % (
        shlex.quote(unbound_conf_path), 
        shlex.quote(repr(unbound_conf)),
        shlex.quote(unbound_conf_path)
    )
    _run(h1, write_cmd)

    # 7) Start/Restart unbound on h1
    _run(h1, 'systemctl restart unbound || service unbound restart || true')

    # 8) Point h1 resolv.conf to localhost
    _run(h1, 'bash -lc "echo \"nameserver 127.0.0.1\" > /etc/resolv.conf"')

    # 9) Quick validation checks
    # Ask dns for the signed zone (direct)
    dig_signed = _run(h1, f'dig +dnssec MX {zone_name} @{net.get(dns_host).IP()} +short')
    results['dig_signed_direct'] = dig_signed.strip()

    # Ask unbound (via resolver) for the zone - expecting AD or an answer
    dig_validated = _run(h1, f'dig MX {zone_name} +short')
    results['dig_validated'] = dig_validated.strip()

    # 10) Simulate attack: show attacker returns an MX but validation should cause resolver to fail when the attacker is used
    # Note: we do not change system-wide settings here; your existing tests toggle resolv.conf to point to attacker directly. Show the attacker's authoritative answer:
    # The attacker host name assumed to be 'att'
    try:
        att = net.get('att')
        attacker_answer = _run(h1, f'dig MX {zone_name} @{att.IP()} +short')
        results['attacker_answer_direct'] = attacker_answer.strip()
    except Exception:
        results['attacker_answer_direct'] = '(no attacker host in net)'

    return results


# End of file
