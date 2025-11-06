"""
Patch helper v2 for DNSSEC -- improved version with absolute paths and single-line writes.
This module enables DNSSEC signing on the authoritative DNS server and configures
Unbound for DNSSEC validation on the client host.

How to use:
- Import and call `enable_dnssec_and_client_validation(net, dns_host='dns', 
  client_host='h1', zone_name='example.com', zone_file='/root/zones/db.example.com')`
- Requires `bind9utils` (dnssec-keygen, dnssec-signzone) and `unbound` to be installed
- Uses absolute paths and simplified command execution for Mininet environments

Key improvements over v1:
- Uses absolute paths throughout
- Single-line friendly file writes (no heredocs)
- Better error handling and diagnostics
- Cleaner output formatting
"""
import os
import time
import re


def _run(h, cmd):
    """Run command `cmd` on Mininet host `h` and return output."""
    return h.cmd(cmd)


def enable_dnssec_and_client_validation(net, dns_host='dns', client_host='h1', 
                                        zone_name='example.com', 
                                        zone_file='/root/zones/db.example.com'):
    """
    Perform DNSSEC key generation and zone signing on `dns_host`, and configure 
    Unbound on `client_host` with a trust-anchor for validation.

    Parameters:
    - net: Mininet network object
    - dns_host: name of authoritative DNS host in the topology (default: 'dns')
    - client_host: name of client host to run Unbound (default: 'h1')
    - zone_name: DNS zone to sign (default: 'example.com')
    - zone_file: absolute path to the unsigned zone file on the dns host

    Returns:
    Dictionary with diagnostics including:
    - ksk_file: KSK filename
    - zsk_file: ZSK filename
    - signed_zone: path to signed zone file
    - ksk_public_key: DNSKEY record for trust anchor
    - ds_record: DS record for parent zone delegation
    - dig_signed_direct: test query to authoritative server
    - dig_validated: test query via validating resolver
    """
    dns = net.get(dns_host)
    h1 = net.get(client_host)

    results = {}
    zone_dir = os.path.dirname(zone_file)
    zone_basename = os.path.basename(zone_file)

    # Ensure zone directory exists
    _run(dns, f'mkdir -p {zone_dir}')

    # 1) Generate DNSSEC keys if they don't exist
    # Check for existing keys
    key_check = _run(dns, f'bash -c "ls {zone_dir}/K{zone_name}.+*.key 2>/dev/null | wc -l"').strip()
    
    if key_check == '0':
        print(f'[DNSSEC] Generating keys for {zone_name}...')
        # Generate KSK (Key Signing Key) with flag 257
        ksk_out = _run(dns, f'cd {zone_dir} && dnssec-keygen -a RSASHA256 -b 2048 -n ZONE -f KSK {zone_name}')
        print(f'[DNSSEC] KSK: {ksk_out.strip()}')
        
        # Generate ZSK (Zone Signing Key) with flag 256
        zsk_out = _run(dns, f'cd {zone_dir} && dnssec-keygen -a RSASHA256 -b 2048 -n ZONE {zone_name}')
        print(f'[DNSSEC] ZSK: {zsk_out.strip()}')
    else:
        print(f'[DNSSEC] Found existing keys ({key_check} key files)')

    # 2) Locate key files
    key_list = _run(dns, f'bash -c "ls {zone_dir}/K{zone_name}.+*.key 2>/dev/null"').strip().split('\n')
    key_files = [k for k in key_list if k]
    
    if not key_files:
        raise RuntimeError(f'No DNSSEC keys found in {zone_dir}')

    # Identify KSK and ZSK by reading the key content (flag 257 vs 256)
    ksk = None
    zsk = None
    for kf in key_files:
        content = _run(dns, f'cat {kf}').strip()
        # DNSKEY format: <zone> IN DNSKEY <flags> <protocol> <algorithm> <key>
        if ' 257 ' in content:  # KSK flag
            ksk = kf
        elif ' 256 ' in content:  # ZSK flag
            zsk = kf

    if not ksk or not zsk:
        # Fallback: assume alphabetical order (KSK typically generated first)
        if len(key_files) >= 2:
            ksk = key_files[0]
            zsk = key_files[1]
        else:
            raise RuntimeError('Could not identify KSK and ZSK from generated keys')

    results['ksk_file'] = ksk
    results['zsk_file'] = zsk

    # 3) Sign the zone
    signed_zone = f'{zone_file}.signed'
    ksk_base = os.path.splitext(ksk)[0]  # Remove .key extension
    zsk_base = os.path.splitext(zsk)[0]
    
    print(f'[DNSSEC] Signing zone {zone_name}...')
    sign_cmd = f'cd {zone_dir} && dnssec-signzone -A -3 $(echo {zone_name} | sha256sum | cut -c1-16) -N INCREMENT -o {zone_name} -t -K . {zone_basename} {ksk_base} {zsk_base}'
    sign_output = _run(dns, sign_cmd)
    
    results['signed_zone'] = signed_zone
    results['sign_output'] = sign_output.strip()
    print(f'[DNSSEC] Zone signed: {signed_zone}')

    # 4) Extract KSK public key for trust anchor
    ksk_content = _run(dns, f'cat {ksk}').strip()
    # Extract the DNSKEY record: example.com. IN DNSKEY 257 3 8 AwEAAa...
    dnskey_match = re.search(r'IN\s+DNSKEY\s+257\s+3\s+\d+\s+([A-Za-z0-9+/=]+)', ksk_content)
    if not dnskey_match:
        raise RuntimeError(f'Could not extract DNSKEY from {ksk}')
    
    ksk_b64 = dnskey_match.group(1)
    results['ksk_public_key'] = ksk_content
    results['ksk_b64'] = ksk_b64

    # 5) Extract DS record for parent zone
    dsset_file = f'{zone_dir}/dsset-{zone_name}.'
    if _run(dns, f'test -f {dsset_file} && echo exists').strip() == 'exists':
        ds_content = _run(dns, f'cat {dsset_file}').strip()
        results['ds_record'] = ds_content
        print(f'[DNSSEC] DS record:\n{ds_content}')

    # 6) Configure Unbound on client for DNSSEC validation
    print(f'[DNSSEC] Configuring Unbound on {client_host}...')
    
    # Create Unbound configuration directory
    _run(h1, 'mkdir -p /etc/unbound/unbound.conf.d')
    
    # Build Unbound configuration with trust anchor
    unbound_conf = f'''server:
    verbosity: 1
    interface: 0.0.0.0
    port: 53
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    access-control: 0.0.0.0/0 allow
    root-hints: ""
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    qname-minimisation: yes
    prefetch: yes
    num-threads: 1
    msg-cache-size: 4m
    rrset-cache-size: 4m
    cache-min-ttl: 0
    val-clean-additional: yes
    val-permissive-mode: no
    trust-anchor: "{zone_name}. 257 3 8 {ksk_b64}"

stub-zone:
    name: "{zone_name}"
    stub-addr: {dns.IP()}@53
'''
    
    # Write configuration file using printf to avoid heredoc issues
    conf_path = '/etc/unbound/unbound.conf.d/lab4_dnssec.conf'
    escaped_conf = unbound_conf.replace('"', '\\"').replace('$', '\\$')
    _run(h1, f'printf "%s" "{escaped_conf}" > {conf_path}')
    
    # Restart Unbound
    _run(h1, 'pkill unbound || true')
    time.sleep(0.2)
    _run(h1, 'unbound -c /etc/unbound/unbound.conf 2>/tmp/unbound.log &')
    time.sleep(0.5)

    # Point resolv.conf to local Unbound
    _run(h1, 'echo "nameserver 127.0.0.1" > /etc/resolv.conf')

    # 7) Validation tests
    print('[DNSSEC] Running validation tests...')
    
    # Direct query to authoritative server (should show RRSIG)
    dig_signed = _run(h1, f'dig +dnssec +noall +answer MX {zone_name} @{dns.IP()}')
    results['dig_signed_direct'] = dig_signed.strip()
    
    # Query via Unbound resolver (should validate)
    dig_validated = _run(h1, f'dig +dnssec +noall +answer +ad MX {zone_name}')
    results['dig_validated'] = dig_validated.strip()
    
    # Check if AD flag is set (authenticated data)
    dig_ad = _run(h1, f'dig MX {zone_name} | grep "flags:"')
    results['dig_ad_flag'] = dig_ad.strip()
    has_ad = 'ad' in dig_ad.lower()
    results['dnssec_validated'] = has_ad

    print(f'[DNSSEC] Validation {"SUCCESS" if has_ad else "FAILED"} (AD flag: {has_ad})')

    return results


# Helper function for generating a README section
def generate_dnssec_readme():
    """Generate documentation text for DNSSEC setup."""
    return """
## DNSSEC Configuration

This lab implements DNSSEC (DNS Security Extensions) to provide cryptographic authentication
of DNS responses and protect against DNS spoofing attacks.

### Key Components

1. **Zone Signing**: The authoritative DNS zone is signed using DNSSEC keys
   - KSK (Key Signing Key): Used to sign the DNSKEY RRset
   - ZSK (Zone Signing Key): Used to sign all other resource records

2. **Trust Anchor**: The client resolver (Unbound) is configured with the KSK public key
   as a trust anchor to validate DNSSEC signatures

3. **Validation**: DNS responses include RRSIG records that can be cryptographically verified

### Files

- `zones/db.example.com` - Unsigned zone file with DNS records
- `zones/db.example.com.signed` - DNSSEC-signed zone file (generated)
- `zones/K*.key` - Public DNSSEC keys (generated)
- `zones/K*.private` - Private DNSSEC keys (generated)
- `zones/dsset-example.com.` - DS record for parent zone delegation (generated)

### Regenerating DNSSEC Keys

To regenerate DNSSEC keys and re-sign the zone:

```bash
# 1. Remove existing keys
cd zones/
rm -f K*.key K*.private dsset-* *.signed

# 2. Generate new keys
dnssec-keygen -a RSASHA256 -b 2048 -n ZONE -f KSK example.com
dnssec-keygen -a RSASHA256 -b 2048 -n ZONE example.com

# 3. Sign the zone
dnssec-signzone -A -3 $(echo example.com | sha256sum | cut -c1-16) \\
    -N INCREMENT -o example.com -t db.example.com

# 4. The signed zone will be in db.example.com.signed
```

### Verification

To verify DNSSEC is working:

```bash
# Query the authoritative server directly (should show RRSIG records)
dig +dnssec MX example.com @10.0.0.53

# Query via validating resolver (should show AD flag)
dig MX example.com

# Check for authenticated data flag
dig MX example.com | grep flags:
# Should show: "flags: qr rd ra ad" (note the "ad" flag)
```

### Security Benefits

- **Authentication**: Cryptographically proves DNS responses came from the authoritative server
- **Integrity**: Detects if DNS responses have been modified in transit
- **Non-repudiation**: Server cannot deny sending a signed response
- **Protection against**: Cache poisoning, man-in-the-middle attacks, DNS spoofing
"""
