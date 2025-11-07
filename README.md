# Lab 4 — Secure E‑Mail and DNS (Authoritative DNS + Forged MX + SPF/DMARC)

This package contains a minimal, **working** Mininet demo that:
- brings up a 4‑host topology (`h1`, `dns`, `mx`, `att`),
- serves **authoritative DNS** for `example.com` on `dns` (good path),
- simulates an **attacker DNS** and **forged MX** on `att`,
- runs SMTP sinks on `mx` and `att` to capture messages,
- adds **SPF** and **DMARC** TXT records on the good zone,
- provides an interactive quick‑check that pauses for screenshots (grader‑friendly).

## Requirements

On a clean Mininet VM:
```bash
sudo apt-get update
sudo apt-get install -y bind9 bind9utils dnsutils swaks python3 unbound
```

**Note**: `bind9utils` provides DNSSEC tools (`dnssec-keygen`, `dnssec-signzone`), and `unbound` is needed for DNSSEC validation.

## How to run

### Manual Interactive Tests

```bash
cd lab4_submission_ready_spf_dmarc
sudo python3 lab4_topo_v6e.py

# In the Mininet CLI:
source mn_quickcheck_v6.cli      # interactive (prompts for screenshots)
# or:
source mn_run_tests4.cli         # non-interactive summary
# or:
source tests/dns_spoof_demo.cli  # DNS spoofing attack demonstration
```

### Automated Test Suite (New!)

For automated pre/post-protection comparison with log collection:

```bash
cd /path/to/Lab4

# Verify environment first
./tests/verify_environment.sh

# Run complete test suite
sudo ./tests/run_all_tests.sh
```

See [`tests/README.md`](tests/README.md) for detailed documentation on the automated test harness.

## What the quick check does

1. **Connectivity pings** from `h1` → `dns/att/mx`.  
   ➤ Take a screenshot when prompted.

2. **GOOD DNS on `dns`** (authoritative for `example.com`): installs minimal `named` configs, loads zone from `zones/db.example.com.good`, and starts `named` on `10.0.0.53:53`.  
   ➤ Screenshot of `:53` listening and `tail /tmp/named.log`.

3. **ATTACKER DNS on `att`** (authoritative with forged MX): loads `zones/db.example.com.att`, starts `named` on `10.0.0.66:53`.  
   ➤ Screenshot of `:53` listening and `tail /tmp/named.log`.

4. **GOOD path lookups** (`h1` resolver → `dns`): shows `MX` and `A` answers, plus **SPF** (`TXT @`) and **DMARC** (`TXT _dmarc`) checks. Then a baseline SMTP handshake to real MX (`10.0.0.25`).  
   ➤ Screenshot with the four `dig` results + the baseline `swaks` handshake.

5. **Forged path** (`h1` resolver → `att`): resolves attacker MX to `10.0.0.66`, sends mail to attacker SMTP sink, and prints the captured message.  
   ➤ Screenshot with the forged `dig` + `swaks` output + attacker log tail.

6. **Summary**: prints OK/FAIL for each requirement.

## Zone records

`zones/db.example.com.good` includes **SPF**, **DMARC**, and **DKIM**:

```zone
@              IN TXT   "v=spf1 a mx -all"
_dmarc         IN TXT   "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com"
s1._domainkey  IN TXT   "v=DKIM1; k=rsa; p=<public-key>"
```

The attacker zone intentionally points MX to `att.example.com` on `10.0.0.66`.

## DKIM Implementation

This package now includes **DKIM signing** support:
- **OpenDKIM** is automatically configured on the `mx` host with selector `s1`
- **Postfix** is configured to use OpenDKIM as a milter on port 8891
- The DKIM public key is published in the DNS zone as `s1._domainkey.example.com`
- Use `tools/generate_dkim_keys.sh` to regenerate keys if needed
- The quick-check includes DKIM TXT record verification and signing tests

## DNSSEC Support

This lab now includes **full DNSSEC support** with automated zone signing and validation.

### Running with DNSSEC

To run the lab with DNSSEC enabled:

```bash
sudo python3 mn_quickcheck_v6_with_dnssec.py
```

This script will:
1. Generate DNSSEC keys (KSK and ZSK) for `example.com`
2. Sign the zone file automatically
3. Configure Unbound on `h1` with the trust anchor
4. Validate DNS responses cryptographically

### Zone Files

- **`zones/db.example.com`** - Main zone file with DNS records (A, MX, SPF, DMARC)
- **`zones/db.example.com.good`** - Alternative good zone file
- **`zones/db.example.com.att`** - Attacker's forged zone file

The main zone file includes:
```zone
dns IN A 10.0.0.53          # Authoritative DNS server
mx  IN A 10.0.0.25          # Mail server
@   IN MX 10 mx.example.com.
@   IN TXT "v=spf1 a mx -all"
_dmarc IN TXT "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com"
```

### DNSSEC Key Generation and Zone Signing

The DNSSEC setup is automated by `mn_quickcheck_v6_dnssec_patch_v2.py`. Keys and signatures are generated at runtime.

To manually regenerate DNSSEC keys:

```bash
cd zones/

# Clean old keys
rm -f K*.key K*.private dsset-* *.signed

# Generate KSK (Key Signing Key)
dnssec-keygen -a RSASHA256 -b 2048 -n ZONE -f KSK example.com

# Generate ZSK (Zone Signing Key)
dnssec-keygen -a RSASHA256 -b 2048 -n ZONE example.com

# Sign the zone
dnssec-signzone -A -3 $(echo example.com | sha256sum | cut -c1-16) \
    -N INCREMENT -o example.com -t db.example.com
```

This produces:
- `K*.key` and `K*.private` - DNSSEC key pairs
- `db.example.com.signed` - Signed zone file with RRSIG records
- `dsset-example.com.` - DS record for parent zone delegation

### DNSSEC Verification

Verify DNSSEC is working:

```bash
# From h1 in Mininet:

# Query authoritative server (should show RRSIG records)
dig +dnssec MX example.com @10.0.0.53

# Query via validating resolver (should show AD flag)
dig MX example.com

# Check the AD (authenticated data) flag
dig MX example.com | grep flags:
# Expected: "flags: qr rd ra ad" (note the "ad" flag indicating validation)
```

### DNSSEC Security Benefits

- **Authentication**: Cryptographically proves responses are from the authoritative server
- **Integrity**: Detects tampering with DNS responses
- **Protection**: Guards against cache poisoning, MITM attacks, and DNS spoofing

## Notes on Advanced Features

For additional enhancements:
- See `mn_quickcheck_v6_dnssec_patch.py` for helper functions
- DKIM tools are available in `tools/generate_dkim_keys.sh`
- Automated testing suite in `tests/` directory

This package now includes **DKIM signing** support:
- **OpenDKIM** is automatically configured on the `mx` host with selector `s1`
- **Postfix** is configured to use OpenDKIM as a milter on port 8891
- The DKIM public key is published in the DNS zone as `s1._domainkey.example.com`
- Use `tools/generate_dkim_keys.sh` to regenerate keys if needed
- The quick-check includes DKIM TXT record verification and signing tests

## Notes on DNSSEC

For A/A+ grading with **DNSSEC**:
- Enable inline‑signing on `dns`, generate keys, sign `example.com`, and verify with `dig +dnssec` (AD bit)
- See `mn_quickcheck_v6_dnssec_patch.py` for helper functions
## Troubleshooting

- If `dig` shows *connection refused*, ensure you run from this folder and that `bind9`, `dnsutils`, `swaks` are installed.
- The scripts kill any stale `named` on start, but if you manually started one, stop it first.
- All paths are **relative**; run Mininet from this directory.

## New: DNS Spoofing/Poisoning Demonstration

This lab now includes a complete DNS spoofing attack demonstration with the following components:

### Tools (`tools/`)
- **`spoof_mx.py`**: Lightweight UDP DNS responder that returns forged MX records
  - Listens on UDP port 53
  - Responds to MX queries with attacker's IP address
  - Configurable domain and IP settings

### Tests (`tests/`)
- **`dns_spoof_demo.cli`**: Mininet CLI script to run the full attack demonstration
- **`dns_spoof_demo_helper.py`**: Python helper module implementing the demo logic
- **`capture_and_compare.sh`**: Evidence capture script using tcpdump
- **`README.md`**: Detailed documentation for the demonstration

### Running the DNS Spoofing Demo

```bash
# Start Mininet
sudo python3 lab4_topo_v6e.py

# In the Mininet CLI, run the demo:
mininet> source tests/dns_spoof_demo.cli
```

The demonstration shows:
1. **Baseline**: Normal DNS resolution with legitimate mail server
2. **Attack**: DNS spoofing causing email to be delivered to attacker
3. **Evidence**: Packet captures and logs proving the attack
4. **Protection**: How DNSSEC would prevent the attack

### Evidence Files Created
- `/tmp/dns_spoof_attack.pcap` - Full packet capture
- `/tmp/dns_spoofer.log` - Attacker's DNS spoofer log  
- `/tmp/att_smtp.log` - Attacker's captured emails
- `/tmp/mx_smtp.log` - Legitimate mail server log

### Manual Testing with spoof_mx.py

```bash
# In Mininet, on the attacker host:
att python3 tools/spoof_mx.py --domain example.com --attacker-ip 10.0.0.66 &

# On the client host:
h1 dig @10.0.0.66 example.com MX +short
# Should return: 10 att.example.com.
#                10.0.0.66
```

See `tests/README.md` and `tools/README.md` for complete documentation.
## Automated Testing and Artifacts

This repository now includes an automated test harness for comparing traffic and logs before and after enabling protections.

### Quick Start

```bash
# Verify your environment
./tests/verify_environment.sh

# Run automated tests
sudo ./tests/run_all_tests.sh
```

### What Gets Tested

The automated suite:
1. **Boots the Mininet topology** automatically
2. **Runs baseline tests** (DNS resolution, SMTP delivery) and captures:
   - DNS queries and responses (dig outputs)
   - SMTP transactions (swaks outputs)
   - Packet captures (tcpdump on ports 53 and 25)
   - Server logs (named, SMTP)
3. **Enables protections** (DNSSEC/SPF/DKIM/DMARC markers)
4. **Re-runs all tests** with protections enabled
5. **Generates a comparison report** showing differences

### Output Structure

- **`results/YYYYMMDD_HHMMSS/`** - Timestamped full results for each run
  - `baseline/` - Tests without protections
  - `protected/` - Tests with protections
  - `comparison_report.txt` - Summary report
- **`artifacts/`** - Latest test artifacts (logs, pcaps, reports)

### Documentation

- See **[`tests/README.md`](tests/README.md)** for complete documentation
- See **[`artifacts/README.md`](artifacts/README.md)** for artifact structure

### Benefits

- **Reproducible**: Same tests run consistently
- **Automated**: No manual intervention needed
- **Comparison**: Easy before/after analysis
- **Deliverable**: Generates artifacts for submission
