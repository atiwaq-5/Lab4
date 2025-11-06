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

```bash
cd lab4_submission_ready_spf_dmarc
sudo python3 lab4_topo_v6e.py

# In the Mininet CLI:
source mn_quickcheck_v6.cli      # interactive (prompts for screenshots)
# or:
source mn_run_tests4.cli         # non-interactive summary
```

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

`zones/db.example.com.good` includes **SPF** and **DMARC**:

```zone
@       IN TXT   "v=spf1 a mx -all"
_dmarc  IN TXT   "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com"
```

The attacker zone intentionally points MX to `att.example.com` on `10.0.0.66`.

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

## Notes on DKIM

For DKIM support (optional enhancement):
- Run `opendkim` on `mx` host
- Publish DKIM selector TXT record in zone
- Sign outgoing mail and verify signatures

These are heavier changes; the current implementation focuses on DNSSEC and SPF/DMARC.

## Notes on the full assignment (DNSSEC/DKIM)

This bundle focuses on the base requirements + SPF/DMARC TXT presence and a complete forged‑MX attack demo. To go for A/A+ with **DNSSEC** and **DKIM**, add:
- DNSSEC: enable inline‑signing on `dns`, generate keys, sign `example.com`, and verify with `dig +dnssec` (AD bit).  
- DKIM: run `opendkim` on `mx`, publish the selector TXT, sign mail, and verify signatures.

These are heavier changes; the current quick‑check keeps them optional so you don’t destabilize the working demo.

## Troubleshooting

- If `dig` shows *connection refused*, ensure you run from this folder and that `bind9`, `dnsutils`, `swaks` are installed.
- The scripts kill any stale `named` on start, but if you manually started one, stop it first.
- All paths are **relative**; run Mininet from this directory.
