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
sudo apt-get install -y bind9 dnsutils swaks python3
```

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

The repository includes three zone files:
- `zones/db.example.com` - Primary zone file with explicit SPF and DMARC records
- `zones/db.example.com.good` - Alternative good zone (legacy)
- `zones/db.example.com.att` - Attacker zone for forged MX demonstration

The primary zone `zones/db.example.com` includes **SPF** and **DMARC**:

```zone
@       IN TXT   "v=spf1 ip4:10.0.0.25/32 -all"
_dmarc  IN TXT   "v=DMARC1; p=quarantine; rua=mailto:postmaster@example.com; ruf=mailto:postmaster@example.com; pct=100"
```

**Key features:**
- **SPF**: Explicitly authorizes only the MX IP (10.0.0.25/32) with hard fail (-all) for all others
- **DMARC**: Enforces quarantine policy on authentication failures, with both aggregate (rua) and forensic (ruf) reporting

The attacker zone intentionally points MX to `att.example.com` on `10.0.0.66`.

## Automated SPF/DMARC Tests

The `tests/` directory contains automated validation scripts:

### Running the tests

After starting the Mininet topology and DNS servers:

```bash
# From Mininet CLI, set up DNS on the good server first
dns pkill -9 named || true
dns mkdir -p /var/cache/bind/zones
dns cp zones/db.example.com /var/cache/bind/zones/db.example.com
dns named -4 -u bind -g -c /etc/bind/named.conf &

# Run the automated SPF/DMARC tests from h1
h1 bash tests/test_spf_dmarc.sh
```

### What the tests validate

1. **SPF Record Presence**: Confirms SPF TXT record exists and authorizes MX IP
2. **DMARC Record Presence**: Verifies DMARC policy is set to quarantine/reject
3. **Unauthorized Sender Detection**: Simulates attacker from 10.0.0.66 and validates SPF would fail
4. **DMARC Policy Application**: Confirms enforcement policy is properly configured
5. **MX Record Validation**: Ensures MX points to the authorized mail server

See `tests/README.md` for detailed documentation on the test suite.

## Notes on the full assignment (DNSSEC/DKIM)

This bundle focuses on the base requirements + SPF/DMARC TXT presence and a complete forged‑MX attack demo. To go for A/A+ with **DNSSEC** and **DKIM**, add:
- DNSSEC: enable inline‑signing on `dns`, generate keys, sign `example.com`, and verify with `dig +dnssec` (AD bit).  
- DKIM: run `opendkim` on `mx`, publish the selector TXT, sign mail, and verify signatures.

These are heavier changes; the current quick‑check keeps them optional so you don’t destabilize the working demo.

## Troubleshooting

- If `dig` shows *connection refused*, ensure you run from this folder and that `bind9`, `dnsutils`, `swaks` are installed.
- The scripts kill any stale `named` on start, but if you manually started one, stop it first.
- All paths are **relative**; run Mininet from this directory.
