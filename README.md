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

`zones/db.example.com.good` includes **SPF** and **DMARC**:

```zone
@       IN TXT   "v=spf1 a mx -all"
_dmarc  IN TXT   "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com"
```

The attacker zone intentionally points MX to `att.example.com` on `10.0.0.66`.

## Notes on the full assignment (DNSSEC/DKIM)

This bundle focuses on the base requirements + SPF/DMARC TXT presence and a complete forged‑MX attack demo. To go for A/A+ with **DNSSEC** and **DKIM**, add:
- DNSSEC: enable inline‑signing on `dns`, generate keys, sign `example.com`, and verify with `dig +dnssec` (AD bit).  
- DKIM: run `opendkim` on `mx`, publish the selector TXT, sign mail, and verify signatures.

These are heavier changes; the current quick‑check keeps them optional so you don’t destabilize the working demo.

## Troubleshooting

- If `dig` shows *connection refused*, ensure you run from this folder and that `bind9`, `dnsutils`, `swaks` are installed.
- The scripts kill any stale `named` on start, but if you manually started one, stop it first.
- All paths are **relative**; run Mininet from this directory.
