# DNS Spoofing/Poisoning Attack Demonstration

This directory contains tools and scripts for demonstrating DNS spoofing/poisoning attacks in the Lab 4 environment.

## Overview

The demonstration shows how an attacker can forge DNS responses to redirect email traffic to their own server, bypassing the legitimate mail server. It also demonstrates how DNSSEC protection can prevent such attacks.

## Files

### `dns_spoof_demo.cli`
Mininet CLI script that runs the complete DNS spoofing demonstration.

**Usage:**
```bash
# Start Mininet with the lab topology
sudo python3 lab4_topo_v6e.py

# In the Mininet CLI, run the demo:
mininet> source tests/dns_spoof_demo.cli
```

The demo will:
1. Start packet capture
2. Establish a baseline with legitimate DNS
3. Launch the DNS spoofing attack
4. Show email being intercepted by the attacker
5. Compare with DNSSEC protection

### `dns_spoof_demo_helper.py`
Python helper module that implements the DNS spoofing demonstration logic.

Can be imported and used programmatically:
```python
from tests.dns_spoof_demo_helper import run_dns_spoof_demo

# In Mininet environment
run_dns_spoof_demo(net, interactive=True)
```

### `capture_and_compare.sh`
Standalone script for capturing network traffic and generating comparison reports.

**Usage:**
```bash
# Capture baseline traffic
./tests/capture_and_compare.sh baseline

# Capture attack traffic
./tests/capture_and_compare.sh attack

# Capture with DNSSEC
./tests/capture_and_compare.sh dnssec

# Generate comparison report (after capturing multiple scenarios)
./tests/capture_and_compare.sh attack
```

**Options:**
- `CAPTURE_DURATION`: Duration of capture in seconds (default: 30)
- `INTERFACE`: Network interface to capture on (default: any)
- `OUTPUT_DIR`: Output directory for capture files (default: /tmp/dns_spoof_evidence)

**Example:**
```bash
CAPTURE_DURATION=60 OUTPUT_DIR=/tmp/evidence ./tests/capture_and_compare.sh attack
```

## Demonstration Flow

### Phase 1: Setup and Baseline
- Start packet capture on client host
- Start SMTP sinks on both legitimate and attacker hosts
- Configure client to use legitimate DNS server
- Verify normal email delivery

### Phase 2: DNS Spoofing Attack
- Start DNS spoofer on attacker host (using `../tools/spoof_mx.py`)
- Reconfigure client to use attacker's DNS server
- Query MX records - now resolve to attacker's IP
- Send email - intercepted by attacker

### Phase 3: Evidence Collection
- Stop packet capture
- Analyze DNS queries and responses
- Review SMTP logs showing intercepted email
- Generate evidence reports

### Phase 4: DNSSEC Protection
- Demonstrates how DNSSEC would prevent the attack
- Shows that forged responses would be rejected
- Explains validation process

## Expected Results

### Without Protection (Attack Successful)
```
MX query for example.com → att.example.com (10.0.0.66)
Email to victim@example.com → delivered to attacker at 10.0.0.66
Attacker log shows: "Received email from boss@bank.com"
```

### With DNSSEC (Attack Prevented)
```
MX query with DNSSEC validation → forged response rejected
Email delivery → fails or falls back to legitimate server
DNSSEC status → BOGUS or validation failure
```

## Evidence Files

After running the demonstration, the following evidence files are created:

- `/tmp/dns_spoof_attack.pcap` - Full packet capture
- `/tmp/dns_spoofer.log` - Attacker's DNS spoofer log
- `/tmp/att_smtp.log` - Attacker's captured emails
- `/tmp/mx_smtp.log` - Legitimate mail server log
- `/tmp/dns_spoof_evidence/` - Comparison reports and analysis

## Analyzing Evidence

### View DNS Traffic
```bash
# On h1 host in Mininet
h1 tcpdump -r /tmp/dns_spoof_attack.pcap -n 'udp port 53'
```

### View SMTP Traffic
```bash
# On h1 host in Mininet
h1 tcpdump -r /tmp/dns_spoof_attack.pcap -n 'tcp port 25'
```

### Review Captured Emails
```bash
# On att host in Mininet
att tail -50 /tmp/att_smtp.log

# On mx host in Mininet
mx tail -50 /tmp/mx_smtp.log
```

## Integration with Existing Tests

This demonstration complements the existing quick check scripts:

- `mn_quickcheck_v6.cli` - Basic DNS and SMTP tests
- `mn_run_tests4.cli` - Non-interactive test suite
- `mn_quickcheck_v6_with_dnssec.py` - DNSSEC-enabled tests

The DNS spoofing demo can be run before or after these tests to show the attack and defense mechanisms.

## Security Notes

⚠️ **Educational Purpose Only**

This demonstration is for educational purposes in a controlled lab environment. DNS spoofing is illegal in production networks and should never be used maliciously.

The attack demonstrates:
- Why DNSSEC is important for DNS integrity
- How email authentication (SPF/DKIM/DMARC) provides additional protection
- The importance of end-to-end encryption (TLS) for email

## Troubleshooting

### DNS Spoofer Not Starting
```bash
# Check if port 53 is in use
att ss -ulnp | grep :53

# Kill existing DNS servers
att pkill -9 named
att pkill -9 -f spoof_mx.py
```

### No Packets Captured
```bash
# Check tcpdump is running
h1 pgrep tcpdump

# Verify interface
h1 ip link show

# Check permissions
ls -la /tmp/dns_spoof_attack.pcap
```

### Email Not Delivered
```bash
# Check SMTP servers are listening
att ss -ltnp | grep :25
mx ss -ltnp | grep :25

# Verify DNS resolution
h1 dig example.com MX +short

# Check resolv.conf
h1 cat /etc/resolv.conf
```

## References

- [RFC 4033](https://tools.ietf.org/html/rfc4033) - DNS Security Introduction
- [RFC 7208](https://tools.ietf.org/html/rfc7208) - SPF for Email Authentication
- [RFC 6376](https://tools.ietf.org/html/rfc6376) - DKIM Signatures
- [RFC 7489](https://tools.ietf.org/html/rfc7489) - DMARC
