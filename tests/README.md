# Lab 4 Test Suite

This directory contains tools and scripts for testing and demonstrating various security features in the Lab 4 environment.

## Test Categories

1. **SPF/DMARC Policy Enforcement Tests** - Validates email authentication mechanisms
2. **DNS Spoofing/Poisoning Attack Demonstration** - Shows DNS-based attacks and protections
3. **Automated Test Harness** - Comprehensive testing framework with logging

---

## SPF/DMARC Tests

### test_spf_dmarc.sh

This script validates the SPF and DMARC configuration for `example.com` and simulates unauthorized sender scenarios.

#### What it tests:

1. **SPF Record Presence and Content**
   - Verifies SPF record exists
   - Confirms it authorizes the MX host IP (10.0.0.25)
   - Checks for hard fail policy (-all)

2. **DMARC Record Presence and Policy**
   - Verifies DMARC record exists at `_dmarc.example.com`
   - Confirms enforcement policy (quarantine or reject)
   - Checks reporting configuration (rua/ruf)

3. **Unauthorized Sender Detection**
   - Simulates an attacker at 10.0.0.66 sending mail claiming to be from example.com
   - Verifies the attacker IP is NOT authorized in SPF
   - Documents expected SPF failure and DMARC policy application

4. **DMARC Policy Application Logic**
   - Validates that DMARC policy would be enforced on SPF failures
   - Documents expected behavior (reject, quarantine, or none)

5. **MX Record Validation**
   - Confirms MX record points to the authorized mail server

#### Running the SPF/DMARC tests:

From within Mininet topology:

```bash
# Start the topology
sudo python3 lab4_topo_v6e.py

# In Mininet CLI, on the dns host:
dns named -4 -u bind -g -c /etc/bind/named.conf &

# On h1 or any host with DNS access:
h1 bash tests/test_spf_dmarc.sh
```

Or standalone (if DNS is running):

```bash
./tests/test_spf_dmarc.sh
```

#### Expected Output:

The script will output color-coded test results:
- ✓ PASS (green) - Test passed
- ✗ FAIL (red) - Test failed
- ℹ INFO (yellow) - Informational message

At the end, it provides a summary of passed/failed tests and exits with:
- Exit code 0 if all tests pass
- Exit code 1 if any test fails

---

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
# Lab 4 Automated Test Suite

This directory contains automated tests for comparing traffic and logs before and after enabling DNS and email security protections (DNSSEC, SPF, DKIM, DMARC).

## Overview

The test suite provides a reproducible, automated way to:

1. Boot the Mininet topology with DNS and SMTP servers
2. Run baseline tests (before enabling protections) and collect logs/pcap
3. Enable security protections (DNSSEC/SPF/DKIM/DMARC)
4. Re-run tests with protections enabled
5. Generate a comparison report and store artifacts

## Files

- **`run_all_tests.sh`** - Main test orchestrator that executes the complete test cycle
- **`collect_logs.sh`** - Utility script for collecting logs, pcaps, and test outputs
- **`verify_environment.sh`** - Environment verification script to check dependencies
- **`README.md`** - This file

## Prerequisites

Ensure the following packages are installed on your Mininet VM:

```bash
sudo apt-get update
sudo apt-get install -y bind9 dnsutils swaks python3 tcpdump
```

### Verify Environment

Before running tests, verify your environment has all required dependencies:

```bash
cd /path/to/Lab4
./tests/verify_environment.sh
```

This will check for all required tools and Python modules.

## Usage

### Quick Start

Run the complete test suite:

```bash
cd /path/to/Lab4
sudo ./tests/run_all_tests.sh
```

This will:
- Create a timestamped results directory under `results/YYYYMMDD_HHMMSS/`
- Run baseline tests without protections
- Enable protections (marker for DNSSEC/DKIM setup)
- Run tests with protections enabled
- Generate a comparison report
- Copy latest results to `artifacts/` for easy access

### Manual Log Collection

To collect logs separately (for example, after running manual tests):

```bash
# Collect baseline logs
sudo ./tests/collect_logs.sh baseline results/my_test_run

# Collect protected logs
sudo ./tests/collect_logs.sh protected results/my_test_run
```

## Output Structure

### Results Directory

Each test run creates a timestamped directory:

```
results/YYYYMMDD_HHMMSS/
├── baseline/
│   ├── logs/
│   │   ├── named_dns.log       # DNS server logs (good)
│   │   ├── named_att.log       # DNS server logs (attacker)
│   │   ├── mx_smtp.log         # SMTP server logs (legitimate)
│   │   └── att_smtp.log        # SMTP server logs (attacker)
│   ├── pcap/
│   │   ├── baseline_dns.pcap   # DNS traffic capture
│   │   ├── baseline_smtp.pcap  # SMTP traffic capture
│   │   └── baseline_h1_all.pcap # Complete traffic
│   ├── dig_outputs/
│   │   ├── dig_baseline_mx_good.txt
│   │   ├── dig_baseline_spf.txt
│   │   └── dig_baseline_dmarc.txt
│   └── swaks_outputs/
│       ├── swaks_baseline_authorized.txt
│       ├── swaks_baseline_unauthorized.txt
│       └── swaks_baseline_attacker.txt
├── protected/
│   ├── logs/
│   ├── pcap/
│   ├── dig_outputs/
│   └── swaks_outputs/
├── comparison_report.txt       # Summary report
└── protections_enabled.txt     # Protection configuration marker
```

### Artifacts Directory

Latest results are copied to `artifacts/` for quick access:

```
artifacts/
├── logs/          # Latest log files
├── pcap/          # Latest packet captures
└── reports/       # Latest comparison report
```

## Tests Performed

### DNS Resolution Tests

1. **MX Record Lookup**: `dig MX example.com`
2. **A Record Lookup**: `dig A mail.example.com`
3. **SPF Record**: `dig TXT example.com` (should contain `v=spf1`)
4. **DMARC Record**: `dig TXT _dmarc.example.com` (should contain `v=DMARC1`)
5. **DNSSEC Validation**: `dig +dnssec MX example.com` (checks for AD bit)
6. **Attacker DNS**: Resolution through forged DNS server

### SMTP Delivery Tests

1. **Authorized Sender**: Send from `admin@example.com` (should pass SPF)
2. **Unauthorized Sender**: Send from `fake@evil.com` (should fail SPF)
3. **Forged Mail**: Send via attacker's MX server

### Traffic Captures

1. **DNS Traffic**: tcpdump on port 53
2. **SMTP Traffic**: tcpdump on port 25
3. **Complete Capture**: All traffic on h1 interface

## Analyzing Results

### View the Comparison Report

```bash
cat results/YYYYMMDD_HHMMSS/comparison_report.txt
# or
cat artifacts/reports/comparison_report.txt
```

### Compare DNS Responses

```bash
# Compare baseline vs protected DNS outputs
diff results/YYYYMMDD_HHMMSS/baseline/dig_outputs/ \
     results/YYYYMMDD_HHMMSS/protected/dig_outputs/
```

### Compare SMTP Behavior

```bash
# Compare baseline vs protected SMTP outputs
diff results/YYYYMMDD_HHMMSS/baseline/swaks_outputs/ \
     results/YYYYMMDD_HHMMSS/protected/swaks_outputs/
```

### Analyze Packet Captures

```bash
# View DNS traffic
wireshark results/YYYYMMDD_HHMMSS/baseline/pcap/baseline_dns.pcap
wireshark results/YYYYMMDD_HHMMSS/protected/pcap/protected_dns.pcap

# View SMTP traffic
wireshark results/YYYYMMDD_HHMMSS/baseline/pcap/baseline_smtp.pcap
wireshark results/YYYYMMDD_HHMMSS/protected/pcap/protected_smtp.pcap
```

Or use tcpdump to analyze:

```bash
# Show DNS queries
tcpdump -r results/YYYYMMDD_HHMMSS/baseline/pcap/baseline_dns.pcap -nn

# Show SMTP connections
tcpdump -r results/YYYYMMDD_HHMMSS/baseline/pcap/baseline_smtp.pcap -nn -A
```

### Review Server Logs

```bash
# Check DNS server logs
cat results/YYYYMMDD_HHMMSS/baseline/logs/named_dns.log

# Check SMTP logs for SPF/DKIM results
cat results/YYYYMMDD_HHMMSS/protected/logs/mx_smtp.log
grep -i "spf\|dkim" results/YYYYMMDD_HHMMSS/protected/logs/*.log
```

## Expected Differences

### Baseline (No Protections)

- DNS responses have no DNSSEC AD (Authenticated Data) bit
- No SPF checks in SMTP logs
- No DKIM signatures in email headers
- Attacker's forged mail is accepted without validation

### Protected (With Protections)

- DNS responses include DNSSEC AD bit (when properly configured)
- SPF checks appear in logs (pass/fail based on sender)
- DKIM signatures in email headers
- Unauthorized mail rejected or quarantined based on SPF/DMARC policy
- Attacker's forged mail fails authentication

## Customization

### Adding Custom Tests

Edit `run_all_tests.sh` and add test functions in the embedded Python script:

```python
def my_custom_test(net, results_dir):
    h1 = net.get('h1')
    # Your test code here
    pass
```

Then call it in the `main()` function.

### Adjusting Test Parameters

Modify the IP addresses, domain names, or test scenarios in the `run_all_tests.sh` script:

```python
dns_ip = "10.0.0.53"
att_ip = "10.0.0.66"
mx_ip  = "10.0.0.25"
```

## Troubleshooting

### Tests fail with "permission denied"

Run with sudo:
```bash
sudo ./tests/run_all_tests.sh
```

### BIND fails to start

Check if bind9 is installed:
```bash
sudo apt-get install -y bind9
```

### tcpdump not found

Install tcpdump:
```bash
sudo apt-get install -y tcpdump
```

### No packet captures

Ensure tcpdump has permissions and the interface name is correct. Check with:
```bash
ip link show
```

### Logs are empty

Check that services started properly:
```bash
ps aux | grep named
ps aux | grep smtpd
ss -ltnp | grep ':53\|:25'
```

## Integration with Existing Tests

This automated test suite complements the existing manual quick-check scripts:

- `mn_quickcheck_v6.cli` - Interactive manual tests with screenshot prompts
- `mn_run_tests4.cli` - Non-interactive manual test summary
- `tests/run_all_tests.sh` - **New**: Automated pre/post comparison

Use the automated suite for:
- Reproducible testing across iterations
- Before/after comparison data
- CI/CD integration
- Generating deliverable artifacts

Use the manual scripts for:
- Interactive demos
- Screenshot collection for reports
- Quick verification during development

## Notes

- The test harness creates a fresh Mininet topology for each run
- All tests run in an isolated network environment
- Results are timestamped to prevent overwriting previous runs
- The `artifacts/` directory always contains the most recent test results
- For full DNSSEC and DKIM functionality, the `enable_protections()` function would need to be fully implemented with actual key generation and signing

## License

This test suite is part of the Lab 4 assignment and follows the same license as the main project.
