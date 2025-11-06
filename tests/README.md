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
- **`README.md`** - This file

## Prerequisites

Ensure the following packages are installed on your Mininet VM:

```bash
sudo apt-get update
sudo apt-get install -y bind9 dnsutils swaks python3 tcpdump
```

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
