# Artifacts Directory

This directory contains the most recent test artifacts from the automated test suite.

## Structure

```
artifacts/
├── logs/              # Latest log files from DNS and SMTP servers
├── pcap/              # Latest packet capture files
└── reports/           # Latest comparison reports
```

## Contents

After running `tests/run_all_tests.sh`, this directory will contain:

### logs/
- `named_dns.log` - DNS server logs from the legitimate server
- `named_att.log` - DNS server logs from the attacker server
- `mx_smtp.log` - SMTP server logs from the legitimate mail server
- `att_smtp.log` - SMTP server logs from the attacker's mail server
- `opendkim.log` - DKIM signing/verification logs (if protections enabled)

### pcap/
- `baseline_dns.pcap` - DNS traffic capture (port 53)
- `baseline_smtp.pcap` - SMTP traffic capture (port 25)
- `baseline_h1_all.pcap` - Complete traffic capture
- `protected_*.pcap` - Corresponding captures with protections enabled

### reports/
- `comparison_report.txt` - Summary report comparing baseline vs protected tests

## Viewing Artifacts

### View the latest report
```bash
cat artifacts/reports/comparison_report.txt
```

### Analyze packet captures
```bash
# Using tcpdump
tcpdump -r artifacts/pcap/baseline_dns.pcap -nn

# Using Wireshark (if available)
wireshark artifacts/pcap/baseline_dns.pcap
```

### Check server logs
```bash
# View DNS logs
cat artifacts/logs/named_dns.log

# Search for SPF/DKIM results
grep -i "spf\|dkim" artifacts/logs/*.log
```

## Full Results

For complete timestamped results from all test runs, see the `results/` directory in the project root:

```
results/
├── 20241106_143022/    # Example timestamped run
│   ├── baseline/
│   ├── protected/
│   └── comparison_report.txt
└── 20241106_150433/    # Another run
    ├── baseline/
    ├── protected/
    └── comparison_report.txt
```

Each test run creates a new timestamped directory to preserve historical data.

## Note

The `.gitkeep` files in subdirectories are placeholders to maintain the directory structure in git. They can be safely ignored.

Actual artifact files are excluded from git via `.gitignore` to avoid committing large binary files and test outputs.
