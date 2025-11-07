# Lab 4 Automated Testing - Quick Reference

## One-Command Test Run

```bash
sudo ./tests/run_all_tests.sh
```

## What It Does

1. ✓ Boots Mininet topology (h1, dns, att, mx)
2. ✓ Runs **baseline tests** (no protections):
   - DNS queries (MX, A, SPF, DMARC, DNSSEC check)
   - SMTP tests (authorized, unauthorized, forged)
   - Packet captures (DNS port 53, SMTP port 25)
3. ✓ Enables protections (marker)
4. ✓ Runs **protected tests** (same tests with protections)
5. ✓ Generates comparison report
6. ✓ Saves artifacts to timestamped directory

## Output Locations

- **Full results**: `results/YYYYMMDD_HHMMSS/`
- **Quick access**: `artifacts/` (latest only)
- **Report**: `artifacts/reports/comparison_report.txt`

## View Results

```bash
# View comparison report
cat artifacts/reports/comparison_report.txt

# Browse all artifacts
ls -R results/$(ls -t results/ | head -1)/

# Analyze DNS traffic
tcpdump -r artifacts/pcap/baseline_dns.pcap -nn | head -20

# Check server logs
cat artifacts/logs/named_dns.log
```

## Compare Baseline vs Protected

```bash
LATEST=$(ls -t results/ | head -1)

# Compare DNS outputs
diff results/$LATEST/baseline/dig_outputs/ \
     results/$LATEST/protected/dig_outputs/

# Compare SMTP outputs
diff results/$LATEST/baseline/swaks_outputs/ \
     results/$LATEST/protected/swaks_outputs/
```

## Expected Differences

| Aspect | Baseline | Protected |
|--------|----------|-----------|
| DNSSEC | No AD bit | AD bit present* |
| SPF | Not checked | Pass/Fail logged |
| DKIM | No signatures | Signatures present* |
| Forged mail | Accepted | Rejected/Quarantined* |

\* When fully configured

## Troubleshooting

```bash
# Check prerequisites
./tests/verify_environment.sh

# Install missing tools
sudo apt-get install -y bind9 dnsutils swaks tcpdump

# Check if Mininet is available
python3 -c "import mininet.net; print('OK')"
```

## Manual Collection

To collect logs from a running topology:

```bash
# In separate terminal while tests are running
sudo ./tests/collect_logs.sh baseline my_results/
sudo ./tests/collect_logs.sh protected my_results/
```

## File Structure

```
Lab4/
├── tests/
│   ├── run_all_tests.sh         # ← Main test runner
│   ├── collect_logs.sh          # Log collection utility
│   ├── verify_environment.sh    # Environment checker
│   └── README.md                # Full documentation
├── artifacts/
│   ├── logs/                    # Latest logs
│   ├── pcap/                    # Latest packet captures
│   └── reports/                 # Latest comparison report
└── results/
    └── YYYYMMDD_HHMMSS/         # Timestamped test runs
        ├── baseline/
        │   ├── logs/
        │   ├── pcap/
        │   ├── dig_outputs/
        │   └── swaks_outputs/
        ├── protected/
        │   └── ... (same structure)
        └── comparison_report.txt
```

## Integration with Manual Tests

The automated suite complements existing scripts:

- **`mn_quickcheck_v6.cli`** - Interactive with screenshots
- **`mn_run_tests4.cli`** - Non-interactive summary  
- **`tests/run_all_tests.sh`** - **Automated comparison** ← New!

Use automated tests for:
- Reproducible testing
- Before/after comparison
- Artifact generation
- CI/CD integration

## Documentation

- **Full test documentation**: `tests/README.md`
- **Artifacts guide**: `artifacts/README.md`
- **Main project README**: `README.md`

## Quick Commands

```bash
# Full test run
sudo ./tests/run_all_tests.sh

# Environment check
./tests/verify_environment.sh

# View latest report
cat artifacts/reports/comparison_report.txt

# Analyze traffic
tcpdump -r artifacts/pcap/baseline_dns.pcap -nn
wireshark artifacts/pcap/baseline_dns.pcap  # If GUI available
```
