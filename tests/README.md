# SPF/DMARC Tests

This directory contains automated tests for SPF and DMARC policy enforcement.

## test_spf_dmarc.sh

This script validates the SPF and DMARC configuration for `example.com` and simulates unauthorized sender scenarios.

### What it tests:

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

### Prerequisites:

- DNS server running on 10.0.0.53 with the zone loaded
- `dig` utility installed (from dnsutils package)

### Running the tests:

From within Mininet topology:

```bash
# Start the topology
sudo python3 lab4_topo_v6e.py

# In Mininet CLI, on the dns host:
dns named -4 -u bind -g -c /etc/bind/named.conf &

# On h1 or any host with DNS access:
h1 bash /home/runner/work/Lab4/Lab4/tests/test_spf_dmarc.sh
```

Or standalone (if DNS is running):

```bash
cd /home/runner/work/Lab4/Lab4
./tests/test_spf_dmarc.sh
```

### Expected Output:

The script will output color-coded test results:
- ✓ PASS (green) - Test passed
- ✗ FAIL (red) - Test failed
- ℹ INFO (yellow) - Informational message

At the end, it provides a summary of passed/failed tests and exits with:
- Exit code 0 if all tests pass
- Exit code 1 if any test fails

### Viewing Mail Logs:

To see actual DMARC policy enforcement in action:

1. **Postfix logs** (if using Postfix instead of smtpd):
   ```bash
   tail -f /var/log/mail.log
   ```

2. **SMTP debugging logs** (from Python smtpd):
   ```bash
   tail -f /tmp/mx-smtp.log
   tail -f /tmp/att-smtp.log
   ```

3. **DMARC aggregate reports** (if configured with real reporting):
   - Check the email address specified in `rua=` tag
   - Reports are typically sent daily in XML format

### Notes:

- The test simulates SPF failure scenarios by checking if unauthorized IPs are in the SPF record
- Actual SPF checking is done by the receiving MTA, not the sending client
- DMARC policy application happens at the receiver based on SPF and DKIM results
- This test validates configuration; real enforcement requires MTA configuration (Postfix, OpenDMARC, etc.)
