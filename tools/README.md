# DNS Spoofing Tools

This directory contains tools for demonstrating DNS spoofing/poisoning attacks.

## spoof_mx.py

A lightweight UDP DNS responder that returns forged MX records for demonstration purposes.

### Features

- Listens for DNS queries on UDP port 53
- Responds to MX queries with forged records pointing to attacker's IP
- Returns both MX and A records for the attacker's mail server
- Configurable domain, IP addresses, and listening interface
- Verbose logging of all queries and responses

### Usage

#### Basic Usage (Default Configuration)

```bash
python3 spoof_mx.py
```

This starts the DNS spoofer with default settings:
- Listen on: 0.0.0.0:53
- Forged domain: example.com
- Attacker IP: 10.0.0.66
- Attacker MX: att.example.com

#### Custom Configuration

```bash
# Forge MX for a different domain
python3 spoof_mx.py --domain company.com --attacker-ip 192.168.1.100

# Listen on specific interface and port
python3 spoof_mx.py --ip 10.0.0.66 --port 5353

# Custom MX hostname
python3 spoof_mx.py --attacker-mx evil.company.com --attacker-ip 10.0.0.66

# Quiet mode (minimal output)
python3 spoof_mx.py -q
```

#### In Mininet Environment

```bash
# On the attacker host
att python3 /path/to/spoof_mx.py --ip 10.0.0.66 --domain example.com

# Or run in background
att python3 /path/to/spoof_mx.py --domain example.com > /tmp/spoofer.log 2>&1 &
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--ip IP` | IP address to bind to | 0.0.0.0 |
| `--port PORT` | Port to listen on | 53 |
| `--domain DOMAIN` | Domain to forge | example.com |
| `--attacker-ip IP` | Attacker's IP address | 10.0.0.66 |
| `--attacker-mx MX` | Attacker's MX hostname | att.example.com |
| `-q, --quiet` | Quiet mode | False |

### Example Output

```
[*] DNS Spoofer listening on 0.0.0.0:53
[*] Forging MX for 'example.com' -> att.example.com (10.0.0.66)
[*] Press Ctrl+C to stop

[+] Query from 10.0.0.10:54321 - example.com (MX)
[!] Sent FORGED MX response: att.example.com -> 10.0.0.66
[+] Query from 10.0.0.10:54322 - att.example.com (A)
[+] Query from 10.0.0.10:54323 - google.com (A)
```

### How It Works

1. **Query Reception**: Listens for UDP DNS queries on the specified port
2. **Query Parsing**: Extracts the domain name and query type from the DNS packet
3. **Response Forgery**: For MX queries matching the forged domain:
   - Creates a DNS response packet
   - Sets the MX record to point to attacker's hostname
   - Adds an additional A record mapping attacker's hostname to IP
4. **Response Transmission**: Sends the forged response back to the client

### DNS Packet Structure

The tool constructs minimal but valid DNS response packets:

```
DNS Header (12 bytes):
  - Transaction ID (from query)
  - Flags: 0x8180 (standard query response, no error)
  - Question count: 1
  - Answer count: 1 (for MX queries)
  - Authority count: 0
  - Additional count: 1 (A record for MX hostname)

Question Section (echoed from query):
  - Domain name
  - Query type (MX = 15)
  - Query class (IN = 1)

Answer Section (for MX queries):
  - Name pointer to question
  - Type: MX (15)
  - Class: IN (1)
  - TTL: 300 seconds
  - RDATA: preference (10) + MX hostname

Additional Section:
  - MX hostname
  - Type: A (1)
  - Class: IN (1)
  - TTL: 300 seconds
  - RDATA: 4-byte IP address
```

### Security Considerations

⚠️ **WARNING**: This tool is for educational purposes only!

- Only use in controlled lab environments
- Never use on production networks
- DNS spoofing is illegal in most jurisdictions
- This demonstrates why DNSSEC is necessary

### Limitations

- Only responds to MX queries for the configured domain
- Does not implement recursive resolution
- Does not support DNSSEC (by design - to show vulnerability)
- Minimal DNS packet parsing (may not handle all edge cases)
- Single-threaded (sufficient for lab demonstrations)

### Testing the Spoofer

```bash
# Start the spoofer
python3 spoof_mx.py --domain example.com --attacker-ip 10.0.0.66 &

# Test with dig (from another terminal/host)
dig @127.0.0.1 example.com MX +short
# Expected output:
# 10 att.example.com.
# 10.0.0.66

# Test A record resolution
dig @127.0.0.1 att.example.com A +short
# Expected output:
# 10.0.0.66

# Test with non-matching domain (should get empty response)
dig @127.0.0.1 google.com MX +short
# Expected output: (empty)
```

### Integration with Lab 4

This tool is designed to work with the Lab 4 topology:

```python
# In lab4_topo_v6e.py, hosts are:
dns = '10.0.0.53'  # Legitimate DNS server
att = '10.0.0.66'  # Attacker (runs spoof_mx.py)
h1  = '10.0.0.10'  # Client
mx  = '10.0.0.25'  # Legitimate mail server
```

Workflow:
1. Start legitimate DNS on `dns` host serving correct MX → `10.0.0.25`
2. Start spoof_mx.py on `att` host serving forged MX → `10.0.0.66`
3. Point client's resolv.conf to `att` instead of `dns`
4. Client queries resolve to attacker's IP
5. Email delivered to attacker instead of legitimate MX

### Comparison with Other Tools

| Feature | spoof_mx.py | dnsspoof | ettercap |
|---------|------------|----------|----------|
| Lightweight | ✓ | ✗ | ✗ |
| Python-based | ✓ | ✗ | ✗ |
| MX-specific | ✓ | ✗ | ✗ |
| Easy to modify | ✓ | ✗ | ✓ |
| Requires root | ✓* | ✓ | ✓ |
| Educational | ✓ | ✗ | ✓ |

*Only for port 53; can use unprivileged port (e.g., 5353) otherwise

### Troubleshooting

#### Permission Denied (Port 53)

```bash
# Run with sudo
sudo python3 spoof_mx.py

# Or use unprivileged port
python3 spoof_mx.py --port 5353
# Then query with: dig @localhost -p 5353 example.com MX
```

#### Address Already in Use

```bash
# Check what's using port 53
sudo ss -ulnp | grep :53

# Kill existing DNS server
sudo pkill -9 named
# or
sudo pkill -9 dnsmasq

# Then retry
sudo python3 spoof_mx.py
```

#### No Responses Received

```bash
# Check spoofer is running
ps aux | grep spoof_mx.py

# Check it's listening
sudo ss -ulnp | grep :53

# Test locally first
dig @127.0.0.1 example.com MX

# Check firewall rules
sudo iptables -L -n | grep 53
```

### Advanced Usage

#### Custom Response Script

Modify `build_dns_response()` function to:
- Forge other record types (A, AAAA, TXT, etc.)
- Return multiple MX records with different priorities
- Add more sophisticated logging
- Implement conditional responses based on source IP

#### Integration with tcpdump

```bash
# Capture all traffic while spoofer is running
tcpdump -i any -w /tmp/spoof.pcap 'udp port 53' &

# Run spoofer
python3 spoof_mx.py

# Generate traffic
dig @localhost example.com MX

# Stop capture and analyze
tcpdump -r /tmp/spoof.pcap -n -vv
```

### References

- [RFC 1035](https://tools.ietf.org/html/rfc1035) - DNS Specification
- [RFC 2782](https://tools.ietf.org/html/rfc2782) - DNS SRV
- [RFC 4033-4035](https://tools.ietf.org/html/rfc4033) - DNSSEC
- [DNS Packet Format](https://www.rfc-editor.org/rfc/rfc1035#section-4.1)
