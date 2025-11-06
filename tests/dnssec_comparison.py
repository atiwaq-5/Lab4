#!/usr/bin/env python3
"""
DNSSEC Comparison Script

This script demonstrates how DNSSEC protection prevents DNS spoofing attacks.
It shows the difference between normal DNS and DNSSEC-validated DNS queries.

Usage:
    # In Mininet environment
    py exec(open('tests/dnssec_comparison.py').read())
    
    # Or standalone
    python3 tests/dnssec_comparison.py
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECK = "✔️"
CROSS = "✖️"
WARN = "⚠️"


def say(msg: str):
    """Print message with flush."""
    print(msg, flush=True)


def show_dnssec_comparison():
    """
    Show how DNSSEC would prevent the DNS spoofing attack.
    
    This is a conceptual demonstration since full DNSSEC setup requires
    zone signing, key management, and resolver validation configuration.
    """
    say("\n" + "=" * 80)
    say("DNSSEC PROTECTION - Conceptual Demonstration")
    say("=" * 80)
    
    say("\n[*] DNSSEC (Domain Name System Security Extensions) prevents DNS spoofing by:")
    say("    1. Cryptographically signing DNS records")
    say("    2. Validating signatures at the resolver")
    say("    3. Rejecting unsigned or incorrectly signed responses")
    
    say("\n--- Scenario 1: Without DNSSEC (VULNERABLE) ---")
    say("")
    say("1. Client queries: example.com MX?")
    say("2. Attacker intercepts and responds:")
    say("   MX 10 att.example.com (10.0.0.66)")
    say(f"   {WARN} No signature required - attacker can forge freely")
    say("3. Client accepts forged response")
    say(f"4. Email delivered to attacker {CROSS}")
    
    say("\n--- Scenario 2: With DNSSEC (PROTECTED) ---")
    say("")
    say("1. Client queries: example.com MX +dnssec?")
    say("2. Legitimate DNS responds:")
    say("   MX 10 mail.example.com (10.0.0.25)")
    say("   RRSIG MX 8 2 300 ... [cryptographic signature]")
    say(f"   {CHECK} Signed with zone's private key")
    say("3. Attacker tries to forge:")
    say("   MX 10 att.example.com (10.0.0.66)")
    say(f"   {CROSS} Cannot create valid signature (no private key)")
    say("4. DNSSEC-validating resolver:")
    say("   - Checks RRSIG signature")
    say("   - Validates chain of trust (DNSKEY → DS → root)")
    say(f"   - Rejects unsigned/invalid responses {CHECK}")
    say("5. Email delivered to legitimate server only")
    
    say("\n--- DNSSEC Record Types ---")
    say("")
    say("DNSKEY: Public key for zone verification")
    say("RRSIG:  Signature for a specific record set")
    say("DS:     Delegation Signer (links to parent zone)")
    say("NSEC/NSEC3: Authenticated denial of existence")
    
    say("\n--- How to Enable DNSSEC in Lab 4 ---")
    say("")
    say("1. On the DNS server (authoritative zone):")
    say("   dns# cd /var/cache/bind/zones")
    say("   dns# dnssec-keygen -a RSASHA256 -b 2048 -n ZONE example.com")
    say("   dns# dnssec-keygen -a RSASHA256 -b 2048 -n ZONE -f KSK example.com")
    say("   dns# dnssec-signzone -o example.com db.example.com.good")
    say("   dns# # Update named.conf to use db.example.com.good.signed")
    say("")
    say("2. On the client (resolver validation):")
    say("   h1# apt-get install unbound")
    say("   h1# # Configure unbound with trust anchor (DNSKEY)")
    say("   h1# # Set nameserver to localhost (unbound)")
    say("")
    say("3. Test DNSSEC validation:")
    say("   h1# dig @localhost example.com MX +dnssec")
    say("   # Look for 'ad' (authenticated data) flag in response")
    say("   # RRSIG records should be present")
    
    say("\n--- Testing Attack with DNSSEC Enabled ---")
    say("")
    say("Attack Attempt:")
    say("  h1# echo 'nameserver 10.0.0.66' > /etc/resolv.conf  # Point to attacker")
    say("  h1# dig example.com MX +dnssec")
    say("")
    say("Expected Result with DNSSEC Validation:")
    say(f"  {CROSS} Query fails or returns SERVFAIL")
    say(f"  {CROSS} No RRSIG or invalid signature")
    say(f"  {CROSS} Resolver rejects the response")
    say(f"  {CHECK} Legitimate email delivery still works via fallback/cache")
    
    say("\n--- Command Comparison ---")
    say("")
    
    # Table format
    say("| Scenario | Command | Expected Result |")
    say("|----------|---------|-----------------|")
    say("| No DNSSEC | `dig @10.0.0.66 example.com MX` | Forged MX: att.example.com |")
    say("| No DNSSEC | `dig @10.0.0.53 example.com MX` | Real MX: mail.example.com |")
    say("| DNSSEC | `dig @10.0.0.66 example.com MX +dnssec` | No valid RRSIG → FAIL |")
    say("| DNSSEC | `dig @10.0.0.53 example.com MX +dnssec` | Valid RRSIG → SUCCESS |")
    
    say("\n--- Validation Status Codes ---")
    say("")
    say("AD (Authenticated Data): Response validated with DNSSEC")
    say("BOGUS: Response failed DNSSEC validation")
    say("INSECURE: Zone not signed with DNSSEC")
    say("SERVFAIL: Validation error (unsigned/invalid signature)")
    
    say("\n--- Integration with Existing Scripts ---")
    say("")
    say("For full DNSSEC demonstration:")
    say("  sudo python3 mn_quickcheck_v6_with_dnssec.py")
    say("")
    say("This will:")
    say(f"  {CHECK} Sign the zone with DNSSEC keys")
    say(f"  {CHECK} Configure Unbound for validation")
    say(f"  {CHECK} Show 'ad' flag in dig output")
    say(f"  {CHECK} Demonstrate attack failure")
    
    say("\n--- Additional Email Security Layers ---")
    say("")
    say("DNSSEC protects DNS integrity, but email needs more:")
    say("")
    say("SPF (Sender Policy Framework):")
    say("  - DNS TXT record specifying authorized mail servers")
    say("  - Example: 'v=spf1 a mx -all'")
    say(f"  {CHECK} Prevents sender IP spoofing")
    say("")
    say("DKIM (DomainKeys Identified Mail):")
    say("  - Cryptographic signature in email headers")
    say("  - Public key published in DNS")
    say(f"  {CHECK} Verifies email wasn't modified in transit")
    say("")
    say("DMARC (Domain-based Message Authentication):")
    say("  - Policy for handling SPF/DKIM failures")
    say("  - Example: 'v=DMARC1; p=quarantine'")
    say(f"  {CHECK} Tells receivers what to do with suspicious email")
    say("")
    say("Defense in Depth:")
    say(f"  {CHECK} DNSSEC: Ensures MX record is correct")
    say(f"  {CHECK} SPF: Verifies sender IP is authorized")
    say(f"  {CHECK} DKIM: Authenticates message content")
    say(f"  {CHECK} DMARC: Enforces policy on failures")
    say(f"  {CHECK} TLS: Encrypts email in transit")
    
    say("\n--- Real-World Attack Prevention ---")
    say("")
    say("Without DNSSEC:")
    say("  1. Attacker poisons DNS cache → MX points to attacker")
    say("  2. Legitimate email servers send to wrong MX")
    say("  3. Attacker intercepts all email for domain")
    say(f"  {CROSS} Attack succeeds")
    say("")
    say("With DNSSEC:")
    say("  1. Attacker tries to poison DNS cache")
    say("  2. DNSSEC resolver validates signatures")
    say("  3. Forged responses rejected")
    say("  4. Email servers query again or use cached valid data")
    say(f"  {CHECK} Attack fails")
    
    say("\n" + "=" * 80)
    say("SUMMARY")
    say("=" * 80)
    
    say(f"\n{WARN} WITHOUT DNSSEC:")
    say("  - DNS responses are unauthenticated")
    say("  - Attackers can forge any DNS record")
    say("  - Email can be redirected to attacker's server")
    say("  - No way to detect tampering")
    
    say(f"\n{CHECK} WITH DNSSEC:")
    say("  - DNS responses are cryptographically signed")
    say("  - Forged responses are detected and rejected")
    say("  - Email reaches only legitimate mail servers")
    say("  - Chain of trust ensures authenticity")
    
    say("\nFor hands-on DNSSEC demonstration, run:")
    say("  sudo python3 mn_quickcheck_v6_with_dnssec.py")
    say("")
    say("=" * 80 + "\n")


if __name__ == '__main__':
    show_dnssec_comparison()
