#!/bin/bash
# Generate DKIM keys for email signing
# Usage: ./generate_dkim_keys.sh [domain] [selector]
#
# This script generates:
# - Private key for signing (s1.private)
# - Public key for DNS TXT record (s1.txt)

DOMAIN="${1:-example.com}"
SELECTOR="${2:-s1}"
KEY_DIR="/etc/opendkim/keys/${DOMAIN}"

echo "Generating DKIM keys for domain: $DOMAIN, selector: $SELECTOR"

# Create directory for keys
mkdir -p "$KEY_DIR"

# Generate the key pair
opendkim-genkey -b 2048 -d "$DOMAIN" -s "$SELECTOR" -D "$KEY_DIR"

# Set proper permissions
chmod 600 "${KEY_DIR}/${SELECTOR}.private"
chmod 644 "${KEY_DIR}/${SELECTOR}.txt"
chown -R opendkim:opendkim /etc/opendkim/keys

echo ""
echo "DKIM keys generated successfully!"
echo "Private key: ${KEY_DIR}/${SELECTOR}.private"
echo "Public key (DNS TXT): ${KEY_DIR}/${SELECTOR}.txt"
echo ""
echo "To add to DNS zone, use the content from ${KEY_DIR}/${SELECTOR}.txt:"
cat "${KEY_DIR}/${SELECTOR}.txt"
echo ""
echo "The TXT record should be added as: ${SELECTOR}._domainkey.${DOMAIN}"
