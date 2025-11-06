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
mkdir -p "$KEY_DIR" || {
    echo "ERROR: Failed to create directory $KEY_DIR"
    exit 1
}

# Generate the key pair
if ! opendkim-genkey -b 2048 -d "$DOMAIN" -s "$SELECTOR" -D "$KEY_DIR"; then
    echo "ERROR: opendkim-genkey failed"
    exit 1
fi

# Verify keys were created
if [ ! -f "${KEY_DIR}/${SELECTOR}.private" ] || [ ! -f "${KEY_DIR}/${SELECTOR}.txt" ]; then
    echo "ERROR: DKIM keys were not created successfully"
    exit 1
fi

# Set proper permissions
chmod 600 "${KEY_DIR}/${SELECTOR}.private"
chmod 644 "${KEY_DIR}/${SELECTOR}.txt"

# Check if opendkim user exists before changing ownership
if id "opendkim" >/dev/null 2>&1; then
    chown -R opendkim:opendkim /etc/opendkim/keys
else
    echo "WARNING: opendkim user does not exist, skipping ownership change"
fi

echo ""
echo "DKIM keys generated successfully!"
echo "Private key: ${KEY_DIR}/${SELECTOR}.private"
echo "Public key (DNS TXT): ${KEY_DIR}/${SELECTOR}.txt"
echo ""
echo "To add to DNS zone, use the content from ${KEY_DIR}/${SELECTOR}.txt:"
cat "${KEY_DIR}/${SELECTOR}.txt"
echo ""
echo "The TXT record should be added as: ${SELECTOR}._domainkey.${DOMAIN}"
