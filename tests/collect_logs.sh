#!/bin/bash
# collect_logs.sh - Collects logs, pcaps, and test outputs for comparison

# Enable nullglob to handle empty glob patterns
shopt -s nullglob

# Parse arguments
PHASE="${1:-baseline}"  # baseline or protected
OUTPUT_DIR="${2:-results/$(date +%Y%m%d_%H%M%S)}"

echo "==== Collecting logs for phase: $PHASE ===="
echo "Output directory: $OUTPUT_DIR"

# Create output structure
mkdir -p "$OUTPUT_DIR/$PHASE/"{logs,pcap,dig_outputs,swaks_outputs}

# Function to safely copy file if it exists
safe_copy() {
    local src="$1"
    local dest="$2"
    if [ -f "$src" ]; then
        cp "$src" "$dest"
        echo "✓ Copied: $src -> $dest"
    else
        echo "⚠ Not found: $src"
    fi
}

# Collect DNS logs from named
echo "Collecting DNS logs..."
safe_copy "/tmp/named.log" "$OUTPUT_DIR/$PHASE/logs/named_dns.log"
safe_copy "/tmp/named_dns.log" "$OUTPUT_DIR/$PHASE/logs/named_dns_alt.log"
safe_copy "/tmp/named_att.log" "$OUTPUT_DIR/$PHASE/logs/named_att.log"

# Collect SMTP logs
echo "Collecting SMTP logs..."
safe_copy "/tmp/mx-smtp.log" "$OUTPUT_DIR/$PHASE/logs/mx_smtp.log"
safe_copy "/tmp/att-smtp.log" "$OUTPUT_DIR/$PHASE/logs/att_smtp.log"
safe_copy "/tmp/smtpd_mx.log" "$OUTPUT_DIR/$PHASE/logs/smtpd_mx.log"
safe_copy "/tmp/smtpd_att.log" "$OUTPUT_DIR/$PHASE/logs/smtpd_att.log"

# Collect DKIM logs if present (for protected phase)
if [ "$PHASE" = "protected" ]; then
    echo "Collecting DKIM logs..."
    safe_copy "/tmp/opendkim.log" "$OUTPUT_DIR/$PHASE/logs/opendkim.log"
    safe_copy "/var/log/opendkim.log" "$OUTPUT_DIR/$PHASE/logs/opendkim_var.log"
fi

# Collect pcap files
echo "Collecting pcap files..."
for pcap in /tmp/*.pcap; do
    if [ -f "$pcap" ]; then
        cp "$pcap" "$OUTPUT_DIR/$PHASE/pcap/"
        echo "✓ Copied: $pcap"
    fi
done

# Collect dig outputs (if saved)
echo "Collecting dig outputs..."
for dig_out in /tmp/dig_*.txt; do
    if [ -f "$dig_out" ]; then
        cp "$dig_out" "$OUTPUT_DIR/$PHASE/dig_outputs/"
        echo "✓ Copied: $dig_out"
    fi
done

# Collect swaks outputs (if saved)
echo "Collecting swaks outputs..."
for swaks_out in /tmp/swaks_*.txt; do
    if [ -f "$swaks_out" ]; then
        cp "$swaks_out" "$OUTPUT_DIR/$PHASE/swaks_outputs/"
        echo "✓ Copied: $swaks_out"
    fi
done

# Helper function to list files or show message
list_files_or_message() {
    local pattern="$1"
    local message="$2"
    ls -lh "$pattern" 2>/dev/null || echo "  $message"
}

# Create a summary file
SUMMARY_FILE="$OUTPUT_DIR/$PHASE/collection_summary.txt"
cat > "$SUMMARY_FILE" <<EOF
Log Collection Summary - Phase: $PHASE
Timestamp: $(date)
======================================

DNS Logs:
$(list_files_or_message "$OUTPUT_DIR/$PHASE/logs/named*.log" "No DNS logs found")

SMTP Logs:
$(list_files_or_message "$OUTPUT_DIR/$PHASE/logs/*smtp*.log" "No SMTP logs found")

PCAP Files:
$(list_files_or_message "$OUTPUT_DIR/$PHASE/pcap/*.pcap" "No pcap files found")

Dig Outputs:
$(list_files_or_message "$OUTPUT_DIR/$PHASE/dig_outputs/*.txt" "No dig outputs found")

Swaks Outputs:
$(list_files_or_message "$OUTPUT_DIR/$PHASE/swaks_outputs/*.txt" "No swaks outputs found")
EOF

echo "✓ Summary saved to: $SUMMARY_FILE"
echo "==== Collection complete for phase: $PHASE ===="
