#!/bin/bash
##
## capture_and_compare.sh - Evidence capture and comparison script
##
## This script captures network traffic during DNS spoofing attacks and
## compares behavior with and without DNSSEC protection.
##
## Usage:
##   ./capture_and_compare.sh <scenario> [output_dir]
##
## Scenarios:
##   baseline  - Capture normal DNS resolution and email delivery
##   attack    - Capture DNS spoofing attack
##   dnssec    - Capture with DNSSEC validation enabled
##
## Output:
##   - PCAP files for each scenario
##   - Text analysis of DNS queries and responses
##   - Email delivery logs
##   - Comparison summary
##

set -e

SCENARIO="${1:-attack}"
OUTPUT_DIR="${2:-/tmp/dns_spoof_evidence}"
CAPTURE_DURATION="${CAPTURE_DURATION:-30}"
INTERFACE="${INTERFACE:-any}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Create output directory
mkdir -p "$OUTPUT_DIR"

log_info "Starting capture for scenario: $SCENARIO"
log_info "Output directory: $OUTPUT_DIR"

# Scenario-specific configuration
case "$SCENARIO" in
    baseline)
        PCAP_FILE="$OUTPUT_DIR/baseline_capture.pcap"
        LOG_FILE="$OUTPUT_DIR/baseline.log"
        DNS_FILTER="udp port 53"
        SMTP_FILTER="tcp port 25"
        DESCRIPTION="Normal DNS resolution with legitimate DNS server"
        ;;
    attack)
        PCAP_FILE="$OUTPUT_DIR/attack_capture.pcap"
        LOG_FILE="$OUTPUT_DIR/attack.log"
        DNS_FILTER="udp port 53"
        SMTP_FILTER="tcp port 25"
        DESCRIPTION="DNS spoofing attack with forged MX records"
        ;;
    dnssec)
        PCAP_FILE="$OUTPUT_DIR/dnssec_capture.pcap"
        LOG_FILE="$OUTPUT_DIR/dnssec.log"
        DNS_FILTER="udp port 53"
        SMTP_FILTER="tcp port 25"
        DESCRIPTION="DNS queries with DNSSEC validation"
        ;;
    *)
        log_error "Unknown scenario: $SCENARIO"
        echo "Valid scenarios: baseline, attack, dnssec"
        exit 1
        ;;
esac

log_info "Description: $DESCRIPTION"
log_info "Capture file: $PCAP_FILE"

# Function to start packet capture
start_capture() {
    log_info "Starting tcpdump on interface $INTERFACE..."
    
    # Kill any existing tcpdump
    pkill -9 tcpdump 2>/dev/null || true
    sleep 1
    
    # Start tcpdump in background
    tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
        "($DNS_FILTER) or ($SMTP_FILTER)" \
        > /tmp/tcpdump_${SCENARIO}.log 2>&1 &
    
    TCPDUMP_PID=$!
    sleep 2
    
    if ps -p "$TCPDUMP_PID" > /dev/null 2>&1; then
        log_success "Packet capture started (PID: $TCPDUMP_PID)"
        return 0
    else
        log_error "Failed to start tcpdump"
        return 1
    fi
}

# Function to stop packet capture
stop_capture() {
    log_info "Stopping packet capture..."
    
    if [ -n "$TCPDUMP_PID" ] && ps -p "$TCPDUMP_PID" > /dev/null 2>&1; then
        kill -SIGINT "$TCPDUMP_PID" 2>/dev/null || true
        sleep 2
        log_success "Packet capture stopped"
    else
        pkill -SIGINT tcpdump 2>/dev/null || true
        sleep 2
        log_warn "Stopped tcpdump via pkill"
    fi
}

# Function to analyze DNS traffic
analyze_dns_traffic() {
    local pcap_file="$1"
    local output_file="$2"
    
    log_info "Analyzing DNS traffic..."
    
    {
        echo "============================================"
        echo "DNS Traffic Analysis - $SCENARIO"
        echo "============================================"
        echo ""
        echo "Capture file: $pcap_file"
        echo "Timestamp: $(date)"
        echo ""
        
        if [ ! -f "$pcap_file" ]; then
            echo "ERROR: Capture file not found!"
            return 1
        fi
        
        # DNS queries summary
        echo "--- DNS Queries Summary ---"
        tcpdump -r "$pcap_file" -n 'udp port 53' 2>/dev/null | \
            grep -E 'A\?|MX\?|TXT\?' | head -20
        echo ""
        
        # DNS responses summary
        echo "--- DNS Responses Summary ---"
        tcpdump -r "$pcap_file" -n 'udp port 53' 2>/dev/null | \
            grep -v 'A\?' | grep -v 'MX\?' | head -20
        echo ""
        
        # MX record queries specifically
        echo "--- MX Record Queries ---"
        tcpdump -r "$pcap_file" -n 'udp port 53' 2>/dev/null | \
            grep 'MX?' || echo "(No MX queries found)"
        echo ""
        
        # SMTP connections
        echo "--- SMTP Connections ---"
        tcpdump -r "$pcap_file" -n 'tcp port 25' 2>/dev/null | \
            grep -E 'SYN|Flags \[S\]' | head -10 || echo "(No SMTP connections found)"
        echo ""
        
        # Statistics
        echo "--- Packet Statistics ---"
        echo -n "Total packets: "
        tcpdump -r "$pcap_file" 2>/dev/null | wc -l
        
        echo -n "DNS packets: "
        tcpdump -r "$pcap_file" -n 'udp port 53' 2>/dev/null | wc -l
        
        echo -n "SMTP packets: "
        tcpdump -r "$pcap_file" -n 'tcp port 25' 2>/dev/null | wc -l
        echo ""
        
    } > "$output_file"
    
    log_success "Analysis saved to $output_file"
}

# Function to generate comparison report
generate_comparison() {
    local baseline_pcap="$OUTPUT_DIR/baseline_capture.pcap"
    local attack_pcap="$OUTPUT_DIR/attack_capture.pcap"
    local dnssec_pcap="$OUTPUT_DIR/dnssec_capture.pcap"
    local comparison_file="$OUTPUT_DIR/comparison_report.txt"
    
    log_info "Generating comparison report..."
    
    {
        echo "================================================================="
        echo "DNS SPOOFING ATTACK - COMPARISON REPORT"
        echo "================================================================="
        echo ""
        echo "Generated: $(date)"
        echo ""
        
        echo "--- Scenario Comparison ---"
        echo ""
        
        # Baseline
        if [ -f "$baseline_pcap" ]; then
            echo "1. BASELINE (Legitimate DNS):"
            echo "   - Capture file: $baseline_pcap"
            echo -n "   - Total packets: "
            tcpdump -r "$baseline_pcap" 2>/dev/null | wc -l
            echo -n "   - DNS queries: "
            tcpdump -r "$baseline_pcap" -n 'udp port 53' 2>/dev/null | wc -l
            echo ""
        fi
        
        # Attack
        if [ -f "$attack_pcap" ]; then
            echo "2. ATTACK (DNS Spoofing):"
            echo "   - Capture file: $attack_pcap"
            echo -n "   - Total packets: "
            tcpdump -r "$attack_pcap" 2>/dev/null | wc -l
            echo -n "   - DNS queries: "
            tcpdump -r "$attack_pcap" -n 'udp port 53' 2>/dev/null | wc -l
            echo ""
        fi
        
        # DNSSEC
        if [ -f "$dnssec_pcap" ]; then
            echo "3. DNSSEC (Protected):"
            echo "   - Capture file: $dnssec_pcap"
            echo -n "   - Total packets: "
            tcpdump -r "$dnssec_pcap" 2>/dev/null | wc -l
            echo -n "   - DNS queries: "
            tcpdump -r "$dnssec_pcap" -n 'udp port 53' 2>/dev/null | wc -l
            echo ""
        fi
        
        echo "--- Key Findings ---"
        echo ""
        echo "Expected behavior:"
        echo "  ✓ Baseline: MX resolves to 10.0.0.25 (legitimate mail server)"
        echo "  ⚠ Attack:   MX resolves to 10.0.0.66 (attacker's server)"
        echo "  ✓ DNSSEC:   Attack fails, MX validation rejects forged records"
        echo ""
        
        echo "Evidence files location: $OUTPUT_DIR"
        echo ""
        echo "To review captures:"
        echo "  tcpdump -r $baseline_pcap -n -vv 'udp port 53'"
        echo "  tcpdump -r $attack_pcap -n -vv 'udp port 53'"
        echo "  tcpdump -r $dnssec_pcap -n -vv 'udp port 53'"
        echo ""
        
    } > "$comparison_file"
    
    log_success "Comparison report saved to $comparison_file"
    cat "$comparison_file"
}

# Main execution
main() {
    log_info "=== DNS Spoofing Evidence Capture ==="
    
    # Start capture
    if ! start_capture; then
        log_error "Failed to start packet capture"
        exit 1
    fi
    
    # Capture for specified duration (if running standalone)
    if [ -t 0 ]; then
        log_info "Capturing for $CAPTURE_DURATION seconds..."
        log_info "You can now run your DNS queries and email tests"
        sleep "$CAPTURE_DURATION"
    else
        log_info "Capture running. Press Ctrl+C to stop."
        # Wait for interrupt
        wait "$TCPDUMP_PID" 2>/dev/null || true
    fi
    
    # Stop capture
    stop_capture
    
    # Analyze
    if [ -f "$PCAP_FILE" ]; then
        ANALYSIS_FILE="${PCAP_FILE%.pcap}_analysis.txt"
        analyze_dns_traffic "$PCAP_FILE" "$ANALYSIS_FILE"
        
        log_success "Capture complete!"
        log_info "Files created:"
        log_info "  - $PCAP_FILE"
        log_info "  - $ANALYSIS_FILE"
    else
        log_error "Capture file not created: $PCAP_FILE"
        exit 1
    fi
    
    # Generate comparison if we have all scenarios
    if [ -f "$OUTPUT_DIR/baseline_capture.pcap" ] && \
       [ -f "$OUTPUT_DIR/attack_capture.pcap" ]; then
        generate_comparison
    fi
    
    log_success "Done!"
}

# Handle Ctrl+C
trap 'stop_capture; exit 0' INT TERM

# Run if executed directly (not sourced)
if [ "${BASH_SOURCE[0]}" -ef "$0" ]; then
    main "$@"
fi
