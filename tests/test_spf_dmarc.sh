#!/bin/bash
# Test script for SPF and DMARC policy enforcement
# This script tests:
# 1. SPF record is present and authorizes the correct MX IP
# 2. DMARC record is present with correct policy
# 3. Email from unauthorized IP (attacker) triggers SPF failure
# 4. DMARC policy is applied based on SPF/DKIM results

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

log_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((TESTS_PASSED++))
}

log_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((TESTS_FAILED++))
}

log_info() {
    echo -e "${YELLOW}ℹ INFO${NC}: $1"
}

echo "======================================"
echo "SPF/DMARC Policy Enforcement Tests"
echo "======================================"
echo ""

# Configuration
DNS_SERVER="10.0.0.53"
MX_IP="10.0.0.25"
ATT_IP="10.0.0.66"
DOMAIN="example.com"

# Test 1: Check SPF record exists
echo "Test 1: SPF Record Presence and Content"
echo "----------------------------------------"
SPF_RECORD=$(dig +short TXT "@${DOMAIN}" @${DNS_SERVER} 2>/dev/null | grep -i "v=spf1" | tr -d '"' || echo "")
if [[ -n "$SPF_RECORD" ]]; then
    log_pass "SPF record found: $SPF_RECORD"
    
    # Verify it authorizes the MX IP
    if echo "$SPF_RECORD" | grep -q "ip4:${MX_IP}"; then
        log_pass "SPF record explicitly authorizes MX IP ${MX_IP}"
    elif echo "$SPF_RECORD" | grep -q -E "mx|a"; then
        log_pass "SPF record authorizes via mx/a mechanism"
    else
        log_fail "SPF record does not appear to authorize MX IP ${MX_IP}"
    fi
    
    # Verify hard fail policy
    if echo "$SPF_RECORD" | grep -q -- "-all"; then
        log_pass "SPF record uses hard fail (-all) for unauthorized senders"
    else
        log_fail "SPF record should use -all for security"
    fi
else
    log_fail "SPF record not found for ${DOMAIN}"
fi
echo ""

# Test 2: Check DMARC record exists
echo "Test 2: DMARC Record Presence and Policy"
echo "-----------------------------------------"
DMARC_RECORD=$(dig +short TXT "_dmarc.${DOMAIN}" @${DNS_SERVER} 2>/dev/null | grep -i "v=DMARC1" | tr -d '"' || echo "")
if [[ -n "$DMARC_RECORD" ]]; then
    log_pass "DMARC record found: $DMARC_RECORD"
    
    # Extract policy
    POLICY=$(echo "$DMARC_RECORD" | grep -oP 'p=\K[^;]+' || echo "none")
    if [[ "$POLICY" == "quarantine" ]] || [[ "$POLICY" == "reject" ]]; then
        log_pass "DMARC policy is set to '$POLICY' (enforcing)"
    elif [[ "$POLICY" == "none" ]]; then
        log_fail "DMARC policy is 'none' (monitoring only, not enforcing)"
    else
        log_fail "DMARC policy is unrecognized: '$POLICY'"
    fi
    
    # Check for reporting addresses
    if echo "$DMARC_RECORD" | grep -q "rua="; then
        log_pass "DMARC aggregate reporting (rua) configured"
    fi
    if echo "$DMARC_RECORD" | grep -q "ruf="; then
        log_pass "DMARC forensic reporting (ruf) configured"
    fi
    
    # Check percentage
    PCT=$(echo "$DMARC_RECORD" | grep -oP 'pct=\K[0-9]+' || echo "100")
    if [[ "$PCT" == "100" ]]; then
        log_pass "DMARC applies to 100% of messages"
    else
        log_info "DMARC applies to ${PCT}% of messages"
    fi
else
    log_fail "DMARC record not found for _dmarc.${DOMAIN}"
fi
echo ""

# Test 3: Simulate unauthorized sender (SPF fail scenario)
echo "Test 3: Unauthorized Sender Detection (SPF Failure Simulation)"
echo "---------------------------------------------------------------"
log_info "This test simulates an attacker at ${ATT_IP} sending mail claiming to be from ${DOMAIN}"
log_info "In a real system, the receiving MTA would:"
log_info "  1. Check SPF: FAIL (sender IP ${ATT_IP} not authorized by SPF record)"
log_info "  2. Check DMARC: FAIL (SPF failed, no DKIM to compensate)"
log_info "  3. Apply DMARC policy: quarantine or reject based on p= setting"

# Check if we can determine SPF result programmatically
# Note: This is a simulation - in production, the receiving MTA does this check
if [[ -n "$SPF_RECORD" ]]; then
    # Check if attacker IP is authorized
    if echo "$SPF_RECORD" | grep -q "ip4:${ATT_IP}"; then
        log_fail "Attacker IP ${ATT_IP} is incorrectly authorized in SPF record"
    else
        log_pass "Attacker IP ${ATT_IP} is NOT authorized (expected SPF failure)"
    fi
    
    # Verify the actual authorized IP
    if echo "$SPF_RECORD" | grep -q "ip4:${MX_IP}"; then
        log_pass "Only legitimate MX IP ${MX_IP} is explicitly authorized"
    fi
fi
echo ""

# Test 4: DMARC Policy Application
echo "Test 4: DMARC Policy Application Logic"
echo "---------------------------------------"
if [[ -n "$DMARC_RECORD" ]] && [[ -n "$SPF_RECORD" ]]; then
    log_info "When SPF fails and DKIM is absent/fails:"
    
    if [[ "$POLICY" == "reject" ]]; then
        log_pass "DMARC policy 'reject' would cause message to be rejected at SMTP time"
    elif [[ "$POLICY" == "quarantine" ]]; then
        log_pass "DMARC policy 'quarantine' would cause message to be quarantined/marked as spam"
    elif [[ "$POLICY" == "none" ]]; then
        log_fail "DMARC policy 'none' would NOT block unauthorized messages (monitoring only)"
    fi
    
    log_info "Legitimate senders from ${MX_IP} would pass SPF and be delivered normally"
else
    log_fail "Cannot test DMARC policy application without valid SPF and DMARC records"
fi
echo ""

# Test 5: MX Record Validation
echo "Test 5: MX Record Points to Authorized Mail Server"
echo "---------------------------------------------------"
MX_RECORD=$(dig +short MX "${DOMAIN}" @${DNS_SERVER} 2>/dev/null | awk '{print $2}' | head -1 | sed 's/\.$//' || echo "")
if [[ -n "$MX_RECORD" ]]; then
    log_pass "MX record found: ${MX_RECORD}"
    
    # Resolve MX to IP
    MX_RESOLVED_IP=$(dig +short A "${MX_RECORD}" @${DNS_SERVER} 2>/dev/null | head -1 || echo "")
    if [[ "$MX_RESOLVED_IP" == "$MX_IP" ]]; then
        log_pass "MX record resolves to authorized IP ${MX_IP}"
    else
        log_fail "MX record resolves to ${MX_RESOLVED_IP}, expected ${MX_IP}"
    fi
else
    log_fail "MX record not found for ${DOMAIN}"
fi
echo ""

# Summary
echo "======================================"
echo "Test Summary"
echo "======================================"
echo -e "Tests Passed: ${GREEN}${TESTS_PASSED}${NC}"
echo -e "Tests Failed: ${RED}${TESTS_FAILED}${NC}"
echo ""

if [[ $TESTS_FAILED -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
    echo ""
    echo "SPF/DMARC Configuration Summary:"
    echo "  ✓ SPF record properly configured to authorize ${MX_IP}"
    echo "  ✓ DMARC policy set to '${POLICY}' for enforcement"
    echo "  ✓ Unauthorized senders will fail SPF checks"
    echo "  ✓ DMARC policy will be applied to failed authentications"
    exit 0
else
    echo -e "${RED}Some tests failed. Please review the configuration.${NC}"
    exit 1
fi
