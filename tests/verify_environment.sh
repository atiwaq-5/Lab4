#!/bin/bash
# verify_environment.sh - Check if the environment has all required dependencies

echo "========================================"
echo "Lab 4 Test Environment Verification"
echo "========================================"
echo ""

MISSING=0

check_command() {
    local cmd="$1"
    local pkg="$2"
    if command -v "$cmd" &> /dev/null; then
        echo "✓ $cmd found"
    else
        echo "✗ $cmd NOT found (install with: sudo apt-get install $pkg)"
        MISSING=1
    fi
}

check_python_module() {
    local module="$1"
    if python3 -c "import $module" 2>/dev/null; then
        echo "✓ Python module '$module' available"
    else
        echo "✗ Python module '$module' NOT available"
        MISSING=1
    fi
}

echo "Checking required commands..."
check_command "dig" "dnsutils"
check_command "swaks" "swaks"
check_command "tcpdump" "tcpdump"
check_command "python3" "python3"
check_command "named" "bind9"

echo ""
echo "Checking Python modules..."
check_python_module "mininet.net"

echo ""
echo "Checking directory structure..."
if [ -d "tests" ]; then
    echo "✓ tests/ directory exists"
else
    echo "✗ tests/ directory NOT found"
    MISSING=1
fi

if [ -d "zones" ]; then
    echo "✓ zones/ directory exists"
else
    echo "✗ zones/ directory NOT found"
    MISSING=1
fi

if [ -f "zones/db.example.com.good" ]; then
    echo "✓ Good DNS zone file found"
else
    echo "✗ Good DNS zone file NOT found"
    MISSING=1
fi

if [ -f "zones/db.example.com.att" ]; then
    echo "✓ Attacker DNS zone file found"
else
    echo "✗ Attacker DNS zone file NOT found"
    MISSING=1
fi

echo ""
echo "Checking test scripts..."
for script in tests/run_all_tests.sh tests/collect_logs.sh; do
    if [ -f "$script" ]; then
        if [ -x "$script" ]; then
            echo "✓ $script exists and is executable"
        else
            echo "⚠ $script exists but is not executable (run: chmod +x $script)"
        fi
    else
        echo "✗ $script NOT found"
        MISSING=1
    fi
done

echo ""
echo "========================================"
if [ $MISSING -eq 0 ]; then
    echo "✓ Environment check PASSED"
    echo "You can run the test suite with:"
    echo "  sudo ./tests/run_all_tests.sh"
else
    echo "✗ Environment check FAILED"
    echo "Please install missing dependencies:"
    echo "  sudo apt-get update"
    echo "  sudo apt-get install -y bind9 dnsutils swaks tcpdump"
    echo ""
    echo "Note: Python 3 is typically pre-installed on Ubuntu/Debian."
    echo "If missing, install with: sudo apt-get install -y python3"
fi
echo "========================================"
