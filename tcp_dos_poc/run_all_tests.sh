#!/bin/bash
#
# Run all TCP DoS PoC tests
#
# This script runs all vulnerability tests in sequence and generates a report.
# Use this for comprehensive testing of the TCP implementation.
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-] This script must be run as root${NC}"
    echo "Please run with: sudo $0 $@"
    exit 1
fi

# Parse arguments
if [ $# -lt 2 ]; then
    echo "Usage: $0 <target_ip> <target_port> [test_level]"
    echo ""
    echo "Arguments:"
    echo "  target_ip    - IP address of target TCP server"
    echo "  target_port  - TCP port number"
    echo "  test_level   - quick, normal, or thorough (default: normal)"
    echo ""
    echo "Examples:"
    echo "  sudo $0 10.0.0.2 8080"
    echo "  sudo $0 10.0.0.2 8080 quick"
    echo "  sudo $0 10.0.0.2 8080 thorough"
    exit 1
fi

TARGET_IP=$1
TARGET_PORT=$2
TEST_LEVEL=${3:-normal}

REPORT_FILE="dos_test_report_$(date +%Y%m%d_%H%M%S).txt"

# Test level parameters
case $TEST_LEVEL in
    quick)
        CHALLENGE_RATE=100
        CHALLENGE_DURATION=10
        OOO_SEGMENTS=1000
        CONNECTIONS=500
        ;;
    normal)
        CHALLENGE_RATE=500
        CHALLENGE_DURATION=20
        OOO_SEGMENTS=5000
        CONNECTIONS=1000
        ;;
    thorough)
        CHALLENGE_RATE=1000
        CHALLENGE_DURATION=30
        OOO_SEGMENTS=20000
        CONNECTIONS=2000
        ;;
    *)
        echo -e "${RED}Invalid test level: $TEST_LEVEL${NC}"
        exit 1
        ;;
esac

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          TCP DoS Vulnerability Test Suite                ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Target:${NC}      $TARGET_IP:$TARGET_PORT"
echo -e "${GREEN}Test Level:${NC}  $TEST_LEVEL"
echo -e "${GREEN}Report:${NC}      $REPORT_FILE"
echo ""

# Check if target is reachable
echo -e "${YELLOW}[*] Checking if target is reachable...${NC}"
if timeout 5 bash -c "echo > /dev/tcp/$TARGET_IP/$TARGET_PORT" 2>/dev/null; then
    echo -e "${GREEN}[+] Target is reachable${NC}"
else
    echo -e "${RED}[-] Target is not reachable${NC}"
    echo "    Make sure the target is running and accessible"
    exit 1
fi

echo ""
read -p "Proceed with all tests? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Initialize report
{
    echo "TCP DoS Vulnerability Test Report"
    echo "=================================="
    echo ""
    echo "Date:        $(date)"
    echo "Target:      $TARGET_IP:$TARGET_PORT"
    echo "Test Level:  $TEST_LEVEL"
    echo ""
    echo "="*60
    echo ""
} > "$REPORT_FILE"

# Function to run a test and capture results
run_test() {
    local test_name=$1
    local test_script=$2
    shift 2
    local test_args="$@"

    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${BLUE}Running: $test_name${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    {
        echo ""
        echo "Test: $test_name"
        echo "Time: $(date)"
        echo "Command: python3 $test_script $test_args"
        echo "-"*60
    } >> "$REPORT_FILE"

    # Run the test and capture output
    if python3 "$test_script" $test_args 2>&1 | tee -a "$REPORT_FILE"; then
        echo -e "\n${GREEN}[+] Test completed${NC}"
        echo "[COMPLETED]" >> "$REPORT_FILE"
    else
        echo -e "\n${RED}[-] Test failed or was interrupted${NC}"
        echo "[FAILED]" >> "$REPORT_FILE"
    fi

    # Wait a bit between tests for system to recover
    echo -e "\n${YELLOW}[*] Waiting 10 seconds for system to stabilize...${NC}"
    sleep 10
}

# Test 1: Challenge ACK Storm
run_test "Challenge ACK Storm" \
    "challenge_ack_storm.py" \
    "--target $TARGET_IP --port $TARGET_PORT --rate $CHALLENGE_RATE" \
    <<< "y"

# Test 2: Out-of-Order Segment DoS
run_test "Out-of-Order Segment Memory Exhaustion" \
    "ooo_segment_dos.py" \
    "--target $TARGET_IP --port $TARGET_PORT --segments $OOO_SEGMENTS" \
    <<< "y"

# Test 3: Connection Exhaustion (RST method)
run_test "Connection Exhaustion (RST)" \
    "connection_exhaustion.py" \
    "--target $TARGET_IP --port $TARGET_PORT --connections $CONNECTIONS --method rst" \
    <<< "y"

# Test 4: Connection Exhaustion (Half-open method)
run_test "Connection Exhaustion (Half-Open)" \
    "connection_exhaustion.py" \
    "--target $TARGET_IP --port $TARGET_PORT --connections $CONNECTIONS --method half-open" \
    <<< "y"

# Final summary
echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}All Tests Complete${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

# Add summary to report
{
    echo ""
    echo "="*60
    echo "SUMMARY"
    echo "="*60
    echo ""
    echo "All tests completed at $(date)"
    echo ""
    echo "Review the results above to determine:"
    echo "  1. Challenge ACK rate limiting effectiveness"
    echo "  2. Out-of-order queue memory management"
    echo "  3. Connection resource cleanup"
    echo "  4. Overall DoS resilience"
    echo ""
    echo "Recommendations will be included in each test section."
    echo ""
} >> "$REPORT_FILE"

echo -e "${GREEN}[+] Report saved to: $REPORT_FILE${NC}"
echo ""
echo "Next steps:"
echo "  1. Review the report for vulnerability indicators"
echo "  2. Check target system logs for errors or crashes"
echo "  3. Apply fixes from TCP_REVIEW.md for any confirmed vulnerabilities"
echo "  4. Re-run tests after fixes to verify mitigation"
echo ""
