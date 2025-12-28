#!/bin/bash
# Integration Test Library
# Common functions for UDP proxy integration tests

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================
PROXY_ALPHA_IP="${PROXY_ALPHA_IP:-172.20.0.2}"
PROXY_BETA_IP="${PROXY_BETA_IP:-172.21.0.2}"
TEST_PORT="${TEST_PORT:-9003}"
TIMEOUT="${TIMEOUT:-5}"
RESULTS_DIR="${RESULTS_DIR:-/results}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# =============================================================================
# Logging Functions
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_test() {
    echo -e "${BLUE}[TEST]${NC} $*"
}

# =============================================================================
# Test Framework Functions
# =============================================================================

# Start a test case
begin_test() {
    local test_name="$1"
    TESTS_RUN=$((TESTS_RUN + 1))
    log_test "Running: $test_name"
}

# Mark test as passed
pass_test() {
    local test_name="$1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    log_success "$test_name"
}

# Mark test as failed
fail_test() {
    local test_name="$1"
    local reason="${2:-}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    log_error "$test_name"
    if [[ -n "$reason" ]]; then
        echo "         Reason: $reason"
    fi
}

# Print test summary
print_summary() {
    echo ""
    echo "============================================"
    echo "         Integration Test Summary"
    echo "============================================"
    echo "  Tests Run:    $TESTS_RUN"
    echo -e "  Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "  Tests Failed: ${RED}$TESTS_FAILED${NC}"
    else
        echo "  Tests Failed: $TESTS_FAILED"
    fi
    echo "============================================"

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}Some tests failed.${NC}"
        return 1
    fi
}

# =============================================================================
# Network Utility Functions
# =============================================================================

# Wait for a service to be reachable
wait_for_host() {
    local host="$1"
    local max_attempts="${2:-30}"
    local attempt=0

    while ! ping -c 1 -W 1 "$host" &>/dev/null; do
        attempt=$((attempt + 1))
        if [[ $attempt -ge $max_attempts ]]; then
            log_error "Timeout waiting for $host"
            return 1
        fi
        sleep 0.5
    done
    return 0
}

# Get the interface name for a given IP
get_interface_for_ip() {
    local ip="$1"
    ip -o addr show | grep "$ip" | awk '{print $2}'
}

# =============================================================================
# UDP Test Functions
# =============================================================================

# Send a UDP packet to broadcast address
# Args: interface_ip port message
send_udp_broadcast() {
    local src_ip="$1"
    local port="$2"
    local message="$3"

    # Get the broadcast address for the source IP's network
    # For 172.20.0.x/24, broadcast is 172.20.0.255
    local network_prefix="${src_ip%.*}"
    local broadcast="${network_prefix}.255"

    log_info "Sending UDP to $broadcast:$port from $src_ip"
    echo -n "$message" | nc -u -w1 -b "$broadcast" "$port" 2>/dev/null || true
}

# Send a UDP packet to a specific address
# Args: dest_ip port message
send_udp() {
    local dest_ip="$1"
    local port="$2"
    local message="$3"

    log_info "Sending UDP to $dest_ip:$port"
    echo -n "$message" | nc -u -w1 "$dest_ip" "$port" 2>/dev/null || true
}

# Start a UDP listener in background
# Args: port output_file [timeout]
# Returns: PID of the listener
start_udp_listener() {
    local port="$1"
    local output_file="$2"
    local timeout="${3:-10}"

    # Clean up any existing listener on this port
    pkill -f "nc.*-l.*$port" 2>/dev/null || true
    sleep 0.2

    # Start listener with timeout
    timeout "$timeout" nc -u -l -p "$port" > "$output_file" 2>/dev/null &
    local pid=$!

    # Give it a moment to bind
    sleep 0.3

    echo "$pid"
}

# Wait for a file to contain expected content
# Args: file expected_content timeout
wait_for_content() {
    local file="$1"
    local expected="$2"
    local timeout="${3:-5}"
    local elapsed=0

    while [[ $elapsed -lt $timeout ]]; do
        if [[ -f "$file" ]] && grep -q "$expected" "$file" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
        elapsed=$((elapsed + 1))
    done
    return 1
}

# =============================================================================
# Test Assertions
# =============================================================================

# Assert that a file contains expected text
assert_contains() {
    local file="$1"
    local expected="$2"
    local description="$3"

    if [[ -f "$file" ]] && grep -q "$expected" "$file"; then
        return 0
    else
        log_error "Assertion failed: $description"
        log_error "Expected '$expected' in $file"
        if [[ -f "$file" ]]; then
            log_error "Actual content: $(cat "$file" 2>/dev/null || echo '<empty>')"
        else
            log_error "File does not exist"
        fi
        return 1
    fi
}

# Assert that a file does NOT contain text
assert_not_contains() {
    local file="$1"
    local unexpected="$2"
    local description="$3"

    if [[ ! -f "$file" ]] || ! grep -q "$unexpected" "$file"; then
        return 0
    else
        log_error "Assertion failed: $description"
        log_error "Did not expect '$unexpected' in $file"
        return 1
    fi
}

# =============================================================================
# Cleanup Functions
# =============================================================================

# Kill all background jobs
cleanup() {
    jobs -p | xargs -r kill 2>/dev/null || true
    wait 2>/dev/null || true
}

# Setup trap for cleanup
trap cleanup EXIT

# Create results directory if needed
mkdir -p "$RESULTS_DIR" 2>/dev/null || true
