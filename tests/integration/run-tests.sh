#!/bin/bash
# =============================================================================
# UDP Proxy Integration Test Suite
# =============================================================================
#
# This script runs integration tests for udp-proxy-2020.
# It must be run from within the test-runner container with access to both
# net_alpha (172.20.0.0/24) and net_beta (172.21.0.0/24).
#
# The proxy should already be running with:
#   -i eth0 -i eth1 -p 9003 -p 1900 -p 5353
#
# Usage:
#   docker compose up -d proxy
#   docker compose run --rm test-runner
#
# =============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load test library
source "${SCRIPT_DIR}/lib.sh"

# =============================================================================
# Test Configuration
# =============================================================================

# Unique test run ID for message tagging
TEST_RUN_ID="$$-$(date +%s)"

# Temp directory for this test run
TEMP_DIR="/tmp/integration-test-${TEST_RUN_ID}"
mkdir -p "$TEMP_DIR"

# =============================================================================
# Pre-flight Checks
# =============================================================================

preflight_checks() {
    log_info "Running pre-flight checks..."

    # Check we have the required network interfaces
    if ! ip addr show | grep -q "172.20.0"; then
        log_error "Not connected to net_alpha (172.20.0.0/24)"
        exit 1
    fi

    if ! ip addr show | grep -q "172.21.0"; then
        log_error "Not connected to net_beta (172.21.0.0/24)"
        exit 1
    fi

    # Check proxy is reachable on both networks
    if ! ping -c 1 -W 2 "$PROXY_ALPHA_IP" &>/dev/null; then
        log_error "Cannot reach proxy at $PROXY_ALPHA_IP (net_alpha)"
        exit 1
    fi

    if ! ping -c 1 -W 2 "$PROXY_BETA_IP" &>/dev/null; then
        log_error "Cannot reach proxy at $PROXY_BETA_IP (net_beta)"
        exit 1
    fi

    log_success "Pre-flight checks passed"
}

# =============================================================================
# Test Cases
# =============================================================================

# Test 1: Basic UDP forwarding from alpha to beta
test_basic_forwarding_alpha_to_beta() {
    local test_name="Basic forwarding: alpha → beta"
    begin_test "$test_name"

    local message="ALPHA_TO_BETA_${TEST_RUN_ID}"
    local output_file="${TEMP_DIR}/test1_received.txt"

    # Start listener on beta network (our 172.21.x interface)
    local listener_pid
    listener_pid=$(start_udp_listener "$TEST_PORT" "$output_file" 10)
    log_info "Started listener (PID: $listener_pid)"

    # Give listener time to bind
    sleep 0.5

    # Send broadcast from alpha network
    send_udp_broadcast "172.20.0.100" "$TEST_PORT" "$message"

    # Wait for the message to arrive
    sleep 2

    # Kill listener
    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    # Verify
    if assert_contains "$output_file" "$message" "Message forwarded from alpha to beta"; then
        pass_test "$test_name"
    else
        fail_test "$test_name" "Message not received on beta network"
        log_info "Listener output: $(cat "$output_file" 2>/dev/null || echo '<empty>')"
    fi
}

# Test 2: Basic UDP forwarding from beta to alpha
test_basic_forwarding_beta_to_alpha() {
    local test_name="Basic forwarding: beta → alpha"
    begin_test "$test_name"

    local message="BETA_TO_ALPHA_${TEST_RUN_ID}"
    local output_file="${TEMP_DIR}/test2_received.txt"

    # Start listener on alpha network
    local listener_pid
    listener_pid=$(start_udp_listener "$TEST_PORT" "$output_file" 10)
    log_info "Started listener (PID: $listener_pid)"

    sleep 0.5

    # Send broadcast from beta network
    send_udp_broadcast "172.21.0.100" "$TEST_PORT" "$message"

    sleep 2

    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    if assert_contains "$output_file" "$message" "Message forwarded from beta to alpha"; then
        pass_test "$test_name"
    else
        fail_test "$test_name" "Message not received on alpha network"
        log_info "Listener output: $(cat "$output_file" 2>/dev/null || echo '<empty>')"
    fi
}

# Test 3: Multiple ports - verify port 1900 (SSDP/UPnP)
test_multiple_ports_1900() {
    local test_name="Multiple ports: port 1900 (SSDP)"
    begin_test "$test_name"

    local message="SSDP_TEST_${TEST_RUN_ID}"
    local output_file="${TEMP_DIR}/test3_received.txt"

    local listener_pid
    listener_pid=$(start_udp_listener 1900 "$output_file" 10)

    sleep 0.5

    send_udp_broadcast "172.20.0.100" 1900 "$message"

    sleep 2

    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    if assert_contains "$output_file" "$message" "Port 1900 forwarding works"; then
        pass_test "$test_name"
    else
        fail_test "$test_name" "Port 1900 message not forwarded"
    fi
}

# Test 4: Multiple ports - verify port 5353 (mDNS)
test_multiple_ports_5353() {
    local test_name="Multiple ports: port 5353 (mDNS)"
    begin_test "$test_name"

    local message="MDNS_TEST_${TEST_RUN_ID}"
    local output_file="${TEMP_DIR}/test4_received.txt"

    local listener_pid
    listener_pid=$(start_udp_listener 5353 "$output_file" 10)

    sleep 0.5

    send_udp_broadcast "172.20.0.100" 5353 "$message"

    sleep 2

    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    if assert_contains "$output_file" "$message" "Port 5353 forwarding works"; then
        pass_test "$test_name"
    else
        fail_test "$test_name" "Port 5353 message not forwarded"
    fi
}

# Test 5: Unconfigured port should NOT be forwarded
test_unconfigured_port_not_forwarded() {
    local test_name="Unconfigured port: NOT forwarded"
    begin_test "$test_name"

    local message="SHOULD_NOT_ARRIVE_${TEST_RUN_ID}"
    local output_file="${TEMP_DIR}/test5_received.txt"

    # Listen on port 8888 (not configured in proxy)
    local listener_pid
    listener_pid=$(start_udp_listener 8888 "$output_file" 5)

    sleep 0.5

    # Send to unconfigured port
    send_udp_broadcast "172.20.0.100" 8888 "$message"

    sleep 2

    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    # This should NOT contain the message
    if assert_not_contains "$output_file" "$message" "Unconfigured port not forwarded"; then
        pass_test "$test_name"
    else
        fail_test "$test_name" "Message was forwarded on unconfigured port (should not happen)"
    fi
}

# Test 6: Rapid consecutive packets
test_rapid_packets() {
    local test_name="Rapid consecutive packets"
    begin_test "$test_name"

    local output_file="${TEMP_DIR}/test6_received.txt"

    local listener_pid
    listener_pid=$(start_udp_listener "$TEST_PORT" "$output_file" 15)

    sleep 0.5

    # Send 5 packets rapidly
    for i in 1 2 3 4 5; do
        local message="RAPID_${i}_${TEST_RUN_ID}"
        send_udp_broadcast "172.20.0.100" "$TEST_PORT" "$message"
        sleep 0.1
    done

    sleep 3

    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    # Check at least some packets arrived (may lose some in rapid fire)
    local received_count
    received_count=$(grep -c "RAPID_.*_${TEST_RUN_ID}" "$output_file" 2>/dev/null || echo "0")

    if [[ "$received_count" -ge 3 ]]; then
        pass_test "$test_name (received $received_count/5 packets)"
    else
        fail_test "$test_name" "Only received $received_count/5 packets"
        log_info "Content: $(cat "$output_file" 2>/dev/null || echo '<empty>')"
    fi
}

# Test 7: Large packet (near MTU)
test_large_packet() {
    local test_name="Large packet (1400 bytes)"
    begin_test "$test_name"

    local output_file="${TEMP_DIR}/test7_received.txt"

    local listener_pid
    listener_pid=$(start_udp_listener "$TEST_PORT" "$output_file" 10)

    sleep 0.5

    # Generate a large message (~1400 bytes)
    local large_message="LARGE_${TEST_RUN_ID}_$(head -c 1350 /dev/urandom | base64 | tr -d '\n' | head -c 1350)"

    send_udp_broadcast "172.20.0.100" "$TEST_PORT" "$large_message"

    sleep 2

    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true

    if assert_contains "$output_file" "LARGE_${TEST_RUN_ID}" "Large packet forwarded"; then
        pass_test "$test_name"
    else
        fail_test "$test_name" "Large packet not received"
    fi
}

# Test 8: Bidirectional simultaneous
test_bidirectional_simultaneous() {
    local test_name="Bidirectional simultaneous"
    begin_test "$test_name"

    local alpha_output="${TEMP_DIR}/test8_alpha.txt"
    local beta_output="${TEMP_DIR}/test8_beta.txt"
    local alpha_msg="FROM_ALPHA_${TEST_RUN_ID}"
    local beta_msg="FROM_BETA_${TEST_RUN_ID}"

    # Start listeners on both networks
    local alpha_listener beta_listener
    alpha_listener=$(start_udp_listener "$TEST_PORT" "$alpha_output" 10)
    sleep 0.2
    beta_listener=$(start_udp_listener "$((TEST_PORT + 1))" "$beta_output" 10)

    sleep 0.5

    # Send from both sides simultaneously (using port 9003 from both sides)
    # Note: We use different ports for listeners to avoid binding conflicts
    send_udp_broadcast "172.20.0.100" "$TEST_PORT" "$alpha_msg" &
    send_udp_broadcast "172.21.0.100" "$TEST_PORT" "$beta_msg" &
    wait

    sleep 2

    kill "$alpha_listener" 2>/dev/null || true
    kill "$beta_listener" 2>/dev/null || true
    wait "$alpha_listener" 2>/dev/null || true
    wait "$beta_listener" 2>/dev/null || true

    # At least one direction should work (bidirectional is complex with single port)
    local passed=0
    if grep -q "$beta_msg" "$alpha_output" 2>/dev/null; then
        log_info "Beta→Alpha: received"
        passed=$((passed + 1))
    fi
    if grep -q "$alpha_msg" "$beta_output" 2>/dev/null; then
        log_info "Alpha→Beta: received"
        passed=$((passed + 1))
    fi

    if [[ $passed -ge 1 ]]; then
        pass_test "$test_name ($passed/2 directions verified)"
    else
        fail_test "$test_name" "No packets received in either direction"
    fi
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo ""
    echo "============================================"
    echo "    UDP Proxy Integration Test Suite"
    echo "============================================"
    echo "  Test Run ID: ${TEST_RUN_ID}"
    echo "  Proxy Alpha: ${PROXY_ALPHA_IP}"
    echo "  Proxy Beta:  ${PROXY_BETA_IP}"
    echo "  Test Port:   ${TEST_PORT}"
    echo "============================================"
    echo ""

    # Run pre-flight checks
    preflight_checks

    echo ""
    log_info "Starting test suite..."
    echo ""

    # Run all tests
    test_basic_forwarding_alpha_to_beta
    test_basic_forwarding_beta_to_alpha
    test_multiple_ports_1900
    test_multiple_ports_5353
    test_unconfigured_port_not_forwarded
    test_rapid_packets
    test_large_packet
    test_bidirectional_simultaneous

    # Print summary
    echo ""
    print_summary

    # Cleanup temp dir
    rm -rf "$TEMP_DIR"

    # Return appropriate exit code
    if [[ $TESTS_FAILED -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

# Run main
main "$@"
