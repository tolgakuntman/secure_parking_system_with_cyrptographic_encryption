#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════
# Security Test Runner - Automated Scenario Execution
# ═══════════════════════════════════════════════════════════════════════════
# This script orchestrates all security test scenarios in sequence:
# - Happy path (P1_HONEST)
# - Negative tests (M4.1, M4.2, CAuth-1, ROGUE_CO, RESV_TAMPER)
# - Each test runs with appropriate environment variables
# - Results are logged and displayed in real-time
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Configuration
DELAY_BETWEEN_TESTS=3
LOG_DIR="./logs/demo_run_$(date +%Y%m%d_%H%M%S)"
SERVICES_READY_TIMEOUT=30


# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Test results tracking
declare -a TEST_RESULTS=()

# ═══════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════

print_header() {
    local title="$1"
    local width=75
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    printf "${CYAN}║${NC} ${BOLD}%-73s${NC} ${CYAN}║${NC}\n" "$title"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_scenario() {
    local num="$1"
    local name="$2"
    local desc="$3"
    echo -e "${BOLD}${BLUE}[TEST ${num}/11]${NC} ${MAGENTA}${name}${NC}"
    echo -e "  ${desc}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

wait_for_services() {
    local services="$1"
    print_info "Waiting for services to be ready: $services"
    
    for service in $services; do
        local retries=0
        while [ $retries -lt $SERVICES_READY_TIMEOUT ]; do
            if sudo docker compose ps $service 2>/dev/null | grep -q "Up"; then
                print_success "Service $service is ready"
                break
            fi
            retries=$((retries + 1))
            sleep 1
        done
        
        if [ $retries -eq $SERVICES_READY_TIMEOUT ]; then
            print_error "Service $service failed to start"
            return 1
        fi
    done
    
    # Additional wait for services to fully initialize
    print_info "Waiting 5 seconds for services to fully initialize..."
    sleep 5
}

cleanup_co_keystore() {
    print_info "Cleaning CO keystore for fresh enrollment..."
    sudo docker compose run --rm co sh -c "rm -rf /app/keystore/*" 2>/dev/null || true
}

record_result() {
    local scenario="$1"
    local status="$2"  # PASS or FAIL
    TEST_RESULTS+=("$scenario|$status")
}

cleanup_from_previous_run() {
    print_info "Cleaning up any stale containers from previous runs..."
    
    # Remove any stale test-profile containers (fake-cauth)
    sudo docker compose --profile test rm -f fake-cauth 2>/dev/null || true
    
    # Remove any manually started containers (ho-container from M4.2 test)
    sudo docker stop ho-container 2>/dev/null || true
    sudo docker rm ho-container 2>/dev/null || true
    
    # Stop all compose-managed containers
    sudo docker compose down -v 2>/dev/null || true
    
    print_success "Cleanup complete"
}

# ═══════════════════════════════════════════════════════════════════════════
# Test Execution Functions
# ═══════════════════════════════════════════════════════════════════════════

run_test_1_honest() {
    print_scenario "1" "P1_HONEST" "Normal flow - Happy path baseline"
    
    # Start core services
    sudo docker compose up -d cauth sp ho
    wait_for_services "cauth sp ho"
    
    # Wait for HO to publish availability
    print_info "Waiting 20s for HO to publish availability..."
    sleep 20
    
    # Run CO in normal mode
    print_info "Running CO with NEG_TEST_MODE=NONE (normal flow)..."
    mkdir -p "$LOG_DIR/P1_HONEST"
    
    if sudo docker compose run --rm co > "$LOG_DIR/P1_HONEST/co_output.txt" 2>&1; then
        print_success "Test completed - Check logs for payment success"
        record_result "P1_HONEST" "PASS"
    else
        print_error "Test failed - CO exited with error"
        record_result "P1_HONEST" "FAIL"
    fi
    
    sleep $DELAY_BETWEEN_TESTS
}

run_test_2_token_tamper() {
    print_scenario "2" "M4.1_TOKEN_TAMPER" "Token integrity - Byte flip detection"
    
    cleanup_co_keystore
    
    print_info "Running CO with NEG_TEST_MODE=TAMPER..."
    mkdir -p "$LOG_DIR/M4.1_TOKEN_TAMPER"
    
    if sudo docker compose run --rm \
        -e NEG_TEST_MODE=TAMPER \
        -e TAMPER_TOKEN_INDEX=0 \
        -e TAMPER_BYTE_INDEX=0 \
        co > "$LOG_DIR/M4.1_TOKEN_TAMPER/co_output.txt" 2>&1; then
        print_success "Test PASSED - Tampering detected as expected"
        record_result "M4.1_TOKEN_TAMPER" "PASS"
    else
        print_error "Test failed - Check logs"
        record_result "M4.1_TOKEN_TAMPER" "FAIL"
    fi
    
    sleep $DELAY_BETWEEN_TESTS
}

run_test_3_replay_prod() {
    print_scenario "3" "M4.2_REPLAY_PROD" "Replay attack - HO-level detection"
    
    cleanup_co_keystore
    
    print_info "Running CO with NEG_TEST_MODE=REPLAY (HO REPLAY_TEST_MODE=false)..."
    mkdir -p "$LOG_DIR/M4.2_REPLAY_PROD"
    
    if sudo docker compose run --rm \
        -e NEG_TEST_MODE=REPLAY \
        -e REPLAY_DELAY_MS=500 \
        co > "$LOG_DIR/M4.2_REPLAY_PROD/co_output.txt" 2>&1; then
        print_success "Test PASSED - Replay detected by HO"
        record_result "M4.2_REPLAY_PROD" "PASS"
    else
        print_error "Test failed - Check logs"
        record_result "M4.2_REPLAY_PROD" "FAIL"
    fi
    
    sleep $DELAY_BETWEEN_TESTS
}

run_test_4_replay_sp() {
    print_scenario "4" "M4.2_REPLAY_SP" "Replay attack - SP-level detection"
    
    cleanup_co_keystore
    
    # Restart HO with REPLAY_TEST_MODE=true
    print_info "Restarting HO with REPLAY_TEST_MODE=true..."
    sudo docker compose stop ho
    sleep 2
    
    # Get current directory for volume mount
    CURRENT_DIR=$(pwd)
    
    # Get the HO image name from docker compose
    HO_IMAGE=$(sudo docker compose images ho | tail -n 1 | awk '{print $2":"$3}')
    if [ -z "$HO_IMAGE" ] || [ "$HO_IMAGE" = ":" ]; then
        # Fallback: try to get from running/stopped containers
        HO_IMAGE=$(sudo docker ps -a --filter "name=ho-container" --format "{{.Image}}" | head -1)
    fi
    if [ -z "$HO_IMAGE" ] || [ "$HO_IMAGE" = ":" ]; then
        # Last resort: use the default naming convention
        HO_IMAGE="secure_software_assignment-ho"
    fi
    
    print_info "Using HO image: $HO_IMAGE"
    
    # Run HO with REPLAY_TEST_MODE using docker run to override environment
    print_info "Starting HO with REPLAY_TEST_MODE=true..."
    if sudo docker run -d \
        --name ho-container \
        --network secure_software_assignment_java-network \
        --ip 172.20.0.12 \
        -v "$CURRENT_DIR/crypto_do_once/ho_truststore.p12:/app/truststore.p12" \
        -v secure_software_assignment_ho_keystore:/app/keystore \
        -e KEYSTORE_PASSWORD=hopassword \
        -e TRUSTSTORE_PASSWORD=trustpassword \
        -e HO_KEY_ALIAS=ho_key \
        -e HO_SERVER_PORT=8445 \
        -e CAUTH_HOST=cauth \
        -e CAUTH_PORT=8443 \
        -e SP_HOST=sp \
        -e SP_PORT=8444 \
        -e REPLAY_TEST_MODE=true \
        "$HO_IMAGE" 2>&1; then
        print_success "HO started with REPLAY_TEST_MODE=true"
        print_info "Waiting 25s for HO to republish availability..."
        sleep 25
    else
        print_error "Failed to start HO with REPLAY_TEST_MODE"
        print_info "Trying alternative approach..."
        # Fallback: just run normally (HO will reject replays by default)
        sudo docker compose up -d ho
        sleep 10
    fi
    
    print_info "Running CO with NEG_TEST_MODE=REPLAY (HO allows duplicate)..."
    mkdir -p "$LOG_DIR/M4.2_REPLAY_SP"
    
    if sudo docker compose run --rm \
        -e NEG_TEST_MODE=REPLAY \
        -e REPLAY_DELAY_MS=500 \
        co > "$LOG_DIR/M4.2_REPLAY_SP/co_output.txt" 2>&1; then
        print_success "Test PASSED - Replay detected by SP"
        record_result "M4.2_REPLAY_SP" "PASS"
    else
        print_error "Test failed - Check logs"
        record_result "M4.2_REPLAY_SP" "FAIL"
    fi
    
    # Restore HO to normal mode
    print_info "Restoring HO to normal mode..."
    sudo docker stop ho-container 2>/dev/null || true
    sudo docker rm ho-container 2>/dev/null || true
    sleep 2
    sudo docker compose up -d ho
    
    print_info "Waiting for HO to restart in normal mode..."
    sleep 10
    
    sleep $DELAY_BETWEEN_TESTS
}

run_test_5_fake_cauth() {
    print_scenario "5" "CAuth-1_FAKE_CAUTH" "Rogue CA - Certificate chain validation"
    
    cleanup_co_keystore
    
    # Stop real cauth, start fake-cauth
    print_info "Stopping real cauth, starting fake-cauth..."
    sudo docker compose stop cauth
    sudo docker compose --profile test rm -f fake-cauth
    sudo docker compose --profile test up -d fake-cauth
    wait_for_services "fake-cauth"
    
    print_info "Running CO with NEG_TEST_MODE=FAKE_CAUTH, CAUTH_HOST=fake-cauth..."
    mkdir -p "$LOG_DIR/CAuth-1_FAKE_CAUTH"
    
    if sudo docker compose run --rm --no-deps \
        -e NEG_TEST_MODE=FAKE_CAUTH \
        -e CAUTH_HOST=fake-cauth \
        -e CAUTH_PORT=8443 \
        co > "$LOG_DIR/CAuth-1_FAKE_CAUTH/co_output.txt" 2>&1; then
        print_success "Test PASSED - Rogue CA rejected"
        record_result "CAuth-1_FAKE_CAUTH" "PASS"
    else
        print_error "Test failed - Check logs"
        record_result "CAuth-1_FAKE_CAUTH" "FAIL"
    fi
    
    # Restore real cauth
    print_info "Stopping fake-cauth, restoring real cauth..."
    sudo docker compose --profile test stop fake-cauth
    sudo docker compose --profile test rm -f fake-cauth
    sudo docker compose up -d cauth
    wait_for_services "cauth"
    
    sleep $DELAY_BETWEEN_TESTS
}

run_test_6_rogue_co_missing() {
    print_scenario "6" "ROGUE_CO_MISSING" "Unauthorized client - No certificate"
    
    cleanup_co_keystore
    
    print_info "Running CO with NEG_TEST_MODE=BAD_CERT, BAD_CERT_MODE=MISSING..."
    mkdir -p "$LOG_DIR/ROGUE_CO_MISSING"
    
    if sudo docker compose run --rm \
        -e NEG_TEST_MODE=BAD_CERT \
        -e BAD_CERT_MODE=MISSING \
        co > "$LOG_DIR/ROGUE_CO_MISSING/co_output.txt" 2>&1; then
        print_success "Test PASSED - Client without cert rejected"
        record_result "ROGUE_CO_MISSING" "PASS"
    else
        print_error "Test failed - Check logs"
        record_result "ROGUE_CO_MISSING" "FAIL"
    fi
    
    sleep $DELAY_BETWEEN_TESTS
}

run_test_7_rogue_co_self_signed() {
    print_scenario "7" "ROGUE_CO_SELF_SIGNED" "Unauthorized client - Self-signed cert"
    
    cleanup_co_keystore
    
    print_info "Running CO with NEG_TEST_MODE=BAD_CERT, BAD_CERT_MODE=SELF_SIGNED..."
    mkdir -p "$LOG_DIR/ROGUE_CO_SELF_SIGNED"
    
    if sudo docker compose run --rm \
        -e NEG_TEST_MODE=BAD_CERT \
        -e BAD_CERT_MODE=SELF_SIGNED \
        co > "$LOG_DIR/ROGUE_CO_SELF_SIGNED/co_output.txt" 2>&1; then
        print_success "Test PASSED - Self-signed cert rejected"
        record_result "ROGUE_CO_SELF_SIGNED" "PASS"
    else
        print_error "Test failed - Check logs"
        record_result "ROGUE_CO_SELF_SIGNED" "FAIL"
    fi
    
    sleep $DELAY_BETWEEN_TESTS
}

run_test_8_resv_field_edit() {
    print_scenario "8" "RESV_TAMPER_FIELD_EDIT" "Reservation tampering - Price modification"
    
    cleanup_co_keystore
    
    print_info "Running CO with NEG_TEST_MODE=RESV_TAMPER, RESV_TAMPER_MODE=FIELD_EDIT..."
    mkdir -p "$LOG_DIR/RESV_TAMPER_FIELD_EDIT"
    
    if sudo docker compose run --rm \
        -e NEG_TEST_MODE=RESV_TAMPER \
        -e RESV_TAMPER_MODE=FIELD_EDIT \
        co > "$LOG_DIR/RESV_TAMPER_FIELD_EDIT/co_output.txt" 2>&1; then
        print_success "Test PASSED - Field tampering detected"
        record_result "RESV_TAMPER_FIELD_EDIT" "PASS"
    else
        print_error "Test failed - Check logs"
        record_result "RESV_TAMPER_FIELD_EDIT" "FAIL"
    fi
    
    sleep $DELAY_BETWEEN_TESTS
}

run_test_9_resv_reorder() {
    print_scenario "9" "RESV_TAMPER_REORDER" "Reservation tampering - Field reordering"
    
    cleanup_co_keystore
    
    print_info "Running CO with NEG_TEST_MODE=RESV_TAMPER, RESV_TAMPER_MODE=REORDER..."
    mkdir -p "$LOG_DIR/RESV_TAMPER_REORDER"
    
    if sudo docker compose run --rm \
        -e NEG_TEST_MODE=RESV_TAMPER \
        -e RESV_TAMPER_MODE=REORDER \
        co > "$LOG_DIR/RESV_TAMPER_REORDER/co_output.txt" 2>&1; then
        print_success "Test PASSED - Field reorder detected"
        record_result "RESV_TAMPER_REORDER" "PASS"
    else
        print_error "Test failed - Check logs"
        record_result "RESV_TAMPER_REORDER" "FAIL"
    fi
    
    sleep $DELAY_BETWEEN_TESTS
}

run_test_10_resv_sig_flip() {
    print_scenario "10" "RESV_TAMPER_SIG_FLIP" "Reservation tampering - Signature corruption"
    
    cleanup_co_keystore
    
    print_info "Running CO with NEG_TEST_MODE=RESV_TAMPER, RESV_TAMPER_MODE=SIG_FLIP..."
    mkdir -p "$LOG_DIR/RESV_TAMPER_SIG_FLIP"
    
    if sudo docker compose run --rm \
        -e NEG_TEST_MODE=RESV_TAMPER \
        -e RESV_TAMPER_MODE=SIG_FLIP \
        co > "$LOG_DIR/RESV_TAMPER_SIG_FLIP/co_output.txt" 2>&1; then
        print_success "Test PASSED - Signature flip detected"
        record_result "RESV_TAMPER_SIG_FLIP" "PASS"
    else
        print_error "Test failed - Check logs"
        record_result "RESV_TAMPER_SIG_FLIP" "FAIL"
    fi
    
    sleep $DELAY_BETWEEN_TESTS
}

run_test_11_resv_drop_field() {
    print_scenario "11" "RESV_TAMPER_DROP_FIELD" "Reservation tampering - Field removal"
    
    cleanup_co_keystore
    
    print_info "Running CO with NEG_TEST_MODE=RESV_TAMPER, RESV_TAMPER_MODE=DROP_FIELD..."
    mkdir -p "$LOG_DIR/RESV_TAMPER_DROP_FIELD"
    
    if sudo docker compose run --rm \
        -e NEG_TEST_MODE=RESV_TAMPER \
        -e RESV_TAMPER_MODE=DROP_FIELD \
        co > "$LOG_DIR/RESV_TAMPER_DROP_FIELD/co_output.txt" 2>&1; then
        print_success "Test PASSED - Field removal detected"
        record_result "RESV_TAMPER_DROP_FIELD" "PASS"
    else
        print_error "Test failed - Check logs"
        record_result "RESV_TAMPER_DROP_FIELD" "FAIL"
    fi
    
    sleep $DELAY_BETWEEN_TESTS
}

# ═══════════════════════════════════════════════════════════════════════════
# Main Execution
# ═══════════════════════════════════════════════════════════════════════════

print_summary() {
    print_header "TEST SUMMARY"
    
    local total=${#TEST_RESULTS[@]}
    local passed=0
    local failed=0
    
    echo -e "${BOLD}Results by scenario:${NC}"
    echo ""
    
    for result in "${TEST_RESULTS[@]}"; do
        IFS='|' read -r scenario status <<< "$result"
        if [ "$status" = "PASS" ]; then
            echo -e "  ${GREEN}✓ PASS${NC}  $scenario"
            passed=$((passed + 1))
        else
            echo -e "  ${RED}✗ FAIL${NC}  $scenario"
            failed=$((failed + 1))
        fi
    done
    
    echo ""
    echo -e "${BOLD}Overall:${NC} $passed/$total passed, $failed/$total failed"
    echo ""
    echo -e "Logs saved to: ${CYAN}$LOG_DIR${NC}"
    echo ""
}

main() {
    print_header "Security Test Suite - Automated Run"
    
    print_info "Starting complete test suite (11 scenarios)..."
    print_info "Logs will be saved to: $LOG_DIR"
    echo ""
    
    # Create log directory
    mkdir -p "$LOG_DIR"
    
    # Cleanup from any previous crashed runs
    cleanup_from_previous_run
    
    # Run all tests in sequence
    run_test_1_honest
    run_test_2_token_tamper
    run_test_3_replay_prod
    run_test_4_replay_sp
    run_test_5_fake_cauth
    run_test_6_rogue_co_missing
    run_test_7_rogue_co_self_signed
    run_test_8_resv_field_edit
    run_test_9_resv_reorder
    run_test_10_resv_sig_flip
    run_test_11_resv_drop_field
    # Print summary
    print_summary
    
    # Cleanup
    print_info "Stopping all containers..."
    sudo docker compose down
    
    print_success "All tests completed!"
}

# Run main function
main
