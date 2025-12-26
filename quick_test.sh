#!/bin/bash

# Quick validation test - runs just one scenario to verify the system works
# This is faster than the full test suite (takes ~1 minute instead of 5-8)

set -euo pipefail

echo "════════════════════════════════════════════════════════════════"
echo "  Quick Validation Test"
echo "  Running P1_HONEST scenario to verify system works"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Clean up
echo "→ Cleaning up previous containers..."
sudo docker compose down -v 2>/dev/null || true
echo ""

# Start services
echo "→ Starting core services (cauth, sp, ho)..."
sudo docker compose up -d cauth sp ho
echo ""

# Wait for services
echo "→ Waiting for services to be ready..."
sleep 10

for service in cauth sp ho; do
    retries=0
    while [ $retries -lt 30 ]; do
        if sudo docker compose ps $service 2>/dev/null | grep -q "Up"; then
            echo "  ✓ $service is ready"
            break
        fi
        retries=$((retries + 1))
        sleep 1
    done
done
echo ""

# Wait for HO to publish availability
echo "→ Waiting 20 seconds for HO to publish availability..."
sleep 20
echo ""

# Run CO in normal mode
echo "→ Running CO with NEG_TEST_MODE=NONE (normal flow)..."
echo ""

if sudo docker compose run --rm co 2>&1 | tee /tmp/co_test_output.txt; then
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  ✓ TEST PASSED!"
    echo "  System is working correctly"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo "Key validations:"
    
    if grep -q "PAYMENT ACCEPTED" /tmp/co_test_output.txt; then
        echo "  ✓ Payment was accepted by HO"
    fi
    
    if grep -q "receipt" /tmp/co_test_output.txt; then
        echo "  ✓ Receipt was received"
    fi
    
    echo ""
    echo "The full test suite with all 11 scenarios is ready!"
    echo "To run it: ./start.sh"
    echo ""
    
    # Cleanup
    echo "→ Cleaning up test containers..."
    sudo docker compose down -v
    
    exit 0
else
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  ✗ TEST FAILED"
    echo "  Please check the output above for errors"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    
    # Show service logs for debugging
    echo "Service logs:"
    echo ""
    echo "--- CAUTH ---"
    sudo docker compose logs --tail 20 cauth
    echo ""
    echo "--- SP ---"
    sudo docker compose logs --tail 20 sp
    echo ""
    echo "--- HO ---"
    sudo docker compose logs --tail 20 ho
    echo ""
    
    # Cleanup
    sudo docker compose down -v
    
    exit 1
fi
