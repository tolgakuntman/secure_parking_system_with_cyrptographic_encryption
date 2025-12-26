# Security Test Suite - Demo Instructions

## Quick Start (For Professor)

To run all 11 security test scenarios automatically in sequence:

```bash
./start.sh
```

That's it! The script will:
1. ✅ Create a 6-pane interactive dashboard
2. ✅ Run all 11 test scenarios automatically, one after another
3. ✅ Show real-time logs from all services
4. ✅ Display test results and summaries
5. ✅ Save detailed logs for each scenario

## Dashboard Layout

```
┌──────────────────┬──────────────────┬──────────────────┐
│     CAUTH        │       SP         │       HO         │
│  Certificate     │  Service         │  Home Owner      │
│  Authority       │  Provider        │  (Payment Host)  │
├──────────────────┼──────────────────┼──────────────────┤
│       CO         │   FAKE-CAUTH     │  TEST RUNNER     │
│  Car Owner       │  Rogue CA        │  Orchestrator    │
│  (Test Client)   │  (Attack Sim)    │  (Progress)      │
└──────────────────┴──────────────────┴──────────────────┘
```

### Pane Functions:

- **CAUTH**: Real certificate authority logs (legitimate CA)
- **SP**: Service provider logs (token verification, settlement)
- **HO**: Home owner logs (payment acceptance)
- **CO**: Car owner logs (client showing current test execution)
- **FAKE-CAUTH**: Rogue CA logs (only active during CAuth-1 test)
- **TEST RUNNER**: Test orchestration (shows progress, results, summaries)

## Test Scenarios (11 Total)

### ✅ 1. P1_HONEST - Happy Path Baseline
Normal operation demonstrating correct system behavior.
- CO enrolls with legitimate CA
- Obtains valid certificate
- Makes successful payment
- All security checks pass

### 🔴 2. M4.1_TOKEN_TAMPER - Token Integrity Attack
Attacker tampers with payment token bytes.
- CO flips 1 byte in token[0]
- HO detects hash chain violation
- **Expected**: Payment REJECTED (tampering detected)

### 🔴 3. M4.2_REPLAY_PROD - Replay Attack (HO Detection)
Attacker replays same payment request twice.
- CO sends identical /pay request twice
- HO detects duplicate startIndex
- **Expected**: 2nd payment REJECTED (replay detected at HO)

### 🔴 4. M4.2_REPLAY_SP - Replay Attack (SP Detection)
Replay attack with HO in test mode (allows duplicate to reach SP).
- HO allows duplicate payment through (test mode)
- SP detects tokens already spent
- **Expected**: 2nd settle REJECTED (double-spend detected at SP)

### 🔴 5. CAuth-1_FAKE_CAUTH - Rogue CA Attack
Attacker sets up fake certificate authority.
- CO attempts enrollment with fake-cauth
- Fake-cauth issues self-signed certificate
- SP rejects mTLS (certificate not chained to Root CA)
- **Expected**: Connection REJECTED (PKIX validation failure)

### 🔴 6. ROGUE_CO_MISSING - Unauthorized Client (No Cert)
Attacker attempts connection without certificate.
- CO skips enrollment (no certificate)
- Attempts mTLS to SP without presenting cert
- **Expected**: Connection REJECTED (peer not authenticated)

### 🔴 7. ROGUE_CO_SELF_SIGNED - Unauthorized Client (Untrusted Cert)
Attacker generates self-signed certificate.
- CO creates self-signed certificate (not from CA)
- Presents certificate during mTLS handshake
- SP validates certificate chain
- **Expected**: Connection REJECTED (PKIX path validation fails)

### 🔴 8. RESV_TAMPER_FIELD_EDIT - Reservation Price Tampering
Attacker modifies reservation price field.
- CO receives signed reservation from HO
- CO changes `priceTokens=5` to `priceTokens=1`
- CO verifies signature against original data
- **Expected**: Verification FAILS (signature mismatch)

### 🔴 9. RESV_TAMPER_REORDER - Reservation Field Reordering
Attacker reorders fields in signed data.
- CO receives signed reservation from HO
- CO swaps order of first two fields
- CO reconstructs canonical order for verification
- **Expected**: Verification FAILS (data mismatch)

### 🔴 10. RESV_TAMPER_SIG_FLIP - Reservation Signature Corruption
Attacker corrupts signature bytes.
- CO receives signed reservation from HO
- CO flips 1 bit in signature byte
- CO performs RSA signature verification
- **Expected**: Verification FAILS (SignatureException)

### 🔴 11. RESV_TAMPER_DROP_FIELD - Reservation Field Removal
Attacker removes required field from signed data.
- CO receives signed reservation from HO
- CO removes `coIdentity` field
- CO reconstructs full canonical data
- **Expected**: Verification FAILS (missing field detected)

## Test Flow

For each scenario, the test runner:

1. **Preparation**
   - Cleans CO keystore (forces fresh enrollment)
   - Ensures correct services are running
   - Waits for services to be ready

2. **Execution**
   - Runs CO with appropriate NEG_TEST_MODE
   - Sets environment variables for the attack scenario
   - Logs output to scenario-specific directory

3. **Verification**
   - Checks exit code (0 = security worked, attack detected)
   - Records PASS/FAIL result
   - Displays status in TEST RUNNER pane

4. **Cleanup**
   - Pauses between tests (3 seconds)
   - Restores services to normal state if modified

## Output Locations

### Real-Time Display
- Watch all 6 panes simultaneously in tmux dashboard
- TEST RUNNER shows progress and summaries
- Service panes show detailed logs

### Saved Logs
All test outputs saved to timestamped directory:
```
logs/demo_run_YYYYMMDD_HHMMSS/
├── P1_HONEST/
│   └── co_output.txt
├── M4.1_TOKEN_TAMPER/
│   └── co_output.txt
├── M4.2_REPLAY_PROD/
│   └── co_output.txt
├── M4.2_REPLAY_SP/
│   └── co_output.txt
├── CAuth-1_FAKE_CAUTH/
│   └── co_output.txt
├── ROGUE_CO_MISSING/
│   └── co_output.txt
├── ROGUE_CO_SELF_SIGNED/
│   └── co_output.txt
├── RESV_TAMPER_FIELD_EDIT/
│   └── co_output.txt
├── RESV_TAMPER_REORDER/
│   └── co_output.txt
├── RESV_TAMPER_SIG_FLIP/
│   └── co_output.txt
└── RESV_TAMPER_DROP_FIELD/
    └── co_output.txt
```

## Navigation (tmux Controls)

While in the dashboard:

- **Ctrl+B, Q**: Show pane numbers
- **Ctrl+B, Arrow Keys**: Navigate between panes
- **Ctrl+B, [**: Enter scroll mode (use arrow keys, PgUp/PgDn to scroll)
  - Press **q** to exit scroll mode
- **Ctrl+B, D**: Detach (dashboard continues running in background)
  - Reattach with: `tmux attach -t security-test-suite`
- **Ctrl+B, Z**: Zoom into current pane (full screen)
  - Press again to zoom out
- **Mouse**: Click to switch panes, scroll wheel to scroll history

## Expected Runtime

- **Total time**: ~5-8 minutes for all 11 scenarios
- Each test takes 20-40 seconds (including service startup)
- Includes 3-second delay between tests for visibility

## Test Result Summary

At the end, you'll see:
```
═══════════════════════════════════════════════════════════════
                        TEST SUMMARY
═══════════════════════════════════════════════════════════════

Results by scenario:

  ✓ PASS  P1_HONEST
  ✓ PASS  M4.1_TOKEN_TAMPER
  ✓ PASS  M4.2_REPLAY_PROD
  ✓ PASS  M4.2_REPLAY_SP
  ✓ PASS  CAuth-1_FAKE_CAUTH
  ✓ PASS  ROGUE_CO_MISSING
  ✓ PASS  ROGUE_CO_SELF_SIGNED
  ✓ PASS  RESV_TAMPER_FIELD_EDIT
  ✓ PASS  RESV_TAMPER_REORDER
  ✓ PASS  RESV_TAMPER_SIG_FLIP
  ✓ PASS  RESV_TAMPER_DROP_FIELD

Overall: 11/11 passed, 0/11 failed

Logs saved to: ./logs/demo_run_20251226_143022
```

## Troubleshooting

### If tests fail:

1. **Check service logs**: Navigate to CAUTH/SP/HO panes to see detailed errors
2. **Review CO output**: Check CO pane for client-side errors
3. **Inspect saved logs**: Look in `logs/demo_run_*/` directories
4. **Verify Docker**: Ensure Docker is running and has sufficient resources
5. **Clean start**: Run `docker compose down -v` before `./start.sh`

### If dashboard doesn't display correctly:

1. **Terminal size**: Ensure terminal is at least 120x40 characters
2. **Tmux installed**: Check with `tmux -V` (should be 2.0+)
3. **Reattach**: If detached, run `tmux attach -t security-test-suite`
4. **Force restart**: Kill session with `tmux kill-session -t security-test-suite`, then `./start.sh`

## Manual Test Execution (Alternative)

If you want to run individual scenarios manually:

```bash
# Start services
docker compose up -d cauth sp ho

# Run specific test
docker compose run --rm \
  -e NEG_TEST_MODE=TAMPER \
  co

# Or for fake-cauth test
docker compose up -d fake-cauth sp ho
docker compose run --rm \
  -e NEG_TEST_MODE=FAKE_CAUTH \
  -e CAUTH_HOST=fake-cauth \
  co
```

## Architecture Highlights

### Security Properties Demonstrated:

1. **Certificate Chain Validation** (CAuth-1, ROGUE_CO)
   - Only certificates chained to Root CA are trusted
   - Self-signed certificates rejected
   - Rogue intermediate CAs rejected

2. **Mutual TLS (mTLS)** (All scenarios)
   - Both client and server authenticate
   - Certificate validation enforced bidirectionally
   - No bypass mechanisms

3. **Token Integrity** (M4.1)
   - Hash chain verification
   - Any byte modification detected
   - Adjacency checks prevent tampering

4. **Replay Protection** (M4.2)
   - Duplicate payment detection at multiple layers
   - HO tracks spent startIndex values
   - SP maintains monotonic spend state

5. **Digital Signatures** (RESV_TAMPER)
   - RSA signature on reservations
   - Canonical data reconstruction
   - Field order, values, and completeness enforced

### Defense in Depth:

- **Early Rejection**: Attacks caught at first opportunity (e.g., TLS handshake)
- **Layered Validation**: Multiple checks (HO validates, SP validates)
- **Fail-Closed**: Any validation failure aborts transaction
- **Cryptographic Enforcement**: Security properties enforced by crypto primitives

## Design Philosophy

This test suite demonstrates **automated security validation**:
- No manual intervention required
- All scenarios run sequentially
- Clear pass/fail criteria for each test
- Comprehensive coverage of attack vectors
- Real-time visibility into system behavior

The 6-pane dashboard provides **educational value**:
- See interactions between services in real-time
- Understand how attacks are detected
- Observe defense-in-depth at multiple layers
- Trace security events from client to server

---

**For questions or issues, refer to M4_TEST_GUIDE.md for detailed scenario documentation.**
