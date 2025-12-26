# M4 Negative Scenarios Test Guide

This document explains how to test M4.1 (Token Tampering) and M4.2 (Replay Payment) security scenarios.

## Architecture Overview

Both negative scenarios are implemented as **toggleable test modes** using environment variables in CO (Car Owner):

### Environment Variables

**CO Configuration:**
- `NEG_TEST_MODE` (default: `NONE`)
  - `NONE` = normal M3.x flow (happy path)
  - `TAMPER` = M4.1 token tampering scenario
  - `REPLAY` = M4.2 replay payment scenario
  
- `TAMPER_TOKEN_INDEX` (default: `0`) - which token to tamper in M4.1
- `TAMPER_BYTE_INDEX` (default: `0`) - which byte to flip in that token
- `REPLAY_DELAY_MS` (default: `500`) - wait time between first and second /pay in M4.2

**HO Configuration:**
- `REPLAY_TEST_MODE` (default: `false`)
  - `true` = allow duplicate /pay requests for same reservationId (for testing)
  - `false` = normal strict duplicate rejection (production mode)

## Test Scenarios

### 1. Normal M3.x Flow (Happy Path)

**Command:**
```bash
docker compose up
```

**Expected Behavior:**
- CO enrolls, discovers availability, requests reservation
- CO sends valid payment tokens to HO
- HO accepts payment and calls SP settle
- SP verifies tokens and updates chain spend state
- Receipt returned to CO
- All green ✓

### 2. M4.1 Token Tampering

**Command:**
```bash
# Set NEG_TEST_MODE=TAMPER to trigger tampering
docker compose up -d cauth sp ho
docker compose run --rm \
  -e NEG_TEST_MODE=TAMPER \
  -e TAMPER_TOKEN_INDEX=0 \
  -e TAMPER_BYTE_INDEX=0 \
  co
```

**Expected Behavior:**

1. **CO Side:**
   - Generates valid payment request with token batch
   - Logs: `[M4] Negative Test Mode: TAMPER`
   - Deep copies tokens array
   - Flips byte 0 of token[0]
   - Logs: `[M4.1] TOKEN TAMPERING ENABLED: flipped byte 0 of token index 0`
   - Sends tampered /pay to HO

2. **HO Side:**
   - Receives /pay with tampered token[0]
   - M3.2 validation: attempts hash chain verification
   - Hash chain fails at adjacency check for token[0]
   - Logs: `[M4] REJECTED: adjacency check failed at i=0 (possible token tampering)`
   - Returns error JSON: `{"status": "error", "code": "token_tampering_detected", "reason": "security_violation"}`

3. **CO Side (Final):**
   - Receives rejection with code `token_tampering_detected`
   - Logs: `[M4.1] ✓ Expected rejection received from HO`
   - Test demonstrates tampering detection working correctly

**Key Points:**
- Token tampering is detected immediately at HO (no SP involvement)
- Hash chain verification naturally catches byte flips
- Anchor token linkage verification fails for tampered token
- Both local and logged confirmations of rejection

### 3. M4.2 Replay Payment

**Command:**
```bash
# Set NEG_TEST_MODE=REPLAY and HO REPLAY_TEST_MODE=true
docker compose up -d cauth sp ho
# Modify docker-compose.yml to set HO REPLAY_TEST_MODE=true, or use:
docker compose run --rm \
  -e NEG_TEST_MODE=REPLAY \
  -e REPLAY_DELAY_MS=1000 \
  -e REPLAY_TEST_MODE=true \  # Note: This is for HO acceptance
  co
```

**Important Setup for M4.2:**
- HO must have `REPLAY_TEST_MODE=true` in its environment
- This tells HO to allow duplicate /pay for same reservationId (testing-only behavior)
- In production, this should be `false` (default)

**Expected Behavior:**

1. **CO Side (Attempt #1):**
   - Logs: `[M4] Negative Test Mode: REPLAY`
   - Logs: `[M4.2] Attempting replay: sending same pay twice`
   - Builds clean payload from legitimate tokens
   - Sends /pay request #1 to HO

2. **HO Side (Attempt #1):**
   - Receives /pay with tokens[0-4]
   - M3.2 validation: PASS (all checks succeed)
   - Stores payment in registry with reservationId key
   - Calls SP /settle with tokens[0-4]
   - SP accept: updates chainMeta.lastSpentIndex = 4
   - Returns success JSON with receipt

3. **CO Side (Attempt #2):**
   - Waits REPLAY_DELAY_MS (1000 ms)
   - Logs: `[M4.2] Waiting 1000 ms before replay...`
   - Logs: `[M4.2] Attempt #2 REPLAY: Sending same payload again...`
   - Sends identical /pay request #2 to HO

4. **HO Side (Attempt #2) - Two Possible Outcomes:**

   **Option A (Without REPLAY_TEST_MODE):**
   - M3.2 validation: checks if startIndex=0 <= lastSpentIndex=4
   - Rejects immediately: `"Double-spend detected: startIndex=0 <= lastSpentIndex=4"`
   - Returns error JSON with code `security_violation`
   - Never calls SP settle

   **Option B (With REPLAY_TEST_MODE=true):**
   - M3.2 validation: checks but REPLAY_TEST_MODE=true allows bypass
   - Stores duplicate payment (allowed for testing)
   - Calls SP /settle again with same tokens[0-4]
   - SP checks: newLastSpentIndex=4 <= currentLastSpentIndex=4
   - SP rejects: `"DOUBLE_SPEND_DETECTED: attempting to reuse already-spent tokens"`
   - Returns error JSON with code `replay_or_double_spend`

5. **CO Side (Final):**
   - Receives either local rejection (Option A) or SP rejection (Option B)
   - If local rejection: logs the security_violation reason
   - If SP rejection: logs `[M4.2] ✓ EXPECTED: SP rejected 2nd settle as double-spend`

## Architecture Details

### M4.1 Refactoring

**Before:**
- Forced tampering mode for all runs
- No way to test happy path and negative scenarios together

**After:**
- `NEG_TEST_MODE` string-based selection
- M4.1 and M4.2 completely separate code paths
- Default to NONE (normal flow)
- Each scenario has dedicated logging
- Helper method `sendPayJson()` reused for both

**Key Implementation:**
```java
if ("TAMPER".equals(NEG_TEST_MODE)) {
    // Deep copy tokens array
    // Tamper only the copy (don't modify original pay JSONObject)
    // Rebuild JSONObject with tampered tokens
    // Send via sendPayJson() helper
} else if ("REPLAY".equals(NEG_TEST_MODE)) {
    // Send same payload twice
    // Wait REPLAY_DELAY_MS between attempts
    // Each send via sendPayJson() helper
} else {
    // Normal NONE mode: single send
    // Send via sendPayJson() helper
}
```

### M4.2 Refactoring

**Replay Scenario Flow:**
1. CO sends legitimate /pay request
2. HO accepts (stores payment)
3. HO calls SP /settle (SP updates chain state)
4. CO sends identical /pay request again
5. HO either:
   - Rejects locally (startIndex already spent) - production mode
   - Accepts (if REPLAY_TEST_MODE=true) and calls SP /settle again
6. SP rejects 2nd settle (tokens already spent monotonically)

**Helper Method (`sendPayJson`):**
- Creates fresh mTLS socket per call
- Sends JSON payload
- Reads and returns response
- Handles cleanup
- Reusable for TAMPER, REPLAY, and NONE scenarios

## Expected Test Outcomes

### M4.1 Summary
```
[M4] Negative Test Mode: TAMPER
[M4.1] Tampering token[0] byte[0]
[M4.1] TOKEN TAMPERING ENABLED: flipped byte 0 of token index 0
[M4.1] Expect HO rejection (adjacency/anchor check failure)
→ Sending TAMPERED pay request to HO at ho:8445
[M4] REJECTED: adjacency check failed at i=0 (possible token tampering)
[M4.1] ✓ Expected rejection received from HO
```

### M4.2 Summary (Production Mode - REPLAY_TEST_MODE=false)
```
[M4] Negative Test Mode: REPLAY
[M4.2] Attempting replay: sending same pay twice
[M4.2] Attempt #1: Sending pay request...
✓✓✓ PAYMENT ACCEPTED BY HO ✓✓✓
[M4.2] Attempt #2 REPLAY: Sending same payload again...
✗ HO rejected payment: Double-spend detected: startIndex=0 <= lastSpentIndex=4
```

### M4.2 Summary (Test Mode - REPLAY_TEST_MODE=true)
```
[M4] Negative Test Mode: REPLAY
[M4.2] Attempting replay: sending same pay twice
[M4.2] Attempt #1: Sending pay request...
✓✓✓ PAYMENT ACCEPTED BY HO ✓✓✓
[M4.2] Attempt #2 REPLAY: Sending same payload again...
[M4.2] REPLAY: HO accepted duplicate payment (this is test behavior)
[SETTLE] HO calls SP /settle for 2nd time
[SETTLE] SP rejects: DOUBLE_SPEND_DETECTED
[M4.2] ✓ EXPECTED: SP rejected 2nd settle as double-spend
```

## Key Design Principles

1. **No Code Duplication:**
   - `sendPayJson()` helper handles all socket management
   - TAMPER, REPLAY, and NONE scenarios share same response handling

2. **Clean Separation:**
   - Each scenario clearly isolated in if/else if/else
   - Distinct logging tags: `[M4.1]`, `[M4.2]`, `[M3]`

3. **Default Safety:**
   - NEG_TEST_MODE defaults to NONE (normal flow)
   - REPLAY_TEST_MODE defaults to false (strict production mode)
   - Negative scenarios require explicit opt-in

4. **Testability:**
   - Both M4.1 and M4.2 work with same docker-compose setup
   - Just change environment variables
   - Can run M3.x, M4.1, M4.2 with same images

## Files Modified

- `co/src/main/java/com/example/Main.java`
  - Added NEG_TEST_MODE, TAMPER_*, REPLAY_* flags
  - Added sendPayJson() helper method
  - Refactored pay sending logic (lines ~1050-1180)
  - Added comprehensive test documentation comments

- `ho/src/main/java/com/example/Main.java`
  - Added REPLAY_TEST_MODE flag
  - Modified payment storage to allow duplicates when flag=true
  - Existing M3.3 settle integration (no changes needed)

- `docker-compose.yml`
  - Added REPLAY_TEST_MODE=false to HO environment (default)

## Verification Checklist

- [ ] M4.1: CO sends tampered token, HO rejects with adjacency error
- [ ] M4.1: Hash chain verification detects tampering
- [ ] M4.1: Error code is `token_tampering_detected` or `security_violation`
- [ ] M4.2: CO sends /pay twice with identical payload
- [ ] M4.2 (Prod): HO rejects 2nd /pay locally as double-spend
- [ ] M4.2 (Test): HO accepts 2nd /pay when REPLAY_TEST_MODE=true
- [ ] M4.2 (Test): HO calls SP /settle twice when REPLAY_TEST_MODE=true
- [ ] M4.2 (Test): SP rejects 2nd settle with `replay_or_double_spend`
- [ ] M3.x: Normal flow works without any NEG_TEST_MODE settings
- [ ] Code compiles without errors
- [ ] All three modes (NONE, TAMPER, REPLAY) can be toggled via env vars
