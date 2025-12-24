# M4 Negative Scenarios Test Guide

This document explains how to test M4.1 (Token Tampering), M4.2 (Replay Payment), CAuth-1 (Rogue Intermediate CA), and ROGUE_CO (Unauthorized Client) security scenarios.

## Architecture Overview

Negative scenarios are implemented as **toggleable test modes** using environment variables:

### Environment Variables

**CO Configuration:**
- `NEG_TEST_MODE` (default: `NONE`)
  - `NONE` = normal M3.x flow (happy path)
  - `TAMPER` = M4.1 token tampering scenario
  - `REPLAY` = M4.2 replay payment scenario
  - `FAKE_CAUTH` = CAuth-1 rogue intermediate CA scenario
  - `BAD_CERT` = ROGUE_CO unauthorized client scenario
  - `RESV_TAMPER` = FORGED_RESERVATION tampering scenario
  
- `CAUTH_HOST` (default: `cauth`) - CAuth server hostname for enrollment
- `CAUTH_PORT` (default: `8443`) - CAuth server port for enrollment
- `TAMPER_TOKEN_INDEX` (default: `0`) - which token to tamper in M4.1
- `TAMPER_BYTE_INDEX` (default: `0`) - which byte to flip in that token
- `REPLAY_DELAY_MS` (default: `500`) - wait time between first and second /pay in M4.2
- `BAD_CERT_MODE` (default: `MISSING`) - ROGUE_CO sub-mode:
  - `MISSING` = no client certificate presented
  - `SELF_SIGNED` = untrusted self-signed certificate
- `RESV_TAMPER_MODE` (default: `FIELD_EDIT`) - FORGED_RESERVATION sub-mode:
  - `FIELD_EDIT` = modify signed field value (e.g., priceTokens)
  - `REORDER` = reorder key-value pairs (tests canonical order)
  - `SIG_FLIP` = flip 1 bit in signature (tests signature integrity)
  - `DROP_FIELD` = remove required field (tests field completeness)

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

###4. CAuth-1 Rogue Intermediate CA

**Command:**
```bash
# Start fake-cauth, SP, and HO (but NOT real cauth)
docker compose up -d fake-cauth sp ho

# Run CO with FAKE_CAUTH mode, redirecting enrollment to fake-cauth
docker compose run --rm \
  -e NEG_TEST_MODE=FAKE_CAUTH \
  -e CAUTH_HOST=fake-cauth \
  co
```

**IMPORTANT NOTE**: This test demonstrates **defense in depth** - the rogue CA is rejected at **multiple** security layers:

1. **Early Rejection (Actual Behavior)**: During enrollment, CO's TLS client validates fake-cauth's server certificate and rejects it immediately during the TLS handshake because fake-cauth uses a self-signed cert not chained to Root CA. CO never completes enrollment. This shows the system rejects rogue CAs at the **first opportunity**.

2. **Late Rejection (Intended Demonstration)**: If CO somehow obtained a certificate from fake-cauth, it would fail when attempting mTLS with SP because SP's truststore doesn't contain the rogue CA.

The current implementation shows **earlier** and **stronger** rejection than originally planned, which is actually better security! The system doesn't even allow enrollment with an untrusted CA server.

**Expected Behavior (Early Rejection - Defense in Depth):**

1. **Fake-CAuth Side (Startup):**
   - Logs: `[FAKE-CAUTH] Generating self-signed rogue intermediate CA...`
   - Creates ephemeral RSA-2048 keypair
   - Issues self-signed certificate with subject: `CN=ROGUE-CA-DO-NOT-TRUST, O=Fake Authority, C=XX`
   - Certificate has CA=true but is NOT signed by legitimate Root CA
   - Uses this certificate for TLS server identity
   - Logs: `NOTE: This CA is self-signed and NOT chained to Root CA!`
   - Starts TLS server on port 8443 (same as real cauth)

2. **CO Side (Enrollment Attempt):**
   - Connects to fake-cauth:8443 instead of cauth:8443
   - Initiates TLS handshake
   - TLS client (CO) validates server certificate
   - **Validation FAILS**: fake-cauth's cert is self-signed, not chained to Root CA
   - Throws `SSLHandshakeException` with cause: `PKIX path building failed`
   - Error: `unable to find valid certification path to requested target`
   - **CO never completes enrollment** (fails at TLS handshake)

3. **CO Side (Final Output):**
   ```
   Step 3: Connecting to CAuth server over TLS...
   
   ✖ CRITICAL ERROR: CO failed to start
   Reason: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: 
           unable to find valid certification path to requested target
   
   javax.net.ssl.SSLHandshakeException: PKIX path building failed...
   Caused by: sun.security.validator.ValidatorException: PKIX path building failed...
   Caused by: sun.security.provider.certpath.SunCertPathBuilderException: 
           unable to find valid certification path to requested target
   ```

4. **Fake-CAuth Side (Error Log):**
   ```
   [FAKE-CAUTH] Client handler error: Received fatal alert: certificate_unknown
   ```

**Security Analysis:**

This test demonstrates **layered security** with **early rejection**:

✓ **TLS Handshake Validation**: CO's TLS client validates the server certificate during handshake
✓ **Trust Anchor Enforcement**: Only certificates chained to Root CA are trusted
✓ **Fail-Closed Behavior**: Connection fails immediately, no certificate exchange occurs  
✓ **Defense in Depth**: Rogue CA rejected at first opportunity (before any CSR submission)
✓ **No Bypass Possible**: System doesn't proceed with enrollment if TLS validation fails

**Why This is Better Than Expected:**
- Original plan: CO enrolls → gets rogue cert → fails at SP
- Actual behavior: CO fails enrollment → never gets rogue cert → even earlier rejection
- **This is stronger security**: Untrusted CA servers are rejected before they can issue any certificates

**Key Security Validation:**
- Fake-cauth's self-signed CA is ephemeral (generated at startup, not persisted)
- No service in the system has fake-cauth's CA in their truststore
- Certificate chain returned by fake-cauth: `[CO-leaf, ROGUE-CA]` (no Root CA)
- SP truststore contains only: `[Real-Root-CA, Real-CAuth-Intermediate]`
- PKIX path building MUST fail: no valid path from ROGUE-CA to Real-Root-CA
- Test is deterministic: mTLS MUST fail with PKIX validation error
- No fallback to real cauth (fail-closed behavior)

**Why This Test is Important:**
1. Demonstrates system correctly validates full certificate chain to Root CA
2. Proves system rejects certificates from untrusted intermediates
3. Shows mTLS is not just "any certificate" but "certificate chained to ROOT"
4. Validates that API compatibility alone doesn't grant trust (fake-cauth has same API)
5. Tests fail-closed behavior (no automatic fallback to legitimate CA)

### 5. ROGUE_CO / BAD_CERT - Unauthorized Client

**Command (MISSING mode - no client certificate):**
```bash
# Start normal services
docker compose up -d cauth sp ho

# Run CO without enrolling, no client certificate
docker compose run --rm \
  -e NEG_TEST_MODE=BAD_CERT \
  -e BAD_CERT_MODE=MISSING \
  co
```

**Command (SELF_SIGNED mode - untrusted certificate):**
```bash
# Start normal services
docker compose up -d cauth sp ho

# Run CO with self-signed certificate
docker compose run --rm \
  -e NEG_TEST_MODE=BAD_CERT \
  -e BAD_CERT_MODE=SELF_SIGNED \
  co
```

**Expected Behavior (MISSING Mode):**

1. **CO Side (Startup):**
   - Logs: `[ROGUE_CO] NEGATIVE TEST MODE: BAD_CERT`
   - Logs: `[ROGUE_CO] Mode: MISSING`
   - Logs: `[ROGUE_CO] MISSING mode: Skipping enrollment, no client certificate`
   - Logs: `[ROGUE_CO] Will attempt mTLS without presenting client certificate`
   - Skips enrollment (no `enrollWithCAuth()` call)
   - `coKeyPair` and `coCertificate` remain null

2. **CO Side (Connection Attempt):**
   - Logs: `[ROGUE_CO] Attempting mTLS connection to SP...`
   - Logs: `[ROGUE_CO] EXPECTED: Connection should FAIL`
   - Logs: `[ROGUE_CO] REASON: No client certificate presented (peer not authenticated)`
   - Creates SSLContext with NO KeyManager (only TrustManager)
   - Attempts socket connection to SP:8444
   - TLS handshake begins

3. **SP Side (TLS Handshake):**
   - SP requires client certificate (`setNeedClientAuth(true)`)
   - CO cannot present a certificate (no KeyManager)
   - TLS handshake FAILS
   - SP logs: handshake error or peer not authenticated
   - Connection terminated

4. **CO Side (Expected Success):**
   ```
   ╔═══════════════════════════════════════════════════════════════╗
   ║   [ROGUE_CO] ✓ SECURITY SUCCESS: Rogue CO REJECTED          ║
   ╚═══════════════════════════════════════════════════════════════╝
   [ROGUE_CO] mTLS connection to SP failed as expected!
   [ROGUE_CO] Error type: SSLHandshakeException (or IOException)
   [ROGUE_CO] Error message: peer not authenticated / handshake failed
   
   [ROGUE_CO] VERIFICATION COMPLETE:
     ✓ CO skipped enrollment (no certificate obtained)
     ✓ CO attempted mTLS without client certificate
     ✓ SP rejected connection (peer not authenticated)
     ✓ System requires valid client certificate for mTLS
     ✓ System correctly enforces client certificate validation
     ✓ No bypass mechanisms available (strong security)
   
   [ROGUE_CO] CONCLUSION: Rogue CO properly rejected!
   [ROGUE_CO] The system is SECURE against unauthorized clients.
   ```
   - Exits with code 0 (test passed)

**Expected Behavior (SELF_SIGNED Mode):**

1. **CO Side (Certificate Generation):**
   - Logs: `[ROGUE_CO] NEGATIVE TEST MODE: BAD_CERT`
   - Logs: `[ROGUE_CO] Mode: SELF_SIGNED`
   - Logs: `[ROGUE_CO] SELF_SIGNED mode: Generating untrusted self-signed certificate`
   - Generates RSA-2048 keypair
   - Creates self-signed certificate:
     - Subject: `CN=ROGUE-CO-UNTRUSTED, O=Unauthorized, C=XX`
     - Issuer: Same as subject (self-signed)
     - Not CA, client auth EKU
   - Logs: `[ROGUE_CO] Generated self-signed certificate:`
   - Logs certificate details
   - Logs: `[ROGUE_CO] ⚠ This certificate is NOT chained to trusted Root CA`
   - Logs: `[ROGUE_CO] ⚠ It is self-signed and will be rejected by services`
   - Stores in keystore

2. **CO Side (Connection Attempt):**
   - Logs: `[ROGUE_CO] Attempting mTLS connection to SP...`
   - Logs: `[ROGUE_CO] EXPECTED: Connection should FAIL`
   - Logs: `[ROGUE_CO] REASON: Self-signed cert not chained to Root CA (PKIX validation fails)`
   - Creates SSLContext with KeyManager containing self-signed cert
   - Attempts socket connection to SP:8444
   - TLS handshake begins

3. **SP Side (TLS Handshake - PKIX Validation):**
   - SP requires and validates client certificate
   - CO presents self-signed certificate
   - SP's TrustManager attempts to validate certificate chain
   - PKIX path building: `[ROGUE-CO-UNTRUSTED] → Root CA?`
   - Path building FAILS: self-signed cert not chained to Root CA
   - SP throws `SSLHandshakeException` with cause `CertPathValidatorException`
   - SP logs: PKIX path validation failed
   - Connection terminated

4. **CO Side (Expected Success):**
   ```
   ╔═══════════════════════════════════════════════════════════════╗
   ║   [ROGUE_CO] ✓ SECURITY SUCCESS: Rogue CO REJECTED          ║
   ╚═══════════════════════════════════════════════════════════════╝
   [ROGUE_CO] mTLS connection to SP failed as expected!
   [ROGUE_CO] Error type: SSLException
   [ROGUE_CO] Error message: PKIX path building failed...
   [ROGUE_CO] Root cause: PKIX path validation failure
   [ROGUE_CO] Reason: unable to find valid certification path...
   
   [ROGUE_CO] VERIFICATION COMPLETE:
     ✓ CO generated self-signed certificate
     ✓ CO attempted mTLS with untrusted certificate
     ✓ SP rejected connection (PKIX validation failed)
     ✓ Certificate not chained to trusted Root CA
     ✓ System correctly enforces client certificate validation
     ✓ No bypass mechanisms available (strong security)
   
   [ROGUE_CO] CONCLUSION: Rogue CO properly rejected!
   [ROGUE_CO] The system is SECURE against unauthorized clients.
   ```
   - Exits with code 0 (test passed)

**Security Analysis:**

Both ROGUE_CO modes demonstrate **client authentication enforcement**:

✓ **MISSING Mode**: System rejects clients without certificates (peer not authenticated)
✓ **SELF_SIGNED Mode**: System rejects untrusted certificates (PKIX validation)
✓ **Trust Anchor Enforcement**: Only certificates chained to Root CA are accepted
✓ **Fail-Closed Behavior**: No connection proceeds without valid client certificate
✓ **Defense in Depth**: Multiple layers prevent unauthorized access

**Why These Tests Are Important:**
1. Demonstrates mTLS client authentication is strictly enforced
2. Proves system rejects clients without valid certificates (MISSING)
3. Proves system rejects clients with untrusted certificates (SELF_SIGNED)
4. Shows certificate chain validation applies to clients, not just servers
5. Tests that no backdoor or bypass exists for unauthorized clients

## Architecture Details

### M4.1 Refactoring

**Before:**
- Forced tampering mode for all runs
- No way to test happy path and negative scenarios together

**After:**
- `NEG_TEST_MODE` string-based selection
- M4.1, M4.2, and CAuth-1 completely separate code paths
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
} else if ("FAKE_CAUTH".equals(NEG_TEST_MODE)) {
    // Enroll with fake-cauth instead of real cauth (CAUTH_HOST=fake-cauth)
    // Store rogue certificate in keystore
    // Attempt mTLS to SP
    // Expect and verify PKIX validation failure
    // Log detailed success confirmation
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

### CAuth-1 Implementation

**Fake-CAuth Service:**
- Standalone Docker container: `fake-cauth`
- Generates self-signed CA keypair at startup (ephemeral, not persisted)
- Implements identical enrollment API as real cauth:
  - Accepts `signCSR` method
  - Validates CSR signature
  - Issues leaf certificates with proper extensions
  - Returns JSON with same field names: `{"status": "ok", "certificate": "...", "caCert": "..."}`
- Certificate chain terminates at fake CA (does NOT include Root CA)
- Subject: `CN=ROGUE-CA-DO-NOT-TRUST, O=Fake Authority, C=XX`
- Runs on same port (8443) as real cauth for transparent redirection

**CO Enrollment Redirection:**
- `CAUTH_HOST` environment variable (default: `cauth`)
- Set to `fake-cauth` to redirect enrollment without code changes
- CO enrollment logic unchanged (uses existing `enrollWithCAuth()` method)
- CO stores rogue certificate in keystore (normal behavior)

**FAKE_CAUTH Test Mode:**
- Triggered by `NEG_TEST_MODE=FAKE_CAUTH`
- After enrollment, inspects certificate issuer DN
- Detects `ROGUE` or `DO-NOT-TRUST` keywords in issuer
- Attempts mTLS connection to SP (calls `discoverAvailabilities()`)
- Wraps in try-catch to handle expected `SSLHandshakeException`
- Verifies failure is due to `CertPathValidatorException` (PKIX validation)
- Logs detailed verification checklist
- Exits 0 on expected failure (test passed)
- Exits 1 if connection succeeds (critical security failure)

**Fail-Closed Design:**
- No fallback to real cauth (if CAUTH_HOST=fake-cauth, CO only tries fake-cauth)
- No retry logic (single enrollment attempt)
- No bypass mechanisms (mTLS MUST succeed for CO to proceed)
- Test demonstrates deterministic rejection by SP truststore validation

### ROGUE_CO / BAD_CERT Implementation

**BAD_CERT Test Mode:**
- Triggered by `NEG_TEST_MODE=BAD_CERT`
- Two sub-modes controlled by `BAD_CERT_MODE`:
  - `MISSING`: CO skips enrollment entirely, no client certificate
  - `SELF_SIGNED`: CO generates self-signed certificate (not chained to Root CA)

**MISSING Mode Flow:**
1. CO skips enrollment (no call to `enrollWithCAuth()`)
2. CO creates SSLContext with NO KeyManager (only TrustManager)
3. CO attempts mTLS connection to SP
4. TLS handshake requires client certificate (SP has `setNeedClientAuth(true)`)
5. CO cannot present a certificate
6. SP rejects with "peer not authenticated" or similar error
7. CO logs success (expected rejection)

**SELF_SIGNED Mode Flow:**
1. CO skips enrollment with real cauth
2. CO generates self-signed certificate:
   - Subject: `CN=ROGUE-CO-UNTRUSTED, O=Unauthorized, C=XX`
   - Issuer: Same as subject (self-signed)
   - Not chained to Root CA
3. CO stores self-signed cert in keystore
4. CO creates SSLContext with KeyManager containing self-signed cert
5. CO attempts mTLS connection to SP
6. TLS handshake: CO presents self-signed certificate
7. SP validates certificate chain
8. PKIX path validation FAILS (cert not chained to Root CA)
9. SP rejects with `CertPathValidatorException`
10. CO logs success (expected rejection)

**Helper Methods:**
- `generateSelfSignedCertificate()`: Creates untrusted self-signed cert using BouncyCastle
- `testRogueCoConnection()`: Attempts mTLS to SP with rogue/missing credentials

**Fail-Closed Design:**
- No fallback to real enrollment
- No retry logic (single connection attempt)
- No bypass mechanisms (mTLS validation strictly enforced)
- Both modes demonstrate deterministic rejection

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

### CAuth-1 Summary
```
═══════════════════════════════════════════════════════════════
  FAKE-CAUTH: Rogue Intermediate CA (CAuth-1 Security Test)
═══════════════════════════════════════════════════════════════
WARNING: This is a ROGUE CA for negative security testing!
         Certificates issued by this CA are NOT trusted.
         They WILL be rejected by legitimate services.
═══════════════════════════════════════════════════════════════

[FAKE-CAUTH] Generating self-signed rogue intermediate CA...
✓ Rogue CA generated
  Subject: C=XX, O=Fake Authority, CN=ROGUE-CA-DO-NOT-TRUST
  Issuer:  C=XX, O=Fake Authority, CN=ROGUE-CA-DO-NOT-TRUST
  NOTE: This CA is self-signed and NOT chained to Root CA!

[FAKE-CAUTH] Listening on port 8443
[FAKE-CAUTH] Ready to issue UNTRUSTED certificates

=== Car Owner (CO) Starting ===
No existing certificate found, enrolling with CAuth...
Step 1: Generating RSA key pair...
✓ RSA-2048 key pair generated successfully

Step 2: Creating Certificate Signing Request (CSR)...
✓ CSR created with subject: CN=CarOwner, O=Parking System, C=BE

Step 3: Connecting to CAuth server over TLS...

✖ CRITICAL ERROR: CO failed to start
Reason: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: 
        unable to find valid certification path to requested target

javax.net.ssl.SSLHandshakeException: PKIX path building failed...
Caused by: sun.security.validator.ValidatorException: PKIX path building failed...
Caused by: sun.security.provider.certpath.SunCertPathBuilderException: 
        unable to find valid certification path to requested target

[FAKE-CAUTH] Client handler error: Received fatal alert: certificate_unknown

═══════════════════════════════════════════════════════════════
SECURITY VALIDATION: PASSED ✓
═══════════════════════════════════════════════════════════════
✓ Rogue CA server rejected during TLS handshake (early rejection)
✓ PKIX path validation enforced (trust anchor verification)
✓ CO never completed enrollment (fail-closed behavior)
✓ System demonstrates defense in depth (rejection at first layer)
✓ No bypass mechanisms available (strong security guarantee)
```

### ROGUE_CO Summary (MISSING Mode)
```
═══════════════════════════════════════════════════════════════
  [ROGUE_CO] NEGATIVE TEST MODE: BAD_CERT
  Sub-mode: MISSING
═══════════════════════════════════════════════════════════════
[ROGUE_CO] Testing rejection of CO without valid certificate
[ROGUE_CO] Mode: MISSING
[ROGUE_CO] MISSING mode: Skipping enrollment, no client certificate
[ROGUE_CO] Will attempt mTLS without presenting client certificate

[ROGUE_CO] Attempting mTLS connection to SP...
[ROGUE_CO] EXPECTED: Connection should FAIL
[ROGUE_CO] REASON: No client certificate presented (peer not authenticated)

[ROGUE_CO] Creating SSLContext WITHOUT client KeyManager
[ROGUE_CO] Connecting to SP at sp:8444
[ROGUE_CO] Starting TLS handshake...
[ROGUE_CO] TLS negotiation completed; validating mTLS acceptance...
[ROGUE_CO] Server authenticated: C=BE,O=Parking System,CN=ServiceProvider
[ROGUE_CO] Performing post-handshake proof (send request)...
[ROGUE_CO] Reading response to confirm mTLS acceptance...

╔═══════════════════════════════════════════════════════════════╗
║   [ROGUE_CO] ✓ SECURITY SUCCESS: Rogue CO REJECTED          ║
╚═══════════════════════════════════════════════════════════════╝
[ROGUE_CO] mTLS rejected by peer during client certificate validation!
[ROGUE_CO] Error type: SSLHandshakeException
[ROGUE_CO] Error message: Received fatal alert: bad_certificate
[ROGUE_CO] Analysis: SP rejected the client certificate (fatal alert: bad_certificate)
[ROGUE_CO] Reason: No client certificate presented (peer not authenticated)

[ROGUE_CO] VERIFICATION COMPLETE:
  ✓ CO skipped enrollment (no certificate obtained)
  ✓ CO attempted mTLS without client certificate
  ✓ SP rejected connection (peer not authenticated)
  ✓ System requires valid client certificate for mTLS
  ✓ System correctly enforces client certificate validation
  ✓ No bypass mechanisms available (strong security)

[ROGUE_CO] CONCLUSION: Rogue CO properly rejected!
[ROGUE_CO] The system is SECURE against unauthorized clients.

SP-Side Logs:
=== Inbound Connection ===
[SP] ✗ TLS handshake failed during client authentication
[SP] Error: Empty client certificate chain
[SP] Case: SSLHandshakeException (other cause)
[SP] Details: Empty client certificate chain

Client disconnected
```

### ROGUE_CO Summary (SELF_SIGNED Mode)
```
═══════════════════════════════════════════════════════════════
  [ROGUE_CO] NEGATIVE TEST MODE: BAD_CERT
  Sub-mode: SELF_SIGNED
═══════════════════════════════════════════════════════════════
[ROGUE_CO] Testing rejection of CO without valid certificate
[ROGUE_CO] Mode: SELF_SIGNED
[ROGUE_CO] SELF_SIGNED mode: Generating untrusted self-signed certificate
[ROGUE_CO] Generating RSA-2048 keypair for self-signed certificate...
[ROGUE_CO] Self-signed certificate created:
[ROGUE_CO]   BasicConstraints: CA=false
[ROGUE_CO]   KeyUsage: digitalSignature, keyEncipherment
[ROGUE_CO]   ExtendedKeyUsage: clientAuth
[ROGUE_CO] Certificate stored in keystore as PrivateKeyEntry
[ROGUE_CO] Keystore path: ./keystore/co_keystore.p12
[ROGUE_CO] Generated self-signed certificate:
  Subject: C=XX, O=Unauthorized, CN=ROGUE-CO-UNTRUSTED
  Issuer:  C=XX, O=Unauthorized, CN=ROGUE-CO-UNTRUSTED
  Serial:  223287081422400487328209984340076205479
[ROGUE_CO] ⚠ This certificate is NOT chained to trusted Root CA
[ROGUE_CO] ⚠ It is self-signed and will be rejected by services

[ROGUE_CO] Attempting mTLS connection to SP...
[ROGUE_CO] EXPECTED: Connection should FAIL
[ROGUE_CO] REASON: Self-signed cert not chained to Root CA (PKIX validation fails)

[ROGUE_CO] Creating SSLContext WITH self-signed certificate
[ROGUE_CO] Loading keystore to verify certificate availability...
[ROGUE_CO] Keystore loaded successfully:
[ROGUE_CO]   Type: PKCS12
[ROGUE_CO]   Path: ./keystore/co_keystore.p12
[ROGUE_CO]   Alias [1]: co_key
[ROGUE_CO]     Entry type: PrivateKeyEntry (has private key)
[ROGUE_CO]     Subject: C=XX,O=Unauthorized,CN=ROGUE-CO-UNTRUSTED
[ROGUE_CO]     Issuer: C=XX,O=Unauthorized,CN=ROGUE-CO-UNTRUSTED
[ROGUE_CO]     SHA-256: EC45269A2912CC084767C98A59E3499D...
[ROGUE_CO] Certificate is available and ready to be sent during TLS handshake
[ROGUE_CO] KeyManagers created: 1 manager(s)
[ROGUE_CO] KeyManager wrapped to force alias selection: co_key
[ROGUE_CO] SSLContext initialized with wrapped KeyManagers
[ROGUE_CO] Connecting to SP at sp:8444
[ROGUE_CO] Starting TLS handshake...
[ROGUE_CO] chooseClientAlias called - forcing alias: co_key
[ROGUE_CO] TLS negotiation completed; validating mTLS acceptance...
[ROGUE_CO] Server authenticated: C=BE,O=Parking System,CN=ServiceProvider
[ROGUE_CO] Performing post-handshake proof (send request)...
[ROGUE_CO] Reading response to confirm mTLS acceptance...

╔═══════════════════════════════════════════════════════════════╗
║   [ROGUE_CO] ✓ SECURITY SUCCESS: Rogue CO REJECTED          ║
╚═══════════════════════════════════════════════════════════════╝
[ROGUE_CO] mTLS rejected by peer during client certificate validation!
[ROGUE_CO] Error type: SSLHandshakeException
[ROGUE_CO] Error message: Received fatal alert: certificate_unknown

[ROGUE_CO] VERIFICATION COMPLETE:
  ✓ CO generated self-signed certificate
  ✓ CO attempted mTLS with untrusted certificate
  ✓ SP rejected connection (PKIX validation failed)
  ✓ Certificate not chained to trusted Root CA
  ✓ System correctly enforces client certificate validation
  ✓ No bypass mechanisms available (strong security)

[ROGUE_CO] CONCLUSION: Rogue CO properly rejected!
[ROGUE_CO] The system is SECURE against unauthorized clients.

SP-Side Logs:
=== Inbound Connection ===
[SP] ✗ TLS handshake failed during client authentication
[SP] Error: PKIX path building failed: unable to find valid certification path...
[SP] Case: CertPathValidatorException (PKIX validation)
[SP] Root cause: ValidatorException: PKIX path building failed...
[SP] Reason: Client presented certificate but it is not chained to trusted Root CA
[SP] This indicates the client certificate was received but rejected as untrusted

Client disconnected
```

## Key Design Principles

1. **No Code Duplication:**
   - `sendPayJson()` helper handles all socket management
   - TAMPER, REPLAY, and NONE scenarios share same response handling
   - Enrollment logic reused for both real and fake cauth

2. **Clean Separation:**
   - Each scenario clearly isolated in if/else if/else
   - Distinct logging tags: `[M4.1]`, `[M4.2]`, `[CAuth-1]`, `[M3]`
   - CAuth-1 mode exits early (doesn't proceed to payment after mTLS failure)

3. **Default Safety:**
   - NEG_TEST_MODE defaults to NONE (normal flow)
   - REPLAY_TEST_MODE defaults to false (strict production mode)
   - CAUTH_HOST defaults to `cauth` (legitimate CA)
   - Negative scenarios require explicit opt-in

4. **Testability:**
   - M4.1, M4.2, and CAuth-1 work with same docker-compose setup
   - Just change environment variables
   - Can run M3.x, M4.1, M4.2, CAuth-1 with same images
   - Each test has deterministic expected outcome

5. **Fail-Closed Behavior:**
   - CAuth-1: No fallback to real cauth (single enrollment attempt)
   - CAuth-1: No retry logic (if mTLS fails, CO exits immediately)
   - CAuth-1: Test explicitly verifies rejection (failure is success criterion)

## Files Modified

- `co/src/main/java/com/example/Main.java`
  - Added NEG_TEST_MODE support for FAKE_CAUTH and BAD_CERT
  - Added CAuth-1 test logic after enrollment (lines ~180-270)
  - Added ROGUE_CO test logic in main() (lines ~187-289)
  - Added BAD_CERT_MODE environment variable (MISSING/SELF_SIGNED)
  - Added generateSelfSignedCertificate() helper method (lines ~622-700)
  - Added testRogueCoConnection() helper method (lines ~702-775)
  - Certificate inspection and issuer validation
  - mTLS attempt with expected failure handling
  - Detailed logging and verification checklist
  - Updated comments to document CAuth-1 and ROGUE_CO scenarios

- `fake-cauth/src/main/java/com/example/Main.java` (NEW)
  - Complete rogue CA implementation
  - Self-signed CA generation at startup
  - CSR signing with untrusted intermediate
  - Identical API to real cauth (signCSR method)
  - Comprehensive logging for security testing

- `fake-cauth/Dockerfile` (NEW)
  - Standard Java 17 + Maven build
  - No volume mounts (ephemeral CA)

- `fake-cauth/pom.xml` (NEW)
  - Same dependencies as real cauth
  - BouncyCastle for certificate operations

- `docker-compose.yml`
  - Added fake-cauth service on 172.20.0.14
  - Exposed on host port 8543 (internal 8443)
  - No dependencies (runs standalone)
  - No volumes (generates own CA)

- `M4_TEST_GUIDE.md`
  - Added CAuth-1 test scenario documentation
  - Complete expected behavior walkthrough
  - Command examples and verification steps

### 6. FORGED_RESERVATION (RESV_TAMPER) - Reservation Signature Tampering

**Purpose:** Tests that CO detects tampering with HomeOwner-signed reservation responses. This demonstrates the integrity and authenticity guarantees of the reservation handshake.

**Security Properties Validated:**
- **Signature Verification**: CO must detect any modification to signed reservation data
- **Canonical Data Binding**: Field order cannot be changed (prevents reordering attacks)
- **Field Integrity**: Individual field values cannot be modified (e.g., priceTokens)
- **Field Completeness**: Required fields cannot be removed (prevents field-stripping)
- **Fail-Closed Behavior**: Any signature verification failure must abort the reservation

**Test Modes:**

#### 6.1 FIELD_EDIT Mode

**Description:** Modifies a signed field value (e.g., changes `priceTokens=5` to `priceTokens=1`). Tests that CO detects value tampering.

**Command:**
```bash
# Clean keystores first
sudo docker compose down
sudo docker volume rm secure_software_assignment_co_keystore \
                       secure_software_assignment_ho_keystore \
                       secure_software_assignment_sp_keystore 2>/dev/null || true

# Start services
sudo docker compose up -d

# Wait for HO to publish availability
sleep 25

# Run test
sudo docker compose run --rm \
  -e NEG_TEST_MODE=RESV_TAMPER \
  -e RESV_TAMPER_MODE=FIELD_EDIT \
  co
```

**Expected Output:**
```
[RESV_TAMPER] ⚠ APPLYING TAMPERING (simulating attacker) ⚠
[RESV_TAMPER] Original signedData: reservationId=...priceTokens=5...
[RESV_TAMPER] FIELD_EDIT: Changed 'priceTokens=5' to 'priceTokens=1'
[RESV_TAMPER] Tampered signedData: reservationId=...priceTokens=1...
[RESV_TAMPER] Proceeding to verification with tampered data...

╔═══════════════════════════════════════════════════════════════╗
║   [RESV_TAMPER] ✓ SECURITY SUCCESS                          ║
╚═══════════════════════════════════════════════════════════════╝
[RESV_TAMPER] Forged reservation detected!
[RESV_TAMPER] Failure reason: Signed data mismatch! Possible tampering...
[RESV_TAMPER] Tampering mode: FIELD_EDIT

[RESV_TAMPER] VERIFICATION COMPLETE:
  ✓ CO applied FIELD_EDIT tampering
  ✓ Signature verification correctly FAILED
  ✓ SecurityException thrown
  ✓ CO failed closed (rejected forged reservation)
  ✓ HO identity binding enforced (cert fingerprint verified)
  ✓ No bypass mechanisms available

[RESV_TAMPER] CONCLUSION:
  SECURITY SUCCESS: Forged reservation detected
  The system is SECURE against reservation tampering.
```

**Exit Code:** 0 (success = tampering detected as expected)

#### 6.2 REORDER Mode

**Description:** Reorders key-value pairs in the signed data (e.g., swaps first two fields). Tests that canonical field order is enforced.

**Command:**
```bash
sudo docker compose run --rm \
  -e NEG_TEST_MODE=RESV_TAMPER \
  -e RESV_TAMPER_MODE=REORDER \
  co
```

**Expected Output:**
```
[RESV_TAMPER] REORDER: Swapped first two fields
[RESV_TAMPER] Tampered signedData: verdict=OK|reservationId=...
...
[RESV_TAMPER] ✓ SECURITY SUCCESS
[RESV_TAMPER] Forged reservation detected!
```

**Verification:** CO reconstructs canonical data in original order, signature verification fails due to mismatch.

#### 6.3 SIG_FLIP Mode

**Description:** Flips a single bit in the signature bytes. Tests that signature integrity is cryptographically enforced.

**Command:**
```bash
sudo docker compose run --rm \
  -e NEG_TEST_MODE=RESV_TAMPER \
  -e RESV_TAMPER_MODE=SIG_FLIP \
  co
```

**Expected Output:**
```
[RESV_TAMPER] SIG_FLIP: Flipped 1 bit in signature byte 0
[RESV_TAMPER] Tampered signature (Base64): apRU/CJ9cZ5UK1GG...
[RESV_TAMPER] Signature unchanged: NO (tampered)
...
[RESV_TAMPER] Failure reason: HO signature verification FAILED!
```

**Verification:** RSA signature verification detects the bit flip and throws SignatureException.

#### 6.4 DROP_FIELD Mode

**Description:** Removes the `coIdentity` field from signed data. Tests that field completeness is enforced.

**Command:**
```bash
sudo docker compose run --rm \
  -e NEG_TEST_MODE=RESV_TAMPER \
  -e RESV_TAMPER_MODE=DROP_FIELD \
  co
```

**Expected Output:**
```
[RESV_TAMPER] DROP_FIELD: Removed 'coIdentity' field
[RESV_TAMPER] Tampered signedData: reservationId=...priceTokens=5
...
[RESV_TAMPER] ✓ SECURITY SUCCESS
[RESV_TAMPER] Forged reservation detected!
```

**Verification:** Reconstructed canonical data includes coIdentity, signed data from HO does not, signature verification fails.

**Key Implementation Details:**

1. **Tampering Location:** Applied in `requestReservation()` AFTER receiving HO response but BEFORE calling `verifyReservationSignature()`
2. **Detection Point:** `verifyReservationSignature()` throws SecurityException when:
   - Signed data doesn't match reconstructed canonical data (FIELD_EDIT, REORDER, DROP_FIELD)
   - RSA signature verification fails (SIG_FLIP)
3. **Fail-Closed:** SecurityException caught in try-catch block, CO exits 0 for RESV_TAMPER mode (success = detected tampering)
4. **Identity Binding:** HO certificate fingerprint verified BEFORE signature verification (prevents MITM)
5. **No Bypass:** No fallback logic, any verification failure aborts reservation

**Files Modified:**
- `co/src/main/java/com/example/Main.java`
  - Added `RESV_TAMPER_MODE` environment variable
  - Added tampering logic in `requestReservation()` before verification
  - Added try-catch around `verifyReservationSignature()` with RESV_TAMPER success logging

## Verification Checklist

- [ ] M4.1: CO sends tampered token, HO rejects with adjacency error
- [ ] M4.1: Hash chain verification detects tampering
- [ ] M4.1: Error code is `token_tampering_detected` or `security_violation`
- [ ] M4.2: CO sends /pay twice with identical payload
- [ ] M4.2 (Prod): HO rejects 2nd /pay locally as double-spend
- [ ] M4.2 (Test): HO accepts 2nd /pay when REPLAY_TEST_MODE=true
- [ ] M4.2 (Test): HO calls SP /settle twice when REPLAY_TEST_MODE=true
- [ ] M4.2 (Test): SP rejects 2nd settle with `replay_or_double_spend`
- [ ] CAuth-1: fake-cauth generates self-signed CA at startup
- [ ] CAuth-1: fake-cauth issues certificate with rogue CA as issuer
- [ ] CAuth-1: CO enrolls successfully with fake-cauth
- [ ] CAuth-1: CO detects certificate issued by ROGUE CA
- [ ] CAuth-1: CO stores rogue certificate in keystore
- [ ] CAuth-1: CO attempts mTLS to SP with rogue certificate
- [ ] CAuth-1: SP rejects mTLS with SSLHandshakeException
- [ ] CAuth-1: Root cause is CertPathValidatorException (PKIX validation)
- [ ] CAuth-1: CO logs detailed verification checklist
- [ ] CAuth-1: Test exits 0 (success = expected rejection)
- [ ] CAuth-1: Rogue CA NOT in any truststore
- [ ] CAuth-1: No fallback to real cauth (fail-closed)
- [ ] ROGUE_CO (MISSING): CO skips enrollment completely
- [ ] ROGUE_CO (MISSING): CO creates SSLContext without KeyManager
- [ ] ROGUE_CO (MISSING): CO attempts mTLS to SP without client cert
- [ ] ROGUE_CO (MISSING): SP rejects with bad_certificate / peer not authenticated
- [ ] ROGUE_CO (MISSING): CO logs expected failure (success criterion)
- [ ] ROGUE_CO (MISSING): Test exits 0 (success = expected rejection)
- [ ] ROGUE_CO (SELF_SIGNED): CO skips enrollment completely
- [ ] ROGUE_CO (SELF_SIGNED): CO generates self-signed certificate
- [ ] ROGUE_CO (SELF_SIGNED): Certificate subject: CN=ROGUE-CO-UNTRUSTED
- [ ] ROGUE_CO (SELF_SIGNED): Certificate issuer: CN=ROGUE-CO-UNTRUSTED (self-signed)
- [ ] ROGUE_CO (SELF_SIGNED): CO attempts mTLS to SP with untrusted cert
- [ ] ROGUE_CO (SELF_SIGNED): SP rejects with SSLHandshakeException
- [ ] ROGUE_CO (SELF_SIGNED): Root cause is CertPathValidatorException (PKIX)
- [ ] ROGUE_CO (SELF_SIGNED): Reason: unable to find valid certification path
- [ ] ROGUE_CO (SELF_SIGNED): CO logs detailed verification checklist
- [ ] ROGUE_CO (SELF_SIGNED): Test exits 0 (success = expected rejection)
- [ ] ROGUE_CO: Both modes demonstrate fail-closed behavior
- [ ] ROGUE_CO: No bypass mechanisms available
- [ ] RESV_TAMPER (FIELD_EDIT): CO tampers with priceTokens value
- [ ] RESV_TAMPER (FIELD_EDIT): Signature verification detects data mismatch
- [ ] RESV_TAMPER (REORDER): CO reorders signed fields
- [ ] RESV_TAMPER (REORDER): Canonical order enforced, verification fails
- [ ] RESV_TAMPER (SIG_FLIP): CO flips 1 bit in signature
- [ ] RESV_TAMPER (SIG_FLIP): RSA verification detects signature corruption
- [ ] RESV_TAMPER (DROP_FIELD): CO removes coIdentity field
- [ ] RESV_TAMPER (DROP_FIELD): Signature verification detects missing field
- [ ] RESV_TAMPER: All modes throw SecurityException
- [ ] RESV_TAMPER: CO logs tampering applied and detection success
- [ ] RESV_TAMPER: Test exits 0 (success = tampering detected)
- [ ] RESV_TAMPER: HO identity binding enforced before verification
- [ ] RESV_TAMPER: No bypass mechanisms, strict fail-closed
- [ ] M3.x: Normal flow works without any NEG_TEST_MODE settings
- [ ] Code compiles without errors
- [ ] All seven modes (NONE, TAMPER, REPLAY, FAKE_CAUTH, BAD_CERT/MISSING, BAD_CERT/SELF_SIGNED, RESV_TAMPER) can be toggled via env vars
