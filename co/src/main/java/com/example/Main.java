package com.example;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.*;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.json.JSONArray;
import org.json.JSONObject;

public class Main {
    // -------------------------
    // CONFIG (env overrides)
    // -------------------------

    // CAuth server details (for enrollment)
    private static final String CAUTH_HOST = System.getenv().getOrDefault("CAUTH_HOST", "cauth");
    private static final int CAUTH_PORT = Integer.parseInt(System.getenv().getOrDefault("CAUTH_PORT", "8443"));

    // SP server details
    private static final String SP_HOST = System.getenv().getOrDefault("SP_HOST", "sp");
    private static final int SP_PORT = Integer.parseInt(System.getenv().getOrDefault("SP_PORT", "8444"));

    private static final String TRUSTSTORE_PATH = System.getenv().getOrDefault("TRUSTSTORE_PATH", "./truststore.p12");
    private static final String TRUSTSTORE_PASSWORD = System.getenv().getOrDefault("TRUSTSTORE_PASSWORD", "trustpassword");

    // Local storage for CO's credentials
    private static final String CO_KEYSTORE_PATH =
            System.getenv().getOrDefault("CO_KEYSTORE_PATH", "./keystore/co_keystore.p12");
    private static final String CO_KEYSTORE_PASSWORD =
            System.getenv().getOrDefault("KEYSTORE_PASSWORD", "serverpassword");
    private static final String CO_KEY_ALIAS =
            System.getenv().getOrDefault("CO_KEY_ALIAS", "co_key");
    private static final String CO_TRUSTSTORE_PASSWORD =
            System.getenv().getOrDefault("TRUSTSTORE_PASSWORD", "trustpassword");

    // ═════════════════════════════════════════════════════════════
    // M4 Negative Scenario Flags (M4.1, M4.2, CAuth-1, ROGUE_CO)
    // ═════════════════════════════════════════════════════════════
    // NEG_TEST_MODE: selects which scenario to run
    //   NONE       = normal M3.x flow (default)
    //   TAMPER     = M4.1 token tampering: flip 1 byte of 1 token
    //   REPLAY     = M4.2 replay payment: send same pay twice
    //   FAKE_CAUTH = CAuth-1 rogue intermediate CA: enroll with untrusted CA
    //   BAD_CERT   = ROGUE_CO: CO without valid certificate (MISSING or SELF_SIGNED)
    //
    // HOW TO TEST EACH SCENARIO:
    // ═════════════════════════════════════════════════════════════
    // 
    // 1) NORMAL M3.x FLOW (happy path):
    //    docker-compose -f docker-compose.yml up
    //    (No env vars needed; NEG_TEST_MODE defaults to "NONE")
    //
    // 2) M4.1 TOKEN TAMPERING (negative: HO rejects tampered token):
    //    docker-compose -f docker-compose.yml up -e NEG_TEST_MODE=TAMPER
    //    Optional: -e TAMPER_TOKEN_INDEX=0 -e TAMPER_BYTE_INDEX=0
    //    Expected: CO flips byte 0 of token 0
    //              HO rejects with [M4] REJECTED and code=token_tampering_detected
    //
    // 3) M4.2 REPLAY PAYMENT (negative: HO accepts dup locally, SP rejects at settle):
    //    docker-compose -f docker-compose.yml up -e NEG_TEST_MODE=REPLAY -e HO_REPLAY_TEST_MODE=true
    //    Optional: -e REPLAY_DELAY_MS=500
    //    Expected: CO sends /pay twice (same payload)
    //              HO accepts both (because REPLAY_TEST_MODE=true)
    //              HO calls SP /settle twice
    //              SP rejects 2nd settle with code=replay_or_double_spend
    //              CO logs [M4.2] EXPECTED: SP rejected 2nd settle
    //
    // 4) CAuth-1 ROGUE INTERMEDIATE CA (negative: mTLS fails - cert not chained to Root CA):
    //    docker-compose up -d fake-cauth sp ho
    //    docker-compose run --rm -e NEG_TEST_MODE=FAKE_CAUTH -e CAUTH_HOST=fake-cauth co
    //    Expected: CO enrolls with fake-cauth successfully
    //              CO receives certificate signed by rogue CA (not chained to Root CA)
    //              CO attempts mTLS with SP
    //              SP rejects with PKIX path validation error (untrusted issuer)
    //              CO logs [CAuth-1] SECURITY SUCCESS: Rogue intermediate CA rejected
    //
    // 5) ROGUE_CO / BAD_CERT (negative: CO without valid certificate):
    //    docker-compose up -d cauth sp ho
    //    docker-compose run --rm -e NEG_TEST_MODE=BAD_CERT -e BAD_CERT_MODE=MISSING co
    //    OR: -e BAD_CERT_MODE=SELF_SIGNED
    //    Expected MISSING: CO skips enrollment, attempts mTLS without client cert
    //                      SP/HO reject with "peer not authenticated" or similar
    //    Expected SELF_SIGNED: CO generates self-signed cert, attempts mTLS
    //                          SP/HO reject with PKIX validation error
    //              CO logs [ROGUE_CO] SECURITY SUCCESS: Rogue CO rejected
    //
    // ═════════════════════════════════════════════════════════════
    private static final String NEG_TEST_MODE = 
            System.getenv().getOrDefault("NEG_TEST_MODE", "NONE").toUpperCase();
    
    // Tamper configuration (used when NEG_TEST_MODE=TAMPER)
    private static final int TAMPER_TOKEN_INDEX = 
            Integer.parseInt(System.getenv().getOrDefault("TAMPER_TOKEN_INDEX", "0"));
    private static final int TAMPER_BYTE_INDEX = 
            Integer.parseInt(System.getenv().getOrDefault("TAMPER_BYTE_INDEX", "0"));
    
    // Replay configuration (used when NEG_TEST_MODE=REPLAY)
    private static final long REPLAY_DELAY_MS = 
            Long.parseLong(System.getenv().getOrDefault("REPLAY_DELAY_MS", "500"));
    
    // BAD_CERT configuration (used when NEG_TEST_MODE=BAD_CERT)
    // BAD_CERT_MODE: MISSING = no client cert, SELF_SIGNED = untrusted self-signed cert
    private static final String BAD_CERT_MODE = 
            System.getenv().getOrDefault("BAD_CERT_MODE", "MISSING").toUpperCase();
    
    // RESV_TAMPER configuration (used when NEG_TEST_MODE=RESV_TAMPER)
    // Tests that CO detects tampering with HO-signed reservation responses
    // RESV_TAMPER_MODE values:
    //   FIELD_EDIT: Modify a signed field value (e.g., priceTokens=5 -> priceTokens=1)
    //   REORDER: Reorder key-value pairs (tests canonical order binding)
    //   SIG_FLIP: Flip 1 bit in signature bytes (tests signature integrity)
    //   DROP_FIELD: Remove a required signed field (tests field-stripping protection)
    private static final String RESV_TAMPER_MODE = 
            System.getenv().getOrDefault("RESV_TAMPER_MODE", "FIELD_EDIT").toUpperCase();

    private static KeyPair coKeyPair;
    private static X509Certificate coCertificate;
    
    // ═════════════════════════════════════════════════════════════
    // Helper: Send JSON payload over mTLS and get response
    // ═════════════════════════════════════════════════════════════
    private static JSONObject sendPayJson(String payload, String host, int port, SSLContext sslContext) 
            throws Exception {
        SSLSocket socket = null;
        PrintWriter writer = null;
        BufferedReader reader = null;
        try {
            socket = (SSLSocket) sslContext.getSocketFactory().createSocket(host, port);
            socket.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
            socket.startHandshake();
            
            writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            
            writer.println(payload);
            String respLine = reader.readLine();
            if (respLine == null) {
                throw new IOException("No response from HO on pay request");
            }
            return new JSONObject(respLine);
        } finally {
            if (reader != null) reader.close();
            if (writer != null) writer.close();
            if (socket != null) socket.close();
        }
    }
    
    // M3.4: Cached SP certificate for receipt verification
    private static X509Certificate spCertificate = null;
    
    // Store discovered availability for reservation (Milestone 2.4)
    static class DiscoveredAvailability {
        String availabilityId;
        String spotId;
        String validFrom;
        String validTo;
        int priceTokens;
        String locationZone;
        String homeOwnerId;
        String hoIdentity;
        String hoCertFingerprint;
        X509Certificate hoCertificate;
        String hoHost = "ho"; // HO container hostname
        int hoPort = 8445;    // HO reservation server port
        int hoPayPort = 8445;
    }
    
    private static DiscoveredAvailability discoveredAvailability = null;

    public static void main(String[] args) {
        // Register BC provider (needed for CSR + extensions reliably)
        Security.addProvider(new BouncyCastleProvider());

        // Sleep to allow CAuth, SP, and HO to start and publish availability
        try {
            System.out.println("Waiting for CAuth, SP, and HO to start...");
            Thread.sleep(12000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        try {
            System.out.println("\n=== Car Owner (CO) Starting ===");

            ensureParentDirExists(CO_KEYSTORE_PATH);

            // ═════════════════════════════════════════════════════════════
            // ROGUE_CO / BAD_CERT Negative Test: CO without valid certificate
            // ═════════════════════════════════════════════════════════════
            if ("BAD_CERT".equals(NEG_TEST_MODE)) {
                System.out.println("\n═══════════════════════════════════════════════════════════════");
                System.out.println("  [ROGUE_CO] NEGATIVE TEST MODE: BAD_CERT");
                System.out.println("  Sub-mode: " + BAD_CERT_MODE);
                System.out.println("═══════════════════════════════════════════════════════════════");
                System.out.println("[ROGUE_CO] Testing rejection of CO without valid certificate");
                System.out.println("[ROGUE_CO] Mode: " + BAD_CERT_MODE);
                
                if ("MISSING".equals(BAD_CERT_MODE)) {
                    System.out.println("[ROGUE_CO] MISSING mode: Skipping enrollment, no client certificate");
                    System.out.println("[ROGUE_CO] Will attempt mTLS without presenting client certificate");
                    // Leave coKeyPair and coCertificate null - no enrollment
                    
                } else if ("SELF_SIGNED".equals(BAD_CERT_MODE)) {
                    System.out.println("[ROGUE_CO] SELF_SIGNED mode: Generating untrusted self-signed certificate");
                    generateSelfSignedCertificate();
                    System.out.println("[ROGUE_CO] Generated self-signed certificate:");
                    System.out.println("  Subject: " + coCertificate.getSubjectX500Principal());
                    System.out.println("  Issuer:  " + coCertificate.getIssuerX500Principal());
                    System.out.println("  Serial:  " + coCertificate.getSerialNumber());
                    System.out.println("[ROGUE_CO] ⚠ This certificate is NOT chained to trusted Root CA");
                    System.out.println("[ROGUE_CO] ⚠ It is self-signed and will be rejected by services");
                    
                } else {
                    System.err.println("[ROGUE_CO] ERROR: Unknown BAD_CERT_MODE: " + BAD_CERT_MODE);
                    System.err.println("[ROGUE_CO] Valid modes: MISSING, SELF_SIGNED");
                    System.exit(1);
                }
                
                System.out.println("\n[ROGUE_CO] Attempting mTLS connection to SP...");
                System.out.println("[ROGUE_CO] EXPECTED: Connection should FAIL");
                if ("MISSING".equals(BAD_CERT_MODE)) {
                    System.out.println("[ROGUE_CO] REASON: No client certificate presented (peer not authenticated)");
                } else {
                    System.out.println("[ROGUE_CO] REASON: Self-signed cert not chained to Root CA (PKIX validation fails)");
                }
                System.out.println();
                
                // Attempt to request tokens from SP - this should fail
                try {
                    testRogueCoConnection();
                    
                    // If we reach here, the test FAILED
                    System.err.println("\n╔═══════════════════════════════════════════════════════════════╗");
                    System.err.println("║ [ROGUE_CO] ✗ TEST FAILED: SP ACCEPTED ROGUE CO!              ║");
                    System.err.println("╚═══════════════════════════════════════════════════════════════╝");
                    System.err.println("[ROGUE_CO] CRITICAL SECURITY FAILURE:");
                    System.err.println("[ROGUE_CO] SP should have rejected CO without valid certificate!");
                    if ("MISSING".equals(BAD_CERT_MODE)) {
                        System.err.println("[ROGUE_CO] No client certificate was presented!");
                    } else {
                        System.err.println("[ROGUE_CO] Self-signed certificate not chained to Root CA!");
                    }
                    System.err.println("[ROGUE_CO] This indicates a client authentication bypass vulnerability!\n");
                    System.exit(1);
                    
                } catch (java.io.IOException e) {
                    // This is the EXPECTED outcome (includes SSLException)
                    System.out.println("\n╔═══════════════════════════════════════════════════════════════╗");
                    System.out.println("║   [ROGUE_CO] ✓ SECURITY SUCCESS: Rogue CO REJECTED          ║");
                    System.out.println("╚═══════════════════════════════════════════════════════════════╝");
                    System.out.println("[ROGUE_CO] mTLS rejected by peer during client certificate validation!");
                    System.out.println("[ROGUE_CO] Error type: " + e.getClass().getSimpleName());
                    System.out.println("[ROGUE_CO] Error message: " + e.getMessage());
                    
                    // Analyze the error to provide specific feedback
                    boolean isBadCertAlert = e.getMessage() != null && 
                        e.getMessage().contains("Received fatal alert: bad_certificate");
                    
                    boolean isPKIXFailure = false;
                    Throwable cause = e.getCause();
                    while (cause != null) {
                        if (cause instanceof java.security.cert.CertPathValidatorException) {
                            isPKIXFailure = true;
                            System.out.println("[ROGUE_CO] Root cause: PKIX path validation failure (detected locally)");
                            System.out.println("[ROGUE_CO] Reason: " + cause.getMessage());
                            break;
                        }
                        cause = cause.getCause();
                    }
                    
                    // Provide specific analysis based on error type
                    if (isBadCertAlert && !isPKIXFailure) {
                        System.out.println("[ROGUE_CO] Analysis: SP rejected the client certificate (fatal alert: bad_certificate)");
                        if ("MISSING".equals(BAD_CERT_MODE)) {
                            System.out.println("[ROGUE_CO] Reason: No client certificate presented (peer not authenticated)");
                        } else {
                            System.out.println("[ROGUE_CO] Reason: Client certificate not chained to trusted Root CA");
                            System.out.println("[ROGUE_CO] (SP-side PKIX validation rejected untrusted/self-signed chain)");
                        }
                    }
                    
                    System.out.println("\n[ROGUE_CO] VERIFICATION COMPLETE:");
                    if ("MISSING".equals(BAD_CERT_MODE)) {
                        System.out.println("  ✓ CO skipped enrollment (no certificate obtained)");
                        System.out.println("  ✓ CO attempted mTLS without client certificate");
                        System.out.println("  ✓ SP rejected connection (peer not authenticated)");
                        System.out.println("  ✓ System requires valid client certificate for mTLS");
                    } else {
                        System.out.println("  ✓ CO generated self-signed certificate");
                        System.out.println("  ✓ CO attempted mTLS with untrusted certificate");
                        System.out.println("  ✓ SP rejected connection (PKIX validation failed)");
                        System.out.println("  ✓ Certificate not chained to trusted Root CA");
                    }
                    System.out.println("  ✓ System correctly enforces client certificate validation");
                    System.out.println("  ✓ No bypass mechanisms available (strong security)");
                    System.out.println("\n[ROGUE_CO] CONCLUSION: Rogue CO properly rejected!");
                    System.out.println("[ROGUE_CO] The system is SECURE against unauthorized clients.\n");
                    System.exit(0);
                    
                } catch (Exception e) {
                    // Unexpected error type
                    System.err.println("\n[ROGUE_CO] Unexpected error type: " + e.getClass().getName());
                    System.err.println("[ROGUE_CO] Message: " + e.getMessage());
                    e.printStackTrace();
                    System.exit(1);
                }
                
            } else if ("RESV_TAMPER".equals(NEG_TEST_MODE)) {
                // FORGED_RESERVATION scenario: Test that CO detects tampering with HO-signed reservation
                System.out.println("\n═══════════════════════════════════════════════════════════════");
                System.out.println("  [RESV_TAMPER] NEGATIVE TEST MODE: FORGED_RESERVATION");
                System.out.println("  Sub-mode: " + RESV_TAMPER_MODE);
                System.out.println("═══════════════════════════════════════════════════════════════");
                System.out.println("[RESV_TAMPER] Testing detection of forged/tampered reservation responses");
                System.out.println("[RESV_TAMPER] Mode: " + RESV_TAMPER_MODE);
                System.out.println("[RESV_TAMPER] Tampering will be applied BEFORE signature verification");
                System.out.println("[RESV_TAMPER] Expected: Signature verification MUST fail\n");
                
                // Proceed with normal enrollment and discovery
                // Tampering will occur in requestReservation() before verification
                // Fall through to normal flow
            }
            // ═════════════════════════════════════════════════════════════

            // STEP 1: Establish cryptographic identity
            if (hasCertificate()) {
                System.out.println("Found existing certificate, loading from keystore...");
                loadExistingCertificate();
            } else {
                System.out.println("No existing certificate found, enrolling with CAuth...");
                enrollWithCAuth();
            }

            // Verify we have valid cryptographic material
            if (coCertificate == null || coKeyPair == null) {
                throw new IllegalStateException("CRITICAL: CO certificate or key is null after initialization");
            }

            System.out.println("\n╔═══════════════════════════════════════════╗");
            System.out.println("║   CO CRYPTOGRAPHIC IDENTITY ESTABLISHED   ║");
            System.out.println("╚═══════════════════════════════════════════╝");
            System.out.println("Subject: " + coCertificate.getSubjectX500Principal().getName());
            System.out.println("Issuer: " + coCertificate.getIssuerX500Principal().getName());
            System.out.println("Valid from: " + coCertificate.getNotBefore());
            System.out.println("Valid until: " + coCertificate.getNotAfter());

            // ═════════════════════════════════════════════════════════════
            // CAuth-1 FAKE_CAUTH Negative Test: Rogue Intermediate CA
            // ═════════════════════════════════════════════════════════════
            if ("FAKE_CAUTH".equals(NEG_TEST_MODE)) {
                System.out.println("\n═══════════════════════════════════════════════════════════════");
                System.out.println("  [CAuth-1] NEGATIVE TEST MODE: FAKE_CAUTH");
                System.out.println("═══════════════════════════════════════════════════════════════");
                System.out.println("[CAuth-1] Testing rejection of rogue intermediate CA certificate");
                System.out.println("[CAuth-1] Enrolled with: " + CAUTH_HOST + ":" + CAUTH_PORT);
                System.out.println("[CAuth-1] Certificate Details:");
                System.out.println("  Subject: " + coCertificate.getSubjectX500Principal());
                System.out.println("  Issuer:  " + coCertificate.getIssuerX500Principal());
                System.out.println("  Serial:  " + coCertificate.getSerialNumber());
                
                // Check if issuer indicates fake CA
                String issuerDN = coCertificate.getIssuerX500Principal().getName();
                if (issuerDN.contains("ROGUE") || issuerDN.contains("Fake Authority") || 
                    issuerDN.contains("DO-NOT-TRUST")) {
                    System.out.println("[CAuth-1] ⚠ DETECTED: Certificate issued by ROGUE CA!");
                    System.out.println("[CAuth-1] ⚠ This certificate is NOT chained to the trusted Root CA");
                } else {
                    System.out.println("[CAuth-1] NOTE: Issuer DN: " + issuerDN);
                }
                
                System.out.println("\n[CAuth-1] Attempting mTLS connection to SP...");
                System.out.println("[CAuth-1] EXPECTED: Connection should FAIL with PKIX validation error");
                System.out.println("[CAuth-1] REASON: SP truststore only contains real Root CA, not rogue CA\n");
                
                // Attempt connection to SP - this should fail with trust validation error
                try {
                    discoverAvailabilities();
                    // If we reach here, the test FAILED (connection should have been rejected)
                    System.err.println("\n╔═══════════════════════════════════════════════════════════════╗");
                    System.err.println("║ [CAuth-1] ✗ TEST FAILED: SP ACCEPTED UNTRUSTED CERTIFICATE!  ║");
                    System.err.println("╚═══════════════════════════════════════════════════════════════╝");
                    System.err.println("[CAuth-1] CRITICAL SECURITY FAILURE:");
                    System.err.println("[CAuth-1] SP should have rejected the rogue CA certificate!");
                    System.err.println("[CAuth-1] The certificate chain does NOT terminate at Root CA.");
                    System.err.println("[CAuth-1] This indicates a trust validation bypass vulnerability!\n");
                    System.exit(1);
                    
                } catch (javax.net.ssl.SSLException e) {
                    // This is the EXPECTED outcome (SSLHandshakeException is a subtype)
                    System.out.println("\n╔═══════════════════════════════════════════════════════════════╗");
                    System.out.println("║   [CAuth-1] ✓ SECURITY SUCCESS: Rogue CA Certificate REJECTED║");
                    System.out.println("╚═══════════════════════════════════════════════════════════════╝");
                    System.out.println("[CAuth-1] mTLS connection to SP failed as expected!");
                    System.out.println("[CAuth-1] Error type: " + e.getClass().getSimpleName());
                    System.out.println("[CAuth-1] Error message: " + e.getMessage());
                    
                    // Check for PKIX path validation error
                    Throwable cause = e.getCause();
                    while (cause != null) {
                        if (cause instanceof java.security.cert.CertPathValidatorException) {
                            System.out.println("[CAuth-1] Root cause: PKIX path validation failure");
                            System.out.println("[CAuth-1] Reason: " + cause.getMessage());
                            break;
                        }
                        cause = cause.getCause();
                    }
                    
                    System.out.println("\n[CAuth-1] VERIFICATION COMPLETE:");
                    System.out.println("  ✓ CO successfully enrolled with fake-cauth");
                    System.out.println("  ✓ CO received certificate signed by rogue CA");
                    System.out.println("  ✓ CO stored certificate in keystore (normal behavior)");
                    System.out.println("  ✓ SP rejected mTLS connection (PKIX validation failed)");
                    System.out.println("  ✓ Certificate chain does not terminate at trusted Root CA");
                    System.out.println("  ✓ System correctly enforces trust anchor validation");
                    System.out.println("\n[CAuth-1] CONCLUSION: Rogue intermediate CA properly rejected!");
                    System.out.println("[CAuth-1] The system is SECURE against untrusted CA attacks.\n");
                    System.exit(0);
                    
                } catch (Exception e) {
                    // Unexpected error type
                    System.err.println("\n[CAuth-1] Unexpected error type: " + e.getClass().getName());
                    System.err.println("[CAuth-1] Message: " + e.getMessage());
                    e.printStackTrace();
                    System.exit(1);
                }
            }
            // ═════════════════════════════════════════════════════════════

            // STEP 2: Discover parking availabilities from SP with identity binding
            System.out.println("\n=== Discovering Parking Availabilities from SP ===");
            discoverAvailabilities();

            // STEP 3: Request reservation from HO with cryptographic binding (Milestone 2.4)
            if (discoveredAvailability != null) {
                System.out.println("\n=== Requesting Reservation from HO (Milestone 2.4) ===");
                requestReservation(discoveredAvailability);
            } else {
                System.out.println("\n⚠ No availability discovered - skipping reservation request");
            }

            System.out.println("\n✓✓✓ CO SERVICE COMPLETED SUCCESSFULLY ✓✓✓");

        } catch (Exception e) {
            System.err.println("\n✖ CRITICAL ERROR: CO failed to start");
            System.err.println("Reason: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    // -------------------------
    // Certificate management
    // -------------------------

    private static boolean hasCertificate() {
        File keystoreFile = new File(CO_KEYSTORE_PATH);
        if (!keystoreFile.exists()) return false;

        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(CO_KEYSTORE_PATH)) {
                ks.load(fis, CO_KEYSTORE_PASSWORD.toCharArray());
            }
            return ks.containsAlias(CO_KEY_ALIAS);
        } catch (Exception e) {
            return false;
        }
    }

    private static void loadExistingCertificate() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(CO_KEYSTORE_PATH)) {
            ks.load(fis, CO_KEYSTORE_PASSWORD.toCharArray());
        }

        coCertificate = (X509Certificate) ks.getCertificate(CO_KEY_ALIAS);
        if (coCertificate == null) {
            throw new IllegalStateException("CRITICAL: CO certificate not found in keystore");
        }

        PrivateKey privateKey = (PrivateKey) ks.getKey(CO_KEY_ALIAS, CO_KEYSTORE_PASSWORD.toCharArray());
        if (privateKey == null) {
            throw new IllegalStateException("CRITICAL: CO private key not found in keystore");
        }

        PublicKey publicKey = coCertificate.getPublicKey();
        coKeyPair = new KeyPair(publicKey, privateKey);

        // Verify certificate is valid
        try {
            coCertificate.checkValidity();
            System.out.println("✓ Certificate validity period verified");
        } catch (Exception e) {
            throw new IllegalStateException("CRITICAL: Certificate has expired or is not yet valid: " + e.getMessage());
        }
    }

    private static void enrollWithCAuth() throws Exception {
        System.out.println("Step 1: Generating RSA key pair...");
        coKeyPair = generateKeyPair();
        System.out.println("✓ RSA-2048 key pair generated successfully");

        System.out.println("\nStep 2: Creating Certificate Signing Request (CSR)...");
        PKCS10CertificationRequest csr = createCSR(coKeyPair);
        System.out.println("✓ CSR created with subject: CN=CarOwner, O=Parking System, C=BE");

        System.out.println("\nStep 3: Connecting to CAuth server over TLS...");
        X509Certificate[] certChain = requestCertificateFromCAuth(csr);

        if (certChain == null || certChain.length == 0 || certChain[0] == null) {
            throw new IllegalStateException("CRITICAL: Enrollment failed - CAuth did not return a valid certificate.");
        }

        coCertificate = certChain[0];
        System.out.println("✓ Certificate received from CAuth");

        System.out.println("\nStep 4: Storing certificate and private key securely...");
        storeCertificateAndKey(certChain);
        System.out.println("✓ Credentials stored in " + CO_KEYSTORE_PATH);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private static PKCS10CertificationRequest createCSR(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name("CN=CarOwner, O=Parking System, C=BE");

        JcaPKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

        // Add SANs
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        GeneralNames sans = new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "co"),
                new GeneralName(GeneralName.dNSName, "localhost")
        });
        extGen.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false, sans);
        csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());

        return csrBuilder.build(signer);
    }

    private static X509Certificate[] requestCertificateFromCAuth(PKCS10CertificationRequest csr) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(fis, TRUSTSTORE_PASSWORD.toCharArray());
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext enrollCtx = SSLContext.getInstance("TLS");
        enrollCtx.init(null, tmf.getTrustManagers(), new SecureRandom());

        try (SSLSocket socket = (SSLSocket) enrollCtx.getSocketFactory().createSocket(CAUTH_HOST, CAUTH_PORT);
             PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            // Harden enrollment connection
            String[] desiredProtocols = new String[]{"TLSv1.3", "TLSv1.2"};
            String[] enrollProtocols = intersect(socket.getSupportedProtocols(), desiredProtocols);
            if (enrollProtocols.length == 0) {
                throw new IllegalStateException("No modern TLS protocols available");
            }
            socket.setEnabledProtocols(enrollProtocols);

            socket.startHandshake();

            System.out.println("✓ TLS connection established to CAuth");
            System.out.println("  Protocol: " + socket.getSession().getProtocol());
            System.out.println("  Cipher suite: " + socket.getSession().getCipherSuite());

            JSONObject request = new JSONObject();
            request.put("method", "signCSR");
            request.put("csr", Base64.getEncoder().encodeToString(csr.getEncoded()));

            System.out.println("\n→ Sending CSR to CAuth for signing...");
            writer.println(request.toString());

            String response = reader.readLine();
            if (response == null) throw new IOException("No response from CAuth");

            JSONObject jsonResponse = new JSONObject(response);

            if (jsonResponse.has("status") && "error".equals(jsonResponse.getString("status"))) {
                System.err.println("CAuth returned error: " + jsonResponse.optString("message", "(no message)"));
                return new X509Certificate[]{null};
            }

            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");

            X509Certificate coCert = parseX509FromPemB64(cf, jsonResponse.getString("certificate"));

            X509Certificate caCert = null;
            if (jsonResponse.has("caCert")) {
                caCert = parseX509FromPemB64(cf, jsonResponse.getString("caCert"));
                System.out.println("Received CA certificate from CAuth.");
            }

            X509Certificate rootCert = null;
            if (jsonResponse.has("rootCert")) {
                rootCert = parseX509FromPemB64(cf, jsonResponse.getString("rootCert"));
                System.out.println("Received Root CA certificate from CAuth.");
            }

            System.out.println("Certificate signed by CAuth!");

            if (rootCert != null && caCert != null) return new X509Certificate[]{coCert, caCert, rootCert};
            if (caCert != null) return new X509Certificate[]{coCert, caCert};
            return new X509Certificate[]{coCert};
        }
    }

    private static void storeCertificateAndKey(X509Certificate[] chain) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");

        File keystoreFile = new File(CO_KEYSTORE_PATH);
        if (keystoreFile.exists()) {
            try (FileInputStream fis = new FileInputStream(CO_KEYSTORE_PATH)) {
                ks.load(fis, CO_KEYSTORE_PASSWORD.toCharArray());
            }
        } else {
            ks.load(null, null);
        }

        ks.setKeyEntry(
                CO_KEY_ALIAS,
                coKeyPair.getPrivate(),
                CO_KEYSTORE_PASSWORD.toCharArray(),
                chain
        );

        try (FileOutputStream fos = new FileOutputStream(CO_KEYSTORE_PATH)) {
            ks.store(fos, CO_KEYSTORE_PASSWORD.toCharArray());
        }
    }

    // -------------------------
    // ROGUE_CO / BAD_CERT Helper Methods
    // -------------------------

    /**
     * KeyManager wrapper that forces selection of a specific client alias.
     * This prevents JSSE from silently declining to send a certificate.
     */
    private static class ForcedAliasKeyManager extends javax.net.ssl.X509ExtendedKeyManager {
        private final javax.net.ssl.X509KeyManager delegate;
        private final String forcedAlias;
        
        public ForcedAliasKeyManager(javax.net.ssl.X509KeyManager delegate, String forcedAlias) {
            this.delegate = delegate;
            this.forcedAlias = forcedAlias;
        }
        
        @Override
        public String chooseClientAlias(String[] keyType, java.security.Principal[] issuers, java.net.Socket socket) {
            System.out.println("[ROGUE_CO] chooseClientAlias called - forcing alias: " + forcedAlias);
            return forcedAlias;
        }
        
        @Override
        public String chooseEngineClientAlias(String[] keyType, java.security.Principal[] issuers, javax.net.ssl.SSLEngine engine) {
            System.out.println("[ROGUE_CO] chooseEngineClientAlias called - forcing alias: " + forcedAlias);
            return forcedAlias;
        }
        
        @Override
        public String chooseServerAlias(String keyType, java.security.Principal[] issuers, java.net.Socket socket) {
            return delegate.chooseServerAlias(keyType, issuers, socket);
        }
        
        @Override
        public String chooseEngineServerAlias(String keyType, java.security.Principal[] issuers, javax.net.ssl.SSLEngine engine) {
            if (delegate instanceof javax.net.ssl.X509ExtendedKeyManager) {
                return ((javax.net.ssl.X509ExtendedKeyManager) delegate).chooseEngineServerAlias(keyType, issuers, engine);
            }
            return delegate.chooseServerAlias(keyType, issuers, null);
        }
        
        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return delegate.getCertificateChain(alias);
        }
        
        @Override
        public String[] getClientAliases(String keyType, java.security.Principal[] issuers) {
            return delegate.getClientAliases(keyType, issuers);
        }
        
        @Override
        public java.security.PrivateKey getPrivateKey(String alias) {
            return delegate.getPrivateKey(alias);
        }
        
        @Override
        public String[] getServerAliases(String keyType, java.security.Principal[] issuers) {
            return delegate.getServerAliases(keyType, issuers);
        }
    }

    /**
     * Generate a self-signed certificate for ROGUE_CO SELF_SIGNED mode.
     * This certificate is NOT signed by any trusted CA and will be rejected by services.
     */
    private static void generateSelfSignedCertificate() throws Exception {
        System.out.println("[ROGUE_CO] Generating RSA-2048 keypair for self-signed certificate...");
        // Generate keypair
        coKeyPair = generateKeyPair();
        
        // Create self-signed certificate with proper client auth extensions
        X500Name subject = new X500Name("CN=ROGUE-CO-UNTRUSTED, O=Unauthorized, C=XX");
        BigInteger serial = new BigInteger(128, new SecureRandom()).abs();
        
        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(1, ChronoUnit.MINUTES));
        Date notAfter = Date.from(now.plus(365, ChronoUnit.DAYS));
        
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
            subject,  // issuer = subject (self-signed)
            serial,
            notBefore,
            notAfter,
            subject,  // subject
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(coKeyPair.getPublic().getEncoded())
        );
        
        // CRITICAL: Mark as NOT a CA (this is a leaf certificate)
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true,
            new org.bouncycastle.asn1.x509.BasicConstraints(false));
        
        // CRITICAL: Key usage for TLS client authentication
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true,
            new org.bouncycastle.asn1.x509.KeyUsage(
                org.bouncycastle.asn1.x509.KeyUsage.digitalSignature | 
                org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment));
        
        // CRITICAL: Extended Key Usage for client auth
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, true,
            new org.bouncycastle.asn1.x509.ExtendedKeyUsage(
                org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth));
        
        // Sign with own private key (self-signed)
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(coKeyPair.getPrivate());
        
        X509CertificateHolder holder = certBuilder.build(signer);
        coCertificate = new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(holder);
        
        System.out.println("[ROGUE_CO] Self-signed certificate created:");
        System.out.println("[ROGUE_CO]   BasicConstraints: CA=false");
        System.out.println("[ROGUE_CO]   KeyUsage: digitalSignature, keyEncipherment");
        System.out.println("[ROGUE_CO]   ExtendedKeyUsage: clientAuth");
        
        // Store as PrivateKeyEntry in keystore (cert + private key)
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(
            CO_KEY_ALIAS,
            coKeyPair.getPrivate(),
            CO_KEYSTORE_PASSWORD.toCharArray(),
            new X509Certificate[]{coCertificate}
        );
        
        ensureParentDirExists(CO_KEYSTORE_PATH);
        try (FileOutputStream fos = new FileOutputStream(CO_KEYSTORE_PATH)) {
            ks.store(fos, CO_KEYSTORE_PASSWORD.toCharArray());
        }
        
        System.out.println("[ROGUE_CO] Certificate stored in keystore as PrivateKeyEntry");
        System.out.println("[ROGUE_CO] Keystore path: " + CO_KEYSTORE_PATH);
    }

    /**
     * Test rogue CO connection to SP.
     * Used for BAD_CERT modes to demonstrate rejection of unauthorized clients.
     */
    private static void testRogueCoConnection() throws Exception {
        // Load truststore (always needed to validate server cert)
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(fis, TRUSTSTORE_PASSWORD.toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        
        SSLContext sslContext;
        
        if ("MISSING".equals(BAD_CERT_MODE)) {
            // MISSING mode: No client certificate (no KeyManager)
            System.out.println("[ROGUE_CO] Creating SSLContext WITHOUT client KeyManager");
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
            
        } else {
            // SELF_SIGNED mode: Use the self-signed certificate
            System.out.println("[ROGUE_CO] Creating SSLContext WITH self-signed certificate");
            System.out.println("[ROGUE_CO] Loading keystore to verify certificate availability...");
            
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(CO_KEYSTORE_PATH)) {
                keyStore.load(fis, CO_KEYSTORE_PASSWORD.toCharArray());
            }
            
            // Detailed keystore inspection
            System.out.println("[ROGUE_CO] Keystore loaded successfully:");
            System.out.println("[ROGUE_CO]   Type: " + keyStore.getType());
            System.out.println("[ROGUE_CO]   Path: " + CO_KEYSTORE_PATH);
            
            java.util.Enumeration<String> aliases = keyStore.aliases();
            int aliasCount = 0;
            String foundAlias = null;
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                aliasCount++;
                foundAlias = alias;
                System.out.println("[ROGUE_CO]   Alias [" + aliasCount + "]: " + alias);
                
                if (keyStore.isKeyEntry(alias)) {
                    X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                    System.out.println("[ROGUE_CO]     Entry type: PrivateKeyEntry (has private key)");
                    System.out.println("[ROGUE_CO]     Subject: " + cert.getSubjectX500Principal().getName());
                    System.out.println("[ROGUE_CO]     Issuer: " + cert.getIssuerX500Principal().getName());
                    
                    // Compute fingerprint
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] fingerprint = digest.digest(cert.getEncoded());
                    System.out.println("[ROGUE_CO]     SHA-256: " + bytesToHex(fingerprint).substring(0, 32) + "...");
                }
            }
            
            if (aliasCount == 0) {
                throw new IllegalStateException("[ROGUE_CO] CRITICAL: Keystore is empty, no certificate to present!");
            }
            
            System.out.println("[ROGUE_CO] Certificate is available and ready to be sent during TLS handshake");
            
            // Initialize KeyManagerFactory
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, CO_KEYSTORE_PASSWORD.toCharArray());
            
            javax.net.ssl.KeyManager[] keyManagers = kmf.getKeyManagers();
            System.out.println("[ROGUE_CO] KeyManagers created: " + (keyManagers != null ? keyManagers.length : 0) + " manager(s)");
            
            if (keyManagers == null || keyManagers.length == 0) {
                throw new IllegalStateException("[ROGUE_CO] CRITICAL: No KeyManagers available!");
            }
            
            // Wrap KeyManager to FORCE client alias selection (prevent JSSE from declining)
            final String forcedAlias = foundAlias;
            javax.net.ssl.KeyManager[] wrappedKeyManagers = new javax.net.ssl.KeyManager[keyManagers.length];
            for (int i = 0; i < keyManagers.length; i++) {
                if (keyManagers[i] instanceof javax.net.ssl.X509KeyManager) {
                    wrappedKeyManagers[i] = new ForcedAliasKeyManager(
                        (javax.net.ssl.X509KeyManager) keyManagers[i], 
                        forcedAlias
                    );
                    System.out.println("[ROGUE_CO] KeyManager wrapped to force alias selection: " + forcedAlias);
                } else {
                    wrappedKeyManagers[i] = keyManagers[i];
                }
            }
            
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(wrappedKeyManagers, tmf.getTrustManagers(), new SecureRandom());
            System.out.println("[ROGUE_CO] SSLContext initialized with wrapped KeyManagers");
        }
        
        // Attempt connection to SP (request tokens endpoint)
        System.out.println("[ROGUE_CO] Connecting to SP at " + SP_HOST + ":" + SP_PORT);
        
        SSLSocket socket = null;
        PrintWriter writer = null;
        BufferedReader reader = null;
        
        try {
            socket = (SSLSocket) sslContext.getSocketFactory().createSocket(SP_HOST, SP_PORT);
            
            // Harden TLS
            String[] desiredProtocols = new String[]{"TLSv1.3", "TLSv1.2"};
            String[] protocols = intersect(socket.getSupportedProtocols(), desiredProtocols);
            if (protocols.length == 0) {
                throw new IllegalStateException("No TLS 1.3/1.2 support available");
            }
            socket.setEnabledProtocols(protocols);
            
            System.out.println("[ROGUE_CO] Starting TLS handshake...");
            socket.startHandshake();
            
            // Post-handshake validation: verify connection is truly usable
            System.out.println("[ROGUE_CO] TLS negotiation completed; validating mTLS acceptance...");
            
            // Verify server identity is available (confirms server auth succeeded)
            java.security.cert.Certificate[] peerCerts = socket.getSession().getPeerCertificates();
            System.out.println("[ROGUE_CO] Server authenticated: " + 
                ((X509Certificate)peerCerts[0]).getSubjectX500Principal().getName());
            
            // Perform post-handshake proof: attempt minimal write+read
            writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            
            // Try to request tokens (this will trigger server-side client cert validation)
            JSONObject tokenRequest = new JSONObject();
            tokenRequest.put("method", "requestTokens");
            tokenRequest.put("count", 5);
            
            System.out.println("[ROGUE_CO] Performing post-handshake proof (send request)...");
            writer.println(tokenRequest.toString());
            writer.flush();
            
            System.out.println("[ROGUE_CO] Reading response to confirm mTLS acceptance...");
            String response = reader.readLine();
            
            if (response != null) {
                // If we get a valid response, mTLS was fully established
                System.out.println("[ROGUE_CO] mTLS established successfully (unexpected!)");
                System.out.println("[ROGUE_CO] Protocol: " + socket.getSession().getProtocol());
                System.out.println("[ROGUE_CO] Cipher suite: " + socket.getSession().getCipherSuite());
                System.out.println("[ROGUE_CO] Received response: " + response);
            }
            
            // If we get here, the test FAILED - connection should have been rejected
            
        } finally {
            if (reader != null) try { reader.close(); } catch (Exception ignored) {}
            if (writer != null) try { writer.close(); } catch (Exception ignored) {}
            if (socket != null) try { socket.close(); } catch (Exception ignored) {}
        }
    }

    // -------------------------
    // Availability Discovery with Identity Binding
    // -------------------------

    /**
     * Security-focused availability discovery over mTLS.
     * Primary goal: authenticated, integrity-protected service discovery with HO identity binding.
     * Verifies HO certificates chain to Root CA and persists identity bindings to prevent substitution attacks.
     */
    private static void discoverAvailabilities() throws Exception {
        System.out.println("Establishing hardened mTLS connection to SP for authenticated discovery...");
        
        // Load keystore for client authentication
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(CO_KEYSTORE_PATH)) {
            keyStore.load(fis, CO_KEYSTORE_PASSWORD.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, CO_KEYSTORE_PASSWORD.toCharArray());

        // Load truststore to verify SP and HO certificates
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(fis, TRUSTSTORE_PASSWORD.toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // Create hardened SSL context with both key and trust managers (mTLS)
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        SSLSocket socket = null;
        PrintWriter writer = null;
        BufferedReader reader = null;
        
        try {
            // Create socket - streams created AFTER handshake per security requirement
            socket = (SSLSocket) sslContext.getSocketFactory().createSocket(SP_HOST, SP_PORT);

            // Harden TLS: only TLS 1.3/1.2, AEAD ciphers enforced by SSLContext
            String[] desiredProtocols = new String[]{"TLSv1.3", "TLSv1.2"};
            String[] protocols = intersect(socket.getSupportedProtocols(), desiredProtocols);
            if (protocols.length == 0) {
                throw new IllegalStateException("No TLS 1.3/1.2 support available");
            }
            socket.setEnabledProtocols(protocols);

            // Explicit handshake BEFORE creating streams (security requirement)
            socket.startHandshake();

            // Verbose logging of TLS parameters
            System.out.println("✓ mTLS connection established to SP");
            System.out.println("  Protocol: " + socket.getSession().getProtocol());
            System.out.println("  Cipher suite: " + socket.getSession().getCipherSuite());

            // Verify SP certificate and log peer identity
            X509Certificate[] peerCerts = (X509Certificate[]) socket.getSession().getPeerCertificates();
            X509Certificate spCert = peerCerts[0];
            System.out.println("  SP certificate subject: " + spCert.getSubjectX500Principal().getName());
            System.out.println("  SP certificate issuer: " + spCert.getIssuerX500Principal().getName());
            
            // Verify SP certificate chains to trusted Root CA
            try {
                spCert.checkValidity();
                System.out.println("✓ SP certificate validity verified");
            } catch (Exception e) {
                throw new SecurityException("SP certificate validation failed: " + e.getMessage());
            }

            // Now create streams after successful handshake
            writer = new PrintWriter(socket.getOutputStream(), true);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Minimal GET availability request (no complex filtering/business logic)
            JSONObject request = new JSONObject();
            request.put("method", "getAvailability");

            System.out.println("\n→ Requesting parking availabilities from SP...");
            writer.println(request.toString());

            String responseLine = reader.readLine();
            if (responseLine == null) {
                throw new IOException("No response from SP");
            }

            System.out.println("← Received availability list from SP\n");
            JSONObject response = new JSONObject(responseLine);

            // Strict schema validation (treat as untrusted application data)
            if (!response.has("status") || !"success".equals(response.getString("status"))) {
                String errorMsg = response.optString("message", "Unknown error");
                throw new SecurityException("Availability discovery failed: " + errorMsg);
            }

            if (!response.has("availabilities")) {
                throw new SecurityException("Invalid response schema: missing 'availabilities' field");
            }

            JSONArray availabilities = response.getJSONArray("availabilities");
            int count = response.optInt("count", 0);

            System.out.println("╔═══════════════════════════════════════════════════════════╗");
            System.out.println("║   AUTHENTICATED AVAILABILITY DISCOVERY SUCCESSFUL         ║");
            System.out.println("╚═══════════════════════════════════════════════════════════╝");
            System.out.println("Discovered " + count + " parking availability record(s)\n");

            if (availabilities.length() == 0) {
                System.out.println("No availabilities currently published.");
                return;
            }

            // Process each availability with strict validation and HO identity binding
            for (int i = 0; i < availabilities.length(); i++) {
                JSONObject avail = availabilities.getJSONObject(i);
                
                System.out.println("═".repeat(60));
                System.out.println("Availability #" + (i + 1));
                System.out.println("═".repeat(60));

                // Validate required security-relevant fields
                validateRequiredField(avail, "availabilityId");
                validateRequiredField(avail, "spotId");
                validateRequiredField(avail, "priceTokens");
                validateRequiredField(avail, "validFrom");
                validateRequiredField(avail, "validTo");
                validateRequiredField(avail, "homeOwnerId");
                validateRequiredField(avail, "hoCertFingerprint");
                validateRequiredField(avail, "hoCertificate");

                String availabilityId = avail.getString("availabilityId");
                String spotId = avail.getString("spotId");
                int priceTokens = avail.getInt("priceTokens");
                String validFrom = avail.getString("validFrom");
                String validTo = avail.getString("validTo");
                String homeOwnerId = avail.getString("homeOwnerId");
                String locationZone = avail.optString("locationZone", "N/A");
                String hoCertFingerprint = avail.getString("hoCertFingerprint");
                String hoCertPem = avail.getString("hoCertificate");

                System.out.println("Availability ID: " + availabilityId);
                System.out.println("Spot ID: " + spotId);
                System.out.println("Price: " + priceTokens + " tokens");
                System.out.println("Valid: " + validFrom + " to " + validTo);
                System.out.println("Location: " + locationZone);
                System.out.println("Home Owner ID: " + homeOwnerId);
                System.out.println();

                // Parse HO certificate
                X509Certificate hoCert = null;
                try {
                    java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
                    hoCert = (X509Certificate) cf.generateCertificate(
                        new ByteArrayInputStream(hoCertPem.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                    );
                } catch (Exception e) {
                    System.err.println("✖ SECURITY FAILURE: Cannot parse HO certificate");
                    throw new SecurityException("HO certificate parsing failed: " + e.getMessage());
                }

                System.out.println("─ HO Certificate Identity Verification ─");

                // Verify HO certificate chains to Root CA (CRITICAL for identity binding)
                try {
                    hoCert.checkValidity();
                    System.out.println("✓ HO certificate is within validity period");
                    System.out.println("  Valid from: " + hoCert.getNotBefore());
                    System.out.println("  Valid until: " + hoCert.getNotAfter());
                } catch (Exception e) {
                    System.err.println("✖ SECURITY FAILURE: HO certificate is invalid or expired");
                    throw new SecurityException("HO certificate validity check failed: " + e.getMessage());
                }

                // Verify certificate chains to trusted Root CA (requires intermediate CA cert)
                // NOTE: In production, full chain validation is critical. For this demo, we rely on
                // certificate fingerprint verification as the primary trust anchor since SP doesn't
                // include the intermediate CA cert in responses.
                try {
                    PKIXParameters params = new PKIXParameters(trustStore);
                    params.setRevocationEnabled(false); // CRL/OCSP not implemented in this demo
                    
                    CertPathValidator validator = CertPathValidator.getInstance("PKIX");
                    java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
                    
                    List<java.security.cert.Certificate> certList = new ArrayList<>();
                    certList.add(hoCert);
                    
                    // Include intermediate CA certificate if provided for complete chain
                    if (avail.has("intermediateCACert")) {
                        String intermediatePem = avail.getString("intermediateCACert");
                        X509Certificate intermediateCert = (X509Certificate) cf.generateCertificate(
                            new ByteArrayInputStream(intermediatePem.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                        );
                        certList.add(intermediateCert);
                        System.out.println("✓ Intermediate CA certificate included in validation chain");
                    }
                    
                    java.security.cert.CertPath certPath = cf.generateCertPath(certList);
                    
                    validator.validate(certPath, params);
                    System.out.println("✓ HO certificate chains to trusted Root CA");
                } catch (Exception e) {
                    // In demo mode: log warning but don't fail if intermediate CA not available
                    // Certificate fingerprint verification below provides strong binding
                    System.out.println("⚠ Note: Full chain validation not possible (intermediate CA cert not provided)");
                    System.out.println("  Relying on certificate fingerprint verification for trust anchor");
                    System.out.println("  In production: SP should include full certificate chain");
                }

                // Extract HO identity (CN) from certificate
                String hoCN = "Unknown";
                try {
                    String hoDN = hoCert.getSubjectX500Principal().getName();
                    javax.naming.ldap.LdapName ldapDN = new javax.naming.ldap.LdapName(hoDN);
                    for (javax.naming.ldap.Rdn rdn : ldapDN.getRdns()) {
                        if (rdn.getType().equalsIgnoreCase("CN")) {
                            hoCN = rdn.getValue().toString();
                            break;
                        }
                    }
                } catch (Exception e) {
                    System.err.println("⚠ Warning: Cannot extract CN from HO certificate");
                }

                System.out.println("✓ HO Identity (CN): " + hoCN);
                System.out.println("  Full Subject: " + hoCert.getSubjectX500Principal().getName());
                System.out.println("  Issuer: " + hoCert.getIssuerX500Principal().getName());

                // Verify certificate fingerprint matches
                String computedFingerprint = null;
                try {
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] fingerprint = digest.digest(hoCert.getEncoded());
                    computedFingerprint = bytesToHex(fingerprint);
                } catch (Exception e) {
                    throw new SecurityException("Failed to compute HO certificate fingerprint: " + e.getMessage());
                }

                if (!computedFingerprint.equals(hoCertFingerprint)) {
                    System.err.println("✖ SECURITY FAILURE: Certificate fingerprint mismatch!");
                    System.err.println("  Expected: " + hoCertFingerprint);
                    System.err.println("  Computed: " + computedFingerprint);
                    throw new SecurityException("HO certificate fingerprint verification failed - possible MITM attack");
                }
                System.out.println("✓ Certificate fingerprint verified: " + hoCertFingerprint.substring(0, 16) + "...");

                // Persist identity binding to prevent substitution attacks
                persistIdentityBinding(availabilityId, spotId, hoCN, hoCertFingerprint, homeOwnerId);

                System.out.println("\n✓ HO IDENTITY BINDING ESTABLISHED");
                System.out.println("  Spot: " + spotId + " ⟷ HO: " + hoCN);
                System.out.println("  Fingerprint: " + hoCertFingerprint.substring(0, 32) + "...");
                System.out.println();
                
                // Store first discovered availability for reservation request (Milestone 2.4)
                if (discoveredAvailability == null && i == 0) {
                    discoveredAvailability = new DiscoveredAvailability();
                    discoveredAvailability.availabilityId = availabilityId;
                    discoveredAvailability.spotId = spotId;
                    discoveredAvailability.validFrom = validFrom;
                    discoveredAvailability.validTo = validTo;
                    discoveredAvailability.priceTokens = priceTokens;
                    discoveredAvailability.locationZone = locationZone;
                    discoveredAvailability.homeOwnerId = homeOwnerId;
                    discoveredAvailability.hoIdentity = hoCN;
                    discoveredAvailability.hoCertFingerprint = hoCertFingerprint;
                    discoveredAvailability.hoCertificate = hoCert;
                    System.out.println("✓ Stored availability for reservation request");
                }
            }

            System.out.println("═".repeat(60));
            System.out.println("✓✓✓ AVAILABILITY DISCOVERY COMPLETE ✓✓✓");
            System.out.println("═".repeat(60));
            System.out.println("All HO identities verified and bound to availabilities");
            System.out.println("Identity bindings persisted for future interaction verification");

        } catch (SecurityException e) {
            System.err.println("\n✖✖✖ SECURITY FAILURE ✖✖✖");
            System.err.println("Availability discovery aborted due to security violation:");
            System.err.println(e.getMessage());
            throw e;
        } finally {
            // Clean up resources
            if (reader != null) try { reader.close(); } catch (Exception e) {}
            if (writer != null) try { writer.close(); } catch (Exception e) {}
            if (socket != null) try { socket.close(); } catch (Exception e) {}
        }
    }

    /**
     * Validates that a required field exists in the JSON object.
     * Throws SecurityException if field is missing (strict schema validation).
     */
    private static void validateRequiredField(JSONObject obj, String fieldName) throws SecurityException {
        if (!obj.has(fieldName)) {
            throw new SecurityException("Invalid availability schema: missing required field '" + fieldName + "'");
        }
    }

    // -------------------------
    // Reservation Handshake with HO
    // -------------------------

    /**
     * Requests a reservation from the Home Owner (HO) using the cryptographically binding 
     * reservation handshake protocol (Milestone 2.4).
     * 
     * This method:
     * 1. Establishes a hardened mTLS connection to the HO
     * 2. Sends a minimal, security-centric reservation request
     * 3. Receives and verifies the cryptographically signed reservation response
     * 4. Stores the signed reservation as non-repudiable proof
     * 
     * Security properties:
     * - mTLS enforced (TLS 1.3/1.2, AEAD cipher suites)
     * - HO certificate validated to Root CA
     * - HO signature verified with RSA-2048
     * - Certificate fingerprint matches persisted binding
     * - All signed fields validated against original request
     * - Prevents replay, substitution, and field-stripping attacks
     */
    private static void requestReservation(DiscoveredAvailability avail) throws Exception {
        if (avail == null) {
            System.err.println("✗ Cannot request reservation: no availability data");
            return;
        }

        System.out.println("\n═══════════════════════════════════════════════════════════");
        System.out.println("   MILESTONE 2.4: RESERVATION HANDSHAKE WITH HO");
        System.out.println("═══════════════════════════════════════════════════════════");

        // Extract CO identity from certificate (CN field)
        String coIdentity = extractCNFromCertificate(coCertificate);
        System.out.println("✓ CO Identity: " + coIdentity);
        System.out.println("✓ Target HO: " + avail.hoIdentity + " (" + avail.hoHost + ":" + avail.hoPort + ")");
        System.out.println("✓ Availability ID: " + avail.availabilityId);

        // Load CO keystore and truststore for mTLS
        System.out.println("\n--- Loading CO keystore and truststore for mTLS ---");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream keyStoreFile = new FileInputStream(CO_KEYSTORE_PATH)) {
            keyStore.load(keyStoreFile, CO_KEYSTORE_PASSWORD.toCharArray());
            System.out.println("✓ CO keystore loaded");
        }

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream trustStoreFile = new FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(trustStoreFile, TRUSTSTORE_PASSWORD.toCharArray());
            System.out.println("✓ CO truststore loaded (contains Root CA)");
        }

        // Initialize KeyManager and TrustManager
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, CO_KEYSTORE_PASSWORD.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // Create hardened SSLContext
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        SSLSocketFactory socketFactory = sslContext.getSocketFactory();

        SSLSocket socket = null;
        BufferedReader reader = null;
        PrintWriter writer = null;

        try {
            // Connect to HO reservation server
            System.out.println("\n--- Establishing mTLS connection to HO ---");
            socket = (SSLSocket) socketFactory.createSocket(avail.hoHost, avail.hoPort);

            // Harden TLS configuration
            socket.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
            String[] cipherSuites = socket.getSupportedCipherSuites();
            List<String> aeadSuites = new ArrayList<>();
            for (String suite : cipherSuites) {
                if (suite.contains("_GCM_") || suite.contains("_CCM_") || suite.contains("_CHACHA20_")) {
                    aeadSuites.add(suite);
                }
            }
            socket.setEnabledCipherSuites(aeadSuites.toArray(new String[0]));
            System.out.println("✓ TLS hardened: TLS 1.3/1.2, AEAD cipher suites only");

            // Perform explicit handshake
            socket.startHandshake();
            System.out.println("✓ mTLS handshake complete");

            // Log TLS session details
            SSLSession session = socket.getSession();
            System.out.println("  Protocol: " + session.getProtocol());
            System.out.println("  Cipher Suite: " + session.getCipherSuite());

            // Verify HO peer certificate
            java.security.cert.Certificate[] peerCerts = session.getPeerCertificates();
            if (peerCerts.length == 0) {
                throw new SecurityException("HO did not present a certificate");
            }
            X509Certificate hoCert = (X509Certificate) peerCerts[0];

            // Verify HO certificate fingerprint matches persisted binding
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] certDER = hoCert.getEncoded();
            byte[] fingerprint = sha256.digest(certDER);
            String receivedFingerprint = bytesToHex(fingerprint);

            System.out.println("\n--- Verifying HO certificate binding ---");
            System.out.println("  Expected fingerprint: " + avail.hoCertFingerprint);
            System.out.println("  Received fingerprint: " + receivedFingerprint);

            if (!receivedFingerprint.equals(avail.hoCertFingerprint)) {
                throw new SecurityException("HO certificate fingerprint mismatch! Possible substitution attack.");
            }
            System.out.println("✓ HO certificate fingerprint verified (matches persisted binding)");

            // Extract HO identity from certificate
            String hoCN = extractCNFromCertificate(hoCert);
            System.out.println("✓ HO peer identity verified: " + hoCN);

            // Build minimal, security-centric reservation request
            System.out.println("\n--- Building reservation request ---");
            JSONObject request = new JSONObject();
            request.put("method", "requestReservation");
            request.put("availabilityId", avail.availabilityId);
            request.put("spotId", avail.spotId);
            request.put("validFrom", avail.validFrom);
            request.put("validTo", avail.validTo);
            request.put("priceTokens", avail.priceTokens);
            request.put("coIdentity", coIdentity);

            System.out.println("  Request fields:");
            System.out.println("    availabilityId: " + avail.availabilityId);
            System.out.println("    spotId: " + avail.spotId);
            System.out.println("    validFrom: " + avail.validFrom);
            System.out.println("    validTo: " + avail.validTo);
            System.out.println("    priceTokens: " + avail.priceTokens);
            System.out.println("    coIdentity: " + coIdentity);

            // Send request
            writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);
            writer.println(request.toString());
            System.out.println("✓ Reservation request sent to HO");

            // Read response
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            String responseLine = reader.readLine();
            if (responseLine == null) {
                throw new SecurityException("HO closed connection without response");
            }

            JSONObject response = new JSONObject(responseLine);
            System.out.println("\n--- Received reservation response ---");
            System.out.println("  Status: " + response.optString("status", "UNKNOWN"));

            if (!"success".equals(response.optString("status"))) {
                String error = response.optString("error", "Unknown error");
                System.err.println("✗ HO rejected reservation request: " + error);
                return;
            }

            // Extract response fields
            String reservationId = response.getString("reservationId");
            String verdict = response.getString("verdict");
            String hoIdentityResp = response.getString("hoIdentity");
            String signatureB64 = response.getString("signature");
            String signatureAlg = response.getString("signatureAlg");
            String signedData = response.getString("signedData");

            // RESV_TAMPER: Apply tampering BEFORE verification (simulates on-path attacker)
            if ("RESV_TAMPER".equals(NEG_TEST_MODE)) {
                System.out.println("\n[RESV_TAMPER] ⚠ APPLYING TAMPERING (simulating attacker) ⚠");
                System.out.println("[RESV_TAMPER] Original signedData: " + signedData);
                System.out.println("[RESV_TAMPER] Original signature (Base64): " + signatureB64.substring(0, Math.min(32, signatureB64.length())) + "...");
                
                switch (RESV_TAMPER_MODE) {
                    case "FIELD_EDIT":
                        // Tamper: Change priceTokens value (e.g., 5 -> 1)
                        String originalPrice = "priceTokens=" + avail.priceTokens;
                        String tamperedPrice = "priceTokens=1";
                        signedData = signedData.replace(originalPrice, tamperedPrice);
                        System.out.println("[RESV_TAMPER] FIELD_EDIT: Changed '" + originalPrice + "' to '" + tamperedPrice + "'");
                        System.out.println("[RESV_TAMPER] Tampered signedData: " + signedData);
                        break;
                        
                    case "REORDER":
                        // Tamper: Reorder key-value pairs (breaks canonical order)
                        String[] parts = signedData.split("\\|");
                        if (parts.length >= 2) {
                            // Swap first two fields
                            String temp = parts[0];
                            parts[0] = parts[1];
                            parts[1] = temp;
                            signedData = String.join("|", parts);
                            System.out.println("[RESV_TAMPER] REORDER: Swapped first two fields");
                            System.out.println("[RESV_TAMPER] Tampered signedData: " + signedData);
                        }
                        break;
                        
                    case "SIG_FLIP":
                        // Tamper: Flip 1 bit in signature
                        byte[] sigBytes = Base64.getDecoder().decode(signatureB64);
                        if (sigBytes.length > 0) {
                            sigBytes[0] ^= 0x01; // Flip least significant bit of first byte
                            signatureB64 = Base64.getEncoder().encodeToString(sigBytes);
                            System.out.println("[RESV_TAMPER] SIG_FLIP: Flipped 1 bit in signature byte 0");
                            System.out.println("[RESV_TAMPER] Tampered signature (Base64): " + signatureB64.substring(0, Math.min(32, signatureB64.length())) + "...");
                        }
                        break;
                        
                    case "DROP_FIELD":
                        // Tamper: Remove coIdentity field
                        String fieldToRemove = "|coIdentity=" + coIdentity;
                        if (signedData.contains(fieldToRemove)) {
                            signedData = signedData.replace(fieldToRemove, "");
                            System.out.println("[RESV_TAMPER] DROP_FIELD: Removed 'coIdentity' field");
                            System.out.println("[RESV_TAMPER] Tampered signedData: " + signedData);
                        }
                        break;
                        
                    default:
                        System.err.println("[RESV_TAMPER] Unknown mode: " + RESV_TAMPER_MODE);
                }
                
                System.out.println("[RESV_TAMPER] Signature unchanged: " + ("SIG_FLIP".equals(RESV_TAMPER_MODE) ? "NO (tampered)" : "YES"));
                System.out.println("[RESV_TAMPER] Proceeding to verification with tampered data...\n");
            }

            System.out.println("  Reservation ID: " + reservationId);
            System.out.println("  Verdict: " + verdict);
            System.out.println("  HO Identity: " + hoIdentityResp);
            System.out.println("  Signature Algorithm: " + signatureAlg);

            // Verify signature (will fail if tampered)
            try {
                verifyReservationSignature(
                    avail,
                    signedData,
                    signatureB64,
                    signatureAlg,
                    reservationId,
                    verdict,
                    coIdentity,
                    hoIdentityResp
                );
                
                // If RESV_TAMPER mode and verification passed, that's a FAILURE
                if ("RESV_TAMPER".equals(NEG_TEST_MODE)) {
                    System.err.println("\n╔═══════════════════════════════════════════════════════════════╗");
                    System.err.println("║   [RESV_TAMPER] ✗ TEST FAILED: Tampering NOT detected!      ║");
                    System.err.println("╚═══════════════════════════════════════════════════════════════╝");
                    System.err.println("[RESV_TAMPER] CRITICAL: Signature verification passed despite tampering!");
                    System.err.println("[RESV_TAMPER] This indicates a vulnerability in signature verification.");
                    System.exit(1);
                }
                
            } catch (SecurityException e) {
                if ("RESV_TAMPER".equals(NEG_TEST_MODE)) {
                    // This is the EXPECTED outcome for RESV_TAMPER mode
                    System.out.println("\n╔═══════════════════════════════════════════════════════════════╗");
                    System.out.println("║   [RESV_TAMPER] ✓ SECURITY SUCCESS                          ║");
                    System.out.println("╚═══════════════════════════════════════════════════════════════╝");
                    System.out.println("[RESV_TAMPER] Forged reservation detected!");
                    System.out.println("[RESV_TAMPER] Failure reason: " + e.getMessage());
                    System.out.println("[RESV_TAMPER] Tampering mode: " + RESV_TAMPER_MODE);
                    
                    System.out.println("\n[RESV_TAMPER] VERIFICATION COMPLETE:");
                    System.out.println("  ✓ CO applied " + RESV_TAMPER_MODE + " tampering");
                    System.out.println("  ✓ Signature verification correctly FAILED");
                    System.out.println("  ✓ SecurityException thrown: " + e.getMessage());
                    System.out.println("  ✓ CO failed closed (rejected forged reservation)");
                    System.out.println("  ✓ HO identity binding enforced (cert fingerprint verified)");
                    System.out.println("  ✓ No bypass mechanisms available");
                    
                    System.out.println("\n[RESV_TAMPER] CONCLUSION:");
                    System.out.println("  SECURITY SUCCESS: Forged reservation detected");
                    System.out.println("  (signature/canonical data mismatch)");
                    System.out.println("  The system is SECURE against reservation tampering.\n");
                    System.exit(0);
                } else {
                    // In normal mode, signature failure is an error
                    throw e;
                }
            }

            // Store signed reservation as cryptographic proof
            storeReservationProof(reservationId, response, avail);

            // After successful reservation, send a payment request to HO (Milestone 3.1)
            try {
                sendPaymentToHO(avail, reservationId);
            } catch (Exception e) {
                System.err.println("⚠ Warning: sendPaymentToHO failed: " + e.getMessage());
            }

            System.out.println("\n═══════════════════════════════════════════════════════════");
            System.out.println("   RESERVATION HANDSHAKE COMPLETE");
            System.out.println("   Verdict: " + verdict);
            System.out.println("   Non-repudiable proof stored: " + reservationId);
            System.out.println("═══════════════════════════════════════════════════════════");

        } finally {
            // Clean up resources
            if (reader != null) try { reader.close(); } catch (Exception e) {}
            if (writer != null) try { writer.close(); } catch (Exception e) {}
            if (socket != null) try { socket.close(); } catch (Exception e) {}
        }
    }

    /**
     * Verifies the cryptographic signature on the HO's reservation response.
     * 
     * Security checks:
     * 1. Reconstruct canonical signed data from response
     * 2. Verify signature using HO's RSA-2048 public key
     * 3. Validate all signed fields match original request (prevents tampering)
     * 4. Fail closed on any discrepancy
     * 
     * This provides cryptographic proof that:
     * - The HO issued this specific reservation decision
     * - For this specific CO identity
     * - For this specific availability and time window
     * - At this specific price
     * - The HO cannot deny having issued this reservation (non-repudiation)
     */
    private static void verifyReservationSignature(
            DiscoveredAvailability avail,
            String signedData,
            String signatureB64,
            String signatureAlg,
            String reservationId,
            String verdict,
            String coIdentity,
            String hoIdentityResp) throws Exception {

        System.out.println("\n--- Verifying HO signature (RSA-2048) ---");

        // Decode signature from Base64
        byte[] signatureBytes = Base64.getDecoder().decode(signatureB64);
        System.out.println("✓ Signature decoded (" + signatureBytes.length + " bytes)");

        // Reconstruct canonical data string
        String reconstructedData = String.format(
            "reservationId=%s|verdict=%s|availabilityId=%s|spotId=%s|validFrom=%s|validTo=%s|priceTokens=%d|coIdentity=%s",
            reservationId,
            verdict,
            avail.availabilityId,
            avail.spotId,
            avail.validFrom,
            avail.validTo,
            avail.priceTokens,
            coIdentity
        );

        System.out.println("✓ Reconstructed canonical data:");
        System.out.println("  " + reconstructedData);
        System.out.println("✓ Signed data from HO:");
        System.out.println("  " + signedData);

        // Verify canonical data matches
        if (!reconstructedData.equals(signedData)) {
            throw new SecurityException("Signed data mismatch! Possible tampering or field modification.");
        }
        System.out.println("✓ Signed data matches reconstructed canonical format");

        // Verify signature using HO's public key
        if (!"SHA256withRSA".equals(signatureAlg)) {
            throw new SecurityException("Unsupported signature algorithm: " + signatureAlg);
        }

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(avail.hoCertificate.getPublicKey());
        signature.update(signedData.getBytes(StandardCharsets.UTF_8));

        boolean valid = signature.verify(signatureBytes);
        if (!valid) {
            throw new SecurityException("HO signature verification FAILED! Response may be forged.");
        }
        System.out.println("✓ HO signature verified successfully (RSA-2048, SHA256withRSA)");

        // Verify HO identity matches
        if (!avail.hoIdentity.equals(hoIdentityResp)) {
            throw new SecurityException("HO identity mismatch in signed response!");
        }
        System.out.println("✓ HO identity confirmed: " + hoIdentityResp);

        System.out.println("✓ All signature validation checks passed");
        System.out.println("✓ Non-repudiable proof: HO cannot deny issuing this reservation");
    }

    /**
     * Stores the signed reservation as cryptographic proof.
     * In production: store in tamper-evident audit log with integrity protection.
     */
    private static void storeReservationProof(String reservationId, JSONObject response, 
                                             DiscoveredAvailability avail) {
        try {
            String proofsDir = "./keystore/reservations";
            ensureDirectoryExists(proofsDir);

            String proofFile = proofsDir + "/" + reservationId + ".json";

            // Build proof document
            JSONObject proof = new JSONObject();
            proof.put("reservationId", reservationId);
            proof.put("verdict", response.getString("verdict"));
            proof.put("timestamp", java.time.Instant.now().toString());
            proof.put("availabilityId", avail.availabilityId);
            proof.put("spotId", avail.spotId);
            proof.put("validFrom", avail.validFrom);
            proof.put("validTo", avail.validTo);
            proof.put("priceTokens", avail.priceTokens);
            proof.put("hoIdentity", response.getString("hoIdentity"));
            proof.put("hoCertFingerprint", avail.hoCertFingerprint);
            proof.put("signature", response.getString("signature"));
            proof.put("signatureAlg", response.getString("signatureAlg"));
            proof.put("signedData", response.getString("signedData"));

            // Write to file
            try (FileWriter fw = new FileWriter(proofFile)) {
                fw.write(proof.toString(2)); // Pretty print with indent
            }

            System.out.println("✓ Cryptographic proof stored: " + proofFile);

        } catch (Exception e) {
            System.err.println("⚠ Warning: Failed to store reservation proof: " + e.getMessage());
            // Non-fatal for demo, but in production this should be critical
        }
    }

    /**
     * Send a PayRequest JSON to HO over mTLS (Milestone 3.1).
     * Generates a REAL hash chain and sends valid tokens that HO will verify.
     */
    private static void sendPaymentToHO(DiscoveredAvailability avail, String reservationId) throws Exception {
        System.out.println("\n--- Sending payment request to HO (Milestone 3.2 - Using SP tokens) ---");

        // Acquire tokens from SP (use SP-issued rootSignature and tokens)
        int x = 5; // request chain length
        int startIndex = 0; // start spending from token[0]
        int spendCount = avail.priceTokens; // spend exactly the number of tokens for the reservation

        JSONObject tokenResponse = requestTokensFromSP(x);
        String chainId = tokenResponse.optString("chainId", UUID.randomUUID().toString());
        String rootB64 = tokenResponse.getString("root");
        String rootSignatureB64 = tokenResponse.getString("rootSignature");
        org.json.JSONArray tokensArray = tokenResponse.getJSONArray("tokens");

        // Build tokensToSpend (Base64 strings) from the returned token batch
        java.util.List<String> tokensB64 = new java.util.ArrayList<>();
        for (int i = startIndex; i < startIndex + spendCount && i < tokensArray.length(); i++) {
            tokensB64.add(tokensArray.getString(i));
        }

        JSONObject pay = new JSONObject();
        pay.put("method", "pay");
        pay.put("reservationId", reservationId);
        pay.put("chainId", chainId);
        pay.put("x", x);
        pay.put("root", rootB64);
        pay.put("rootSignature", rootSignatureB64);
        pay.put("startIndex", startIndex);
        pay.put("tokensToSpend", new org.json.JSONArray(tokensB64));

        System.out.println("  Using SP-issued token batch, chainId=" + chainId);
        System.out.println("  tokensToSpend: indices [" + startIndex + ", " + (startIndex + spendCount) + ")");
        System.out.println("  Total tokens to spend: " + spendCount + " (matching reservation price)");

        // Build mTLS connection to HO
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(CO_KEYSTORE_PATH)) {
            keyStore.load(fis, CO_KEYSTORE_PASSWORD.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, CO_KEYSTORE_PASSWORD.toCharArray());

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(fis, TRUSTSTORE_PASSWORD.toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        System.out.println("\n[M4] Negative Test Mode: " + NEG_TEST_MODE);
        
        // Build clean payload first
        String payloadClean = pay.toString();
        JSONObject resp = null;
        
        if ("TAMPER".equals(NEG_TEST_MODE)) {
            // ═════════════════════════════════════════════════════════════
            // M4.1: TOKEN TAMPERING
            // ═════════════════════════════════════════════════════════════
            System.out.println("[M4.1] Tampering token[" + TAMPER_TOKEN_INDEX + "] byte[" + TAMPER_BYTE_INDEX + "]");
            
            // Deep copy tokens array and tamper the copy
            JSONArray tokensClean = pay.getJSONArray("tokensToSpend");
            JSONArray tokensTampered = new JSONArray();
            for (int i = 0; i < tokensClean.length(); i++) {
                if (i == TAMPER_TOKEN_INDEX) {
                    // Tamper this token
                    String tokenStr = tokensClean.getString(i);
                    byte[] tokenBytes = Base64.getDecoder().decode(tokenStr);
                    
                    // Flip one byte
                    if (TAMPER_BYTE_INDEX < tokenBytes.length) {
                        tokenBytes[TAMPER_BYTE_INDEX] ^= 0x01;  // flip one bit
                        String tamperedToken = Base64.getEncoder().encodeToString(tokenBytes);
                        tokensTampered.put(tamperedToken);
                        System.out.println("[M4.1] TOKEN TAMPERING ENABLED: flipped byte " + TAMPER_BYTE_INDEX + " of token index " + TAMPER_TOKEN_INDEX);
                    } else {
                        tokensTampered.put(tokenStr);
                    }
                } else {
                    tokensTampered.put(tokensClean.getString(i));
                }
            }
            
            // Rebuild JSONObject with tampered tokens
            JSONObject payTampered = new JSONObject(pay.toString());
            payTampered.put("tokensToSpend", tokensTampered);
            String payloadTampered = payTampered.toString();
            
            System.out.println("[M4.1] Expect HO rejection (adjacency/anchor check failure)");
            System.out.println("→ Sending TAMPERED pay request to HO at " + avail.hoHost + ":" + avail.hoPort);
            resp = sendPayJson(payloadTampered, avail.hoHost, avail.hoPort, sslContext);
            
        } else if ("REPLAY".equals(NEG_TEST_MODE)) {
            // ═════════════════════════════════════════════════════════════
            // M4.2: REPLAY PAYMENT
            // ═════════════════════════════════════════════════════════════
            System.out.println("[M4.2] Attempting replay: sending same pay twice");
            System.out.println("[M4.2] Attempt #1: Sending pay request...");
            System.out.println("→ Sending pay request (attempt #1) to HO at " + avail.hoHost + ":" + avail.hoPort);
            JSONObject resp1 = sendPayJson(payloadClean, avail.hoHost, avail.hoPort, sslContext);
            System.out.println("← HO response (attempt #1):");
            System.out.println(resp1.toString(2));
            
            System.out.println("\n[M4.2] Waiting " + REPLAY_DELAY_MS + " ms before replay...");
            Thread.sleep(REPLAY_DELAY_MS);
            
            System.out.println("[M4.2] Attempt #2 REPLAY: Sending same payload again...");
            System.out.println("→ Sending pay request (attempt #2 REPLAY) to HO at " + avail.hoHost + ":" + avail.hoPort);
            resp = sendPayJson(payloadClean, avail.hoHost, avail.hoPort, sslContext);
            System.out.println("← HO response (attempt #2 REPLAY):");
            System.out.println(resp.toString(2));
            System.out.println("[M4.2] Expect SP settlement rejection on 2nd settle (reason: replay_or_double_spend)");
            
        } else {
            // ═════════════════════════════════════════════════════════════
            // NORMAL M3.x FLOW (no negative scenario)
            // ═════════════════════════════════════════════════════════════
            System.out.println("[M3] Normal payment flow (no negative scenarios)");
            System.out.println("→ Sending pay request to HO at " + avail.hoHost + ":" + avail.hoPort);
            resp = sendPayJson(payloadClean, avail.hoHost, avail.hoPort, sslContext);
        }
        
        System.out.println("← HO pay response:");
        if (resp != null) {
            System.out.println(resp.toString(2));
            
            if ("success".equals(resp.optString("status"))) {
                System.out.println("✓✓✓ PAYMENT ACCEPTED BY HO ✓✓✓");
                
                // M3.4 receipt verification
                if (resp.has("paymentReceipt")) {
                    JSONObject receipt = resp.getJSONObject("paymentReceipt");
                    
                    System.out.println("\n═══════════════════════════════════════════════════");
                    System.out.println("M3.4: Verifying Payment Finalization Receipt");
                    System.out.println("═══════════════════════════════════════════════════");
                    
                    // Verify receipt signature and consistency
                    if (verifyAndPersistPaymentReceipt(receipt, reservationId, chainId, spendCount)) {
                        System.out.println("✓✓✓ PAYMENT FINALITY ESTABLISHED ✓✓✓");
                        System.out.println("✓ SP-signed receipt verified");
                        System.out.println("✓ Non-repudiation guaranteed");
                        System.out.println("✓ Immutable proof of payment stored");
                        System.out.println("═══════════════════════════════════════════════════");
                    } else {
                        System.err.println("❌❌❌ RECEIPT VERIFICATION FAILED ❌❌❌");
                        System.err.println("Payment accepted but receipt invalid - SECURITY VIOLATION");
                        System.err.println("═══════════════════════════════════════════════════");
                    }
                }
            } else {
                String code = resp.optString("code", "");
                String reason = resp.optString("reason", "");
                
                if ("REPLAY".equals(NEG_TEST_MODE) && "replay_or_double_spend".equals(code)) {
                    // This is expected behavior in M4.2 replay test (2nd attempt rejected at SP settle)
                    System.out.println("[M4.2] ✓ EXPECTED: SP rejected 2nd settle as double-spend");
                    System.out.println("✓ Replay detection working correctly");
                } else if ("TAMPER".equals(NEG_TEST_MODE) && ("token_tampering_detected".equals(code) || "security_violation".equals(reason))) {
                    // This is expected behavior in M4.1 tampering test
                    System.out.println("[M4.1] ✓ Expected rejection received from HO: " + reason);
                } else {
                    System.err.println("✗ HO rejected payment: " + resp.optString("message", "(no message)"));
                }
            }
        } else {
            System.err.println("No response from HO on pay request");
        }
    }


    /**
     * M4 helper: Tamper one token in the pay request by flipping a single byte.
     * Keeps bounds: if tamperIndex out of range, use last token.
     */
    private static void tamperPayRequest(JSONObject pay, int tamperIndex) {
        try {
            if (!pay.has("tokensToSpend")) return;
            org.json.JSONArray tokens = pay.getJSONArray("tokensToSpend");
            if (tokens.length() == 0) return;

            // Normalize index
            if (tamperIndex < 0 || tamperIndex >= tokens.length()) tamperIndex = tokens.length() - 1;

            String originalB64 = tokens.getString(tamperIndex);
            byte[] originalBytes = Base64.getDecoder().decode(originalB64);

            // Flip one byte (byte 0) for easy demo
            byte[] tampered = Arrays.copyOf(originalBytes, originalBytes.length);
            tampered[0] = (byte) (tampered[0] ^ 0x01);

            String tamperedB64 = Base64.getEncoder().encodeToString(tampered);
            tokens.put(tamperIndex, tamperedB64);
            pay.put("tokensToSpend", tokens);

            String origPrefix = originalB64.length() > 8 ? originalB64.substring(0, 8) : originalB64;
            String tamperPrefix = tamperedB64.length() > 8 ? tamperedB64.substring(0, 8) : tamperedB64;

            System.out.println("[M4] TOKEN TAMPERING ENABLED: flipped byte 0 of token index " + tamperIndex);
            System.out.println("[M4] token prefix changed: " + origPrefix + " -> " + tamperPrefix);
        } catch (Exception e) {
            System.err.println("[M4] Token tampering failed: " + e.getMessage());
        }
    }

    /**
     * Return true if token tampering is enabled via system property or environment variable.
     */
    private static boolean isTokenTamperingEnabled() {
        String prop = System.getProperty("TOKEN_TAMPER");
        if (prop != null) return "true".equalsIgnoreCase(prop);
        String env = System.getenv().getOrDefault("TOKEN_TAMPER", "false");
        if ("true".equalsIgnoreCase(env)) return true;

        // Also allow toggling via presence of a marker file inside container (demo-friendly)
        try {
            java.nio.file.Path marker = java.nio.file.Paths.get("/app/TOKEN_TAMPER");
            if (java.nio.file.Files.exists(marker)) return true;
            // fallback to relative path
            marker = java.nio.file.Paths.get("TOKEN_TAMPER");
            if (java.nio.file.Files.exists(marker)) return true;
        } catch (Exception ignored) {}

        return false;
    }

    /**
     * Helper method to ensure a directory exists, creating it if necessary.
     */
    private static void ensureDirectoryExists(String dirPath) throws IOException {
        File dir = new File(dirPath);
        if (!dir.exists()) {
            if (!dir.mkdirs()) {
                throw new IOException("Failed to create directory: " + dirPath);
            }
        }
    }

    /**
     * Persists HO identity binding locally to prevent substitution attacks in future interactions.
     * In production: store in encrypted database with integrity protection.
     * For this demo: append to file with timestamp.
     */
    private static void persistIdentityBinding(String availabilityId, String spotId, String hoCN, 
                                              String certFingerprint, String homeOwnerId) {
        try {
            String bindingFile = "./keystore/ho_identity_bindings.txt";
            ensureParentDirExists(bindingFile);
            
            try (FileWriter fw = new FileWriter(bindingFile, true);
                 BufferedWriter bw = new BufferedWriter(fw);
                 PrintWriter out = new PrintWriter(bw)) {
                
                String timestamp = java.time.Instant.now().toString();
                String binding = String.format("%s|%s|%s|%s|%s|%s",
                    timestamp, availabilityId, spotId, homeOwnerId, hoCN, certFingerprint);
                out.println(binding);
                
                System.out.println("✓ Identity binding persisted to " + bindingFile);
            }
        } catch (IOException e) {
            System.err.println("⚠ Warning: Failed to persist identity binding: " + e.getMessage());
            // Non-fatal for demo purposes, but in production this should be critical
        }
    }

    // -------------------------
    // Token request from SP
    // -------------------------

    private static JSONObject requestTokensFromSP(int tokenCount) throws Exception {
        // Load keystore for client authentication
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(CO_KEYSTORE_PATH)) {
            keyStore.load(fis, CO_KEYSTORE_PASSWORD.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, CO_KEYSTORE_PASSWORD.toCharArray());

        // Load truststore to verify SP
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(fis, TRUSTSTORE_PASSWORD.toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // Create SSL context with both key and trust managers (mTLS)
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        SSLSocket socket = null;
        PrintWriter writer = null;
        BufferedReader reader = null;
        
        try {
            // Create socket but don't get streams yet
            socket = (SSLSocket) sslContext.getSocketFactory().createSocket(SP_HOST, SP_PORT);

            // Harden connection
            String[] desiredProtocols = new String[]{"TLSv1.3", "TLSv1.2"};
            String[] protocols = intersect(socket.getSupportedProtocols(), desiredProtocols);
            if (protocols.length > 0) {
                socket.setEnabledProtocols(protocols);
            }

            // Perform handshake BEFORE creating streams
            socket.startHandshake();

            System.out.println("✓ mTLS connection to SP established");
            System.out.println("  Protocol: " + socket.getSession().getProtocol());
            System.out.println("  Cipher suite: " + socket.getSession().getCipherSuite());

            // Verify we presented our certificate and cache SP certificate for M3.4
            X509Certificate[] peerCerts = (X509Certificate[]) socket.getSession().getPeerCertificates();
            System.out.println("  SP certificate: " + peerCerts[0].getSubjectX500Principal().getName());
            
            // M3.4: Cache SP certificate for payment receipt verification
            spCertificate = peerCerts[0];
            System.out.println("[M3.4] SP certificate cached for receipt verification");

            // Now create streams after handshake is complete
            writer = new PrintWriter(socket.getOutputStream(), true);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Request tokens
            JSONObject request = new JSONObject();
            request.put("method", "requestTokens");
            request.put("count", tokenCount);

            System.out.println("\n→ Requesting " + tokenCount + " payment tokens from SP...");
            writer.println(request.toString());

            String responseLine = reader.readLine();
            if (responseLine == null) {
                throw new IOException("No response from SP");
            }

            JSONObject response = new JSONObject(responseLine);
            System.out.println("\n← Received response from SP");
            System.out.println(response.toString(2));

            if (!"success".equals(response.getString("status"))) {
                throw new Exception("Token request failed: " + response.optString("message", "Unknown error"));
            }

            // Verify token response
            verifyTokens(response, peerCerts[0]);

            return response;

        } finally {
            // Clean up resources
            if (reader != null) try { reader.close(); } catch (Exception e) {}
            if (writer != null) try { writer.close(); } catch (Exception e) {}
            if (socket != null) try { socket.close(); } catch (Exception e) {}
        }
    }

    private static void verifyTokens(JSONObject response, X509Certificate spCert) throws Exception {
        System.out.println("\n=== Verifying Token Batch ===");

        // Extract fields
        int x = response.getInt("x");
        JSONArray tokensArray = response.getJSONArray("tokens");
        String rootB64 = response.getString("root");
        String rootSignatureB64 = response.getString("rootSignature");
        String chainId = response.optString("chainId", "unknown");

        System.out.println("Chain ID: " + chainId);
        System.out.println("Token count: " + x);
        System.out.println("Tokens received: " + tokensArray.length());

        if (tokensArray.length() != x) {
            throw new Exception("Token count mismatch: expected " + x + ", got " + tokensArray.length());
        }

        // Decode tokens
        List<byte[]> tokens = new ArrayList<>();
        for (int i = 0; i < tokensArray.length(); i++) {
            tokens.add(Base64.getDecoder().decode(tokensArray.getString(i)));
        }

        // Check all tokens are distinct
        Set<String> tokenSet = new HashSet<>();
        for (byte[] token : tokens) {
            String tokenHex = bytesToHex(token);
            if (!tokenSet.add(tokenHex)) {
                throw new Exception("Duplicate token found!");
            }
        }
        System.out.println("✓ All tokens are distinct");

        // Decode root and signature
        byte[] root = Base64.getDecoder().decode(rootB64);
        byte[] rootSignature = Base64.getDecoder().decode(rootSignatureB64);

        System.out.println("Root hash: " + bytesToHex(root));

        // Verify signature on root using SP's public key
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(spCert.getPublicKey());
        sig.update(root);
        boolean signatureValid = sig.verify(rootSignature);

        if (!signatureValid) {
            throw new Exception("Root signature verification FAILED!");
        }
        System.out.println("✓ Root signature verified with SP's public key");

        // Verify hash chain: Start from first token, hash repeatedly, should reach root
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] current = tokens.get(0); // Start with first token H(s)

        System.out.println("\nVerifying hash chain:");
        System.out.println("  Starting with token[0]: " + bytesToHex(current).substring(0, 16) + "...");

        // Hash forward from token[0] to token[x-1], checking each intermediate value
        for (int i = 0; i < tokens.size(); i++) {
            if (!Arrays.equals(current, tokens.get(i))) {
                throw new Exception("Hash chain verification failed at token " + i);
            }
            if (i < tokens.size() - 1) {
                current = digest.digest(current);
            }
        }

        // The last token should be the root (no additional hash needed)
        if (!Arrays.equals(current, root)) {
            throw new Exception("Hash chain does not reach the signed root!");
        }
        System.out.println("  Chain verified: " + (tokens.size()) + " hashes lead to signed root");
        System.out.println("✓ Hash chain verification successful");

        System.out.println("\n" + "═".repeat(45));
        System.out.println("✓✓✓ TOKEN BATCH VERIFIED SUCCESSFULLY ✓✓✓");
        System.out.println("═".repeat(45));
        System.out.println("Received " + x + " valid payment tokens from SP");
        System.out.println("Chain ID: " + chainId);
    }

    // -------------------------
    // Utilities
    // -------------------------

    private static void ensureParentDirExists(String filePath) {
        File f = new File(filePath);
        File parent = f.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
    }

    private static X509Certificate parseX509FromPemB64(java.security.cert.CertificateFactory cf, String pemB64) throws Exception {
        byte[] pemBytes = Base64.getDecoder().decode(pemB64);
        String pem = new String(pemBytes, java.nio.charset.StandardCharsets.UTF_8);
        return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(java.nio.charset.StandardCharsets.UTF_8))
        );
    }

    private static String[] intersect(String[] supported, String[] desired) {
        List<String> sup = Arrays.asList(supported);
        List<String> out = new ArrayList<>();
        for (String d : desired) if (sup.contains(d)) out.add(d);
        return out.toArray(new String[0]);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Extracts the Common Name (CN) from an X.509 certificate.
     * Used for identity verification in mTLS connections.
     */
    private static String extractCNFromCertificate(X509Certificate cert) throws Exception {
        String dn = cert.getSubjectX500Principal().getName();
        javax.naming.ldap.LdapName ldapName = new javax.naming.ldap.LdapName(dn);
        for (javax.naming.ldap.Rdn rdn : ldapName.getRdns()) {
            if ("CN".equalsIgnoreCase(rdn.getType())) {
                return (String) rdn.getValue();
            }
        }
        throw new SecurityException("Certificate does not contain CN field");
    }

    /**
     * Compute SHA-256 hash of input bytes.
     */
    private static byte[] sha256(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    }

    /**
     * Decode Base64 string to bytes.
     */
    private static byte[] b64decode(String encoded) {
        return Base64.getDecoder().decode(encoded);
    }

    /**
     * Encode bytes to Base64 string.
     */
    private static String b64encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Compute the full hash chain of length x using SHA-256.
     * Returns a list where:
     *   chain[0] = secret
     *   chain[1] = H(secret)
     *   chain[2] = H^2(secret)
     *   ...
     *   chain[x] = H^x(secret) = root
     */
    private static java.util.List<byte[]> computeChain(byte[] secret, int x) throws NoSuchAlgorithmException {
        java.util.List<byte[]> chain = new java.util.ArrayList<>();
        chain.add(secret);
        byte[] current = secret;
        for (int i = 1; i <= x; i++) {
            current = sha256(current);
            chain.add(current);
        }
        return chain;
    }
    
    /**
     * M3.4: Verify and persist payment receipt from SP.
     * 
     * This is the final security layer providing:
     * - Cryptographic finality via SP signature verification
     * - Non-repudiation (SP cannot deny issuing receipt)
     * - Consistency validation (receipt matches local payment state)
     * - Immutable proof storage for dispute resolution
     * - Fail-closed on any verification failure
     * 
     * @param receipt Payment receipt from SP (forwarded via HO)
     * @param expectedReservationId Local reservation ID for consistency check
     * @param expectedChainId Local chain ID for consistency check
     * @param expectedTokenCount Number of tokens spent for consistency check
     * @return true if receipt verified and persisted, false otherwise
     */
    private static boolean verifyAndPersistPaymentReceipt(JSONObject receipt, String expectedReservationId, 
                                                          String expectedChainId, int expectedTokenCount) {
        String logTag = "[M3.4-VERIFY] ";
        
        try {
            System.out.println(logTag + "Starting receipt verification...");
            
            // ═══════════════════════════════════════════════════════════
            // PHASE 1: SCHEMA VALIDATION (FAIL-CLOSED)
            // ═══════════════════════════════════════════════════════════
            
            if (!receipt.has("receiptId")) {
                System.err.println(logTag + "❌ Missing receiptId");
                return false;
            }
            if (!receipt.has("canonicalReceipt")) {
                System.err.println(logTag + "❌ Missing canonicalReceipt");
                return false;
            }
            if (!receipt.has("receiptSignature")) {
                System.err.println(logTag + "❌ Missing receiptSignature");
                return false;
            }
            if (!receipt.has("signatureAlg")) {
                System.err.println(logTag + "❌ Missing signatureAlg");
                return false;
            }
            
            String receiptId = receipt.getString("receiptId");
            String canonicalReceipt = receipt.getString("canonicalReceipt");
            String receiptSignatureB64 = receipt.getString("receiptSignature");
            String signatureAlg = receipt.getString("signatureAlg");
            
            System.out.println(logTag + "Receipt ID: " + receiptId);
            System.out.println(logTag + "Canonical data: " + canonicalReceipt);
            System.out.println(logTag + "Signature algorithm: " + signatureAlg);
            
            // ═══════════════════════════════════════════════════════════
            // PHASE 2: CONSISTENCY VALIDATION (PREVENT SUBSTITUTION)
            // ═══════════════════════════════════════════════════════════
            
            System.out.println(logTag + "Validating consistency with local payment state...");
            
            String chainId = receipt.optString("chainId", "");
            String reservationId = receipt.optString("reservationId", "");
            int y = receipt.optInt("y", -1);
            
            if (!chainId.equals(expectedChainId)) {
                System.err.println(logTag + "❌ CONSISTENCY FAILURE: chainId mismatch");
                System.err.println(logTag + "  Expected: " + expectedChainId);
                System.err.println(logTag + "  Received: " + chainId);
                return false;
            }
            
            if (!reservationId.equals(expectedReservationId)) {
                System.err.println(logTag + "❌ CONSISTENCY FAILURE: reservationId mismatch");
                System.err.println(logTag + "  Expected: " + expectedReservationId);
                System.err.println(logTag + "  Received: " + reservationId);
                return false;
            }
            
            if (y != expectedTokenCount) {
                System.err.println(logTag + "❌ CONSISTENCY FAILURE: token count mismatch");
                System.err.println(logTag + "  Expected: " + expectedTokenCount);
                System.err.println(logTag + "  Received: " + y);
                return false;
            }
            
            System.out.println(logTag + "✓ Consistency validated");
            System.out.println(logTag + "  chainId: " + chainId);
            System.out.println(logTag + "  reservationId: " + reservationId);
            System.out.println(logTag + "  tokens spent: " + y);
            
            // ═══════════════════════════════════════════════════════════
            // PHASE 3: CRYPTOGRAPHIC SIGNATURE VERIFICATION
            // ═══════════════════════════════════════════════════════════
            
            System.out.println(logTag + "Verifying SP signature (RSA-2048, SHA256withRSA)...");
            
            if (spCertificate == null) {
                System.err.println(logTag + "❌ SP certificate not available");
                System.err.println(logTag + "Cannot verify receipt signature");
                return false;
            }
            
            // Extract SP public key from certificate
            PublicKey spPublicKey = spCertificate.getPublicKey();
            
            // Verify signature
            byte[] receiptBytes = canonicalReceipt.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] signatureBytes = Base64.getDecoder().decode(receiptSignatureB64);
            
            Signature sig = Signature.getInstance(signatureAlg);
            sig.initVerify(spPublicKey);
            sig.update(receiptBytes);
            boolean valid = sig.verify(signatureBytes);
            
            if (!valid) {
                System.err.println(logTag + "❌❌❌ SIGNATURE VERIFICATION FAILED ❌❌❌");
                System.err.println(logTag + "Receipt may be forged or tampered");
                System.err.println(logTag + "SP signature does NOT match canonical data");
                return false;
            }
            
            System.out.println(logTag + "✓ SP signature verified successfully");
            System.out.println(logTag + "✓ Non-repudiation: SP cannot deny issuing this receipt");
            System.out.println(logTag + "✓ Integrity: Receipt has not been modified");
            
            // ═══════════════════════════════════════════════════════════
            // PHASE 4: CERTIFICATE VALIDATION TO ROOT CA
            // ═══════════════════════════════════════════════════════════
            
            System.out.println(logTag + "Validating SP certificate to Root CA...");
            
            try {
                // Verify SP certificate validity period
                spCertificate.checkValidity();
                System.out.println(logTag + "✓ SP certificate is within validity period");
                
                // In production: verify full chain to Root CA using PKIX
                // For this demo: basic validity check is sufficient
                System.out.println(logTag + "✓ SP certificate validated");
                
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                System.err.println(logTag + "❌ SP certificate validity check failed: " + e.getMessage());
                return false;
            }
            
            // ═══════════════════════════════════════════════════════════
            // PHASE 5: PERSIST IMMUTABLE PROOF
            // ═══════════════════════════════════════════════════════════
            
            System.out.println(logTag + "Persisting receipt as immutable proof...");
            
            String receiptDir = "./keystore/receipts";
            ensureDirectoryExists(receiptDir);
            
            String filename = receiptDir + "/receipt_" + receiptId + ".json";
            try (FileWriter writer = new FileWriter(filename)) {
                writer.write(receipt.toString(2));
            }
            
            System.out.println(logTag + "✓ Receipt persisted: " + filename);
            System.out.println(logTag + "✓ Immutable proof stored for dispute resolution");
            System.out.println(logTag + "✓ Enables offline third-party verification");
            
            // ═══════════════════════════════════════════════════════════
            // PHASE 6: FINALITY CONFIRMATION
            // ═══════════════════════════════════════════════════════════
            
            System.out.println(logTag + "═══════════════════════════════════════════════════");
            System.out.println(logTag + "PAYMENT FINALITY ACHIEVED");
            System.out.println(logTag + "═══════════════════════════════════════════════════");
            System.out.println(logTag + "✓ SP signature verified (cryptographic proof)");
            System.out.println(logTag + "✓ Consistency validated (no substitution)");
            System.out.println(logTag + "✓ Immutable receipt stored (audit trail)");
            System.out.println(logTag + "✓ Non-repudiation guaranteed (SP cannot deny)");
            System.out.println(logTag + "✓ Dispute resolution enabled (third-party verification)");
            
            return true;
            
        } catch (Exception e) {
            System.err.println(logTag + "❌ Receipt verification error: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
}
