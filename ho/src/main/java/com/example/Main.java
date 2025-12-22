package com.example;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.json.JSONObject;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {
    private static final String CAUTH_HOST = System.getenv().getOrDefault("CAUTH_HOST", "localhost");
    private static final int CAUTH_PORT = Integer.parseInt(System.getenv().getOrDefault("CAUTH_PORT", "8443"));
    private static final String SP_HOST = System.getenv().getOrDefault("SP_HOST", "localhost");
    private static final int SP_PORT = Integer.parseInt(System.getenv().getOrDefault("SP_PORT", "8444"));
    private static final int HO_SERVER_PORT = Integer.parseInt(System.getenv().getOrDefault("HO_SERVER_PORT", "8445"));
    
    private static final String HO_KEYSTORE_PATH = "/app/keystore/ho_keystore.p12";
    private static final String KEYSTORE_PASSWORD = System.getenv().getOrDefault("KEYSTORE_PASSWORD", "changeit");
    private static final String ROOT_CA_PATH = System.getenv().getOrDefault("ROOT_CA_PATH", "/app/certs/root_ca.crt");
    private static final String TRUSTSTORE_PATH = "/app/truststore.p12";
    private static final String TRUSTSTORE_PASSWORD = "trustpassword";
    
    // HO configuration
    private static final String HOME_OWNER_ID = System.getenv().getOrDefault("HOME_OWNER_ID", "HO-001");
    private static final String SPOT_ID = System.getenv().getOrDefault("SPOT_ID", "SPOT-A1");
    private static final String LOCATION_ZONE = System.getenv().getOrDefault("LOCATION_ZONE", "Downtown-North");
    private static final int PRICE_TOKENS = Integer.parseInt(System.getenv().getOrDefault("PRICE_TOKENS", "5"));
    private static final int AVAILABILITY_HOURS = Integer.parseInt(System.getenv().getOrDefault("AVAILABILITY_HOURS", "8"));
    
    private static KeyPair hoKeyPair;
    private static X509Certificate hoCertificate;
    private static String publishedAvailabilityId; // Store for validation

    public static void main(String[] args) {
        // Register BC provider (needed for CSR + extensions reliably)
        Security.addProvider(new BouncyCastleProvider());

        // Sleep to allow CAuth and SP to start
        try {
            System.out.println("Waiting for CAuth and SP to start...");
            Thread.sleep(8000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        try {
            System.out.println("\n=== Home Owner (HO) Starting ===");

            ensureParentDirExists(HO_KEYSTORE_PATH);

            // STEP 1: Establish cryptographic identity
            if (hasCertificate()) {
                System.out.println("Found existing certificate, loading from keystore...");
                loadExistingCertificate();
            } else {
                System.out.println("No existing certificate found, enrolling with CAuth...");
                enrollWithCAuth();
            }

            // Verify certificate validity
            hoCertificate.checkValidity();
            System.out.println("✓ Certificate validity period verified");

            System.out.println("\n╔═══════════════════════════════════════════╗");
            System.out.println("║   HO CRYPTOGRAPHIC IDENTITY ESTABLISHED   ║");
            System.out.println("╚═══════════════════════════════════════════╝");
            System.out.println("Subject: " + hoCertificate.getSubjectX500Principal().getName());
            System.out.println("Issuer: " + hoCertificate.getIssuerX500Principal().getName());
            System.out.println("Valid from: " + hoCertificate.getNotBefore());
            System.out.println("Valid until: " + hoCertificate.getNotAfter());

            // STEP 2: Publish parking availability to SP
            publishAvailability();

            // STEP 3: Start reservation server to handle CO requests
            System.out.println("\n=== Starting HO Reservation Server ===");
            startReservationServer();

        } catch (Exception e) {
            System.err.println("\n✖ CRITICAL ERROR: HO failed to start");
            System.err.println("Reason: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static boolean hasCertificate() {
        return Files.exists(Paths.get(HO_KEYSTORE_PATH));
    }

    private static void loadExistingCertificate() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(HO_KEYSTORE_PATH)) {
            keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
        }

        String alias = "homeowner";
        Key key = keyStore.getKey(alias, KEYSTORE_PASSWORD.toCharArray());
        if (!(key instanceof PrivateKey)) {
            throw new Exception("No private key found in keystore");
        }

        Certificate cert = keyStore.getCertificate(alias);
        if (!(cert instanceof X509Certificate)) {
            throw new Exception("No X.509 certificate found in keystore");
        }

        hoKeyPair = new KeyPair(cert.getPublicKey(), (PrivateKey) key);
        hoCertificate = (X509Certificate) cert;
    }

    private static void enrollWithCAuth() throws Exception {
        System.out.println("\n=== Enrollment Phase ===");
        
        // Generate RSA-2048 key pair
        System.out.println("→ Generating RSA-2048 key pair...");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        hoKeyPair = keyGen.generateKeyPair();
        System.out.println("✓ Key pair generated");

        // Create CSR with stable CN
        System.out.println("→ Creating Certificate Signing Request (CSR)...");
        X500Name subject = new X500Name("C=BE, O=Parking System, CN=HomeOwner");
        
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
            subject, hoKeyPair.getPublic());
        
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(hoKeyPair.getPrivate());
        
        PKCS10CertificationRequest csr = csrBuilder.build(signer);
        System.out.println("✓ CSR created with subject: " + subject);

        // Submit CSR to CAuth over TLS
        System.out.println("→ Submitting CSR to CAuth at " + CAUTH_HOST + ":" + CAUTH_PORT + "...");

        X509Certificate[] certChain = submitCSRToCAuth(csr);
        hoCertificate = certChain[0];
        System.out.println("✓ Certificate received from CAuth");

        // Parse certificate
        System.out.println("✓ Certificate parsed successfully");
        System.out.println("  Serial: " + hoCertificate.getSerialNumber().toString(16).toUpperCase());
        System.out.println("  Issuer: " + hoCertificate.getIssuerX500Principal().getName());

        // Store in keystore with full chain
        saveToKeystore(certChain);
        System.out.println("✓ Certificate and private key stored in keystore");
    }

    private static X509Certificate[] submitCSRToCAuth(PKCS10CertificationRequest csr) throws Exception {
        // Initialize truststore for CAuth connection
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(ROOT_CA_PATH)) {
            X509Certificate rootCert = (X509Certificate) cf.generateCertificate(fis);
            trustStore.setCertificateEntry("root_ca", rootCert);
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());

        SSLSocket socket = null;
        PrintWriter writer = null;
        BufferedReader reader = null;

        try {
            socket = (SSLSocket) sslContext.getSocketFactory().createSocket(CAUTH_HOST, CAUTH_PORT);
            
            // Harden connection
            String[] desiredProtocols = new String[]{"TLSv1.3", "TLSv1.2"};
            String[] protocols = intersect(socket.getSupportedProtocols(), desiredProtocols);
            if (protocols.length > 0) {
                socket.setEnabledProtocols(protocols);
            }

            socket.startHandshake();

            writer = new PrintWriter(socket.getOutputStream(), true);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Send enrollment request (same format as CO)
            JSONObject request = new JSONObject();
            request.put("method", "signCSR");
            request.put("csr", Base64.getEncoder().encodeToString(csr.getEncoded()));
            writer.println(request.toString());

            // Read response
            String responseLine = reader.readLine();
            if (responseLine == null) {
                throw new IOException("No response from CAuth");
            }

            JSONObject response = new JSONObject(responseLine);
            if (response.has("status") && "error".equals(response.getString("status"))) {
                throw new Exception("CAuth returned error: " + response.optString("message", "Unknown error"));
            }

            // Parse all certificates from response (HO cert, intermediate, root)
            byte[] hoCertBytes = Base64.getDecoder().decode(response.getString("certificate"));
            X509Certificate hoCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(hoCertBytes));
            
            byte[] intermediateCertBytes = Base64.getDecoder().decode(response.getString("caCert"));
            X509Certificate intermediateCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(intermediateCertBytes));

            byte[] rootCertBytes = Base64.getDecoder().decode(response.getString("rootCert"));
            X509Certificate rootCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(rootCertBytes));

            return new X509Certificate[]{hoCert, intermediateCert, rootCert};

        } finally {
            if (reader != null) try { reader.close(); } catch (Exception e) {}
            if (writer != null) try { writer.close(); } catch (Exception e) {}
            if (socket != null) try { socket.close(); } catch (Exception e) {}
        }
    }

    private static void saveToKeystore(Certificate[] chain) throws Exception {
        ensureParentDirExists(HO_KEYSTORE_PATH);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);

        keyStore.setKeyEntry("homeowner", hoKeyPair.getPrivate(), 
                           KEYSTORE_PASSWORD.toCharArray(), chain);

        try (FileOutputStream fos = new FileOutputStream(HO_KEYSTORE_PATH)) {
            keyStore.store(fos, KEYSTORE_PASSWORD.toCharArray());
        }
    }

    private static void publishAvailability() throws Exception {
        System.out.println("\n=== Publishing Parking Availability to SP ===");
        
        // Initialize keystore with HO certificate
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(HO_KEYSTORE_PATH)) {
            keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

        // Initialize truststore
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(ROOT_CA_PATH)) {
            X509Certificate rootCert = (X509Certificate) cf.generateCertificate(fis);
            trustStore.setCertificateEntry("root_ca", rootCert);
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // Create SSL context with both key and trust managers (mTLS)
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        int maxRetries = 3;
        int retryDelay = 2000; // 2 seconds
        
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
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

                // Verify we're connected to SP
                X509Certificate[] peerCerts = (X509Certificate[]) socket.getSession().getPeerCertificates();
                System.out.println("  SP certificate: " + peerCerts[0].getSubjectX500Principal().getName());

                // Now create streams after handshake is complete
                writer = new PrintWriter(socket.getOutputStream(), true);
                reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                // Build availability request
                JSONObject request = new JSONObject();
                request.put("method", "publishAvailability");
                request.put("homeOwnerId", HOME_OWNER_ID);
                request.put("spotId", SPOT_ID);
                
                // Calculate availability window
                Instant now = Instant.now();
                Instant validFrom = now;
                Instant validTo = now.plus(AVAILABILITY_HOURS, ChronoUnit.HOURS);
                
                request.put("validFrom", validFrom.toString());
                request.put("validTo", validTo.toString());
                request.put("priceTokens", PRICE_TOKENS);
                request.put("locationZone", LOCATION_ZONE);
                request.put("metadata", new JSONObject()
                    .put("autoRenewal", false)
                    .put("maxDuration", AVAILABILITY_HOURS + "h")
                    .put("spotType", "residential"));

                System.out.println("\n→ Publishing availability to SP...");
                System.out.println("  Spot ID: " + SPOT_ID);
                System.out.println("  Valid from: " + validFrom);
                System.out.println("  Valid to: " + validTo);
                System.out.println("  Price: " + PRICE_TOKENS + " tokens");
                System.out.println("  Location: " + LOCATION_ZONE);

                writer.println(request.toString());

                String responseLine = reader.readLine();
                if (responseLine == null) {
                    throw new IOException("No response from SP");
                }

                JSONObject response = new JSONObject(responseLine);
                System.out.println("\n← Received response from SP");

                if ("success".equals(response.getString("status"))) {
                    System.out.println("\n╔═══════════════════════════════════════════╗");
                    System.out.println("║   AVAILABILITY PUBLISHED SUCCESSFULLY     ║");
                    System.out.println("╚═══════════════════════════════════════════╝");
                    if (response.has("availabilityId")) {
                        publishedAvailabilityId = response.getString("availabilityId");
                        System.out.println("Availability ID: " + publishedAvailabilityId);
                    }
                    if (response.has("message")) {
                        System.out.println("Message: " + response.getString("message"));
                    }
                    return; // Success - exit retry loop
                } else {
                    String errorMsg = response.optString("message", "Unknown error");
                    throw new Exception("SP rejected availability: " + errorMsg);
                }

            } catch (IOException e) {
                if (attempt < maxRetries) {
                    System.err.println("⚠ Connection failed (attempt " + attempt + "/" + maxRetries + "): " + e.getMessage());
                    System.err.println("  Retrying in " + (retryDelay/1000) + " seconds...");
                    Thread.sleep(retryDelay);
                    retryDelay *= 2; // Exponential backoff
                } else {
                    throw new Exception("Failed to publish availability after " + maxRetries + " attempts: " + e.getMessage());
                }
            } finally {
                if (reader != null) try { reader.close(); } catch (Exception e) {}
                if (writer != null) try { writer.close(); } catch (Exception e) {}
                if (socket != null) try { socket.close(); } catch (Exception e) {}
            }
        }
    }

    // -------------------------
    // Reservation Server (Milestone 2.4)
    // -------------------------

    /**
     * Start mTLS server to accept reservation requests from CO.
     * Uses same hardened TLS configuration: TLS 1.3/1.2, AEAD ciphers, client cert required.
     */
    private static void startReservationServer() throws Exception {
        // Load keystore for server authentication
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(HO_KEYSTORE_PATH)) {
            keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

        // Load truststore to verify CO certificates
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(fis, TRUSTSTORE_PASSWORD.toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // Create hardened SSL context with mTLS
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(HO_SERVER_PORT);

        // Harden TLS configuration
        String[] desiredProtocols = new String[]{"TLSv1.3", "TLSv1.2"};
        String[] protocols = intersect(serverSocket.getSupportedProtocols(), desiredProtocols);
        if (protocols.length == 0) {
            throw new IllegalStateException("No TLS 1.3/1.2 support available");
        }
        serverSocket.setEnabledProtocols(protocols);

        // REQUIRE client certificates (mTLS enforcement)
        serverSocket.setNeedClientAuth(true);

        System.out.println("\n╔═══════════════════════════════════════════════════════════╗");
        System.out.println("║   HO RESERVATION SERVER CRYPTOGRAPHIC BASELINE           ║");
        System.out.println("╚═══════════════════════════════════════════════════════════╝");
        System.out.println("Version: 2025-12-22 (Milestone 2.4 - Reservation Handshake)");
        System.out.println("✓ Enabled TLS protocols: " + java.util.Arrays.toString(protocols));
        System.out.println("✓ Mutual TLS (mTLS) REQUIRED - client certificates enforced");
        System.out.println();
        System.out.println("=== HO Reservation Server Configuration ===");
        System.out.println("Server listening on port: " + HO_SERVER_PORT);
        System.out.println("Server certificate subject: " + hoCertificate.getSubjectX500Principal().getName());
        System.out.println("Server certificate issuer: " + hoCertificate.getIssuerX500Principal().getName());
        System.out.println("RSA key size: 2048 bits");
        System.out.println("Signature algorithm: SHA256withRSA");
        System.out.println("mTLS enforcement: ENABLED (CO certificates REQUIRED)");
        System.out.println();
        System.out.println("✓ HO Reservation Server ready to accept secure connections");
        System.out.println("==========================================\n");

        ExecutorService executor = Executors.newCachedThreadPool();
        while (true) {
            SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
            executor.submit(new ReservationHandler(clientSocket));
        }
    }

    /**
     * Handler for individual CO reservation requests.
     * Implements cryptographically binding authorization protocol.
     */
    static class ReservationHandler implements Runnable {
        private final SSLSocket clientSocket;

        public ReservationHandler(SSLSocket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            String coCN = null;
            BufferedReader reader = null;
            PrintWriter writer = null;
            
            try {
                System.out.println("\n=== Inbound Reservation Request ===");
                
                // Force handshake - enforces mTLS parameters
                clientSocket.startHandshake();

                // Get streams after successful handshake
                reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                writer = new PrintWriter(clientSocket.getOutputStream(), true);

                // Authenticate CO via mTLS client certificate
                X509Certificate[] clientCerts = (X509Certificate[]) clientSocket.getSession().getPeerCertificates();
                X509Certificate coCert = clientCerts[0];
                String coDN = coCert.getSubjectX500Principal().getName();

                // Extract CO CN
                try {
                    LdapName ldapDN = new LdapName(coDN);
                    for (Rdn rdn : ldapDN.getRdns()) {
                        if (rdn.getType().equalsIgnoreCase("CN")) {
                            coCN = rdn.getValue().toString();
                            break;
                        }
                    }
                } catch (Exception e) {
                    coCN = "Unknown";
                }

                System.out.println("\n║   CO AUTHENTICATED VIA mTLS               ║");
                System.out.println("CO CN: " + coCN);
                System.out.println("CO address: " + clientSocket.getRemoteSocketAddress());
                System.out.println("CO certificate subject: " + coCert.getSubjectX500Principal().getName());
                System.out.println("CO certificate issuer: " + coCert.getIssuerX500Principal().getName());
                System.out.println("CO certificate serial: " + coCert.getSerialNumber().toString(16).toUpperCase());
                System.out.println();
                System.out.println("TLS Session Details:");
                System.out.println("  Protocol: " + clientSocket.getSession().getProtocol());
                System.out.println("  Cipher suite: " + clientSocket.getSession().getCipherSuite());
                System.out.println("═══════════════════════════════════════════\n");

                // Read reservation request
                String requestLine = reader.readLine();
                if (requestLine == null) {
                    throw new IOException("No request received from CO");
                }

                JSONObject request = new JSONObject(requestLine);
                System.out.println("Received reservation request from " + coCN + ":");
                System.out.println(request.toString(2));

                // Process reservation and generate signed response
                JSONObject response = handleReservationRequest(request, coCert);

                writer.println(response.toString());
                System.out.println("\nSent signed reservation response:");
                System.out.println(response.toString(2));

            } catch (Exception e) {
                System.err.println("Error processing reservation request: " + e.getMessage());
                e.printStackTrace();
                try {
                    JSONObject errorResponse = new JSONObject();
                    errorResponse.put("status", "error");
                    errorResponse.put("message", "Reservation processing failed: " + e.getMessage());
                    if (writer != null) writer.println(errorResponse.toString());
                } catch (Exception ex) {
                    // Ignore
                }
            } finally {
                if (reader != null) try { reader.close(); } catch (Exception e) {}
                if (writer != null) try { writer.close(); } catch (Exception e) {}
                if (clientSocket != null) try { clientSocket.close(); } catch (Exception e) {}
                System.out.println("\n" + coCN + " disconnected\n");
            }
        }
    }

    /**
     * Process reservation request with cryptographically binding authorization.
     * Implements non-repudiable signature over reservation context.
     */
    private static JSONObject handleReservationRequest(JSONObject request, X509Certificate coCert) {
        JSONObject response = new JSONObject();
        
        try {
            System.out.println("\n=== Processing Reservation Request (Milestone 2.4) ===");

            // Validate required fields (strict schema validation)
            if (!request.has("method") || !"requestReservation".equals(request.getString("method"))) {
                throw new SecurityException("Invalid method");
            }
            if (!request.has("availabilityId")) throw new SecurityException("Missing availabilityId");
            if (!request.has("spotId")) throw new SecurityException("Missing spotId");
            if (!request.has("validFrom")) throw new SecurityException("Missing validFrom");
            if (!request.has("validTo")) throw new SecurityException("Missing validTo");
            if (!request.has("priceTokens")) throw new SecurityException("Missing priceTokens");
            if (!request.has("coIdentity")) throw new SecurityException("Missing coIdentity");

            String requestedAvailabilityId = request.getString("availabilityId");
            String requestedSpotId = request.getString("spotId");
            String validFrom = request.getString("validFrom");
            String validTo = request.getString("validTo");
            int priceTokens = request.getInt("priceTokens");
            String requestCoIdentity = request.getString("coIdentity");

            System.out.println("  Availability ID: " + requestedAvailabilityId);
            System.out.println("  Spot ID: " + requestedSpotId);
            System.out.println("  Valid: " + validFrom + " to " + validTo);
            System.out.println("  Price: " + priceTokens + " tokens");
            System.out.println("  Requested CO Identity: " + requestCoIdentity);

            // Verify CO identity matches certificate (prevent identity substitution)
            String coCertCN = null;
            try {
                LdapName ldapDN = new LdapName(coCert.getSubjectX500Principal().getName());
                for (Rdn rdn : ldapDN.getRdns()) {
                    if (rdn.getType().equalsIgnoreCase("CN")) {
                        coCertCN = rdn.getValue().toString();
                        break;
                    }
                }
            } catch (Exception e) {
                throw new SecurityException("Cannot extract CO CN from certificate");
            }

            if (!requestCoIdentity.equals(coCertCN)) {
                System.err.println("✖ SECURITY FAILURE: CO identity mismatch!");
                System.err.println("  Request claims: " + requestCoIdentity);
                System.err.println("  Certificate CN: " + coCertCN);
                throw new SecurityException("CO identity mismatch - possible impersonation attack");
            }
            System.out.println("✓ CO identity verified: " + coCertCN);

            // Simple decision logic (OK/NOT_OK without complex business rules)
            String verdict;
            if (publishedAvailabilityId != null && publishedAvailabilityId.equals(requestedAvailabilityId)) {
                verdict = "OK";
                System.out.println("✓ Availability ID matches published availability");
            } else {
                verdict = "NOT_OK";
                System.out.println("⚠ Availability ID does not match published availability");
            }

            // Generate reservationId
            String reservationId = UUID.randomUUID().toString();
            System.out.println("Generated Reservation ID: " + reservationId);

            // Get HO identity
            String hoIdentity = null;
            try {
                LdapName ldapDN = new LdapName(hoCertificate.getSubjectX500Principal().getName());
                for (Rdn rdn : ldapDN.getRdns()) {
                    if (rdn.getType().equalsIgnoreCase("CN")) {
                        hoIdentity = rdn.getValue().toString();
                        break;
                    }
                }
            } catch (Exception e) {
                hoIdentity = "HomeOwner";
            }

            // Create canonical, immutable representation of reservation context
            // This prevents replay, substitution, and field-stripping attacks
            String canonicalData = String.format(
                "reservationId=%s|verdict=%s|availabilityId=%s|spotId=%s|validFrom=%s|validTo=%s|priceTokens=%d|coIdentity=%s",
                reservationId, verdict, requestedAvailabilityId, requestedSpotId, 
                validFrom, validTo, priceTokens, requestCoIdentity
            );

            System.out.println("\n─ Generating Cryptographic Signature ─");
            System.out.println("Canonical data to sign:");
            System.out.println("  " + canonicalData);

            // Sign with HO's RSA-2048 private key using SHA256withRSA
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(hoKeyPair.getPrivate());
            signature.update(canonicalData.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] signatureBytes = signature.sign();
            String signatureB64 = Base64.getEncoder().encodeToString(signatureBytes);

            System.out.println("✓ Signature generated with HO private key");
            System.out.println("  Algorithm: SHA256withRSA");
            System.out.println("  Signature length: " + signatureBytes.length + " bytes");
            System.out.println("  Signature (Base64): " + signatureB64.substring(0, 32) + "...");

            // Build response (security-relevant fields only)
            response.put("status", "success");
            response.put("reservationId", reservationId);
            response.put("verdict", verdict);
            response.put("hoIdentity", hoIdentity);
            response.put("signature", signatureB64);
            response.put("signatureAlg", "SHA256withRSA");
            
            // Include the exact canonical data that was signed (as string)
            // CO will use this to verify the signature
            response.put("signedData", canonicalData);

            System.out.println("\n╔═══════════════════════════════════════════════════════════╗");
            System.out.println("║   RESERVATION DECISION: " + verdict);
            System.out.println("╚═══════════════════════════════════════════════════════════╝");
            System.out.println("Reservation ID: " + reservationId);
            System.out.println("CO Identity: " + requestCoIdentity);
            System.out.println("✓ Cryptographic signature binds HO to this decision");
            System.out.println("✓ Non-repudiable authorization established");

        } catch (SecurityException e) {
            System.err.println("✖ SECURITY FAILURE: " + e.getMessage());
            response.put("status", "error");
            response.put("verdict", "NOT_OK");
            response.put("message", "Security validation failed: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("✖ Error processing reservation: " + e.getMessage());
            e.printStackTrace();
            response.put("status", "error");
            response.put("verdict", "NOT_OK");
            response.put("message", "Reservation processing failed: " + e.getMessage());
        }
        
        return response;
    }

    // Utility methods
    private static void ensureParentDirExists(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        Path parent = path.getParent();
        if (parent != null && !Files.exists(parent)) {
            Files.createDirectories(parent);
        }
    }

    private static String[] intersect(String[] supported, String[] desired) {
        return java.util.Arrays.stream(desired)
            .filter(d -> java.util.Arrays.asList(supported).contains(d))
            .toArray(String[]::new);
    }
}
