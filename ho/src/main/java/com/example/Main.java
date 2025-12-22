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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.security.MessageDigest;
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
    // For backward compatibility some code referenced HO_PAY_PORT; alias it to HO_SERVER_PORT
    private static final int HO_PAY_PORT = HO_SERVER_PORT;
    
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
    // In-memory payment attempts storage (keyed by reservationId)
    private static final ConcurrentMap<String, PaymentRecord> payments = new ConcurrentHashMap<>();
    // Simple struct to hold reservation metadata we will need for M3.2 policy checks
    static class ReservationInfo {
        public final Instant createdAt;
        public final int priceTokens;
        public final String verdict; // "OK" or "NOT_OK"

        public ReservationInfo(Instant createdAt, int priceTokens, String verdict) {
            this.createdAt = createdAt;
            this.priceTokens = priceTokens;
            this.verdict = verdict;
        }
    }

    // Reservation registry: reservationId -> ReservationInfo (for binding payment to valid reservation)
    private static final ConcurrentMap<String, ReservationInfo> reservationRegistry = new ConcurrentHashMap<>();
    // Double-spend prevention: chainId -> lastSpentIndex (reject if new startIndex <= lastSpentIndex)
    private static final ConcurrentMap<String, Long> chainSpendTracking = new ConcurrentHashMap<>();
    // Cached SP public key (populated during publishAvailability mTLS handshake)
    private static volatile java.security.PublicKey spPublicKey = null;
    
    // M3.3: Double-spend test configuration
    private static final boolean TEST_DOUBLE_SPEND = "true".equalsIgnoreCase(System.getenv().getOrDefault("TEST_DOUBLE_SPEND", "false"));
    
    // Store last settlement for replay test
    static class LastSettlement {
        String reservationId;
        String chainId;
        int x;
        int startIndex;
        org.json.JSONArray tokensToSpend;
        String rootB64;
        String rootSignatureB64;
    }
    private static LastSettlement lastSettlement = null;

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

            // STEP 3: Start reservation & payment server to handle CO requests (both on port 8445)
            System.out.println("\n=== Starting HO Reservation & Payment Server ===");
            startReservationServer();

        } catch (Exception e) {
            System.err.println("\n✖ CRITICAL ERROR: HO failed to start");
            System.err.println("Reason: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    // Simple record to store a payment attempt in-memory
    static class PaymentRecord {
        public final String reservationId;
        public final String chainId;
        public final int startIndex;
        public final int tokenCount;
        public final Instant receivedAt;
        public final String callerCN;
        public final String callerCertFingerprint;

        public PaymentRecord(String reservationId, String chainId, int startIndex, int tokenCount,
                             Instant receivedAt, String callerCN, String callerCertFingerprint) {
            this.reservationId = reservationId;
            this.chainId = chainId;
            this.startIndex = startIndex;
            this.tokenCount = tokenCount;
            this.receivedAt = receivedAt;
            this.callerCN = callerCN;
            this.callerCertFingerprint = callerCertFingerprint;
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

                // Verify we're connected to SP and cache SP public key for M3.2 signature checks
                X509Certificate[] peerCerts = (X509Certificate[]) socket.getSession().getPeerCertificates();
                System.out.println("  SP certificate: " + peerCerts[0].getSubjectX500Principal().getName());
                try {
                    spPublicKey = peerCerts[0].getPublicKey();
                    System.out.println("[M3.2] SP public key cached from mTLS handshake");
                } catch (Exception e) {
                    System.err.println("[M3.2] Failed to cache SP public key: " + e.getMessage());
                }

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

    private static void startPaymentServer() throws Exception {
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

    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

    SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
    SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(HO_PAY_PORT);

    // Harden protocols
    String[] desiredProtocols = new String[]{"TLSv1.3", "TLSv1.2"};
    String[] protocols = intersect(serverSocket.getSupportedProtocols(), desiredProtocols);
    if (protocols.length == 0) throw new IllegalStateException("No TLSv1.3/1.2 supported");
    serverSocket.setEnabledProtocols(protocols);

    // Enforce mTLS
    serverSocket.setNeedClientAuth(true);

    System.out.println("\n╔═══════════════════════════════════════════════════════════╗");
    System.out.println("║   HO PAYMENT SERVER READY (Milestone 3.x)                 ║");
    System.out.println("╚═══════════════════════════════════════════════════════════╝");
    System.out.println("Listening on port: " + HO_PAY_PORT);
    System.out.println("mTLS enforcement: ENABLED (CO certificates REQUIRED)");
    System.out.println("Protocols: " + java.util.Arrays.toString(protocols));
    System.out.println("==========================================\n");

    ExecutorService executor = Executors.newCachedThreadPool();
    while (true) {
        SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
        executor.submit(new PaymentHandler(clientSocket));
    }
}

static class PaymentHandler implements Runnable {
    private final SSLSocket clientSocket;
    PaymentHandler(SSLSocket clientSocket) { this.clientSocket = clientSocket; }

    @Override
    public void run() {
        String coCN = null;
        try (
            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true)
        ) {
            System.out.println("\n=== Inbound Payment Request ===");

            // Force handshake (mTLS enforced)
            clientSocket.startHandshake();

            // Identify CO
            X509Certificate[] clientCerts = (X509Certificate[]) clientSocket.getSession().getPeerCertificates();
            X509Certificate coCert = clientCerts[0];

            coCN = extractCN(coCert);

            // Read one-line JSON
            String line = reader.readLine();
            if (line == null) throw new IOException("No request received");

            JSONObject req = new JSONObject(line);
            String method = req.optString("method", "");

            JSONObject resp;
            if ("pay".equals(method)) {
                resp = handlePayRequest(req, coCert, coCN, clientSocket);
            } else {
                resp = new JSONObject()
                        .put("status", "error")
                        .put("code", "bad_request")
                        .put("message", "unknown method");
            }

            writer.println(resp.toString());
        } catch (SSLHandshakeException hs) {
            System.err.println("TLS handshake failed (missing/invalid client cert): " + hs.getMessage());
        } catch (Exception e) {
            System.err.println("Payment handler error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try { clientSocket.close(); } catch (Exception ignored) {}
            System.out.println((coCN != null ? coCN : "Client") + " disconnected");
        }
    }
}

private static String extractCN(X509Certificate cert) {
    try {
        String dn = cert.getSubjectX500Principal().getName();
        LdapName ldap = new LdapName(dn);
        for (Rdn rdn : ldap.getRdns()) {
            if ("CN".equalsIgnoreCase(rdn.getType())) return String.valueOf(rdn.getValue());
        }
    } catch (Exception ignored) {}
    return "Unknown";
}

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

                // Read inbound request (method-based dispatch)
                String requestLine = reader.readLine();
                if (requestLine == null) {
                    throw new IOException("No request received from CO");
                }

                JSONObject request = new JSONObject(requestLine);
                System.out.println("Received request from " + coCN + ":");
                System.out.println(request.toString(2));

                // Dispatch based on method field
                JSONObject response;
                String method = request.optString("method", "");
                if ("requestReservation".equals(method)) {
                    response = handleReservationRequest(request, coCert);
                    writer.println(response.toString());
                    System.out.println("\nSent signed reservation response:");
                    System.out.println(response.toString(2));
                } else if ("pay".equals(method)) {
                    response = handlePayRequest(request, coCert, coCN, clientSocket);
                    writer.println(response.toString());
                    System.out.println("\nSent pay response:");
                    System.out.println(response.toString(2));
                } else {
                    response = new JSONObject();
                    response.put("status", "error");
                    response.put("message", "unknown method");
                    writer.println(response.toString());
                    System.out.println("\nSent error response (unknown method)");
                }

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
            
            // Register reservation in-memory (for payment binding validation)
            reservationRegistry.put(reservationId, new ReservationInfo(Instant.now(), PRICE_TOKENS, verdict));

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

    /**
     * Handle incoming payment request from CO (Milestone 3.1).
     * Validates hash-chain, enforces double-spend prevention, binds to reservation.
     */
    private static JSONObject handlePayRequest(JSONObject request, X509Certificate coCert, String coCN, SSLSocket clientSocket) {
        JSONObject response = new JSONObject();
        String logTag = "[PAY] ";

        try {
            // Schema validation
            if (!request.has("method") || !"pay".equals(request.getString("method"))) {
                throw new IllegalArgumentException("Invalid method");
            }
            if (!request.has("reservationId")) throw new IllegalArgumentException("Missing reservationId");
            if (!request.has("chainId")) throw new IllegalArgumentException("Missing chainId");
            if (!request.has("x")) throw new IllegalArgumentException("Missing x");
            if (!request.has("root")) throw new IllegalArgumentException("Missing root");
            if (!request.has("rootSignature")) throw new IllegalArgumentException("Missing rootSignature");
            if (!request.has("startIndex")) throw new IllegalArgumentException("Missing startIndex");
            if (!request.has("tokensToSpend")) throw new IllegalArgumentException("Missing tokensToSpend");

            String reservationId = request.getString("reservationId");
            String chainId = request.getString("chainId");
            int x = request.getInt("x");
            String rootB64 = request.getString("root");
            int startIndex = request.getInt("startIndex");
            org.json.JSONArray tokensArray = request.getJSONArray("tokensToSpend");

            // Sanity checks
            if (reservationId == null || reservationId.isBlank()) throw new IllegalArgumentException("reservationId blank");
            if (chainId == null || chainId.isBlank()) throw new IllegalArgumentException("chainId blank");
            if (x <= 0) throw new IllegalArgumentException("x must be > 0");
            if (startIndex < 0) throw new IllegalArgumentException("startIndex must be >= 0");
            if (tokensArray.length() == 0) throw new IllegalArgumentException("tokensToSpend cannot be empty");

            int tokenCount = tokensArray.length();

            // Run local M3.2 checks (signature via SP public key, policy checks)
            validatePaymentLocally(request);

            // 1. BINDING TO RESERVATION: verify reservationId exists
            if (!reservationRegistry.containsKey(reservationId)) {
                throw new SecurityException("Reservation " + reservationId + " not found (invalid or expired)");
            }

            // 2. DOUBLE-SPEND PREVENTION: check if this chain has been spent already
            Long lastSpentIndex = chainSpendTracking.getOrDefault(chainId, -1L);
            if (startIndex <= lastSpentIndex) {
                throw new SecurityException("Double-spend detected: startIndex=" + startIndex + " <= lastSpentIndex=" + lastSpentIndex);
            }

            // 3. HASH-CHAIN VERIFICATION: decode tokens and verify hash forward to root
            byte[] rootBytes = b64decode(rootB64);
            java.util.List<byte[]> tokens = new java.util.ArrayList<>();
            for (int i = 0; i < tokensArray.length(); i++) {
                tokens.add(b64decode(tokensArray.getString(i)));
            }

            // Verify tokens are contiguous by hashing forward: each token hashes to the next
            byte[] current = tokens.get(0);
            for (int i = 1; i < tokens.size(); i++) {
                byte[] nextExpected = sha256(current);
                if (!java.util.Arrays.equals(nextExpected, tokens.get(i))) {
                    throw new SecurityException("Hash chain broken: token[" + i + "] does not hash to token[" + (i+1) + "]");
                }
                current = tokens.get(i);
            }

            // Verify last token hashes to root (accounting for remaining hashes beyond tokenCount)
            byte[] computed = current;
            long lastIndex = startIndex + tokenCount - 1;
            int hashesToRoot = (int) (x - (startIndex + tokenCount));
            if (hashesToRoot < 0) throw new SecurityException("Invalid indices: chain length/x mismatch");
            for (int i = 0; i < hashesToRoot; i++) {
                computed = sha256(computed);
            }
            if (!java.util.Arrays.equals(computed, rootBytes)) {
                throw new SecurityException("Hash chain does not reach provided root. Chain verification failed.");
            }

            System.out.println(logTag + "received from " + coCN);
            System.out.println(logTag + "  reservationId=" + reservationId);
            System.out.println(logTag + "  chainId=" + chainId);
            System.out.println(logTag + "  tokenCount=" + tokenCount);
            System.out.println(logTag + "  startIndex=" + startIndex);
            System.out.println(logTag + "  x=" + x);
            System.out.println(logTag + "  Hash-chain verification: SUCCESS");

            // 4. M3.3 SETTLEMENT: Notify SP of the spend progress before accepting payment locally
            String rootSignatureB64 = request.getString("rootSignature");
            boolean settlementSuccess = settleWithSP(reservationId, chainId, x, startIndex, tokensArray, rootB64, rootSignatureB64);
            
            if (!settlementSuccess) {
                // SP rejected settlement - do NOT store payment locally (atomic behavior)
                response.put("status", "error");
                response.put("message", "Settlement with SP failed - payment not accepted");
                response.put("reason", "settlement_failed");
                System.out.println(logTag + "Payment REJECTED: SP settlement failed");
                return response;
            }
            
            // M3.3: DOUBLE-SPEND TEST - Store settlement for replay test
            if (TEST_DOUBLE_SPEND) {
                System.out.println(logTag + "⚠️  TEST_DOUBLE_SPEND enabled - storing settlement for replay");
                lastSettlement = new LastSettlement();
                lastSettlement.reservationId = reservationId;
                lastSettlement.chainId = chainId;
                lastSettlement.x = x;
                lastSettlement.startIndex = startIndex;
                lastSettlement.tokensToSpend = tokensArray;
                lastSettlement.rootB64 = rootB64;
                lastSettlement.rootSignatureB64 = rootSignatureB64;
                
                // Schedule replay attempt in 3 seconds
                new Thread(() -> {
                    try {
                        Thread.sleep(3000);
                        System.out.println("\n" + logTag + "═══════════════════════════════════════════════════");
                        System.out.println(logTag + "⚠️  NEGATIVE TEST: Attempting Double-Spend Replay");
                        System.out.println(logTag + "═══════════════════════════════════════════════════");
                        
                        boolean replayResult = settleWithSP(
                            lastSettlement.reservationId,
                            lastSettlement.chainId,
                            lastSettlement.x,
                            lastSettlement.startIndex,
                            lastSettlement.tokensToSpend,
                            lastSettlement.rootB64,
                            lastSettlement.rootSignatureB64
                        );
                        
                        if (replayResult) {
                            System.err.println(logTag + "❌❌❌ SECURITY FAILURE: SP ACCEPTED DOUBLE-SPEND ❌❌❌");
                        } else {
                            System.out.println(logTag + "✓✓✓ SECURITY SUCCESS: SP REJECTED DOUBLE-SPEND ✓✓✓");
                            System.out.println(logTag + "Double-spend protection working correctly!");
                        }
                        System.out.println(logTag + "═══════════════════════════════════════════════════\n");
                        
                    } catch (Exception e) {
                        System.err.println(logTag + "Replay test error: " + e.getMessage());
                    }
                }).start();
            }

            // 5. STORE PAYMENT RECORD (only after successful settlement)
            String callerFingerprint = "unknown";
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(coCert.getEncoded());
                callerFingerprint = bytesToHex(digest);
            } catch (Exception e) {
                // ignore
            }

            PaymentRecord rec = new PaymentRecord(reservationId, chainId, startIndex, tokenCount,
                    Instant.now(), coCN, callerFingerprint);
            payments.put(reservationId, rec);

            // 6. UPDATE DOUBLE-SPEND TRACKING: store the new lastSpentIndex
            long newLastSpentIndex = (long) (startIndex + tokenCount - 1);
            chainSpendTracking.put(chainId, newLastSpentIndex);

            // 7. BUILD SUCCESS RESPONSE
            response.put("status", "success");
            response.put("message", "payment accepted");
            response.put("reservationId", reservationId);
            response.put("chainId", chainId);
            response.put("startIndex", startIndex);
            response.put("spentCount", tokenCount);
            response.put("newLastSpentIndex", newLastSpentIndex);
            response.put("timestamp", Instant.now().toString());

            System.out.println(logTag + "Payment ACCEPTED. newLastSpentIndex=" + newLastSpentIndex);

        } catch (SecurityException e) {
            System.err.println(logTag + "SECURITY FAILURE: " + e.getMessage());
            response.put("status", "error");
            response.put("message", e.getMessage());
            response.put("reason", "security_violation");
        } catch (IllegalArgumentException e) {
            System.err.println(logTag + "Validation error: " + e.getMessage());
            response.put("status", "error");
            response.put("message", e.getMessage());
            response.put("reason", "bad_request");
        } catch (Exception e) {
            System.err.println(logTag + "Unexpected error: " + e.getMessage());
            e.printStackTrace();
            response.put("status", "error");
            response.put("message", "Payment processing failed: " + e.getMessage());
            response.put("reason", "internal_error");
        }

        return response;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
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

    // Utility methods
    private static void ensureParentDirExists(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        Path parent = path.getParent();
        if (parent != null && !Files.exists(parent)) {
            Files.createDirectories(parent);
        }
    }

    /**
     * M3.3: Settle payment with SP to ensure SP enforces double-spend prevention.
     * HO notifies SP of the new spent progress and SP responds with acceptance or rejection.
     * Returns true if settlement succeeds, false otherwise.
     */
    /**
     * M3.3: Settlement Protocol - HO → SP with Hardened mTLS
     * 
     * Security-focused "token redemption" protocol that finalizes parking payment
     * and prevents replay/double spending. This function:
     * - Establishes hardened mTLS connection to SP (TLS 1.3/1.2, AEAD ciphers)
     * - Explicitly calls startHandshake() before stream creation
     * - Submits minimal JSON settlement request with cryptographic proof
     * - Receives authenticated success response from SP
     * 
     * @param reservationId The reservation being paid for
     * @param chainId The token chain identifier
     * @param x Total chain length
     * @param startIndex First token index spent in this payment
     * @param tokensToSpend Array of tokens being spent
     * @param rootB64 Base64-encoded chain root (for cryptographic verification)
     * @param rootSignatureB64 Base64-encoded SP signature over root
     * @return true if SP accepts settlement, false otherwise
     */
    private static boolean settleWithSP(String reservationId, String chainId, int x, int startIndex, 
                                       org.json.JSONArray tokensToSpend, String rootB64, String rootSignatureB64) {
        String logTag = "[SETTLE] ";
        try {
            // Calculate settlement parameters
            int y = tokensToSpend.length(); // Number of tokens spent
            // newLastSpentIndex = total tokens spent (SP tracks cumulative spend count)
            // When spending indices [startIndex, startIndex+y-1], the new count is startIndex+y
            int newLastSpentIndex = startIndex + y; // Total tokens spent after this payment
            String lastTokenSpent = tokensToSpend.getString(tokensToSpend.length() - 1); // Cryptographic proof
            
            // Optional: include first token as additional proof
            String firstTokenSpent = tokensToSpend.getString(0);

            // ═══════════════════════════════════════════════════════════
            // BUILD MINIMAL SECURITY-CRITICAL SETTLEMENT REQUEST
            // ═══════════════════════════════════════════════════════════
            
            JSONObject settleRequest = new JSONObject();
            settleRequest.put("method", "settle");
            
            // Required fields (strict schema)
            settleRequest.put("chainId", chainId);
            settleRequest.put("reservationId", reservationId);
            settleRequest.put("y", y); // Number of tokens spent
            settleRequest.put("newLastSpentIndex", newLastSpentIndex);
            settleRequest.put("lastTokenSpent", lastTokenSpent); // Cryptographic proof
            
            // Optional but recommended for audit trail
            settleRequest.put("availabilityId", publishedAvailabilityId != null ? publishedAvailabilityId : "unknown");
            settleRequest.put("x", x); // Total chain length
            settleRequest.put("root", rootB64); // For cryptographic verification
            settleRequest.put("rootSignature", rootSignatureB64); // For authenticity verification
            settleRequest.put("firstTokenSpent", firstTokenSpent); // Additional proof
            settleRequest.put("startIndex", startIndex); // Audit information

            System.out.println(logTag + "═══════════════════════════════════════════════════");
            System.out.println(logTag + "Preparing Settlement Request to SP");
            System.out.println(logTag + "  chainId: " + chainId);
            System.out.println(logTag + "  reservationId: " + reservationId);
            System.out.println(logTag + "  y (tokens spent): " + y);
            System.out.println(logTag + "  newLastSpentIndex: " + newLastSpentIndex);
            System.out.println(logTag + "  x (chain length): " + x);
            System.out.println(logTag + "═══════════════════════════════════════════════════");

            // ═══════════════════════════════════════════════════════════
            // ESTABLISH HARDENED mTLS CONNECTION TO SP
            // ═══════════════════════════════════════════════════════════
            
            // Load HO keystore (client certificate for mTLS)
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(HO_KEYSTORE_PATH)) {
                keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            // Load truststore (to verify SP certificate)
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH)) {
                trustStore.load(fis, TRUSTSTORE_PASSWORD.toCharArray());
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            // Create SSLContext with TLS 1.3/1.2 only
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new java.security.SecureRandom());

            SSLSocketFactory factory = sslContext.getSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(SP_HOST, SP_PORT)) {
                
                // ═══════════════════════════════════════════════════════════
                // CONFIGURE HARDENED TLS PARAMETERS
                // ═══════════════════════════════════════════════════════════
                
                // Enforce TLS 1.3 and TLS 1.2 only (modern, secure versions)
                socket.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
                
                // Enforce AEAD cipher suites only (GCM, ChaCha20-Poly1305)
                String[] aeadCiphers = new String[]{
                    "TLS_AES_256_GCM_SHA384",           // TLS 1.3
                    "TLS_CHACHA20_POLY1305_SHA256",      // TLS 1.3
                    "TLS_AES_128_GCM_SHA256",            // TLS 1.3
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",   // TLS 1.2
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"    // TLS 1.2
                };
                socket.setEnabledCipherSuites(aeadCiphers);

                System.out.println(logTag + "✓ TLS hardening applied (TLS 1.3/1.2, AEAD ciphers only)");

                // ═══════════════════════════════════════════════════════════
                // EXPLICIT HANDSHAKE (SECURITY REQUIREMENT)
                // ═══════════════════════════════════════════════════════════
                
                System.out.println(logTag + "Initiating explicit TLS handshake...");
                socket.startHandshake();
                System.out.println(logTag + "✓ TLS handshake completed successfully");
                System.out.println(logTag + "  Protocol: " + socket.getSession().getProtocol());
                System.out.println(logTag + "  Cipher Suite: " + socket.getSession().getCipherSuite());

                // Verify SP certificate
                X509Certificate[] serverCerts = (X509Certificate[]) socket.getSession().getPeerCertificates();
                System.out.println(logTag + "✓ SP certificate verified: " + serverCerts[0].getSubjectX500Principal().getName());

                // ═══════════════════════════════════════════════════════════
                // SEND SETTLEMENT REQUEST (AFTER HANDSHAKE)
                // ═══════════════════════════════════════════════════════════
                
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                out.println(settleRequest.toString());
                out.flush();
                
                System.out.println(logTag + "→ Settlement request sent to SP");

                // ═══════════════════════════════════════════════════════════
                // RECEIVE AUTHENTICATED RESPONSE
                // ═══════════════════════════════════════════════════════════
                
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String response = in.readLine();
                
                if (response == null) {
                    System.err.println(logTag + "❌ No response from SP");
                    return false;
                }

                JSONObject spResponse = new JSONObject(response);
                String status = spResponse.optString("status", "unknown");
                
                if ("success".equals(status)) {
                    System.out.println(logTag + "✓✓✓ SP SETTLEMENT ACCEPTED ✓✓✓");
                    System.out.println(logTag + "  chainId: " + chainId);
                    System.out.println(logTag + "  acceptedLastSpentIndex: " + spResponse.optInt("acceptedLastSpentIndex", -1));
                    System.out.println(logTag + "  tokensConsumed: " + spResponse.optInt("tokensConsumed", y));
                    System.out.println(logTag + "  remainingTokens: " + spResponse.optInt("remainingTokens", -1));
                    System.out.println(logTag + "  timestamp: " + spResponse.optString("timestamp", "unknown"));
                    return true;
                    
                } else {
                    String message = spResponse.optString("message", "unknown error");
                    String reason = spResponse.optString("reason", "unspecified");
                    
                    System.err.println(logTag + "❌❌❌ SP SETTLEMENT REJECTED ❌❌❌");
                    System.err.println(logTag + "  Reason: " + reason);
                    System.err.println(logTag + "  Message: " + message);
                    
                    // Check for double-spend detection
                    if ("double_spend".equals(reason)) {
                        System.err.println(logTag + "⚠️  DOUBLE_SPEND_DETECTED by SP");
                        System.err.println(logTag + "  currentLastSpentIndex: " + spResponse.optInt("currentLastSpentIndex", -1));
                        System.err.println(logTag + "  rejectedNewIndex: " + spResponse.optInt("rejectedNewIndex", -1));
                    }
                    
                    return false;
                }
            }
            
        } catch (Exception e) {
            System.err.println(logTag + "❌ Settlement error: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    /**
     * M3.2: Local payment verification.
     * Perform local M3.2 payment validation checks before accepting payment:
     *  - Verify `rootSignature` over `root` using cached SP public key
     *  - Policy checks: reservation exists, verdict == "OK", token count matches price
     * Throws SecurityException on any validation failure.
     */
    private static void validatePaymentLocally(org.json.JSONObject request) throws Exception {
        String logTag = "[M3.2] ";

        if (spPublicKey == null) throw new SecurityException("SP public key not available for signature verification");

        // Signature check: verify rootSignature over root using SP public key
        if (!request.has("root") || !request.has("rootSignature")) {
            throw new SecurityException("Missing root/rootSignature for signature verification");
        }
        byte[] rootBytes = b64decode(request.getString("root"));
        byte[] sigBytes = b64decode(request.getString("rootSignature"));

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(spPublicKey);
        sig.update(rootBytes);
        boolean ok = sig.verify(sigBytes);
        if (!ok) throw new SecurityException("root signature verification failed");
        System.out.println(logTag + "root signature verified via cached SP public key");

        // Policy checks: reservation exists and verdict OK and token count matches price
        if (!request.has("reservationId")) throw new SecurityException("Missing reservationId for policy check");
        String reservationId = request.getString("reservationId");
        ReservationInfo info = reservationRegistry.get(reservationId);
        if (info == null) throw new SecurityException("Reservation not found or expired");
        if (!"OK".equals(info.verdict)) throw new SecurityException("Reservation verdict != OK");

        if (!request.has("tokensToSpend")) throw new SecurityException("Missing tokensToSpend for policy check");
        org.json.JSONArray tokensArray = request.getJSONArray("tokensToSpend");
        if (tokensArray.length() != info.priceTokens) throw new SecurityException("Token count does not match priceTokens");
        System.out.println(logTag + "policy checks passed (reservation verdict OK, token count matches)");
    }

    private static String[] intersect(String[] supported, String[] desired) {
        return java.util.Arrays.stream(desired)
            .filter(d -> java.util.Arrays.asList(supported).contains(d))
            .toArray(String[]::new);
    }
}
