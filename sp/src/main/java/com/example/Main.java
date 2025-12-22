package com.example;

import java.io.*;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
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

    // SP server details (for accepting client connections)
    private static final int SP_SERVER_PORT = Integer.parseInt(System.getenv().getOrDefault("SP_SERVER_PORT", "8444"));

    private static final String TRUSTSTORE_PATH = System.getenv().getOrDefault("TRUSTSTORE_PATH", "./truststore.p12");
    private static final String TRUSTSTORE_PASSWORD = System.getenv().getOrDefault("TRUSTSTORE_PASSWORD", "trustpassword");

    // Local storage for SP's credentials
    // With docker-compose you should mount a volume to /app/keystore
    private static final String SP_KEYSTORE_PATH =
            System.getenv().getOrDefault("SP_KEYSTORE_PATH", "./keystore/sp_keystore.p12");
    private static final String SP_KEYSTORE_PASSWORD =
            System.getenv().getOrDefault("KEYSTORE_PASSWORD", "serverpassword");
    private static final String SP_KEY_ALIAS =
            System.getenv().getOrDefault("SP_KEY_ALIAS", "sp_key");

    private static KeyPair spKeyPair;
    private static X509Certificate spCertificate;
    private static X509Certificate intermediateCACert; // Intermediate CA certificate for HO chain validation
    private static SSLContext sslContext;

    // Token chain storage (chainId -> chain metadata)
    private static final Map<String, TokenChainMetadata> issuedChains = new ConcurrentHashMap<>();

    // Parking availability storage (availabilityId -> availability record)
    private static final Map<String, ParkingAvailability> availabilities = new ConcurrentHashMap<>();

    static class TokenChainMetadata {
        final byte[] root;
        final int x;
        int lastSpentIndex;

        TokenChainMetadata(byte[] root, int x) {
            this.root = root;
            this.x = x;
            this.lastSpentIndex = 0;
        }
    }

    static class ParkingAvailability {
        final String availabilityId;
        final String homeOwnerId;
        final String spotId;
        final String validFrom;
        final String validTo;
        final int priceTokens;
        final String locationZone;
        final String metadata;
        final String publishedAt;
        final X509Certificate hoCertificate; // HO certificate from mTLS session
        final String hoCertFingerprint; // SHA-256 fingerprint for identity binding

        ParkingAvailability(String availabilityId, String homeOwnerId, String spotId,
                          String validFrom, String validTo, int priceTokens,
                          String locationZone, String metadata, X509Certificate hoCertificate) {
            this.availabilityId = availabilityId;
            this.homeOwnerId = homeOwnerId;
            this.spotId = spotId;
            this.validFrom = validFrom;
            this.validTo = validTo;
            this.priceTokens = priceTokens;
            this.locationZone = locationZone;
            this.metadata = metadata;
            this.publishedAt = java.time.Instant.now().toString();
            this.hoCertificate = hoCertificate;
            
            // Compute SHA-256 fingerprint of certificate for identity binding
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] fingerprint = digest.digest(hoCertificate.getEncoded());
                this.hoCertFingerprint = bytesToHex(fingerprint);
            } catch (Exception e) {
                throw new RuntimeException("Failed to compute certificate fingerprint", e);
            }
        }
    }

    public static void main(String[] args) {
        // Register BC provider (needed for CSR + extensions reliably)
        Security.addProvider(new BouncyCastleProvider());

        // Sleep to allow CAuth to start
        try {
            System.out.println("Waiting for CAuth to start...");
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        try {
            System.out.println("\n=== Service Provider Starting ===");
            System.out.println("Initializing cryptographic baseline...\n");

            ensureParentDirExists(SP_KEYSTORE_PATH);

            // CRITICAL: Establish cryptographic identity before starting server
            if (hasCertificate()) {
                System.out.println("Found existing certificate, loading from keystore...");
                loadExistingCertificate();
            } else {
                System.out.println("No existing certificate found, enrolling with CAuth...");
                enrollWithCAuth();
            }

            // CRITICAL: Verify we have valid cryptographic material
            if (spCertificate == null) {
                throw new IllegalStateException("CRITICAL: SP certificate is null after initialization");
            }
            if (spKeyPair == null || spKeyPair.getPrivate() == null) {
                throw new IllegalStateException("CRITICAL: SP private key is null after initialization");
            }

            // Display certificate information
            System.out.println("\n\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
            System.out.println("\u2551   CRYPTOGRAPHIC IDENTITY ESTABLISHED     \u2551");
            System.out.println("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d");
            System.out.println("Subject: " + spCertificate.getSubjectX500Principal().getName());
            System.out.println("Issuer: " + spCertificate.getIssuerX500Principal().getName());
            System.out.println("Valid from: " + spCertificate.getNotBefore());
            System.out.println("Valid until: " + spCertificate.getNotAfter());
            System.out.println("Serial: " + spCertificate.getSerialNumber().toString(16).toUpperCase());
            System.out.println("\u2713 Certificate and private key verified\n");

            System.out.println("=== Starting SP Server ===");
            startServer();

        } catch (Exception e) {
            System.err.println("\n\u2716 CRITICAL ERROR: SP failed to start");
            System.err.println("Reason: " + e.getMessage());
            e.printStackTrace();
            System.err.println("\n\u2716 SP cannot operate without valid cryptographic material");
            System.err.println("Exiting...");
            System.exit(1);
        }
    }

    // -------------------------
    // Enrollment + keystore
    // -------------------------

    private static boolean hasCertificate() {
        File keystoreFile = new File(SP_KEYSTORE_PATH);
        if (!keystoreFile.exists()) return false;

        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(SP_KEYSTORE_PATH)) {
                ks.load(fis, SP_KEYSTORE_PASSWORD.toCharArray());
            }
            return ks.containsAlias(SP_KEY_ALIAS);
        } catch (Exception e) {
            return false;
        }
    }

    private static void loadExistingCertificate() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(SP_KEYSTORE_PATH)) {
            ks.load(fis, SP_KEYSTORE_PASSWORD.toCharArray());
        }

        spCertificate = (X509Certificate) ks.getCertificate(SP_KEY_ALIAS);
        if (spCertificate == null) {
            throw new IllegalStateException("CRITICAL: SP certificate not found in keystore under alias: " + SP_KEY_ALIAS);
        }

        PrivateKey privateKey = (PrivateKey) ks.getKey(SP_KEY_ALIAS, SP_KEYSTORE_PASSWORD.toCharArray());
        if (privateKey == null) {
            throw new IllegalStateException("CRITICAL: SP private key not found in keystore under alias: " + SP_KEY_ALIAS);
        }

        PublicKey publicKey = spCertificate.getPublicKey();
        spKeyPair = new KeyPair(publicKey, privateKey);

        // STRICT: Certificate MUST be valid
        try {
            spCertificate.checkValidity();
            System.out.println("✓ Certificate validity period verified");
        } catch (Exception e) {
            throw new IllegalStateException("CRITICAL: Certificate has expired or is not yet valid: " + e.getMessage());
        }

        // Verify certificate chain
        java.security.cert.Certificate[] chain = ks.getCertificateChain(SP_KEY_ALIAS);
        if (chain == null || chain.length == 0) {
            throw new IllegalStateException("CRITICAL: No certificate chain found in keystore");
        }

        System.out.println("✓ Certificate chain loaded (" + chain.length + " certificates)");
        
        // Store intermediate CA certificate (index 1 in chain) for including in availability responses
        if (chain.length >= 2) {
            intermediateCACert = (X509Certificate) chain[1];
            System.out.println("✓ Intermediate CA certificate stored for HO chain validation");
        }
        
        validateCertificateChain(chain);
    }

    private static void enrollWithCAuth() throws Exception {
        System.out.println("Step 1: Generating RSA key pair...");
        spKeyPair = generateKeyPair();
        System.out.println("✓ RSA-2048 key pair generated successfully");

        System.out.println("\nStep 2: Creating Certificate Signing Request (CSR)...");
        PKCS10CertificationRequest csr = createCSR(spKeyPair);
        System.out.println("✓ CSR created with subject: CN=ServiceProvider, O=Parking System, C=BE");

        System.out.println("\nStep 3: Connecting to CAuth server over TLS...");
        X509Certificate[] certChain = requestCertificateFromCAuth(csr);

        if (certChain == null || certChain.length == 0 || certChain[0] == null) {
            throw new IllegalStateException("CRITICAL: Enrollment failed - CAuth did not return a valid certificate.");
        }

        spCertificate = certChain[0];
        System.out.println("✓ Certificate received from CAuth");

        // Validate received certificate before storing
        System.out.println("\nStep 4: Validating received certificate...");
        validateReceivedCertificate(spCertificate, certChain);
        System.out.println("✓ Certificate chain validation successful");

        System.out.println("\nStep 5: Storing certificate and private key securely...");
        storeCertificateAndKey(certChain);
        System.out.println("✓ Credentials stored in " + SP_KEYSTORE_PATH);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    /**
     * Validates the certificate received from CAuth during enrollment.
     * Ensures the certificate is valid, properly signed, and matches our public key.
     */
    private static void validateReceivedCertificate(X509Certificate cert, X509Certificate[] chain) throws Exception {
        // 1. Check validity period
        try {
            cert.checkValidity();
            System.out.println("  ✓ Certificate is within validity period");
            System.out.println("    Valid from: " + cert.getNotBefore());
            System.out.println("    Valid until: " + cert.getNotAfter());
        } catch (Exception e) {
            throw new IllegalStateException("Certificate validity check failed: " + e.getMessage());
        }

        // 2. Verify public key matches what we generated
        if (!cert.getPublicKey().equals(spKeyPair.getPublic())) {
            throw new IllegalStateException("Certificate public key does not match generated key pair");
        }
        System.out.println("  ✓ Certificate public key matches generated key pair");

        // 3. Validate certificate chain
        validateCertificateChain(chain);
    }

    /**
     * Validates the full certificate chain against the truststore.
     * This ensures the chain terminates at our trusted Root CA.
     */
    private static void validateCertificateChain(java.security.cert.Certificate[] chain) throws Exception {
        if (chain == null || chain.length == 0) {
            throw new IllegalStateException("Certificate chain is empty");
        }

        System.out.println("  Validating certificate chain (" + chain.length + " certificates):");
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = (X509Certificate) chain[i];
            System.out.println("    [" + i + "] " + cert.getSubjectX500Principal().getName());
            System.out.println("        Issuer: " + cert.getIssuerX500Principal().getName());
            
            // Verify each cert is valid
            try {
                cert.checkValidity();
            } catch (Exception e) {
                throw new IllegalStateException("Certificate [" + i + "] in chain is invalid: " + e.getMessage());
            }

            // Verify signature chain (except for root which is self-signed)
            if (i < chain.length - 1) {
                X509Certificate issuerCert = (X509Certificate) chain[i + 1];
                try {
                    cert.verify(issuerCert.getPublicKey());
                    System.out.println("        ✓ Signature verified by issuer");
                } catch (Exception e) {
                    throw new IllegalStateException("Certificate [" + i + "] signature verification failed: " + e.getMessage());
                }
            }
        }

        // Verify the chain terminates at a trusted root from our truststore
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(fis, TRUSTSTORE_PASSWORD.toCharArray());
        }

        X509Certificate rootCert = (X509Certificate) chain[chain.length - 1];
        boolean foundTrustedRoot = false;
        
        var aliases = trustStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            java.security.cert.Certificate trustedCert = trustStore.getCertificate(alias);
            if (trustedCert instanceof X509Certificate && trustedCert.equals(rootCert)) {
                foundTrustedRoot = true;
                System.out.println("  ✓ Chain terminates at trusted Root CA: " + alias);
                break;
            }
        }

        if (!foundTrustedRoot) {
            throw new IllegalStateException("Certificate chain does not terminate at a trusted Root CA");
        }

        System.out.println("  ✓ Certificate chain validation complete");
    }

    private static PKCS10CertificationRequest createCSR(KeyPair keyPair) throws Exception {
        // Stable identity (no timestamp) for consistent CN across enrollments
        X500Name subject = new X500Name(
                "CN=ServiceProvider, O=Parking System, C=BE"
        );

        JcaPKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

        // Add SANs (good practice; CA may ignore if not copying CSR extensions)
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        GeneralNames sans = new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "sp"),
                new GeneralName(GeneralName.dNSName, "localhost")
        });
        extGen.addExtension(Extension.subjectAlternativeName, false, sans);
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

            // Harden enrollment connection: restrict to modern TLS protocols only
            String[] desiredProtocols = new String[]{"TLSv1.3", "TLSv1.2"};
            String[] enrollProtocols = intersect(socket.getSupportedProtocols(), desiredProtocols);
            if (enrollProtocols.length == 0) {
                throw new IllegalStateException("No modern TLS protocols (1.2/1.3) supported for enrollment connection");
            }
            socket.setEnabledProtocols(enrollProtocols);

            // Restrict to strong cipher suites (same allowlist as server)
            String[] preferredCiphers = new String[]{
                // TLS 1.3 ciphers
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256",
                "TLS_CHACHA20_POLY1305_SHA256",
                // TLS 1.2 strong ciphers with PFS
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
            };
            String[] enrollCiphers = intersect(socket.getSupportedCipherSuites(), preferredCiphers);
            if (enrollCiphers.length == 0) {
                throw new IllegalStateException("No strong cipher suites available for enrollment connection (modern TLS requirement)");
            }
            socket.setEnabledCipherSuites(enrollCiphers);

            socket.startHandshake();

            // Log TLS connection details for audit
            System.out.println("✓ TLS connection established to CAuth");
            System.out.println("  Protocol: " + socket.getSession().getProtocol());
            System.out.println("  Cipher suite: " + socket.getSession().getCipherSuite());
            
            // Verify CAuth certificate
            X509Certificate[] cauthCerts = (X509Certificate[]) socket.getSession().getPeerCertificates();
            if (cauthCerts.length > 0) {
                System.out.println("  CAuth certificate verified:");
                System.out.println("    Subject: " + cauthCerts[0].getSubjectX500Principal().getName());
                System.out.println("    Issuer: " + cauthCerts[0].getIssuerX500Principal().getName());
            }

            JSONObject request = new JSONObject();
            request.put("method", "signCSR");
            request.put("csr", java.util.Base64.getEncoder().encodeToString(csr.getEncoded()));

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

            X509Certificate spCert = parseX509FromPemB64(cf, jsonResponse.getString("certificate"));

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

            if (rootCert != null && caCert != null) return new X509Certificate[]{spCert, caCert, rootCert};
            if (caCert != null) return new X509Certificate[]{spCert, caCert};
            return new X509Certificate[]{spCert};
        }
    }

    private static void storeCertificateAndKey(X509Certificate[] chain) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");

        File keystoreFile = new File(SP_KEYSTORE_PATH);
        if (keystoreFile.exists()) {
            try (FileInputStream fis = new FileInputStream(SP_KEYSTORE_PATH)) {
                ks.load(fis, SP_KEYSTORE_PASSWORD.toCharArray());
            }
        } else {
            ks.load(null, null);
        }

        System.out.println("Storing certificate chain with " + chain.length + " certificate(s)");
        for (int i = 0; i < chain.length && chain[i] != null; i++) {
            System.out.println("  [" + i + "] " + chain[i].getSubjectX500Principal().getName());
        }

        if (chain[0] == null) throw new IllegalStateException("Cannot store: SP leaf certificate is null");

        ks.setKeyEntry(
                SP_KEY_ALIAS,
                spKeyPair.getPrivate(),
                SP_KEYSTORE_PASSWORD.toCharArray(),
                chain
        );

        try (FileOutputStream fos = new FileOutputStream(SP_KEYSTORE_PATH)) {
            ks.store(fos, SP_KEYSTORE_PASSWORD.toCharArray());
        }
    }

    // -------------------------
    // TLS Server (mTLS)
    // -------------------------

    private static void startServer() throws Exception {
        // 1) Truststore: verify client certificates (HO/CO)
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(fis, TRUSTSTORE_PASSWORD.toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // 2) Keystore: SP identity (server cert + private key)
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(SP_KEYSTORE_PATH)) {
            keyStore.load(fis, SP_KEYSTORE_PASSWORD.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, SP_KEYSTORE_PASSWORD.toCharArray());

        // 3) SSLContext with both
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(SP_SERVER_PORT);

        System.out.println("\n=== SP CRYPTOGRAPHIC BASELINE ESTABLISHED ===");
        System.out.println("Version: 2025-12-22 (Hardened TLS with mTLS enforcement)");

        // Configure protocols: ONLY TLS 1.3 and TLS 1.2 (modern, secure versions)
        String[] enabledProtocols = intersect(serverSocket.getSupportedProtocols(),
                new String[]{"TLSv1.3", "TLSv1.2"});
        serverSocket.setEnabledProtocols(enabledProtocols);
        System.out.println("✓ Enabled TLS protocols: " + java.util.Arrays.toString(enabledProtocols));

        // Configure strong cipher suites: Prefer AEAD ciphers (GCM), exclude weak/anonymous ciphers
        String[] preferredCiphers = new String[]{
            // TLS 1.3 ciphers (if available)
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            // TLS 1.2 strong ciphers with Perfect Forward Secrecy
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
        };
        String[] enabledCiphers = intersect(serverSocket.getSupportedCipherSuites(), preferredCiphers);
        if (enabledCiphers.length > 0) {
            serverSocket.setEnabledCipherSuites(enabledCiphers);
            System.out.println("✓ Strong cipher suites configured: " + enabledCiphers.length + " suites");
            // for (String cipher : enabledCiphers) {
            //     System.out.println("    - " + cipher);
            // }
        } else {
            System.out.println("Warning: No preferred cipher suites available, using platform defaults");
        }

        // Configure client-auth: MUST be set on server socket before accept()
        serverSocket.setNeedClientAuth(true);
        System.out.println(" Mutual TLS (mTLS) REQUIRED - client certificates enforced");

        // Log security configuration
        System.out.println("\n=== TLS Server Configuration ===");
        System.out.println("Server listening on port: " + SP_SERVER_PORT);
        System.out.println("Server certificate subject: " + spCertificate.getSubjectX500Principal().getName());
        System.out.println("Server certificate issuer: " + spCertificate.getIssuerX500Principal().getName());
        System.out.println("Certificate serial: " + spCertificate.getSerialNumber().toString(16).toUpperCase());
        System.out.println("Certificate algorithm: " + spCertificate.getSigAlgName());
        System.out.println("Public key algorithm: " + spCertificate.getPublicKey().getAlgorithm());
        if (spCertificate.getPublicKey().getAlgorithm().equals("RSA")) {
            java.security.interfaces.RSAPublicKey rsaKey = (java.security.interfaces.RSAPublicKey) spCertificate.getPublicKey();
            System.out.println("RSA key size: " + rsaKey.getModulus().bitLength() + " bits");
        }
        System.out.println("mTLS enforcement: ENABLED (client certificates REQUIRED)");
        System.out.println("\n✓ SP Server ready to accept secure connections");
        System.out.println("==========================================\n");

        ExecutorService executor = Executors.newCachedThreadPool();
        while (true) {
            SSLSocket clientSocket = (SSLSocket) serverSocket.accept();

            clientSocket.setUseClientMode(false);
            clientSocket.setNeedClientAuth(true);
            clientSocket.setEnabledProtocols(enabledProtocols); // reuse the same enabledProtocols you computed

            executor.submit(new ClientHandler(clientSocket));
        }
    }

    // -------------------------
    // Client handler
    // -------------------------

    static class ClientHandler implements Runnable {
        private final SSLSocket clientSocket;

        public ClientHandler(SSLSocket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            String cn = null;
            BufferedReader reader = null;
            PrintWriter writer = null;
            try {
                System.out.println("\n=== Inbound Connection ===");
                
                // Force handshake - this will enforce the mTLS parameters we set on the socket
                clientSocket.startHandshake();

                // Now get streams after successful handshake
                reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                writer = new PrintWriter(clientSocket.getOutputStream(), true);

                // Get peer certificates - this will throw SSLPeerUnverifiedException if client didn't provide cert
                X509Certificate[] clientCerts = (X509Certificate[]) clientSocket.getSession().getPeerCertificates();
                String dn = clientCerts[0].getSubjectX500Principal().getName();

                try {
                    LdapName ldapDN = new LdapName(dn);
                    for (Rdn rdn : ldapDN.getRdns()) {
                        if (rdn.getType().equalsIgnoreCase("CN")) {
                            cn = rdn.getValue().toString();
                            break;
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }

                System.out.println("\n║   CLIENT AUTHENTICATED VIA mTLS           ║");
                System.out.println("Client CN: " + cn);
                System.out.println("Client address: " + clientSocket.getRemoteSocketAddress());
                System.out.println("Client certificate subject: " + clientCerts[0].getSubjectX500Principal().getName());
                System.out.println("Client certificate issuer: " + clientCerts[0].getIssuerX500Principal().getName());
                System.out.println("Client certificate serial: " + clientCerts[0].getSerialNumber().toString(16).toUpperCase());
                System.out.println("Certificate valid from: " + clientCerts[0].getNotBefore());
                System.out.println("Certificate valid until: " + clientCerts[0].getNotAfter());
                System.out.println("\nTLS Session Details:");
                System.out.println("  Protocol: " + clientSocket.getSession().getProtocol());
                System.out.println("  Cipher suite: " + clientSocket.getSession().getCipherSuite());
                byte[] sessionId = clientSocket.getSession().getId();
                if (sessionId != null && sessionId.length > 0) {
                    String hexId = bytesToHex(sessionId).substring(0, Math.min(16, sessionId.length * 2));
                    System.out.println("  Session ID: " + hexId + "...");
                }
                System.out.println("═══════════════════════════════════════════\n");

                String inputLine;
                while ((inputLine = reader.readLine()) != null) {
                    try {
                        JSONObject request = new JSONObject(inputLine);
                        System.out.println("\nReceived from " + cn + ": " + request.toString(2));

                        String method = request.getString("method");
                        JSONObject response = new JSONObject();

                        switch (method) {
                            case "hello" -> {
                                response.put("status", "success");
                                response.put("message", "Hello " + clientCerts[0].getSubjectX500Principal().getName() + "! Welcome to SP.");
                                response.put("timestamp", new Date().toString());
                            }
                            case "requestTokens" -> {
                                response = handleTokenRequest(request, cn);
                            }
                            case "publishAvailability" -> {
                                response = handlePublishAvailability(request, cn, clientCerts[0]);
                            }
                            case "getAvailability" -> {
                                response = handleGetAvailability(cn);
                            }
                            default -> {
                                response.put("status", "error");
                                response.put("message", "Unknown method: " + method);
                            }
                        }

                        writer.println(response.toString());
                        System.out.println("Sent response: " + response.toString(2));

                    } catch (Exception e) {
                        System.err.println("Error processing request: " + e.getMessage());
                        JSONObject errorResponse = new JSONObject();
                        errorResponse.put("status", "error");
                        errorResponse.put("message", "Error processing request");
                        writer.println(errorResponse.toString());
                    }
                }

            } catch (SSLHandshakeException hs) {
                System.err.println("TLS handshake failed (missing/invalid client cert): " + hs.getMessage());
            } catch (Exception e) {
                System.err.println("Error handling client: " + e.getMessage());
                e.printStackTrace();
            } finally {
                try {
                    if (reader != null) reader.close();
                } catch (Exception ignored) {}
                try {
                    if (writer != null) writer.close();
                } catch (Exception ignored) {}
                try {
                    if (clientSocket != null && !clientSocket.isClosed()) {
                        clientSocket.close();
                    }
                } catch (Exception ignored) {}
                System.out.println("\n" + (cn != null ? cn : "Client") + " disconnected");
            }
        }
    }

    // -------------------------
    // Token generation (hash chain)
    // -------------------------

    private static JSONObject handleTokenRequest(JSONObject request, String clientCN) {
        JSONObject response = new JSONObject();
        try {
            int count = request.getInt("count");
            
            if (count <= 0 || count > 10000) {
                response.put("status", "error");
                response.put("message", "Invalid token count (must be 1-10000)");
                return response;
            }

            System.out.println("\n=== Generating " + count + " payment tokens for " + clientCN + " ===");

            // Generate secret s (32 bytes of cryptographic randomness)
            SecureRandom secureRandom = new SecureRandom();
            byte[] secret = new byte[32];
            secureRandom.nextBytes(secret);

            System.out.println("✓ Generated secret s (" + secret.length + " bytes)");

            // Generate hash chain: H(s), H(H(s)), ..., H^x(s)
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            List<byte[]> tokens = new ArrayList<>();
            
            byte[] current = secret;
            for (int i = 0; i < count; i++) {
                current = digest.digest(current);
                tokens.add(current.clone());
            }

            // The last token is the root H^x(s)
            byte[] root = tokens.get(tokens.size() - 1);
            System.out.println("✓ Generated hash chain of length " + count);
            System.out.println("  Root H^" + count + "(s): " + bytesToHex(root).substring(0, 16) + "...");

            // Sign the root with SP's private key
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(spKeyPair.getPrivate());
            sig.update(root);
            byte[] rootSignature = sig.sign();
            System.out.println("✓ Signed root with SP private key (" + rootSignature.length + " bytes)");

            // Generate unique chain ID
            String chainId = UUID.randomUUID().toString();

            // Store chain metadata for future spending verification (Milestone 2)
            TokenChainMetadata metadata = new TokenChainMetadata(root, count);
            issuedChains.put(chainId, metadata);
            System.out.println("✓ Stored chain metadata (ID: " + chainId + ")");

            // Build response
            response.put("status", "success");
            response.put("x", count);
            response.put("chainId", chainId);
            
            // Encode tokens as Base64
            JSONArray tokensArray = new JSONArray();
            for (byte[] token : tokens) {
                tokensArray.put(Base64.getEncoder().encodeToString(token));
            }
            response.put("tokens", tokensArray);
            
            // Root and signature
            response.put("root", Base64.getEncoder().encodeToString(root));
            response.put("rootSignature", Base64.getEncoder().encodeToString(rootSignature));
            response.put("tokenHashAlg", "SHA-256");
            response.put("signatureAlg", "SHA256withRSA");

            System.out.println("✓ Token batch ready to send to " + clientCN);
            System.out.println("═".repeat(50));

        } catch (Exception e) {
            System.err.println("Error generating tokens: " + e.getMessage());
            e.printStackTrace();
            response.put("status", "error");
            response.put("message", "Token generation failed: " + e.getMessage());
        }
        return response;
    }

    private static JSONObject handlePublishAvailability(JSONObject request, String clientCN, X509Certificate hoCertificate) {
        JSONObject response = new JSONObject();
        try {
            // Validate required fields
            if (!request.has("homeOwnerId") || !request.has("spotId") || 
                !request.has("validFrom") || !request.has("validTo") || 
                !request.has("priceTokens")) {
                response.put("status", "error");
                response.put("message", "Missing required fields: homeOwnerId, spotId, validFrom, validTo, priceTokens");
                return response;
            }

            String homeOwnerId = request.getString("homeOwnerId");
            String spotId = request.getString("spotId");
            String validFrom = request.getString("validFrom");
            String validTo = request.getString("validTo");
            int priceTokens = request.getInt("priceTokens");
            String locationZone = request.optString("locationZone", "");
            String metadata = request.optJSONObject("metadata") != null ? 
                            request.getJSONObject("metadata").toString() : "{}";

            System.out.println("\n=== Publishing Parking Availability from " + clientCN + " ===");
            System.out.println("  Home Owner: " + homeOwnerId);
            System.out.println("  Spot ID: " + spotId);
            System.out.println("  Valid: " + validFrom + " to " + validTo);
            System.out.println("  Price: " + priceTokens + " tokens");
            System.out.println("  Location: " + locationZone);

            // Validate price
            if (priceTokens <= 0) {
                response.put("status", "error");
                response.put("message", "Invalid price (must be > 0)");
                return response;
            }

            // Validate time window (basic validation)
            try {
                java.time.Instant from = java.time.Instant.parse(validFrom);
                java.time.Instant to = java.time.Instant.parse(validTo);
                
                if (to.isBefore(from)) {
                    response.put("status", "error");
                    response.put("message", "Invalid time window: validTo must be after validFrom");
                    return response;
                }

                if (from.isBefore(java.time.Instant.now().minusSeconds(300))) {
                    response.put("status", "error");
                    response.put("message", "validFrom is too far in the past");
                    return response;
                }
            } catch (java.time.format.DateTimeParseException e) {
                response.put("status", "error");
                response.put("message", "Invalid date format (use ISO-8601)");
                return response;
            }

            // Generate availability ID
            String availabilityId = UUID.randomUUID().toString();

            // Store availability with HO certificate from mTLS session
            ParkingAvailability availability = new ParkingAvailability(
                availabilityId, homeOwnerId, spotId, validFrom, validTo,
                priceTokens, locationZone, metadata, hoCertificate
            );
            availabilities.put(availabilityId, availability);

            System.out.println("✓ Availability stored with ID: " + availabilityId);
            System.out.println("✓ Total availabilities in system: " + availabilities.size());
            System.out.println("═".repeat(50));

            // Build success response
            response.put("status", "success");
            response.put("availabilityId", availabilityId);
            response.put("message", "Parking availability published successfully");
            response.put("spotId", spotId);
            response.put("publishedAt", availability.publishedAt);

        } catch (Exception e) {
            System.err.println("Error publishing availability: " + e.getMessage());
            e.printStackTrace();
            response.put("status", "error");
            response.put("message", "Failed to publish availability: " + e.getMessage());
        }
        return response;
    }

    private static JSONObject handleGetAvailability(String clientCN) {
        JSONObject response = new JSONObject();
        try {
            System.out.println("\n=== Availability Discovery Request from " + clientCN + " ===");
            System.out.println("  Total availabilities in system: " + availabilities.size());

            JSONArray availabilityList = new JSONArray();

            for (ParkingAvailability avail : availabilities.values()) {
                JSONObject item = new JSONObject();
                
                // Security-relevant fields for authenticated service discovery
                item.put("availabilityId", avail.availabilityId);
                item.put("spotId", avail.spotId);
                item.put("priceTokens", avail.priceTokens);
                item.put("validFrom", avail.validFrom);
                item.put("validTo", avail.validTo);
                item.put("locationZone", avail.locationZone);
                item.put("homeOwnerId", avail.homeOwnerId);
                
                // HO identity binding fields
                item.put("hoCertFingerprint", avail.hoCertFingerprint);
                
                // Extract HO certificate CN for logging
                String hoCN = "";
                try {
                    String hoDN = avail.hoCertificate.getSubjectX500Principal().getName();
                    LdapName ldapDN = new LdapName(hoDN);
                    for (Rdn rdn : ldapDN.getRdns()) {
                        if (rdn.getType().equalsIgnoreCase("CN")) {
                            hoCN = rdn.getValue().toString();
                            break;
                        }
                    }
                } catch (Exception e) {
                    hoCN = "Unknown";
                }
                item.put("hoIdentity", hoCN);
                
                // Encode HO certificate as Base64 PEM for CO to verify chain
                try {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    baos.write("-----BEGIN CERTIFICATE-----\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    String b64 = Base64.getEncoder().encodeToString(avail.hoCertificate.getEncoded());
                    // Split into 64-char lines
                    for (int i = 0; i < b64.length(); i += 64) {
                        baos.write(b64.substring(i, Math.min(i + 64, b64.length())).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        baos.write('\n');
                    }
                    baos.write("-----END CERTIFICATE-----\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    item.put("hoCertificate", baos.toString("UTF-8"));
                } catch (Exception e) {
                    System.err.println("  ⚠ Failed to encode HO certificate: " + e.getMessage());
                    item.put("hoCertificate", "");
                }
                
                // Include intermediate CA certificate for chain validation
                if (intermediateCACert != null) {
                    try {
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        baos.write("-----BEGIN CERTIFICATE-----\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        String b64 = Base64.getEncoder().encodeToString(intermediateCACert.getEncoded());
                        for (int i = 0; i < b64.length(); i += 64) {
                            baos.write(b64.substring(i, Math.min(i + 64, b64.length())).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                            baos.write('\n');
                        }
                        baos.write("-----END CERTIFICATE-----\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        item.put("intermediateCACert", baos.toString("UTF-8"));
                    } catch (Exception e) {
                        System.err.println("  ⚠ Failed to encode intermediate CA certificate: " + e.getMessage());
                    }
                }
                
                availabilityList.put(item);
                
                System.out.println("  [" + avail.availabilityId + "] " + avail.spotId + " - " + 
                                 avail.priceTokens + " tokens (HO: " + hoCN + ")");
            }

            response.put("status", "success");
            response.put("availabilities", availabilityList);
            response.put("count", availabilities.size());
            response.put("timestamp", java.time.Instant.now().toString());

            System.out.println("✓ Returned " + availabilities.size() + " availability record(s) to " + clientCN);
            System.out.println("═".repeat(50));

        } catch (Exception e) {
            System.err.println("Error retrieving availabilities: " + e.getMessage());
            e.printStackTrace();
            response.put("status", "error");
            response.put("message", "Failed to retrieve availabilities: " + e.getMessage());
        }
        return response;
    }

    // -------------------------
    // Helpers
    // -------------------------

    private static void ensureParentDirExists(String filePath) {
        File f = new File(filePath);
        File parent = f.getParentFile();
        if (parent != null && !parent.exists()) {
            boolean ok = parent.mkdirs();
            if (!ok) {
                System.out.println("Warning: could not create keystore directory: " + parent.getAbsolutePath());
            }
        }
    }

    private static X509Certificate parseX509FromPemB64(java.security.cert.CertificateFactory cf, String pemB64) throws Exception {
        byte[] pemBytes = java.util.Base64.getDecoder().decode(pemB64);
        String pem = new String(pemBytes, java.nio.charset.StandardCharsets.UTF_8);
        return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(java.nio.charset.StandardCharsets.UTF_8))
        );
    }

    private static String[] intersect(String[] supported, String[] desired) {
        java.util.List<String> sup = java.util.Arrays.asList(supported);
        java.util.List<String> out = new java.util.ArrayList<>();
        for (String d : desired) if (sup.contains(d)) out.add(d);
        return out.toArray(new String[0]);
    }

    /**
     * Converts byte array to hexadecimal string (for logging session IDs, serials, etc.)
     * Does NOT log sensitive cryptographic material (keys, passwords, etc.)
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
