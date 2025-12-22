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

public class Main {
    private static final String CAUTH_HOST = System.getenv().getOrDefault("CAUTH_HOST", "localhost");
    private static final int CAUTH_PORT = Integer.parseInt(System.getenv().getOrDefault("CAUTH_PORT", "8443"));
    private static final String SP_HOST = System.getenv().getOrDefault("SP_HOST", "localhost");
    private static final int SP_PORT = Integer.parseInt(System.getenv().getOrDefault("SP_PORT", "8444"));
    
    private static final String HO_KEYSTORE_PATH = "/app/keystore/ho_keystore.p12";
    private static final String KEYSTORE_PASSWORD = System.getenv().getOrDefault("KEYSTORE_PASSWORD", "changeit");
    private static final String ROOT_CA_PATH = System.getenv().getOrDefault("ROOT_CA_PATH", "/app/certs/root_ca.crt");
    private static final String TRUSTSTORE_PATH = "/app/truststore/ho_truststore.p12";
    
    // HO configuration
    private static final String HOME_OWNER_ID = System.getenv().getOrDefault("HOME_OWNER_ID", "HO-001");
    private static final String SPOT_ID = System.getenv().getOrDefault("SPOT_ID", "SPOT-A1");
    private static final String LOCATION_ZONE = System.getenv().getOrDefault("LOCATION_ZONE", "Downtown-North");
    private static final int PRICE_TOKENS = Integer.parseInt(System.getenv().getOrDefault("PRICE_TOKENS", "5"));
    private static final int AVAILABILITY_HOURS = Integer.parseInt(System.getenv().getOrDefault("AVAILABILITY_HOURS", "8"));
    
    private static KeyPair hoKeyPair;
    private static X509Certificate hoCertificate;

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

            System.out.println("\n✓✓✓ HO SERVICE COMPLETED SUCCESSFULLY ✓✓✓");

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
                        System.out.println("Availability ID: " + response.getString("availabilityId"));
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
