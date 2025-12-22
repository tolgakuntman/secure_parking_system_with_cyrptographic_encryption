package com.example;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.net.ssl.*;

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

    private static KeyPair coKeyPair;
    private static X509Certificate coCertificate;

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
            System.out.println("\n=== Car Owner (CO) Starting ===");

            ensureParentDirExists(CO_KEYSTORE_PATH);

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

            // STEP 2: Connect to SP and request tokens
            System.out.println("\n=== Connecting to SP to request payment tokens ===");
            requestTokensFromSP(10); // Request 10 tokens

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
    // Token request from SP
    // -------------------------

    private static void requestTokensFromSP(int tokenCount) throws Exception {
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

            // Verify we presented our certificate
            X509Certificate[] peerCerts = (X509Certificate[]) socket.getSession().getPeerCertificates();
            System.out.println("  SP certificate: " + peerCerts[0].getSubjectX500Principal().getName());

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
}
