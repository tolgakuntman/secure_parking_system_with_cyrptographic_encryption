package com.example;

import java.io.*;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
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
    private static SSLContext sslContext;

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

            ensureParentDirExists(SP_KEYSTORE_PATH);

            if (hasCertificate()) {
                System.out.println("Found existing certificate, loading from keystore...");
                loadExistingCertificate();
            } else {
                System.out.println("No existing certificate found, enrolling with CAuth...");
                enrollWithCAuth();
            }

            if (spCertificate != null) {
                System.out.println("\n=== Certificate Ready ===");
                System.out.println("Subject: " + spCertificate.getSubjectX500Principal().getName());
                System.out.println("Valid from: " + spCertificate.getNotBefore());
                System.out.println("Valid until: " + spCertificate.getNotAfter());
                System.out.println("Issuer: " + spCertificate.getIssuerX500Principal().getName());
            }

            System.out.println("\n=== Starting SP Server ===");
            startServer();

        } catch (Exception e) {
            e.printStackTrace();
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
        PrivateKey privateKey = (PrivateKey) ks.getKey(SP_KEY_ALIAS, SP_KEYSTORE_PASSWORD.toCharArray());
        PublicKey publicKey = spCertificate.getPublicKey();
        spKeyPair = new KeyPair(publicKey, privateKey);

        try {
            spCertificate.checkValidity();
        } catch (Exception e) {
            System.out.println("Warning: Certificate has expired or is not yet valid!");
        }
    }

    private static void enrollWithCAuth() throws Exception {
        System.out.println("Step 1: Generating RSA key pair...");
        spKeyPair = generateKeyPair();
        System.out.println("Key pair generated successfully");

        System.out.println("\nStep 2: Creating Certificate Signing Request (CSR)...");
        PKCS10CertificationRequest csr = createCSR(spKeyPair);
        System.out.println("CSR created successfully");

        System.out.println("\nStep 3: Connecting to CAuth server...");
        X509Certificate[] certChain = requestCertificateFromCAuth(csr);

        if (certChain == null || certChain.length == 0 || certChain[0] == null) {
            throw new IllegalStateException("Enrollment failed: CAuth did not return a valid certificate.");
        }

        spCertificate = certChain[0];
        System.out.println("Certificate received from CAuth");

        System.out.println("\nStep 4: Storing certificate and private key...");
        storeCertificateAndKey(certChain);
        System.out.println("Credentials stored in " + SP_KEYSTORE_PATH);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private static PKCS10CertificationRequest createCSR(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name(
                "CN=ServiceProvider-" + System.currentTimeMillis() + ", O=Parking System, C=BE"
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

            socket.startHandshake();

            JSONObject request = new JSONObject();
            request.put("method", "signCSR");
            request.put("csr", java.util.Base64.getEncoder().encodeToString(csr.getEncoded()));

            System.out.println("Connected to CAuth at " + CAUTH_HOST + ":" + CAUTH_PORT);
            System.out.println("Sending CSR to CAuth...");
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

        System.out.println("=== SP CODE VERSION: 2025-12-19-C (mTLS enforced) ===");

        // Configure protocols FIRST
        serverSocket.setEnabledProtocols(intersect(serverSocket.getSupportedProtocols(),
                new String[]{"TLSv1.3", "TLSv1.2"}));

        // Configure client-auth LAST (best-effort)
        SSLParameters serverParams = sslContext.getDefaultSSLParameters();
        serverParams.setNeedClientAuth(true);
        serverParams.setWantClientAuth(false);
        serverSocket.setSSLParameters(serverParams);

        // Some runtimes lie in getter; we still enforce on accepted sockets
        System.out.println("ServerSocket class: " + serverSocket.getClass().getName());
        System.out.println("ServerSocket.getNeedClientAuth(): " + serverSocket.getNeedClientAuth());
        System.out.println("ServerSocket SSLParameters needClientAuth: " + serverSocket.getSSLParameters().getNeedClientAuth());

        System.out.println("SP Server started on port " + SP_SERVER_PORT);
        System.out.println("Waiting for inbound connections...");

        ExecutorService executor = Executors.newCachedThreadPool();
        while (true) {
            SSLSocket clientSocket = (SSLSocket) serverSocket.accept();

            // ENFORCE mTLS ON THE SOCKET (reliable)
            SSLParameters p = clientSocket.getSSLParameters();
            p.setNeedClientAuth(true);
            p.setWantClientAuth(false);
            clientSocket.setSSLParameters(p);

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
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                 PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true)) {

                System.out.println("\n=== Inbound Connection ===");

                // Handshake will FAIL here if client does not provide a valid cert
                clientSocket.startHandshake();

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

                System.out.println("\n=== " + cn + " Connected ===");
                System.out.println("Client address: " + clientSocket.getRemoteSocketAddress());
                System.out.println("Client certificate: " + clientCerts[0].getSubjectX500Principal().getName());
                System.out.println("Certificate issuer: " + clientCerts[0].getIssuerX500Principal().getName());
                System.out.println("Cipher suite: " + clientSocket.getSession().getCipherSuite());
                System.out.println("Protocol: " + clientSocket.getSession().getProtocol());

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
                    clientSocket.close();
                    System.out.println("\n" + (cn != null ? cn : "Client") + " disconnected");
                } catch (Exception e) {
                    System.err.println("Error closing socket: " + e.getMessage());
                }
            }
        }
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
}
