package com.example;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * FAKE-CAUTH: Rogue Intermediate CA for CAuth-1 Negative Security Test
 * 
 * This service mimics the legitimate CAuth enrollment API but uses a self-signed
 * "rogue" intermediate CA certificate that is NOT signed by the trusted Root CA.
 * 
 * Purpose: Demonstrate that the system properly rejects certificates issued by
 * untrusted CAs, even if the API interface is identical to the real CAuth.
 * 
 * Security Test: When CO enrolls with fake-cauth (NEG_TEST_MODE=FAKE_CAUTH):
 * 1. CO receives a valid certificate signed by this fake CA
 * 2. CO stores the certificate in its keystore (normal enrollment behavior)
 * 3. CO attempts mTLS connection to SP/HO using the fake certificate
 * 4. EXPECTED OUTCOME: Connection fails with PKIX path validation error
 *    because SP/HO truststores only contain the real Root CA, not this rogue CA
 * 
 * Implementation:
 * - Generates self-signed CA keypair at startup (ephemeral, not persisted)
 * - Accepts signCSR requests identical to real CAuth
 * - Returns certificate chain: [leaf, fake-ca-intermediate] (no Root CA)
 * - Uses same JSON field names as real CAuth for API compatibility
 * - Runs on same port (8443) to allow transparent redirection via CAUTH_HOST
 */
public class Main {

    private static final int PORT = 8443;
    private static final int LEAF_VALIDITY_DAYS = 365;
    private static final int MAX_JSON_CHARS = 200000;
    private static final Gson GSON = new Gson();

    private static PrivateKey fakeCaPrivateKey;
    private static X509Certificate fakeCaCertificate;

    public static void main(String[] args) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            System.out.println("═══════════════════════════════════════════════════════════════");
            System.out.println("  FAKE-CAUTH: Rogue Intermediate CA (CAuth-1 Security Test)");
            System.out.println("═══════════════════════════════════════════════════════════════");
            System.out.println("WARNING: This is a ROGUE CA for negative security testing!");
            System.out.println("         Certificates issued by this CA are NOT trusted.");
            System.out.println("         They WILL be rejected by legitimate services.");
            System.out.println("═══════════════════════════════════════════════════════════════\n");

            // Generate ephemeral self-signed "rogue" CA certificate
            System.out.println("[FAKE-CAUTH] Generating self-signed rogue intermediate CA...");
            generateSelfSignedCA();
            System.out.println("✓ Rogue CA generated");
            System.out.println("  Subject: " + fakeCaCertificate.getSubjectX500Principal());
            System.out.println("  Issuer:  " + fakeCaCertificate.getIssuerX500Principal());
            System.out.println("  Serial:  " + fakeCaCertificate.getSerialNumber());
            System.out.println("  NOTE: This CA is self-signed and NOT chained to Root CA!");

            // Create minimal TLS context without client auth requirements
            // (we don't validate clients during enrollment)
            KeyStore fakeKeyStore = KeyStore.getInstance("PKCS12");
            fakeKeyStore.load(null, null);
            fakeKeyStore.setKeyEntry(
                "fake-ca",
                fakeCaPrivateKey,
                "fake".toCharArray(),
                new Certificate[]{fakeCaCertificate}
            );

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(fakeKeyStore, "fake".toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());

            SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
            try (SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(PORT)) {

                serverSocket.setEnabledProtocols(intersect(serverSocket.getSupportedProtocols(),
                        new String[]{"TLSv1.3", "TLSv1.2"}));

                // No client auth required for enrollment
                serverSocket.setNeedClientAuth(false);
                serverSocket.setWantClientAuth(false);

                System.out.println("\n[FAKE-CAUTH] Listening on port " + PORT);
                System.out.println("[FAKE-CAUTH] Ready to issue UNTRUSTED certificates\n");

                ExecutorService pool = Executors.newCachedThreadPool();
                while (true) {
                    SSLSocket client = (SSLSocket) serverSocket.accept();
                    pool.submit(new ClientHandler(client));
                }
            }
        } catch (Exception e) {
            System.err.println("[FAKE-CAUTH] Fatal error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Generate self-signed "rogue" CA certificate.
     * This CA is NOT signed by the legitimate Root CA and will not be trusted
     * by any service in the system.
     */
    private static void generateSelfSignedCA() throws Exception {
        // Generate keypair for fake CA
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        KeyPair caKeyPair = keyGen.generateKeyPair();
        fakeCaPrivateKey = caKeyPair.getPrivate();

        // Create self-signed certificate with CA=true
        X500Name subject = new X500Name("CN=ROGUE-CA-DO-NOT-TRUST, O=Fake Authority, C=XX");
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
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(caKeyPair.getPublic().getEncoded())
        );

        // Mark as CA certificate
        certBuilder.addExtension(Extension.basicConstraints, true, 
            new org.bouncycastle.asn1.x509.BasicConstraints(true));

        // CA key usage
        certBuilder.addExtension(Extension.keyUsage, true,
            new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        // Sign with own private key (self-signed)
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(fakeCaPrivateKey);

        X509CertificateHolder holder = certBuilder.build(signer);
        fakeCaCertificate = new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(holder);
    }

    private static class ClientHandler implements Runnable {
        private final SSLSocket clientSocket;

        ClientHandler(SSLSocket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            try (SSLSocket socket = clientSocket;
                 BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                 PrintWriter writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true)) {

                socket.startHandshake();

                String json = readSingleJsonMessage(reader);
                if (json == null) {
                    writer.println(error("empty_request", "No JSON received"));
                    return;
                }

                JsonObject req;
                try {
                    req = GSON.fromJson(json, JsonObject.class);
                } catch (JsonSyntaxException ex) {
                    writer.println(error("bad_json", "Invalid JSON"));
                    return;
                }

                String method = req.has("method") ? req.get("method").getAsString() : "";
                switch (method) {
                    case "test" -> writer.println(ok("Hello from FAKE-CAUTH (rogue CA)"));
                    case "signCSR" -> writer.println(handleSignCSR(req));
                    default -> writer.println(error("unknown_method", "Unknown method: " + method));
                }

            } catch (Exception e) {
                System.err.println("[FAKE-CAUTH] Client handler error: " + e.getMessage());
            }
        }
    }

    /**
     * Handle signCSR request - identical API to real CAuth but signs with rogue CA
     */
    private static String handleSignCSR(JsonObject req) {
        System.out.println("\n[FAKE-CAUTH] ⚠ Received CSR signing request");

        if (!req.has("csr")) {
            return error("missing_field", "Missing 'csr' field");
        }

        String csrB64 = req.get("csr").getAsString();
        byte[] csrDer;
        try {
            csrDer = Base64.getDecoder().decode(csrB64);
        } catch (IllegalArgumentException e) {
            return error("bad_base64", "CSR is not valid Base64");
        }

        try {
            PKCS10CertificationRequest bcCsr = new PKCS10CertificationRequest(csrDer);

            // Verify CSR signature
            JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(bcCsr).setProvider("BC");
            PublicKey subjectPublicKey = jcaCsr.getPublicKey();
            if (!jcaCsr.isSignatureValid(new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                    .setProvider("BC").build(subjectPublicKey))) {
                return error("csr_invalid", "CSR signature verification failed");
            }

            System.out.println("[FAKE-CAUTH] CSR signature valid");
            System.out.println("[FAKE-CAUTH] Subject: " + bcCsr.getSubject());

            // Issue certificate signed by ROGUE CA (not trusted!)
            X509Certificate issuedCert = issueLeafCertificate(bcCsr, subjectPublicKey);

            System.out.println("[FAKE-CAUTH] ✗ Issued UNTRUSTED certificate");
            System.out.println("[FAKE-CAUTH]   Issued cert subject: " + issuedCert.getSubjectX500Principal());
            System.out.println("[FAKE-CAUTH]   Issued cert issuer:  " + issuedCert.getIssuerX500Principal());
            System.out.println("[FAKE-CAUTH]   Serial: " + issuedCert.getSerialNumber());
            System.out.println("[FAKE-CAUTH] NOTE: This cert chain does NOT terminate at Root CA!");
            System.out.println("[FAKE-CAUTH] NOTE: All mTLS connections will FAIL with trust validation error!\n");

            // Return response with same field names as real CAuth
            JsonObject out = new JsonObject();
            out.addProperty("status", "ok");
            out.addProperty("certificate", base64Pem(issuedCert));
            out.addProperty("caCert", base64Pem(fakeCaCertificate));
            // Deliberately DO NOT include rootCert - we have no legitimate root

            return GSON.toJson(out);

        } catch (Exception e) {
            return error("signing_failed", "Could not sign CSR: " + e.getMessage());
        }
    }

    /**
     * Issue leaf certificate signed by the ROGUE CA
     */
    private static X509Certificate issueLeafCertificate(PKCS10CertificationRequest csr, PublicKey subjectPublicKey) throws Exception {
        var subject = csr.getSubject();
        var issuer = new X509CertificateHolder(fakeCaCertificate.getEncoded()).getSubject();

        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(1, ChronoUnit.MINUTES));
        Date notAfter = Date.from(now.plus(LEAF_VALIDITY_DAYS, ChronoUnit.DAYS));

        BigInteger serial = new BigInteger(128, new SecureRandom()).abs();

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
            issuer,
            serial,
            notBefore,
            notAfter,
            subject,
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(subjectPublicKey.getEncoded())
        );

        // Leaf certificate extensions (NOT a CA)
        certBuilder.addExtension(Extension.basicConstraints, true, 
            new org.bouncycastle.asn1.x509.BasicConstraints(false));

        certBuilder.addExtension(Extension.keyUsage, true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        certBuilder.addExtension(Extension.extendedKeyUsage, false,
            new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, 
            extUtils.createSubjectKeyIdentifier(subjectPublicKey));
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, 
            extUtils.createAuthorityKeyIdentifier(fakeCaCertificate.getPublicKey()));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(fakeCaPrivateKey);

        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(holder);
    }

    // -------------------- Utilities --------------------

    private static String readSingleJsonMessage(BufferedReader reader) throws IOException {
        StringBuilder sb = new StringBuilder();
        String line;

        while ((line = reader.readLine()) != null) {
            sb.append(line);
            if (sb.length() > MAX_JSON_CHARS) {
                return null;
            }
            try {
                GSON.fromJson(sb.toString(), JsonObject.class);
                return sb.toString();
            } catch (JsonSyntaxException ignore) {
                // keep reading
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static String base64Pem(X509Certificate cert) throws IOException, java.security.cert.CertificateEncodingException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(cert);
        }
        String pem = sw.toString();
        return Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8));
    }

    private static String ok(String message) {
        JsonObject out = new JsonObject();
        out.addProperty("status", "ok");
        out.addProperty("message", message);
        return GSON.toJson(out);
    }

    private static String error(String code, String message) {
        JsonObject out = new JsonObject();
        out.addProperty("status", "error");
        out.addProperty("code", code);
        out.addProperty("message", message);
        return GSON.toJson(out);
    }

    private static String[] intersect(String[] supported, String[] desired) {
        java.util.List<String> sup = java.util.Arrays.asList(supported);
        java.util.List<String> out = new java.util.ArrayList<>();
        for (String d : desired) if (sup.contains(d)) out.add(d);
        return out.toArray(new String[0]);
    }
}
