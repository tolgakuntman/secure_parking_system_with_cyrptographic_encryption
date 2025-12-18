package com.example;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
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
import java.net.Socket;
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

public class Main {

    // ---- Networking ----
    private static final int PORT = 8443;

    // ---- Stores (mounted by docker-compose into /app/) ----
    private static final String KEYSTORE_PATH = "./keystore.p12";
    private static final String TRUSTSTORE_PATH = "./truststore.p12";

    // Prefer env vars; fall back to defaults for coursework convenience
    private static final String KEYSTORE_PASSWORD =
            System.getenv().getOrDefault("KEYSTORE_PASSWORD", "serverpassword");
    private static final String TRUSTSTORE_PASSWORD =
            System.getenv().getOrDefault("TRUSTSTORE_PASSWORD", "trustpassword");

    // CA private key alias in keystore created by your script
    private static final String CA_KEY_ALIAS =
            System.getenv().getOrDefault("CA_KEY_ALIAS", "cauth_server");

    // Cert issuance policy (reasonable default; tweak if you want)
    private static final int LEAF_VALIDITY_DAYS =
            Integer.parseInt(System.getenv().getOrDefault("LEAF_VALIDITY_DAYS", "365"));

    // Basic input hardening
    private static final int MAX_JSON_CHARS =
            Integer.parseInt(System.getenv().getOrDefault("MAX_JSON_CHARS", "200000"));

    private static final Gson GSON = new Gson();

    private static PrivateKey caPrivateKey;
    private static X509Certificate caCertificate;
    private static X509Certificate rootCertificate; // optional (from truststore)

    public static void main(String[] args) {
        try {
            // Register BC provider for CSR parsing & X.509 building
            Security.addProvider(new BouncyCastleProvider());

            // Load CA private key + CA cert from keystore
            KeyStore keyStore = loadPkcs12(KEYSTORE_PATH, KEYSTORE_PASSWORD);
            caPrivateKey = (PrivateKey) keyStore.getKey(CA_KEY_ALIAS, KEYSTORE_PASSWORD.toCharArray());
            if (caPrivateKey == null) {
                throw new IllegalStateException("CA private key not found under alias: " + CA_KEY_ALIAS);
            }
            Certificate caCert = keyStore.getCertificate(CA_KEY_ALIAS);
            if (!(caCert instanceof X509Certificate)) {
                throw new IllegalStateException("CA certificate missing or not X509 under alias: " + CA_KEY_ALIAS);
            }
            caCertificate = (X509Certificate) caCert;

            // Load truststore (Root CA anchor)
            KeyStore trustStore = loadPkcs12(TRUSTSTORE_PATH, TRUSTSTORE_PASSWORD);
            rootCertificate = findAnyX509InTruststore(trustStore);

            // Build SSLContext with KeyManagers (server identity) but NO TrustManagers (don't validate clients)
            // This allows enrollment without requiring client certs
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());

            SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
            try (SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(PORT)) {

                // Enforce modern TLS (allow 1.2 for compatibility; prefer 1.3)
                serverSocket.setEnabledProtocols(intersect(serverSocket.getSupportedProtocols(),
                        new String[]{"TLSv1.3", "TLSv1.2"}));

                // Don't require client certs for enrollment (SP doesn't have one yet)
                serverSocket.setNeedClientAuth(false);
                serverSocket.setWantClientAuth(false);

                System.out.println("CAuth running on port " + PORT);
                System.out.println("CAuth cert subject: " + caCertificate.getSubjectX500Principal());
                System.out.println("CAuth cert issuer:  " + caCertificate.getIssuerX500Principal());

                ExecutorService pool = Executors.newCachedThreadPool();
                while (true) {
                    SSLSocket client = (SSLSocket) serverSocket.accept();
                    pool.submit(new ClientHandler(client));
                }
            }
        } catch (Exception e) {
            System.err.println("CAuth fatal error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
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

                // Force handshake so we can log peer identity (useful for scenario logs)
                socket.startHandshake();
                logPeerIdentity(socket);

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
                    case "test" -> writer.println(ok("Hello from CAuth!"));
                    case "signCSR" -> writer.println(handleSignCSR(req));
                    default -> writer.println(error("unknown_method", "Unknown method: " + method));
                }

            } catch (SSLHandshakeException hs) {
                // This is GREAT for a negative scenario: invalid client cert => handshake fails
                System.err.println("TLS handshake failed (likely client cert/trust issue): " + hs.getMessage());
            } catch (Exception e) {
                System.err.println("Client handler error: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    // -------------------- signCSR implementation --------------------

    private static String handleSignCSR(JsonObject req) {
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

            // Verify CSR signature (proves requester owns the private key)
            JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(bcCsr).setProvider("BC");
            PublicKey subjectPublicKey = jcaCsr.getPublicKey();
            if (!jcaCsr.isSignatureValid(new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                    .setProvider("BC").build(subjectPublicKey))) {
                return error("csr_invalid", "CSR signature verification failed");
            }

            // Build leaf certificate signed by this CA
            X509Certificate issued = issueLeafCertificate(bcCsr, subjectPublicKey);

            String issuedPemB64 = base64Pem(issued);

            // Return chain (CA + Root) for convenience
            JsonObject out = new JsonObject();
            out.addProperty("status", "ok");
            out.addProperty("certificate", issuedPemB64);

            // CA cert
            out.addProperty("caCert", base64Pem(caCertificate));

            // Root cert (optional, if present in truststore)
            if (rootCertificate != null) {
                out.addProperty("rootCert", base64Pem(rootCertificate));
            }

            return GSON.toJson(out);

        } catch (Exception e) {
            return error("signing_failed", "Could not sign CSR: " + e.getMessage());
        }
    }

    private static X509Certificate issueLeafCertificate(PKCS10CertificationRequest csr, PublicKey subjectPublicKey) throws Exception {
        // Subject from CSR
        var subject = csr.getSubject();

        // Issuer from CA cert
        var issuer = new X509CertificateHolder(caCertificate.getEncoded()).getSubject();

        // Validity window
        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(1, ChronoUnit.MINUTES));
        Date notAfter = Date.from(now.plus(LEAF_VALIDITY_DAYS, ChronoUnit.DAYS));

        // Serial number: random 128-bit
        BigInteger serial = new BigInteger(128, new SecureRandom()).abs();

        // Build certificate
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(subjectPublicKey.getEncoded())
        );

        // Extensions: leaf cert (NOT a CA)
        certBuilder.addExtension(Extension.basicConstraints, true, new org.bouncycastle.asn1.x509.BasicConstraints(false));

        // Key usage: typical for TLS client/server certs
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        // EKU: both client and server auth (simplifies project)
        certBuilder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));

        // Subject Key Identifier + Authority Key Identifier (nice-to-have, improves chain quality)
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectPublicKey));
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCertificate.getPublicKey()));

        // Choose a sane signature algorithm based on CA key type
        String sigAlg = pickSignatureAlgorithm(caPrivateKey);
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(caPrivateKey);

        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    private static String pickSignatureAlgorithm(PrivateKey key) {
        String alg = key.getAlgorithm();
        if ("EC".equalsIgnoreCase(alg) || "ECDSA".equalsIgnoreCase(alg)) {
            return "SHA256withECDSA";
        }
        // Default for RSA
        return "SHA256withRSA";
    }

    // -------------------- Utilities --------------------

    private static KeyStore loadPkcs12(String path, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(path)) {
            ks.load(fis, password.toCharArray());
        }
        return ks;
    }

    private static X509Certificate findAnyX509InTruststore(KeyStore trustStore) {
        try {
            var aliases = trustStore.aliases();
            while (aliases.hasMoreElements()) {
                String a = aliases.nextElement();
                Certificate c = trustStore.getCertificate(a);
                if (c instanceof X509Certificate) return (X509Certificate) c;
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static void logPeerIdentity(SSLSocket socket) {
        try {
            SSLSession session = socket.getSession();
            System.out.println("TLS: " + session.getProtocol() + " / " + session.getCipherSuite());
            Certificate[] peer = session.getPeerCertificates();
            if (peer.length > 0 && peer[0] instanceof X509Certificate x) {
                System.out.println("Peer subject: " + x.getSubjectX500Principal());
                System.out.println("Peer issuer:  " + x.getIssuerX500Principal());
            }
        } catch (Exception e) {
            System.out.println("Could not log peer identity: " + e.getMessage());
        }
    }

    private static String readSingleJsonMessage(BufferedReader reader) throws IOException {
        StringBuilder sb = new StringBuilder();
        String line;

        while ((line = reader.readLine()) != null) {
            sb.append(line);
            if (sb.length() > MAX_JSON_CHARS) {
                return null; // basic DoS protection
            }
            // attempt parse when we have something
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
        // simple intersection that preserves "desired" order
        java.util.List<String> sup = java.util.Arrays.asList(supported);
        java.util.List<String> out = new java.util.ArrayList<>();
        for (String d : desired) if (sup.contains(d)) out.add(d);
        return out.toArray(new String[0]);
    }
}
