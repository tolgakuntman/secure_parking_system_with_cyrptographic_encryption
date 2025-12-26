package com.example;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * Unified structured logging utility for security-focused demos.
 * 
 * Format: HH:MM:SS [MODULE][LEVEL] message
 * 
 * Levels:
 *   INFO    - Normal operational milestones
 *   AUDIT   - Identity binding, certificate fingerprints, TLS details
 *   SEC_OK  - Security success (attack detected/rejected as expected)
 *   SEC_ERR - Security rejection/failure events
 *   WARN    - Warnings (non-fatal issues)
 *   DBG     - Debug details (only when LOG_LEVEL=DBG)
 * 
 * Environment variables:
 *   SERVICE_NAME - Module tag (SP, HO, CO, CAUTH, FAKE-CAUTH)
 *   LOG_LEVEL    - INFO (default) or DBG for verbose mode
 */
public class Log {
    private static final String SERVICE;
    private static final boolean DBG_ENABLED;
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");
    
    static {
        SERVICE = System.getenv().getOrDefault("SERVICE_NAME", "CAUTH");
        String level = System.getenv().getOrDefault("LOG_LEVEL", "INFO").toUpperCase();
        DBG_ENABLED = "DBG".equals(level) || "DEBUG".equals(level);
    }
    
    // ═══════════════════════════════════════════════════════════
    // Core logging methods
    // ═══════════════════════════════════════════════════════════
    
    private static String fmt(String level, String msg) {
        String time = LocalTime.now().format(TIME_FMT);
        // Truncate message to ~140 chars for readability (unless DBG)
        String truncMsg = DBG_ENABLED ? msg : truncate(msg, 140);
        return String.format("%s [%s][%s] %s", time, SERVICE, level, truncMsg);
    }
    
    public static void info(String msg) {
        System.out.println(fmt("INFO", msg));
    }
    
    public static void audit(String msg) {
        System.out.println(fmt("AUDIT", msg));
    }
    
    public static void secOk(String msg) {
        System.out.println(fmt("SEC_OK", msg));
    }
    
    public static void secErr(String msg) {
        System.err.println(fmt("SEC_ERR", msg));
    }
    
    public static void warn(String msg) {
        System.out.println(fmt("WARN", msg));
    }
    
    public static void dbg(String msg) {
        if (DBG_ENABLED) {
            System.out.println(fmt("DBG", msg));
        }
    }
    
    // ═══════════════════════════════════════════════════════════
    // Scenario result logging (for grading output)
    // ═══════════════════════════════════════════════════════════
    
    /**
     * Log scenario success: attack was detected/rejected as expected.
     * @param scenario The scenario name (e.g., "ROGUE_CO/SELF_SIGNED")
     * @param reason Short reason for the rejection
     */
    public static void scenarioPass(String scenario, String reason) {
        System.out.println(fmt("SEC_OK", scenario + ": " + reason + " (expected)"));
    }
    
    /**
     * Log scenario failure: attack was NOT detected (unexpected).
     * @param scenario The scenario name
     * @param reason What unexpectedly succeeded
     */
    public static void scenarioFail(String scenario, String reason) {
        System.err.println(fmt("SEC_ERR", scenario + ": " + reason + " (unexpected)"));
    }
    
    // ═══════════════════════════════════════════════════════════
    // Exception summarization
    // ═══════════════════════════════════════════════════════════
    
    /**
     * Extract a short, security-informative summary from an exception.
     * Handles SSL, PKIX, security, and JSON errors specially.
     */
    public static String summarizeException(Throwable ex) {
        if (ex == null) return "null";
        
        String msg = ex.getMessage();
        String className = ex.getClass().getSimpleName();
        
        // SSLHandshakeException special handling
        if (ex instanceof javax.net.ssl.SSLHandshakeException) {
            if (msg != null) {
                if (msg.contains("bad_certificate")) return "bad_certificate";
                if (msg.contains("certificate_unknown")) return "certificate_unknown";
                if (msg.contains("Empty client certificate chain")) return "no client cert presented";
            }
            // Check cause chain for PKIX
            Throwable cause = ex.getCause();
            while (cause != null) {
                String causeName = cause.getClass().getName();
                if (causeName.contains("CertPathValidatorException") || 
                    causeName.contains("ValidatorException")) {
                    return "PKIX path validation failed";
                }
                cause = cause.getCause();
            }
            return "TLS handshake failed";
        }
        
        // SSLPeerUnverifiedException
        if (ex instanceof javax.net.ssl.SSLPeerUnverifiedException) {
            return "peer not authenticated (no client cert)";
        }
        
        // SSLException (generic)
        if (ex instanceof javax.net.ssl.SSLException) {
            if (msg != null && msg.contains("bad_certificate")) return "bad_certificate";
            return "SSL error: " + truncate(msg, 50);
        }
        
        // Certificate exceptions
        if (className.contains("CertPathValidatorException") ||
            className.contains("CertificateException")) {
            return "certificate validation failed";
        }
        
        // Security exceptions
        if (ex instanceof SecurityException) {
            return msg != null ? truncate(msg, 80) : "security violation";
        }
        
        // JSON/schema errors
        if (className.contains("JSON") || className.contains("Parse")) {
            if (msg != null && msg.contains("missing")) {
                return "schema validation failed: " + truncate(msg, 50);
            }
            return "JSON parse error";
        }
        
        // Generic: class + short message
        return className + (msg != null ? ": " + truncate(msg, 60) : "");
    }
    
    /**
     * Log exception with SEC_ERR level, using summarization.
     */
    public static void secErr(String context, Throwable ex) {
        String summary = summarizeException(ex);
        secErr(context + ": " + summary);
        if (DBG_ENABLED) {
            ex.printStackTrace();
        }
    }
    
    /**
     * Log exception with WARN level.
     */
    public static void warn(String context, Throwable ex) {
        String summary = summarizeException(ex);
        warn(context + ": " + summary);
        if (DBG_ENABLED) {
            ex.printStackTrace();
        }
    }
    
    // ═══════════════════════════════════════════════════════════
    // Certificate and TLS audit helpers
    // ═══════════════════════════════════════════════════════════
    
    /**
     * Log mTLS peer information (CN, fingerprint, TLS details).
     */
    public static void auditPeer(SSLSocket socket) {
        try {
            SSLSession session = socket.getSession();
            java.security.cert.Certificate[] certs = session.getPeerCertificates();
            if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                X509Certificate cert = (X509Certificate) certs[0];
                String cn = extractCN(cert);
                String fp = fingerprint(cert);
                String proto = session.getProtocol();
                String suite = session.getCipherSuite();
                audit("mTLS peer CN=" + cn + " fp=" + fp + " tls=" + proto + " suite=" + suite);
            }
        } catch (Exception e) {
            dbg("Could not audit peer: " + e.getMessage());
        }
    }
    
    /**
     * Log mTLS peer from certificate array.
     */
    public static void auditPeer(X509Certificate[] certs, SSLSession session) {
        try {
            if (certs != null && certs.length > 0) {
                String cn = extractCN(certs[0]);
                String fp = fingerprint(certs[0]);
                String proto = session != null ? session.getProtocol() : "?";
                String suite = session != null ? session.getCipherSuite() : "?";
                audit("mTLS peer CN=" + cn + " fp=" + fp + " tls=" + proto + " suite=" + suite);
            }
        } catch (Exception e) {
            dbg("Could not audit peer: " + e.getMessage());
        }
    }
    
    /**
     * Extract CN from certificate subject DN.
     */
    public static String extractCN(X509Certificate cert) {
        try {
            String dn = cert.getSubjectX500Principal().getName();
            LdapName ldapDN = new LdapName(dn);
            for (Rdn rdn : ldapDN.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return String.valueOf(rdn.getValue());
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return "Unknown";
    }
    
    /**
     * Compute short SHA-256 fingerprint of certificate (first 16 hex chars).
     */
    public static String fingerprint(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());
            return bytesToHex(digest).substring(0, 16);
        } catch (Exception e) {
            return "????????";
        }
    }
    
    /**
     * Full fingerprint (for DBG mode).
     */
    public static String fingerprintFull(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());
            return bytesToHex(digest);
        } catch (Exception e) {
            return "?";
        }
    }
    
    // ═══════════════════════════════════════════════════════════
    // Utility methods
    // ═══════════════════════════════════════════════════════════
    
    public static String truncate(String s, int maxLen) {
        if (s == null) return "";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen - 3) + "...";
    }
    
    public static String truncHex(String hex, int len) {
        if (hex == null) return "";
        if (hex.length() <= len) return hex;
        return hex.substring(0, len);
    }
    
    public static String truncHex(String hex) {
        return truncHex(hex, 16);
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
    
    public static boolean isDebug() {
        return DBG_ENABLED;
    }
    
    public static String getService() {
        return SERVICE;
    }
}
