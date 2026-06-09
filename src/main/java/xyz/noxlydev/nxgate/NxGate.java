package xyz.noxlydev.nxgate;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * A Java wrapper for communicating with NxGate - supports cloud and self-hosted setups.
 */
public class NxGate {

    private static final String DEFAULT_SERVER = "https://api.nxgate.noxlydev.xyz";
    private static final String LIB_VERSION = "nxgate/1.1.0";

    private String userId;
    private String publicRsaKey;
    private String validationServer = DEFAULT_SERVER;
    private boolean useChallenges = false;
    private boolean debug = false;

    private int maxAttempts = 1;
    private long initialBackoffMs = 1000L;
    private int connectTimeoutMs = 10000;
    private int readTimeoutMs = 10000;
    private boolean augmentMetadata = false;
    private java.util.List<String> pinnedSha256 = null;

    public NxGate(String userId) {
        this.userId = userId;
    }

    public NxGate(String userId, String publicRsaKey) {
        this.userId = userId;
        this.publicRsaKey = publicRsaKey;
        this.useChallenges = true;
    }

    public NxGate setPublicRsaKey(String publicRsaKey) {
        this.publicRsaKey = publicRsaKey;
        return this;
    }

    public NxGate setValidationServer(String validationServer) {
        this.validationServer = validationServer;
        return this;
    }

    public NxGate useChallenges() {
        useChallenges = true;
        return this;
    }

    public NxGate debug() {
        debug = true;
        return this;
    }

    public NxGate withRetry(int attempts, long backoffMs) {
        this.maxAttempts = Math.max(1, attempts);
        this.initialBackoffMs = Math.max(0, backoffMs);
        return this;
    }

    public NxGate withTimeout(int connectMs, int readMs) {
        this.connectTimeoutMs = connectMs;
        this.readTimeoutMs = readMs;
        return this;
    }

    public NxGate withMetadataAugmentation(boolean enable) {
        this.augmentMetadata = enable;
        return this;
    }

    public NxGate withTlsPinning(java.util.List<String> sha256Fingerprints) {
        this.pinnedSha256 = sha256Fingerprints;
        return this;
    }

    // ---- verify overloads ----

    public ValidationType verify(String licenseKey) {
        return verify(licenseKey, null, null, null);
    }

    public ValidationType verify(String licenseKey, String scope) {
        return verify(licenseKey, scope, null, null);
    }

    public ValidationType verify(String licenseKey, String scope, String metadata) {
        return verify(licenseKey, scope, metadata, null);
    }

    /**
     * Verify a license key with scope, metadata, and product slug.
     *
     * @param licenseKey  The license key to verify.
     * @param scope       The scope to verify against (nullable).
     * @param metadata    Metadata to associate with the request (nullable).
     * @param productSlug The product slug this license should be restricted to (nullable).
     *                    If the license is not assigned to this product, server returns PRODUCT_MISMATCH.
     * @return The validation result.
     */
    public ValidationType verify(String licenseKey, String scope, String metadata, String productSlug) {
        if (augmentMetadata) {
            String aug = "machineFp=" + Fingerprints.machine() + ";jarFp=" + Fingerprints.callerJar();
            metadata = (metadata == null || metadata.isEmpty()) ? aug : (metadata + ";" + aug);
        }

        long backoff = initialBackoffMs;
        ValidationType last = ValidationType.CONNECTION_ERROR;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            last = verifyOnce(licenseKey, scope, metadata, productSlug);
            if (last != ValidationType.CONNECTION_ERROR && last != ValidationType.SERVER_ERROR) {
                return last;
            }
            if (attempt < maxAttempts) {
                try { Thread.sleep(backoff); } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return last;
                }
                backoff *= 3;
            }
        }
        return last;
    }

    private ValidationType verifyOnce(String licenseKey, String scope, String metadata, String productSlug) {
        try {
            String challenge = this.useChallenges
                    ? System.currentTimeMillis() + "-" + java.util.UUID.randomUUID()
                    : null;
            JSONObject response = requestServer(buildUrl(licenseKey, scope, metadata, challenge, productSlug));

            if (response.has("error") || !response.has("result")) {
                if (debug) System.out.println("[NxGate] Error: " + response.optString("error", "no result"));
                return ValidationType.SERVER_ERROR;
            }

            if (response.has("valid") && !response.getBoolean("valid")) {
                ValidationType result = ValidationType.valueOf(response.getString("result"));
                return result == ValidationType.VALID ? ValidationType.SERVER_ERROR : result;
            }

            if (useChallenges) {
                if (!response.has("signedChallenge")) {
                    if (debug) System.out.println("[NxGate] No signed challenge in response");
                    return ValidationType.FAILED_CHALLENGE;
                }
                if (!verifyChallenge(challenge, response.getString("signedChallenge"))) {
                    if (debug) System.out.println("[NxGate] Challenge verification failed");
                    return ValidationType.FAILED_CHALLENGE;
                }
            }

            return ValidationType.valueOf(response.getString("result"));
        } catch (IOException e) {
            if (debug) e.printStackTrace();
            return ValidationType.CONNECTION_ERROR;
        }
    }

    // ---- verifySimple overloads ----

    public boolean verifySimple(String licenseKey) {
        return verify(licenseKey) == ValidationType.VALID;
    }

    public boolean verifySimple(String licenseKey, String scope) {
        return verify(licenseKey, scope) == ValidationType.VALID;
    }

    public boolean verifySimple(String licenseKey, String scope, String metadata) {
        return verify(licenseKey, scope, metadata) == ValidationType.VALID;
    }

    /**
     * Verify a license key and return true if VALID.
     *
     * @param licenseKey  The license key to verify.
     * @param scope       The scope to verify against (nullable).
     * @param metadata    Metadata to associate with the request (nullable).
     * @param productSlug The product slug to restrict verification to (nullable).
     * @return True if the license key is valid.
     */
    public boolean verifySimple(String licenseKey, String scope, String metadata, String productSlug) {
        return verify(licenseKey, scope, metadata, productSlug) == ValidationType.VALID;
    }

    // ---- Internals ----

    private String buildUrl(String licenseKey, String scope, String metadata, String challenge, String productSlug)
            throws UnsupportedEncodingException {
        StringBuilder qs = new StringBuilder();
        if (metadata != null) {
            qs.append("?metadata=").append(URLEncoder.encode(metadata, StandardCharsets.UTF_8.name()));
        }
        if (scope != null) {
            qs.append(qs.length() == 0 ? "?" : "&")
              .append("scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8.name()));
        }
        if (productSlug != null) {
            qs.append(qs.length() == 0 ? "?" : "&")
              .append("productSlug=").append(URLEncoder.encode(productSlug, StandardCharsets.UTF_8.name()));
        }
        if (useChallenges && challenge != null) {
            qs.append(qs.length() == 0 ? "?" : "&")
              .append("challenge=").append(URLEncoder.encode(challenge, StandardCharsets.UTF_8.name()));
        }
        return validationServer + "/license/" + userId + "/" + licenseKey + "/verify" + qs;
    }

    private JSONObject requestServer(String urlStr) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.setRequestProperty("User-Agent", LIB_VERSION);
        con.setConnectTimeout(connectTimeoutMs);
        con.setReadTimeout(readTimeoutMs);

        if (pinnedSha256 != null && !pinnedSha256.isEmpty() && con instanceof javax.net.ssl.HttpsURLConnection) {
            try {
                javax.net.ssl.HttpsURLConnection https = (javax.net.ssl.HttpsURLConnection) con;
                https.connect();
                java.security.cert.Certificate[] certs = https.getServerCertificates();
                if (certs.length == 0) throw new IOException("no server certs");
                byte[] sha = java.security.MessageDigest.getInstance("SHA-256").digest(certs[0].getEncoded());
                String hex = toHex(sha);
                boolean ok = false;
                for (String pin : pinnedSha256) {
                    if (pin.replace(":", "").equalsIgnoreCase(hex)) { ok = true; break; }
                }
                if (!ok) {
                    if (debug) System.out.println("[NxGate] TLS pin mismatch. Got " + hex);
                    con.disconnect();
                    throw new IOException("TLS pin mismatch");
                }
            } catch (java.security.GeneralSecurityException gse) {
                con.disconnect();
                throw new IOException(gse);
            }
        }

        int responseCode = con.getResponseCode();
        if (debug) {
            System.out.println("[NxGate] Sending request to URL : " + urlStr);
            System.out.println("[NxGate] Response Code : " + responseCode);
        }

        try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) sb.append(line);
            String body = sb.toString();
            if (debug) System.out.println("[NxGate] Response: " + body);
            return new JSONObject(body);
        }
    }

    private boolean verifyChallenge(String challenge, String signedChallengeBase64) {
        try {
            String pemHeader = "-----BEGIN PUBLIC KEY-----";
            String pemFooter = "-----END PUBLIC KEY-----";
            String base64PublicKey = this.publicRsaKey
                    .replace(pemHeader, "").replace(pemFooter, "").replaceAll("\\s+", "");
            byte[] publicKeyBytes = Base64.getDecoder().decode(base64PublicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            byte[] signatureBytes = Base64.getDecoder().decode(signedChallengeBase64);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(challenge.getBytes(StandardCharsets.UTF_8));
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            if (debug) e.printStackTrace();
            return false;
        }
    }

    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public enum ValidationType {

        VALID(true), NOT_FOUND, NOT_ACTIVE, EXPIRED, LICENSE_SCOPE_FAILED,
        IP_LIMIT_EXCEEDED, RATE_LIMIT_EXCEEDED, PRODUCT_MISMATCH,
        FAILED_CHALLENGE, SERVER_ERROR, CONNECTION_ERROR;

        private final boolean valid;

        ValidationType(boolean valid) { this.valid = valid; }
        ValidationType() { this(false); }

        public boolean isValid() { return valid; }
    }
}
