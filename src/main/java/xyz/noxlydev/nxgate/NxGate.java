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
 * This class provides methods to set up license verification parameters, perform the verification,
 * and handle the responses from the verification server.
 *
 * <p>Additional hardening (opt-in via builder methods):
 * <ul>
 *   <li>{@link #withRetry(int, long)} — retry transient failures with exponential backoff.</li>
 *   <li>{@link #withTimeout(int, int)} — connect &amp; read timeouts (avoids 30s+ hangs).</li>
 *   <li>{@link #withTlsPinning(java.util.List)} — pin server cert SHA-256 fingerprints.</li>
 *   <li>{@link #withMetadataAugmentation(boolean)} — auto-append machine + jar fingerprint to metadata.</li>
 * </ul>
 *
 * <p>For offline grace cache + heartbeat, use the companion class {@link HardenedNxGate}.
 */
public class NxGate {

    private static final String DEFAULT_SERVER = "https://api.nxgate.noxlydev.xyz";
    private static final String LIB_VERSION = "nxgate/1.1.0";

    private String userId;
    private String publicRsaKey;
    private String validationServer = DEFAULT_SERVER;
    private boolean useChallenges = false;
    private boolean debug = false;

    // Hardening options (all opt-in; defaults match original library behavior)
    private int maxAttempts = 1;
    private long initialBackoffMs = 1000L;
    private int connectTimeoutMs = 10000;
    private int readTimeoutMs = 10000;
    private boolean augmentMetadata = false;
    private java.util.List<String> pinnedSha256 = null;

    /**
     * Create a new NxGate instance with your user ID.
     *
     * @param userId The user ID of the license owner's NxGate account.
     */
    public NxGate(String userId) {
        this.userId = userId;
    }

    /**
     * Create a new NxGate instance with your user ID and public RSA key.
     * Using this constructor enables the use of challenges for added security
     * (recommended for client-side verification).
     *
     * @param userId       The user ID of the license owner's NxGate account.
     * @param publicRsaKey The public RSA key of the license owner's NxGate account.
     */
    public NxGate(String userId, String publicRsaKey) {
        this.userId = userId;
        this.publicRsaKey = publicRsaKey;
        this.useChallenges = true;
    }

    /**
     * Set the public RSA key of the license owner's NxGate account.
     *
     * @param publicRsaKey The public RSA key of the license owner's NxGate account.
     * @return The NxGate instance.
     */
    public NxGate setPublicRsaKey(String publicRsaKey) {
        this.publicRsaKey = publicRsaKey;
        return this;
    }

    /**
     * Set the validation server URL.
     * Use this method to set the URL of your self-hosted NxGate server.
     * Default: NxGate cloud server
     * Example: "https://license.yourdomain.com"
     *
     * @param validationServer The URL of the validation server.
     * @return The NxGate instance.
     */
    public NxGate setValidationServer(String validationServer) {
        this.validationServer = validationServer;
        return this;
    }

    /**
     * Enable the use and verification of challenges.
     *
     * @return The NxGate instance.
     */
    public NxGate useChallenges() {
        useChallenges = true;
        return this;
    }

    /**
     * Enable debug mode to print request, response and error information to the console.
     *
     * @return The NxGate instance.
     */
    public NxGate debug() {
        debug = true;
        return this;
    }

    // ---------------- Hardening builder methods ----------------

    /**
     * Enable automatic retry of transient failures (CONNECTION_ERROR / SERVER_ERROR).
     * Backoff is exponential (factor 3): e.g. attempts=3, backoff=1000ms → waits 1s, 3s.
     *
     * @param attempts  total attempts including the first (>=1).
     * @param backoffMs initial backoff in milliseconds.
     * @return The NxGate instance.
     */
    public NxGate withRetry(int attempts, long backoffMs) {
        this.maxAttempts = Math.max(1, attempts);
        this.initialBackoffMs = Math.max(0, backoffMs);
        return this;
    }

    /**
     * Set HTTP timeouts. Default is 10s/10s. Lower values = faster failure detection.
     *
     * @param connectMs connect timeout in milliseconds.
     * @param readMs    read timeout in milliseconds.
     * @return The NxGate instance.
     */
    public NxGate withTimeout(int connectMs, int readMs) {
        this.connectTimeoutMs = connectMs;
        this.readTimeoutMs = readMs;
        return this;
    }

    /**
     * When enabled, the metadata string sent to the server is augmented with
     * {@code machineFp=...;jarFp=...} so admins can detect tampering / cloned hardware.
     * If you also pass your own metadata, both are merged with a {@code ;} separator.
     *
     * @param enable whether to enable metadata augmentation.
     * @return The NxGate instance.
     */
    public NxGate withMetadataAugmentation(boolean enable) {
        this.augmentMetadata = enable;
        return this;
    }

    /**
     * Pin one or more server certificate SHA-256 fingerprints (hex, no colons).
     * Connections whose leaf certificate doesn't match any pin are rejected as CONNECTION_ERROR.
     * Defeats network MITM attacks (e.g. Burp / mitmproxy) that bypass the license check.
     *
     * @param sha256Fingerprints list of SHA-256 hex fingerprints to pin.
     * @return The NxGate instance.
     */
    public NxGate withTlsPinning(java.util.List<String> sha256Fingerprints) {
        this.pinnedSha256 = sha256Fingerprints;
        return this;
    }

    // ---------------- Verify methods (original API preserved) ----------------

    /**
     * Verify a license key.
     *
     * @param licenseKey The license key to verify.
     * @return The validation result.
     */
    public ValidationType verify(String licenseKey) {
        return verify(licenseKey, null, null);
    }

    /**
     * Verify a license key with a specific scope.
     *
     * @param licenseKey The license key to verify.
     * @param scope      The scope to verify the license key against.
     * @return The validation result.
     */
    public ValidationType verify(String licenseKey, String scope) {
        return verify(licenseKey, scope, null);
    }

    /**
     * Verify a license key with a specific scope and metadata that should be associated
     * with the verification request.
     *
     * @param licenseKey The license key to verify.
     * @param scope      The scope to verify the license key against.
     * @param metadata   The metadata to associate with the verification request.
     * @return The validation result.
     */
    public ValidationType verify(String licenseKey, String scope, String metadata) {
        if (augmentMetadata) {
            String aug = "machineFp=" + Fingerprints.machine() + ";jarFp=" + Fingerprints.callerJar();
            metadata = (metadata == null || metadata.isEmpty()) ? aug : (metadata + ";" + aug);
        }

        long backoff = initialBackoffMs;
        ValidationType last = ValidationType.CONNECTION_ERROR;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            last = verifyOnce(licenseKey, scope, metadata);
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

    private ValidationType verifyOnce(String licenseKey, String scope, String metadata) {
        try {
            String challenge = this.useChallenges
                    ? System.currentTimeMillis() + "-" + java.util.UUID.randomUUID()
                    : null;
            JSONObject response = requestServer(buildUrl(licenseKey, scope, metadata, challenge));

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

    /**
     * Verify a license key and return a boolean indicating whether the license key is valid.
     *
     * @param licenseKey The license key to verify.
     * @return True if the license key is valid, false otherwise.
     */
    public boolean verifySimple(String licenseKey) {
        return verify(licenseKey) == ValidationType.VALID;
    }

    /**
     * Verify a license key with a specific scope and return a boolean indicating whether
     * the license key is valid.
     *
     * @param licenseKey The license key to verify.
     * @param scope      The scope to verify the license key against.
     * @return True if the license key is valid, false otherwise.
     */
    public boolean verifySimple(String licenseKey, String scope) {
        return verify(licenseKey, scope) == ValidationType.VALID;
    }

    /**
     * Verify a license key with a specific scope and metadata.
     *
     * @param licenseKey The license key to verify.
     * @param scope      The scope to verify the license key against.
     * @param metadata   The metadata to associate with the verification request.
     * @return True if the license key is valid, false otherwise.
     */
    public boolean verifySimple(String licenseKey, String scope, String metadata) {
        return verify(licenseKey, scope, metadata) == ValidationType.VALID;
    }

    // ---------------- Internals ----------------

    private String buildUrl(String licenseKey, String scope, String metadata, String challenge)
            throws UnsupportedEncodingException {
        StringBuilder qs = new StringBuilder();
        if (metadata != null) {
            qs.append("?metadata=").append(URLEncoder.encode(metadata, StandardCharsets.UTF_8.name()));
        }
        if (scope != null) {
            qs.append(qs.length() == 0 ? "?" : "&")
              .append("scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8.name()));
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

    /**
     * The result of a license verification.
     * Most of these types are the same as the ones returned by the NxGate server.
     * Check the official documentation for more information.
     * <ul>
     *   <li>CONNECTION_ERROR: The request to the NxGate server failed.</li>
     *   <li>SERVER_ERROR: The NxGate server returned an invalid response.</li>
     *   <li>FAILED_CHALLENGE: The challenge verification failed.</li>
     * </ul>
     */
    public enum ValidationType {

        VALID(true), NOT_FOUND, NOT_ACTIVE, EXPIRED, LICENSE_SCOPE_FAILED,
        IP_LIMIT_EXCEEDED, RATE_LIMIT_EXCEEDED, FAILED_CHALLENGE,
        SERVER_ERROR, CONNECTION_ERROR;

        private final boolean valid;

        ValidationType(boolean valid) { this.valid = valid; }
        ValidationType() { this(false); }

        /**
         * Returns whether the result is valid. This is true for VALID and false for all other types.
         *
         * @return Whether the result is valid.
         */
        public boolean isValid() { return valid; }
    }
}
