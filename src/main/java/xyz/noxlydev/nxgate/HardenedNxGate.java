package xyz.noxlydev.nxgate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.logging.Logger;

/**
 * High-level wrapper around {@link NxGate} that adds:
 *
 *   1. Automatic retry with exponential backoff (configurable).
 *   2. HMAC-signed offline cache file, bound to machine + jar fingerprint.
 *      Plugin keeps running for {@code gracePeriodMs} after a successful verify
 *      even if the NxGate API becomes unreachable.
 *   3. Background heartbeat that re-verifies periodically. If the server
 *      returns a definitive negative answer (EXPIRED / NOT_ACTIVE / NOT_FOUND
 *      / LICENSE_SCOPE_FAILED), the {@code onInvalid} callback fires so the
 *      plugin can disable itself in real time.
 *   4. Tamper resistance:
 *      - cache HMAC keyed with userId + scope + machineFp + jarFp,
 *        so cache can't be moved across machines or used with a re-packaged JAR.
 *      - constant-time comparison (timing attack resistant).
 *      - jar fingerprint sent as request metadata for server-side detection.
 *
 * Thread-safe. Designed for "fail-closed-after-grace" semantics — i.e. the
 * plugin runs while online OR within the grace window, and refuses to start
 * once the cache is stale and the server is still unreachable.
 *
 * <pre>{@code
 * HardenedNxGate gate = new HardenedNxGate.Builder()
 *     .userId("16777218")
 *     .publicKey(PUBLIC_KEY_PEM)
 *     .scope("MyPlugin")
 *     .productSlug("my-plugin-slug")
 *     .serverUrl("https://api.nxgate.noxlydev.xyz")
 *     .cacheDir(getDataFolder())
 *     .gracePeriod(24, TimeUnit.HOURS)
 *     .heartbeat(6, TimeUnit.HOURS)
 *     .retry(3, 1000)
 *     .logger(getLogger())
 *     .onRevoked(reason -> getServer().getPluginManager().disablePlugin(this))
 *     .build();
 *
 * if (!gate.verifyBlocking(licenseKey)) {
 *     getServer().getPluginManager().disablePlugin(this);
 *     return;
 * }
 * gate.startHeartbeat(() -> licenseKey);
 * }</pre>
 */
public class HardenedNxGate {

    private final String userId;
    private final String publicKey;
    private final String scope;
    private final String productSlug;
    private final String serverUrl;
    private final File cacheFile;
    private final File hwidCacheFile;
    private final long gracePeriodMs;
    private final long heartbeatMs;
    private final int retries;
    private final long backoffMs;
    private final Logger logger;
    private final Consumer<String> onRevoked;
    private final java.util.List<String> tlsPins;
    private final boolean debug;

    private volatile boolean licenseValid = false;
    private volatile NxGate.ValidationType lastResult;
    private ScheduledExecutorService heartbeat;

    private HardenedNxGate(Builder b) {
        if (b.userId == null) throw new IllegalArgumentException("userId required");
        this.userId = b.userId;
        this.publicKey = b.publicKey;
        this.scope = b.scope;
        this.productSlug = b.productSlug;
        this.serverUrl = b.serverUrl;
        this.cacheFile = new File(b.cacheDir, ".nxgate-cache");
        this.hwidCacheFile = new File(b.cacheDir, ".nxgate-hwid-cache");
        this.gracePeriodMs = b.gracePeriodMs;
        this.heartbeatMs = b.heartbeatMs;
        this.retries = b.retries;
        this.backoffMs = b.backoffMs;
        this.logger = b.logger != null ? b.logger : Logger.getLogger("NxGate");
        this.onRevoked = b.onRevoked;
        this.tlsPins = b.tlsPins;
        this.debug = b.debug;
    }

    public boolean isLicenseValid() { return licenseValid; }
    public NxGate.ValidationType getLastResult() { return lastResult; }

    /**
     * Verify synchronously. Returns true if VALID, or if a previous successful
     * verify is still within the grace window when the server is unreachable.
     */
    public boolean verifyBlocking(String licenseKey) {
        if (licenseKey == null || licenseKey.trim().isEmpty()) {
            licenseValid = false;
            lastResult = NxGate.ValidationType.NOT_FOUND;
            logger.severe("[NxGate] No license key configured.");
            return false;
        }

        NxGate gate = buildGate();

        NxGate.ValidationType result = gate.verify(licenseKey, scope, null, productSlug);
        lastResult = result;

        if (result == NxGate.ValidationType.VALID) {
            writeCache(System.currentTimeMillis());
            licenseValid = true;
            logger.info("[NxGate] License is VALID. Verified online.");
            return true;
        }

        if (result == NxGate.ValidationType.CONNECTION_ERROR || result == NxGate.ValidationType.SERVER_ERROR) {
            Long lastValidAt = readCache();
            if (lastValidAt != null) {
                long age = System.currentTimeMillis() - lastValidAt;
                if (age < gracePeriodMs) {
                    long remH = (gracePeriodMs - age) / TimeUnit.HOURS.toMillis(1);
                    logger.warning("[NxGate] " + result + " — running in offline grace period (~" + remH + "h remaining).");
                    licenseValid = true;
                    return true;
                }
                logger.severe("[NxGate] Offline grace expired. Online re-verification required.");
            } else {
                logger.severe("[NxGate] No valid offline cache. Cannot start.");
            }
        } else {
            logger.severe("[NxGate] License INVALID: " + result);
            invalidateCache();
        }

        licenseValid = false;
        return false;
    }

    /**
     * Perform synchronous hardware-bound cryptographic handshake.
     * Returns a valid {@link HandshakeResult} containing the derived AES key if successful,
     * or uses cached keys if running within the grace window during server outage.
     */
    public HandshakeResult handshakeBlocking(String licenseKey) {
        if (licenseKey == null || licenseKey.trim().isEmpty()) {
            licenseValid = false;
            lastResult = NxGate.ValidationType.NOT_FOUND;
            logger.severe("[NxGate] No license key configured for handshake.");
            return HandshakeResult.failure(NxGate.ValidationType.NOT_FOUND, "Missing license key");
        }

        NxGate gate = buildGate();
        HandshakeResult result = gate.handshake(licenseKey, productSlug, scope);
        lastResult = result.getStatus();

        if (result.isValid()) {
            writeHwidCache(result);
            licenseValid = true;
            logger.info("[NxGate] Handshake SUCCESS. Cryptographic core bound to HWID.");
            return result;
        }

        if (result.getStatus() == NxGate.ValidationType.CONNECTION_ERROR || result.getStatus() == NxGate.ValidationType.SERVER_ERROR) {
            HandshakeResult cached = readHwidCache();
            if (cached != null) {
                logger.warning("[NxGate] " + result.getStatus() + " — running handshake in offline grace period.");
                licenseValid = true;
                return cached;
            } else {
                logger.severe("[NxGate] No valid offline cryptographic cache. Cannot start core.");
            }
        } else {
            logger.severe("[NxGate] Handshake INVALID: " + result.getStatus() + " (" + result.getMessage() + ")");
            invalidateHwidCache();
        }

        licenseValid = false;
        return result;
    }

    /** Begin background re-verification at the configured interval. Idempotent. */
    public synchronized void startHeartbeat(Supplier<String> licenseKeySupplier) {
        if (heartbeat != null) return;
        heartbeat = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "NxGate-Heartbeat");
            t.setDaemon(true);
            return t;
        });
        heartbeat.scheduleAtFixedRate(() -> {
            try {
                NxGate gate = buildGate();

                NxGate.ValidationType r = gate.verify(licenseKeySupplier.get(), scope, null, productSlug);
                lastResult = r;
                if (r == NxGate.ValidationType.VALID) {
                    writeCache(System.currentTimeMillis());
                    licenseValid = true;
                } else if (r != NxGate.ValidationType.CONNECTION_ERROR && r != NxGate.ValidationType.SERVER_ERROR) {
                    licenseValid = false;
                    invalidateCache();
                    if (onRevoked != null) onRevoked.accept(r.toString());
                }
                // transient errors: keep current state and rely on cache.
            } catch (Throwable t) {
                logger.warning("[NxGate] Heartbeat error: " + t.getMessage());
            }
        }, heartbeatMs, heartbeatMs, TimeUnit.MILLISECONDS);
    }

    public synchronized void shutdown() {
        if (heartbeat != null) { heartbeat.shutdownNow(); heartbeat = null; }
    }

    // ---- HMAC-signed, machine-bound cache ----

    private NxGate buildGate() {
        NxGate g = new NxGate(userId, publicKey)
                .setValidationServer(serverUrl)
                .withRetry(retries, backoffMs)
                .withMetadataAugmentation(true);
        if (tlsPins != null && !tlsPins.isEmpty()) g.withTlsPinning(tlsPins);
        if (debug) g.debug();
        return g;
    }

    private void writeCache(long timestamp) {
        try {
            String fp = Fingerprints.machine();
            String jar = Fingerprints.callerJar();
            String payload = timestamp + "|" + fp + "|" + jar;
            String mac = hmacHex(payload);
            String content = payload + "|" + mac;
            cacheFile.getParentFile().mkdirs();
            Files.write(cacheFile.toPath(), content.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (Exception ignored) {}
    }

    private Long readCache() {
        try {
            if (!cacheFile.exists()) return null;
            if (cacheFile.length() > 512) {
                logger.warning("[NxGate] Cache file unexpectedly large — ignoring.");
                return null;
            }
            String content = new String(Files.readAllBytes(cacheFile.toPath()), StandardCharsets.UTF_8).trim();
            String[] p = content.split("\\|");
            if (p.length != 4) return null;
            long ts = Long.parseLong(p[0]);
            String fp = p[1], jar = p[2], mac = p[3];
            if (!Fingerprints.machine().equals(fp)) {
                logger.warning("[NxGate] Cache machine fingerprint mismatch — ignoring.");
                return null;
            }
            if (!Fingerprints.callerJar().equals(jar)) {
                logger.warning("[NxGate] Cache jar fingerprint mismatch — ignoring.");
                return null;
            }
            if (!constEq(hmacHex(ts + "|" + fp + "|" + jar), mac)) {
                logger.warning("[NxGate] Cache HMAC invalid — tampering suspected.");
                return null;
            }
            return ts;
        } catch (Exception e) {
            return null;
        }
    }

    private void invalidateCache() {
        try { if (cacheFile.exists()) cacheFile.delete(); } catch (Exception ignored) {}
    }

    private void writeHwidCache(HandshakeResult res) {
        if (res.getRealAesKey() == null || res.getIv() == null) return;
        try {
            long ts = System.currentTimeMillis();
            String hwid = HWIDProvider.getHWID();
            String jar = Fingerprints.callerJar();
            String keyHex = NxGate.toHex(res.getRealAesKey());
            String ivHex = NxGate.toHex(res.getIv());
            String sessionToken = res.getSessionToken() != null ? res.getSessionToken() : "";
            String payload = ts + "|" + hwid + "|" + jar + "|" + keyHex + "|" + ivHex + "|" + sessionToken;
            String mac = hmacHwidHex(payload);
            String content = payload + "|" + mac;
            hwidCacheFile.getParentFile().mkdirs();
            Files.write(hwidCacheFile.toPath(), content.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (Exception ignored) {}
    }

    private HandshakeResult readHwidCache() {
        try {
            if (!hwidCacheFile.exists()) return null;
            if (hwidCacheFile.length() > 2048) {
                logger.warning("[NxGate] HWID cache file unexpectedly large — ignoring.");
                return null;
            }
            String content = new String(Files.readAllBytes(hwidCacheFile.toPath()), StandardCharsets.UTF_8).trim();
            String[] p = content.split("\\|");
            if (p.length != 7) return null;
            long ts = Long.parseLong(p[0]);
            String hwid = p[1], jar = p[2], keyHex = p[3], ivHex = p[4], sessionToken = p[5], mac = p[6];

            if (!HWIDProvider.getHWID().equals(hwid)) {
                logger.warning("[NxGate] HWID cache machine ID mismatch — ignoring.");
                return null;
            }
            if (!Fingerprints.callerJar().equals(jar)) {
                logger.warning("[NxGate] HWID cache jar mismatch — ignoring.");
                return null;
            }
            String expectedPayload = ts + "|" + hwid + "|" + jar + "|" + keyHex + "|" + ivHex + "|" + sessionToken;
            if (!constEq(hmacHwidHex(expectedPayload), mac)) {
                logger.warning("[NxGate] HWID cache HMAC invalid — tampering suspected.");
                return null;
            }
            long age = System.currentTimeMillis() - ts;
            if (age >= gracePeriodMs) {
                logger.severe("[NxGate] HWID cache expired.");
                return null;
            }

            byte[] realKey = NxGate.fromHex(keyHex);
            byte[] iv = NxGate.fromHex(ivHex);
            return new HandshakeResult(
                true,
                NxGate.ValidationType.VALID,
                "Loaded from valid offline HWID cache",
                null,
                null,
                (int) TimeUnit.MILLISECONDS.toHours(gracePeriodMs - age),
                realKey,
                iv,
                sessionToken,
                true
            );
        } catch (Exception e) {
            return null;
        }
    }

    private void invalidateHwidCache() {
        try { if (hwidCacheFile.exists()) hwidCacheFile.delete(); } catch (Exception ignored) {}
    }

    private String hmacHwidHex(String data) throws Exception {
        String secret = userId + "|" + scope + "|" + (productSlug != null ? productSlug : "") + "|" + HWIDProvider.getHWID() + "|" + Fingerprints.callerJar() + "|nxgate-hwid-cache-v2";
        byte[] key = Fingerprints.sha256(secret.getBytes(StandardCharsets.UTF_8));
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(key, "HmacSHA256"));
        return NxGate.toHex(m.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    private String hmacHex(String data) throws Exception {
        String secret = userId + "|" + scope + "|" + (productSlug != null ? productSlug : "") + "|" + Fingerprints.machine() + "|" + Fingerprints.callerJar() + "|nxgate-cache-v1";
        byte[] key = Fingerprints.sha256(secret.getBytes(StandardCharsets.UTF_8));
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(key, "HmacSHA256"));
        return NxGate.toHex(m.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    private static boolean constEq(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++) diff |= a.charAt(i) ^ b.charAt(i);
        return diff == 0;
    }

    // ---- Builder ----

    public static class Builder {
        private String userId;
        private String publicKey;
        private String scope;
        private String productSlug;
        private String serverUrl = "https://api.nxgate.noxlydev.xyz";
        private File cacheDir = new File(".");
        private long gracePeriodMs = TimeUnit.HOURS.toMillis(24);
        private long heartbeatMs = TimeUnit.HOURS.toMillis(6);
        private int retries = 3;
        private long backoffMs = 1000L;
        private Logger logger;
        private Consumer<String> onRevoked;
        private java.util.List<String> tlsPins;
        private boolean debug = false;

        public Builder userId(String v) { this.userId = v; return this; }
        public Builder publicKey(String v) { this.publicKey = v; return this; }
        public Builder scope(String v) { this.scope = v; return this; }
        public Builder productSlug(String v) { this.productSlug = v; return this; }
        public Builder serverUrl(String v) { this.serverUrl = v; return this; }
        public Builder cacheDir(File v) { this.cacheDir = v; return this; }
        public Builder gracePeriod(long amt, TimeUnit unit) { this.gracePeriodMs = unit.toMillis(amt); return this; }
        public Builder heartbeat(long amt, TimeUnit unit) { this.heartbeatMs = unit.toMillis(amt); return this; }
        public Builder retry(int attempts, long backoffMs) { this.retries = attempts; this.backoffMs = backoffMs; return this; }
        public Builder logger(Logger v) { this.logger = v; return this; }
        public Builder onRevoked(Consumer<String> v) { this.onRevoked = v; return this; }
        public Builder tlsPins(java.util.List<String> v) { this.tlsPins = v; return this; }
        public Builder debug() { this.debug = true; return this; }

        public HardenedNxGate build() { return new HardenedNxGate(this); }
    }
}