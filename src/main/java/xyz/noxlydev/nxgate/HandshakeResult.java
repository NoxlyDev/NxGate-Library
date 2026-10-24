package xyz.noxlydev.nxgate;

import java.util.Arrays;

/**
 * Result of a cryptographic HWID handshake with NxGate.
 */
public final class HandshakeResult {

    private final boolean valid;
    private final NxGate.ValidationType status;
    private final String message;
    private final String signedNonce;
    private final String expiresAt;
    private final int gracePeriodHours;
    private final byte[] realAesKey;
    private final byte[] iv;
    private final String sessionToken;
    private final boolean grace;

    public HandshakeResult(
            boolean valid,
            NxGate.ValidationType status,
            String message,
            String signedNonce,
            String expiresAt,
            int gracePeriodHours,
            byte[] realAesKey,
            byte[] iv,
            String sessionToken,
            boolean grace) {
        this.valid = valid;
        this.status = status;
        this.message = message;
        this.signedNonce = signedNonce;
        this.expiresAt = expiresAt;
        this.gracePeriodHours = gracePeriodHours;
        this.realAesKey = realAesKey != null ? Arrays.copyOf(realAesKey, realAesKey.length) : null;
        this.iv = iv != null ? Arrays.copyOf(iv, iv.length) : null;
        this.sessionToken = sessionToken;
        this.grace = grace;
    }

    public static HandshakeResult failure(NxGate.ValidationType status, String message) {
        return new HandshakeResult(false, status, message, null, null, 0, null, null, null, false);
    }

    public boolean isValid() {
        return valid;
    }

    public NxGate.ValidationType getStatus() {
        return status;
    }

    public String getMessage() {
        return message;
    }

    public String getSignedNonce() {
        return signedNonce;
    }

    public String getExpiresAt() {
        return expiresAt;
    }

    public int getGracePeriodHours() {
        return gracePeriodHours;
    }

    public byte[] getRealAesKey() {
        return realAesKey != null ? Arrays.copyOf(realAesKey, realAesKey.length) : null;
    }

    public byte[] getIv() {
        return iv != null ? Arrays.copyOf(iv, iv.length) : null;
    }

    public String getSessionToken() {
        return sessionToken;
    }

    public boolean isGrace() {
        return grace;
    }

    @Override
    public String toString() {
        return "HandshakeResult{" +
                "valid=" + valid +
                ", status=" + status +
                ", message='" + message + '\'' +
                ", isGrace=" + grace +
                ", hasKey=" + (realAesKey != null) +
                '}';
    }
}
