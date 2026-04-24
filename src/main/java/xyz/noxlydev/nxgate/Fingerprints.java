package xyz.noxlydev.nxgate;

import java.io.File;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Enumeration;

/**
 * Stable, privacy-respecting fingerprints used by the hardened NxGate.
 *
 *  - {@link #machine()} hashes hostname + first non-loopback MAC + os.name + os.arch.
 *    Same machine → same fingerprint. Different machine → different fingerprint.
 *  - {@link #callerJar()} hashes the JAR that loaded this class. Detects re-packaged
 *    or modified plugin JARs (e.g. when someone strips the license check and re-jars).
 *
 * Both return short hex strings (32 chars). Cached after first call for performance.
 */
public final class Fingerprints {

    private Fingerprints() {}

    private static volatile String cachedMachine;
    private static volatile String cachedJar;

    public static String machine() {
        String m = cachedMachine;
        if (m != null) return m;
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(System.getProperty("os.name", "")).append('|');
            sb.append(System.getProperty("os.arch", "")).append('|');
            try { sb.append(java.net.InetAddress.getLocalHost().getHostName()).append('|'); } catch (Exception ignored) {}
            try {
                Enumeration<NetworkInterface> nics = NetworkInterface.getNetworkInterfaces();
                while (nics != null && nics.hasMoreElements()) {
                    NetworkInterface ni = nics.nextElement();
                    if (ni.isLoopback() || ni.isVirtual() || !ni.isUp()) continue;
                    byte[] mac = ni.getHardwareAddress();
                    if (mac != null && mac.length > 0) { sb.append(NxGate.toHex(mac)); break; }
                }
            } catch (Exception ignored) {}
            m = NxGate.toHex(sha256(sb.toString().getBytes("UTF-8"))).substring(0, 32);
        } catch (Exception e) {
            m = "unknown";
        }
        cachedMachine = m;
        return m;
    }

    public static String callerJar() {
        String j = cachedJar;
        if (j != null) return j;
        try {
            File f = new File(Fingerprints.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            if (f.exists() && f.isFile()) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                try (java.io.InputStream is = java.nio.file.Files.newInputStream(f.toPath())) {
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = is.read(buf)) != -1) md.update(buf, 0, n);
                }
                j = NxGate.toHex(md.digest()).substring(0, 32);
            } else {
                j = "no-jar";
            }
        } catch (Exception e) {
            j = "no-jar";
        }
        cachedJar = j;
        return j;
    }

    static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }
}
