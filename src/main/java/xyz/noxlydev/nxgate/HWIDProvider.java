package xyz.noxlydev.nxgate;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Enumeration;

/**
 * Robust, cross-platform Hardware ID (HWID) generator.
 * Produces a stable, unique 64-character SHA-256 hex string bound to the host machine.
 */
public final class HWIDProvider {

    private HWIDProvider() {}

    private static volatile String cachedHWID = null;
    private static volatile byte[] cachedHWIDDigest = null;

    /**
     * Get the machine's 64-character SHA-256 HWID string.
     */
    public static String getHWID() {
        if (cachedHWID != null) {
            return cachedHWID;
        }

        synchronized (HWIDProvider.class) {
            if (cachedHWID != null) {
                return cachedHWID;
            }

            StringBuilder sb = new StringBuilder();
            String os = System.getProperty("os.name", "").toLowerCase();

            // 1. OS & Core System Arch
            sb.append(System.getProperty("os.name", "")).append(';');
            sb.append(System.getProperty("os.arch", "")).append(';');
            sb.append(Runtime.getRuntime().availableProcessors()).append(';');

            // 2. Platform-specific machine identifiers
            if (os.contains("win")) {
                String winId = getWindowsGuid();
                if (winId != null && !winId.isEmpty()) {
                    sb.append("win:").append(winId).append(';');
                }
            } else if (os.contains("linux")) {
                String linuxId = getLinuxMachineId();
                if (linuxId != null && !linuxId.isEmpty()) {
                    sb.append("linux:").append(linuxId).append(';');
                }
            } else if (os.contains("mac")) {
                String macId = getMacSerialNumber();
                if (macId != null && !macId.isEmpty()) {
                    sb.append("mac:").append(macId).append(';');
                }
            }

            // 3. Network Interfaces (Primary MAC address)
            String mac = getPrimaryMacAddress();
            if (mac != null && !mac.isEmpty()) {
                sb.append("mac-addr:").append(mac).append(';');
            }

            // 4. Fallback components (user & env)
            sb.append(System.getProperty("user.name", "")).append(';');
            sb.append(System.getProperty("user.home", ""));

            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(sb.toString().getBytes(StandardCharsets.UTF_8));
                cachedHWIDDigest = digest;
                cachedHWID = toHex(digest);
            } catch (Exception e) {
                // Extreme fallback
                cachedHWID = "0000000000000000000000000000000000000000000000000000000000000000";
                cachedHWIDDigest = new byte[32];
            }

            return cachedHWID;
        }
    }

    /**
     * Get the machine's 32-byte SHA-256 HWID digest directly.
     */
    public static byte[] getHWIDBytes() {
        getHWID();
        return cachedHWIDDigest;
    }

    private static String getPrimaryMacAddress() {
        try {
            Enumeration<NetworkInterface> nics = NetworkInterface.getNetworkInterfaces();
            while (nics != null && nics.hasMoreElements()) {
                NetworkInterface ni = nics.nextElement();
                if (ni.isLoopback() || ni.isVirtual() || !ni.isUp()) continue;
                byte[] mac = ni.getHardwareAddress();
                if (mac != null && mac.length > 0) {
                    return toHex(mac);
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static String getWindowsGuid() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{
                "reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"
            });
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("MachineGuid")) {
                        String[] parts = line.trim().split("\\s+");
                        if (parts.length >= 3) {
                            return parts[2].trim();
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static String getLinuxMachineId() {
        // Try /etc/machine-id
        File f1 = new File("/etc/machine-id");
        if (f1.exists() && f1.canRead()) {
            try {
                return new String(Files.readAllBytes(f1.toPath()), StandardCharsets.UTF_8).trim();
            } catch (Exception ignored) {}
        }
        // Try /var/lib/dbus/machine-id
        File f2 = new File("/var/lib/dbus/machine-id");
        if (f2.exists() && f2.canRead()) {
            try {
                return new String(Files.readAllBytes(f2.toPath()), StandardCharsets.UTF_8).trim();
            } catch (Exception ignored) {}
        }
        // Try DMI product UUID
        File f3 = new File("/sys/class/dmi/id/product_uuid");
        if (f3.exists() && f3.canRead()) {
            try {
                return new String(Files.readAllBytes(f3.toPath()), StandardCharsets.UTF_8).trim();
            } catch (Exception ignored) {}
        }
        return null;
    }

    private static String getMacSerialNumber() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"ioreg", "-rd1", "-c", "IOPlatformExpertDevice"});
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("IOPlatformUUID")) {
                        String[] parts = line.split("=");
                        if (parts.length >= 2) {
                            return parts[1].replace("\"", "").trim();
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
