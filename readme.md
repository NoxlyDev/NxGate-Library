# NxGate

Java wrapper untuk validasi lisensi lewat NxGate — mendukung setup cloud maupun self-hosted. Cocok dipakai di plugin Minecraft (Bukkit/Paper/Fabric) atau aplikasi Java lainnya yang butuh license-gating.

## Fitur

- **Verifikasi lisensi via HTTP** ke server NxGate (cloud atau self-hosted).
- **Challenge-response RSA** (opsional) untuk memastikan respons server benar-benar datang dari server asli, bukan hasil spoof.
- **TLS certificate pinning** (opsional) untuk mencegah MITM.
- **Retry otomatis dengan exponential backoff**.
- **`HardenedNxGate`** — wrapper tingkat tinggi dengan:
  - Cache offline ber-HMAC, terikat ke machine fingerprint + jar fingerprint (cache tidak bisa dipindah ke mesin lain / jar hasil re-pack).
  - Grace period — plugin tetap jalan sementara waktu meski server tidak bisa dihubungi.
  - Heartbeat background — re-verifikasi berkala, otomatis men-disable plugin kalau lisensi dicabut.
  - Constant-time comparison (tahan timing attack) untuk validasi cache.
- **Obfuscated build** (ProGuard) — public API tetap stabil, internal logic disamarkan untuk mempersulit reverse-engineering. Lihat [`PANDUAN-DEPLOY.md`](./PANDUAN-DEPLOY.md) untuk detail proses build/deploy.

> Catatan jujur: ini tetap client-side check. Obfuscation & hardening menaikkan effort untuk reverse-engineer, bukan menjamin mustahil dibypass sepenuhnya.

## Instalasi

Tambahkan repository dan dependency:

**Maven**
```xml
<repositories>
    <repository>
        <id>reposilite</id>
        <url>https://repo.noxlydev.xyz/releases</url>
    </repository>
</repositories>

<dependency>
    <groupId>xyz.noxlydev.nxgate</groupId>
    <artifactId>nxgate</artifactId>
    <version>1.0.10</version>
</dependency>
```

**Gradle**
```groovy
repositories {
    maven { url 'https://repo.noxlydev.xyz/releases' }
}

dependencies {
    implementation 'xyz.noxlydev.nxgate:nxgate:1.0.10'
}
```

Requires Java 8+. Dependency transitif: `org.json:json`.

## Penggunaan

### Dasar — `NxGate`

```java
NxGate gate = new NxGate("YOUR_USER_ID");

NxGate.ValidationType result = gate.verify(licenseKey);

if (result == NxGate.ValidationType.VALID) {
    // lisensi valid
} else {
    // cek result: NOT_FOUND, EXPIRED, NOT_ACTIVE, dll.
}

// atau versi ringkas:
boolean valid = gate.verifySimple(licenseKey);
```

Dengan scope, metadata, atau product slug:
```java
gate.verify(licenseKey, scope, metadata, productSlug);
```

### Dengan challenge-response (anti-spoof)

```java
NxGate gate = new NxGate("YOUR_USER_ID", publicRsaKeyPem)
        .useChallenges();

gate.verify(licenseKey); // FAILED_CHALLENGE jika signature tidak valid
```

### Opsi tambahan

```java
gate.withRetry(3, 1000)              // 3x percobaan, backoff x3 tiap gagal
    .withTimeout(10000, 10000)        // connect/read timeout (ms)
    .withTlsPinning(List.of("AB:CD:...")) // SHA-256 cert pin
    .setValidationServer("https://your-self-hosted-server.com")
    .debug();                          // log request/response ke stdout
```

### Rekomendasi produksi — `HardenedNxGate`

Untuk plugin/aplikasi yang butuh offline grace period + heartbeat + cache tamper-resistant:

```java
HardenedNxGate gate = new HardenedNxGate.Builder()
    .userId("YOUR_USER_ID")
    .publicKey(PUBLIC_KEY_PEM)
    .scope("MyPlugin")
    .serverUrl("https://api.nxgate.noxlydev.xyz")
    .cacheDir(getDataFolder())
    .gracePeriod(24, TimeUnit.HOURS)
    .heartbeat(6, TimeUnit.HOURS)
    .retry(3, 1000)
    .logger(getLogger())
    .onRevoked(reason -> getServer().getPluginManager().disablePlugin(this))
    .build();

if (!gate.verifyBlocking(licenseKey)) {
    getServer().getPluginManager().disablePlugin(this);
    return;
}
gate.startHeartbeat(() -> licenseKey);

// saat plugin di-disable:
gate.shutdown();
```

## Hasil Validasi (`NxGate.ValidationType`)

| Value | Keterangan |
|---|---|
| `VALID` | Lisensi valid |
| `NOT_FOUND` | Lisensi tidak ditemukan |
| `NOT_ACTIVE` | Lisensi belum aktif |
| `EXPIRED` | Lisensi sudah kedaluwarsa |
| `LICENSE_SCOPE_FAILED` | Scope tidak cocok |
| `IP_LIMIT_EXCEEDED` | Melebihi batas IP |
| `RATE_LIMIT_EXCEEDED` | Melebihi rate limit |
| `PRODUCT_MISMATCH` | Lisensi tidak terdaftar untuk product ini |
| `FAILED_CHALLENGE` | Signature challenge tidak valid |
| `SERVER_ERROR` | Error di sisi server |
| `CONNECTION_ERROR` | Tidak bisa menghubungi server |

## Build & Deploy

Lihat [`PANDUAN-DEPLOY.md`](./PANDUAN-DEPLOY.md) untuk panduan lengkap build lokal, deploy ke release/development, serta troubleshooting umum (409 conflict, locked `target` folder di Windows, dll).

## Lisensi

Proprietary — internal use, NOXLYDEV.
