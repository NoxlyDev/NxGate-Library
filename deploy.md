# Panduan Deploy NxGate Library

Panduan build & deploy `xyz.noxlydev.nxgate:nxgate` ke reposilite (`repo.noxlydev.xyz`).

## Ringkasan Repo

| Repo | URL | Isi | Kapan Dipakai |
|---|---|---|---|
| `releases` | `https://repo.noxlydev.xyz/releases` | jar obfuscated + javadoc (**tanpa** sources) | Rilis publik/production, dipakai project lain |
| `snapshots` | `https://repo.noxlydev.xyz/snapshots` | mengikuti versi `-SNAPSHOT` | Build snapshot standar Maven |
| `development` | `https://repo.noxlydev.xyz/development` | jar obfuscated + javadoc + **sources** | Testing internal, debug lokal antar-project |

> Repo `development` harus sudah dibuat lebih dulu di admin panel reposilite sebelum dipakai.

## Profile Maven yang Tersedia

Didefinisikan di `pom.xml`:

- **`dev`** — mengaktifkan `maven-source-plugin` (attach sources jar). Tidak aktif secara default.
- **`dev-deploy`** — override `distributionManagement` agar upload diarahkan ke repo `development`, bukan `releases`.

Kedua profile ini independen — bisa dipakai sendiri-sendiri atau bareng.

## Command Deploy

### 1. Rilis publik (default, paling umum)

Jar obfuscated + javadoc saja, **tanpa sources**, upload ke `releases`.

```powershell
mvn clean deploy
```

Version di `pom.xml` cukup format normal, contoh:
```xml
<version>1.0.8</version>
```

### 2. Deploy ke development (sources ikut, repo terpisah)

```powershell
mvn clean deploy -Pdev -Pdev-deploy
```

atau (kalau mau satu flag, wajib di-quote karena PowerShell menganggap koma sebagai separator):
```powershell
mvn clean deploy "-Pdev,dev-deploy"
```

Ini akan:
- Attach sources jar (`-Pdev`)
- Upload ke `https://repo.noxlydev.xyz/development` (`-Pdev-deploy`)
- Version **tidak perlu** `-SNAPSHOT` untuk ini — routing repo ditentukan oleh profile `dev-deploy`, bukan oleh suffix version.

### 3. Install lokal saja (tanpa upload kemana-mana)

Untuk testing di mesin sendiri, sources ikut ter-attach ke `.m2` lokal:

```powershell
mvn clean install -Pdev
```

### 4. Snapshot standar Maven (opsional, kalau memang butuh konvensi `-SNAPSHOT`)

```xml
<version>1.0.9-SNAPSHOT</version>
```
```powershell
mvn clean deploy -Pdev
```
Otomatis ke `snapshotRepository` karena ada suffix `-SNAPSHOT`, terlepas dari profile `dev-deploy` (tidak perlu dipakai di case ini).

## Troubleshooting

**Error 409 Conflict saat `mvn deploy`**
Artinya versi tersebut sudah pernah di-deploy ke repo release (immutable by design). Solusi: bump versi (`1.0.8` → `1.0.9`), atau hapus artifact lama dari reposilite kalau memang ingin overwrite.

**`maven-clean-plugin` gagal hapus folder `target` (Windows)**
Folder sedang di-lock proses lain (biasanya IDE atau antivirus).
1. Tutup IDE / stop semua proses `java.exe` terkait project.
2. Coba hapus manual: `Remove-Item -Recurse -Force .\target`
3. Kalau masih gagal, restart Explorer (`taskkill /f /im explorer.exe && start explorer.exe`) atau restart PC.

**PowerShell error "Missing argument in parameter list" saat pakai multi-profile**
PowerShell membaca koma sebagai array separator. Bungkus dengan quote (`"-Pdev,dev-deploy"`) atau panggil `-P` dua kali (`-Pdev -Pdev-deploy`).

## Cara Kerja Obfuscation (Ringkas)

- ProGuard jalan otomatis di phase `package` (`proguard-nxgate.pro`).
- Public API (`NxGate`, `HardenedNxGate`, `Fingerprints`, enum `ValidationType`) di-`-keep` utuh — konsumen tetap compile & jalan normal tanpa perubahan.
- Yang di-rename hanya member private/internal (helper method, field) — memperlambat reverse-engineering, bukan menjamin tidak bisa di-reverse sama sekali.
- Sources jar **tidak** ikut ter-attach di deploy default (`mvn deploy` biasa) — hanya muncul kalau profile `dev` diaktifkan secara eksplisit.
