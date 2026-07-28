# ============================================================
#  ProGuard Configuration — NxGate (published library)
#
#  BEDA PENTING dari proguard.pro di NoxAeApi (Paper) / proguard-fabric.pro
#  (Fabric): NxGate BUKAN aplikasi akhir, dia LIBRARY yang di-publish ke
#  Maven repo (repo.noxlydev.xyz) dan di-*compile* langsung terhadap oleh
#  proyek lain (NoxAeApi Paper & Fabric import xyz.noxlydev.nxgate.NxGate,
#  .HardenedNxGate, .Fingerprints by name di source code mereka).
#
#  Kalau public API (nama class, nama method public, enum constants) di-
#  rename, konsumen gak cuma gagal runtime — mereka gagal COMPILE begitu
#  update ke versi nxgate yang baru. Jadi strateginya di sini beda:
#
#    - Nama class publik + method publik/protected TETAP dipertahankan
#      (supaya konsumen tetap bisa compile & jalan tanpa perubahan apa pun).
#    - Yang di-obfuscate cuma bagian PRIVATE: nama field, method helper
#      private, dan urutan/isi logic (lewat -dontshrink dimatikan tapi
#      rename tetap jalan untuk member non-public).
#
#  Catatan jujur: ini tetap client-side check, jadi obfuscation memperlambat
#  reverse-engineering (nama-nama helper jadi 'a', 'b', 'c', gak ada lagi
#  petunjuk dari nama method soal urutan validasi/HMAC/cache), TAPI bukan
#  jaminan mutlak — orang yang niat banget tetap bisa decompile & trace
#  alur eksekusinya. Ini soal menaikkan effort buat reverse-engineer, bukan
#  membuatnya mustahil.
# ============================================================

-dontoptimize
-dontshrink

# ---- PUBLIC API — HARUS tetap sama persis (dipakai proyek lain) ----

-keep public class xyz.noxlydev.nxgate.NxGate {
    public *;
    protected *;
}
-keep public enum xyz.noxlydev.nxgate.NxGate$ValidationType {
    *;
}

-keep public class xyz.noxlydev.nxgate.HardenedNxGate {
    public *;
    protected *;
}
-keep public class xyz.noxlydev.nxgate.HardenedNxGate$Builder {
    public *;
}

-keep public class xyz.noxlydev.nxgate.Fingerprints {
    public *;
}

# ---- Field private, method helper private (buildUrl, requestServer,
# verifyChallenge, hmacHex, readCache/writeCache, constEq, dst.) TIDAK
# di-keep secara eksplisit di atas — otomatis boleh di-rename ProGuard
# selama dia bukan bagian dari signature public yang dipertahankan.

# ---- ENUM machinery (dipanggil reflectively lewat valueOf/values) ----
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ---- ATRIBUT ----
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes Exceptions
-keepattributes InnerClasses
-keepattributes EnclosingMethod
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

-dontwarn **
