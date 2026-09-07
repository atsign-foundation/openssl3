# openssl3

Prebuilt **OpenSSL 3.5 LTS `libcrypto`** for Dart and Flutter, bundled into your
app by a [build hook](https://dart.dev/tools/hooks), with `@Native` bindings for
the **complete public libcrypto API** and a small idiomatic layer for the
operations most apps need (AES-GCM/CTR, X25519, ML-KEM-768, ML-DSA-65).

- **Zero toolchain at build time.** No OpenSSL, Perl or C compiler on the
  machine that builds your app. The hook downloads a sha256-pinned library from
  this package's GitHub release and fails closed on any mismatch.
- **Same bytes everywhere.** Linux (glibc and musl), macOS, iOS, Android and
  Windows all get the same OpenSSL version, built by CI from the pinned tag with
  the toolchains OpenSSL's own CI uses.
- **Post-quantum ready.** ML-KEM-768 and ML-DSA-65 are compiled in (OpenSSL
  3.5), so at_chops and NoPorts no longer need a pure-Dart fallback.
- **Pin what you ship.** The package version *is* the OpenSSL version:
  `openssl3: 3.5.8+1` pins one exact build.

The library is named `libopenssl3_crypto` and never collides with a system
`libcrypto.so.3` / `libcrypto.3.dylib` already loaded in the process.

## Install

```sh
dart pub add openssl3        # or: flutter pub add openssl3
```

Requires Dart ≥ 3.10 / Flutter ≥ 3.38 (build hooks are stable there). Then
build as usual: `flutter run`, `flutter build …`, `dart run`, `dart test`, or
`dart build cli`. The first build downloads the library for your target
(≈ 5 MB) into the hook's shared cache; later builds are offline.

> **`dart compile exe` does not run build hooks** and will refuse:
> `'dart compile' does not support build hooks, use 'dart build' instead.`
> Use `dart build cli`, which produces `bundle/bin/<app>` plus
> `bundle/lib/libopenssl3_crypto.*` (in preview in Dart 3.11; stable since 3.13).

## Use

Raw C API, one-to-one with the OpenSSL headers:

```dart
import 'dart:ffi';
import 'package:ffi/ffi.dart';
import 'package:openssl3/openssl3.dart';

void main() {
  initNoConfig(); // OPENSSL_init_crypto without reading any openssl.cnf
  print(OpenSSL_version(OPENSSL_VERSION).cast<Utf8>().toDartString());
  final caps = OpenSSLCapabilities.instance;
  print('ML-KEM-768: ${caps.hasMlKem768}, AES-CTR: ${caps.hasAesCtr}');
  final ctx = EVP_PKEY_CTX_new_from_name(nullptr, 'ML-DSA-65'.toNativeUtf8().cast(), nullptr);
  // ... any of the ~5 700 libcrypto functions, structs, enums and macros
  EVP_PKEY_CTX_free(ctx);
}
```

Idiomatic layer (`package:openssl3/evp.dart`), keys are plain bytes in
OpenSSL's raw encodings:

```dart
import 'package:openssl3/evp.dart';

final key = Random.privateBytes(32);
final nonce = Random.bytes(12);
final box = Aead.aes256Gcm(key).seal(nonce, plaintext, aad: header);
final again = Aead.aes256Gcm(key).open(nonce, box, aad: header); // AuthenticationException on tamper

final ctr = Cipher.aesCtr(key);                  // 128/192/256 by key length (at_chops / NoPorts)
final ct = ctr.encrypt(iv16, data);              // or ctr.encryptStream(iv16).update(...)/finish()

final a = X25519.keyPair(), b = X25519.keyPair();
assert(X25519.agree(a.privateKey, b.publicKey) == X25519.agree(b.privateKey, a.publicKey));

final kem = MlKem768.keyPair();                  // kem.seed (64 B) fully determines the pair
final enc = MlKem768.encaps(kem.publicKey);      // ciphertext 1088 B, shared secret 32 B
final ss = MlKem768.decaps(kem.seed!, enc.ciphertext);

final dsa = MlDsa65.keyPair();
final sig = MlDsa65.sign(dsa.privateKey, message);
MlDsa65.verify(dsa.publicKey, message, sig);     // true
```

Errors from libcrypto surface as `OpenSSLException` with the drained error
queue. Everything else in libcrypto (SHA-3, HKDF, RSA, X.509, PEM, BIO, …) is
available through the raw bindings; every declaration links to its manual page
at <https://docs.openssl.org/3.5/man3/>.

## Versions and pinning

| You write | You get |
|---|---|
| `openssl3: 3.5.8+1` | exactly that build |
| `openssl3: ^3.5.8` | any OpenSSL 3.x ≥ 3.5.8 (OpenSSL keeps API/ABI compatible across 3.x) |
| `openssl3: '>=3.5.0 <3.6.0'` | stays on the 3.5 LTS line |

`OpenSSLCapabilities.instance.versionString` and `.buildInfo` (target, OpenSSL
commit, compiler, Configure arguments) tell you at runtime exactly what was
bundled. New OpenSSL releases are picked up by a weekly workflow that opens a
PR; see CONTRIBUTING.md.

## Supported targets

| OS | Architectures | Notes |
|---|---|---|
| Linux (glibc) | x64, arm64, riscv64 | x64/arm64 built in manylinux_2_28 → glibc ≥ 2.28 (RHEL 8, Debian 10, Ubuntu 20.04 and newer); riscv64 cross-built on Ubuntu 24.04 → glibc ≥ 2.39 |
| Linux (musl) | x64, arm64 | for Alpine / scratch images; auto-detected on a musl host, or `linux_libc: musl` |
| macOS | arm64, x64 | 10.15+, thin dylibs (Flutter builds the framework) |
| iOS | arm64 device; arm64, x64 simulator | 13.0+ |
| Android | arm64-v8a, armeabi-v7a, x86_64 | API 21+, 16 KB page aligned |
| Windows | x64, arm64 | static CRT, no extra DLLs |

Any other `(OS, architecture)` makes the build fail with a clear message rather
than silently falling back. Web/WASM is planned (see `PLAN.md`).

## Configuring the hook

All options go in the **root** `pubspec.yaml` of your app or workspace:

```yaml
hooks:
  user_defines:
    openssl3:
      # Mirror for air-gapped builds; $RELEASE_TAG and $FILENAME are replaced.
      url_pattern: "https://artifacts.example.com/openssl3/$RELEASE_TAG/$FILENAME"
      # Use a pre-downloaded release asset; still verified against the pinned sha256 ...
      local_path: third_party/libopenssl3_crypto.arm64.macos.dylib
      # ... unless you explicitly opt out.
      local_path_unverified: true
      # Force the musl build on Linux (default: glibc, or musl if the host is musl).
      linux_libc: musl
      # Load the operating system's libcrypto instead of bundling (distro packagers).
      system: true
      system_name: libcrypto.so.3        # or a map: {linux: ..., macos: ..., windows: ..., default: ...}
```

`system`, `local_path`, `local_build` and `test_directory` are mutually
exclusive. Set what you need and nothing else.

### Offline and air-gapped builds

1. Download `libopenssl3_crypto.<arch>.<os>.<ext>` for your targets from the
   GitHub release matching your package version (file names in
   `manifest.json` there).
2. Either serve them from an internal mirror and set `url_pattern`, or point
   `local_path` at the file. Both are sha256-verified against the hashes
   compiled into the package, so a stale or tampered mirror fails the build.
3. The hook's cache lives under the SDK's shared output directory; once warm,
   no network access happens at all.

`HTTP_PROXY`/`HTTPS_PROXY` are honoured (Dart ≥ 3.11 passes them to hooks).

### Docker and Alpine

Images built on Debian/Ubuntu get the glibc library (built in a manylinux_2_28
image, so it loads on glibc ≥ 2.28: RHEL 8+, Debian 10+, Ubuntu 20.04+; older
bases need `local_build`). On Alpine the hook detects musl
(`/etc/alpine-release` or `ld-musl-*`) and uses the musl build; when
cross-building for Alpine from a glibc host, set `linux_libc: musl`. The
resulting `dart build cli` bundle has no dependency on the image's OpenSSL.

### Building from source (`local_build`)

```yaml
hooks:
  user_defines:
    openssl3:
      local_build: true
      source_path: ../openssl        # optional: an OpenSSL source tree
```

Compiles libcrypto on your machine with exactly the pipeline CI uses (same
Configure flags, same link step, same verification). **Requires Perl 5,
`make`/`nmake` and the platform C toolchain, and takes several minutes**; the
result is cached in the hook's shared directory. Without `source_path` the
pinned `openssl-<version>.tar.gz` is downloaded from GitHub and verified
against the sha256 recorded in the package; a checkout of this repository
(no release yet) must pass `source_path`. Android needs `ANDROID_NDK_ROOT`.

## Symbol-clash avoidance

The bundled file is `libopenssl3_crypto.{so,dylib,dll}` with that SONAME /
install name, linked `-Bsymbolic` on ELF, exporting exactly OpenSSL's public
ABI. A process that already has a system `libcrypto.so.3` loaded (Flutter on
Linux via GTK, for instance) keeps both without interference; a test loads the
bundled library next to Homebrew's OpenSSL 3.6 and checks they report different
versions. The one extra symbol, `openssl3_build_info`, is what
`OpenSSLCapabilities.buildInfo` reads.

## What is (not) in the binary

Built from the pinned OpenSSL tag with
`no-shared no-module no-dso no-engine no-legacy no-apps no-tests no-docs no-comp no-zlib --openssldir=/nonexistent`.
The default provider is compiled in; nothing is loaded from disk; no
`openssl.cnf` is read (`initNoConfig()` makes that explicit). The **legacy
provider is absent**: MD4, RC4, DES, Blowfish, CAST, IDEA, SEED, RC2 are not
available. libssl (TLS) is not included. Deprecated 1.x-era API is kept and
marked `@Deprecated` in Dart.

94 exported functions have no Dart binding because ffigen cannot express them
(functions returning raw function pointers such as `RSA_meth_get_*`) or no
public header declares them (`DSO_*`); see `unboundSymbols`.

## Export compliance

This package ships strong encryption (AES, ChaCha20, X25519, ML-KEM, ML-DSA,
RSA, ECC). OpenSSL is publicly available open-source software, which in most
jurisdictions places it under lighter-weight rules (for example US EAR
§742.15(b) / License Exception ENC for publicly available encryption source
code, with the binary treated the same), but **your app** is what gets
distributed:

- App Store: answer the encryption questions in App Store Connect truthfully;
  apps using non-exempt encryption typically set `ITSAppUsesNonExemptEncryption`
  and may need a self-classification report or CCATS depending on use.
- Google Play: complete the export compliance questions in Play Console.
- Some countries restrict import/use of cryptography independently of export.

None of this is legal advice; check with counsel for your product and markets.

## Licenses

This package is BSD-3-Clause. OpenSSL is Apache-2.0; its LICENSE is shipped in
`third_party/openssl/LICENSE.txt` and applies to the bundled binary.

## Migration

See [MIGRATION.md](https://github.com/cconstab/openssl3/blob/trunk/MIGRATION.md)
for moving from a system `libcrypto` (`DynamicLibrary.open` probing, as in
at_chops ≤ 3.6) or from `package:openssl` (LucazzP), which compiles OpenSSL on
every consumer machine.
