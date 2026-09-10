# Migrating to `package:openssl3`

## From a system `libcrypto` (at_chops ≤ 3.6 style)

at_chops probes for an OpenSSL library at runtime:

<!-- pyml disable-num-lines 4 md013-->
```dart
final lib = tryLoadLibCrypto();            // DynamicLibrary.open('libcrypto.so.3'), Homebrew paths, ...
if (lib != null && libCryptoSupportsMlKem768(lib)) MlKem768FfiAlgo.fromLib(lib) else pureDart;
```

and each `*FfiAlgo` class resolves symbols with `lib.lookupFunction<...>('EVP_...')`.

With `openssl3` the library is bundled at build time and symbols are resolved
by the Dart compiler through `@Native`, so there is no `DynamicLibrary` and no
probe:

<!-- pyml disable-num-lines 8 md013-->
| Before | After |
|---|---|
| `tryLoadLibCrypto()` and `AT_CHOPS_LIBCRYPTO_PATH` | nothing; `dart pub add openssl3` bundles the library |
| `libCryptoSupportsMlKem768(lib)` | `OpenSSLCapabilities.instance.hasMlKem768` (same `EVP_PKEY_CTX_new_from_name` probe) |
| `lib.lookupFunction<EvpPkeyKeygenNative, EvpPkeyKeygenDart>('EVP_PKEY_keygen')` | `EVP_PKEY_keygen` from `package:openssl3/openssl3.dart` |
| hand-written typedefs and `Opaque` classes | generated: `EVP_PKEY`, `EVP_PKEY_CTX`, `OSSL_PARAM_BLD`, … |
| `Pointer<Utf8>` for `const char*` | ffigen uses `Pointer<Char>`; `.cast()` from `toNativeUtf8()` |
| "which OpenSSL did we get?" | `OpenSSLCapabilities.instance.versionString` / `.buildInfo` |

Or skip the raw API and use `package:openssl3/evp.dart`:

<!-- pyml disable-num-lines 7 md013-->
| at_chops class | evp.dart |
|---|---|
| `AesGcm256FfiAlgo` | `Aead.aes256Gcm(key).seal/open` (`combined` = `ciphertext || tag`) |
| `AESEncryptionAlgo` (AES-CTR, pure Dart) | `Cipher.aesCtr(key).encrypt/decrypt`, `encryptStream` for streams |
| `X25519FfiAlgo` | `X25519.keyPair()`, `X25519.agree()` |
| `MlKem768FfiAlgo` (seed-based keys) | `MlKem768.keyPair(seed:)`, `encaps`, `decaps(seedOrExpandedKey, ct)` |
| `MlDsa65FfiAlgo` | `MlDsa65.keyPair(seed:)`, `sign`, `verify` |
| `XWingFfiAlgo` | compose `MlKem768` + `X25519` as today |

All key material is in OpenSSL's raw encodings (ML-KEM seed 64 B, ML-DSA seed
32 B, X25519 32 B), so keys stored by the old FFI classes keep working.

Because `@Native` bindings resolve against the bundled asset, the escape hatch
for "use the OS libcrypto anyway" is a **build-time** switch for the app, not a
runtime one: `hooks: user_defines: openssl3: system: true` in the app's
`pubspec.yaml`. `OpenSSLCapabilities` then reports what that library supports
(`hasMlKem768` is false on OpenSSL < 3.5).

### Web

`package:openssl3/openssl3.dart` and `evp.dart` are `dart:ffi` libraries; keep
your pure-Dart fallback behind a conditional import for web until the WASM
build lands (tracked in PLAN.md).

## From `package:openssl` (LucazzP/openssl_dart)

Both packages are ffigen `@Native` bindings over OpenSSL's public headers,
driven by a Dart build hook, so most call sites compile unchanged. The
difference is how the library reaches your machine.

`package:openssl` 1.0.1 compiles OpenSSL 3.5.4 from source inside its build
hook on every consumer machine: it `curl`s the tarball, runs `Configure` and
`make` (Perl and a C toolchain required, about a minute or more), and on
Windows also downloads Strawberry Perl and jom and assumes a Visual Studio 2022
Community install path. None of those downloads is hash-checked. `openssl3`
downloads a prebuilt library that CI built from the pinned tag and verifies it
against a sha256 compiled into the package (ADR-0001, ADR-0007).

<!-- pyml disable-num-lines 12 md013-->
| | `package:openssl` 1.0.1 | `openssl3` |
|---|---|---|
| OpenSSL | 3.5.4, hardcoded in the hook | 3.5.8 LTS; the package version *is* the OpenSSL version (ADR-0010) |
| Toolchain on the build machine | Perl, make/jom, C compiler | none |
| Integrity | none | sha256 per asset, fails closed; mirror and `local_path` for air-gapped builds |
| Assembly | `no-asm`: no AES-NI, SHA extensions or ARMv8 crypto | enabled on every target except Windows arm64 |
| Library name | `libcrypto.so` / `libcrypto.dylib` / `libcrypto-3-*.dll` | `libopenssl3_crypto`, cannot collide with a system `libcrypto.so.3` |
| Config and providers | stock: reads `openssl.cnf`, can `dlopen` modules | `no-module no-dso no-engine no-legacy`, `initNoConfig()` (ADR-0005) |
| Legacy algorithms (MD4, RC4, DES, Blowfish, …) | compiled in | not compiled in (ADR-0005) |
| libssl | `SSL_*` bindings are declared but the hook builds with `no-ssl` and copies only libcrypto, so they do not resolve | not declared, not bundled (ADR-0009) |
| Dart-side API | raw C API only, by design | raw C API plus `evp.dart`, `OpenSSLCapabilities`, `OpenSSLException` |
| `BN_ULONG` | `UnsignedLong` (32-bit on Windows x64, wrong) | `UintPtr` (pointer-sized, what OpenSSL means) |

Mechanical changes:

- Imports: `package:openssl/openssl.dart` → `package:openssl3/openssl3.dart`.
- Asset id: `package:openssl/src/third_party/openssl.g.dart` →
  `package:openssl3/src/third_party/openssl.g.dart` (only matters if you wrote
  your own `@Native` externals).
- Call `initNoConfig()` once at startup; the bundled library never reads
  `openssl.cnf` or `OPENSSL_CONF` anyway, so this only makes it explicit.
- Code that used MD4, RC4, DES or other legacy-provider algorithms has no
  replacement here; that is deliberate.
- TLS: neither package gives you a working libssl today. If you need one, open
  an issue against `openssl3` (ADR-0009 leaves room for a second
  `libopenssl3_ssl` code asset) rather than expecting `package:openssl` to
  provide it.
- If you stored `BN_ULONG` values through the old bindings on Windows x64,
  re-check them; the old width was wrong.

## From `dart compile exe`

Build hooks are not supported by `dart compile exe` / `aot-snapshot`. Use
`dart build cli`; the executable lives in `bundle/bin/` and the library in
`bundle/lib/`. Ship the whole `bundle/` directory.
