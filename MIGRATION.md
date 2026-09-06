# Migrating to `package:openssl3`

## From a system `libcrypto` (at_chops ≤ 3.6 style)

at_chops probes for an OpenSSL library at runtime:

```dart
final lib = tryLoadLibCrypto();            // DynamicLibrary.open('libcrypto.so.3'), Homebrew paths, ...
if (lib != null && libCryptoSupportsMlKem768(lib)) MlKem768FfiAlgo.fromLib(lib) else pureDart;
```

and each `*FfiAlgo` class resolves symbols with `lib.lookupFunction<...>('EVP_...')`.

With `openssl3` the library is bundled at build time and symbols are resolved
by the Dart compiler through `@Native`, so there is no `DynamicLibrary` and no
probe:

| Before | After |
|---|---|
| `tryLoadLibCrypto()` and `AT_CHOPS_LIBCRYPTO_PATH` | nothing; `dart pub add openssl3` bundles the library |
| `libCryptoSupportsMlKem768(lib)` | `OpenSSLCapabilities.instance.hasMlKem768` (same `EVP_PKEY_CTX_new_from_name` probe) |
| `lib.lookupFunction<EvpPkeyKeygenNative, EvpPkeyKeygenDart>('EVP_PKEY_keygen')` | `EVP_PKEY_keygen` from `package:openssl3/openssl3.dart` |
| hand-written typedefs and `Opaque` classes | generated: `EVP_PKEY`, `EVP_PKEY_CTX`, `OSSL_PARAM_BLD`, … |
| `Pointer<Utf8>` for `const char*` | ffigen uses `Pointer<Char>`; `.cast()` from `toNativeUtf8()` |
| "which OpenSSL did we get?" | `OpenSSLCapabilities.instance.versionString` / `.buildInfo` |

Or skip the raw API and use `package:openssl3/evp.dart`:

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

That package compiles OpenSSL from source inside its build hook on every
consumer machine (Perl, a C toolchain, several minutes; downloads Strawberry
Perl and jom on Windows). `openssl3` downloads a prebuilt, sha256-pinned
library instead.

- Imports: `package:openssl/openssl.dart` → `package:openssl3/openssl3.dart`.
  Both are ffigen `@Native` bindings over the public headers with C names, so
  most call sites compile unchanged.
- Asset id: `package:openssl/src/third_party/openssl.g.dart` →
  `package:openssl3/src/third_party/openssl.g.dart` (only matters if you wrote
  your own `@Native` externals).
- libssl: not included in `openssl3`. If you need TLS, stay on `package:openssl`
  or open an issue (ADR-0009).
- Legacy algorithms (MD4, RC4, DES, Blowfish, …): not compiled in (ADR-0005).
- `BN_ULONG` is `UintPtr` here (pointer-sized on every target, which is what
  OpenSSL means); `package:openssl` emits `UnsignedLong`, which is wrong on
  Windows x64.
- Versions: `openssl3` versions are the bundled OpenSSL version (`3.5.8+1`).

## From `dart compile exe`

Build hooks are not supported by `dart compile exe` / `aot-snapshot`. Use
`dart build cli`; the executable lives in `bundle/bin/` and the library in
`bundle/lib/`. Ship the whole `bundle/` directory.
