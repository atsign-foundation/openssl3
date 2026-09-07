# Changelog

Versions follow the bundled OpenSSL: `<openssl version>+<package build>`
(ADR-0010). Pre-releases are `<openssl version>-dev.<n>`.

## 3.5.8-dev.1

Initial development release. Bundles OpenSSL 3.5.8 (LTS) `libcrypto`.

- Build hook downloads a sha256-pinned `libopenssl3_crypto` for
  Linux (glibc x64/arm64/riscv64, musl x64/arm64), macOS (arm64/x64),
  iOS (device arm64, simulator arm64/x64), Android (arm64-v8a, armeabi-v7a,
  x86_64) and Windows (x64/arm64); fails closed on hash mismatch.
- User defines: `url_pattern`, `local_path`, `local_path_unverified`,
  `linux_libc`, `system`, `system_name`; `local_build` reserved.
- `@Native` bindings for the complete public libcrypto API (5 702 functions,
  10 582 macro constants), each linked to its manual page; deprecated API
  annotated. libssl excluded.
- `OpenSSLCapabilities` (version, build info, ML-KEM-768 / ML-DSA-65 / X25519 /
  AES-GCM / AES-CTR / ChaCha20-Poly1305 probes, provider list),
  `initNoConfig()`, `OpenSSLException`.
- `package:openssl3/evp.dart`: `Aead` (AES-256/128-GCM, ChaCha20-Poly1305),
  `Cipher.aesCtr` with streaming, `X25519`, `MlKem768`, `MlDsa65`, `Random`,
  `Digest` (SHA-2/SHA-3, streaming), `Hmac`, `Hkdf`.
