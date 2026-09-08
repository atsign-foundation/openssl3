# Changelog

Versions follow the bundled OpenSSL: `<openssl version>+<package build>`
(ADR-0010). Pre-releases are `<openssl version>-dev.<n>`.

## 3.5.8+3

Security review follow-ups. Same OpenSSL 3.5.8.

- Hook: downloads are bounded by the manifest's recorded size, time out
  instead of hanging (30 s connect, 60 s idle), refuse `https` → `http`
  redirects, use a unique temporary file so concurrent hooks cannot corrupt
  each other, and leave nothing behind on failure. `manifest_override` is
  refused with the default download URL and announced on stderr when used.
- `evp.dart`: keys, seeds, IKM, shared secrets, derived keys and plaintext are
  wiped from native memory (`OPENSSL_cleanse`) after every call;
  `Hmac.verify` uses `CRYPTO_memcmp`. **Breaking:** `Aead.seal`/`open` reject
  nonces shorter than 12 bytes (`Aead.minNonceLength`); `Cipher.named`
  rejects AEAD modes and unknown names at construction.
- Prebuilt Linux libraries are built with `-fstack-protector-strong
  -D_FORTIFY_SOURCE=2`, Windows DLLs with Control Flow Guard; the build
  verifier asserts both. Release pipeline: actions pinned to commit SHAs,
  build images pinned by digest, provenance attestations verified before a
  release is published, upstream tarball checked against its PGP signature
  and the pinned submodule (ADR-0011).
- Build tool: build-info JSON is embedded with octal escapes (a non-ASCII
  compiler or host string no longer breaks the shim compile).

## 3.5.8+2

- New prebuilt target `linux-arm` (32-bit ARMv7 hard-float glibc, glibc ≥ 2.35):
  Dart's `linux-arm` SDK on Raspberry Pi class devices. 16 targets now.
- Release workflow fixes found during the first release (duplicate asset upload,
  PR base branch, release-notes quoting). No library or API changes.

## 3.5.8+1

Initial release. Bundles OpenSSL 3.5.8 (LTS) `libcrypto`.

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
