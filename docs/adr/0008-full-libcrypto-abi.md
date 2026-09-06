# 0008 — Expose the full libcrypto public ABI

Status: Accepted (2026-09-06)

## Context
First draft exported and bound a curated subset (EVP, RAND, ERR, …). Review asked for the whole
surface: "as OpenSSL exposes more surfaces we should expose them all." OpenSSL's own ABI list,
`util/libcrypto.num`, has 5 926 entries (1 031 deprecated). The existing full-API Dart package
scores 70/160 on pub.dev, largely for zero dartdoc coverage of ~6 900 generated symbols.

## Decision
Export list = `libcrypto.num` rendered by `util/mkdef.pl`, filtered by our feature flags.
Bindings = ffigen over every generated public header except libssl's. Deprecated API is kept and
marked `@Deprecated`. The generator post-processes the output to add a `///` doc comment per
declaration linking to the OpenSSL man page, and emits `macros.dart` for function-like macros
ffigen cannot bind. A checked-in required-symbols list (at_chops's 45 symbols, AES-CTR for
NoPorts, ChaCha20-Poly1305, SHA/HMAC/HKDF) is asserted present in every built library.

## Consequences
- Library size ≈ stock libcrypto (4–5 MB per arch). Unused `@Native` externals are tree-shaken.
- ~2.5 MB generated Dart; analysis time is measured in CI.
- Full-ABI wasm cannot be dead-code-eliminated; a lite variant is measured alongside.
