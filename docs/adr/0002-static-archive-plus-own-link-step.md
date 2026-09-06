# 0002 — Static `libcrypto.a` plus our own link step

Status: Accepted (2026-09-06)

## Context
The brief requires a distinct file name and SONAME (no clash with a system `libcrypto.so.3`), a
controlled export list, `/MT` on Windows, 16 KB page alignment on Android and `-Bsymbolic` on ELF.
OpenSSL's `shared` build names the library `libcrypto.so.3`; `shlib_variant` only appends to the
name, and the other properties would require patching Configure or post-processing with
`patchelf` / `install_name_tool`.

## Decision
Configure OpenSSL with `no-shared`, build `libcrypto.a` (`make build_libs`), then link
`libopenssl3_crypto.{so,dylib}` / `openssl3_crypto.dll` ourselves
(`tool/link_asset.dart`) with: `-soname` / `-install_name`, the export list from ADR-0008,
`-Wl,-Bsymbolic`, `-Wl,-z,max-page-size=16384` (Android), static CRT on Windows (OpenSSL's
`VC-*` configs already compile `no-shared` static libraries with `/MT /Zl`, so the DLL we link
from `libcrypto.lib` plus `/DEFAULTLIB:libcmt.lib` gets the static runtime with no flag
overrides), plus a tiny C shim exporting `openssl3_build_info()`.

## Consequences
- One place controls naming, exports and platform flags; identical for CI and `local_build`.
- The Windows `.def` and ELF version script come from OpenSSL's `util/mkdef.pl`, so they track
  upstream's own ABI list.
- Deviates from the brief's literal `Configure shared …` flag list; the resulting artifact is
  what the brief asks for.
