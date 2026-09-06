# 0006 — Web/WASM in the same package, wasm not in the tarball

Status: Accepted (2026-09-06)

## Context
The brief allows either a separate `openssl3_wasm` package or conditional imports inside one
package. `package:sqlite3` ships `sqlite3/wasm.dart` in the same package and serves `sqlite3.wasm`
as a release download.

## Decision
One package: `package:openssl3/wasm.dart` with `OpenSSLWasm.load(Uri)`, and `evp.dart`
implemented over `dart:ffi` or `dart:js_interop` via conditional imports. `openssl.wasm` is a
GitHub release asset that apps serve themselves; it is not in the pub tarball.

## Consequences
- One version, one changelog, `platforms: web` on pub.dev once the stretch lands.
- Consumers must host the wasm file; README documents how.
