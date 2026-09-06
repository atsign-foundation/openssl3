# 0001 — Prebuilt download, not compile-at-consumer

Status: Accepted (2026-09-06)

## Context
`pub.dev/packages/openssl` (LucazzP) compiles OpenSSL from source inside `hook/build.dart` at every
consumer's build. That needs Perl, a C toolchain and minutes of CPU on each developer machine and
CI runner, and on Windows it downloads Strawberry Perl and jom at build time. `package:sqlite3`
≥ 3.0 instead downloads a sha256-pinned prebuilt library from its own GitHub release.

## Decision
Follow sqlite3: CI builds every target, a release carries the binaries and `manifest.json`, the
hook downloads the one matching `(os, arch, sdk)` into `outputDirectoryShared`, verifies sha256
and emits a `CodeAsset`. Compiling from source stays available behind `local_build: true`.

## Consequences
- Zero toolchain requirements for consumers; deterministic bytes across machines.
- The package must publish binaries before the Dart package (see ADR-0007).
- A network fetch at first build; `url_pattern`, `local_path` and a warm cache cover offline use.
