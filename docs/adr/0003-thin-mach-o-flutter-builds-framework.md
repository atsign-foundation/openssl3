# 0003 — Thin per-arch Mach-O; Flutter builds the framework

Status: Accepted (2026-09-06)

## Context
The brief asks for a universal `.dylib` wrapped as `.framework` and an `.xcframework` for iOS.
`code_assets` 2.0.0 validates bundled libraries and rejects multi-architecture Mach-O because
"hooks run once per target architecture". flutter_tools (`native_assets_host.dart`) lipo's the
per-arch dylibs it receives into a fat binary, wraps it in `<name>.framework`, rewrites install
names and ad-hoc codesigns.

## Decision
The hook emits thin dylibs per `(os, sdk, arch)`. Framework wrapping and signing are left to
flutter_tools. `release.yml` additionally publishes `openssl3_crypto.xcframework.zip` as a
convenience for non-hooks consumers; the hook never uses it.

## Consequences
- Works with `code_assets` 1.x and 2.x validation.
- Release carries five Apple dylibs (macOS arm64/x64, iOS arm64, iOS-sim arm64/x64).
