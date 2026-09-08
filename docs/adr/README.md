# Architecture Decision Records

One file per non-obvious decision. Format: Context, Decision, Consequences.
Statuses: Proposed, Accepted, Superseded.

| # | Title | Status |
|---|---|---|
| [0001](0001-prebuilt-download-not-compile-at-consumer.md) | Prebuilt download, not compile-at-consumer | Accepted |
| [0002](0002-static-archive-plus-own-link-step.md) | Static `libcrypto.a` plus our own link step | Accepted |
| [0003](0003-thin-mach-o-flutter-builds-framework.md) | Thin per-arch Mach-O; Flutter builds the framework | Accepted |
| [0004](0004-toolchains-mirror-openssl-ci.md) | Linux/musl toolchains mirror OpenSSL's own CI | Accepted |
| [0005](0005-no-config-no-module-no-dso.md) | `--openssldir` nowhere, `no-module no-dso`, `initNoConfig()` | Accepted |
| [0006](0006-web-in-same-package.md) | Web/WASM in the same package, wasm not in the tarball | Accepted |
| [0007](0007-fail-closed-hashes-and-release-gate.md) | Fail-closed hashing and the release-PR gate | Accepted |
| [0008](0008-full-libcrypto-abi.md) | Expose the full libcrypto public ABI | Accepted |
| [0009](0009-libcrypto-only.md) | libcrypto only, no libssl | Accepted |
| [0010](0010-version-tracks-openssl.md) | Package version tracks the bundled OpenSSL version | Accepted |
| [0011](0011-supply-chain-pins-and-release-verification.md) | Supply-chain pins and release verification | Accepted |
