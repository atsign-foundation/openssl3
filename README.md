# openssl3

<!-- pyml disable-num-lines 4 md013,md033-->
<a href="https://atsign.com#gh-light-mode-only"><img width=250px src="https://atsign.com/wp-content/uploads/2022/05/atsign-logo-horizontal-color2022.svg#gh-light-mode-only" alt="The Atsign Foundation"></a><a href="https://atsign.com#gh-dark-mode-only"><img width=250px src="https://atsign.com/wp-content/uploads/2023/08/atsign-logo-horizontal-reverse2022-Color.svg#gh-dark-mode-only" alt="The Atsign Foundation"></a>

Prebuilt OpenSSL 3.5 LTS `libcrypto` for Dart and Flutter, delivered as a
[code asset](https://dart.dev/tools/hooks) by the `openssl3` pub package, with
`@Native` bindings for the complete public libcrypto API.

**Package documentation:** [packages/openssl3/README.md](packages/openssl3/README.md)

## Repository layout

<!-- pyml disable-num-lines 9 md013-->
| Path | What |
|---|---|
| [`packages/openssl3/`](packages/openssl3/) | the published package: `hook/build.dart`, generated bindings, `evp.dart`, the native build pipeline |
| [`tool/`](tool/) | CLIs used by CI and maintainers: build a target, generate symbols/bindings/manifest, watch upstream |
| [`example/cli/`](example/cli/) | Dart CLI smoke test (`dart build cli`) |
| [`example/e2e/`](example/e2e/) | iperf3-style end-to-end test: hybrid X25519 + ML-KEM-768 handshake, ML-DSA-65 identity, AES-GCM or AES-CTR + HMAC over TCP |
| [`example/flutter_app/`](example/flutter_app/) | Flutter smoke app with an integration test |
| [`third_party/openssl`](third_party/openssl) | git submodule pinned to the bundled OpenSSL tag |
| [`docs/adr/`](docs/adr/) | architecture decision records |
| [`PLAN.md`](PLAN.md) | the design, target matrix, CI design and decision log |

## How a release works

1. CI builds `libopenssl3_crypto` for 16 targets from the pinned OpenSSL tag,
   verifies each binary (exported ABI, SONAME, dependencies, Android page
   alignment) and attaches them plus `manifest.json` to a GitHub release.
2. The sha256 of every asset is compiled into the package
   (`lib/src/manifest.dart`) through an automated PR; the hook refuses anything
   that does not match.
3. Consumers run `dart pub add openssl3` and build. No OpenSSL, Perl or C
   compiler is needed on their machine.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the exact steps, and
[MIGRATION.md](MIGRATION.md) if you come from a system `libcrypto` or from
`package:openssl`.

## Why "openssl3"

Named after [`package:sqlite3`](https://pub.dev/packages/sqlite3), whose
build-hook design (prebuilt library downloaded by sha256, hashes pinned by CI,
never by hand) this repository ports to OpenSSL. Library plus major version, as
sqlite3 did.

## Maintainers

Created by
[Colin Constable](https://github.com/cconstab),
[Chris Swan](https://github.com/cpswan),
[Gary Casey](https://github.com/gkc).
