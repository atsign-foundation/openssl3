# 0010 — Package version tracks the bundled OpenSSL version

Status: Accepted (2026-09-06)

## Context
Consumers need to (a) pin the exact OpenSSL build they ship, for reproducibility and security
review, and (b) pick up new OpenSSL releases promptly. With an independent package version the
mapping to OpenSSL lives only in a changelog table.

## Decision
The pub version is `<openssl major.minor.patch>+<n>`, e.g. `3.5.8+1`; `n` increments for
package-side changes between OpenSSL releases and resets to 1 on each OpenSSL bump. Pre-releases
use `<ver>-dev.n`. A test asserts that the pubspec version core equals the ABI version in
`symbols.dart` and the OpenSSL version in `manifest.dart`.

A scheduled workflow (`openssl-update.yml`, `tool/bin/check_upstream.dart`) watches upstream tags
on the configured release line and opens a PR that bumps the submodule, the version, the
generated symbol table and bindings, and the changelog.

## Consequences
- `openssl3: 3.5.8+1` pins an exact build; `^3.5.8` follows OpenSSL 3.x; `'>=3.5.0 <3.6.0'`
  stays on the LTS line. Pub orders build numbers, so `+2 > +1`.
- The Dart API of this package must remain backwards compatible while OpenSSL 3.x does; a
  breaking Dart change would have to wait for OpenSSL 4 or ship as a differently named package.
- Reverses the first draft's "independent 0.1.0" default (PLAN.md Q6).
