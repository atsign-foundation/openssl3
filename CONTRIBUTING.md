# Contributing to openssl3

Thanks for helping. This document covers the things that are specific to this
repository: how the native libraries are built and verified, how the OpenSSL
version is bumped, and how a release gets its hashes. General conduct rules are
in [code_of_conduct.md](code_of_conduct.md); security reports go through
[SECURITY.md](SECURITY.md).

## Prerequisites

- Dart SDK ≥ 3.10 (Flutter ≥ 3.38 for the Flutter example).
- To build the native library locally: Perl 5, `make`, and the platform C
  toolchain (Xcode CLT on macOS, gcc on Linux, MSVC + NASM on Windows). Consumers
  of the published package never need these; only this repository does.
- To regenerate bindings: libclang (Xcode CLT provides it on macOS;
  `apt install libclang-dev` on Linux).

```sh
git clone --recurse-submodules https://github.com/cconstab/openssl3
cd openssl3
dart pub get
dart run tool/bin/build_openssl.dart --list          # target ids
dart run tool/bin/build_openssl.dart macos-arm64     # ~30 s; writes out/
cd packages/openssl3 && dart test                     # hook + FFI tests
```

Inside this repository the workspace root `pubspec.yaml` points the hook at
`out/` (`hooks: user_defines: openssl3: test_directory: out`) so that tests and
examples exercise freshly built binaries. On a fresh clone `out/` is empty and
the hook warns and emits **no** library (any native call would then fail).
Either build your host target as above, or fetch the released build instead of
compiling (no toolchain needed):

```sh
gh release download v3.5.8-1 --pattern 'libopenssl3_crypto.x64.linux.so*' --dir out
```

The pattern must match both the library and its `.json` sidecar; the hook
verifies the file against the sidecar's sha256.

## Before every commit

```sh
dart format packages tool example/cli example/e2e
dart analyze --fatal-infos packages tool example/cli example/e2e
cd packages/openssl3 && dart test
```

Format with the **latest stable Dart SDK**: CI and pub.dev's pana use it, and
the formatter's output changes between SDK releases. `tool/bin/generate_bindings.dart`
formats its output the same way, so regenerate bindings with that SDK too.

Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `ci:`, `docs:`, `chore(openssl):` …). Keep them small and
reviewable. Never hand-edit generated files (`lib/src/symbols.dart`,
`lib/src/third_party/*.g.dart`, `lib/src/manifest.dart`); CI checks they match
their generators.

## Repository tour

| Path | Purpose |
|---|---|
| `packages/openssl3/hook/build.dart` | the build hook: picks the target, obtains the library (download / local_path / system / test_directory), emits the code asset |
| `packages/openssl3/lib/src/hook/` | user-define parsing, download + sha256 cache, supported target table (shared with the tooling) |
| `packages/openssl3/lib/src/native_build/` | Configure → make → link → verify pipeline used by CI and by `local_build` |
| `packages/openssl3/src/native/openssl3_shim.c` | the one extra exported symbol, `openssl3_build_info()` |
| `tool/bin/build_openssl.dart` | build one target into `out/` (+ `.json` sidecar with sha256 and build info) |
| `tool/bin/gen_symbols.dart` | `lib/src/symbols.dart` from OpenSSL's `util/libcrypto.num` |
| `tool/bin/generate_bindings.dart` | ffigen over every public header → `openssl.g.dart` (+ docs, `@Deprecated`, `unbound_symbols.g.dart`) |
| `tool/bin/write_manifest.dart` | `manifest.json` + `lib/src/manifest.dart` from `out/`; `--assert` for the release gate |
| `tool/bin/check_upstream.dart` | find newer OpenSSL tags; `--apply` performs the bump |
| `docs/adr/` | why things are the way they are; add an ADR for any non-obvious decision |

## Bumping OpenSSL

Normally the weekly `openssl-update.yml` workflow does this and opens a PR.
By hand:

```sh
dart run tool/bin/check_upstream.dart                # report
dart run tool/bin/check_upstream.dart --apply        # submodule, version, symbols, bindings, changelog
dart run tool/bin/build_openssl.dart <host-target>   # rebuild out/
cd packages/openssl3 && dart test
```

`--line 3.6` (or `latest`) moves off the 3.5 LTS line; the package version
follows (`3.6.x+1`), which under `^3.5.8` constraints consumers will pick up,
consistent with OpenSSL's 3.x API/ABI compatibility promise (ADR-0010).

Review the diff of `symbols.dart` and `unbound_symbols.g.dart`: added symbols
are expected, removed ones need a CHANGELOG note.

## Changing the native build

`packages/openssl3/lib/src/native_build/targets.dart` holds Configure targets
and flags; `supported_targets.dart` holds the target ids and file names shared
with the hook. Run `build_openssl.dart` for at least your host, and let
`build-natives.yml` (manual dispatch) exercise the rest. `verify.dart` must
keep passing: exports == ABI list, required symbols present, SONAME correct, no
system libcrypto dependency, 16 KB alignment on Android.

## How a release gets its hashes (ADR-0007)

Hashes never enter the repository by hand.

1. Make sure `packages/openssl3/pubspec.yaml` has the final version, e.g.
   `3.5.8+1`, and CHANGELOG is updated. Commit to `trunk`.
2. Tag it. Git refs cannot contain `+`, so the tag spells the build with a
   dash: `git tag v3.5.8-1 && git push origin v3.5.8-1`.
3. `release.yml` builds all 16 libraries (with provenance attestations),
   creates a **draft** GitHub release with the binaries and `manifest.json`,
   regenerates `lib/src/manifest.dart` from the uploaded bytes and opens the
   PR `chore(release): pin v3.5.8-1 asset hashes` (label `release-hashes`).
4. Review and merge that PR. `release-check` then re-downloads the release
   assets, asserts `manifest.dart` matches them byte for byte, runs the hook
   tests against the real release URL, `dart pub publish --dry-run` and pana,
   moves the tag to the merge commit and publishes the release.
5. Publish to pub.dev **by hand** from that commit:

   ```sh
   git fetch --tags && git checkout v3.5.8-1
   cd packages/openssl3 && dart pub publish
   ```

If anything fails in step 4 the release stays a draft and nothing is
published. To retry, delete the draft release and the tag and start again from
step 2.

## Regenerating bindings

```sh
dart run tool/bin/generate_bindings.dart          # needs libclang
dart run tool/bin/generate_bindings.dart --check  # what CI runs
```

Generation-time header patches (`BN_ULONG`, `ossl_ssize_t` → pointer-sized
typedefs) are documented in the generator; if OpenSSL changes those headers the
generator fails loudly rather than emitting wrong widths.

## Tests

- `dart test --exclude-tags ffi` needs no native library (hook logic, ABI
  parsing, version consistency).
- `dart test` (all) also runs the FFI suite through the hook-bundled library:
  known-answer vectors (GCM, ChaCha20-Poly1305, NIST CTR, RFC 7748) and
  ML-KEM-768 / ML-DSA-65 fixtures generated with python-cryptography
  (`test/evp/vectors/`).
- `example/e2e` is the end-to-end test (`dart test`, then `dart run bin/openssl3_e2e.dart selftest`); CI also runs it as two processes from a `dart build cli` bundle
- `example/cli` and `example/flutter_app` are the consumer-side smoke tests
  used by `verify.yml`.
- `upstream-tests.yml` runs OpenSSL's own `make test` (linux x64 and arm64)
  with this package's Configure flags minus `no-tests`/`no-apps`, weekly and
  on submodule bumps. Locally: `dart run tool/bin/build_openssl.dart
  --print-configure linux-x64 | grep -vx -e no-tests -e no-apps`, then
  `perl ../third_party/openssl/Configure <args> && make && make test` out of tree.
