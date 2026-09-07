# PLAN — `openssl3`: prebuilt OpenSSL 3.5 LTS libcrypto as a Dart code asset

Status: **implemented through milestone 9 on 2026-09-06 (see §12 for what is proven, what is not,
and what remains).**
Date: 2026-09-06.

Everything below is grounded in sources read today. Where I borrowed a design I say from where.
Numbers (versions, hashes, tags) are the ones I observed, not invented; hashes will only ever be
produced by CI.

---

## 0. Facts established during research

| Fact | Value / source |
|---|---|
| Newest OpenSSL 3.5 LTS tag | `openssl-3.5.8`, commit `f4dc4d58b48d346a8270183f89acf826d459b0ca` (2026-08-25), `SHLIB_VERSION=3` (`git ls-remote`, `VERSION.dat`) |
| Hooks stable since | Dart 3.10 / Flutter 3.38; link hooks + tree-shaking since Dart 3.13 (dart.dev/tools/hooks) |
| `dart build cli` | Introduced Dart 3.10; runs hooks; emits `bundle/bin/` + `bundle/lib/` (dart.dev/tools/dart-build) |
| `dart compile exe` | Does **not** run build hooks; dart-lang/skills says: "If bundling code assets and dynamic libraries: Use `dart build cli`" |
| Local toolchain | Dart 3.11.5, Flutter 3.41.9 (stable), Xcode clang, perl 5, cmake, ninja; no emcc |
| Latest stable Flutter | 3.47.1 with Dart 3.13.1 (web search, 2026-08-19) |
| pub packages (latest, publisher) | `hooks` 2.2.0 (dart.dev), `code_assets` 2.0.0 (dart.dev), `native_toolchain_c` 0.19.4 (**labs.dart.dev**), `ffigen` 21.0.0 (tools.dart.dev), `crypto` 3.0.7, `ffi` 2.2.0, `path`, `meta`, `web`, `logging` (dart.dev) |
| `code_assets` 2.0.0 breaking behaviour | Validates bundled dylib headers against target arch and **rejects multi-architecture Mach-O** ("hooks run once per target architecture") |
| `package:sqlite3` 3.5.2 constraints | `sdk >=3.10.0 <4.0.0`, `hooks ^2.2.0`, `code_assets >=1.0.0 <3.0.0`, `native_toolchain_c >=0.17.5 <0.20.0`, `ffigen ^21` (dev) |
| Flutter iOS/macOS packaging | flutter_tools itself lipo's per-arch dylibs into a fat binary, wraps it in `<name>.framework`, rewrites install names, ad-hoc codesigns (`native_assets_host.dart`) |
| GitHub-hosted arm64 runners | `ubuntu-24.04-arm`, `ubuntu-22.04-arm`, `windows-11-arm` free for public repos (GitHub changelog 2025-08-07) |
| pub.dev name availability | `openssl3` → 404 (free); `openssl3_wasm` also free |
| Target GitHub repo | remote is `cconstab/openssl3` (public, not a fork); `atsign-foundation/openssl3` does not exist yet |
| at_chops | now lives in `atsign-foundation/at_client_sdk/packages/at_chops` (3.6.1, `sdk ^3.6.0`); FFI tests tagged `@Tags(['ffi'])` |
| OpenSSL's own public ABI list | `util/libcrypto.num`: 5 926 entries, 1 031 of them `DEPRECATEDIN_*`; `util/mkdef.pl` renders it as a `.def` / version script |
| Stock libcrypto for scale | Homebrew `libcrypto.3.dylib` (arm64): 4.86 MB, 8 118 exported text symbols |
| Full-API binding precedent | pub `openssl` 1.0.1 (LucazzP): 6 882 `@Native` externals in one 2.4 MB file; **pub score 70/160**, no platform tags |

### 0.1 Exact OpenSSL symbol set at_chops calls today

From `openssl_loader.dart`, `aes_gcm_ffi_algo.dart`, `x25519_ffi_algo.dart`, `ml_kem_768_ffi.dart`,
`ml_dsa_65_ffi.dart`, `x_wing_ffi.dart` (X-Wing composes the ML-KEM and X25519 classes):

```
CRYPTO_free
EVP_CIPHER_CTX_ctrl EVP_CIPHER_CTX_free EVP_CIPHER_CTX_new EVP_CIPHER_fetch EVP_CIPHER_free
EVP_DecryptFinal_ex EVP_DecryptInit_ex EVP_DecryptUpdate
EVP_EncryptFinal_ex EVP_EncryptInit_ex EVP_EncryptUpdate EVP_aes_256_gcm
EVP_DigestSign EVP_DigestSignInit EVP_DigestVerify EVP_DigestVerifyInit
EVP_MD_CTX_free EVP_MD_CTX_new
EVP_PKEY_CTX_free EVP_PKEY_CTX_new EVP_PKEY_CTX_new_from_name
EVP_PKEY_decapsulate EVP_PKEY_decapsulate_init EVP_PKEY_encapsulate EVP_PKEY_encapsulate_init
EVP_PKEY_derive EVP_PKEY_derive_init EVP_PKEY_derive_set_peer
EVP_PKEY_free EVP_PKEY_fromdata EVP_PKEY_fromdata_init EVP_PKEY_get1_encoded_public_key
EVP_PKEY_get_raw_private_key EVP_PKEY_get_raw_public_key EVP_PKEY_keygen EVP_PKEY_keygen_init
EVP_PKEY_new_raw_private_key EVP_PKEY_new_raw_private_key_ex
EVP_PKEY_new_raw_public_key EVP_PKEY_new_raw_public_key_ex
OSSL_PARAM_BLD_free OSSL_PARAM_BLD_new OSSL_PARAM_BLD_push_octet_string OSSL_PARAM_BLD_to_param OSSL_PARAM_free
```

Algorithm names used: `"ML-KEM-768"`, `"ML-DSA-65"`, `"X25519"`, cipher `"AES-256-GCM"`; OSSL_PARAM keys `"seed"`, `"pub"`.
All are in the `EVP_*` / `OSSL_PARAM*` / `CRYPTO_*` families the brief asks us to keep. Everything
at_chops needs is covered by the export list in §4.4.

### 0.2 AES-CTR is a hard requirement (NoPorts)

`noports_core` (sshnoports) depends on at_chops and protects its session keys (`aesKeyC2D`,
`aesKeyD2C`, `relayAuthAesKey`) with at_chops's `AESEncryptionAlgo`, which is **AES-CTR with 128,
192 or 256-bit keys and no MAC**, today implemented in pure Dart via `package:cryptography`
(`aes_ctr_factory.dart`). at_chops has *no* FFI CTR class yet, so this is a new FFI algorithm, not
a migration. Requirements this adds:

- `EVP_aes_128_ctr`, `EVP_aes_192_ctr`, `EVP_aes_256_ctr` (plus fetch-by-name `"AES-128-CTR"`,
  `"AES-192-CTR"`, `"AES-256-CTR"`) are in the default provider, so `no-legacy` does not affect
  them. With the full-ABI export decision in §2.4 they are exported automatically; the
  required-symbols guard in §4.3 still names them so a future build-flag change cannot silently
  drop them.
- `evp.dart` gets `Cipher.aesCtr(key, {int keyBits})` with one-shot `encrypt/decrypt` **and** a
  streaming `update()/finish()` form (repeated `EVP_EncryptUpdate` keeps the counter state), because
  NoPorts moves streams, not just short strings. CTR is malleable; docs point to `Aead.aes256Gcm`
  when integrity is needed.
- `OpenSSLCapabilities.hasAesCtr`.
- Tests: NIST SP 800-38A §F.5 CTR vectors (128/192/256), cross-check against
  `package:cryptography` output so at_chops's pure-Dart fallback and the FFI path are
  byte-identical, streaming == one-shot.
- Example CLI and Flutter app add an AES-256-CTR round trip; `verify.yml` smoke test asserts it.
- The wasm size-trimming pass in §6 may drop algorithm families, but never AES-CTR/GCM,
  X25519, ML-KEM, ML-DSA, SHA-2/3, HMAC, HKDF.

---

## 1. Architecture

```
consumer app  ──dart build cli / flutter build──►  hooks runner
                                                      │ runs
                                        openssl3/hook/build.dart
                                                      │
              ┌───────────────────────────────────────┼─────────────────────────────┐
              │ default                               │ user_defines                │
              ▼                                       ▼                             ▼
   lib/src/manifest.dart (generated,          local_path / url_pattern       local_build: true
   compiled into package; filename →          / system: true                 perl Configure + make
   sha256, size, openssl commit)                                             (needs Perl + C toolchain)
              │
              ▼
   download github.com/cconstab/openssl3/releases/download/v<pkgver>/<file>
   into input.outputDirectoryShared/<sha-prefix>/, verify sha256 (fail closed)
              │
              ▼
   CodeAsset(package: openssl3, name: src/third_party/openssl.g.dart,
             linkMode: DynamicLoadingBundled(), file: <thin per-arch library>)
              │
              ▼
   Dart:  @Native(assetId: 'package:openssl3/src/third_party/openssl.g.dart') externals
          ├─ lib/openssl3.dart   (raw bindings + OpenSSLCapabilities + initNoConfig)
          └─ lib/evp.dart              (thin: Aead.aes256Gcm, X25519, MlKem768, MlDsa65, Random)
```

Borrowed wholesale from `simolus3/sqlite3.dart` (`sqlite3/hook/build.dart`,
`lib/src/hook/compile/description.dart`, `lib/src/hook/assets.dart`, `asset_hashes.dart`):

- The **sealed "binary source" class** (`PrecompiledFromGithubAssets` / `PrecompiledForTesting` /
  `LookupSystem` / `CompileFromSource`) selected from `input.userDefines`.
- **Streaming sha256 verification** while downloading, `.tmp` + rename, cache re-validation by
  re-hashing the existing file in `outputDirectoryShared/download-<sha8>/`.
- **Fixed on-disk file name per OS** ("We need the file name to be the same because of constraints
  on Apple platforms") — the per-target discriminator lives in the *directory*, not the file name.
- `url_pattern` with `$RELEASE_TAG` / `$FILENAME` placeholders; `HttpClient.findProxyFromEnvironment`
  (Dart ≥ 3.11 passes proxy env vars to hooks); the descriptive `CouldNotDownloadException`.
- A generated **hash table compiled into the package** with a `releaseTag` constant, written by a
  tool and *asserted* (not regenerated) at release time (`tool/write_asset_hashes.dart` pattern).
- `-Wl,-Bsymbolic` + a **linker version script** on Linux, to avoid resolving internals against
  an already-loaded system copy (dart-lang/native#2724). sqlite3 builds that script from its list
  of *used* symbols; we render OpenSSL's own `util/libcrypto.num` instead (§2.4), because the
  whole public ABI is exported.
- Test mode `source: test-…` + `directory:` so the package's own tests run against freshly built
  binaries before any GitHub release exists (`tool/hook_overrides.dart`).
- `ffigen` driven from a Dart script (`tool/generate_bindings.dart`) with
  `NativeExternalBindings(assetId: …)`.

Borrowed from `LucazzP/openssl_dart` (pub `openssl` 1.0.1): the `(OS, Architecture, IOSSdk) →
OpenSSL Configure target` table (`resolveConfigName`), the "**every public header** under
`include/openssl/`, drop `_`-prefixed declarations" ffigen approach, and the reminder that those
headers must be **generated by running `Configure`** (28 `*.h.in` files such as
`configuration.h.in`, `opensslv.h.in`, `core_names.h.in`, `x509.h.in`). Explicitly *not*
borrowed: compiling OpenSSL at the consumer's build (their default), downloading Strawberry Perl /
jom at hook time, and shipping the generated file undocumented (their 70/160 pub score).

### 1.1 Repository / workspace layout

The repo is currently an atsign template (`melos.yaml`, placeholder `pubspec.yaml`, template docs).
It becomes a pub workspace (no melos):

```
/                              pubspec.yaml  (workspace root, sdk >=3.10.0)
├── PLAN.md  README.md  CHANGELOG.md  MIGRATION.md  CONTRIBUTING.md  LICENSE (BSD-3, keep)
├── docs/adr/                  ADR-0001 … (one file per non-obvious decision, list in §8)
├── packages/openssl3/   the published package (see below)
├── example/
│   ├── cli/                   Dart CLI: version, AES-256-GCM, AES-256-CTR, X25519, ML-KEM-768 (dart build cli)
│   └── flutter_app/           Flutter app doing the same four calls on screen
├── tool/                      CI scripts (Dart): build_openssl.dart, link_asset.dart,
│                              write_manifest.dart, verify_exports.dart, hook_overrides.dart
├── third_party/openssl/       git submodule @ openssl-3.5.8 (repo-side only, see §1.2)
└── .github/workflows/         build-natives.yml release.yml verify.yml offline.yml web.yml ci.yml
```

`packages/openssl3/`:

```
pubspec.yaml            name: openssl3, sdk '>=3.10.0 <4.0.0', platforms: android ios linux macos windows (web later)
hook/build.dart
lib/openssl3.dart          barrel: bindings + capabilities + initNoConfig
lib/evp.dart                     thin idiomatic layer
lib/wasm.dart                    (stretch) OpenSSLWasm.load(Uri)
lib/src/third_party/openssl.g.dart   ffigen output (@Native), full libcrypto public API, doc-annotated (§4.3)
lib/src/capabilities.dart
lib/src/manifest.dart            GENERATED: releaseTag + filename→(sha256,size) + openssl commit/version
lib/src/hook/…                   binary_source.dart, prebuilt_library.dart, download.dart, local_build.dart
lib/src/evp/…                    ffi and (stretch) wasm backends behind conditional imports
lib/src/symbols.dart             GENERATED from util/libcrypto.num: the exported ABI (used by tests + wasm export list)
third_party/openssl/LICENSE.txt, NOTICE   copied from the pinned tag (Apache-2.0)
ffigen.yaml                      documentation-only mirror of tool/generate_bindings.dart config
test/                            hook unit tests + FFI round-trip tests (tag ffi)
```

**Decision: web/WASM folds into the main package** behind conditional imports (`dart:ffi` vs
`dart:js_interop`), exactly like `package:sqlite3` (`sqlite3/wasm.dart`). One pub entry, one
`platforms:` list including `web`, one version. `openssl.wasm` is a release asset, never in the
tarball. Rationale in ADR-0006.

### 1.2 Why the OpenSSL source is *not* shipped in the tarball, and what `local_build` does

`dart pub publish` uses `git ls-files`; a submodule shows up as a gitlink only, so
`third_party/openssl` is **absent from the published package**. Therefore:

- The submodule serves CI builds, header generation and bindings regeneration.
- `local_build: true` on a consumer machine downloads the pinned
  `openssl-3.5.8.tar.gz` release tarball (its sha256 is *also* recorded in `manifest.dart` by CI,
  never typed by hand) into `outputDirectoryShared`, or uses `source_path:` if the user points at a
  checkout. This mirrors sqlite3's `DownloadAmalgamation` + `source: source, path:`.
- `native_toolchain_c` ended up **not** being a dependency: the pipeline drives `perl Configure`,
  `make libcrypto.a` and the final link with the compiler OpenSSL's own Makefile selected, which
  also covers the shim objects, so `CBuilder` had nothing left to do. Dropping it also removed
  a dependency chain that constrained which Flutter stable releases can resolve the package
  (hooks ≥ 2.1 → record_use 1.x → meta 1.19, unavailable before Flutter 3.47). `local_build`
  will reuse `input.config.code.cCompiler` for toolchain discovery when it lands. README
  documents "requires Perl 5 + C toolchain + ~10 minutes".

---

## 2. Native library design

### 2.1 Build recipe (identical for CI and `local_build`)

1. `perl Configure <target> no-shared no-module no-legacy no-apps no-tests no-docs no-engine no-dso
   no-async(where noted) no-ssl-trace no-comp no-zlib --openssldir=/nonexistent/openssl3
   --api=3.0 no-deprecated --release`
   - `no-shared` on purpose: we build **`libcrypto.a` only** (`make build_libs` builds
     `libcrypto.a`; `libssl.a` is skipped via `make libcrypto.a` target — verified in
     `unix-Makefile.tmpl`: `LIBS=` lists both, individual targets exist).
   - `no-module` ⇒ default provider compiled in, nothing loaded from disk; `no-dso` ⇒ no `dlopen`
     machinery; `no-legacy` drops the legacy provider (INSTALL.md §no-module/no-dso/no-legacy).
   - `no-async`: OpenSSL already disables it for iOS (`15-ios.conf: disable => ["async"]`); we
     add it for Android (bionic has no `ucontext`), musl, and Emscripten.
   - **Default API level, deprecated functions kept** (no `--api=`, no `no-deprecated`): the
     brief asks for the full surface, and 1 031 of the 5 926 ABI entries are deprecated-but-present
     in every stock libcrypto (`RSA_*`, `EC_KEY_*`, `HMAC()`, `AES_*`, …). Code migrating from a
     system libcrypto or from `LucazzP/openssl` may call them. Open question Q10.
   - Keep `asm` on (except wasm and Windows arm64 where the toolchain lacks a working assembler
     flow on the runner — decided per target in the matrix).
2. **Own link step** (tool/link_asset.dart) produces `libopenssl3_crypto.{so,dylib}` /
   `openssl3_crypto.dll` from `libcrypto.a`:
   - Distinct **file name and SONAME/install-name** (`-Wl,-soname,libopenssl3_crypto.so`,
     `-install_name @rpath/libopenssl3_crypto.dylib`). No collision with a process that already
     has `libcrypto.so.3` / `libcrypto.3.dylib` loaded; dlopen treats it as a different library.
   - **Export list = OpenSSL's complete public ABI** (§2.4): `perl util/mkdef.pl --name CRYPTO
     --ordinals util/libcrypto.num --version 3.5.8 --OS {linux|windows|darwin}` yields the GNU
     version script, `.def`, and exported-symbols list OpenSSL itself would use for its shared
     build, filtered by the same feature flags (`no-legacy` etc.). Internal symbols stay `local:`.
     Dead-stripping (`-Wl,--gc-sections`, `-dead_strip`, `/OPT:REF`) is kept but expected to remove
     little, since everything public is reachable.
   - `-Wl,-Bsymbolic` on ELF (sqlite3's fix for dart-lang/native#2724).
   - Android: `-Wl,-z,max-page-size=16384` (16 KB pages; `15-android.conf` does not add it), NDK
     r27, `__ANDROID_API__=21`, link `-lm -ldl` only.
   - Windows: static CRT. With `no-shared`, OpenSSL's `VC-*` configs compile the static library
     with `/MT /Zl` already (`10-main.conf`, `lib_cflags`), so no flag override is needed; our
     `link /DLL /DEF:… /DEFAULTLIB:libcmt.lib` step completes it. Import `.lib` produced as a
     secondary artifact.
   - Apple: thin per-arch Mach-O (see 2.2), `-headerpad_max_install_names`, min versions
     macOS 10.15 / iOS 13 (Flutter's floors), ad-hoc `codesign -s -`.
3. A 40-line C shim `openssl3_shim.c` is linked in. It exposes exactly one extra symbol,
   `openssl3_build_info()`, returning the JSON string embedded at link time (OpenSSL commit,
   Configure line, compiler `--version`, flags). That makes the binary self-describing, lets the hook
   cross-check `manifest.dart` at test time, and gives `OpenSSLCapabilities.buildInfo`.

Why "static archive + own link" instead of OpenSSL's `shared` build: it gives us the distinct
SONAME, the export-list stripping, `/MT`, 16 KB alignment and `-Bsymbolic` in one place without
patching Configure or post-processing with `patchelf`/`install_name_tool` (OpenSSL's
`shlib_variant` only *appends* to the name). ADR-0002. This departs from the brief's literal
`Configure shared …` flag list; the resulting library is what the brief asks for.

### 2.2 Deviation: no universal (fat) `.dylib`, no `.xcframework` in the hook path

`code_assets` 2.0.0 **rejects multi-architecture Mach-O** in the validator, and Flutter builds each
architecture through a separate hook invocation, then lipo's the thin dylibs into
`openssl3_crypto.framework` itself and codesigns it (`native_assets_host.dart:lipoDylibs`,
`frameworkUri`, `codesignDylib`). So the hook emits **thin per-(os, sdk, arch)** dylibs, and the
framework wrapping the brief asks for happens in flutter_tools, not in our package.

To still honour the brief for non-hooks consumers, `release.yml` additionally publishes
`openssl3_crypto.xcframework.zip` (device arm64 + simulator arm64/x64 + macOS arm64/x64)
built with `xcodebuild -create-xcframework` — purely a convenience artifact, unused by the hook.
ADR-0003.

### 2.3 Release file naming (single flat directory, like sqlite3)

`libopenssl3_crypto.<arch>.<os>.<ext>` where `<os>` ∈ `linux`, `linux_musl`, `macos`, `ios`,
`ios_sim`, `android`, `windows`, and `<arch>` uses `Architecture.name` (`x64`, `arm64`, `arm`,
`riscv64`). Plus `openssl.wasm`, `manifest.json`, `openssl3_crypto.xcframework.zip`,
`openssl-3.5.8-source.sha256` (hash of the upstream tarball CI actually used).

`manifest.json` entry: `{target, file, sha256, size, openssl_version, openssl_commit, compiler,
configure_args, link_args, built_by_run_id}`.

### 2.4 Decision: expose the *entire* libcrypto public API, not a curated subset

Requested in review ("as OpenSSL exposes more surfaces we should expose them all"). Consequences:

- **Native**: export list is `libcrypto.num` (≈5 900 symbols, minus feature-disabled ones). The
  shipped library is the same size class as a stock libcrypto: **≈4–5 MB per architecture**
  (Homebrew arm64: 4.86 MB). Stripping to a subset would have saved symbol-table bytes only.
- **Bindings**: ffigen over every generated public header (LucazzP's approach), ≈6 900 declarations
  in one generated file. This is what the brief's "strip symbols not exported by the public headers"
  becomes: *public headers = the whole surface*. §4.3 explains how we avoid the 70/160 pub score
  the existing full-API package has.
- **Regression guard** (§4.3) still exists, now as a *minimum* set that CI asserts is present,
  rather than a maximum that defines the export list.
- **Wasm**: exporting ≈5 900 functions defeats `wasm-opt` dead-code elimination, so the "few MB"
  target is at risk; §6 `web.yml` measures both a full-ABI and a trimmed variant. Open question Q13.
- Unchanged: libcrypto only (no libssl, Q12), `no-legacy` provider (Q11), `no-module no-dso`,
  distinct SONAME, `initNoConfig()`.

---

## 3. Target matrix

| OS | Arch | Configure target | Runner | Toolchain | Notes |
|---|---|---|---|---|---|
| Linux glibc | x64 | `linux-x86_64` | `ubuntu-24.04` | native gcc (as OpenSSL CI) | glibc floor = runner (2.39); "new builds only" accepted |
| Linux glibc | arm64 | `linux-aarch64` | `ubuntu-24.04-arm` | native gcc | native arm runner, no cross toolchain; smoke test same job |
| Linux glibc | riscv64 | `linux64-riscv64` | `ubuntu-24.04` | `gcc-riscv64-linux-gnu` + `--cross-compile-prefix=riscv64-linux-gnu-` (OpenSSL `cross-compiles.yml`) | smoke test under `qemu-user`, `QEMU_CPU=rv64,v=true,vext_spec=v1.0` as OpenSSL does |
| Linux musl | x64 | `linux-x86_64` | `ubuntu-24.04` in `container: alpine:3.20` | apk `build-base perl linux-headers` (OpenSSL `os-zoo.yml`) | smoke test in the same container |
| Linux musl | arm64 | `linux-aarch64` | `ubuntu-24.04-arm` in `container: alpine:3.20` | apk gcc | smoke test in the same container |
| macOS | arm64, x64 | `darwin64-arm64`, `darwin64-x86_64` | `macos-15` | Xcode clang | thin dylibs, `-mmacosx-version-min=10.15` |
| iOS device | arm64 | `ios64-xcrun` | `macos-15` | Xcode | `-miphoneos-version-min=13` |
| iOS simulator | arm64, x64 | `iossimulator-arm64-xcrun`, `iossimulator-x86_64-xcrun` | `macos-15` | Xcode | |
| Android | arm64-v8a, armeabi-v7a, x86_64 | `android-arm64`, `android-arm`, `android-x86_64` | `ubuntu-22.04` | NDK r27 (`ANDROID_NDK_ROOT` on runner) | API 21, 16 KB page alignment |
| Windows | x64 | `VC-WIN64A` | `windows-2022` | MSVC 17, Strawberry Perl, NASM | `/MT` |
| Windows | arm64 | `VC-WIN64-ARM` | `windows-2022` (cross) | MSVC arm64 cross tools | `no-asm`; smoke test on `windows-11-arm` |
| Web (stretch) | wasm32 | `linux-generic32` via `emconfigure` | `ubuntu-22.04` | Emscripten (pinned via `mymindstorm/setup-emsdk`) | `no-asm no-threads no-sock no-stdio no-posix-io` |

Every `(os, arch)` **not** in this table makes the hook throw `UnsupportedError` with the exact pair
and a pointer to `local_build`/`system`/`local_path` (sqlite3's `checkSupported()` message style).
Notably unsupported on purpose: Linux/Android ia32 and arm32-linux (Dart dropped or never had
them), Android x86.

### 3.1 Toolchain decision: what the OpenSSL project itself uses (ADR-0004)

Decided 2026-09-06: **use the toolchains OpenSSL's own CI uses**, not Zig. From the 3.5.8 tree:

- `.github/workflows/ci.yml`: gcc/clang on `ubuntu-latest`, `macos-15`, `windows-2022`.
- `.github/workflows/cross-compiles.yml`: Debian `gcc-<triple>` packages (`gcc-aarch64-linux-gnu`,
  `gcc-riscv64-linux-gnu`, …) with `--cross-compile-prefix=<triple>-` and `qemu-user` for tests.
- `.github/workflows/os-zoo.yml`: musl via `container: alpine:{edge,latest}` with
  `apk add build-base perl linux-headers`.
- `.github/workflows/windows.yml`: MSVC, `choco install nasm`, `perl Configure VC-WIN64A`; arm64
  via `VC-WIN64-ARM` cross tools.

This is also what `package:sqlite3` does for Linux (apt cross-gcc), minus musl, so we are on the
most-travelled path for both the library and the hooks ecosystem. GitHub's free arm64 runners let
us build Linux arm64 (glibc and musl) natively instead of cross-compiling.

glibc floor: first CI runs showed the Ubuntu 24.04-built library needs `GLIBC_2.38` and fails to
load on Debian 12 (2.36), so the x64/arm64 glibc builds run inside `quay.io/pypa/manylinux_2_28` containers
(the same host-driven container mechanism as musl; Debian 11 was tried first but its apt
repositories moved after its August 2026 EOL), giving a floor of **glibc 2.28**; riscv64 is
cross-built on the runner image (2.39). Per the maintainer, only current distributions need to be supported; the
README states the floor and the release manifest records it (`glibc_min`), and `local_build` /
`url_pattern` remain for anyone who needs older. Zig stays documented here as the fallback if a
glibc-floor requirement ever appears.

---

## 4. Dart API

### 4.1 `package:openssl3/openssl3.dart`

- Re-exports `src/third_party/openssl.g.dart` (`@Native` externals, asset id
  `package:openssl3/src/third_party/openssl.g.dart`; no `DynamicLibrary` anywhere).
- `OpenSSLCapabilities`: `versionString`, `versionNumber`, `hasMlKem768`, `hasMlDsa65`,
  `hasX25519`, `hasAesGcm`, `providerList`, `buildInfo` (from the shim). Probes use
  `EVP_PKEY_CTX_new_from_name` / `EVP_CIPHER_fetch` exactly as at_chops's loader does today, so
  the semantics match.
- `initNoConfig()` → `OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG | OPENSSL_INIT_NO_ATEXIT …,
  nullptr)`; idempotent; documented as "call once at startup; `--openssldir` points nowhere".
- `OpenSSLException` built from `ERR_get_error` / `ERR_error_string_n`.

### 4.2 `package:openssl3/evp.dart` (thin, at_chops-sized)

`Aead.aes256Gcm(key).seal/open(nonce, plaintext, aad)`, `Cipher.aesCtr(key).encrypt/decrypt(iv, data)`
plus a streaming `CipherStream` (`update`/`finish`) for NoPorts (§0.2), `X25519.keyPair()/agree()`,
`MlKem768.keyPair()/fromSeed()/encaps()/decaps()`, `MlDsa65.keyPair()/sign()/verify()`,
`Random.bytes(n)`. `Arena`-managed, typed exceptions, no state beyond `EVP_PKEY`/`EVP_CIPHER_CTX`
handles wrapped in `Finalizer`-backed classes. Raw bindings stay primary.

### 4.3 Bindings generation (`tool/generate_bindings.dart`)

1. `tool/bin/generate_bindings.dart` runs `perl Configure <host> … && make build_generated` into
   `.dart_tool/openssl_build/<host>/` (or reuses an existing build dir) to materialise the
   `*.h.in` headers. *Changed from the first draft:* no header snapshot is committed; anyone
   regenerating bindings already needs Perl for the submodule build, and it saves 3 MB of
   generated headers in git. Two generation-time patches keep ABI-variant types right on every
   target: `BN_ULONG` and `ossl_ssize_t` become pointer-sized typedefs (`UintPtr`/`IntPtr`).
2. Entry points: **every** `include/openssl/*.h` from the generated snapshot except `ssl.h`,
   `ssl2.h`, `ssl3.h`, `tls1.h`, `dtls1.h`, `srtp.h`, `quic.h` (libssl, not shipped) and headers for
   features disabled at build time (checked against `configuration.h`'s `OPENSSL_NO_*`).
3. Include filter: everything not `_`-prefixed and not in libssl. Deprecated declarations are
   kept and annotated `@Deprecated('Deprecated in OpenSSL <ver>, see …')` by the post-processor
   (ffigen exposes the clang `deprecated` availability attribute).
4. **Regression guard**: `tool/required_symbols.txt` (the 45 at_chops symbols from §0.1, the
   AES-CTR set from §0.2, `EVP_chacha20_poly1305`, SHA-2/SHA-3/HMAC/HKDF entry points).
   `verify_exports.dart` diffs the built library's exports against `libcrypto.num` (must be equal
   modulo disabled features) **and** asserts the guard list is present. `lib/src/symbols.dart` is
   generated from `libcrypto.num` and used by the wasm export list and by a test that every
   `@Native` in `openssl.g.dart` has a matching export — so bindings and exports cannot drift.
5. Output style `NativeExternalBindings(assetId: …)`; `isLeaf` for pure functions
   (`OpenSSL_version_num`, `ERR_get_error`, `CRYPTO_free`, …).
6. **Pub-score defence.** pana awards points for ≥20 % dartdoc coverage of the *public* API,
   and a raw 6 900-symbol file has 0 %. The existing full-API `openssl` package sits at 70/160
   largely for this reason. `tool/generate_bindings.dart` therefore **post-processes** the ffigen
   output and prefixes every public function/struct/enum with a `///` comment:
   `/// OpenSSL `EVP_PKEY_keygen`. Manual: https://docs.openssl.org/3.5/man3/EVP_PKEY_keygen/`,
   using the man-page index shipped in the OpenSSL tree (`doc/build.info` / `doc/man3/*.pod`
   `=head1 NAME` sections) to map symbols to pages, and a generic "no manual page" note otherwise.
   Deterministic, checked in, and genuinely useful. `// ignore_for_file: type=lint` keeps analyzer
   noise out; `dart analyze` time on the file is measured in CI and must stay under a minute.
7. Function-like **macros are not bound** by ffigen (`BIO_get_mem_data`, `EVP_PKEY_assign_RSA`,
   `EVP_CIPHER_CTX_set_padding`, …). The post-processor emits `lib/src/macros.dart` with hand-
   written Dart equivalents for a documented list (starting with the memory-BIO and
   `EVP_*_CTX_ctrl` helpers), and the README lists which macros have equivalents.
8. Measured (2026-09-06): 3.4 MB generated Dart, 5 702 externals, 10 582 macro constants,
   301 opaque types, 152 structs, 1 689 `@Deprecated` annotations, doc comment on every public
   declaration; `dart analyze` of the package takes under a second. Unused `@Native` externals
   cost nothing at runtime: the AOT compiler tree-shakes them. 94 exported symbols have no
   binding (`unbound_symbols.g.dart`): functions returning raw function pointers
   (`*_meth_get_*`, `UI_method_get_*`) and symbols no public header declares (`DSO_*`,
   `OPENSSL_DIR_*`); a test asserts none of the required symbols is among them.

### 4.4 at_chops integration

All 45 symbols in §0.1 are inside the export list. Because `@Native` bindings have no
`DynamicLibrary`, at_chops's `*.fromLib(DynamicLibrary)` constructors and `_lib.lookupFunction<…>`
calls cannot be pointed at this package unchanged (`asFunction` type arguments must be static, so a
generic `lookupFunction` shim is impossible). Proposed at_chops change (their repo, separate PR):

- Add `AtPqc.backend` selection: `openssl3` (default when the package is present) vs
  `systemLibCrypto` (today's probe) vs `pureDart`.
- Replace `_lib.lookupFunction<X, Y>('sym')` with the generated `sym(...)` externals — a
  mechanical, ~45-site edit; the `*FfiAlgo` bodies are unchanged.
- **New `AesCtrFfiAlgo`** implementing `SymmetricEncryptionAlgorithm` for 128/192/256-bit keys,
  selected by `AtPqc`/`AESEncryptionAlgo` when the bundled library is present, falling back to the
  current `package:cryptography` path. Output must be byte-identical to the pure-Dart path so
  mixed-version NoPorts peers (daemon on FFI, client on pure Dart, or vice versa) interoperate.
- The `--tags ffi` suite runs against the bundled library on Linux/macOS/Windows/Android/iOS with
  no `AT_CHOPS_LIBCRYPTO_PATH`.

Open question Q4 asks whether you want me to include an `OpenSslSymbols` façade in this package
that mirrors at_chops's typedef names to make that diff smaller.

---

## 5. `hook/build.dart` behaviour (spec → implementation mapping)

| Brief item | Implementation |
|---|---|
| Resolve target | `input.config.code.targetOS/targetArchitecture`, `code.iOS.targetSdk/targetVersion`, `code.android.targetNdkApi` (all present in `code_assets` 2.0) |
| Compiled-in table | `lib/src/manifest.dart`: `releaseTag`, `Map<String, AssetInfo>` keyed by release file name |
| Download + cache | `outputDirectoryShared/download-<sha8>/libopenssl3_crypto.<ext>`; re-hash on cache hit; `.tmp` + rename; sha256 mismatch ⇒ throw (fail closed); URL `https://github.com/cconstab/openssl3/releases/download/v<pkgver>/<file>` (see §6.1 on the planned transfer) |
| Emit | `CodeAsset(package: 'openssl3', name: 'src/third_party/openssl.g.dart', linkMode: DynamicLoadingBundled(), file: …)` |
| `url_pattern` | `$RELEASE_TAG`/`$FILENAME` template (sqlite3 syntax) |
| `local_path` | absolute or workspace-relative path (resolved via `userDefines.baseUri`), still sha256-checked **unless** `local_path_unverified: true` — default fails closed |
| `local_build: true` | §1.2; optional `source_path`; toolchain from `cCompiler` config; logs every command |
| `system: true` | `DynamicLoadingSystem(Uri.parse(os.libraryFileName('crypto')))`, with `system_name:` override map per OS (sqlite3's `name:` map) |
| Precedence | `system` > `local_path` > `local_build` > `url_pattern`/default; conflicting combinations throw |
| Determinism | no network on warm cache; `output.dependencies` lists `local_path`/`source_path`; `info` log states the chosen source and why |
| Unsupported pair | `UnsupportedError('openssl3 has no prebuilt libcrypto for <os>/<arch>…')` |
| Test-only | `test_directory:` (CI) — the `PrecompiledForTesting` idea |

Not code assets: when `input.config.buildCodeAssets` is false the hook returns immediately (sqlite3).

---

## 6. CI / release pipeline

All workflows: `permissions: {}` at top, `persist-credentials: false`, pinned action SHAs,
`dart-lang/setup-dart`, `subosito/flutter-action`.

### `ci.yml` (PR + push)
`dart format --set-exit-if-changed`, `dart analyze --fatal-infos`, `dart test` (hook unit tests
with fake downloads; FFI tests skipped unless `test_directory` provided), `pana --exit-code-threshold 0`
target 160, ADR/link check.

### `build-natives.yml` (`workflow_call` + manual)
Matrix over §3; per job: cache keyed on `hashFiles('tool/**', 'third_party/openssl')`; run
`dart run tool/build_openssl.dart <os> <arch>`; `dart run tool/verify_exports.dart` (nm/dumpbin:
exported set == `symbols.dart`, SONAME/install-name correct, no `libcrypto` in `NEEDED`, page
alignment for Android, arch check as code_assets 2.0 will do); upload artifact + `*.sha256`;
`merge` job assembles a flat dir, writes `manifest.json` (`tool/write_manifest.dart`), attests
provenance (`actions/attest`, as sqlite3 does).

### `release.yml` (on tag `v*`)
1. Calls `build-natives.yml`.
2. Creates a **draft** GitHub release `v<ver>`, uploads artifacts + `manifest.json` + xcframework zip.
3. Regenerates `lib/src/manifest.dart` from `manifest.json`, opens PR
   `chore(release): pin v<ver> asset hashes` via `peter-evans/create-pull-request`.
4. **Gate**: a `release-check` job runs on merge of that PR (`pull_request: closed` + label
   `release-hashes` + merged): re-runs `tool/write_manifest.dart --assert v<ver>` (the sqlite3
   "assert, don't regenerate" step), `dart pub publish --dry-run`, `pana`, moves the `v<ver>` tag to
   the merge commit and flips the draft release to published. **Publishing to pub.dev is manual**
   (decision 2026-09-06): the maintainer runs `dart pub publish` from that tagged commit; the job
   summary prints the exact commands. No pub.dev OIDC job, no publisher secrets in CI.
   Chicken-and-egg note: the tag that triggers step 1 points at a commit whose `manifest.dart`
   still holds the *previous* release; the hashes PR is what makes `v<ver>` self-consistent.
   Spelled out in CONTRIBUTING.md.

#### 6.1 Repository transfer
`cconstab/openssl3` will move to `atsign-foundation/openssl3` unchanged. GitHub serves HTTP 301
redirects for the old owner's URLs (including `releases/download/…`) as long as no new
`cconstab/openssl3` is created, and Dart's `HttpClient` follows redirects, so already-published
versions keep working. After the transfer: change the default URL constant, release a patch
version, and keep `url_pattern` as the escape hatch. Both origins are covered by the offline/mirror
tests.

### `verify.yml` (after build-natives; also nightly)
Per platform on a **clean runner**, with a step that asserts no OpenSSL is available to the build
(`! command -v openssl` where possible; on Linux run inside `debian:bookworm-slim` / `alpine` containers
that have no `libssl3`): `dart build cli` for `example/cli` and run it; `flutter build
apk|ios --simulator|macos|windows|linux`; run the Flutter example's `integration_test` on macOS,
Windows, Linux, iOS simulator (`xcrun simctl`), Android emulator (`reactivecircus/android-emulator-runner`,
x86_64). Also runs `dart compile exe example/cli/bin/main.dart` and **records** the observed
behaviour in the job summary; README documents `dart build cli` as the supported path (§0 facts).

### `offline.yml`
Ubuntu + macOS + Windows: pre-download assets, then `sudo ip link set eth0 down` /
`networksetup -setnetworkserviceenabled` / `netsh interface set interface … disable` (or, more
portably, `HTTPS_PROXY=http://127.0.0.1:9` + a `hosts` blackhole for github.com), prove
`local_path`, `url_pattern` (against a `python -m http.server` on localhost) and warm-cache rebuild
all succeed, and that a **wrong sha256 fails**.

### `web.yml` (stretch)
Emscripten build, `dart test -p chrome` with `RAND_bytes` non-determinism test, size report in job
summary (`-Oz`, `no-*` families table). Builds **two** variants and reports both: `openssl.wasm`
(full ABI export, matching native) and `openssl-lite.wasm` (export list = guard list + evp.dart
needs, `wasm-opt` DCE allowed). Which one ships is Q13.

---

## 7. Docs, licensing, compliance

- Package LICENSE: BSD-3-Clause (repo already has it, Atsign Foundation). `third_party/openssl/LICENSE.txt`
  + `NOTICE` from the pinned tag shipped inside the package; README "Third-party licenses" section.
- README sections: install; how it works; user defines (all six); offline/air-gapped; Docker/Alpine
  (glibc floor = runner image, musl build for Alpine); `dart compile exe` vs `dart build cli`; symbol-clash avoidance
  (SONAME, `-Bsymbolic`, test that loads both); export compliance (OpenSSL is publicly available
  encryption source; typical classification ECCN 5D002 with mass-market/open-source
  considerations; App Store `ITSAppUsesNonExemptEncryption` and the annual self-classification
  report; Play Console export questionnaire — phrased as "consult counsel", not legal advice);
  migration from system libcrypto and from `LucazzP/openssl`.
- CHANGELOG (keep-a-changelog), MIGRATION.md, CONTRIBUTING.md (bump OpenSSL: update submodule +
  headers snapshot + regenerate bindings + run build-natives; release hashing flow), `docs/adr/`.

### 6.2 Keeping up with OpenSSL releases
`openssl-update.yml` runs weekly (and on demand): `tool/bin/check_upstream.dart` lists
`openssl-3.*` tags, picks the newest on the configured line (default: the submodule's
major.minor, i.e. the LTS branch; `--line 3.6` or `--line latest` to move), and if it is newer
than the submodule it bumps the submodule, sets the pubspec version to `<ver>+1`, regenerates
`symbols.dart` and the bindings, adds a CHANGELOG entry linking the upstream release notes, and the
workflow opens a PR. Normal CI then builds and tests it; merging and tagging follows §6.
Dependabot cannot do this: its `gitsubmodule` ecosystem tracks branch heads, not release tags.

## 8. ADRs to write

1. Prebuilt download over compile-at-consumer (why not `LucazzP/openssl`'s model).
2. Static `libcrypto.a` + own link step for distinct SONAME, export stripping, `/MT`, 16 KB pages.
3. Thin per-arch Mach-O; Flutter does the framework; xcframework is a convenience artifact.
4. Linux/musl toolchains mirror OpenSSL's own CI (gcc, Debian cross-gcc, Alpine container); no glibc floor pin; Zig documented as fallback.
5. `--openssldir` nowhere + `no-module no-dso`; `initNoConfig()`.
6. Web support inside the same package, wasm not in tarball.
7. Fail-closed hashing and the release-PR gate.
8. Full libcrypto public ABI exported and bound (export list = `libcrypto.num`, bindings over all
   public headers, deprecated API kept); doc post-processing for pub score.
9. libcrypto only, no libssl (nothing in at_chops or the brief needs TLS; halves size; can be
   added later as a second asset).
10. Package version tracks the bundled OpenSSL version (`3.5.8+N`); weekly upstream-tag watcher.

## 9. Milestones (each a small conventional-commit series, `format`/`analyze --fatal-infos`/`test` green)

1. `chore: convert template repo to pub workspace` — remove melos, root pubspec, gitignore, submodule
   at `openssl-3.5.8`, copy OpenSSL LICENSE/NOTICE, ADR skeleton, this PLAN.
2. `feat(openssl3): package skeleton, manifest/symbols generators, hook with fake download tests`.
3. `feat(tool): build_openssl.dart + link_asset.dart + verify_exports.dart` — proven locally for
   macOS arm64 (I have Xcode/perl here) before touching CI.
4. `feat(bindings): headers snapshot + ffigen @Native bindings over all public headers + doc
   post-processor + macros.dart + capabilities + initNoConfig`.
5. `feat(evp): thin layer + FFI tests` (run locally against the macOS build via `test_directory`).
6. `ci: build-natives matrix` (iterate per target; Linux gcc first, then Alpine, Android, Apple, Windows).
7. `feat(example): cli + flutter app`; `ci: verify.yml`, `offline.yml`.
8. `ci: release.yml` with the hashes-PR gate; first `v0.1.0` release dry-run.
9. Docs: README, MIGRATION, CONTRIBUTING, CHANGELOG, ADR bodies; `pana` to 160.
10. Stretch: wasm build, `wasm.dart`, `web.yml`; at_chops PR in `at_client_sdk`.

## 10. Open questions (need your answer before milestone 1; defaults in bold)

1. ~~Repo/org.~~ **Answered 2026-09-06:** stays `cconstab/openssl3`, to be transferred to
   `atsign-foundation` as-is later. Download origin is `cconstab/openssl3`; see §6.1.
2. ~~`native_toolchain_c` publisher.~~ **Answered:** labs.dart.dev is allowed.
3. ~~Linux toolchain.~~ **Answered:** use what the OpenSSL project uses (gcc, Debian cross-gcc,
   Alpine container, MSVC+NASM); only current distributions need support. See §3.1.
4. **at_chops façade.** Should this package ship an `OpenSslSymbols` class mirroring at_chops's
   `Evp*Dart` typedef names so their migration is import-only, or is the ~45-site mechanical edit in
   at_chops acceptable? **Default: no façade; keep this package's surface small.**
5. **Minimum OS versions.** **Default: macOS 10.15, iOS 13, Android API 21, glibc = build runner's (2.39), Windows 10.**
6. ~~Package versioning vs OpenSSL.~~ **Decided 2026-09-06 (maintainer: "allow users to pin to
   releases"):** the package version *is* the bundled OpenSSL version plus a build counter,
   `3.5.8+N`. Pub orders build numbers, so `openssl3: 3.5.8+1` pins one exact build,
   `^3.5.8` follows OpenSSL 3.x (whose API/ABI is stable across minors), and
   `'>=3.5.0 <3.6.0'` stays on the 3.5 LTS line. A test asserts pubspec version core ==
   `symbols.dart` ABI version == manifest OpenSSL version. Consequence: the Dart API of this
   package must stay backwards compatible for as long as OpenSSL 3.x does. ADR-0010.
7. **First release scope.** Ship `v0.1.0` without web, or block on the wasm stretch? **Default:
   ship native first; web in `0.2.0`.**
8. **Windows arm64 assembly.** Build `no-asm` on arm64 (safe, slower) — **default** — or install
   the arm64 assembler flow on the x64 runner.
9. ~~Secrets/permissions.~~ **Answered:** pub.dev publishing is done by hand by the maintainer;
   CI stops at the verified draft release + hashes PR (§6). Still needed from GitHub only:
   `contents: write` for releases (workflow permission) and, if branch protection blocks the
   default token, a PAT/GitHub App for the hashes PR.
10. **Deprecated API.** Full surface now includes the 1 031 deprecated-but-present functions
    (`RSA_*`, `EC_KEY_*`, `HMAC()`, `AES_*`, …), marked `@Deprecated` in Dart. **Default: keep
    them** so the ABI equals a stock libcrypto and migration from system libcrypto is lossless.
11. **Legacy provider.** `no-legacy` currently drops MD4, RC4, DES, Blowfish, CAST, IDEA, SEED,
    RC2, Whirlpool. "Expose all" could be read to include them (+≈300 KB, weak algorithms
    available by default). **Default: stay `no-legacy`**; say if NoPorts needs any of them.
12. **libssl.** Not built. Adding it later is a second code asset (`libopenssl3_ssl`) plus
    `ssl.h`-family bindings; roughly doubles size. **Default: libcrypto only for 0.x.**
13. **Wasm variant.** Full-ABI wasm cannot be dead-code-eliminated and may land well above the
    "few MB" target; a lite variant can. **Default: ship full for API parity, publish lite as a
    second release asset if it is materially smaller.** Decided by the numbers `web.yml` reports.

## 11. Known risks

- `code_assets` 2.0.0 validation is new; sqlite3 pins `>=1.0.0 <3.0.0` — I will do the same and test
  with both 1.x and 2.x resolutions in CI.
- `@Native` in ffigen 21 is still marked experimental in its README although sqlite3 ships it in
  production; if the config API shifts, only `tool/generate_bindings.dart` changes.
- A 2.5 MB / 6 900-declaration generated file slows `dart analyze`, dartdoc and IDE indexing for
  consumers; mitigations are `type=lint` ignores, keeping it under `lib/src/` behind the barrel,
  and measuring analysis time in CI. If it becomes a problem the generator can split output per
  header family (`evp.g.dart`, `x509.g.dart`, …) without changing the public import.
- Doc coverage for pana depends on the post-processor mapping symbols to man pages; a fallback
  generic comment guarantees the ≥20 % threshold regardless.
- Full-ABI export on wasm may miss the size target (Q13).
- riscv64 assembly under Debian cross-gcc is exercised by OpenSSL's own CI; if it misbehaves for us the build script has a per-target `no-asm` switch.
- The verify matrix costs ~40 runner-minutes per run; scheduled nightly + on release, not on every PR.
- App Store review has previously rejected unsigned/ad-hoc dylibs in odd layouts; we rely on
  flutter_tools' framework/codesign path, which sqlite3 already ships through the App Store.

---

## 12. Status (2026-09-06, end of first implementation session)

**Proven locally (macOS arm64 host)**
- Pipeline builds all five Apple targets (macos-arm64/x64, ios-arm64, ios_sim-arm64/x64): 4.8–5.4 MB
  thin dylibs, 5 729 exports each, install name `@rpath/libopenssl3_crypto.dylib`, ad-hoc signed.
- Bundled 3.5.8 loads beside Homebrew OpenSSL 3.6.3 in one process without interference.
- 73 package tests pass, including FFI tests through the hook-supplied asset: GCM spec vector,
  RFC 8439, NIST CTR (128/192/256), RFC 7748, and ML-KEM-768 / ML-DSA-65 fixtures produced by
  python-cryptography (same seed → same public key; OpenSSL decapsulates/verifies python output).
- `dart build cli` bundles `bin/` + `lib/libopenssl3_crypto.dylib`; the example reports 0 failures.
  `dart compile exe` refuses with "does not support build hooks, use dart build".
- `flutter build macos` + `flutter test integration_test -d macos` pass; Flutter wrapped the dylib
  as `openssl3_crypto.framework` itself (ADR-0003 confirmed).
- `local_build: true` through the hook compiles, verifies and bundles in ~20 s on this machine.
- pana: 150/160 locally; the last 10 points are the repository-URL check, which needs the
  commits pushed so the remote contains `packages/openssl3/pubspec.yaml`.

**Proven on GitHub Actions (2026-09-07, after the first push)**
- `build-natives.yml`: all 15 targets build and pass `verify.dart` (exports == ABI, SONAME,
  no system libcrypto, Android 16 KB alignment); Linux glibc x64/arm64 built in
  `manylinux_2_28` containers with a CI assertion that no symbol version exceeds `GLIBC_2.28`;
  riscv64 smoke-tested under qemu-user; musl in Alpine; `manifest.json` with all 15 assets and
  the upstream tarball sha256.
- `ci.yml`: format/analyze/generated-file freshness, hook tests, pana (repository check passes
  now that the package is on the remote), and build + full test suite + `dart build cli` on
  Linux x64, Linux arm64, macOS arm64 and Windows x64.
- `verify.yml` (14 jobs): `dart build cli` on debian-slim (no compiler; bundle checked with
  `ldd`), Alpine (musl), Linux arm64, macOS, Windows x64 and Windows arm64; `flutter build` plus
  the integration test on macOS, Linux (xvfb), Windows, iOS simulator and an Android x86_64
  emulator (APK checked for 16 KB alignment); `local_build` from source on Linux and macOS.
- `offline.yml`: with github.com blackholed, mirror download via `url_pattern` +
  `manifest_override`, warm-cache rebuild with the mirror down, tampered mirror fails closed
  with the digest message, `local_path` verified against the manifest.
- Bindings regenerate byte-identically on Linux (Docker, Dart 3.13) and macOS.

**Lessons that changed the design during CI bring-up**
- The Ubuntu 24.04-built library needed `GLIBC_2.38` and did not load on Debian 12; glibc
  builds moved into `manylinux_2_28` containers (Debian 11 was tried first; its apt repos moved
  after its EOL).
- The hooks runner hides hook stdout on success; tests must assert on side effects.
- Formatting must use the latest stable Dart (pana and CI do); the bindings generator formats
  its output in place so `--check` is byte-exact.
- `dart run tool/...` runs this package's own hook; `test_directory` mode tolerates a missing
  build so the tool can bootstrap.

**Not yet exercised**
- `release.yml` end to end (no tag pushed yet; every building block has run), `openssl-update.yml`
  against a real newer tag.

**Not started**
- Web/WASM (§6 web.yml, `wasm.dart`): stretch goal, design unchanged.
- at_chops PR in `at_client_sdk` (§4.4): needs this package published or a path dependency.
- Web platform badge (depends on WASM).

**Decisions taken during implementation (all reversible before first publish)**
- Package/pub name `openssl3`; library `libopenssl3_crypto`; user-defines key `openssl3`.
- Version = bundled OpenSSL version + build (`3.5.8+N`), ADR-0010; currently `3.5.8-dev.1`.
- Full libcrypto ABI exported and bound (ADR-0008); `native_toolchain_c` not a dependency.
- `hooks '>=2.0.0 <3.0.0'` so Flutter 3.41/3.44 stable can resolve the package.
- Release tags spell the build with a dash (`v3.5.8-1`) because git refs cannot contain `+`.
