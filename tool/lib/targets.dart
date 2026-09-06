/// The matrix of prebuilt libraries this package ships, and how each is built.
///
/// One entry per release artifact. `tool/bin/build_openssl.dart <id>` builds
/// one of them; CI builds all of them; `hook/build.dart` resolves the
/// consumer's `(os, arch, sdk, libc)` to one of these ids.
library;

import 'package:code_assets/code_assets.dart';

import 'abi.dart';

/// Base name of the shared library. Distinct from `crypto` on purpose so it
/// never collides with a system `libcrypto.so.3` / `libcrypto.3.dylib`.
const libraryBaseName = 'openssl_assets_crypto';

/// OpenSSL `Configure` feature flags shared by every target (ADR-0005, 0008).
///
/// `no-shared`: we link the shared library ourselves (ADR-0002).
/// `no-module no-dso no-engine no-legacy`: nothing is loaded from disk.
/// Deprecated API is intentionally kept (ADR-0008).
const commonConfigureArgs = <String>[
  'no-shared',
  'no-module',
  'no-dso',
  'no-engine',
  'no-legacy',
  'no-apps',
  'no-tests',
  'no-docs',
  'no-comp',
  'no-zlib',
  'no-makedepend',
  '--openssldir=/nonexistent/openssl_assets',
  '--release',
];

enum Libc { glibc, musl, bionic, darwin, msvcrt }

enum ObjectFormat { elf, machO, pe }

final class BuildTarget {
  /// Stable id, e.g. `linux-x64`, `linux_musl-arm64`, `ios_sim-x64`.
  final String id;

  final OS os;
  final Architecture arch;
  final IOSSdk? iosSdk;
  final Libc libc;

  /// OpenSSL `Configure` target name.
  final String configureTarget;

  /// Extra `Configure` arguments for this target only.
  final List<String> extraConfigureArgs;

  /// Compiler/linker flags added to both the OpenSSL build and our link step.
  final List<String> cflags;

  /// Additional linker-only flags for our link step.
  final List<String> ldflags;

  /// Libraries to link (`-l` names on Unix, `.lib` names on Windows).
  final List<String> libs;

  /// `--cross-compile-prefix` for Debian cross toolchains, if any.
  final String? crossCompilePrefix;

  const BuildTarget({
    required this.id,
    required this.os,
    required this.arch,
    required this.libc,
    required this.configureTarget,
    this.iosSdk,
    this.extraConfigureArgs = const [],
    this.cflags = const [],
    this.ldflags = const [],
    this.libs = const [],
    this.crossCompilePrefix,
  });

  ObjectFormat get objectFormat => switch (os) {
    OS.windows => ObjectFormat.pe,
    OS.macOS || OS.iOS => ObjectFormat.machO,
    _ => ObjectFormat.elf,
  };

  AbiPlatform get abiPlatform =>
      os == OS.windows ? AbiPlatform.windows : AbiPlatform.unix;

  /// The `<os>` component of the release file name.
  String get osTag {
    if (os == OS.iOS) {
      return iosSdk == IOSSdk.iPhoneSimulator ? 'ios_sim' : 'ios';
    }
    if (os == OS.linux && libc == Libc.musl) return 'linux_musl';
    return os.name;
  }

  /// File name in the GitHub release, e.g.
  /// `libopenssl_assets_crypto.arm64.macos.dylib`,
  /// `openssl_assets_crypto.x64.windows.dll`.
  String get releaseFileName =>
      os.dylibFileName('$libraryBaseName.${arch.name}.$osTag');

  /// File name the library must have on disk when loaded (SONAME / install
  /// name / DLL name), identical for every architecture of an OS.
  String get installedFileName => os.dylibFileName(libraryBaseName);

  /// SONAME (ELF) or `@rpath/...` install name (Mach-O).
  String get installName => switch (objectFormat) {
    ObjectFormat.elf => installedFileName,
    ObjectFormat.machO => '@rpath/$installedFileName',
    ObjectFormat.pe => installedFileName,
  };

  static BuildTarget byId(String id) => all.firstWhere(
    (t) => t.id == id,
    orElse: () {
      throw ArgumentError.value(
        id,
        'id',
        'Unknown target. Known: ${all.map((t) => t.id).join(', ')}',
      );
    },
  );

  /// Finds the target for a hook's code config, or `null` if unsupported.
  static BuildTarget? forCodeConfig(CodeConfig config, {Libc? linuxLibc}) {
    final os = config.targetOS;
    final arch = config.targetArchitecture;
    final sdk = os == OS.iOS ? config.iOS.targetSdk : null;
    for (final t in all) {
      if (t.os != os || t.arch != arch) continue;
      if (os == OS.iOS && t.iosSdk != sdk) continue;
      if (os == OS.linux && t.libc != (linuxLibc ?? Libc.glibc)) continue;
      return t;
    }
    return null;
  }

  static const _apple10_15 = ['-mmacosx-version-min=10.15'];
  static const _ios13 = ['-miphoneos-version-min=13.0'];
  static const _iosSim13 = ['-mios-simulator-version-min=13.0'];

  static const List<BuildTarget> all = [
    // Linux glibc — native gcc (x64, arm64 on arm runners), Debian cross-gcc
    // for riscv64, exactly as OpenSSL's own cross-compiles.yml (ADR-0004).
    BuildTarget(
      id: 'linux-x64',
      os: OS.linux,
      arch: Architecture.x64,
      libc: Libc.glibc,
      configureTarget: 'linux-x86_64',
      libs: ['pthread', 'dl'],
    ),
    BuildTarget(
      id: 'linux-arm64',
      os: OS.linux,
      arch: Architecture.arm64,
      libc: Libc.glibc,
      configureTarget: 'linux-aarch64',
      libs: ['pthread', 'dl'],
    ),
    BuildTarget(
      id: 'linux-riscv64',
      os: OS.linux,
      arch: Architecture.riscv64,
      libc: Libc.glibc,
      configureTarget: 'linux64-riscv64',
      crossCompilePrefix: 'riscv64-linux-gnu-',
      libs: ['pthread', 'dl', 'atomic'],
    ),
    // Linux musl — built inside an alpine container (os-zoo.yml style).
    BuildTarget(
      id: 'linux_musl-x64',
      os: OS.linux,
      arch: Architecture.x64,
      libc: Libc.musl,
      configureTarget: 'linux-x86_64',
      extraConfigureArgs: ['no-async'],
      libs: ['pthread'],
    ),
    BuildTarget(
      id: 'linux_musl-arm64',
      os: OS.linux,
      arch: Architecture.arm64,
      libc: Libc.musl,
      configureTarget: 'linux-aarch64',
      extraConfigureArgs: ['no-async'],
      libs: ['pthread'],
    ),
    // macOS — thin per-arch dylibs (ADR-0003).
    BuildTarget(
      id: 'macos-arm64',
      os: OS.macOS,
      arch: Architecture.arm64,
      libc: Libc.darwin,
      configureTarget: 'darwin64-arm64',
      cflags: _apple10_15,
    ),
    BuildTarget(
      id: 'macos-x64',
      os: OS.macOS,
      arch: Architecture.x64,
      libc: Libc.darwin,
      configureTarget: 'darwin64-x86_64',
      cflags: _apple10_15,
    ),
    // iOS — OpenSSL's ios configs already disable async.
    BuildTarget(
      id: 'ios-arm64',
      os: OS.iOS,
      arch: Architecture.arm64,
      iosSdk: IOSSdk.iPhoneOS,
      libc: Libc.darwin,
      configureTarget: 'ios64-xcrun',
      cflags: _ios13,
    ),
    BuildTarget(
      id: 'ios_sim-arm64',
      os: OS.iOS,
      arch: Architecture.arm64,
      iosSdk: IOSSdk.iPhoneSimulator,
      libc: Libc.darwin,
      configureTarget: 'iossimulator-arm64-xcrun',
      cflags: _iosSim13,
    ),
    BuildTarget(
      id: 'ios_sim-x64',
      os: OS.iOS,
      arch: Architecture.x64,
      iosSdk: IOSSdk.iPhoneSimulator,
      libc: Libc.darwin,
      configureTarget: 'iossimulator-x86_64-xcrun',
      cflags: _iosSim13,
    ),
    // Android — NDK r27+, API 21, 16 KB page alignment.
    BuildTarget(
      id: 'android-arm64',
      os: OS.android,
      arch: Architecture.arm64,
      libc: Libc.bionic,
      configureTarget: 'android-arm64',
      extraConfigureArgs: ['no-async', '-D__ANDROID_API__=21'],
      ldflags: ['-Wl,-z,max-page-size=16384'],
      libs: ['dl', 'm'],
    ),
    BuildTarget(
      id: 'android-arm',
      os: OS.android,
      arch: Architecture.arm,
      libc: Libc.bionic,
      configureTarget: 'android-arm',
      extraConfigureArgs: ['no-async', '-D__ANDROID_API__=21'],
      ldflags: ['-Wl,-z,max-page-size=16384'],
      libs: ['dl', 'm'],
    ),
    BuildTarget(
      id: 'android-x64',
      os: OS.android,
      arch: Architecture.x64,
      libc: Libc.bionic,
      configureTarget: 'android-x86_64',
      extraConfigureArgs: ['no-async', '-D__ANDROID_API__=21'],
      ldflags: ['-Wl,-z,max-page-size=16384'],
      libs: ['dl', 'm'],
    ),
    // Windows — MSVC. `no-shared` already selects /MT /Zl for the static lib.
    BuildTarget(
      id: 'windows-x64',
      os: OS.windows,
      arch: Architecture.x64,
      libc: Libc.msvcrt,
      configureTarget: 'VC-WIN64A',
      libs: ['ws2_32', 'gdi32', 'advapi32', 'crypt32', 'user32'],
    ),
    BuildTarget(
      id: 'windows-arm64',
      os: OS.windows,
      arch: Architecture.arm64,
      libc: Libc.msvcrt,
      configureTarget: 'VC-WIN64-ARM',
      extraConfigureArgs: ['no-asm'],
      libs: ['ws2_32', 'gdi32', 'advapi32', 'crypt32', 'user32'],
    ),
  ];
}
