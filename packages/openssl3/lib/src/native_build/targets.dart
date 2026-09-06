/// How each [SupportedTarget] is built: OpenSSL `Configure` target, extra
/// flags, cross-compile prefix and platform libraries.
///
/// Naming (release file, installed file, SONAME) lives on [SupportedTarget]
/// so the hook and the build tooling can never disagree.
library;

import 'package:code_assets/code_assets.dart';

import '../hook/supported_targets.dart';
import 'abi.dart';

export '../hook/supported_targets.dart';

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
  '--openssldir=/nonexistent/openssl3',
  '--release',
];

enum ObjectFormat { elf, machO, pe }

final class BuildTarget {
  final SupportedTarget base;

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

  const BuildTarget(
    this.base, {
    required this.configureTarget,
    this.extraConfigureArgs = const [],
    this.cflags = const [],
    this.ldflags = const [],
    this.libs = const [],
    this.crossCompilePrefix,
  });

  String get id => base.id;
  OS get os => base.os;
  Architecture get arch => base.arch;
  String get releaseFileName => base.releaseFileName;
  String get installedFileName => base.installedFileName;
  String get installName => base.installName;

  ObjectFormat get objectFormat => switch (os) {
    OS.windows => ObjectFormat.pe,
    OS.macOS || OS.iOS => ObjectFormat.machO,
    _ => ObjectFormat.elf,
  };

  AbiPlatform get abiPlatform =>
      os == OS.windows ? AbiPlatform.windows : AbiPlatform.unix;

  @override
  String toString() => id;

  static BuildTarget byId(String id) => all.firstWhere(
    (t) => t.id == id,
    orElse: () => throw ArgumentError.value(
      id,
      'id',
      'Unknown target. Known: ${all.map((t) => t.id).join(', ')}',
    ),
  );

  static BuildTarget forSupported(SupportedTarget base) => byId(base.id);

  static const _apple10_15 = ['-mmacosx-version-min=10.15'];
  static const _ios13 = ['-miphoneos-version-min=13.0'];
  static const _iosSim13 = ['-mios-simulator-version-min=13.0'];
  static const _android = ['no-async', '-D__ANDROID_API__=21'];
  static const _android16k = ['-Wl,-z,max-page-size=16384'];

  static final List<BuildTarget> all = [
    // Linux glibc: native gcc (x64; arm64 on arm runners), Debian cross-gcc
    // for riscv64, exactly as OpenSSL's own cross-compiles.yml (ADR-0004).
    BuildTarget(
      SupportedTarget.byId('linux-x64'),
      configureTarget: 'linux-x86_64',
      libs: ['pthread', 'dl'],
    ),
    BuildTarget(
      SupportedTarget.byId('linux-arm64'),
      configureTarget: 'linux-aarch64',
      libs: ['pthread', 'dl'],
    ),
    BuildTarget(
      SupportedTarget.byId('linux-riscv64'),
      configureTarget: 'linux64-riscv64',
      crossCompilePrefix: 'riscv64-linux-gnu-',
      libs: ['pthread', 'dl', 'atomic'],
    ),
    // Linux musl: built inside an alpine container (os-zoo.yml style).
    BuildTarget(
      SupportedTarget.byId('linux_musl-x64'),
      configureTarget: 'linux-x86_64',
      extraConfigureArgs: ['no-async'],
      libs: ['pthread'],
    ),
    BuildTarget(
      SupportedTarget.byId('linux_musl-arm64'),
      configureTarget: 'linux-aarch64',
      extraConfigureArgs: ['no-async'],
      libs: ['pthread'],
    ),
    // macOS: thin per-arch dylibs (ADR-0003).
    BuildTarget(
      SupportedTarget.byId('macos-arm64'),
      configureTarget: 'darwin64-arm64',
      cflags: _apple10_15,
    ),
    BuildTarget(
      SupportedTarget.byId('macos-x64'),
      configureTarget: 'darwin64-x86_64',
      cflags: _apple10_15,
    ),
    // iOS: OpenSSL's ios configs already disable async.
    BuildTarget(
      SupportedTarget.byId('ios-arm64'),
      configureTarget: 'ios64-xcrun',
      cflags: _ios13,
    ),
    BuildTarget(
      SupportedTarget.byId('ios_sim-arm64'),
      configureTarget: 'iossimulator-arm64-xcrun',
      cflags: _iosSim13,
    ),
    BuildTarget(
      SupportedTarget.byId('ios_sim-x64'),
      configureTarget: 'iossimulator-x86_64-xcrun',
      cflags: _iosSim13,
    ),
    // Android: NDK r27+, API 21, 16 KB page alignment.
    BuildTarget(
      SupportedTarget.byId('android-arm64'),
      configureTarget: 'android-arm64',
      extraConfigureArgs: _android,
      ldflags: _android16k,
      libs: ['dl', 'm'],
    ),
    BuildTarget(
      SupportedTarget.byId('android-arm'),
      configureTarget: 'android-arm',
      extraConfigureArgs: _android,
      ldflags: _android16k,
      libs: ['dl', 'm'],
    ),
    BuildTarget(
      SupportedTarget.byId('android-x64'),
      configureTarget: 'android-x86_64',
      extraConfigureArgs: _android,
      ldflags: _android16k,
      libs: ['dl', 'm'],
    ),
    // Windows: MSVC. `no-shared` already selects /MT /Zl for the static lib.
    BuildTarget(
      SupportedTarget.byId('windows-x64'),
      configureTarget: 'VC-WIN64A',
      libs: ['ws2_32', 'gdi32', 'advapi32', 'crypt32', 'user32'],
    ),
    BuildTarget(
      SupportedTarget.byId('windows-arm64'),
      configureTarget: 'VC-WIN64-ARM',
      extraConfigureArgs: ['no-asm'],
      libs: ['ws2_32', 'gdi32', 'advapi32', 'crypt32', 'user32'],
    ),
  ];
}
