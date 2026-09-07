/// The `(os, architecture, sdk, libc)` combinations this package ships
/// prebuilt libraries for, and how the release files are named.
///
/// This is the single source of truth shared by `hook/build.dart` (to pick a
/// file) and the repository tooling (to build and name it), so the two can
/// never disagree.
library;

import 'package:code_assets/code_assets.dart';

/// Base name of the shared library. Deliberately not `crypto`, so the file
/// name and SONAME/install name never collide with a system `libcrypto.so.3`
/// or `libcrypto.3.dylib` already loaded in the process (ADR-0002).
const libraryBaseName = 'openssl3_crypto';

/// Asset id (package-relative) of the `@Native` bindings this library backs.
const codeAssetName = 'src/third_party/openssl.g.dart';

/// C library flavour of a Linux target. Other OSes have exactly one.
enum Libc { glibc, musl, bionic, darwin, msvcrt }

final class SupportedTarget {
  /// Stable id, e.g. `linux-x64`, `linux_musl-arm64`, `ios_sim-x64`.
  final String id;
  final OS os;
  final Architecture arch;
  final IOSSdk? iosSdk;
  final Libc libc;

  const SupportedTarget({
    required this.id,
    required this.os,
    required this.arch,
    required this.libc,
    this.iosSdk,
  });

  /// The `<os>` component of the release file name.
  String get osTag {
    if (os == OS.iOS) {
      return iosSdk == IOSSdk.iPhoneSimulator ? 'ios_sim' : 'ios';
    }
    if (os == OS.linux && libc == Libc.musl) return 'linux_musl';
    return os.name;
  }

  /// File name in the GitHub release, e.g.
  /// `libopenssl3_crypto.arm64.macos.dylib`,
  /// `openssl3_crypto.x64.windows.dll`.
  String get releaseFileName =>
      os.dylibFileName('$libraryBaseName.${arch.name}.$osTag');

  /// File name the library must have on disk when it is loaded (its SONAME,
  /// install name or DLL name). Identical for every architecture of an OS,
  /// which Apple packaging requires.
  String get installedFileName => os.dylibFileName(libraryBaseName);

  /// SONAME (ELF), `@rpath/...` install name (Mach-O) or DLL name (PE).
  String get installName => switch (os) {
    OS.macOS || OS.iOS => '@rpath/$installedFileName',
    _ => installedFileName,
  };

  @override
  String toString() => id;

  static SupportedTarget byId(String id) => all.firstWhere(
    (t) => t.id == id,
    orElse: () => throw ArgumentError.value(
      id,
      'id',
      'Unknown target. Known: ${all.map((t) => t.id).join(', ')}',
    ),
  );

  /// The target matching a hook's [CodeConfig], or `null` if unsupported.
  ///
  /// [linuxLibc] must be supplied for Linux (the hook detects or is told it).
  static SupportedTarget? forCodeConfig(
    CodeConfig config, {
    Libc linuxLibc = Libc.glibc,
  }) {
    final os = config.targetOS;
    final arch = config.targetArchitecture;
    final sdk = os == OS.iOS ? config.iOS.targetSdk : null;
    for (final t in all) {
      if (t.os != os || t.arch != arch) continue;
      if (os == OS.iOS && t.iosSdk != sdk) continue;
      if (os == OS.linux && t.libc != linuxLibc) continue;
      return t;
    }
    return null;
  }

  static const List<SupportedTarget> all = [
    SupportedTarget(
      id: 'linux-x64',
      os: OS.linux,
      arch: Architecture.x64,
      libc: Libc.glibc,
    ),
    SupportedTarget(
      id: 'linux-arm64',
      os: OS.linux,
      arch: Architecture.arm64,
      libc: Libc.glibc,
    ),
    SupportedTarget(
      id: 'linux-arm',
      os: OS.linux,
      arch: Architecture.arm,
      libc: Libc.glibc,
    ),
    SupportedTarget(
      id: 'linux-riscv64',
      os: OS.linux,
      arch: Architecture.riscv64,
      libc: Libc.glibc,
    ),
    SupportedTarget(
      id: 'linux_musl-x64',
      os: OS.linux,
      arch: Architecture.x64,
      libc: Libc.musl,
    ),
    SupportedTarget(
      id: 'linux_musl-arm64',
      os: OS.linux,
      arch: Architecture.arm64,
      libc: Libc.musl,
    ),
    SupportedTarget(
      id: 'macos-arm64',
      os: OS.macOS,
      arch: Architecture.arm64,
      libc: Libc.darwin,
    ),
    SupportedTarget(
      id: 'macos-x64',
      os: OS.macOS,
      arch: Architecture.x64,
      libc: Libc.darwin,
    ),
    SupportedTarget(
      id: 'ios-arm64',
      os: OS.iOS,
      arch: Architecture.arm64,
      iosSdk: IOSSdk.iPhoneOS,
      libc: Libc.darwin,
    ),
    SupportedTarget(
      id: 'ios_sim-arm64',
      os: OS.iOS,
      arch: Architecture.arm64,
      iosSdk: IOSSdk.iPhoneSimulator,
      libc: Libc.darwin,
    ),
    SupportedTarget(
      id: 'ios_sim-x64',
      os: OS.iOS,
      arch: Architecture.x64,
      iosSdk: IOSSdk.iPhoneSimulator,
      libc: Libc.darwin,
    ),
    SupportedTarget(
      id: 'android-arm64',
      os: OS.android,
      arch: Architecture.arm64,
      libc: Libc.bionic,
    ),
    SupportedTarget(
      id: 'android-arm',
      os: OS.android,
      arch: Architecture.arm,
      libc: Libc.bionic,
    ),
    SupportedTarget(
      id: 'android-x64',
      os: OS.android,
      arch: Architecture.x64,
      libc: Libc.bionic,
    ),
    SupportedTarget(
      id: 'windows-x64',
      os: OS.windows,
      arch: Architecture.x64,
      libc: Libc.msvcrt,
    ),
    SupportedTarget(
      id: 'windows-arm64',
      os: OS.windows,
      arch: Architecture.arm64,
      libc: Libc.msvcrt,
    ),
  ];
}
