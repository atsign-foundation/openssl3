/// Where `hook/build.dart` obtains `libopenssl3_crypto` from, chosen
/// from the consumer's `hooks: user_defines: openssl3:` block.
///
/// Modelled on `package:sqlite3`'s `SqliteBinary` (lib/src/hook/compile/
/// description.dart), adapted to this package's user defines:
///
/// ```yaml
/// hooks:
///   user_defines:
///     openssl3:
///       url_pattern: "https://mirror.example/$RELEASE_TAG/$FILENAME"
///       local_path: native/libopenssl3_crypto.dylib   # + sha256 check
///       local_path_unverified: true    # opt out of the sha256 check
///       local_build: true              # Configure + make from source
///       source_path: ../openssl        # source tree for local_build
///       system: true                   # dlopen the OS libcrypto instead
///       system_name: libcrypto.so.3    # or a per-OS map
///       linux_libc: musl               # glibc (default) or musl
///       test_directory: ../out         # CI only: files + .json sidecars
///       manifest_override: ../out/manifest.json   # CI only
/// ```
library;

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

import '../manifest.dart' as compiled;
import 'manifest_model.dart';
import 'supported_targets.dart';

/// Default location of release assets. `$RELEASE_TAG` and `$FILENAME` are
/// substituted (same placeholders as `package:sqlite3`).
///
/// The repository is `cconstab/openssl3` and will be transferred to
/// `atsign-foundation` unchanged; GitHub redirects the old owner's URLs.
const defaultUrlPattern =
    r'https://github.com/cconstab/openssl3/releases/download/$RELEASE_TAG/$FILENAME';

sealed class BinarySource {
  const BinarySource();

  /// Reads the user defines and returns the selected source.
  ///
  /// Throws [ArgumentError] for conflicting or malformed defines.
  static BinarySource forInput(BuildInput input) {
    final d = input.userDefines;

    bool flag(String key) => switch (d[key]) {
      null => false,
      final bool b => b,
      'true' => true,
      'false' => false,
      final other => throw ArgumentError.value(
        other,
        key,
        'Expected true or false',
      ),
    };

    final chosen = <String>[
      if (flag('system')) 'system',
      if (d['local_path'] != null) 'local_path',
      if (flag('local_build')) 'local_build',
      if (d['test_directory'] != null) 'test_directory',
    ];
    if (chosen.length > 1) {
      throw ArgumentError(
        'openssl3: user defines ${chosen.join(', ')} are mutually '
        'exclusive; set only one of system, local_path, local_build, '
        'test_directory.',
      );
    }

    final manifest = switch (d.path('manifest_override')) {
      null => compiled.compiledInManifest,
      final uri => Manifest.parse(File.fromUri(uri).readAsStringSync()),
    };

    switch (chosen.singleOrNull) {
      case 'system':
        return SystemLibrary(_systemName(d, input.config.code));
      case 'local_path':
        final uri = d.path('local_path')!;
        return LocalPath(
          File.fromUri(uri),
          verify: !flag('local_path_unverified'),
          manifest: manifest,
        );
      case 'local_build':
        return LocalBuild(
          sourcePath: switch (d.path('source_path')) {
            null => null,
            final uri => Directory.fromUri(uri),
          },
          manifest: manifest,
        );
      case 'test_directory':
        return PrecompiledFromDirectory(
          Directory.fromUri(d.path('test_directory')!),
        );
      default:
        final pattern = switch (d['url_pattern']) {
          null => defaultUrlPattern,
          final String s => s,
          final other => throw ArgumentError.value(
            other,
            'url_pattern',
            'Expected a string',
          ),
        };
        return PrecompiledFromRelease(urlPattern: pattern, manifest: manifest);
    }
  }

  static String _systemName(HookInputUserDefines d, CodeConfig code) {
    final os = code.targetOS;
    final configured = switch (d['system_name']) {
      null => null,
      final String s => s,
      final Map<Object?, Object?> m => (m[os.name] ?? m['default']) as String?,
      final other => throw ArgumentError.value(
        other,
        'system_name',
        'Expected a string or a map of OS name to string',
      ),
    };
    if (configured != null) return configured;
    return switch (os) {
      OS.linux || OS.android => 'libcrypto.so.3',
      OS.macOS => 'libcrypto.3.dylib',
      OS.windows => switch (code.targetArchitecture) {
        Architecture.x64 => 'libcrypto-3-x64.dll',
        Architecture.arm64 => 'libcrypto-3-arm64.dll',
        _ => 'libcrypto-3.dll',
      },
      _ => throw UnsupportedError(
        'openssl3: `system: true` is not available on ${os.name}; '
        'there is no system libcrypto to load.',
      ),
    };
  }
}

/// Emit `DynamicLoadingSystem` so the app dlopens the OS libcrypto.
///
/// Escape hatch for distribution packagers. The system library may be older
/// than 3.5 and lack ML-KEM/ML-DSA; `OpenSSLCapabilities` reports that.
final class SystemLibrary extends BinarySource {
  final String name;
  const SystemLibrary(this.name);

  LinkMode get linkMode => DynamicLoadingSystem(Uri.parse(name));
}

/// Sources that yield a file the hook bundles with `DynamicLoadingBundled`.
sealed class BundledSource extends BinarySource {
  const BundledSource();
}

/// Download `<file>` for the resolved target from a GitHub release (or a
/// mirror given by `url_pattern`) and verify it against the manifest.
final class PrecompiledFromRelease extends BundledSource {
  final String urlPattern;
  final Manifest manifest;

  const PrecompiledFromRelease({
    required this.urlPattern,
    required this.manifest,
  });

  Uri downloadUri(String fileName) => Uri.parse(
    urlPattern
        .replaceAll(r'$RELEASE_TAG', manifest.releaseTag ?? 'null')
        .replaceAll(r'$FILENAME', fileName),
  );
}

/// CI only: read `<dir>/<file>` and verify it against the sha256 in the
/// `<dir>/<file>.json` sidecar written by `tool/bin/build_openssl.dart`.
/// Lets the package test itself before a release exists.
final class PrecompiledFromDirectory extends BundledSource {
  final Directory directory;
  const PrecompiledFromDirectory(this.directory);
}

/// Use a file the consumer already has. Verified against the manifest unless
/// `local_path_unverified: true`.
final class LocalPath extends BundledSource {
  final File file;
  final bool verify;
  final Manifest manifest;

  const LocalPath(this.file, {required this.verify, required this.manifest});
}

/// Compile from source with Perl and a C toolchain (slow; documented loudly).
final class LocalBuild extends BundledSource {
  /// An OpenSSL source tree; when `null` the pinned release tarball is
  /// downloaded and verified against [Manifest.sourceTarballSha256].
  final Directory? sourcePath;
  final Manifest manifest;

  const LocalBuild({required this.sourcePath, required this.manifest});
}

/// Resolves the consumer's target, detecting musl on Linux when building for
/// the host and honouring the `linux_libc` user define.
SupportedTarget resolveTarget(BuildInput input) {
  final code = input.config.code;
  var libc = Libc.glibc;
  if (code.targetOS == OS.linux) {
    libc = switch (input.userDefines['linux_libc']) {
      null => _hostIsMusl(code) ? Libc.musl : Libc.glibc,
      'glibc' => Libc.glibc,
      'musl' => Libc.musl,
      final other => throw ArgumentError.value(
        other,
        'linux_libc',
        'Expected "glibc" or "musl"',
      ),
    };
  }
  final target = SupportedTarget.forCodeConfig(code, linuxLibc: libc);
  if (target == null) {
    final sdk = code.targetOS == OS.iOS ? ' (${code.iOS.targetSdk})' : '';
    final libcNote = code.targetOS == OS.linux ? ' ${libc.name}' : '';
    throw UnsupportedError(
      'openssl3 has no prebuilt libcrypto for '
      '${code.targetOS.name}$libcNote/${code.targetArchitecture.name}$sdk. '
      'Supported: ${SupportedTarget.all.join(', ')}. '
      'Options: `local_build: true` (needs Perl + C toolchain), '
      '`local_path: <file>`, or `system: true`. See the package README.',
    );
  }
  return target;
}

/// True when the hook runs on a musl Linux host and targets the host itself.
bool _hostIsMusl(CodeConfig code) {
  if (!Platform.isLinux || code.targetArchitecture != Architecture.current) {
    return false;
  }
  try {
    if (File('/etc/alpine-release').existsSync()) return true;
    return Directory(
      '/lib',
    ).listSync().any((e) => e.uri.pathSegments.last.startsWith('ld-musl-'));
  } on FileSystemException {
    return false;
  }
}
