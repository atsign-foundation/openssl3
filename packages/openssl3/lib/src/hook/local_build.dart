/// The `local_build: true` user define: compile libcrypto from source on the
/// consumer's machine with the same pipeline CI uses.
///
/// Needs Perl 5, `make` (or `nmake`) and the platform C toolchain; takes a few
/// minutes. Sources come from `source_path` (an OpenSSL tree such as this
/// repository's submodule) or, by default, the pinned upstream release
/// tarball, downloaded and verified against `Manifest.sourceTarballSha256`
/// (fail closed, ADR-0007).
library;

import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:hooks/hooks.dart';
import 'package:path/path.dart' as p;

import '../native_build/build.dart';
import '../native_build/targets.dart';
import 'binary_source.dart';
import 'download.dart';

const _upstreamTarball =
    r'https://github.com/openssl/openssl/releases/download/openssl-$VERSION/openssl-$VERSION.tar.gz';

/// The manifest records no size for the source tarball (3.5.x is ~55 MB), so
/// bound the download generously instead: enough for any OpenSSL release,
/// small enough that a misbehaving server cannot fill the disk.
const _maxTarballBytes = 256 * 1024 * 1024;

Future<File> buildLocally(
  BuildInput input,
  BuildOutputBuilder output,
  LocalBuild source,
  SupportedTarget target,
) async {
  final shared = Directory.fromUri(
    input.outputDirectoryShared.resolve('local_build/'),
  )..createSync(recursive: true);

  final version = source.manifest.opensslVersion;
  final Directory tree;
  if (source.sourcePath != null) {
    tree = source.sourcePath!;
    if (!File(p.join(tree.path, 'Configure')).existsSync()) {
      throw FileSystemException(
        'openssl3: source_path is not an OpenSSL source tree (no Configure)',
        tree.path,
      );
    }
    output.dependencies.add(tree.uri.resolve('VERSION.dat'));
  } else {
    tree = await _fetchSourceTarball(
      shared,
      version: version,
      expectedSha256: source.manifest.sourceTarballSha256,
      releaseTag: source.manifest.releaseTag,
    );
  }

  stdout.writeln(
    'openssl3: local_build requested; compiling OpenSSL $version for '
    '${target.id} from ${tree.path}. This needs Perl and a C toolchain and '
    'takes a few minutes.',
  );
  final outDir = Directory(p.join(shared.path, 'out-${target.id}'));
  final result = await buildTarget(
    BuildOptions(
      target: BuildTarget.forSupported(target),
      source: tree,
      buildDir: Directory(p.join(shared.path, 'build-${target.id}')),
      outDir: outDir,
      packageRoot: Directory.fromUri(input.packageRoot),
      reuseBuildDir: true,
      jobs: Platform.numberOfProcessors,
    ),
  );
  // The hook must hand out the *installed* file name (identical across
  // architectures, which Apple packaging requires).
  final installed = File(p.join(outDir.path, target.installedFileName));
  result.library.copySync(installed.path);
  return installed;
}

/// Downloads `openssl-<version>.tar.gz`, verifies it, extracts it once into
/// [shared] and returns the source tree.
Future<Directory> _fetchSourceTarball(
  Directory shared, {
  required String version,
  required String? expectedSha256,
  required String? releaseTag,
}) async {
  if (expectedSha256 == null) {
    throw StateError(
      'openssl3: local_build needs the sha256 of openssl-$version.tar.gz, '
      'which this build of the package does not carry '
      '(manifest.sourceTarballSha256 is null'
      '${releaseTag == null ? ', no release yet' : ''}). '
      'Point `source_path` at an OpenSSL $version source tree instead.',
    );
  }
  final tree = Directory(p.join(shared.path, 'openssl-$version'));
  final marker = File(p.join(tree.path, '.openssl3-verified-$expectedSha256'));
  if (marker.existsSync()) return tree;

  final tarball = File(p.join(shared.path, 'openssl-$version.tar.gz'));
  if (!tarball.existsSync() ||
      (await sha256.bind(tarball.openRead()).first).toString() !=
          expectedSha256) {
    final uri = Uri.parse(_upstreamTarball.replaceAll(r'$VERSION', version));
    stdout.writeln('openssl3: downloading $uri');
    // Unique temporary name, renamed into place only once verified; a failed
    // or oversized download never leaves bytes under the tarball's name.
    final tmp = File('${tarball.path}.$pid.tmp');
    try {
      final written = await writeVerified(
        downloadStream(uri, releaseTag),
        tmp,
        limit: _maxTarballBytes,
      );
      if (written.sha256 != expectedSha256) {
        throw DigestMismatchException(
          fileName: p.basename(tarball.path),
          expected: expectedSha256,
          actual: written.sha256,
          source: uri,
        );
      }
      tmp.renameSync(tarball.path);
    } catch (_) {
      if (tmp.existsSync()) tmp.deleteSync();
      rethrow;
    }
  }

  if (tree.existsSync()) tree.deleteSync(recursive: true);
  final result = await Process.run('tar', [
    'xzf',
    tarball.path,
    '-C',
    shared.path,
  ]);
  if (result.exitCode != 0) {
    throw ProcessException(
      'tar',
      ['xzf', tarball.path],
      '${result.stderr}',
      result.exitCode,
    );
  }
  if (!tree.existsSync()) {
    throw FileSystemException('openssl3: tarball did not contain', tree.path);
  }
  marker.writeAsStringSync('ok\n');
  return tree;
}
