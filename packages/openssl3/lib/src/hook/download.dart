/// Fetching and sha256-verifying prebuilt libraries into the hook's shared
/// output directory. Fails closed: a digest mismatch is an error, never a
/// fallback.
///
/// The caching layout follows `package:sqlite3`: a per-digest subdirectory
/// under [BuildInput.outputDirectoryShared] holding the file under its
/// *installed* name (identical across architectures, as Apple packaging
/// requires), re-validated by re-hashing on every run.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:hooks/hooks.dart';
import 'package:path/path.dart' as p;

import 'binary_source.dart';
import 'supported_targets.dart';

final class DigestMismatchException implements Exception {
  final String fileName;
  final String expected;
  final String actual;
  final Uri? source;

  DigestMismatchException({
    required this.fileName,
    required this.expected,
    required this.actual,
    this.source,
  });

  @override
  String toString() =>
      'openssl3: sha256 of $fileName'
      '${source == null ? '' : ' (from $source)'} is $actual, '
      'expected $expected. Refusing to use it. If you maintain a mirror, make '
      'sure it serves the unmodified release asset; if you supplied '
      '`local_path`, either use the file from the matching release or set '
      '`local_path_unverified: true` to accept it.';
}

final class NoPrebuiltForReleaseException implements Exception {
  final String fileName;
  final String? releaseTag;
  NoPrebuiltForReleaseException(this.fileName, this.releaseTag);

  @override
  String toString() => releaseTag == null
      ? 'openssl3: this checkout has no release hashes yet '
            '(lib/src/manifest.dart has releaseTag == null), so $fileName '
            'cannot be downloaded. Use `test_directory`, `local_path`, '
            '`local_build` or `system` (see README, "Building from a git '
            'checkout").'
      : 'openssl3: release $releaseTag has no entry for $fileName. '
            'Please file an issue with your target platform.';
}

final class CouldNotDownloadException implements Exception {
  final Uri uri;
  final Object cause;
  CouldNotDownloadException(this.uri, this.cause);

  @override
  String toString() {
    final b = StringBuffer(
      'openssl3 downloads a prebuilt OpenSSL libcrypto at build time. '
      'Downloading $uri failed.',
    );
    if (cause is HandshakeException) {
      b.write(
        ' This looks like a TLS/certificate problem; HTTP_PROXY/HTTPS_PROXY '
        'environment variables are honoured.',
      );
    }
    b.write(
      ' For offline builds set `url_pattern` to a mirror or `local_path` to a '
      'pre-downloaded file (README, "Offline and air-gapped builds"). '
      'Cause: $cause',
    );
    return b.toString();
  }
}

/// Obtains the bundled library for [target] from [source] and returns the
/// verified file inside `outputDirectoryShared`.
Future<File> obtainBundledLibrary(
  BuildInput input,
  BuildOutputBuilder output,
  BundledSource source,
  SupportedTarget target,
) async {
  switch (source) {
    case PrecompiledFromRelease():
      final info = source.manifest[target.releaseFileName];
      if (info == null) {
        throw NoPrebuiltForReleaseException(
          target.releaseFileName,
          source.manifest.releaseTag,
        );
      }
      final uri = source.downloadUri(target.releaseFileName);
      return _cachedOrFetched(
        input,
        target,
        expectedSha256: info.sha256,
        fetch: () => downloadStream(uri, source.manifest.releaseTag),
        description: uri.toString(),
      );

    case PrecompiledFromDirectory():
      final file = File(p.join(source.directory.path, target.releaseFileName));
      final sidecar = File('${file.path}.json');
      if (!file.existsSync() || !sidecar.existsSync()) {
        throw FileSystemException(
          'openssl3: test_directory needs both the library and its '
          '.json sidecar (from tool/bin/build_openssl.dart)',
          file.path,
        );
      }
      output.dependencies.add(file.uri);
      output.dependencies.add(sidecar.uri);
      final expected =
          (jsonDecode(sidecar.readAsStringSync())
                  as Map<String, Object?>)['sha256']
              as String;
      return _cachedOrFetched(
        input,
        target,
        expectedSha256: expected,
        fetch: () => file.openRead().map(_asUint8List),
        description: file.path,
      );

    case LocalPath():
      output.dependencies.add(source.file.uri);
      if (!source.file.existsSync()) {
        throw FileSystemException(
          'openssl3: local_path does not exist',
          source.file.path,
        );
      }
      if (!source.verify) {
        stdout.writeln(
          'openssl3: using ${source.file.path} WITHOUT verification '
          '(local_path_unverified: true)',
        );
        return _copyToShared(input, target, source.file, verifiedSha: null);
      }
      final info = source.manifest[target.releaseFileName];
      if (info == null) {
        throw NoPrebuiltForReleaseException(
          target.releaseFileName,
          source.manifest.releaseTag,
        );
      }
      return _cachedOrFetched(
        input,
        target,
        expectedSha256: info.sha256,
        fetch: () => source.file.openRead().map(_asUint8List),
        description: source.file.path,
      );

    case LocalBuild():
      throw ArgumentError(
        'LocalBuild is handled by buildLocally() in local_build.dart',
      );
  }
}

/// Returns the cached copy for [expectedSha256] if it re-hashes correctly,
/// otherwise runs [fetch] and verifies the stream while writing it.
Future<File> _cachedOrFetched(
  BuildInput input,
  SupportedTarget target, {
  required String expectedSha256,
  required Stream<Uint8List> Function() fetch,
  required String description,
}) async {
  final dir = Directory.fromUri(
    input.outputDirectoryShared.resolve(
      'download-${expectedSha256.substring(0, 12)}/',
    ),
  );
  dir.createSync(recursive: true);
  final file = File(p.join(dir.path, target.installedFileName));

  if (file.existsSync()) {
    final actual = await _sha256Of(file.openRead());
    if (actual == expectedSha256) {
      stdout.writeln(
        'openssl3: using cached ${target.releaseFileName} '
        '(sha256 ${actual.substring(0, 12)}…)',
      );
      return file;
    }
    file.deleteSync();
  }

  stdout.writeln(
    'openssl3: fetching ${target.releaseFileName} from '
    '$description',
  );
  final tmp = File('${file.path}.tmp');
  final sink = tmp.openWrite();
  final digestSink = _DigestSink();
  final hasher = sha256.startChunkedConversion(digestSink);
  try {
    await for (final chunk in fetch()) {
      sink.add(chunk);
      hasher.add(chunk);
    }
    await sink.flush();
  } finally {
    await sink.close();
  }
  hasher.close();
  final actual = digestSink.digest.toString();
  if (actual != expectedSha256) {
    tmp.deleteSync();
    throw DigestMismatchException(
      fileName: target.releaseFileName,
      expected: expectedSha256,
      actual: actual,
      source: Uri.tryParse(description),
    );
  }
  tmp.renameSync(file.path);
  return file;
}

Future<File> _copyToShared(
  BuildInput input,
  SupportedTarget target,
  File from, {
  required String? verifiedSha,
}) async {
  final dir = Directory.fromUri(
    input.outputDirectoryShared.resolve('local-${_shortHash(from.path)}/'),
  );
  dir.createSync(recursive: true);
  final to = File(p.join(dir.path, target.installedFileName));
  from.copySync(to.path);
  return to;
}

/// Streams [uri] with proxy support; throws [CouldNotDownloadException].
Stream<Uint8List> downloadStream(Uri uri, String? releaseTag) async* {
  final client = HttpClient()
    ..findProxy = HttpClient.findProxyFromEnvironment
    ..userAgent = 'openssl3 hook (release ${releaseTag ?? 'dev'})';
  HttpClientResponse response;
  try {
    final request = await client.getUrl(uri);
    request.followRedirects = true;
    request.maxRedirects = 10;
    response = await request.close();
    if (response.statusCode != HttpStatus.ok) {
      throw HttpException(
        'HTTP ${response.statusCode} ${response.reasonPhrase}',
        uri: uri,
      );
    }
  } catch (e, s) {
    client.close(force: true);
    Error.throwWithStackTrace(CouldNotDownloadException(uri, e), s);
  }
  try {
    await for (final chunk in response) {
      yield _asUint8List(chunk);
    }
  } finally {
    client.close();
  }
}

Future<String> _sha256Of(Stream<List<int>> bytes) async =>
    (await sha256.bind(bytes).first).toString();

String _shortHash(String s) =>
    sha256.convert(utf8.encode(s)).toString().substring(0, 12);

Uint8List _asUint8List(List<int> chunk) =>
    chunk is Uint8List ? chunk : Uint8List.fromList(chunk);

final class _DigestSink implements Sink<Digest> {
  Digest? _digest;
  Digest get digest => _digest!;

  @override
  void add(Digest data) => _digest = data;

  @override
  void close() {}
}
