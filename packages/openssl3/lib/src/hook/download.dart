/// Fetching and sha256-verifying prebuilt libraries into the hook's shared
/// output directory. Fails closed: a digest mismatch is an error, never a
/// fallback.
///
/// The caching layout follows `package:sqlite3`: a per-digest subdirectory
/// under [BuildInput.outputDirectoryShared] holding the file under its
/// *installed* name (identical across architectures, as Apple packaging
/// requires), re-validated by re-hashing on every run.
///
/// Besides the digest, a fetch is bounded by the size the manifest records
/// (a mirror cannot fill the disk before the mismatch is noticed), by
/// connection and idle timeouts (a stalled mirror cannot hang the build), and
/// an `https` URL is never followed to a plain `http` redirect.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:hooks/hooks.dart';
import 'package:path/path.dart' as p;

import '../manifest.dart' as compiled;
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

/// The bytes received do not match the size the manifest records for the
/// asset. Thrown as soon as the stream exceeds that size, so a hostile or
/// broken mirror cannot fill the disk before the digest check would fail.
final class SizeMismatchException implements Exception {
  final String fileName;
  final int expected;

  /// Bytes seen so far; larger than [expected] when aborted mid-stream.
  final int actual;
  final Uri? source;

  SizeMismatchException({
    required this.fileName,
    required this.expected,
    required this.actual,
    this.source,
  });

  @override
  String toString() =>
      'openssl3: $fileName'
      '${source == null ? '' : ' (from $source)'} is '
      '${actual > expected ? 'more than ' : ''}$actual bytes, the release '
      'manifest says $expected. Refusing to use it; the file is not the '
      'released asset.';
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
    } else if (cause is TimeoutException) {
      b.write(' The server did not respond in time.');
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
/// Returns `null` only for [PrecompiledFromDirectory] (the CI/test mode) when
/// the directory does not hold the file yet: inside this repository the tool
/// that *produces* the file is itself a Dart program depending on this
/// package, so its hook must be able to run before the first build exists.
/// Every other source fails closed.
Future<File?> obtainBundledLibrary(
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
        expectedSize: info.size,
        fetch: () => downloadStream(uri, source.manifest.releaseTag),
        description: uri.toString(),
      );

    case PrecompiledFromDirectory():
      final file = File(p.join(source.directory.path, target.releaseFileName));
      final sidecar = File('${file.path}.json');
      output.dependencies.add(file.uri);
      output.dependencies.add(sidecar.uri);
      if (!file.existsSync() || !sidecar.existsSync()) {
        final tag = compiled.compiledInManifest.releaseTag;
        final fetch = tag == null
            ? ''
            : ', or fetch the released build: `gh release download $tag '
                  "--pattern '${target.releaseFileName}*' "
                  '--dir ${source.directory.path}`';
        stderr.writeln(
          'openssl3: WARNING: test_directory ${source.directory.path} has no '
          '${target.releaseFileName} (+ .json sidecar) yet; emitting no code '
          'asset. Build it with `dart run tool/bin/build_openssl.dart '
          '${target.id} --out ${source.directory.path}`$fetch. '
          'Any @Native call will fail until then.',
        );
        return null;
      }
      final json =
          jsonDecode(sidecar.readAsStringSync()) as Map<String, Object?>;
      return _cachedOrFetched(
        input,
        target,
        expectedSha256: json['sha256'] as String,
        expectedSize: json['size'] as int?,
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
        return _copyToShared(input, target, source.file);
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
        expectedSize: info.size,
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
///
/// The download goes to a uniquely named temporary file that is renamed into
/// place only after the digest (and, when known, the size) matched, so two
/// hooks fetching the same asset at once never see each other's partial
/// bytes, and nothing unverified is ever left under the installed name.
Future<File> _cachedOrFetched(
  BuildInput input,
  SupportedTarget target, {
  required String expectedSha256,
  required int? expectedSize,
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
  final source = Uri.tryParse(description);
  final tmp = File('${file.path}.${_uniqueSuffix()}.tmp');
  try {
    final actual = await writeVerified(
      fetch(),
      tmp,
      onExceeded: expectedSize == null
          ? null
          : (received) => SizeMismatchException(
              fileName: target.releaseFileName,
              expected: expectedSize,
              actual: received,
              source: source,
            ),
      limit: expectedSize,
    );
    if (expectedSize != null && actual.size != expectedSize) {
      throw SizeMismatchException(
        fileName: target.releaseFileName,
        expected: expectedSize,
        actual: actual.size,
        source: source,
      );
    }
    if (actual.sha256 != expectedSha256) {
      throw DigestMismatchException(
        fileName: target.releaseFileName,
        expected: expectedSha256,
        actual: actual.sha256,
        source: source,
      );
    }
    tmp.renameSync(file.path);
  } catch (_) {
    _deleteQuietly(tmp);
    rethrow;
  }
  return file;
}

/// Size and digest of a stream that was written to disk.
final class Written {
  final int size;
  final String sha256;
  const Written(this.size, this.sha256);
}

/// Streams [bytes] into [target] while hashing, and returns what was written.
///
/// When [limit] is set the stream is aborted as soon as more than [limit]
/// bytes arrive; [onExceeded] builds the exception to throw then (a plain
/// [StateError] when `null`). The caller owns [target] and decides whether to
/// keep or delete it.
Future<Written> writeVerified(
  Stream<Uint8List> bytes,
  File target, {
  int? limit,
  Exception Function(int received)? onExceeded,
}) async {
  final sink = target.openWrite();
  final digestSink = _DigestSink();
  final hasher = sha256.startChunkedConversion(digestSink);
  var received = 0;
  try {
    await for (final chunk in bytes) {
      received += chunk.length;
      if (limit != null && received > limit) {
        throw onExceeded?.call(received) ??
            StateError('openssl3: download exceeded $limit bytes');
      }
      sink.add(chunk);
      hasher.add(chunk);
    }
    await sink.flush();
  } finally {
    await sink.close();
  }
  hasher.close();
  return Written(received, digestSink.digest.toString());
}

Future<File> _copyToShared(
  BuildInput input,
  SupportedTarget target,
  File from,
) {
  final dir = Directory.fromUri(
    input.outputDirectoryShared.resolve('local-${_shortHash(from.path)}/'),
  );
  dir.createSync(recursive: true);
  final to = File(p.join(dir.path, target.installedFileName));
  from.copySync(to.path);
  return Future.value(to);
}

/// How long to wait for a TCP connection / TLS handshake.
const defaultConnectTimeout = Duration(seconds: 30);

/// How long the response (headers, then each chunk of the body) may stall
/// before the download is abandoned.
const defaultIdleTimeout = Duration(seconds: 60);

/// Streams [uri] with proxy support; throws [CouldNotDownloadException].
///
/// Follows redirects, but never from `https` to `http`: the digest check would
/// still catch tampering, yet a mirror that downgrades is misconfigured and the
/// build should say so instead of quietly fetching in the clear.
Stream<Uint8List> downloadStream(
  Uri uri,
  String? releaseTag, {
  Duration connectTimeout = defaultConnectTimeout,
  Duration idleTimeout = defaultIdleTimeout,
}) async* {
  final client = HttpClient()
    ..findProxy = HttpClient.findProxyFromEnvironment
    ..connectionTimeout = connectTimeout
    ..userAgent = 'openssl3 hook (release ${releaseTag ?? 'dev'})';
  HttpClientResponse response;
  try {
    final request = await client.getUrl(uri);
    request.followRedirects = true;
    request.maxRedirects = 10;
    response = await request.close().timeout(idleTimeout);
    final insecure = insecureRedirect(uri, response.redirects);
    if (insecure != null) {
      throw HttpException(
        'redirected from https to an insecure URL: $insecure',
        uri: uri,
      );
    }
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
    await for (final chunk in response.timeout(idleTimeout)) {
      yield _asUint8List(chunk);
    }
  } on TimeoutException catch (e, s) {
    Error.throwWithStackTrace(CouldNotDownloadException(uri, e), s);
  } finally {
    client.close(force: true);
  }
}

/// The first redirect target that leaves `https` for `http`, or `null` when
/// [original] was not `https` or every hop stayed secure. Relative
/// `Location` headers have no scheme and inherit the previous hop's.
Uri? insecureRedirect(Uri original, List<RedirectInfo> redirects) {
  if (original.scheme != 'https') return null;
  for (final r in redirects) {
    if (r.location.scheme == 'http') return r.location;
  }
  return null;
}

Future<String> _sha256Of(Stream<List<int>> bytes) async =>
    (await sha256.bind(bytes).first).toString();

String _shortHash(String s) =>
    sha256.convert(utf8.encode(s)).toString().substring(0, 12);

String _uniqueSuffix() =>
    '$pid-${Random.secure().nextInt(1 << 32).toRadixString(16)}';

void _deleteQuietly(File f) {
  try {
    if (f.existsSync()) f.deleteSync();
  } on FileSystemException {
    // Best effort: a leftover .tmp is never picked up by the cache lookup.
  }
}

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
