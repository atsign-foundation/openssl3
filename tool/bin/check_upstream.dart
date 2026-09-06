/// Watches upstream OpenSSL for new releases on a release line and, when asked,
/// prepares the bump (ADR-0010).
///
///     dart run tool/bin/check_upstream.dart            # report only
///     dart run tool/bin/check_upstream.dart --apply    # bump submodule etc.
///     dart run tool/bin/check_upstream.dart --line 3.6 --apply
///
/// Release line: `major.minor` of the current submodule by default (the 3.5
/// LTS branch), a specific `--line X.Y`, or `--line latest` for the newest
/// 3.x. With `--apply` it:
///   1. checks out the new tag in `third_party/openssl`,
///   2. sets `packages/openssl3/pubspec.yaml` to `<version>+1`,
///   3. regenerates `lib/src/symbols.dart` and the bindings,
///   4. prepends a CHANGELOG entry with a link to the upstream release notes,
/// and prints `new_version=<v>` / `new_tag=<t>` lines for the workflow.
/// Exit code 0 always; the workflow reads `updated=true|false` from stdout.
library;

import 'dart:io';

import 'package:args/args.dart';
import 'package:openssl3/src/native_build/proc.dart';
import 'package:path/path.dart' as p;

const _upstream = 'https://github.com/openssl/openssl.git';
const _submodule = 'third_party/openssl';
const _pubspec = 'packages/openssl3/pubspec.yaml';
const _changelog = 'packages/openssl3/CHANGELOG.md';

Future<void> main(List<String> args) async {
  final parser = ArgParser()
    ..addOption('line', help: 'X.Y release line, or "latest"')
    ..addFlag('apply', negatable: false)
    ..addFlag('help', abbr: 'h', negatable: false);
  final opts = parser.parse(args);
  if (opts.flag('help')) {
    stdout.writeln(parser.usage);
    return;
  }

  final current = _readVersionDat();
  final line = opts.option('line') ?? '${current.major}.${current.minor}';
  stdout.writeln('current=${current.tag} line=$line');

  final tags = await capture('git', [
    'ls-remote',
    '--tags',
    '--refs',
    _upstream,
    'openssl-3.*',
  ]);
  final candidates = <_Version>[];
  for (final l in tags.split('\n')) {
    final m = RegExp(r'refs/tags/openssl-(\d+)\.(\d+)\.(\d+)$').firstMatch(l);
    if (m == null) continue; // skips alpha/beta tags
    final v = _Version(int.parse(m[1]!), int.parse(m[2]!), int.parse(m[3]!));
    if (line == 'latest' || '${v.major}.${v.minor}' == line) {
      candidates.add(v);
    }
  }
  if (candidates.isEmpty) {
    stdout.writeln('updated=false');
    stdout.writeln('No upstream tags on line $line');
    return;
  }
  candidates.sort();
  final newest = candidates.last;
  stdout.writeln('newest=${newest.tag}');
  if (newest.compareTo(current) <= 0) {
    stdout.writeln('updated=false');
    return;
  }
  stdout.writeln('new_version=${newest.string}');
  stdout.writeln('new_tag=${newest.tag}');
  stdout.writeln(
    'release_notes=https://github.com/openssl/openssl/releases/tag/${newest.tag}',
  );
  if (!opts.flag('apply')) {
    stdout.writeln('updated=false');
    stdout.writeln('(re-run with --apply to bump)');
    return;
  }

  // 1. Submodule.
  await run('git', [
    '-C',
    _submodule,
    'fetch',
    '--depth',
    '1',
    'origin',
    'tag',
    newest.tag,
  ]);
  await run('git', ['-C', _submodule, 'checkout', '-q', newest.tag]);

  // 2. Version.
  final pubspec = File(_pubspec);
  final text = pubspec.readAsStringSync();
  final newVersion = '${newest.string}+1';
  pubspec.writeAsStringSync(
    text.replaceFirst(
      RegExp(r'^version:.*$', multiLine: true),
      'version: $newVersion',
    ),
  );

  // 3. Generated sources (Configure + build_generated run inside the tools).
  await run('dart', ['run', 'tool/bin/generate_bindings.dart']);
  final hostBuild = Directory(p.join('.dart_tool', 'openssl_build'))
      .listSync()
      .whereType<Directory>()
      .map((d) => File(p.join(d.path, 'include', 'openssl', 'configuration.h')))
      .firstWhere((f) => f.existsSync());
  await run('dart', [
    'run',
    'tool/bin/gen_symbols.dart',
    '--configuration-h',
    hostBuild.path,
  ]);
  await run('dart', ['format', 'packages/openssl3']);

  // 4. Changelog.
  final changelog = File(_changelog);
  final existing = changelog.existsSync()
      ? changelog.readAsStringSync()
      : '# Changelog\n\n';
  final entry =
      '## $newVersion\n\n'
      '- Update bundled OpenSSL to ${newest.string} '
      '([release notes](https://github.com/openssl/openssl/releases/tag/${newest.tag})).\n'
      '- Regenerated `symbols.dart` and the `@Native` bindings.\n\n';
  final marker = RegExp(r'^## ', multiLine: true);
  final at = marker.firstMatch(existing)?.start;
  changelog.writeAsStringSync(
    at == null ? '$existing$entry' : existing.replaceRange(at, at, entry),
  );

  stdout.writeln('updated=true');
}

_Version _readVersionDat() {
  final lines = File(p.join(_submodule, 'VERSION.dat')).readAsLinesSync();
  String get(String k) =>
      lines.firstWhere((l) => l.startsWith('$k=')).split('=')[1].trim();
  return _Version(
    int.parse(get('MAJOR')),
    int.parse(get('MINOR')),
    int.parse(get('PATCH')),
  );
}

final class _Version implements Comparable<_Version> {
  final int major, minor, patch;
  const _Version(this.major, this.minor, this.patch);

  String get string => '$major.$minor.$patch';
  String get tag => 'openssl-$string';

  @override
  int compareTo(_Version o) {
    if (major != o.major) return major.compareTo(o.major);
    if (minor != o.minor) return minor.compareTo(o.minor);
    return patch.compareTo(o.patch);
  }

  @override
  String toString() => string;
}
