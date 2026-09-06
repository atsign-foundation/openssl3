/// Assembles `manifest.json` from the `<file>.json` sidecars in an output
/// directory and regenerates `packages/openssl3/lib/src/manifest.dart`.
///
///     dart run tool/bin/write_manifest.dart --out out --tag v0.1.0
///     dart run tool/bin/write_manifest.dart --out out --tag v0.1.0 --assert
///
/// `--assert` (used by the release gate, ADR-0007) fails if the committed
/// `manifest.dart` differs from what this run would generate, instead of
/// writing it. Hashes only ever enter the repository through this tool.
library;

import 'dart:convert';
import 'dart:io';

import 'package:args/args.dart';
import 'package:crypto/crypto.dart';
import 'package:openssl3/src/hook/manifest_model.dart';
import 'package:openssl3/src/hook/supported_targets.dart';
import 'package:path/path.dart' as p;

Future<void> main(List<String> args) async {
  final parser = ArgParser()
    ..addOption('out', defaultsTo: 'out', help: 'Directory with built assets')
    ..addOption('tag', help: 'Release tag, e.g. v0.1.0 (omit for none)')
    ..addOption(
      'dart-output',
      defaultsTo: 'packages/openssl3/lib/src/manifest.dart',
    )
    ..addOption(
      'source-tarball-sha256',
      help: 'sha256 of the upstream openssl-<ver>.tar.gz used by local_build',
    )
    ..addFlag('assert', negatable: false, help: 'Verify instead of writing')
    ..addFlag(
      'require-all',
      negatable: false,
      help: 'Fail unless every supported target has an asset',
    );
  final opts = parser.parse(args);
  final out = Directory(opts.option('out')!);
  final tag = opts.option('tag');

  final sidecars =
      out
          .listSync()
          .whereType<File>()
          .where(
            (f) =>
                f.path.endsWith('.json') && !f.path.endsWith('manifest.json'),
          )
          .toList()
        ..sort((a, b) => a.path.compareTo(b.path));
  if (sidecars.isEmpty) {
    stderr.writeln('No <file>.json sidecars in ${out.path}');
    exit(66);
  }

  final assets = <String, AssetInfo>{};
  final versions = <String>{};
  final commits = <String?>{};
  for (final sidecar in sidecars) {
    final json = jsonDecode(sidecar.readAsStringSync()) as Map<String, Object?>;
    final file = json['file'] as String;
    final binary = File(p.join(out.path, file));
    if (!binary.existsSync()) {
      stderr.writeln('Sidecar ${sidecar.path} but no $file');
      exit(65);
    }
    // Recompute rather than trust the sidecar: the binary is what ships.
    final bytes = binary.readAsBytesSync();
    final digest = _sha256Hex(bytes);
    if (digest != json['sha256']) {
      stderr.writeln(
        '$file: sidecar sha256 ${json['sha256']} != actual $digest',
      );
      exit(65);
    }
    assets[file] = AssetInfo(
      file: file,
      sha256: digest,
      size: bytes.length,
      target: json['target'] as String,
    );
    versions.add(json['openssl_version'] as String);
    commits.add(json['openssl_commit'] as String?);
  }
  if (versions.length != 1) {
    stderr.writeln('Assets built from different OpenSSL versions: $versions');
    exit(65);
  }
  if (opts.flag('require-all')) {
    final missing = SupportedTarget.all
        .map((t) => t.releaseFileName)
        .where((f) => !assets.containsKey(f))
        .toList();
    if (missing.isNotEmpty) {
      stderr.writeln('Missing assets for: ${missing.join(', ')}');
      exit(65);
    }
  }

  // The upstream tarball hash lets `local_build` verify its download. CI
  // writes out/openssl-<version>.tar.gz.sha256 ("<hex>  <name>" or "<hex>").
  var tarballSha = opts.option('source-tarball-sha256');
  final shaFile = File(
    p.join(out.path, 'openssl-${versions.single}.tar.gz.sha256'),
  );
  if (tarballSha == null && shaFile.existsSync()) {
    tarballSha = shaFile.readAsStringSync().trim().split(RegExp(r'\s+')).first;
  }
  if (tarballSha != null && !RegExp(r'^[0-9a-f]{64}$').hasMatch(tarballSha)) {
    stderr.writeln('Invalid source tarball sha256: $tarballSha');
    exit(65);
  }

  final manifest = Manifest(
    releaseTag: tag,
    opensslVersion: versions.single,
    opensslCommit: commits.length == 1 ? commits.single : null,
    sourceTarballSha256: tarballSha,
    assets: assets,
  );

  final dart = _renderDart(manifest);
  final dartFile = File(opts.option('dart-output')!);
  if (opts.flag('assert')) {
    final current = dartFile.existsSync() ? dartFile.readAsStringSync() : '';
    if (current != dart) {
      stderr.writeln(
        '${dartFile.path} does not match the assets in ${out.path} for tag '
        '$tag. Regenerate it with write_manifest.dart (without --assert) and '
        'commit the result.',
      );
      exit(1);
    }
    stdout.writeln('${dartFile.path} matches ${assets.length} assets');
    return;
  }

  File(p.join(out.path, 'manifest.json')).writeAsStringSync(
    '${const JsonEncoder.withIndent('  ').convert(manifest.toJson())}\n',
  );
  dartFile.writeAsStringSync(dart);
  stdout.writeln(
    'Wrote ${out.path}/manifest.json and ${dartFile.path} '
    '(${assets.length} assets, tag ${tag ?? 'none'})',
  );
}

String _renderDart(Manifest m) {
  final b = StringBuffer()
    ..writeln(
      '// GENERATED by tool/bin/write_manifest.dart. Do not edit by hand.',
    )
    ..writeln('//')
    ..writeln(
      '// Hashes of the prebuilt libraries attached to the GitHub release named by',
    )
    ..writeln(
      '// [releaseTag]. The hook refuses to use any file whose sha256 is not listed',
    )
    ..writeln(
      '// here (ADR-0007). A `null` [releaseTag] means no release exists yet; only',
    )
    ..writeln(
      '// `local_path`, `local_build`, `system` or `test_directory` can work then.',
    )
    ..writeln()
    ..writeln('// dart format off')
    ..writeln()
    ..writeln("import 'hook/manifest_model.dart';")
    ..writeln()
    ..writeln('const String? releaseTag = ${_lit(m.releaseTag)};')
    ..writeln()
    ..writeln('const Manifest compiledInManifest = Manifest(')
    ..writeln('  releaseTag: releaseTag,')
    ..writeln("  opensslVersion: '${m.opensslVersion}',")
    ..writeln('  opensslCommit: ${_lit(m.opensslCommit)},')
    ..writeln('  sourceTarballSha256: ${_lit(m.sourceTarballSha256)},')
    ..writeln('  assets: {');
  for (final name in m.assets.keys.toList()..sort()) {
    final a = m.assets[name]!;
    b
      ..writeln("    '$name': AssetInfo(")
      ..writeln("      file: '$name',")
      ..writeln("      sha256: '${a.sha256}',")
      ..writeln('      size: ${a.size},')
      ..writeln("      target: '${a.target}',")
      ..writeln('    ),');
  }
  b
    ..writeln('  },')
    ..writeln(');');
  return b.toString();
}

String _lit(String? s) => s == null ? 'null' : "'$s'";

String _sha256Hex(List<int> bytes) => sha256.convert(bytes).toString();
