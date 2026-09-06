/// Builds one prebuilt `libopenssl_assets_crypto` for a target id.
///
/// Usage (from the repository root):
///
///     dart run tool/bin/build_openssl.dart macos-arm64 [--out out]
///         [--source third_party/openssl] [--build-dir .dart_tool/openssl_build]
///         [--no-asm] [--reuse-build-dir] [--skip-verify] [--jobs N]
///
/// Run with `--list` to print the known target ids.
library;

import 'dart:io';

import 'package:args/args.dart';
import 'package:openssl_assets_tool/build.dart';
import 'package:openssl_assets_tool/targets.dart';
import 'package:path/path.dart' as p;

Future<void> main(List<String> args) async {
  final parser = ArgParser()
    ..addOption('source', defaultsTo: 'third_party/openssl')
    ..addOption('build-dir')
    ..addOption('out', defaultsTo: 'out')
    ..addOption('jobs', defaultsTo: '${Platform.numberOfProcessors}')
    ..addFlag('no-asm', negatable: false)
    ..addFlag('reuse-build-dir', negatable: false)
    ..addFlag('skip-verify', negatable: false)
    ..addFlag('list', negatable: false, help: 'List target ids and exit')
    ..addFlag('help', abbr: 'h', negatable: false);
  final opts = parser.parse(args);
  if (opts.flag('help') || (opts.rest.isEmpty && !opts.flag('list'))) {
    stdout.writeln('Usage: build_openssl.dart <target-id> [options]\n');
    stdout.writeln(parser.usage);
    exit(opts.flag('help') ? 0 : 64);
  }
  if (opts.flag('list')) {
    for (final t in BuildTarget.all) {
      stdout.writeln(
        '${t.id.padRight(18)} ${t.configureTarget.padRight(28)} '
        '${t.releaseFileName}',
      );
    }
    return;
  }

  final target = BuildTarget.byId(opts.rest.single);
  final source = Directory(opts.option('source')!);
  if (!File(p.join(source.path, 'Configure')).existsSync()) {
    stderr.writeln(
      'No OpenSSL source at ${source.path} '
      '(run `git submodule update --init`).',
    );
    exit(66);
  }
  final result = await buildTarget(
    BuildOptions(
      target: target,
      source: source,
      buildDir: Directory(
        opts.option('build-dir') ??
            p.join('.dart_tool', 'openssl_build', target.id),
      ),
      outDir: Directory(opts.option('out')!),
      noAsm: opts.flag('no-asm'),
      reuseBuildDir: opts.flag('reuse-build-dir'),
      skipVerify: opts.flag('skip-verify'),
      jobs: int.parse(opts.option('jobs')!),
    ),
  );
  stdout.writeln(result.library.path);
}
