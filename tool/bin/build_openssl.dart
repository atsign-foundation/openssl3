/// Builds one prebuilt `libopenssl3_crypto` for a target id.
///
/// Usage (from the repository root):
///
///     dart run tool/bin/build_openssl.dart macos-arm64 [--out out]
///         [--source third_party/openssl] [--build-dir .dart_tool/openssl_build]
///         [--no-asm] [--reuse-build-dir] [--skip-verify] [--jobs N]
///
/// Run with `--list` to print the known target ids, or
/// `--print-configure <target-id>` to print that target's `Configure`
/// arguments one per line (used by `upstream-tests.yml`).
library;

import 'dart:io';
import 'dart:isolate';

import 'package:args/args.dart';
import 'package:openssl3/src/native_build/build.dart';
import 'package:openssl3/src/native_build/proc.dart';
import 'package:openssl3/src/native_build/targets.dart';
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
    ..addOption(
      'docker',
      help:
          'Run every build command inside this running container (the '
          'workspace must be bind-mounted at the same absolute path); used '
          'for the musl targets.',
    )
    ..addFlag('list', negatable: false, help: 'List target ids and exit')
    ..addFlag(
      'print-configure',
      negatable: false,
      help: 'Print the Configure arguments for the target, one per line',
    )
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

  dockerContainer = opts.option('docker');
  final target = BuildTarget.byId(opts.rest.single);
  if (opts.flag('print-configure')) {
    configureArgsFor(
      target,
      noAsm: opts.flag('no-asm'),
    ).forEach(stdout.writeln);
    return;
  }
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
      packageRoot: await _packageRoot(),
      noAsm: opts.flag('no-asm'),
      reuseBuildDir: opts.flag('reuse-build-dir'),
      skipVerify: opts.flag('skip-verify'),
      jobs: int.parse(opts.option('jobs')!),
    ),
  );
  stdout.writeln(result.library.path);
}

/// The openssl3 package root, resolved through the package config so this
/// works from any working directory inside the workspace.
Future<Directory> _packageRoot() async {
  final lib = await Isolate.resolvePackageUri(Uri.parse('package:openssl3/'));
  if (lib == null) throw StateError('package:openssl3 not resolvable');
  return Directory.fromUri(lib).parent;
}
