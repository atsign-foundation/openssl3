/// Minimal process helper with logging, used by the build tooling.
library;

import 'dart:convert';
import 'dart:io';

/// When set, every command runs inside this Docker container via
/// `docker exec -w <cwd> -e K=V ... <container> <cmd>`. The workspace must be
/// bind-mounted at the same absolute path inside the container. Used by CI to
/// build the musl targets in `alpine` the way OpenSSL's own os-zoo.yml does,
/// while the (glibc-only) Dart tooling stays on the host.
String? dockerContainer;

/// Environment keys forwarded into the container with `-e` (beyond what the
/// tool passes explicitly). PATH is deliberately not forwarded.
const _forwardedEnv = {
  'ANDROID_NDK_ROOT',
  'CC',
  'CFLAGS',
  'LDFLAGS',
  'MAKEFLAGS',
};

(String, List<String>, Directory?, Map<String, String>?) _wrap(
  String executable,
  List<String> arguments,
  Directory? workingDirectory,
  Map<String, String>? environment,
) {
  final container = dockerContainer;
  if (container == null) {
    return (executable, arguments, workingDirectory, environment);
  }
  final cwd = (workingDirectory ?? Directory.current).absolute.path;
  final envArgs = <String>[];
  environment?.forEach((k, v) {
    if (_forwardedEnv.contains(k) || !Platform.environment.containsKey(k)) {
      envArgs.addAll(['-e', '$k=$v']);
    }
  });
  return (
    'docker',
    ['exec', '-w', cwd, ...envArgs, container, executable, ...arguments],
    null,
    null,
  );
}

/// Runs [executable] with [arguments], streaming output to stdout/stderr, and
/// throws if the exit code is non-zero.
Future<void> run(
  String executable,
  List<String> arguments, {
  Directory? workingDirectory,
  Map<String, String>? environment,
  bool quiet = false,
}) async {
  final pretty = [executable, ...arguments].map(_quote).join(' ');
  stdout.writeln(
    '\$ ${workingDirectory == null ? '' : '(cd ${workingDirectory.path}) '}'
    '$pretty${dockerContainer == null ? '' : '  [in docker $dockerContainer]'}',
  );
  final (exe, args, cwd, env) = _wrap(
    executable,
    arguments,
    workingDirectory,
    environment,
  );
  final process = await Process.start(
    exe,
    args,
    workingDirectory: cwd?.path,
    environment: env,
    runInShell: Platform.isWindows,
  );
  final out = <String>[];
  final futures = [
    process.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .forEach((l) {
          out.add(l);
          if (!quiet) stdout.writeln(l);
        }),
    process.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .forEach((l) {
          out.add(l);
          if (!quiet) stderr.writeln(l);
        }),
  ];
  final code = await process.exitCode;
  await Future.wait(futures);
  if (code != 0) {
    throw ProcessException(
      executable,
      arguments,
      quiet ? out.join('\n') : 'see output above',
      code,
    );
  }
}

/// Runs and returns trimmed stdout; throws on non-zero exit.
Future<String> capture(
  String executable,
  List<String> arguments, {
  Directory? workingDirectory,
  Map<String, String>? environment,
}) async {
  final (exe, args, cwd, env) = _wrap(
    executable,
    arguments,
    workingDirectory,
    environment,
  );
  final result = await Process.run(
    exe,
    args,
    workingDirectory: cwd?.path,
    environment: env,
    runInShell: Platform.isWindows,
  );
  if (result.exitCode != 0) {
    throw ProcessException(
      executable,
      arguments,
      '${result.stdout}\n${result.stderr}',
      result.exitCode,
    );
  }
  return (result.stdout as String).trim();
}

/// Like [capture] but returns `null` instead of throwing when the tool is
/// missing or fails.
Future<String?> tryCapture(String executable, List<String> arguments) async {
  try {
    return await capture(executable, arguments);
  } on ProcessException {
    return null;
  }
}

String _quote(String s) =>
    s.contains(RegExp(r'[\s"]')) ? '"${s.replaceAll('"', r'\"')}"' : s;
