/// Minimal process helper with logging, used by the build tooling.
library;

import 'dart:convert';
import 'dart:io';

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
    '$pretty',
  );
  final process = await Process.start(
    executable,
    arguments,
    workingDirectory: workingDirectory?.path,
    environment: environment,
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
  final result = await Process.run(
    executable,
    arguments,
    workingDirectory: workingDirectory?.path,
    environment: environment,
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
