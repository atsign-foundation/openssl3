@Tags(['hook'])
library;

import 'dart:io';

import 'package:openssl3/src/manifest.dart';
import 'package:openssl3/src/symbols.dart';
import 'package:test/test.dart';

/// ADR-0010: the package version is `<openssl version>+<n>` (or `-dev.n`).
void main() {
  test('pubspec version tracks the bundled OpenSSL version', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();
    final version = RegExp(
      r'^version:\s*(\S+)',
      multiLine: true,
    ).firstMatch(pubspec)!.group(1)!;
    final core = version.split(RegExp(r'[+-]')).first;
    expect(
      core,
      opensslAbiVersion,
      reason: 'symbols.dart was generated from this OpenSSL',
    );
    expect(
      core,
      compiledInManifest.opensslVersion,
      reason: 'manifest.dart records this OpenSSL',
    );
    expect(
      version,
      matches(RegExp(r'^\d+\.\d+\.\d+(\+\d+|-dev\.\d+)$')),
      reason: 'allowed forms: 3.5.8+1 or 3.5.8-dev.1',
    );
  });

  test('submodule VERSION.dat agrees when the submodule is checked out', () {
    final versionDat = File('../../third_party/openssl/VERSION.dat');
    if (!versionDat.existsSync()) {
      markTestSkipped('submodule not checked out');
      return;
    }
    final lines = versionDat.readAsLinesSync();
    String get(String k) =>
        lines.firstWhere((l) => l.startsWith('$k=')).split('=')[1].trim();
    expect(
      '${get('MAJOR')}.${get('MINOR')}.${get('PATCH')}',
      opensslAbiVersion,
    );
  });
}
