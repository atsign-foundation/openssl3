@Tags(['local_build'])
library;

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import '../../hook/build.dart' as hook;

/// End to end: `local_build: true` with `source_path` = the submodule, for the
/// host target. Needs Perl and a C toolchain; several minutes on first run.
void main() {
  test('local_build compiles, verifies and bundles libcrypto', () async {
    final source = Directory(p.absolute('..', '..', 'third_party', 'openssl'));
    if (!File(p.join(source.path, 'Configure')).existsSync()) {
      markTestSkipped('submodule not checked out');
      return;
    }
    await testCodeBuildHook(
      mainMethod: hook.main,
      userDefines: PackageUserDefines(
        workspacePubspec: PackageUserDefinesSource(
          defines: {'local_build': true, 'source_path': source.path},
          basePath: Directory.current.uri,
        ),
      ),
      check: (input, output) {
        final asset = output.assets.code.single;
        expect(asset.linkMode, isA<DynamicLoadingBundled>());
        final file = File.fromUri(asset.file!);
        expect(file.existsSync(), isTrue);
        expect(file.lengthSync(), greaterThan(3 * 1024 * 1024));
        expect(
          p.basename(file.path),
          OS.current.dylibFileName('openssl3_crypto'),
        );
      },
    );
  }, timeout: const Timeout(Duration(minutes: 30)));
}
