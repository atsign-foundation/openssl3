// Build hook for package:openssl3.
//
// Resolves the consumer's target, obtains the matching prebuilt
// `libopenssl3_crypto` (download + sha256 verification by default), and
// emits it as a code asset backing the `@Native` bindings in
// `lib/src/third_party/openssl.g.dart`. See PLAN.md §5 and the README for the
// user defines that change where the library comes from.

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:openssl3/src/hook/binary_source.dart';
import 'package:openssl3/src/hook/download.dart';
import 'package:openssl3/src/hook/local_build.dart';
import 'package:openssl3/src/hook/supported_targets.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) {
      return;
    }

    final source = BinarySource.forInput(input);

    if (source case SystemLibrary(:final name, :final linkMode)) {
      stdout.writeln(
        'openssl3: `system: true` set; the app will load the OS '
        'libcrypto as $name. ML-KEM/ML-DSA need OpenSSL >= 3.5 there.',
      );
      output.assets.code.add(
        CodeAsset(
          package: input.packageName,
          name: codeAssetName,
          linkMode: linkMode,
        ),
      );
      return;
    }

    final target = resolveTarget(input);
    final file = switch (source) {
      LocalBuild() => await buildLocally(input, output, source, target),
      BundledSource() => await obtainBundledLibrary(
        input,
        output,
        source,
        target,
      ),
      SystemLibrary() => throw StateError('handled above'),
    };
    if (file == null) return; // test_directory without a build yet
    stdout.writeln(
      'openssl3: bundling ${target.releaseFileName} for ${target.id} '
      'as ${target.installedFileName}',
    );
    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: codeAssetName,
        linkMode: DynamicLoadingBundled(),
        file: file.uri,
      ),
    );
  });
}
