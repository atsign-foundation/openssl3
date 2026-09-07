@Tags(['hook'])
library;

import 'dart:convert';
import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart';
import 'package:hooks/hooks.dart';
import 'package:openssl3/src/hook/binary_source.dart';
import 'package:openssl3/src/hook/download.dart';
import 'package:openssl3/src/hook/manifest_model.dart';
import 'package:openssl3/src/hook/supported_targets.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import '../../hook/build.dart' as hook;

/// Builds a [BuildInput] the way the hooks runner would, without running the
/// hook's `main` (which calls `exit()` on failure).
BuildInput makeInput({
  Map<String, Object?> defines = const {},
  OS os = OS.macOS,
  Architecture arch = Architecture.arm64,
  IOSSdk iosSdk = IOSSdk.iPhoneOS,
  required Directory temp,
  String shared = 'shared',
}) {
  final sharedDir = Directory(p.join(temp.path, shared))..createSync();
  final builder = BuildInputBuilder()
    ..setupShared(
      packageRoot: Directory.current.uri,
      packageName: 'openssl3',
      outputFile: temp.uri.resolve('output.json'),
      outputDirectoryShared: sharedDir.uri,
      userDefines: PackageUserDefines(
        workspacePubspec: PackageUserDefinesSource(
          defines: defines,
          basePath: temp.uri,
        ),
      ),
    )
    ..setupBuildInput()
    ..config.setupBuild(linkingEnabled: false);
  CodeAssetExtension(
    linkModePreference: LinkModePreference.dynamic,
    targetArchitecture: arch,
    targetOS: os,
    iOS: os == OS.iOS
        ? IOSCodeConfig(targetSdk: iosSdk, targetVersion: 13)
        : null,
    macOS: os == OS.macOS ? MacOSCodeConfig(targetVersion: 13) : null,
    android: os == OS.android ? AndroidCodeConfig(targetNdkApi: 21) : null,
  ).setupBuildInput(builder);
  return builder.build();
}

String sha256Hex(List<int> bytes) => sha256.convert(bytes).toString();

void main() {
  late Directory temp;
  setUp(() => temp = Directory.systemTemp.createTempSync('openssl3_hook_'));
  tearDown(() => temp.deleteSync(recursive: true));

  group('resolveTarget', () {
    test('maps hook configs to supported targets', () {
      expect(resolveTarget(makeInput(temp: temp)).id, 'macos-arm64');
      expect(
        resolveTarget(
          makeInput(
            temp: temp,
            os: OS.iOS,
            arch: Architecture.x64,
            iosSdk: IOSSdk.iPhoneSimulator,
          ),
        ).id,
        'ios_sim-x64',
      );
      expect(
        resolveTarget(
          makeInput(temp: temp, os: OS.android, arch: Architecture.arm),
        ).id,
        'android-arm',
      );
      expect(
        resolveTarget(
          makeInput(temp: temp, os: OS.windows, arch: Architecture.arm64),
        ).id,
        'windows-arm64',
      );
    });

    test('linux_libc selects the musl build', () {
      expect(
        resolveTarget(
          makeInput(
            temp: temp,
            os: OS.linux,
            arch: Architecture.x64,
            defines: {'linux_libc': 'musl'},
          ),
        ).id,
        'linux_musl-x64',
      );
      expect(
        resolveTarget(
          makeInput(
            temp: temp,
            os: OS.linux,
            arch: Architecture.arm64,
            defines: {'linux_libc': 'glibc'},
          ),
        ).id,
        'linux-arm64',
      );
      expect(
        () => resolveTarget(
          makeInput(
            temp: temp,
            os: OS.linux,
            arch: Architecture.x64,
            defines: {'linux_libc': 'uclibc'},
          ),
        ),
        throwsArgumentError,
      );
    });

    test('unsupported pairs fail with a clear message', () {
      expect(
        () => resolveTarget(
          makeInput(temp: temp, os: OS.linux, arch: Architecture.ia32),
        ),
        throwsA(
          isA<UnsupportedError>().having(
            (e) => e.message,
            'message',
            allOf(contains('linux glibc/ia32'), contains('local_build')),
          ),
        ),
      );
      expect(
        () => resolveTarget(
          makeInput(temp: temp, os: OS.android, arch: Architecture.ia32),
        ),
        throwsUnsupportedError,
      );
    });
  });

  group('BinarySource.forInput', () {
    test('defaults to the GitHub release with the compiled-in manifest', () {
      final source = BinarySource.forInput(makeInput(temp: temp));
      expect(source, isA<PrecompiledFromRelease>());
      final release = source as PrecompiledFromRelease;
      expect(release.urlPattern, defaultUrlPattern);
      expect(
        release.downloadUri('x.dylib').toString(),
        'https://github.com/cconstab/openssl3/releases/download/null/x.dylib',
        reason: 'no release tag compiled in yet',
      );
    });

    test('url_pattern replaces placeholders', () {
      final source =
          BinarySource.forInput(
                makeInput(
                  temp: temp,
                  defines: {
                    'url_pattern': r'https://m.example/$RELEASE_TAG/$FILENAME',
                    'manifest_override': _writeManifest(temp, {}, 'v9.9.9'),
                  },
                ),
              )
              as PrecompiledFromRelease;
      expect(
        source.downloadUri('f.so').toString(),
        'https://m.example/v9.9.9/f.so',
      );
    });

    test('system picks OS-specific default names', () {
      String nameFor(OS os, Architecture arch) =>
          (BinarySource.forInput(
                    makeInput(
                      temp: temp,
                      os: os,
                      arch: arch,
                      defines: {'system': true},
                    ),
                  )
                  as SystemLibrary)
              .name;
      expect(nameFor(OS.linux, Architecture.x64), 'libcrypto.so.3');
      expect(nameFor(OS.android, Architecture.arm64), 'libcrypto.so.3');
      expect(nameFor(OS.macOS, Architecture.arm64), 'libcrypto.3.dylib');
      expect(nameFor(OS.windows, Architecture.x64), 'libcrypto-3-x64.dll');
      expect(nameFor(OS.windows, Architecture.arm64), 'libcrypto-3-arm64.dll');
      expect(() => nameFor(OS.iOS, Architecture.arm64), throwsUnsupportedError);
    });

    test('system_name accepts a string or a per-OS map', () {
      final plain =
          BinarySource.forInput(
                makeInput(
                  temp: temp,
                  defines: {'system': true, 'system_name': 'libfoo.dylib'},
                ),
              )
              as SystemLibrary;
      expect(plain.name, 'libfoo.dylib');
      expect(
        plain.linkMode,
        isA<DynamicLoadingSystem>().having(
          (m) => m.uri.toString(),
          'uri',
          'libfoo.dylib',
        ),
      );
      final mapped =
          BinarySource.forInput(
                makeInput(
                  temp: temp,
                  os: OS.windows,
                  arch: Architecture.x64,
                  defines: {
                    'system': 'true',
                    'system_name': {'windows': 'crypto.dll', 'default': 'x'},
                  },
                ),
              )
              as SystemLibrary;
      expect(mapped.name, 'crypto.dll');
    });

    test('mutually exclusive defines are rejected', () {
      expect(
        () => BinarySource.forInput(
          makeInput(
            temp: temp,
            defines: {'system': true, 'local_path': 'a.dylib'},
          ),
        ),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('mutually exclusive'),
          ),
        ),
      );
      expect(
        () => BinarySource.forInput(
          makeInput(temp: temp, defines: {'local_build': 'yes'}),
        ),
        throwsArgumentError,
      );
    });

    test('local_path resolves relative to the workspace pubspec', () {
      final source =
          BinarySource.forInput(
                makeInput(
                  temp: temp,
                  defines: {'local_path': 'native/lib.dylib'},
                ),
              )
              as LocalPath;
      expect(source.file.path, p.join(temp.path, 'native', 'lib.dylib'));
      expect(source.verify, isTrue);
    });
  });

  group('obtainBundledLibrary', () {
    final target = SupportedTarget.byId('macos-arm64');
    final payload = List<int>.generate(4096, (i) => (i * 7) & 0xff);

    test(
      'test_directory: verifies against the .json sidecar and caches',
      () async {
        final dir = _fakeReleaseDir(temp, target, payload);
        final input = makeInput(temp: temp);
        final output = BuildOutputBuilder();
        final file = await obtainBundledLibrary(
          input,
          output,
          PrecompiledFromDirectory(dir),
          target,
        );
        expect(p.basename(file!.path), target.installedFileName);
        expect(file.readAsBytesSync(), payload);
        expect(
          p.isWithin(input.outputDirectoryShared.toFilePath(), file.path),
          isTrue,
        );
        final first = file.statSync().modified;
        final again = await obtainBundledLibrary(
          input,
          output,
          PrecompiledFromDirectory(dir),
          target,
        );
        expect(again!.path, file.path);
        expect(again.statSync().modified, first, reason: 'cache hit');
      },
    );

    test('test_directory: missing file yields null (bootstrap mode)', () async {
      final empty = Directory(p.join(temp.path, 'empty'))..createSync();
      final input = makeInput(temp: temp);
      expect(
        await obtainBundledLibrary(
          input,
          BuildOutputBuilder(),
          PrecompiledFromDirectory(empty),
          target,
        ),
        isNull,
      );
    });

    test('test_directory: wrong sidecar hash fails closed', () async {
      final dir = _fakeReleaseDir(temp, target, payload, sha256: 'ff' * 32);
      final input = makeInput(temp: temp);
      await expectLater(
        obtainBundledLibrary(
          input,
          BuildOutputBuilder(),
          PrecompiledFromDirectory(dir),
          target,
        ),
        throwsA(isA<DigestMismatchException>()),
      );
      final leftovers = Directory.fromUri(
        input.outputDirectoryShared,
      ).listSync(recursive: true).whereType<File>();
      expect(leftovers, isEmpty, reason: 'no partial files are kept');
    });

    test(
      'release download: verified, cached, mismatch and 404 handled',
      () async {
        final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        var hits = 0;
        server.listen((req) {
          hits++;
          if (req.uri.path.endsWith(target.releaseFileName)) {
            req.response
              ..statusCode = 200
              ..add(payload);
          } else {
            req.response.statusCode = 404;
          }
          req.response.close();
        });
        addTearDown(() => server.close(force: true));
        final pattern =
            'http://127.0.0.1:${server.port}/\$RELEASE_TAG/\$FILENAME';

        Manifest manifest(String sha, {String? file}) => Manifest(
          releaseTag: 'v0.0.1',
          opensslVersion: '3.5.8',
          opensslCommit: null,
          sourceTarballSha256: null,
          assets: {
            (file ?? target.releaseFileName): AssetInfo(
              file: file ?? target.releaseFileName,
              sha256: sha,
              size: payload.length,
              target: target.id,
            ),
          },
        );

        final input = makeInput(temp: temp);
        final ok = PrecompiledFromRelease(
          urlPattern: pattern,
          manifest: manifest(sha256Hex(payload)),
        );
        final file = await obtainBundledLibrary(
          input,
          BuildOutputBuilder(),
          ok,
          target,
        );
        expect(file.readAsBytesSync(), payload);
        expect(hits, 1);

        await obtainBundledLibrary(input, BuildOutputBuilder(), ok, target);
        expect(hits, 1, reason: 'warm cache makes no network request');

        await expectLater(
          obtainBundledLibrary(
            input,
            BuildOutputBuilder(),
            PrecompiledFromRelease(
              urlPattern: pattern,
              manifest: manifest('00' * 32),
            ),
            target,
          ),
          throwsA(isA<DigestMismatchException>()),
        );

        await expectLater(
          obtainBundledLibrary(
            input,
            BuildOutputBuilder(),
            PrecompiledFromRelease(
              urlPattern: 'http://127.0.0.1:${server.port}/missing/\$FILENAME',
              manifest: manifest(sha256Hex(payload)),
            ),
            SupportedTarget.byId('macos-x64'),
          ),
          throwsA(isA<NoPrebuiltForReleaseException>()),
          reason: 'target not in manifest is rejected before any download',
        );

        await expectLater(
          obtainBundledLibrary(
            input,
            BuildOutputBuilder(),
            PrecompiledFromRelease(
              urlPattern: 'http://127.0.0.1:${server.port}/missing/nothing',
              manifest: manifest('11' * 32),
            ),
            target,
          ),
          throwsA(isA<CouldNotDownloadException>()),
        );
      },
    );

    test('release download without a release tag explains itself', () async {
      final input = makeInput(temp: temp);
      await expectLater(
        obtainBundledLibrary(
          input,
          BuildOutputBuilder(),
          const PrecompiledFromRelease(
            urlPattern: defaultUrlPattern,
            manifest: Manifest(
              releaseTag: null,
              opensslVersion: '3.5.8',
              opensslCommit: null,
              sourceTarballSha256: null,
              assets: {},
            ),
          ),
          target,
        ),
        throwsA(
          isA<NoPrebuiltForReleaseException>().having(
            (e) => e.toString(),
            'message',
            contains('test_directory'),
          ),
        ),
      );
    });

    test(
      'local_path: verified against manifest, or copied unverified',
      () async {
        final src = File(p.join(temp.path, 'mine.dylib'))
          ..writeAsBytesSync(payload);
        final input = makeInput(temp: temp);
        final manifest = Manifest(
          releaseTag: 'v1',
          opensslVersion: '3.5.8',
          opensslCommit: null,
          sourceTarballSha256: null,
          assets: {
            target.releaseFileName: AssetInfo(
              file: target.releaseFileName,
              sha256: sha256Hex(payload),
              size: payload.length,
              target: target.id,
            ),
          },
        );
        final verified = await obtainBundledLibrary(
          input,
          BuildOutputBuilder(),
          LocalPath(src, verify: true, manifest: manifest),
          target,
        );
        expect(verified!.readAsBytesSync(), payload);

        // A changed file with a cold cache is rejected. (With a warm cache the
        // previously verified copy is reused: the cache is keyed by digest.)
        src.writeAsBytesSync([1, 2, 3]);
        final coldInput = makeInput(temp: temp, shared: 'shared2');
        await expectLater(
          obtainBundledLibrary(
            coldInput,
            BuildOutputBuilder(),
            LocalPath(src, verify: true, manifest: manifest),
            target,
          ),
          throwsA(isA<DigestMismatchException>()),
        );
        final unverified = await obtainBundledLibrary(
          coldInput,
          BuildOutputBuilder(),
          LocalPath(src, verify: false, manifest: manifest),
          target,
        );
        expect(unverified!.readAsBytesSync(), [1, 2, 3]);
        expect(p.basename(unverified.path), target.installedFileName);
      },
    );
  });

  group('hook end to end', () {
    test('system: true emits DynamicLoadingSystem', () async {
      await testCodeBuildHook(
        mainMethod: hook.main,
        targetOS: OS.linux,
        targetArchitecture: Architecture.x64,
        userDefines: PackageUserDefines(
          workspacePubspec: PackageUserDefinesSource(
            defines: {'system': true},
            basePath: temp.uri,
          ),
        ),
        check: (input, output) {
          final asset = output.assets.code.single;
          expect(asset.id, 'package:openssl3/$codeAssetName');
          expect(
            asset.linkMode,
            isA<DynamicLoadingSystem>().having(
              (m) => m.uri.toString(),
              'uri',
              'libcrypto.so.3',
            ),
          );
          expect(asset.file, isNull);
        },
      );
    });

    test(
      'test_directory with a real build emits DynamicLoadingBundled',
      () async {
        final out = Directory(p.join('..', '..', 'out'));
        final host = SupportedTarget.forCodeConfig(
          _hostConfig(),
          linuxLibc: Libc.glibc,
        );
        final built = host == null
            ? null
            : File(p.join(out.path, host.releaseFileName));
        if (built == null || !built.existsSync()) {
          markTestSkipped(
            'no host build in out/; run dart run tool/bin/build_openssl.dart',
          );
          return;
        }
        await testCodeBuildHook(
          mainMethod: hook.main,
          userDefines: PackageUserDefines(
            workspacePubspec: PackageUserDefinesSource(
              defines: {'test_directory': out.absolute.path},
              basePath: Directory.current.uri,
            ),
          ),
          check: (input, output) {
            final asset = output.assets.code.single;
            expect(asset.id, 'package:openssl3/$codeAssetName');
            expect(asset.linkMode, isA<DynamicLoadingBundled>());
            final file = File.fromUri(asset.file!);
            expect(p.basename(file.path), host!.installedFileName);
            expect(file.lengthSync(), built.lengthSync());
          },
        );
      },
    );
  });
}

CodeConfig _hostConfig() {
  final builder = BuildInputBuilder()
    ..setupShared(
      packageRoot: Directory.current.uri,
      packageName: 'openssl3',
      outputFile: Directory.systemTemp.uri.resolve('o.json'),
      outputDirectoryShared: Directory.systemTemp.uri,
    )
    ..setupBuildInput()
    ..config.setupBuild(linkingEnabled: false);
  CodeAssetExtension(
    linkModePreference: LinkModePreference.dynamic,
    targetArchitecture: Architecture.current,
    targetOS: OS.current,
    macOS: OS.current == OS.macOS ? MacOSCodeConfig(targetVersion: 13) : null,
  ).setupBuildInput(builder);
  return builder.build().config.code;
}

/// Writes `<temp>/release/<file>` and its `.json` sidecar like
/// `tool/bin/build_openssl.dart` does.
Directory _fakeReleaseDir(
  Directory temp,
  SupportedTarget target,
  List<int> payload, {
  String? sha256,
}) {
  final dir = Directory(p.join(temp.path, 'release'))..createSync();
  File(p.join(dir.path, target.releaseFileName)).writeAsBytesSync(payload);
  File(p.join(dir.path, '${target.releaseFileName}.json')).writeAsStringSync(
    jsonEncode({
      'target': target.id,
      'file': target.releaseFileName,
      'sha256': sha256 ?? sha256Hex(payload),
      'size': payload.length,
    }),
  );
  return dir;
}

String _writeManifest(
  Directory temp,
  Map<String, AssetInfo> assets,
  String tag,
) {
  final f = File(p.join(temp.path, 'manifest.json'));
  f.writeAsStringSync(
    jsonEncode(
      Manifest(
        releaseTag: tag,
        opensslVersion: '3.5.8',
        opensslCommit: null,
        sourceTarballSha256: null,
        assets: assets,
      ).toJson(),
    ),
  );
  return f.path;
}
