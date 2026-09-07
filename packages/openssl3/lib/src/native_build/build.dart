/// The per-target build pipeline: Configure → make libcrypto.a → link our
/// distinct-named shared library → verify → copy to the output directory.
///
/// The same code runs in CI (`tool/bin/build_openssl.dart`) and, later, behind
/// the `local_build` user define in the hook.
library;

import 'dart:convert';
import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as p;

import 'abi.dart';
import 'proc.dart';
import 'required_symbols.dart';
import 'targets.dart';
import 'verify.dart';

final class BuildOptions {
  final BuildTarget target;

  /// OpenSSL source tree (the `third_party/openssl` submodule or an unpacked
  /// release tarball).
  final Directory source;

  /// Out-of-tree build directory. Wiped unless [reuseBuildDir] is set.
  final Directory buildDir;

  /// Where the finished `<releaseFileName>` and its `.json` are written.
  final Directory outDir;

  final bool noAsm;
  final bool reuseBuildDir;
  final bool skipVerify;
  final int jobs;

  /// Extra environment for Configure/make (e.g. `ANDROID_NDK_ROOT`).
  final Map<String, String> environment;

  /// Root of the `openssl3` package (holds `src/native/openssl3_shim.c`).
  final Directory packageRoot;

  const BuildOptions({
    required this.target,
    required this.source,
    required this.buildDir,
    required this.outDir,
    required this.packageRoot,
    this.noAsm = false,
    this.reuseBuildDir = false,
    this.skipVerify = false,
    this.jobs = 4,
    this.environment = const {},
  });
}

final class BuildResult {
  final File library;
  final Map<String, Object?> buildInfo;
  const BuildResult(this.library, this.buildInfo);
}

Future<BuildResult> buildTarget(BuildOptions options) async {
  // Everything below runs with the build directory as working directory, so
  // every path we hand to a tool must be absolute.
  final o = BuildOptions(
    target: options.target,
    source: options.source.absolute,
    buildDir: options.buildDir.absolute,
    outDir: options.outDir.absolute,
    packageRoot: options.packageRoot.absolute,
    noAsm: options.noAsm,
    reuseBuildDir: options.reuseBuildDir,
    skipVerify: options.skipVerify,
    jobs: options.jobs,
    environment: options.environment,
  );
  final t = o.target;
  final env = {...Platform.environment, ...o.environment};
  final isWindows = t.os == OS.windows;
  if (t.os == OS.android) {
    _prepareAndroidEnv(env);
  }

  if (!o.reuseBuildDir && o.buildDir.existsSync()) {
    o.buildDir.deleteSync(recursive: true);
  }
  o.buildDir.createSync(recursive: true);
  o.outDir.createSync(recursive: true);

  // 1. Configure (out of tree).
  final configureArgs = <String>[
    t.configureTarget,
    if (t.crossCompilePrefix != null)
      '--cross-compile-prefix=${t.crossCompilePrefix}',
    ...commonConfigureArgs,
    ...t.extraConfigureArgs,
    if (o.noAsm) 'no-asm',
    ...t.cflags,
  ];
  final configureScript = p.join(o.source.absolute.path, 'Configure');
  await run(
    'perl',
    [configureScript, ...configureArgs],
    workingDirectory: o.buildDir,
    environment: env,
  );

  // 2. Generate headers, then build the static library only (not libssl).
  final staticLib = isWindows ? 'libcrypto.lib' : 'libcrypto.a';
  final make = isWindows ? 'nmake' : 'make';
  final makeFlags = isWindows ? ['/NOLOGO'] : ['-j${o.jobs}'];
  for (final goal in ['build_generated', staticLib]) {
    await run(
      make,
      [...makeFlags, goal],
      workingDirectory: o.buildDir,
      environment: env,
      quiet: goal == staticLib,
    );
  }

  // 3. Export list from OpenSSL's own ABI list, filtered like mkdef.pl does.
  final configurationH = File(
    p.join(o.buildDir.path, 'include', 'openssl', 'configuration.h'),
  );
  final disabled = disabledFeaturesFromConfigurationHeader(
    configurationH.readAsStringSync(),
  );
  final abi = AbiEntry.parseFile(
    File(p.join(o.source.path, 'util', 'libcrypto.num')),
  );
  final exported = exportedEntries(
    abi,
    platform: t.abiPlatform,
    disabled: disabled,
  ).map((e) => e.name).toList()..sort();
  const shimSymbol = 'openssl3_build_info';
  final allExports = [...exported, shimSymbol];

  final exportFile = File(p.join(o.buildDir.path, 'openssl3.exports'));
  exportFile.writeAsStringSync(switch (t.objectFormat) {
    ObjectFormat.elf => renderVersionScript(allExports),
    ObjectFormat.machO => renderMachOExportList(allExports),
    ObjectFormat.pe => renderModuleDef(
      allExports,
      libraryName: p.basenameWithoutExtension(t.installedFileName),
    ),
  });

  // 4. Toolchain as OpenSSL configured it.
  final mk = _Makefile.read(
    File(p.join(o.buildDir.path, isWindows ? 'makefile' : 'Makefile')),
  );
  final cc = mk.words('CC');
  final compilerVersion = await tryCapture(cc.first, [
    ...cc.skip(1),
    if (isWindows) '/?' else '--version',
  ]);

  // 5. Build-info shim.
  final version = _readVersion(o.source);
  // Always on the host (never through the docker wrapper): the container has
  // no git, and the checkout is the host's anyway.
  final commit = await _gitCommit(o.source);
  final ldflags = <String>[...t.ldflags];
  final buildInfo = <String, Object?>{
    'target': t.id,
    'file': t.releaseFileName,
    'library_name': t.installedFileName,
    'install_name': t.installName,
    'openssl_version': version,
    'openssl_commit': commit,
    'configure_target': t.configureTarget,
    'configure_args': configureArgs,
    'compiler': cc.join(' '),
    'compiler_version': compilerVersion?.split('\n').first,
    'cflags': mk.words('CFLAGS') + mk.words('CNF_CFLAGS'),
    'ldflags': ldflags,
    'disabled_features': disabled.toList()..sort(),
    'exported_symbols': allExports.length,
    'host': '${Platform.operatingSystem} ${Platform.operatingSystemVersion}',
  };
  final infoC = File(p.join(o.buildDir.path, 'openssl3_build_info.c'));
  infoC.writeAsStringSync(
    'const char openssl3_build_info_json[] = '
    '${_cStringLiteral(jsonEncode(buildInfo))};\n',
  );
  final shimC = File(
    p.join(o.packageRoot.path, 'src', 'native', 'openssl3_shim.c'),
  );

  // 6. Compile shim objects and link.
  final objExt = isWindows ? '.obj' : '.o';
  final shimObj = p.join(o.buildDir.path, 'openssl3_shim$objExt');
  final infoObj = p.join(o.buildDir.path, 'openssl3_build_info$objExt');
  final archFlags = mk.archFlags(mk.words('CFLAGS') + mk.words('CNF_CFLAGS'));
  final output = File(p.join(o.buildDir.path, t.installedFileName));

  if (isWindows) {
    for (final (src, obj) in [(shimC.path, shimObj), (infoC.path, infoObj)]) {
      await run(
        cc.first,
        [
          ...cc.skip(1),
          '/nologo',
          '/c',
          '/MT',
          '/O2',
          '/W3',
          '/I',
          p.join(o.buildDir.path, 'include'),
          '/I',
          p.join(o.source.path, 'include'),
          '/Fo$obj',
          src,
        ],
        workingDirectory: o.buildDir,
        environment: env,
      );
    }
    final implib = p.join(
      o.buildDir.path,
      '${p.basenameWithoutExtension(t.installedFileName)}.lib',
    );
    await run(
      'link',
      [
        '/NOLOGO',
        '/DLL',
        '/OUT:${output.path}',
        '/DEF:${exportFile.path}',
        '/IMPLIB:$implib',
        '/OPT:REF',
        '/OPT:ICF',
        '/DEFAULTLIB:libcmt.lib',
        p.join(o.buildDir.path, staticLib),
        shimObj,
        infoObj,
        ...mk.words('EX_LIBS'),
        for (final l in t.libs) '$l.lib',
        ...ldflags,
      ],
      workingDirectory: o.buildDir,
      environment: env,
    );
  } else {
    for (final (src, obj) in [(shimC.path, shimObj), (infoC.path, infoObj)]) {
      await run(
        cc.first,
        [
          ...cc.skip(1),
          ...archFlags,
          '-c',
          '-O2',
          '-fPIC',
          '-fvisibility=hidden',
          '-I',
          p.join(o.buildDir.path, 'include'),
          '-I',
          p.join(o.source.path, 'include'),
          '-o',
          obj,
          src,
        ],
        workingDirectory: o.buildDir,
        environment: env,
      );
    }
    final libArchive = p.join(o.buildDir.path, staticLib);
    final linkArgs = switch (t.objectFormat) {
      ObjectFormat.machO => [
        ...archFlags,
        '-dynamiclib',
        '-o',
        output.path,
        '-Wl,-force_load,$libArchive',
        shimObj,
        infoObj,
        '-Wl,-exported_symbols_list,${exportFile.path}',
        '-Wl,-dead_strip',
        '-Wl,-headerpad_max_install_names',
        '-install_name',
        t.installName,
        '-current_version',
        version,
        '-compatibility_version',
        '3.0.0',
        ...ldflags,
        ...mk.words('EX_LIBS'),
      ],
      _ => [
        ...archFlags,
        '-shared',
        '-o',
        output.path,
        '-Wl,--whole-archive',
        libArchive,
        '-Wl,--no-whole-archive',
        shimObj,
        infoObj,
        '-Wl,--version-script=${exportFile.path}',
        '-Wl,-Bsymbolic',
        '-Wl,--gc-sections',
        '-Wl,-soname,${t.installName}',
        '-Wl,-z,noexecstack',
        '-Wl,-z,relro',
        '-Wl,-z,now',
        '-Wl,--no-undefined',
        ...ldflags,
        ...mk.words('EX_LIBS'),
        for (final l in t.libs) '-l$l',
      ],
    };
    await run(
      cc.first,
      [...cc.skip(1), ...linkArgs],
      workingDirectory: o.buildDir,
      environment: env,
    );
    if (t.objectFormat == ObjectFormat.machO) {
      await run('codesign', ['--force', '--sign', '-', output.path]);
    }
  }
  buildInfo['ldflags'] = ldflags;

  // 7. Verify.
  if (!o.skipVerify) {
    await verifyLibrary(
      output,
      target: t,
      expectedExports: allExports.toSet(),
      requiredSymbols: requiredSymbols,
    );
  }

  // 8. Publish into outDir with the release file name, plus sidecar JSON.
  final released = File(p.join(o.outDir.path, t.releaseFileName));
  output.copySync(released.path);
  final bytes = released.readAsBytesSync();
  buildInfo['sha256'] = sha256.convert(bytes).toString();
  buildInfo['size'] = bytes.length;
  File('${released.path}.json').writeAsStringSync(
    '${const JsonEncoder.withIndent('  ').convert(buildInfo)}\n',
  );
  stdout.writeln(
    'Built ${released.path} (${bytes.length} bytes, '
    'sha256 ${buildInfo['sha256']})',
  );
  return BuildResult(released, buildInfo);
}

String _readVersion(Directory source) {
  final lines = File(p.join(source.path, 'VERSION.dat')).readAsLinesSync();
  String get(String k) =>
      lines.firstWhere((l) => l.startsWith('$k=')).split('=')[1].trim();
  return '${get('MAJOR')}.${get('MINOR')}.${get('PATCH')}';
}

String _cStringLiteral(String s) {
  final b = StringBuffer('"');
  for (final r in s.runes) {
    switch (r) {
      case 0x22:
        b.write(r'\"');
      case 0x5c:
        b.write(r'\\');
      case 0x0a:
        b.write(r'\n');
      default:
        if (r < 0x20 || r > 0x7e) {
          b.write('\\x${r.toRadixString(16).padLeft(2, '0')}');
        } else {
          b.writeCharCode(r);
        }
    }
  }
  b.write('"');
  return b.toString();
}

/// Tiny reader for the `VAR=value` lines of an OpenSSL-generated Makefile,
/// with `$(VAR)` expansion for the variables we need.
final class _Makefile {
  final Map<String, String> vars;
  _Makefile(this.vars);

  static _Makefile read(File makefile) {
    final vars = <String, String>{};
    final lines = makefile.readAsLinesSync();
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      // Join continuation lines.
      while (line.endsWith(r'\') && i + 1 < lines.length) {
        line = '${line.substring(0, line.length - 1)} ${lines[++i].trim()}';
      }
      final m = RegExp(
        r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$',
      ).firstMatch(line);
      if (m != null) vars.putIfAbsent(m[1]!, () => m[2]!.trim());
    }
    return _Makefile(vars);
  }

  String expand(String name, [int depth = 0]) {
    final raw = vars[name] ?? '';
    if (depth > 10) return raw;
    return raw.replaceAllMapped(
      RegExp(r'\$\(([A-Za-z_][A-Za-z0-9_]*)\)'),
      (m) => expand(m[1]!, depth + 1),
    );
  }

  /// Whitespace-separated words of [name], with surrounding double quotes
  /// removed: OpenSSL's Windows makefile writes `CC="cl"`, `PERL="..."`.
  List<String> words(String name) => expand(name)
      .split(RegExp(r'\s+'))
      .where((w) => w.isNotEmpty)
      .map(
        (w) => w.length >= 2 && w.startsWith('"') && w.endsWith('"')
            ? w.substring(1, w.length - 1)
            : w,
      )
      .toList();

  /// Flags that must also be passed when *linking* with the same compiler:
  /// architecture, sysroot, minimum OS version, target triple.
  List<String> archFlags(List<String> cflags) {
    final out = <String>[];
    for (var i = 0; i < cflags.length; i++) {
      final f = cflags[i];
      if (f == '-arch' || f == '-isysroot' || f == '-target') {
        if (i + 1 < cflags.length) out.addAll([f, cflags[++i]]);
      } else if (f.startsWith('--target=') ||
          f.startsWith('-m') && f.contains('version-min') ||
          f.startsWith('--sysroot=') ||
          f == '-fPIC') {
        out.add(f);
      }
    }
    return out;
  }
}

/// OpenSSL's `android-*` Configure targets need `ANDROID_NDK_ROOT` and the
/// NDK's `llvm/prebuilt/<host>/bin` on `PATH` (they invoke
/// `<triple><api>-clang`). GitHub runners expose the NDK as
/// `ANDROID_NDK_LATEST_HOME` / `ANDROID_NDK_HOME`.
void _prepareAndroidEnv(Map<String, String> env) {
  final ndk =
      env['ANDROID_NDK_ROOT'] ??
      env['ANDROID_NDK_HOME'] ??
      env['ANDROID_NDK_LATEST_HOME'];
  if (ndk == null || !Directory(ndk).existsSync()) {
    throw StateError(
      'Android targets need ANDROID_NDK_ROOT (or ANDROID_NDK_HOME / '
      'ANDROID_NDK_LATEST_HOME) pointing at NDK r27 or newer.',
    );
  }
  env['ANDROID_NDK_ROOT'] = ndk;
  final hostTag = switch (Platform.operatingSystem) {
    'linux' => 'linux-x86_64',
    'macos' => 'darwin-x86_64',
    'windows' => 'windows-x86_64',
    final other => throw UnsupportedError('No NDK host tag for $other'),
  };
  final bin = p.join(ndk, 'toolchains', 'llvm', 'prebuilt', hostTag, 'bin');
  if (!Directory(bin).existsSync()) {
    throw StateError('NDK toolchain directory not found: $bin');
  }
  final sep = Platform.isWindows ? ';' : ':';
  env['PATH'] = '$bin$sep${env['PATH'] ?? ''}';
}

Future<String?> _gitCommit(Directory source) async {
  try {
    final r = await Process.run('git', [
      '-C',
      source.path,
      'rev-parse',
      'HEAD',
    ]);
    if (r.exitCode != 0) return null;
    final out = (r.stdout as String).trim();
    return RegExp(r'^[0-9a-f]{40}$').hasMatch(out) ? out : null;
  } on ProcessException {
    return null;
  }
}
