/// Generates `packages/openssl3/lib/src/third_party/openssl.g.dart`: `@Native`
/// bindings for the complete public libcrypto API (ADR-0008).
///
///     dart run tool/bin/generate_bindings.dart [--build-dir DIR] [--check]
///
/// Inputs:
/// - the OpenSSL source tree (`third_party/openssl`, for the static headers,
///   `util/libcrypto.num` and `doc/man3/*.pod`);
/// - a configured build directory holding the *generated* headers
///   (`include/openssl/configuration.h` and friends). By default the host
///   target's directory under `.dart_tool/openssl_build/` is used; if absent
///   `perl Configure … && make build_generated` runs into it.
///
/// What it does:
/// 1. Assembles a temporary include tree from static + generated headers,
///    excluding libssl's headers, and patches `bn.h` so `BN_ULONG` becomes a
///    `typedef uintptr_t` (see [_patchBnUlong]).
/// 2. Runs ffigen with `NativeExternalBindings`, binding exactly the
///    functions in the exported ABI (`lib/src/symbols.dart`) and every
///    non-underscore struct, union, enum, typedef, macro and global.
/// 3. Post-processes the output: a `///` doc comment on every declaration
///    linking to the OpenSSL manual page (from `doc/man3`), and `@Deprecated`
///    on symbols tagged `DEPRECATEDIN_*` in `libcrypto.num`.
library;

import 'dart:io';

import 'package:args/args.dart';
import 'package:code_assets/code_assets.dart';
import 'package:ffigen/ffigen.dart';
import 'package:logging/logging.dart';
import 'package:openssl3/src/native_build/proc.dart';
import 'package:openssl3/src/native_build/targets.dart';
import 'package:openssl3/src/symbols.dart' as abi;
import 'package:path/path.dart' as p;

const _assetId = 'package:openssl3/src/third_party/openssl.g.dart';
const _manualBase = 'https://docs.openssl.org/3.5/man3/';

/// Pins libc types whose Dart mapping would otherwise depend on the host that
/// ran ffigen (bindings must be identical from macOS, Linux and Windows):
/// - `time_t`  -> `intptr_t`: 64-bit on every 64-bit target incl. Windows x64
///   (where `long` is 32-bit), 32-bit on 32-bit Android; matches OpenSSL's ABI.
/// - `FILE`    -> an opaque struct; Dart only ever passes `FILE*` through.
/// - `pthread_t` (`CRYPTO_THREAD_ID`) -> `uintptr_t`; `pthread_once_t`
///   (`CRYPTO_ONCE`) and `struct tm` -> opaque; `pthread_key_t`
///   (`CRYPTO_THREAD_LOCAL`) -> `uintptr_t`.
/// The functions that still cannot be expressed portably (`struct tm`,
/// `va_list`, `CRYPTO_ONCE`, `CRYPTO_THREAD_LOCAL`, thread ids) are excluded
/// by name in [_hostDependentFunctions].
const _prelude = '''
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
typedef intptr_t openssl3_time_t;
#define time_t openssl3_time_t
typedef struct openssl3_FILE openssl3_FILE;
#define FILE openssl3_FILE
typedef uintptr_t openssl3_pthread_t;
#define pthread_t openssl3_pthread_t
typedef struct openssl3_pthread_once_t openssl3_pthread_once_t;
#define pthread_once_t openssl3_pthread_once_t
typedef uintptr_t openssl3_pthread_key_t;
#define pthread_key_t openssl3_pthread_key_t
typedef struct openssl3_tm openssl3_tm;
#define tm openssl3_tm
''';

/// Exported functions whose C signatures involve host-specific libc types that
/// no portable Dart type can represent. Reachable via `unboundSymbols`.
const _hostDependentFunctions = {
  // struct tm (layout differs between libcs)
  'ASN1_TIME_to_tm',
  'OPENSSL_gmtime',
  'OPENSSL_gmtime_adj',
  'OPENSSL_gmtime_diff',
  // va_list
  'BIO_vprintf', 'BIO_vsnprintf', 'ERR_add_error_vdata', 'ERR_vset_error',
  'OSSL_STORE_vctrl',
  // CRYPTO_THREAD_ID / CRYPTO_ONCE / CRYPTO_THREAD_LOCAL (pthread vs Win32)
  'CRYPTO_THREAD_compare_id', 'CRYPTO_THREAD_get_current_id',
  'CRYPTO_THREAD_run_once', 'CRYPTO_THREAD_init_local',
  'CRYPTO_THREAD_get_local', 'CRYPTO_THREAD_set_local',
  'CRYPTO_THREAD_cleanup_local',
};

/// libssl's headers: not shipped (ADR-0009). `asn1_mac.h` is an `#error` stub.
const _excludedHeaders = {
  'ssl.h',
  'ssl2.h',
  'ssl3.h',
  'sslerr.h',
  'sslerr_legacy.h',
  'tls1.h',
  'dtls1.h',
  'srtp.h',
  'quic.h',
  'asn1_mac.h',
};

Future<void> main(List<String> args) async {
  final parser = ArgParser()
    ..addOption('source', defaultsTo: 'third_party/openssl')
    ..addOption('build-dir', help: 'Configured OpenSSL build dir')
    ..addOption(
      'output',
      defaultsTo: 'packages/openssl3/lib/src/third_party/openssl.g.dart',
    )
    ..addFlag('check', negatable: false, help: 'Fail if output is stale')
    ..addFlag('verbose', abbr: 'v', negatable: false);
  final opts = parser.parse(args);

  Logger.root.level = opts.flag('verbose') ? Level.ALL : Level.WARNING;
  Logger.root.onRecord.listen(
    (r) => stderr.writeln('[ffigen ${r.level.name}] ${r.message}'),
  );

  final source = Directory(opts.option('source')!).absolute;
  final buildDir = await _ensureGeneratedHeaders(
    source,
    opts.option('build-dir'),
  );
  final scratch = Directory.systemTemp.createTempSync('openssl3_ffigen_');
  try {
    final include = _assembleIncludeTree(source, buildDir, scratch);
    final rawOutput = File(p.join(scratch.path, 'openssl.raw.g.dart'));
    _runFfigen(include, rawOutput);
    final manual = _manualIndex(Directory(p.join(source.path, 'doc', 'man3')));
    final decorated = _decorate(rawOutput.readAsStringSync(), manual);

    final unbound = _unboundReport(decorated);
    final output = File(opts.option('output')!);
    final unboundFile = File(
      p.join(p.dirname(output.path), 'unbound_symbols.g.dart'),
    );
    if (opts.flag('check')) {
      if (!unboundFile.existsSync() ||
          unboundFile.readAsStringSync() != unbound) {
        stderr.writeln(
          '${unboundFile.path} is stale; re-run generate_bindings',
        );
        exit(1);
      }
      if (!output.existsSync() || output.readAsStringSync() != decorated) {
        stderr.writeln('${output.path} is stale; re-run generate_bindings');
        exit(1);
      }
      stdout.writeln('${output.path} is up to date');
      return;
    }
    output.parent.createSync(recursive: true);
    output.writeAsStringSync(decorated);
    unboundFile.writeAsStringSync(unbound);
    final externals = RegExp(
      r'^external ',
      multiLine: true,
    ).allMatches(decorated).length;
    stdout.writeln(
      'Wrote ${output.path}: ${decorated.length} bytes, $externals externals',
    );
  } finally {
    scratch.deleteSync(recursive: true);
  }
}

/// Returns a build directory containing `include/openssl/configuration.h`,
/// running Configure for the host if needed.
Future<Directory> _ensureGeneratedHeaders(
  Directory source,
  String? explicit,
) async {
  if (explicit != null) {
    final dir = Directory(explicit).absolute;
    if (!_hasGeneratedHeaders(dir)) {
      throw StateError('No generated headers under ${dir.path}');
    }
    return dir;
  }
  final host = BuildTarget.all.firstWhere(
    (t) => t.os == OS.current && t.arch == Architecture.current,
    orElse: () => throw UnsupportedError(
      'No build target for host ${OS.current}/${Architecture.current}; '
      'pass --build-dir',
    ),
  );
  final dir = Directory(
    p.join('.dart_tool', 'openssl_build', host.id),
  ).absolute;
  if (_hasGeneratedHeaders(dir)) return dir;
  dir.createSync(recursive: true);
  await run(
    'perl',
    [
      p.join(source.path, 'Configure'),
      host.configureTarget,
      ...commonConfigureArgs,
      ...host.extraConfigureArgs,
    ],
    workingDirectory: dir,
    quiet: true,
  );
  await run('make', ['build_generated'], workingDirectory: dir, quiet: true);
  return dir;
}

bool _hasGeneratedHeaders(Directory buildDir) => File(
  p.join(buildDir.path, 'include', 'openssl', 'configuration.h'),
).existsSync();

/// Copies static and generated public headers into `<scratch>/include/openssl`,
/// applies [_patchBnUlong], and returns the include root.
Directory _assembleIncludeTree(
  Directory source,
  Directory buildDir,
  Directory scratch,
) {
  final include = Directory(p.join(scratch.path, 'include'));
  final target = Directory(p.join(include.path, 'openssl'))
    ..createSync(recursive: true);
  for (final origin in [
    Directory(p.join(source.path, 'include', 'openssl')),
    Directory(p.join(buildDir.path, 'include', 'openssl')),
  ]) {
    for (final f in origin.listSync().whereType<File>()) {
      if (!f.path.endsWith('.h')) continue;
      f.copySync(p.join(target.path, p.basename(f.path)));
    }
  }
  _patchBnUlong(File(p.join(target.path, 'bn.h')));
  _patchOsslSsize(File(p.join(target.path, 'e_os2.h')));
  return include;
}

/// `bn.h` defines `BN_ULONG` with a `#define` to `unsigned long`,
/// `unsigned long long` or `unsigned int` depending on the configured word
/// size. ffigen sees only the macro's expansion for the host that generated
/// the bindings; `unsigned long` would become `ffi.UnsignedLong`, which is 32
/// bits on Windows x64 where OpenSSL's `BN_ULONG` is 64 bits. On every target
/// this package ships, `BN_ULONG` has exactly the pointer width, so the
/// generation-time copy is rewritten to `typedef uintptr_t BN_ULONG;`, which
/// ffigen maps to `ffi.UintPtr`.
void _patchBnUlong(File bnH) {
  var s = bnH.readAsStringSync();
  final before = s;
  s = s.replaceAll(
    RegExp(r'^# *define BN_ULONG unsigned long long$', multiLine: true),
    'typedef uintptr_t BN_ULONG; /* openssl3: patched for ffigen */',
  );
  s = s.replaceAll(
    RegExp(r'^# *define BN_ULONG unsigned long$', multiLine: true),
    'typedef uintptr_t BN_ULONG; /* openssl3: patched for ffigen */',
  );
  s = s.replaceAll(
    RegExp(r'^# *define BN_ULONG unsigned int$', multiLine: true),
    'typedef uintptr_t BN_ULONG; /* openssl3: patched for ffigen */',
  );
  if (s == before) {
    throw StateError('bn.h did not contain the expected BN_ULONG defines');
  }
  // Make sure uintptr_t is declared before the typedef.
  s = s.replaceFirst(
    '#include <openssl/e_os2.h>',
    '#include <openssl/e_os2.h>\n#include <stdint.h>',
  );
  bnH.writeAsStringSync(s);
}

/// `e_os2.h` defines `ossl_ssize_t` as `ssize_t` on Unix and `__int64` on
/// Windows; ffigen would emit `ffi.Long` (32 bits on Windows x64). It is
/// pointer-sized on every shipped target, so the generation-time copy gets
/// `typedef intptr_t` (mapped to `ffi.IntPtr`). Affects three CMS functions.
void _patchOsslSsize(File eOs2) {
  var s = eOs2.readAsStringSync();
  const anchor = '#include <openssl/opensslconf.h>';
  if (!s.contains(anchor)) {
    throw StateError('e_os2.h did not contain the expected include');
  }
  s = s.replaceFirst(
    anchor,
    '$anchor\n#include <stdint.h>\n'
    'typedef intptr_t ossl_ssize_t; /* openssl3: patched for ffigen */\n'
    '#define ossl_ssize_t ossl_ssize_t',
  );
  eOs2.writeAsStringSync(s);
}

void _runFfigen(Directory include, File output) {
  final headerDir = Directory(p.join(include.path, 'openssl'));
  final headers =
      headerDir
          .listSync()
          .whereType<File>()
          .map((f) => p.basename(f.path))
          .where((n) => n.endsWith('.h') && !_excludedHeaders.contains(n))
          .toList()
        ..sort();
  // One umbrella header: passing each header as its own translation unit
  // trips "#pragma once in main file" warnings, which ffigen treats as fatal.
  final umbrella = File(p.join(include.path, 'openssl3_all.h'))
    ..writeAsStringSync(
      '$_prelude${headers.map((h) => '#include <openssl/$h>').join('\n')}\n',
    );

  final exported = {
    ...abi.commonSymbols,
    ...abi.unixOnlySymbols,
    ...abi.windowsOnlySymbols,
  };
  bool public(Declaration d) => !d.originalName.startsWith('_');
  final logger = Logger('ffigen');

  FfiGenerator(
    output: Output(
      dartFile: output.uri,
      style: const NativeExternalBindings(assetId: _assetId),
      preamble:
          '''
// GENERATED by tool/bin/generate_bindings.dart from OpenSSL
// ${abi.opensslAbiVersion} public headers. Do not edit by hand.
//
// Every function here is backed by libopenssl3_crypto, the prebuilt libcrypto
// bundled by hook/build.dart. Manual pages: https://docs.openssl.org/3.5/man3/

// ignore_for_file: type=lint
// ignore_for_file: deprecated_member_use_from_same_package''',
    ),
    headers: Headers(
      entryPoints: [umbrella.uri],
      // Bind declarations from OpenSSL's own headers only, never from the
      // system headers they pull in.
      include: (uri) {
        final accepted =
            p.basename(p.dirname(uri.path)) == 'openssl' &&
            uri.path.contains('openssl3_ffigen_') &&
            !_excludedHeaders.contains(p.basename(uri.path));
        if (Platform.environment['OPENSSL3_FFIGEN_DEBUG'] != null) {
          stderr.writeln('[header ${accepted ? 'keep' : 'drop'}] ${uri.path}');
        }
        return accepted;
      },
      compilerOptions: [
        ...defaultCompilerOpts(logger),
        '-I${include.path}',
        // Do not force C mode here: ffigen evaluates macros by compiling a
        // generated C++ file, which `-xc` would break (all macros vanish).
      ],
    ),
    functions: Functions(
      include: (d) =>
          exported.contains(d.originalName) &&
          !_hostDependentFunctions.contains(d.originalName),
      // No leaf calls: several functions take callbacks and none is on a
      // path hot enough to justify the GC-safety trade-off.
    ),
    structs: Structs(include: public),
    unions: Unions(include: public),
    enums: Enums(include: public, silenceWarning: true),
    unnamedEnums: UnnamedEnums(include: public),
    typedefs: Typedefs(include: public, includeUnused: false),
    macros: Macros(include: public),
    globals: Globals(include: public),
  ).generate(logger: logger);
}

/// Maps every function named in a `doc/man3/*.pod` NAME section to the page.
Map<String, String> _manualIndex(Directory man3) {
  final index = <String, String>{};
  if (!man3.existsSync()) return index;
  for (final pod in man3.listSync().whereType<File>()) {
    if (!pod.path.endsWith('.pod')) continue;
    final page = p.basenameWithoutExtension(pod.path);
    var inName = false;
    final names = StringBuffer();
    for (final line in pod.readAsLinesSync()) {
      if (line.startsWith('=head1 NAME')) {
        inName = true;
        continue;
      }
      if (line.startsWith('=head1')) {
        if (inName) break;
        continue;
      }
      if (inName) names.write('$line ');
    }
    // "A, B, C - description"
    final list = names.toString().split(' - ').first;
    for (final raw in list.split(',')) {
      final name = raw.trim();
      if (RegExp(r'^[A-Za-z_][A-Za-z0-9_]*$').hasMatch(name)) {
        index.putIfAbsent(name, () => page);
      }
    }
  }
  return index;
}

/// Adds doc comments and deprecation annotations to ffigen's output.
String _decorate(String generated, Map<String, String> manual) {
  final lines = generated.split('\n');
  final out = <String>[];
  var lastBlank = -1; // index in `out` of the last blank line

  String docFor(String kind, String name) {
    final page = manual[name];
    final link = page == null
        ? 'https://docs.openssl.org/3.5/man3/ (no dedicated page)'
        : '$_manualBase$page/';
    return '/// OpenSSL $kind `$name`. Manual: $link';
  }

  final external = RegExp(r'^external\s+[\w<>.?, ]+\s(\w+)\(');
  final opaque = RegExp(r'^final class (\w+) extends ffi\.Opaque');
  final struct = RegExp(r'^final class (\w+) extends ffi\.(Struct|Union)');
  final typedef = RegExp(r'^typedef (\w+) =');
  final constant = RegExp(r'^const (?:int|double|String) (\w+) =');
  final enumDecl = RegExp(r'^enum (\w+) ');

  for (var i = 0; i < lines.length; i++) {
    final line = lines[i];
    if (line.trim().isEmpty) {
      out.add(line);
      lastBlank = out.length - 1;
      continue;
    }
    final m = external.firstMatch(line);
    if (m != null) {
      final name = m[1]!;
      // Insert before the @ffi.Native annotation that follows the last blank
      // line, unless ffigen already emitted a doc comment there.
      var insertAt = lastBlank + 1;
      if (insertAt < out.length && out[insertAt].startsWith('///')) {
        insertAt = -1;
      }
      final extra = <String>[];
      if (insertAt >= 0) extra.add(docFor('function', name));
      final since = abi.deprecatedSymbols[name];
      if (since != null) {
        extra.add(
          "@Deprecated('Deprecated since OpenSSL $since; kept for ABI "
          "compatibility. Prefer the EVP/OSSL_* API.')",
        );
      }
      if (extra.isNotEmpty) {
        out.insertAll(insertAt >= 0 ? insertAt : lastBlank + 1, extra);
      }
      out.add(line);
      continue;
    }
    String? doc;
    if (opaque.firstMatch(line) case final o?) {
      doc = '/// Opaque OpenSSL type `${o[1]}`; only pointers to it are used.';
    } else if (struct.firstMatch(line) case final s?) {
      doc = docFor(s[2] == 'Union' ? 'union' : 'struct', s[1]!);
    } else if (typedef.firstMatch(line) case final t?) {
      doc = '/// OpenSSL typedef `${t[1]}`.';
    } else if (constant.firstMatch(line) case final c?) {
      doc = '/// OpenSSL macro `${c[1]}`.';
    } else if (enumDecl.firstMatch(line) case final e?) {
      doc = docFor('enum', e[1]!);
    }
    if (doc != null && (out.isEmpty || !out.last.startsWith('///'))) {
      out.add(doc);
    }
    out.add(line);
  }
  return out.join('\n');
}

/// Exported ABI symbols for which ffigen produced neither an `external` nor
/// an enum-converting wrapper, written to `unbound_symbols.g.dart` so tests can
/// assert nothing required is missing and the README can list them.
///
/// Typical causes: functions returning raw function pointers
/// (`*_meth_get_*`), symbols in `libcrypto.num` that no public header declares
/// (`DSO_*`, `OPENSSL_DIR_*`), and [_hostDependentFunctions].
String _unboundReport(String generated) {
  final exported = {
    ...abi.commonSymbols,
    ...abi.unixOnlySymbols,
    ...abi.windowsOnlySymbols,
  };
  final declared = <String>{
    ...RegExp(
      r'^external\s+[\w<>.?, ]+\s(\w+)\(',
      multiLine: true,
    ).allMatches(generated).map((m) => m[1]!),
    ...RegExp(
      r'^[\w<>.?, ]+\s(\w+)\([^)]*\)\s*(?:=>|\{)',
      multiLine: true,
    ).allMatches(generated).map((m) => m[1]!),
  };
  final unbound = exported.where((s) => !declared.contains(s)).toList()..sort();
  final b = StringBuffer()
    ..writeln('// GENERATED by tool/bin/generate_bindings.dart. Do not edit.')
    ..writeln()
    ..writeln(
      '/// Symbols exported by libopenssl3_crypto that have no Dart binding in',
    )
    ..writeln(
      '/// `openssl.g.dart`, because ffigen cannot express them (functions',
    )
    ..writeln(
      '/// returning raw function pointers) or no public header declares them.',
    )
    ..writeln(
      '/// They are still reachable through `DynamicLibrary`-free lookups such as',
    )
    ..writeln('/// `Native.addressOf` on hand-written externals.')
    ..writeln('const Set<String> unboundSymbols = {');
  for (final s in unbound) {
    b.writeln("  '$s',");
  }
  b.writeln('};');
  return b.toString();
}
