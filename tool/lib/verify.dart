/// Post-link verification of a built `libopenssl_assets_crypto`.
///
/// Checks, per object format:
/// - the set of exported symbols equals the expected ABI list (+ shim);
/// - every symbol in `required_symbols.txt` is present;
/// - SONAME / install name is the distinct package name;
/// - no dependency on a system `libcrypto` / `libssl`;
/// - Android: every PT_LOAD segment is 16 KB aligned.
library;

import 'dart:io';

import 'package:code_assets/code_assets.dart';

import 'proc.dart';
import 'targets.dart';

final class VerificationError extends Error {
  final String message;
  VerificationError(this.message);
  @override
  String toString() => 'VerificationError: $message';
}

Future<void> verifyLibrary(
  File library, {
  required BuildTarget target,
  required Set<String> expectedExports,
  required Set<String> requiredSymbols,
}) async {
  final problems = <String>[];
  final exports = await _exportedSymbols(library, target);

  final missing = expectedExports.difference(exports).toList()..sort();
  final extra = exports.difference(expectedExports).toList()..sort();
  if (missing.isNotEmpty) {
    problems.add(
      '${missing.length} expected symbols missing, e.g. '
      '${missing.take(10).join(', ')}',
    );
  }
  if (extra.isNotEmpty) {
    problems.add(
      '${extra.length} unexpected exports, e.g. '
      '${extra.take(10).join(', ')}',
    );
  }
  final missingRequired = requiredSymbols.difference(exports).toList()..sort();
  if (missingRequired.isNotEmpty) {
    problems.add('required symbols missing: ${missingRequired.join(', ')}');
  }

  switch (target.objectFormat) {
    case ObjectFormat.machO:
      final id = await capture('otool', ['-D', library.path]);
      if (!id.split('\n').last.trim().endsWith(target.installName)) {
        problems.add('install name is "$id", expected ${target.installName}');
      }
      final deps = await capture('otool', ['-L', library.path]);
      _checkDeps(deps, problems);
    case ObjectFormat.elf:
      final readelf = await _firstAvailable(['readelf', 'llvm-readelf']);
      if (readelf == null) {
        problems.add(
          'neither readelf nor llvm-readelf found; cannot verify '
          'SONAME/NEEDED/alignment',
        );
        break;
      }
      final dyn = await capture(readelf, ['-d', library.path]);
      if (!RegExp(
        r'SONAME.*\[' + RegExp.escape(target.installName) + r'\]',
      ).hasMatch(dyn)) {
        problems.add('SONAME is not ${target.installName}:\n$dyn');
      }
      _checkDeps(dyn, problems);
      if (target.os == OS.android) {
        final ph = await capture(readelf, ['-lW', library.path]);
        for (final line in ph.split('\n')) {
          if (!line.trim().startsWith('LOAD')) continue;
          final align = line.trim().split(RegExp(r'\s+')).last;
          final value = int.tryParse(align.replaceFirst('0x', ''), radix: 16);
          if (value == null || value < 0x4000) {
            problems.add('PT_LOAD alignment $align < 0x4000 (16 KB pages)');
          }
        }
      }
    case ObjectFormat.pe:
      final deps = await tryCapture('dumpbin', ['/DEPENDENTS', library.path]);
      if (deps == null) {
        problems.add('dumpbin not found; cannot verify DLL dependents');
      } else {
        _checkDeps(deps, problems);
      }
  }

  if (problems.isNotEmpty) {
    throw VerificationError(
      'Verification of ${library.path} failed:\n - ${problems.join('\n - ')}',
    );
  }
  stdout.writeln(
    'Verified ${library.path}: ${exports.length} exports, '
    'install name ${target.installName}',
  );
}

void _checkDeps(String listing, List<String> problems) {
  final bad = RegExp(r'lib(crypto|ssl)[.-]', caseSensitive: false);
  for (final line in listing.split('\n')) {
    if (bad.hasMatch(line) && !line.contains(libraryBaseName)) {
      problems.add('depends on a system OpenSSL: ${line.trim()}');
    }
  }
}

Future<Set<String>> _exportedSymbols(File library, BuildTarget t) async {
  switch (t.objectFormat) {
    case ObjectFormat.machO:
      final out = await capture('nm', ['-gU', library.path]);
      return {
        for (final line in out.split('\n'))
          if (line.split(' ') case [
            _,
            final type,
            final name,
          ] when 'TDSC'.contains(type) && name.startsWith('_'))
            name.substring(1),
      };
    case ObjectFormat.elf:
      final nm = await _firstAvailable(['nm', 'llvm-nm']);
      if (nm == null) {
        throw VerificationError('neither nm nor llvm-nm found');
      }
      final out = await capture(nm, ['-D', '--defined-only', library.path]);
      return {
        for (final line in out.split('\n'))
          if (line.trim().split(RegExp(r'\s+')) case [
            _,
            final type,
            final name,
            ...,
          ] when 'TDRBWVi'.contains(type) && !name.startsWith('_'))
            name,
      };
    case ObjectFormat.pe:
      final out = await capture('dumpbin', ['/EXPORTS', library.path]);
      // Lines look like: "          1    0 0001A2B0 AES_bi_ige_encrypt"
      final re = RegExp(r'^\s+\d+\s+[0-9A-F]+\s+[0-9A-F]{8}\s+(\S+)');
      return {
        for (final line in out.split('\n'))
          if (re.firstMatch(line) case final m?) m[1]!,
      };
  }
}

Future<String?> _firstAvailable(List<String> tools) async {
  for (final t in tools) {
    if (await tryCapture(t, ['--version']) != null) return t;
  }
  return null;
}
