/// Parsing and filtering of OpenSSL's public ABI list (`util/libcrypto.num`)
/// and rendering of linker export lists for each object format.
///
/// This mirrors the filtering `util/mkdef.pl` performs in the OpenSSL tree
/// (`platform_filter` and `feature_filter`), because mkdef.pl has writers for
/// ELF and PE only and we also need a Mach-O exported-symbols list.
library;

import 'dart:io';

/// One line of `libcrypto.num`.
///
/// Format: `NAME  ORDINAL  VERSION  EXIST:PLATFORMS:KIND:FEATURES`, where
/// `PLATFORMS` and `FEATURES` are comma separated and a platform may be
/// negated with a leading `!`.
final class AbiEntry {
  final String name;
  final int ordinal;
  final String version;
  final bool exists;

  /// Platform tags such as `UNIX`, `_WIN32`, `VMS`, `__FreeBSD__`.
  /// `true` means "only on this platform", `false` means "not on this platform".
  final Map<String, bool> platforms;

  /// Feature tags such as `EC`, `DEPRECATEDIN_3_0`, `STDIO`.
  final List<String> features;

  const AbiEntry({
    required this.name,
    required this.ordinal,
    required this.version,
    required this.exists,
    required this.platforms,
    required this.features,
  });

  /// The `DEPRECATEDIN_x_y[_z]` tag of this entry, if any, as `x.y.z`.
  String? get deprecatedIn {
    for (final f in features) {
      final m = _deprecatedIn.firstMatch(f);
      if (m != null) {
        return '${m[1]}.${m[2]}.${m[3] ?? '0'}';
      }
    }
    return null;
  }

  static final _deprecatedIn = RegExp(r'^DEPRECATEDIN_(\d+)_(\d+)(?:_(\d+))?$');

  static AbiEntry? parseLine(String line) {
    final trimmed = line.trim();
    if (trimmed.isEmpty || trimmed.startsWith('#')) return null;
    final parts = trimmed.split(RegExp(r'\s+'));
    if (parts.length < 4) {
      throw FormatException('Unexpected libcrypto.num line', line);
    }
    final info = parts[3].split(':');
    if (info.length != 4) {
      throw FormatException('Unexpected info field', parts[3]);
    }
    final platforms = <String, bool>{};
    if (info[1].isNotEmpty) {
      for (final tag in info[1].split(',')) {
        if (tag.startsWith('!')) {
          platforms[tag.substring(1)] = false;
        } else {
          platforms[tag] = true;
        }
      }
    }
    return AbiEntry(
      name: parts[0],
      ordinal: int.parse(parts[1]),
      version: parts[2],
      exists: info[0] == 'EXIST',
      platforms: platforms,
      features: info[3].isEmpty ? const [] : info[3].split(','),
    );
  }

  static List<AbiEntry> parse(String contents) => [
    for (final line in contents.split('\n')) ?parseLine(line),
  ];

  static List<AbiEntry> parseFile(File file) => parse(file.readAsStringSync());
}

/// Platform family used for ABI filtering; the same vocabulary mkdef.pl uses.
enum AbiPlatform {
  /// Linux, Android, macOS, iOS, musl: `UNIX` is true, everything else false.
  unix({'UNIX': true}),

  /// Windows (MSVC or MinGW): `WIN32` and `_WIN32` are true.
  windows({'WIN32': true, '_WIN32': true});

  final Map<String, bool> tags;
  const AbiPlatform(this.tags);

  /// mkdef.pl `platform_filter`: an entry with platform tags is included if a
  /// known tag agrees with this platform; an unknown positive tag excludes it.
  bool accepts(AbiEntry entry) {
    if (entry.platforms.isEmpty) return true;
    for (final MapEntry(key: tag, value: wanted) in entry.platforms.entries) {
      final known = tags[tag];
      if (known != null) return wanted == known;
      if (wanted) return false;
    }
    return true;
  }
}

/// Reads the `OPENSSL_NO_*` macros from a generated `configuration.h` and
/// returns the feature tags they disable, in `libcrypto.num` spelling
/// (upper case, `-` replaced by `_`), exactly as mkdef.pl's `%disabled_uc`.
Set<String> disabledFeaturesFromConfigurationHeader(String contents) {
  final re = RegExp(r'#\s*define\s+OPENSSL_NO_([A-Z0-9_]+)');
  return {for (final m in re.allMatches(contents)) m[1]!};
}

/// Applies mkdef.pl's `feature_filter` (without `no-deprecated` handling,
/// which this package does not use) and `platform_filter`, returning the
/// entries that a shared library built with [disabled] features exports.
List<AbiEntry> exportedEntries(
  Iterable<AbiEntry> entries, {
  required AbiPlatform platform,
  required Set<String> disabled,
}) {
  return [
    for (final e in entries)
      if (e.exists && platform.accepts(e) && !e.features.any(disabled.contains))
        e,
  ];
}

/// Renders a GNU ld version script exporting exactly [names]; everything else
/// becomes local. Used for ELF targets (Linux, Android).
String renderVersionScript(Iterable<String> names, {String? versionNode}) {
  final b = StringBuffer();
  b.writeln(versionNode == null ? '{' : '$versionNode {');
  b.writeln('    global:');
  for (final n in names) {
    b.writeln('        $n;');
  }
  b.writeln('    local:');
  b.writeln('        *;');
  b.writeln('};');
  return b.toString();
}

/// Renders an `ld64 -exported_symbols_list` file (Mach-O). Symbols get the
/// leading underscore Apple's C ABI uses.
String renderMachOExportList(Iterable<String> names) =>
    '${names.map((n) => '_$n').join('\n')}\n';

/// Renders a module-definition file for `link.exe /DEF:` (PE).
String renderModuleDef(Iterable<String> names, {required String libraryName}) {
  final b = StringBuffer()
    ..writeln('LIBRARY $libraryName')
    ..writeln('EXPORTS');
  for (final n in names) {
    b.writeln('    $n');
  }
  return b.toString();
}
