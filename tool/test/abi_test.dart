import 'dart:io';

import 'package:openssl_assets_tool/abi.dart';
import 'package:openssl_assets_tool/targets.dart';
import 'package:test/test.dart';

void main() {
  group('AbiEntry.parseLine', () {
    test('plain function', () {
      final e = AbiEntry.parseLine(
        'b2i_PVK_bio                             2\t3_0_0\tEXIST::FUNCTION:',
      )!;
      expect(e.name, 'b2i_PVK_bio');
      expect(e.ordinal, 2);
      expect(e.exists, isTrue);
      expect(e.platforms, isEmpty);
      expect(e.features, isEmpty);
      expect(e.deprecatedIn, isNull);
    });

    test('deprecated with algorithm tag', () {
      final e = AbiEntry.parseLine(
        'd2i_EC_PUBKEY 1 3_0_0 EXIST::FUNCTION:DEPRECATEDIN_3_0,EC',
      )!;
      expect(e.features, ['DEPRECATEDIN_3_0', 'EC']);
      expect(e.deprecatedIn, '3.0.0');
    });

    test('platform tags, positive and negated', () {
      final win = AbiEntry.parseLine(
        'RAND_event 1318 3_0_0 EXIST:_WIN32:FUNCTION:DEPRECATEDIN_1_1_0',
      )!;
      expect(win.platforms, {'_WIN32': true});
      final notVms = AbiEntry.parseLine('X 1 3_0_0 EXIST:!VMS,UNIX:FUNCTION:')!;
      expect(notVms.platforms, {'VMS': false, 'UNIX': true});
    });

    test('comments and blank lines are skipped', () {
      expect(AbiEntry.parseLine('# comment'), isNull);
      expect(AbiEntry.parseLine('   '), isNull);
    });
  });

  group('filtering', () {
    final entries = AbiEntry.parse('''
plain          1 3_0_0 EXIST::FUNCTION:
gone           2 3_0_0 NOEXIST::FUNCTION:
winonly        3 3_0_0 EXIST:_WIN32:FUNCTION:
unixonly       4 3_0_0 EXIST:UNIX:FUNCTION:
notvms         5 3_0_0 EXIST:!VMS:FUNCTION:
vmsonly        6 3_0_0 EXIST:VMS:FUNCTION:
needs_comp     7 3_0_0 EXIST::FUNCTION:COMP
needs_ec       8 3_0_0 EXIST::FUNCTION:EC,DEPRECATEDIN_3_0
''');

    test(
      'unix keeps UNIX and !VMS, drops _WIN32/VMS and disabled features',
      () {
        final names = exportedEntries(
          entries,
          platform: AbiPlatform.unix,
          disabled: {'COMP'},
        ).map((e) => e.name);
        expect(names, ['plain', 'unixonly', 'notvms', 'needs_ec']);
      },
    );

    test('windows keeps _WIN32, drops UNIX', () {
      final names = exportedEntries(
        entries,
        platform: AbiPlatform.windows,
        disabled: const {},
      ).map((e) => e.name);
      expect(names, ['plain', 'winonly', 'notvms', 'needs_comp', 'needs_ec']);
    });
  });

  test('disabledFeaturesFromConfigurationHeader', () {
    const header = '''
# define OPENSSL_NO_COMP
#  define OPENSSL_NO_EC_NISTP_64_GCC_128
#define OPENSSL_NO_MD2
# define OPENSSL_THREADS
''';
    expect(disabledFeaturesFromConfigurationHeader(header), {
      'COMP',
      'EC_NISTP_64_GCC_128',
      'MD2',
    });
  });

  group('renderers', () {
    test('version script', () {
      expect(renderVersionScript(['a', 'b']), '''
{
    global:
        a;
        b;
    local:
        *;
};
''');
    });

    test('mach-o export list prefixes underscore', () {
      expect(renderMachOExportList(['a', 'b']), '_a\n_b\n');
    });

    test('module def', () {
      expect(renderModuleDef(['a'], libraryName: 'x'), '''
LIBRARY x
EXPORTS
    a
''');
    });
  });

  group('real libcrypto.num', () {
    final numFile = File('../third_party/openssl/util/libcrypto.num');

    test(
      'parses every line',
      () {
        final entries = AbiEntry.parseFile(numFile);
        expect(entries.length, greaterThan(5000));
        expect(entries.where((e) => e.exists).length, greaterThan(5000));
      },
      skip: numFile.existsSync() ? false : 'submodule not checked out',
    );

    test(
      'required symbols are all in the ABI list',
      () {
        final names = AbiEntry.parseFile(numFile).map((e) => e.name).toSet();
        final required = File('required_symbols.txt')
            .readAsLinesSync()
            .map((l) => l.trim())
            .where((l) => l.isNotEmpty && !l.startsWith('#'));
        expect(required.where((s) => !names.contains(s)), isEmpty);
      },
      skip: numFile.existsSync() ? false : 'submodule not checked out',
    );
  });

  group('targets', () {
    test('ids are unique and file names are unique', () {
      final ids = BuildTarget.all.map((t) => t.id).toSet();
      expect(ids.length, BuildTarget.all.length);
      final files = BuildTarget.all.map((t) => t.releaseFileName).toSet();
      expect(files.length, BuildTarget.all.length);
    });

    test('naming', () {
      expect(
        BuildTarget.byId('macos-arm64').releaseFileName,
        'libopenssl_assets_crypto.arm64.macos.dylib',
      );
      expect(
        BuildTarget.byId('windows-x64').releaseFileName,
        'openssl_assets_crypto.x64.windows.dll',
      );
      expect(
        BuildTarget.byId('ios_sim-x64').releaseFileName,
        'libopenssl_assets_crypto.x64.ios_sim.dylib',
      );
      expect(
        BuildTarget.byId('linux_musl-arm64').releaseFileName,
        'libopenssl_assets_crypto.arm64.linux_musl.so',
      );
      expect(
        BuildTarget.byId('android-arm').installName,
        'libopenssl_assets_crypto.so',
      );
      expect(
        BuildTarget.byId('ios-arm64').installName,
        '@rpath/libopenssl_assets_crypto.dylib',
      );
    });

    test('byId rejects unknown', () {
      expect(() => BuildTarget.byId('plan9-mips'), throwsArgumentError);
    });
  });
}
