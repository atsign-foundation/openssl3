import 'dart:convert';

import 'package:openssl3/src/native_build/build.dart';
import 'package:test/test.dart';

/// Decodes a C string literal the way a C compiler would: `\"`, `\\`, `\n`,
/// `\?` and three-digit octal escapes; nothing else is expected.
List<int> decodeCLiteral(String literal) {
  expect(literal, startsWith('"'));
  expect(literal, endsWith('"'));
  final body = literal.substring(1, literal.length - 1);
  final out = <int>[];
  for (var i = 0; i < body.length; i++) {
    final c = body[i];
    if (c != r'\') {
      out.add(c.codeUnitAt(0));
      continue;
    }
    final next = body[++i];
    switch (next) {
      case '"':
        out.add(0x22);
      case r'\':
        out.add(0x5c);
      case 'n':
        out.add(0x0a);
      case '?':
        out.add(0x3f);
      default:
        final digits = body.substring(i, i + 3);
        expect(digits, matches(RegExp(r'^[0-7]{3}$')), reason: literal);
        out.add(int.parse(digits, radix: 8));
        i += 2;
    }
  }
  return out;
}

void main() {
  group('cStringLiteral', () {
    test(
      'passes printable ASCII through and escapes quotes and backslashes',
      () {
        expect(cStringLiteral('abc 123'), '"abc 123"');
        expect(cStringLiteral(r'say "hi" \ bye'), r'"say \"hi\" \\ bye"');
        expect(cStringLiteral('a\nb'), r'"a\nb"');
      },
    );

    test('never emits a \\x escape, so a following hex digit cannot merge', () {
      // With `\x`, "é" + "a" would become `\xc3\xa9a`, which C reads as the
      // out-of-range escape `\xa9a`. Octal escapes are fixed at three digits.
      final literal = cStringLiteral('éa');
      expect(literal, isNot(contains(r'\x')));
      expect(literal, r'"\303\251a"');
      expect(utf8.decode(decodeCLiteral(literal)), 'éa');
    });

    test('round-trips the build-info JSON byte for byte', () {
      final json = jsonEncode({
        'compiler_version': 'Apple clang “21.0.0” (clang-2100.1.1.101)',
        'host': 'macos Version 26.5.2 (Build 25F84) — ünïcödé ✓',
        'cflags': ['-O3', '-D_FORTIFY_SOURCE=2', r'C:\path\with\backslash'],
        'control': 'tab\there\u0001bell\u0007 question??',
      });
      final literal = cStringLiteral(json);
      expect(decodeCLiteral(literal), utf8.encode(json));
      expect(literal, isNot(contains('??')), reason: 'no trigraph openers');
    });
  });
}
