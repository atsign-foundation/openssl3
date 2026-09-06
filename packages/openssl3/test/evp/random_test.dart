@Tags(['ffi'])
library;

import 'package:openssl3/evp.dart';
import 'package:test/test.dart';

void main() {
  test('Random.bytes returns the requested length and varies', () {
    expect(Random.bytes(0), isEmpty);
    final a = Random.bytes(64);
    final b = Random.bytes(64);
    expect(a.length, 64);
    expect(a, isNot(equals(b)));
    expect(a.toSet().length, greaterThan(20), reason: 'not degenerate');
    expect(() => Random.bytes(-1), throwsRangeError);
  });

  test('Random.privateBytes works and differs from the public stream', () {
    final a = Random.privateBytes(32);
    expect(a.length, 32);
    expect(a, isNot(equals(Random.bytes(32))));
  });
}
