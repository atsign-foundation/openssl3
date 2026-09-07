@Tags(['ffi'])
library;

import 'dart:convert';

import 'package:openssl3/evp.dart';
import 'package:test/test.dart';

import 'hex.dart';

void main() {
  group('Digest', () {
    test('SHA-2 one-shot matches known answers', () {
      expect(
        toHex(Digest.sha256.hash(utf8.encode('abc'))),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
      expect(
        toHex(Digest.sha384.hash(utf8.encode('abc'))),
        startsWith('cb00753f45a35e8bb5a03d699ac65007'),
      );
      expect(
        toHex(Digest.sha512.hash(utf8.encode('abc'))),
        startsWith('ddaf35a193617abacc417349ae204131'),
      );
      expect(Digest.sha256.length, 32);
      expect(Digest.sha3_256.length, 32);
      expect(Digest.sha512.length, 64);
    });

    test('streaming equals one-shot and rejects reuse', () {
      final data = List<int>.generate(100000, (i) => (i * 13) & 0xff);
      final s = Digest.sha256.start();
      for (var off = 0; off < data.length; off += 7919) {
        s.update(data.sublist(off, (off + 7919).clamp(0, data.length)));
      }
      expect(toHex(s.finish()), toHex(Digest.sha256.hash(data)));
      expect(() => s.update([1]), throwsStateError);
    });

    test('unknown digest throws OpenSSLException', () {
      expect(
        () => const Digest.named('NOPE-1').hash([1]),
        throwsA(isA<OpenSSLException>()),
      );
    });
  });

  group('Hmac', () {
    test('RFC 4231 test case 2', () {
      final mac = Hmac.sha256(utf8.encode('Jefe'));
      final data = utf8.encode('what do ya want for nothing?');
      expect(
        toHex(mac.compute(data)),
        '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
      );
      expect(mac.verify(data, mac.compute(data)), isTrue);
      expect(mac.verify([...data, 0], mac.compute(data)), isFalse);
      expect(Hmac.sha512(utf8.encode('k')).compute([1]).length, 64);
    });
  });

  group('Hkdf', () {
    test('RFC 5869 test case 1', () {
      final okm = Hkdf.derive(
        ikm: List.filled(22, 0x0b),
        salt: hex('000102030405060708090a0b0c'),
        info: hex('f0f1f2f3f4f5f6f7f8f9'),
        length: 42,
      );
      expect(
        toHex(okm),
        '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
        '34007208d5b887185865',
      );
    });

    test('RFC 5869 test case 3 (no salt, no info)', () {
      expect(
        toHex(Hkdf.derive(ikm: List.filled(22, 0x0b), length: 42)),
        '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d'
        '9d201395faa4b61a96c8',
      );
    });

    test('other digests and lengths', () {
      expect(Hkdf.derive(ikm: [1, 2, 3], length: 0), isEmpty);
      expect(
        Hkdf.derive(ikm: [1, 2, 3], length: 100, digest: 'SHA2-512').length,
        100,
      );
    });
  });
}
