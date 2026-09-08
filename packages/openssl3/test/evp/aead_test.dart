@Tags(['ffi'])
library;

import 'dart:convert';

import 'package:openssl3/evp.dart';
import 'package:test/test.dart';

import 'hex.dart';

void main() {
  group('AES-256-GCM', () {
    // GCM spec test case 16 (McGrew & Viega), cross-checked with
    // python-cryptography 49.
    final key = hex(
      'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
    );
    final iv = hex('cafebabefacedbaddecaf888');
    final plaintext = hex(
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
      '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
    );
    final aad = hex('feedfacedeadbeeffeedfacedeadbeefabaddad2');
    final expectedCt = hex(
      '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa'
      '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662',
    );
    final expectedTag = hex('76fc6ece0f4e1768cddf8853bb2d551b');

    test('matches the known-answer vector', () {
      final box = Aead.aes256Gcm(key).seal(iv, plaintext, aad: aad);
      expect(toHex(box.ciphertext), toHex(expectedCt));
      expect(toHex(box.tag), toHex(expectedTag));
    });

    test('opens the known-answer vector', () {
      final out = Aead.aes256Gcm(
        key,
      ).open(iv, SealedBox(expectedCt, expectedTag), aad: aad);
      expect(toHex(out), toHex(plaintext));
    });

    test('combined layout is ciphertext || tag', () {
      final aead = Aead.aes256Gcm(key);
      final combined = aead.sealCombined(iv, plaintext, aad: aad);
      expect(toHex(combined), toHex(expectedCt) + toHex(expectedTag));
      expect(
        toHex(aead.openCombined(iv, combined, aad: aad)),
        toHex(plaintext),
      );
    });

    test('rejects tampering of ciphertext, tag, aad and nonce', () {
      final aead = Aead.aes256Gcm(key);
      final box = aead.seal(iv, plaintext, aad: aad);
      final badCt = SealedBox((box.ciphertext..[0] ^= 1), box.tag);
      expect(
        () => aead.open(iv, badCt, aad: aad),
        throwsA(isA<AuthenticationException>()),
      );
      final good = aead.seal(iv, plaintext, aad: aad);
      final badTag = SealedBox(good.ciphertext, (good.tag..[15] ^= 1));
      expect(
        () => aead.open(iv, badTag, aad: aad),
        throwsA(isA<AuthenticationException>()),
      );
      final again = aead.seal(iv, plaintext, aad: aad);
      expect(
        () => aead.open(iv, again, aad: [...aad, 0]),
        throwsA(isA<AuthenticationException>()),
      );
      expect(
        () => aead.open(hex('000000000000000000000000'), again, aad: aad),
        throwsA(isA<AuthenticationException>()),
      );
      expect(
        () => Aead.aes256Gcm(List.filled(32, 7)).open(iv, again, aad: aad),
        throwsA(isA<AuthenticationException>()),
      );
    });

    test('empty plaintext and no aad', () {
      final aead = Aead.aes256Gcm(key);
      final box = aead.seal(iv, const []);
      expect(box.ciphertext, isEmpty);
      expect(box.tag.length, 16);
      expect(aead.open(iv, box), isEmpty);
    });

    test('longer nonces work (16 bytes), shorter ones are refused', () {
      final aead = Aead.aes256Gcm(key);
      final nonce16 = List<int>.generate(16, (i) => i);
      final box = aead.seal(nonce16, plaintext);
      expect(toHex(aead.open(nonce16, box)), toHex(plaintext));

      expect(Aead.minNonceLength, 12);
      for (final len in [0, 1, 8, 11]) {
        final short = List<int>.generate(len, (i) => i);
        expect(() => aead.seal(short, plaintext), throwsArgumentError);
        expect(() => aead.open(short, box), throwsArgumentError);
      }
    });

    test('key length is validated', () {
      expect(() => Aead.aes256Gcm(List.filled(16, 0)), throwsArgumentError);
      expect(() => Aead.aes128Gcm(List.filled(32, 0)), throwsArgumentError);
    });
  });

  group('ChaCha20-Poly1305', () {
    // RFC 8439 §2.8.2.
    final key = hex(
      '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
    );
    final nonce = hex('070000004041424344454647');
    final aad = hex('50515253c0c1c2c3c4c5c6c7');
    final plaintext = utf8.encode(
      "Ladies and Gentlemen of the class of '99: If I could offer you only "
      'one tip for the future, sunscreen would be it.',
    );
    final expectedCt = hex(
      'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6'
      '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36'
      '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc'
      '3ff4def08e4b7a9de576d26586cec64b6116',
    );
    final expectedTag = hex('1ae10b594f09e26a7e902ecbd0600691');

    test('matches RFC 8439', () {
      final box = Aead.chacha20Poly1305(key).seal(nonce, plaintext, aad: aad);
      expect(toHex(box.ciphertext), toHex(expectedCt));
      expect(toHex(box.tag), toHex(expectedTag));
      expect(
        utf8.decode(Aead.chacha20Poly1305(key).open(nonce, box, aad: aad)),
        startsWith('Ladies and Gentlemen'),
      );
    });
  });
}
