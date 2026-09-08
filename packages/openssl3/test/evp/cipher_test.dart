@Tags(['ffi'])
library;

import 'dart:typed_data';

import 'package:openssl3/evp.dart';
import 'package:test/test.dart';

import 'hex.dart';

void main() {
  // NIST SP 800-38A, F.5 CTR examples (also verified against `openssl enc`).
  final counter = hex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
  final plaintext = hex(
    '6bc1bee22e409f96e93d7e117393172a'
    'ae2d8a571e03ac9c9eb76fac45af8e51'
    '30c81c46a35ce411e5fbc1191a0a52ef'
    'f69f2445df4f9b17ad2b417be66c3710',
  );
  final vectors = {
    // F.5.1 CTR-AES128
    '2b7e151628aed2a6abf7158809cf4f3c':
        '874d6191b620e3261bef6864990db6ce'
        '9806f66b7970fdff8617187bb9fffdff'
        '5ae4df3edbd5d35e5b4f09020db03eab'
        '1e031dda2fbe03d1792170a0f3009cee',
    // F.5.3 CTR-AES192
    '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b':
        '1abc932417521ca24f2b0459fe7e6e0b'
        '090339ec0aa6faefd5ccc2c6f4ce8e94'
        '1e36b26bd1ebc670d1bd1d665620abf7'
        '4f78a7f6d29809585a97daec58c6b050',
    // F.5.5 CTR-AES256
    '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4':
        '601ec313775789a5b7a7f504bbf3d228'
        'f443e3ca4d62b59aca84e990cacaf5c5'
        '2b0930daa23de94ce87017ba2d84988d'
        'dfc9c58db67aada613c2dd08457941a6',
  };

  for (final MapEntry(key: keyHex, value: ctHex) in vectors.entries) {
    final bits = keyHex.length * 4;
    test('AES-$bits-CTR matches NIST SP 800-38A', () {
      final cipher = Cipher.aesCtr(hex(keyHex));
      expect(cipher.algorithm, 'AES-$bits-CTR');
      expect(cipher.ivLength, 16);
      expect(cipher.blockSize, 1);
      expect(toHex(cipher.encrypt(counter, plaintext)), ctHex);
      expect(toHex(cipher.decrypt(counter, hex(ctHex))), toHex(plaintext));
    });
  }

  test('streaming output equals one-shot output across odd chunk sizes', () {
    final key = hex(
      '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
    );
    final cipher = Cipher.aesCtr(key);
    final data = Uint8List.fromList(
      List.generate(1000, (i) => (i * 31 + 7) & 0xff),
    );
    final oneShot = cipher.encrypt(counter, data);
    final stream = cipher.encryptStream(counter);
    final out = BytesBuilder();
    var offset = 0;
    for (final size in [1, 5, 16, 17, 100, 333, 528]) {
      out.add(stream.update(data.sublist(offset, offset + size)));
      offset += size;
    }
    expect(offset, data.length);
    out.add(stream.finish());
    expect(toHex(out.takeBytes()), toHex(oneShot));
    expect(() => stream.update([1]), throwsStateError, reason: 'finished');
  });

  test('CTR is its own inverse and length-preserving', () {
    final key = List<int>.generate(24, (i) => i);
    final iv = List<int>.generate(16, (i) => 255 - i);
    final cipher = Cipher.aesCtr(key);
    for (final len in [0, 1, 15, 16, 17, 4096]) {
      final msg = List<int>.generate(len, (i) => i & 0xff);
      final ct = cipher.encrypt(iv, msg);
      expect(ct.length, len);
      expect(cipher.decrypt(iv, ct), msg);
    }
  });

  test('validates key and IV lengths', () {
    expect(() => Cipher.aesCtr(List.filled(20, 0)), throwsArgumentError);
    expect(
      () => Cipher.aesCtr(List.filled(16, 0)).encrypt(List.filled(12, 0), [1]),
      throwsArgumentError,
    );
  });

  test('named ciphers refuse AEAD modes (no tag would be produced)', () {
    for (final aead in ['AES-256-GCM', 'ChaCha20-Poly1305', 'AES-128-CCM']) {
      expect(
        () => Cipher.named(aead, List.filled(32, 1)),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message.toString(),
            'message',
            contains('Aead'),
          ),
        ),
        reason: aead,
      );
    }
    expect(
      () => Cipher.named('NO-SUCH-CIPHER', List.filled(32, 1)),
      throwsA(isA<OpenSSLException>()),
    );
  });

  test('named ciphers: AES-256-CBC pads to a block', () {
    final cipher = Cipher.named('AES-256-CBC', List.filled(32, 1));
    expect(cipher.blockSize, 16);
    final iv = List.filled(16, 2);
    final ct = cipher.encrypt(iv, [1, 2, 3]);
    expect(ct.length, 16);
    expect(cipher.decrypt(iv, ct), [1, 2, 3]);
  });
}
