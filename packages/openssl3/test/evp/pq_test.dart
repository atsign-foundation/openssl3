@Tags(['ffi'])
library;

import 'dart:convert';
import 'dart:io';

import 'package:openssl3/evp.dart';
import 'package:test/test.dart';

import 'hex.dart';

Map<String, Object?> _vectors() =>
    jsonDecode(File('test/evp/vectors/pq_vectors.json').readAsStringSync())
        as Map<String, Object?>;

void main() {
  final v = _vectors();

  group('ML-KEM-768', () {
    final kem = v['ml_kem_768'] as Map<String, Object?>;
    final seed = hex(kem['seed'] as String);
    final publicKey = hex(kem['public_key'] as String);
    final privateKey = hex(kem['private_key'] as String);
    final ciphertext = hex(kem['ciphertext'] as String);
    final sharedSecret = hex(kem['shared_secret'] as String);

    test('seed expands to the same keys as python-cryptography', () {
      final kp = MlKem768.keyPair(seed: seed);
      expect(toHex(kp.publicKey), toHex(publicKey));
      // python-cryptography's private_bytes_raw() is the seed form; OpenSSL's
      // raw private key is the 2400-byte expanded decapsulation key.
      expect(toHex(privateKey), toHex(seed));
      expect(kp.seed, seed);
      expect(kp.publicKey.length, MlKem768.publicKeyLength);
      expect(kp.privateKey.length, MlKem768.privateKeyLength);
    });

    test(
      'decapsulates a python-cryptography ciphertext (seed and expanded key)',
      () {
        expect(toHex(MlKem768.decaps(seed, ciphertext)), toHex(sharedSecret));
        final expanded = MlKem768.keyPair(seed: seed).privateKey;
        expect(
          toHex(MlKem768.decaps(expanded, ciphertext)),
          toHex(sharedSecret),
        );
      },
    );

    test('encaps/decaps round trip with fresh keys', () {
      final kp = MlKem768.keyPair();
      expect(kp.seed, isNotNull);
      expect(kp.seed!.length, MlKem768.seedLength);
      final enc = MlKem768.encaps(kp.publicKey);
      expect(enc.ciphertext.length, MlKem768.ciphertextLength);
      expect(enc.sharedSecret.length, MlKem768.sharedSecretLength);
      expect(
        toHex(MlKem768.decaps(kp.privateKey, enc.ciphertext)),
        toHex(enc.sharedSecret),
      );
      expect(
        toHex(MlKem768.decaps(kp.seed!, enc.ciphertext)),
        toHex(enc.sharedSecret),
      );
      // A second encapsulation to the same key yields a different secret.
      expect(
        MlKem768.encaps(kp.publicKey).sharedSecret,
        isNot(equals(enc.sharedSecret)),
      );
    });

    test(
      'implicit rejection: a corrupted ciphertext yields a different secret',
      () {
        final kp = MlKem768.keyPair();
        final enc = MlKem768.encaps(kp.publicKey);
        final bad = List<int>.of(enc.ciphertext)..[0] ^= 0x01;
        final ss = MlKem768.decaps(kp.privateKey, bad);
        expect(ss.length, 32);
        expect(ss, isNot(equals(enc.sharedSecret)));
      },
    );

    test('rejects malformed inputs', () {
      expect(
        () => MlKem768.keyPair(seed: List.filled(63, 0)),
        throwsArgumentError,
      );
      expect(
        () => MlKem768.encaps(List.filled(10, 0)),
        throwsA(isA<OpenSSLException>()),
      );
    });
  });

  group('ML-DSA-65', () {
    final dsa = v['ml_dsa_65'] as Map<String, Object?>;
    final seed = hex(dsa['seed'] as String);
    final publicKey = hex(dsa['public_key'] as String);
    final privateKey = hex(dsa['private_key'] as String);
    final message = hex(dsa['message'] as String);
    final signature = hex(dsa['signature'] as String);

    test('seed expands to the same keys as python-cryptography', () {
      final kp = MlDsa65.keyPair(seed: seed);
      expect(toHex(kp.publicKey), toHex(publicKey));
      // As for ML-KEM: python exports the 32-byte seed, OpenSSL the expanded
      // 4032-byte key.
      expect(toHex(privateKey), toHex(seed));
      expect(kp.publicKey.length, MlDsa65.publicKeyLength);
      expect(kp.privateKey.length, MlDsa65.privateKeyLength);
    });

    test('verifies a python-cryptography signature', () {
      expect(MlDsa65.verify(publicKey, message, signature), isTrue);
      expect(signature.length, MlDsa65.signatureLength);
    });

    test('sign/verify round trip with seed and expanded key', () {
      final kp = MlDsa65.keyPair();
      expect(kp.seed!.length, MlDsa65.seedLength);
      final sig1 = MlDsa65.sign(kp.privateKey, message);
      final sig2 = MlDsa65.sign(kp.seed!, message);
      expect(sig1.length, MlDsa65.signatureLength);
      expect(MlDsa65.verify(kp.publicKey, message, sig1), isTrue);
      expect(MlDsa65.verify(kp.publicKey, message, sig2), isTrue);
      expect(sig1, isNot(equals(sig2)), reason: 'hedged signatures differ');
    });

    test('rejects tampered message, signature and wrong key', () {
      final kp = MlDsa65.keyPair();
      final sig = MlDsa65.sign(kp.privateKey, message);
      expect(MlDsa65.verify(kp.publicKey, [...message, 0], sig), isFalse);
      final badSig = List<int>.of(sig)..[100] ^= 1;
      expect(MlDsa65.verify(kp.publicKey, message, badSig), isFalse);
      expect(MlDsa65.verify(publicKey, message, sig), isFalse);
    });
  });
}
