/// ML-KEM-768 (FIPS 203) key encapsulation over `EVP_PKEY`.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../errors.dart';
import '../third_party/openssl.g.dart' as ssl;
import 'bytes.dart';
import 'pkey.dart';

/// An ML-KEM-768 key pair.
///
/// [seed] is the 64-byte FIPS 203 `d || z` seed; it fully determines the key
/// pair and is the recommended long-term storage form (at_chops stores it).
/// [privateKey] is the 2400-byte expanded decapsulation key.
final class MlKem768KeyPair {
  final Uint8List publicKey;
  final Uint8List privateKey;
  final Uint8List? seed;
  const MlKem768KeyPair(this.publicKey, this.privateKey, this.seed);
}

/// Result of [MlKem768.encaps].
final class Encapsulation {
  final Uint8List ciphertext;
  final Uint8List sharedSecret;
  const Encapsulation(this.ciphertext, this.sharedSecret);
}

abstract final class MlKem768 {
  static const String algorithm = 'ML-KEM-768';
  static const int publicKeyLength = 1184;
  static const int privateKeyLength = 2400;
  static const int seedLength = 64;
  static const int ciphertextLength = 1088;
  static const int sharedSecretLength = 32;

  /// Generates a key pair, from [seed] (64 bytes) when given.
  static MlKem768KeyPair keyPair({List<int>? seed}) => using((arena) {
    if (seed != null) {
      if (seed.length != seedLength) {
        throw ArgumentError.value(
          seed.length,
          'seed',
          'ML-KEM-768 seed is $seedLength bytes',
        );
      }
      final pkey = keyFromOctetParam(arena, algorithm, 'seed', seed);
      return MlKem768KeyPair(
        rawPublicBytes(arena, pkey),
        rawPrivateBytes(arena, pkey),
        Uint8List.fromList(seed),
      );
    }
    return withGeneratedKey(
      arena,
      algorithm,
      (pkey) => MlKem768KeyPair(
        rawPublicBytes(arena, pkey),
        rawPrivateBytes(arena, pkey),
        octetParam(arena, pkey, 'seed'),
      ),
    );
  });

  /// Encapsulates to [publicKey], producing a ciphertext and shared secret.
  static Encapsulation encaps(List<int> publicKey) => using((arena) {
    final pkey = rawPublicKey(arena, algorithm, publicKey);
    final ctx = checkNotNull(
      ssl.EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr),
      'EVP_PKEY_CTX_new_from_pkey',
    );
    arena.using(ctx, ssl.EVP_PKEY_CTX_free);
    checkOne(
      ssl.EVP_PKEY_encapsulate_init(ctx, nullptr),
      'EVP_PKEY_encapsulate_init',
    );
    final ctLen = arena<Size>()..value = ciphertextLength;
    final ssLen = arena<Size>()..value = sharedSecretLength;
    final ct = arena<UnsignedChar>(ciphertextLength);
    final ss = secretBuffer(arena, sharedSecretLength);
    checkOne(
      ssl.EVP_PKEY_encapsulate(ctx, ct, ctLen, ss, ssLen),
      'EVP_PKEY_encapsulate',
    );
    return Encapsulation(
      fromNative(ct, ctLen.value),
      fromNative(ss, ssLen.value),
    );
  });

  /// Recovers the shared secret from [ciphertext] with [privateKey], which may
  /// be either the 2400-byte expanded key or the 64-byte seed.
  static Uint8List decaps(List<int> privateKey, List<int> ciphertext) =>
      using((arena) {
        final pkey = privateKey.length == seedLength
            ? keyFromOctetParam(arena, algorithm, 'seed', privateKey)
            : rawPrivateKey(arena, algorithm, privateKey);
        final ctx = checkNotNull(
          ssl.EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr),
          'EVP_PKEY_CTX_new_from_pkey',
        );
        arena.using(ctx, ssl.EVP_PKEY_CTX_free);
        checkOne(
          ssl.EVP_PKEY_decapsulate_init(ctx, nullptr),
          'EVP_PKEY_decapsulate_init',
        );
        final ssLen = arena<Size>()..value = sharedSecretLength;
        final ss = secretBuffer(arena, sharedSecretLength);
        checkOne(
          ssl.EVP_PKEY_decapsulate(
            ctx,
            ss,
            ssLen,
            toNative(arena, ciphertext),
            ciphertext.length,
          ),
          'EVP_PKEY_decapsulate',
        );
        return fromNative(ss, ssLen.value);
      });
}
