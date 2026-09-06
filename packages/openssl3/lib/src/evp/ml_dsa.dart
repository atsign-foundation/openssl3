/// ML-DSA-65 (FIPS 204) signatures over `EVP_PKEY`.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../errors.dart';
import '../third_party/openssl.g.dart' as ssl;
import 'bytes.dart';
import 'pkey.dart';

/// An ML-DSA-65 key pair. [seed] is the 32-byte FIPS 204 seed that fully
/// determines the pair; [privateKey] is the 4032-byte expanded key.
final class MlDsa65KeyPair {
  final Uint8List publicKey;
  final Uint8List privateKey;
  final Uint8List? seed;
  const MlDsa65KeyPair(this.publicKey, this.privateKey, this.seed);
}

abstract final class MlDsa65 {
  static const String algorithm = 'ML-DSA-65';
  static const int publicKeyLength = 1952;
  static const int privateKeyLength = 4032;
  static const int seedLength = 32;
  static const int signatureLength = 3309;

  /// Generates a key pair, from [seed] (32 bytes) when given.
  static MlDsa65KeyPair keyPair({List<int>? seed}) => using((arena) {
    if (seed != null) {
      if (seed.length != seedLength) {
        throw ArgumentError.value(
          seed.length,
          'seed',
          'ML-DSA-65 seed is $seedLength bytes',
        );
      }
      final pkey = keyFromOctetParam(arena, algorithm, 'seed', seed);
      return MlDsa65KeyPair(
        rawPublicBytes(arena, pkey),
        rawPrivateBytes(arena, pkey),
        Uint8List.fromList(seed),
      );
    }
    return withGeneratedKey(
      arena,
      algorithm,
      (pkey) => MlDsa65KeyPair(
        rawPublicBytes(arena, pkey),
        rawPrivateBytes(arena, pkey),
        octetParam(arena, pkey, 'seed'),
      ),
    );
  });

  /// Signs [message] (pure ML-DSA, empty context string) with [privateKey],
  /// which may be the 4032-byte expanded key or the 32-byte seed. Signatures
  /// are randomised ("hedged") as FIPS 204 recommends.
  static Uint8List sign(List<int> privateKey, List<int> message) =>
      using((arena) {
        final pkey = privateKey.length == seedLength
            ? keyFromOctetParam(arena, algorithm, 'seed', privateKey)
            : rawPrivateKey(arena, algorithm, privateKey);
        final md = checkNotNull(ssl.EVP_MD_CTX_new(), 'EVP_MD_CTX_new');
        arena.using(md, ssl.EVP_MD_CTX_free);
        checkOne(
          ssl.EVP_DigestSignInit(md, nullptr, nullptr, nullptr, pkey),
          'EVP_DigestSignInit',
        );
        final msg = toNative(arena, message);
        final sigLen = arena<Size>();
        checkOne(
          ssl.EVP_DigestSign(md, nullptr, sigLen, msg, message.length),
          'EVP_DigestSign(len)',
        );
        final sig = arena<UnsignedChar>(sigLen.value);
        checkOne(
          ssl.EVP_DigestSign(md, sig, sigLen, msg, message.length),
          'EVP_DigestSign',
        );
        return fromNative(sig, sigLen.value);
      });

  /// Verifies [signature] over [message] with [publicKey]. Returns `false` on
  /// a bad signature; throws [OpenSSLException] only for malformed inputs.
  static bool verify(
    List<int> publicKey,
    List<int> message,
    List<int> signature,
  ) => using((arena) {
    final pkey = rawPublicKey(arena, algorithm, publicKey);
    final md = checkNotNull(ssl.EVP_MD_CTX_new(), 'EVP_MD_CTX_new');
    arena.using(md, ssl.EVP_MD_CTX_free);
    checkOne(
      ssl.EVP_DigestVerifyInit(md, nullptr, nullptr, nullptr, pkey),
      'EVP_DigestVerifyInit',
    );
    final ok = ssl.EVP_DigestVerify(
      md,
      toNative(arena, signature),
      signature.length,
      toNative(arena, message),
      message.length,
    );
    if (ok == 1) return true;
    ssl.ERR_clear_error();
    return false;
  });
}
