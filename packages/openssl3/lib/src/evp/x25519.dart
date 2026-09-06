/// X25519 key agreement (RFC 7748) over `EVP_PKEY`.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../errors.dart';
import '../third_party/openssl.g.dart' as ssl;
import 'pkey.dart';

/// A raw X25519 key pair: 32-byte public and private keys.
final class X25519KeyPair {
  final Uint8List publicKey;
  final Uint8List privateKey;
  const X25519KeyPair(this.publicKey, this.privateKey);
}

abstract final class X25519 {
  static const String algorithm = 'X25519';
  static const int keyLength = 32;

  /// Generates a fresh key pair.
  static X25519KeyPair keyPair() => using(
    (arena) => withGeneratedKey(
      arena,
      algorithm,
      (pkey) => X25519KeyPair(
        rawPublicBytes(arena, pkey),
        rawPrivateBytes(arena, pkey),
      ),
    ),
  );

  /// The public key for a 32-byte [privateKey].
  static Uint8List publicKeyOf(List<int> privateKey) => using((arena) {
    final pkey = rawPrivateKey(arena, algorithm, privateKey);
    return rawPublicBytes(arena, pkey);
  });

  /// The 32-byte shared secret between [privateKey] and [peerPublicKey].
  ///
  /// Throws [OpenSSLException] for an all-zero result (small-order peer
  /// point), which OpenSSL rejects.
  static Uint8List agree(List<int> privateKey, List<int> peerPublicKey) =>
      using((arena) {
        final mine = rawPrivateKey(arena, algorithm, privateKey);
        final peer = rawPublicKey(arena, algorithm, peerPublicKey);
        final ctx = checkNotNull(
          ssl.EVP_PKEY_CTX_new(mine, nullptr),
          'EVP_PKEY_CTX_new',
        );
        arena.using(ctx, ssl.EVP_PKEY_CTX_free);
        checkOne(ssl.EVP_PKEY_derive_init(ctx), 'EVP_PKEY_derive_init');
        checkOne(
          ssl.EVP_PKEY_derive_set_peer(ctx, peer),
          'EVP_PKEY_derive_set_peer',
        );
        final len = arena<Size>()..value = keyLength;
        final out = arena<UnsignedChar>(keyLength);
        checkOne(ssl.EVP_PKEY_derive(ctx, out, len), 'EVP_PKEY_derive');
        return Uint8List.fromList(out.cast<Uint8>().asTypedList(len.value));
      });
}
