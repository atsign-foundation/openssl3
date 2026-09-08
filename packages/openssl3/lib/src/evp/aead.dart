/// Authenticated encryption with associated data: AES-256-GCM and
/// ChaCha20-Poly1305 over `EVP_CIPHER`.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../capabilities.dart';
import '../errors.dart';
import '../third_party/openssl.g.dart' as ssl;
import 'bytes.dart';

/// Ciphertext plus its authentication tag, kept separate so callers can pick
/// their own wire format. [combined] is `ciphertext || tag`, the layout
/// at_chops' `AesGcm256FfiAlgo` and most protocols use.
final class SealedBox {
  final Uint8List ciphertext;
  final Uint8List tag;

  SealedBox(List<int> ciphertext, List<int> tag)
    : ciphertext = Uint8List.fromList(ciphertext),
      tag = Uint8List.fromList(tag);

  /// Splits `ciphertext || tag` with a [tagLength]-byte tag (16 by default).
  factory SealedBox.fromCombined(List<int> combined, {int tagLength = 16}) {
    if (combined.length < tagLength) {
      throw ArgumentError.value(
        combined.length,
        'combined',
        'shorter than the $tagLength byte tag',
      );
    }
    final split = combined.length - tagLength;
    return SealedBox(
      Uint8List.fromList(combined.sublist(0, split)),
      Uint8List.fromList(combined.sublist(split)),
    );
  }

  Uint8List get combined => Uint8List.fromList([...ciphertext, ...tag]);
}

/// Thrown by [Aead.open] when the tag does not verify. Deliberately carries
/// no detail: the data or the key/nonce/AAD are wrong, and that is all a
/// caller should learn.
final class AuthenticationException implements Exception {
  const AuthenticationException();

  @override
  String toString() => 'AuthenticationException: AEAD tag verification failed';
}

/// An AEAD cipher bound to a key.
final class Aead {
  /// OpenSSL algorithm name, e.g. `AES-256-GCM`.
  final String algorithm;
  final Uint8List _key;

  /// Tag length in bytes (16).
  final int tagLength;

  /// Shortest nonce [seal] and [open] accept, in bytes. 96 bits is what GCM
  /// (NIST SP 800-38D) and ChaCha20-Poly1305 (RFC 8439) are specified for;
  /// GCM technically takes shorter nonces, but they shrink the space a random
  /// nonce is drawn from and are a classic mistake, so they are refused.
  /// Longer GCM nonces are hashed down to 96 bits by OpenSSL and accepted.
  static const int minNonceLength = 12;

  /// The key is copied here for the object's lifetime; every native copy is
  /// wiped after use, but this Dart copy lives until garbage collected.
  Aead._(this.algorithm, Uint8List key, this.tagLength)
    : _key = Uint8List.fromList(key);

  /// AES-256-GCM with a 32-byte [key]. Nonce: 12 bytes recommended; longer
  /// nonces are accepted (via `EVP_CTRL_AEAD_SET_IVLEN`), shorter ones are
  /// rejected, see [minNonceLength].
  factory Aead.aes256Gcm(List<int> key) {
    if (key.length != 32) {
      throw ArgumentError.value(key.length, 'key', 'AES-256 needs 32 bytes');
    }
    return Aead._('AES-256-GCM', Uint8List.fromList(key), 16);
  }

  /// AES-128-GCM with a 16-byte [key].
  factory Aead.aes128Gcm(List<int> key) {
    if (key.length != 16) {
      throw ArgumentError.value(key.length, 'key', 'AES-128 needs 16 bytes');
    }
    return Aead._('AES-128-GCM', Uint8List.fromList(key), 16);
  }

  /// ChaCha20-Poly1305 (RFC 8439) with a 32-byte [key] and 12-byte nonce.
  factory Aead.chacha20Poly1305(List<int> key) {
    if (key.length != 32) {
      throw ArgumentError.value(key.length, 'key', 'ChaCha20 needs 32 bytes');
    }
    return Aead._('ChaCha20-Poly1305', Uint8List.fromList(key), 16);
  }

  /// Encrypts and authenticates [plaintext] with [nonce] and optional [aad].
  SealedBox seal(
    List<int> nonce,
    List<int> plaintext, {
    List<int> aad = const [],
  }) {
    initNoConfig();
    return using((arena) {
      final ctx = _newCtx(arena, nonce, encrypt: true);
      try {
        final outl = arena<Int>();
        if (aad.isNotEmpty) {
          checkOne(
            ssl.EVP_EncryptUpdate(
              ctx,
              nullptr,
              outl,
              toNative(arena, aad),
              aad.length,
            ),
            'EVP_EncryptUpdate(aad)',
          );
        }
        final out = arena<UnsignedChar>(plaintext.length + 16);
        var produced = 0;
        if (plaintext.isNotEmpty) {
          checkOne(
            ssl.EVP_EncryptUpdate(
              ctx,
              out,
              outl,
              secretToNative(arena, plaintext),
              plaintext.length,
            ),
            'EVP_EncryptUpdate',
          );
          produced = outl.value;
        }
        checkOne(
          ssl.EVP_EncryptFinal_ex(ctx, out + produced, outl),
          'EVP_EncryptFinal_ex',
        );
        produced += outl.value;
        final tag = arena<UnsignedChar>(tagLength);
        checkOne(
          ssl.EVP_CIPHER_CTX_ctrl(
            ctx,
            ssl.EVP_CTRL_AEAD_GET_TAG,
            tagLength,
            tag.cast(),
          ),
          'EVP_CIPHER_CTX_ctrl(GET_TAG)',
        );
        return SealedBox(fromNative(out, produced), fromNative(tag, tagLength));
      } finally {
        ssl.EVP_CIPHER_CTX_free(ctx);
      }
    });
  }

  /// Verifies and decrypts [box]. Throws [AuthenticationException] on any
  /// mismatch of key, nonce, AAD, ciphertext or tag.
  Uint8List open(List<int> nonce, SealedBox box, {List<int> aad = const []}) {
    initNoConfig();
    if (box.tag.length != tagLength) {
      throw const AuthenticationException();
    }
    return using((arena) {
      final ctx = _newCtx(arena, nonce, encrypt: false);
      try {
        final outl = arena<Int>();
        if (aad.isNotEmpty) {
          checkOne(
            ssl.EVP_DecryptUpdate(
              ctx,
              nullptr,
              outl,
              toNative(arena, aad),
              aad.length,
            ),
            'EVP_DecryptUpdate(aad)',
          );
        }
        // Holds unauthenticated plaintext until the tag verifies; wiped on
        // release whether or not it did.
        final out = secretBuffer(arena, box.ciphertext.length + 16);
        var produced = 0;
        if (box.ciphertext.isNotEmpty) {
          checkOne(
            ssl.EVP_DecryptUpdate(
              ctx,
              out,
              outl,
              toNative(arena, box.ciphertext),
              box.ciphertext.length,
            ),
            'EVP_DecryptUpdate',
          );
          produced = outl.value;
        }
        checkOne(
          ssl.EVP_CIPHER_CTX_ctrl(
            ctx,
            ssl.EVP_CTRL_AEAD_SET_TAG,
            tagLength,
            toNative(arena, box.tag).cast(),
          ),
          'EVP_CIPHER_CTX_ctrl(SET_TAG)',
        );
        final ok = ssl.EVP_DecryptFinal_ex(ctx, out + produced, outl);
        if (ok != 1) {
          ssl.ERR_clear_error();
          throw const AuthenticationException();
        }
        produced += outl.value;
        return fromNative(out, produced);
      } finally {
        ssl.EVP_CIPHER_CTX_free(ctx);
      }
    });
  }

  /// Convenience: `seal` returning `ciphertext || tag`.
  Uint8List sealCombined(
    List<int> nonce,
    List<int> plaintext, {
    List<int> aad = const [],
  }) => seal(nonce, plaintext, aad: aad).combined;

  /// Convenience: `open` on `ciphertext || tag`.
  Uint8List openCombined(
    List<int> nonce,
    List<int> combined, {
    List<int> aad = const [],
  }) => open(
    nonce,
    SealedBox.fromCombined(combined, tagLength: tagLength),
    aad: aad,
  );

  Pointer<ssl.EVP_CIPHER_CTX> _newCtx(
    Arena arena,
    List<int> nonce, {
    required bool encrypt,
  }) {
    if (nonce.length < minNonceLength) {
      throw ArgumentError.value(
        nonce.length,
        'nonce',
        'must be at least $minNonceLength bytes (12 recommended)',
      );
    }
    final cipher = checkNotNull(
      ssl.EVP_CIPHER_fetch(nullptr, cString(arena, algorithm), nullptr),
      'EVP_CIPHER_fetch($algorithm)',
    );
    arena.using(cipher, ssl.EVP_CIPHER_free);
    final ctx = checkNotNull(ssl.EVP_CIPHER_CTX_new(), 'EVP_CIPHER_CTX_new');
    try {
      final init = encrypt ? ssl.EVP_EncryptInit_ex2 : ssl.EVP_DecryptInit_ex2;
      final name = encrypt ? 'EVP_EncryptInit_ex2' : 'EVP_DecryptInit_ex2';
      // Set the cipher first so the IV length can be adjusted, then key + IV.
      checkOne(init(ctx, cipher, nullptr, nullptr, nullptr), name);
      checkOne(
        ssl.EVP_CIPHER_CTX_ctrl(
          ctx,
          ssl.EVP_CTRL_AEAD_SET_IVLEN,
          nonce.length,
          nullptr,
        ),
        'EVP_CIPHER_CTX_ctrl(SET_IVLEN)',
      );
      checkOne(
        init(
          ctx,
          nullptr,
          secretToNative(arena, _key),
          toNative(arena, nonce),
          nullptr,
        ),
        name,
      );
      return ctx;
    } catch (_) {
      ssl.EVP_CIPHER_CTX_free(ctx);
      rethrow;
    }
  }
}
