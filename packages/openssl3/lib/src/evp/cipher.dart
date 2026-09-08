/// Symmetric ciphers: AES-CTR (as used by at_chops / NoPorts for session key
/// protection) with one-shot and streaming forms.
///
/// CTR mode provides confidentiality only. Anything that needs integrity
/// should use `Aead.aes256Gcm` instead.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../capabilities.dart';
import '../errors.dart';
import '../third_party/openssl.g.dart' as ssl;
import 'bytes.dart';

/// An unauthenticated block-cipher mode fetched by name from the default
/// provider, e.g. `AES-256-CTR`.
final class Cipher {
  /// OpenSSL algorithm name, e.g. `AES-256-CTR`.
  final String algorithm;
  final Uint8List _key;

  Cipher._(this.algorithm, Uint8List key) : _key = Uint8List.fromList(key);

  /// AES in counter mode with a 128, 192 or 256-bit [key], selected by the
  /// key length exactly like at_chops' `AesCtrFactory`.
  factory Cipher.aesCtr(List<int> key) {
    final bits = key.length * 8;
    if (bits != 128 && bits != 192 && bits != 256) {
      throw ArgumentError.value(
        key.length,
        'key',
        'AES-CTR needs a 16, 24 or 32 byte key',
      );
    }
    return Cipher._('AES-$bits-CTR', Uint8List.fromList(key));
  }

  /// Any *unauthenticated* cipher `EVP_CIPHER_fetch` knows, e.g.
  /// `AES-256-CBC`, `ChaCha20`.
  ///
  /// Throws [ArgumentError] for AEAD modes (`AES-256-GCM`,
  /// `ChaCha20-Poly1305`, CCM, OCB, SIV): this class never produces or checks
  /// a tag, so it would silently emit unauthenticated output. Use [Aead] for
  /// those. Throws [OpenSSLException] for a name the provider does not know.
  factory Cipher.named(String algorithm, List<int> key) {
    final cipher = Cipher._(algorithm, Uint8List.fromList(key));
    final flags = cipher._withCipher((c) => ssl.EVP_CIPHER_get_flags(c));
    if (flags & ssl.EVP_CIPH_FLAG_AEAD_CIPHER != 0) {
      throw ArgumentError.value(
        algorithm,
        'algorithm',
        'is an AEAD cipher; Cipher never handles authentication tags, '
            'use Aead instead',
      );
    }
    return cipher;
  }

  /// Block size in bytes (1 for stream-like modes such as CTR).
  int get blockSize => _withCipher((c) => ssl.EVP_CIPHER_get_block_size(c));

  /// Required IV/nonce length in bytes (16 for AES-CTR).
  int get ivLength => _withCipher((c) => ssl.EVP_CIPHER_get_iv_length(c));

  int get keyLength => _withCipher((c) => ssl.EVP_CIPHER_get_key_length(c));

  /// Encrypts [plaintext] in one call. For CTR the output has the same length.
  Uint8List encrypt(List<int> iv, List<int> plaintext) {
    final s = encryptStream(iv);
    final out = BytesBuilder(copy: false)
      ..add(s.update(plaintext))
      ..add(s.finish());
    return out.takeBytes();
  }

  /// Decrypts [ciphertext] in one call.
  Uint8List decrypt(List<int> iv, List<int> ciphertext) {
    final s = decryptStream(iv);
    final out = BytesBuilder(copy: false)
      ..add(s.update(ciphertext))
      ..add(s.finish());
    return out.takeBytes();
  }

  /// A streaming encryptor: call [CipherStream.update] repeatedly, then
  /// [CipherStream.finish]. Counter state carries across calls, so the
  /// concatenated output equals [encrypt] of the concatenated input.
  CipherStream encryptStream(List<int> iv) => CipherStream._(this, iv, true);

  CipherStream decryptStream(List<int> iv) => CipherStream._(this, iv, false);

  T _withCipher<T>(T Function(Pointer<ssl.EVP_CIPHER>) f) {
    initNoConfig();
    return using((arena) {
      final c = checkNotNull(
        ssl.EVP_CIPHER_fetch(nullptr, cString(arena, algorithm), nullptr),
        'EVP_CIPHER_fetch($algorithm)',
      );
      try {
        return f(c);
      } finally {
        ssl.EVP_CIPHER_free(c);
      }
    });
  }
}

/// Incremental encryption/decryption state (an `EVP_CIPHER_CTX`).
///
/// Not thread-safe; use from one isolate. Always call [finish] (or [dispose])
/// to release native memory; a [NativeFinalizer] frees leaked contexts.
final class CipherStream implements Finalizable {
  static final _finalizer = NativeFinalizer(
    Native.addressOf<
          NativeFunction<Void Function(Pointer<ssl.EVP_CIPHER_CTX>)>
        >(ssl.EVP_CIPHER_CTX_free)
        .cast(),
  );

  final Cipher cipher;
  final bool _encrypt;
  Pointer<ssl.EVP_CIPHER_CTX> _ctx;
  bool _finished = false;

  CipherStream._(this.cipher, List<int> iv, this._encrypt)
    : _ctx = ssl.EVP_CIPHER_CTX_new() {
    initNoConfig();
    if (_ctx == nullptr) {
      throw OpenSSLException.drain('EVP_CIPHER_CTX_new');
    }
    _finalizer.attach(this, _ctx.cast(), detach: this);
    try {
      using((arena) {
        final c = checkNotNull(
          ssl.EVP_CIPHER_fetch(
            nullptr,
            cString(arena, cipher.algorithm),
            nullptr,
          ),
          'EVP_CIPHER_fetch(${cipher.algorithm})',
        );
        try {
          final expectedIv = ssl.EVP_CIPHER_get_iv_length(c);
          if (iv.length != expectedIv) {
            throw ArgumentError.value(
              iv.length,
              'iv',
              '${cipher.algorithm} needs a $expectedIv byte IV',
            );
          }
          final init = _encrypt
              ? ssl.EVP_EncryptInit_ex2
              : ssl.EVP_DecryptInit_ex2;
          checkOne(
            init(
              _ctx,
              c,
              secretToNative(arena, cipher._key),
              toNative(arena, iv),
              nullptr,
            ),
            _encrypt ? 'EVP_EncryptInit_ex2' : 'EVP_DecryptInit_ex2',
          );
        } finally {
          ssl.EVP_CIPHER_free(c);
        }
      });
    } catch (_) {
      dispose();
      rethrow;
    }
  }

  void _checkOpen() {
    if (_finished) {
      throw StateError('CipherStream already finished');
    }
  }

  /// Processes [input], returning the bytes produced so far (for CTR, as many
  /// as were given).
  Uint8List update(List<int> input) {
    _checkOpen();
    if (input.isEmpty) return Uint8List(0);
    return using((arena) {
      // One side of every update is plaintext; wipe both.
      final inp = secretToNative(arena, input);
      final out = secretBuffer(arena, input.length + cipher.blockSize);
      final outl = arena<Int>();
      final fn = _encrypt ? ssl.EVP_EncryptUpdate : ssl.EVP_DecryptUpdate;
      checkOne(
        fn(_ctx, out, outl, inp, input.length),
        _encrypt ? 'EVP_EncryptUpdate' : 'EVP_DecryptUpdate',
      );
      return fromNative(out, outl.value);
    });
  }

  /// Flushes any buffered block (none for CTR) and releases the context.
  Uint8List finish() {
    _checkOpen();
    try {
      return using((arena) {
        final out = arena<UnsignedChar>(cipher.blockSize + 16);
        final outl = arena<Int>();
        final fn = _encrypt ? ssl.EVP_EncryptFinal_ex : ssl.EVP_DecryptFinal_ex;
        checkOne(
          fn(_ctx, out, outl),
          _encrypt ? 'EVP_EncryptFinal_ex' : 'EVP_DecryptFinal_ex',
        );
        return fromNative(out, outl.value);
      });
    } finally {
      dispose();
    }
  }

  /// Releases the native context without producing final output.
  void dispose() {
    if (_finished) return;
    _finished = true;
    _finalizer.detach(this);
    ssl.EVP_CIPHER_CTX_free(_ctx);
    _ctx = nullptr;
  }
}
