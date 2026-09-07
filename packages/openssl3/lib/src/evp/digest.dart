/// Message digests (SHA-2, SHA-3) over `EVP_MD`, one-shot and streaming.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../capabilities.dart';
import '../errors.dart';
import '../third_party/openssl.g.dart' as ssl;
import 'bytes.dart';

/// A digest algorithm fetched by name from the default provider.
final class Digest {
  /// OpenSSL algorithm name, e.g. `SHA2-256`.
  final String algorithm;

  const Digest._(this.algorithm);

  static const sha256 = Digest._('SHA2-256');
  static const sha384 = Digest._('SHA2-384');
  static const sha512 = Digest._('SHA2-512');
  static const sha3_256 = Digest._('SHA3-256');
  static const sha3_512 = Digest._('SHA3-512');

  /// Any digest `EVP_MD_fetch` knows, e.g. `BLAKE2B-512`, `SHAKE128`.
  const Digest.named(this.algorithm);

  /// Output length in bytes.
  int get length => _withMd((md) => ssl.EVP_MD_get_size(md));

  /// Hashes [data] in one call.
  Uint8List hash(List<int> data) {
    final s = start();
    s.update(data);
    return s.finish();
  }

  /// Begins an incremental hash.
  DigestStream start() => DigestStream._(this);

  T _withMd<T>(T Function(Pointer<ssl.EVP_MD>) f) {
    initNoConfig();
    return using((arena) {
      final md = checkNotNull(
        ssl.EVP_MD_fetch(nullptr, cString(arena, algorithm), nullptr),
        'EVP_MD_fetch($algorithm)',
      );
      try {
        return f(md);
      } finally {
        ssl.EVP_MD_free(md);
      }
    });
  }
}

/// Incremental digest state (an `EVP_MD_CTX`). Call [finish] exactly once.
final class DigestStream implements Finalizable {
  static final _finalizer = NativeFinalizer(
    Native.addressOf<NativeFunction<Void Function(Pointer<ssl.EVP_MD_CTX>)>>(
      ssl.EVP_MD_CTX_free,
    ).cast(),
  );

  final Digest digest;
  Pointer<ssl.EVP_MD_CTX> _ctx;
  bool _finished = false;

  DigestStream._(this.digest) : _ctx = ssl.EVP_MD_CTX_new() {
    initNoConfig();
    if (_ctx == nullptr) throw OpenSSLException.drain('EVP_MD_CTX_new');
    _finalizer.attach(this, _ctx.cast(), detach: this);
    try {
      using((arena) {
        final md = checkNotNull(
          ssl.EVP_MD_fetch(nullptr, cString(arena, digest.algorithm), nullptr),
          'EVP_MD_fetch(${digest.algorithm})',
        );
        try {
          checkOne(
            ssl.EVP_DigestInit_ex2(_ctx, md, nullptr),
            'EVP_DigestInit_ex2',
          );
        } finally {
          ssl.EVP_MD_free(md);
        }
      });
    } catch (_) {
      dispose();
      rethrow;
    }
  }

  void update(List<int> data) {
    if (_finished) throw StateError('DigestStream already finished');
    if (data.isEmpty) return;
    using((arena) {
      checkOne(
        ssl.EVP_DigestUpdate(_ctx, toNative(arena, data).cast(), data.length),
        'EVP_DigestUpdate',
      );
    });
  }

  Uint8List finish() {
    if (_finished) throw StateError('DigestStream already finished');
    try {
      return using((arena) {
        final out = arena<UnsignedChar>(ssl.EVP_MAX_MD_SIZE);
        final len = arena<UnsignedInt>();
        checkOne(ssl.EVP_DigestFinal_ex(_ctx, out, len), 'EVP_DigestFinal_ex');
        return fromNative(out, len.value);
      });
    } finally {
      dispose();
    }
  }

  void dispose() {
    if (_finished) return;
    _finished = true;
    _finalizer.detach(this);
    ssl.EVP_MD_CTX_free(_ctx);
    _ctx = nullptr;
  }
}
