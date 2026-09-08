/// Message authentication codes over `EVP_MAC` (HMAC).
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../capabilities.dart';
import '../errors.dart';
import '../third_party/openssl.g.dart' as ssl;
import 'bytes.dart';

/// HMAC with a SHA-2 digest, keyed once and reusable.
final class Hmac {
  /// OpenSSL digest name, e.g. `SHA2-256`.
  final String digest;
  final Uint8List _key;

  Hmac._(this.digest, List<int> key) : _key = Uint8List.fromList(key);

  factory Hmac.sha256(List<int> key) => Hmac._('SHA2-256', key);
  factory Hmac.sha384(List<int> key) => Hmac._('SHA2-384', key);
  factory Hmac.sha512(List<int> key) => Hmac._('SHA2-512', key);

  /// Any digest `EVP_MAC` accepts for HMAC.
  factory Hmac.withDigest(String digest, List<int> key) => Hmac._(digest, key);

  /// The tag over [data].
  Uint8List compute(List<int> data) {
    initNoConfig();
    return using((arena) {
      final mac = checkNotNull(
        ssl.EVP_MAC_fetch(nullptr, cString(arena, 'HMAC'), nullptr),
        'EVP_MAC_fetch(HMAC)',
      );
      _ArenaFree.add(arena, () => ssl.EVP_MAC_free(mac));
      final ctx = checkNotNull(ssl.EVP_MAC_CTX_new(mac), 'EVP_MAC_CTX_new');
      _ArenaFree.add(arena, () => ssl.EVP_MAC_CTX_free(ctx));

      final bld = checkNotNull(ssl.OSSL_PARAM_BLD_new(), 'OSSL_PARAM_BLD_new');
      _ArenaFree.add(arena, () => ssl.OSSL_PARAM_BLD_free(bld));
      checkOne(
        ssl.OSSL_PARAM_BLD_push_utf8_string(
          bld,
          cString(arena, 'digest'),
          cString(arena, digest),
          0,
        ),
        'OSSL_PARAM_BLD_push_utf8_string(digest)',
      );
      final params = checkNotNull(
        ssl.OSSL_PARAM_BLD_to_param(bld),
        'OSSL_PARAM_BLD_to_param',
      );
      _ArenaFree.add(arena, () => ssl.OSSL_PARAM_free(params));

      checkOne(
        ssl.EVP_MAC_init(ctx, secretToNative(arena, _key), _key.length, params),
        'EVP_MAC_init',
      );
      checkOne(
        ssl.EVP_MAC_update(ctx, toNative(arena, data), data.length),
        'EVP_MAC_update',
      );
      final out = arena<UnsignedChar>(ssl.EVP_MAX_MD_SIZE);
      final outl = arena<Size>();
      checkOne(
        ssl.EVP_MAC_final(ctx, out, outl, ssl.EVP_MAX_MD_SIZE),
        'EVP_MAC_final',
      );
      return fromNative(out, outl.value);
    });
  }

  /// Constant-time comparison of [tag] against the tag over [data].
  bool verify(List<int> data, List<int> tag) =>
      constantTimeEquals(compute(data), tag);
}

/// Registers a release callback on an [Arena].
abstract final class _ArenaFree {
  static void add(Arena arena, void Function() free) =>
      arena.onReleaseAll(free);
}
