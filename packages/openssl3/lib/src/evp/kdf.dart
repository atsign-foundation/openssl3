/// Key derivation over `EVP_KDF` (HKDF, RFC 5869).
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../capabilities.dart';
import '../errors.dart';
import '../third_party/openssl.g.dart' as ssl;
import 'bytes.dart';

abstract final class Hkdf {
  /// HKDF-Extract-and-Expand with [digest] (OpenSSL name, default SHA2-256).
  ///
  /// [salt] may be empty (RFC 5869 then uses a zero-filled salt), [info] may
  /// be empty. [length] is bounded by 255 × digest size.
  static Uint8List derive({
    required List<int> ikm,
    required int length,
    List<int> salt = const [],
    List<int> info = const [],
    String digest = 'SHA2-256',
  }) {
    RangeError.checkNotNegative(length, 'length');
    if (length == 0) return Uint8List(0);
    initNoConfig();
    return using((arena) {
      final kdf = checkNotNull(
        ssl.EVP_KDF_fetch(nullptr, cString(arena, 'HKDF'), nullptr),
        'EVP_KDF_fetch(HKDF)',
      );
      arena.onReleaseAll(() => ssl.EVP_KDF_free(kdf));
      final ctx = checkNotNull(ssl.EVP_KDF_CTX_new(kdf), 'EVP_KDF_CTX_new');
      arena.onReleaseAll(() => ssl.EVP_KDF_CTX_free(ctx));

      final bld = checkNotNull(ssl.OSSL_PARAM_BLD_new(), 'OSSL_PARAM_BLD_new');
      arena.onReleaseAll(() => ssl.OSSL_PARAM_BLD_free(bld));
      checkOne(
        ssl.OSSL_PARAM_BLD_push_utf8_string(
          bld,
          cString(arena, 'digest'),
          cString(arena, digest),
          0,
        ),
        'OSSL_PARAM_BLD_push_utf8_string(digest)',
      );
      checkOne(
        ssl.OSSL_PARAM_BLD_push_octet_string(
          bld,
          cString(arena, 'key'),
          toNative(arena, ikm).cast(),
          ikm.length,
        ),
        'OSSL_PARAM_BLD_push_octet_string(key)',
      );
      if (salt.isNotEmpty) {
        checkOne(
          ssl.OSSL_PARAM_BLD_push_octet_string(
            bld,
            cString(arena, 'salt'),
            toNative(arena, salt).cast(),
            salt.length,
          ),
          'OSSL_PARAM_BLD_push_octet_string(salt)',
        );
      }
      if (info.isNotEmpty) {
        checkOne(
          ssl.OSSL_PARAM_BLD_push_octet_string(
            bld,
            cString(arena, 'info'),
            toNative(arena, info).cast(),
            info.length,
          ),
          'OSSL_PARAM_BLD_push_octet_string(info)',
        );
      }
      final params = checkNotNull(
        ssl.OSSL_PARAM_BLD_to_param(bld),
        'OSSL_PARAM_BLD_to_param',
      );
      arena.onReleaseAll(() => ssl.OSSL_PARAM_free(params));

      final out = arena<UnsignedChar>(length == 0 ? 1 : length);
      checkOne(
        ssl.EVP_KDF_derive(ctx, out, length, params),
        'EVP_KDF_derive(HKDF)',
      );
      return fromNative(out, length);
    });
  }
}
