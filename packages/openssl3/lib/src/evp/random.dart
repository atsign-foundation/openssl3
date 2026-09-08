/// Cryptographically secure random bytes from OpenSSL's DRBG.
library;

import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../capabilities.dart';
import '../errors.dart';
import '../third_party/openssl.g.dart' as ssl;
import 'bytes.dart';

/// `RAND_bytes` / `RAND_priv_bytes` as Dart.
abstract final class Random {
  /// [length] random bytes from the public DRBG (`RAND_bytes`).
  static Uint8List bytes(int length) => _fill(length, private: false);

  /// [length] random bytes from the private DRBG (`RAND_priv_bytes`), meant
  /// for long-term secrets such as keys.
  static Uint8List privateBytes(int length) => _fill(length, private: true);

  static Uint8List _fill(int length, {required bool private}) {
    RangeError.checkNotNegative(length, 'length');
    initNoConfig();
    if (length == 0) return Uint8List(0);
    return using((arena) {
      final buf = secretBuffer(arena, length);
      checkOne(
        private
            ? ssl.RAND_priv_bytes(buf, length)
            : ssl.RAND_bytes(buf, length),
        private ? 'RAND_priv_bytes' : 'RAND_bytes',
      );
      return fromNative(buf, length);
    });
  }
}
