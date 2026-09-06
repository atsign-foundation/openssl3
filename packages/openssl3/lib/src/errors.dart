/// Typed access to OpenSSL's error queue.
library;

import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'third_party/openssl.g.dart' as ssl;

/// An error reported by libcrypto, taken from `ERR_get_error()`.
final class OpenSSLException implements Exception {
  /// What the caller was doing, e.g. `EVP_PKEY_keygen`.
  final String operation;

  /// Packed OpenSSL error codes (`ERR_get_error()`), oldest first. Empty when
  /// a call failed without queueing an error.
  final List<int> codes;

  /// Human readable strings for [codes] (`ERR_error_string_n`).
  final List<String> messages;

  OpenSSLException(this.operation, this.codes, this.messages);

  /// Drains the current thread's error queue into an [OpenSSLException].
  factory OpenSSLException.drain(String operation) {
    final codes = <int>[];
    final messages = <String>[];
    final buf = calloc<Char>(256);
    try {
      for (var i = 0; i < 32; i++) {
        final code = ssl.ERR_get_error();
        if (code == 0) break;
        codes.add(code);
        ssl.ERR_error_string_n(code, buf, 256);
        messages.add(buf.cast<Utf8>().toDartString());
      }
    } finally {
      calloc.free(buf);
    }
    return OpenSSLException(operation, codes, messages);
  }

  @override
  String toString() {
    if (messages.isEmpty) {
      return 'OpenSSLException: $operation failed (no error queued)';
    }
    return 'OpenSSLException: $operation failed: ${messages.join('; ')}';
  }
}

/// Throws [OpenSSLException] for [operation] when [result] is not 1, the
/// success value of most `EVP_*` functions. Returns [result] otherwise.
int checkOne(int result, String operation) {
  if (result != 1) {
    throw OpenSSLException.drain(operation);
  }
  return result;
}

/// Throws [OpenSSLException] for [operation] when [pointer] is null.
Pointer<T> checkNotNull<T extends NativeType>(
  Pointer<T> pointer,
  String operation,
) {
  if (pointer == nullptr) {
    throw OpenSSLException.drain(operation);
  }
  return pointer;
}
