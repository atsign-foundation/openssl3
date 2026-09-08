/// Small helpers for moving byte buffers across the FFI boundary.
///
/// Two flavours: [toNative] for public data (ciphertext, AAD, public keys),
/// and [secretToNative] / [secretBuffer] for anything a caller would not want
/// left behind in freed heap memory (keys, seeds, IKM, shared secrets,
/// plaintext). The secret flavour wipes the native copy with
/// `OPENSSL_cleanse` when the arena is released. The Dart-side copies the
/// caller holds (and the `Uint8List`s returned) are garbage collected and
/// cannot be wiped from here; keep their lifetime short.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../third_party/openssl.g.dart' as ssl;

/// Copies [bytes] into arena-allocated native memory.
Pointer<UnsignedChar> toNative(Arena arena, List<int> bytes) {
  final ptr = arena<UnsignedChar>(bytes.isEmpty ? 1 : bytes.length);
  if (bytes.isNotEmpty) {
    ptr.cast<Uint8>().asTypedList(bytes.length).setAll(0, bytes);
  }
  return ptr;
}

/// Copies secret [bytes] into native memory that is wiped with
/// `OPENSSL_cleanse` and freed when [arena] is released.
Pointer<UnsignedChar> secretToNative(Arena arena, List<int> bytes) {
  final ptr = secretBuffer(arena, bytes.length);
  if (bytes.isNotEmpty) {
    ptr.cast<Uint8>().asTypedList(bytes.length).setAll(0, bytes);
  }
  return ptr;
}

/// Zero-filled native memory of [length] bytes (at least one) for secret
/// output, wiped with `OPENSSL_cleanse` and freed when [arena] is released.
///
/// The buffer is not owned by the arena's allocator: the wipe must run while
/// the memory is still mapped, so one release callback does both, independent
/// of the order in which the arena frees its own allocations.
Pointer<UnsignedChar> secretBuffer(Arena arena, int length) {
  final n = length == 0 ? 1 : length;
  final ptr = calloc<UnsignedChar>(n);
  arena.onReleaseAll(() {
    ssl.OPENSSL_cleanse(ptr.cast(), n);
    calloc.free(ptr);
  });
  return ptr;
}

/// Copies [length] bytes out of native memory into a fresh [Uint8List].
Uint8List fromNative(Pointer<UnsignedChar> ptr, int length) =>
    Uint8List.fromList(ptr.cast<Uint8>().asTypedList(length));

/// A C string in arena memory.
Pointer<Char> cString(Arena arena, String s) =>
    s.toNativeUtf8(allocator: arena).cast<Char>();

/// Constant-time equality for byte strings of equal length, via libcrypto's
/// `CRYPTO_memcmp` so no JIT can shortcut the comparison. Lengths are not
/// secret; unequal lengths return `false` at once.
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  if (a.isEmpty) return true;
  return using(
    (arena) =>
        ssl.CRYPTO_memcmp(
          toNative(arena, a).cast(),
          toNative(arena, b).cast(),
          a.length,
        ) ==
        0,
  );
}
