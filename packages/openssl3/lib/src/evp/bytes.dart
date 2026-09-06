/// Small helpers for moving byte buffers across the FFI boundary.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

/// Copies [bytes] into arena-allocated native memory.
Pointer<UnsignedChar> toNative(Arena arena, List<int> bytes) {
  final ptr = arena<UnsignedChar>(bytes.isEmpty ? 1 : bytes.length);
  if (bytes.isNotEmpty) {
    ptr.cast<Uint8>().asTypedList(bytes.length).setAll(0, bytes);
  }
  return ptr;
}

/// Copies [length] bytes out of native memory into a fresh [Uint8List].
Uint8List fromNative(Pointer<UnsignedChar> ptr, int length) =>
    Uint8List.fromList(ptr.cast<Uint8>().asTypedList(length));

/// A C string in arena memory.
Pointer<Char> cString(Arena arena, String s) =>
    s.toNativeUtf8(allocator: arena).cast<Char>();

/// Constant-time equality for fixed-length byte strings.
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
