/// Shared `EVP_PKEY` plumbing for the key-exchange, KEM and signature layers.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../capabilities.dart';
import '../errors.dart';
import '../third_party/openssl.g.dart' as ssl;
import 'bytes.dart';

/// Runs [body] with a freshly generated key of [algorithm] and frees it.
T withGeneratedKey<T>(
  Arena arena,
  String algorithm,
  T Function(Pointer<ssl.EVP_PKEY>) body, {
  void Function(Pointer<ssl.EVP_PKEY_CTX> ctx)? configure,
}) {
  initNoConfig();
  final ctx = checkNotNull(
    ssl.EVP_PKEY_CTX_new_from_name(nullptr, cString(arena, algorithm), nullptr),
    'EVP_PKEY_CTX_new_from_name($algorithm)',
  );
  arena.using(ctx, ssl.EVP_PKEY_CTX_free);
  checkOne(ssl.EVP_PKEY_keygen_init(ctx), 'EVP_PKEY_keygen_init');
  configure?.call(ctx);
  final out = arena<Pointer<ssl.EVP_PKEY>>();
  checkOne(ssl.EVP_PKEY_keygen(ctx, out), 'EVP_PKEY_keygen($algorithm)');
  final pkey = out.value;
  try {
    return body(pkey);
  } finally {
    ssl.EVP_PKEY_free(pkey);
  }
}

/// Builds a key of [algorithm] from raw public bytes.
Pointer<ssl.EVP_PKEY> rawPublicKey(
  Arena arena,
  String algorithm,
  List<int> bytes,
) {
  initNoConfig();
  final pkey = checkNotNull(
    ssl.EVP_PKEY_new_raw_public_key_ex(
      nullptr,
      cString(arena, algorithm),
      nullptr,
      toNative(arena, bytes),
      bytes.length,
    ),
    'EVP_PKEY_new_raw_public_key_ex($algorithm)',
  );
  arena.using(pkey, ssl.EVP_PKEY_free);
  return pkey;
}

/// Builds a key of [algorithm] from raw private bytes.
Pointer<ssl.EVP_PKEY> rawPrivateKey(
  Arena arena,
  String algorithm,
  List<int> bytes,
) {
  initNoConfig();
  final pkey = checkNotNull(
    ssl.EVP_PKEY_new_raw_private_key_ex(
      nullptr,
      cString(arena, algorithm),
      nullptr,
      toNative(arena, bytes),
      bytes.length,
    ),
    'EVP_PKEY_new_raw_private_key_ex($algorithm)',
  );
  arena.using(pkey, ssl.EVP_PKEY_free);
  return pkey;
}

/// Builds a key of [algorithm] from an OSSL_PARAM octet string such as the
/// ML-KEM/ML-DSA `seed`, via `EVP_PKEY_fromdata`.
Pointer<ssl.EVP_PKEY> keyFromOctetParam(
  Arena arena,
  String algorithm,
  String paramName,
  List<int> value, {
  int selection = ssl.EVP_PKEY_KEYPAIR,
}) {
  initNoConfig();
  final bld = checkNotNull(ssl.OSSL_PARAM_BLD_new(), 'OSSL_PARAM_BLD_new');
  arena.using(bld, ssl.OSSL_PARAM_BLD_free);
  checkOne(
    ssl.OSSL_PARAM_BLD_push_octet_string(
      bld,
      cString(arena, paramName),
      toNative(arena, value).cast(),
      value.length,
    ),
    'OSSL_PARAM_BLD_push_octet_string($paramName)',
  );
  final params = checkNotNull(
    ssl.OSSL_PARAM_BLD_to_param(bld),
    'OSSL_PARAM_BLD_to_param',
  );
  arena.using(params, ssl.OSSL_PARAM_free);
  final ctx = checkNotNull(
    ssl.EVP_PKEY_CTX_new_from_name(nullptr, cString(arena, algorithm), nullptr),
    'EVP_PKEY_CTX_new_from_name($algorithm)',
  );
  arena.using(ctx, ssl.EVP_PKEY_CTX_free);
  checkOne(ssl.EVP_PKEY_fromdata_init(ctx), 'EVP_PKEY_fromdata_init');
  final out = arena<Pointer<ssl.EVP_PKEY>>();
  checkOne(
    ssl.EVP_PKEY_fromdata(ctx, out, selection, params),
    'EVP_PKEY_fromdata($algorithm, $paramName)',
  );
  arena.using(out.value, ssl.EVP_PKEY_free);
  return out.value;
}

/// `EVP_PKEY_get_raw_public_key` as bytes.
Uint8List rawPublicBytes(Arena arena, Pointer<ssl.EVP_PKEY> pkey) {
  final len = arena<Size>();
  checkOne(
    ssl.EVP_PKEY_get_raw_public_key(pkey, nullptr, len),
    'EVP_PKEY_get_raw_public_key(len)',
  );
  final buf = arena<UnsignedChar>(len.value);
  checkOne(
    ssl.EVP_PKEY_get_raw_public_key(pkey, buf, len),
    'EVP_PKEY_get_raw_public_key',
  );
  return fromNative(buf, len.value);
}

/// `EVP_PKEY_get_raw_private_key` as bytes.
Uint8List rawPrivateBytes(Arena arena, Pointer<ssl.EVP_PKEY> pkey) {
  final len = arena<Size>();
  checkOne(
    ssl.EVP_PKEY_get_raw_private_key(pkey, nullptr, len),
    'EVP_PKEY_get_raw_private_key(len)',
  );
  final buf = arena<UnsignedChar>(len.value);
  checkOne(
    ssl.EVP_PKEY_get_raw_private_key(pkey, buf, len),
    'EVP_PKEY_get_raw_private_key',
  );
  return fromNative(buf, len.value);
}

/// An octet-string key parameter such as `seed`, or `null` if absent.
Uint8List? octetParam(Arena arena, Pointer<ssl.EVP_PKEY> pkey, String name) {
  final len = arena<Size>();
  final buf = arena<UnsignedChar>(256);
  final ok = ssl.EVP_PKEY_get_octet_string_param(
    pkey,
    cString(arena, name),
    buf,
    256,
    len,
  );
  if (ok != 1) {
    ssl.ERR_clear_error();
    return null;
  }
  return fromNative(buf, len.value);
}

/// Arena helper: free [ptr] with [free] when the arena is released.
extension ArenaRelease on Arena {
  void using<T extends NativeType>(
    Pointer<T> ptr,
    void Function(Pointer<T>) free,
  ) {
    onReleaseAll(() => free(ptr));
  }
}
