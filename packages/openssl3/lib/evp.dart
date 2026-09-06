/// A small idiomatic layer over the raw bindings, sized for at_chops and
/// NoPorts: enough to replace their `*FfiAlgo` classes, no more.
///
/// - [Aead]: AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305 (`seal` / `open`).
/// - [Cipher]: AES-CTR with 128/192/256-bit keys, one-shot and streaming.
/// - [X25519]: key pairs and agreement.
/// - [MlKem768]: key pairs (optionally from a 64-byte seed), encaps, decaps.
/// - [MlDsa65]: key pairs (optionally from a 32-byte seed), sign, verify.
/// - [Random]: `RAND_bytes` / `RAND_priv_bytes`.
///
/// Keys are plain byte strings in OpenSSL's raw encodings, so they round-trip
/// with at_chops and with any other OpenSSL-based implementation. Errors from
/// libcrypto surface as [OpenSSLException]; failed AEAD authentication as
/// [AuthenticationException].
///
/// The raw C API in `package:openssl3/openssl3.dart` remains the primary
/// surface; this library exists so common operations need no `dart:ffi`.
library;

export 'src/errors.dart' show OpenSSLException;
export 'src/evp/aead.dart';
export 'src/evp/cipher.dart';
export 'src/evp/ml_dsa.dart';
export 'src/evp/ml_kem.dart';
export 'src/evp/random.dart';
export 'src/evp/x25519.dart';
