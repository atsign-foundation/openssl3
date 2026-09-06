/// Library initialisation and capability probing for the bundled libcrypto.
library;

import 'dart:convert';
import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'third_party/openssl.g.dart' as ssl;

/// The one symbol this package adds to libcrypto: a JSON document describing
/// how the bundled binary was built (see `src/native/openssl3_shim.c`).
@Native<Pointer<Char> Function()>(
  symbol: 'openssl3_build_info',
  assetId: 'package:openssl3/src/third_party/openssl.g.dart',
  isLeaf: true,
)
external Pointer<Char> _openssl3BuildInfo();

bool _initialised = false;

/// Initialises libcrypto **without** loading any configuration file.
///
/// The bundled library is built with `--openssldir` pointing at a path that
/// does not exist and with `no-module no-dso`, so nothing is ever read from
/// disk; this call makes that explicit by passing `OPENSSL_INIT_NO_LOAD_CONFIG`
/// and `OPENSSL_INIT_NO_ATEXIT`. Safe to call more than once; the first call
/// does the work. Every helper in this package calls it, so calling it
/// yourself is optional but recommended at startup.
void initNoConfig() {
  if (_initialised) return;
  final ok = ssl.OPENSSL_init_crypto(
    ssl.OPENSSL_INIT_NO_LOAD_CONFIG |
        ssl.OPENSSL_INIT_NO_ATEXIT |
        ssl.OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
    nullptr,
  );
  if (ok != 1) {
    throw StateError('OPENSSL_init_crypto failed');
  }
  _initialised = true;
}

/// What the bundled (or, with `system: true`, the system) libcrypto offers.
///
/// Probes use `EVP_PKEY_CTX_new_from_name` and `EVP_CIPHER_fetch`, the same
/// checks at_chops performs before choosing an FFI backend, so their answers
/// agree.
final class OpenSSLCapabilities {
  OpenSSLCapabilities._();

  static final OpenSSLCapabilities instance = OpenSSLCapabilities._();

  /// `OpenSSL_version_num()`, e.g. `0x30500080` for 3.5.8.
  int get versionNumber {
    initNoConfig();
    return ssl.OpenSSL_version_num();
  }

  /// `OpenSSL_version(OPENSSL_VERSION)`, e.g. `OpenSSL 3.5.8 25 Aug 2026`.
  String get versionString {
    initNoConfig();
    return ssl.OpenSSL_version(ssl.OPENSSL_VERSION).cast<Utf8>().toDartString();
  }

  /// Build metadata embedded by this package's build pipeline (target, OpenSSL
  /// commit, compiler, Configure arguments). `null` when the loaded library
  /// is not one of ours (e.g. `system: true`).
  Map<String, Object?>? get buildInfo {
    try {
      final ptr = _openssl3BuildInfo();
      if (ptr == nullptr) return null;
      return jsonDecode(ptr.cast<Utf8>().toDartString())
          as Map<String, Object?>;
    } on ArgumentError {
      // Symbol missing: a system libcrypto was substituted.
      return null;
    }
  }

  bool get hasMlKem768 => hasKeyType('ML-KEM-768');
  bool get hasMlDsa65 => hasKeyType('ML-DSA-65');
  bool get hasX25519 => hasKeyType('X25519');
  bool get hasEd25519 => hasKeyType('ED25519');
  bool get hasAesGcm => hasCipher('AES-256-GCM');
  bool get hasAesCtr =>
      hasCipher('AES-128-CTR') &&
      hasCipher('AES-192-CTR') &&
      hasCipher('AES-256-CTR');
  bool get hasChaCha20Poly1305 => hasCipher('ChaCha20-Poly1305');

  /// Whether `EVP_PKEY_CTX_new_from_name(NULL, name, NULL)` succeeds.
  bool hasKeyType(String name) {
    initNoConfig();
    final n = name.toNativeUtf8();
    try {
      final ctx = ssl.EVP_PKEY_CTX_new_from_name(nullptr, n.cast(), nullptr);
      if (ctx == nullptr) {
        ssl.ERR_clear_error();
        return false;
      }
      ssl.EVP_PKEY_CTX_free(ctx);
      return true;
    } finally {
      calloc.free(n);
    }
  }

  /// Whether `EVP_CIPHER_fetch(NULL, name, NULL)` succeeds.
  bool hasCipher(String name) {
    initNoConfig();
    final n = name.toNativeUtf8();
    try {
      final cipher = ssl.EVP_CIPHER_fetch(nullptr, n.cast(), nullptr);
      if (cipher == nullptr) {
        ssl.ERR_clear_error();
        return false;
      }
      ssl.EVP_CIPHER_free(cipher);
      return true;
    } finally {
      calloc.free(n);
    }
  }

  /// Whether `EVP_MD_fetch(NULL, name, NULL)` succeeds.
  bool hasDigest(String name) {
    initNoConfig();
    final n = name.toNativeUtf8();
    try {
      final md = ssl.EVP_MD_fetch(nullptr, n.cast(), nullptr);
      if (md == nullptr) {
        ssl.ERR_clear_error();
        return false;
      }
      ssl.EVP_MD_free(md);
      return true;
    } finally {
      calloc.free(n);
    }
  }

  /// Names of the providers loaded in the default library context. For the
  /// bundled build this is `default` (and `base`/`null` if activated); the
  /// legacy and FIPS providers are not compiled in.
  List<String> get providerList {
    initNoConfig();
    final names = <String>[];
    // OSSL_PROVIDER_do_all only enumerates *activated* providers; make sure
    // the default one is, which is also what any EVP call would do.
    final def = 'default'.toNativeUtf8();
    try {
      ssl.OSSL_PROVIDER_load(nullptr, def.cast());
    } finally {
      calloc.free(def);
    }
    final callback =
        NativeCallable<
          Int Function(Pointer<ssl.OSSL_PROVIDER>, Pointer<Void>)
        >.isolateLocal((Pointer<ssl.OSSL_PROVIDER> prov, Pointer<Void> _) {
          names.add(
            ssl.OSSL_PROVIDER_get0_name(prov).cast<Utf8>().toDartString(),
          );
          return 1;
        }, exceptionalReturn: 0);
    try {
      ssl.OSSL_PROVIDER_do_all(nullptr, callback.nativeFunction, nullptr);
    } finally {
      callback.close();
    }
    return names;
  }
}
