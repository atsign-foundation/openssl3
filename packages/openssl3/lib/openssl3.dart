/// Prebuilt OpenSSL 3.5 LTS `libcrypto` for Dart and Flutter, bundled as a
/// code asset by this package's build hook, with `@Native` bindings for the
/// complete public libcrypto API.
///
/// - The raw C API: every function, struct, enum, typedef and macro from the
///   OpenSSL public headers (libssl excluded) is exported here under its C
///   name. See <https://docs.openssl.org/3.5/man3/>.
/// - [OpenSSLCapabilities] answers "does this build have ML-KEM-768 / AES-CTR
///   / …" the same way at_chops probes.
/// - [initNoConfig] initialises libcrypto without reading any config file.
/// - [OpenSSLException] turns the OpenSSL error queue into a Dart exception.
///
/// For a small idiomatic layer (AES-GCM/CTR, X25519, ML-KEM-768, ML-DSA-65,
/// random bytes) import `package:openssl3/evp.dart`.
library;

export 'src/capabilities.dart';
export 'src/errors.dart';
export 'src/third_party/openssl.g.dart';
export 'src/third_party/unbound_symbols.g.dart';
