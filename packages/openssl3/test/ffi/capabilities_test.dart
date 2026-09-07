@Tags(['ffi'])
library;

import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:openssl3/openssl3.dart';
import 'package:openssl3/src/native_build/required_symbols.dart';
import 'package:test/test.dart';

void main() {
  final caps = OpenSSLCapabilities.instance;

  test('initNoConfig is idempotent', () {
    initNoConfig();
    initNoConfig();
  });

  test('reports OpenSSL 3.5.x', () {
    expect(caps.versionNumber >> 20, 0x305, reason: 'major.minor = 3.5');
    expect(caps.versionString, startsWith('OpenSSL 3.5.'));
    expect(OPENSSL_VERSION_NUMBER >> 20, 0x305);
  });

  test('build info identifies this package\'s build', () {
    final info = caps.buildInfo;
    expect(info, isNotNull);
    expect(info!['openssl_version'], startsWith('3.5.'));
    expect(
      info['library_name'],
      contains('openssl3_crypto'),
    ); // lib prefix except on Windows
    expect(info['configure_args'], contains('no-module'));
    expect(info['configure_args'], contains('no-legacy'));
  });

  test('post-quantum and classic algorithms are present', () {
    expect(caps.hasMlKem768, isTrue);
    expect(caps.hasMlDsa65, isTrue);
    expect(caps.hasX25519, isTrue);
    expect(caps.hasEd25519, isTrue);
    expect(caps.hasAesGcm, isTrue);
    expect(caps.hasAesCtr, isTrue, reason: 'NoPorts session keys');
    expect(caps.hasChaCha20Poly1305, isTrue);
    expect(caps.hasDigest('SHA2-256'), isTrue);
    expect(caps.hasDigest('SHA3-256'), isTrue);
  });

  test('legacy-provider algorithms are absent by design', () {
    expect(caps.hasCipher('RC4'), isFalse);
    expect(caps.hasDigest('MD4'), isFalse);
    expect(caps.hasKeyType('NOT-A-REAL-ALGORITHM'), isFalse);
  });

  test('only the default provider is loaded', () {
    expect(caps.providerList, contains('default'));
    expect(caps.providerList, isNot(contains('legacy')));
    expect(caps.providerList, isNot(contains('fips')));
  });

  test('error queue becomes a typed exception', () {
    final n = 'NOT-A-REAL-ALGORITHM'.toNativeUtf8();
    try {
      final ctx = EVP_PKEY_CTX_new_from_name(nullptr, n.cast(), nullptr);
      expect(ctx, nullptr);
      final e = OpenSSLException.drain('EVP_PKEY_CTX_new_from_name');
      expect(e.codes, isNotEmpty);
      expect(e.toString(), contains('EVP_PKEY_CTX_new_from_name'));
      expect(ERR_get_error(), 0, reason: 'queue drained');
    } finally {
      calloc.free(n);
    }
  });

  test('every required symbol has a Dart binding', () {
    expect(requiredSymbols.intersection(unboundSymbols), isEmpty);
  });

  test('RAND_bytes is not deterministic', () {
    final a = calloc<UnsignedChar>(32);
    final b = calloc<UnsignedChar>(32);
    try {
      expect(RAND_bytes(a, 32), 1);
      expect(RAND_bytes(b, 32), 1);
      final la = a.cast<Uint8>().asTypedList(32);
      final lb = b.cast<Uint8>().asTypedList(32);
      expect(la, isNot(equals(lb)));
      expect(la.any((x) => x != 0), isTrue);
    } finally {
      calloc.free(a);
      calloc.free(b);
    }
  });
}
