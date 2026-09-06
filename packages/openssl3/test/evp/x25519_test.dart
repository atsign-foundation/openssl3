@Tags(['ffi'])
library;

import 'package:openssl3/evp.dart';
import 'package:test/test.dart';

import 'hex.dart';

void main() {
  // RFC 7748 §6.1.
  final alicePriv = hex(
    '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
  );
  final alicePub = hex(
    '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
  );
  final bobPriv = hex(
    '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
  );
  final bobPub = hex(
    'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
  );
  final shared = hex(
    '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
  );

  test('public keys derive per RFC 7748', () {
    expect(toHex(X25519.publicKeyOf(alicePriv)), toHex(alicePub));
    expect(toHex(X25519.publicKeyOf(bobPriv)), toHex(bobPub));
  });

  test('agreement matches RFC 7748 in both directions', () {
    expect(toHex(X25519.agree(alicePriv, bobPub)), toHex(shared));
    expect(toHex(X25519.agree(bobPriv, alicePub)), toHex(shared));
  });

  test('fresh key pairs agree with each other', () {
    final a = X25519.keyPair();
    final b = X25519.keyPair();
    expect(a.publicKey.length, 32);
    expect(a.privateKey.length, 32);
    expect(a.publicKey, isNot(equals(b.publicKey)));
    expect(
      X25519.agree(a.privateKey, b.publicKey),
      X25519.agree(b.privateKey, a.publicKey),
    );
  });

  test('all-zero peer point is rejected', () {
    expect(
      () => X25519.agree(alicePriv, List.filled(32, 0)),
      throwsA(isA<OpenSSLException>()),
    );
  });

  test('wrong key lengths are rejected', () {
    expect(
      () => X25519.agree(alicePriv, List.filled(31, 1)),
      throwsA(isA<OpenSSLException>()),
    );
  });
}
