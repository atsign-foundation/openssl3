// The same checks as example/cli, returned as data so both the UI and the
// integration test can render/assert them.
import 'dart:convert';

import 'package:openssl3/evp.dart';
import 'package:openssl3/openssl3.dart' show OpenSSLCapabilities, initNoConfig;

final class SmokeResult {
  final String version;
  final String? target;
  final Map<String, bool> checks;
  const SmokeResult(this.version, this.target, this.checks);
  bool get allPassed => checks.values.every((v) => v);
}

SmokeResult runSmoke() {
  initNoConfig();
  final caps = OpenSSLCapabilities.instance;
  final checks = <String, bool>{};
  final message = utf8.encode('hello from openssl3');

  checks['openssl 3.5.x'] = caps.versionNumber >> 20 == 0x305;
  checks['ML-KEM-768 / ML-DSA-65 / X25519 / AES available'] =
      caps.hasMlKem768 &&
      caps.hasMlDsa65 &&
      caps.hasX25519 &&
      caps.hasAesGcm &&
      caps.hasAesCtr;

  final key = Random.privateBytes(32);
  final nonce = Random.bytes(12);
  final aead = Aead.aes256Gcm(key);
  final box = aead.seal(nonce, message, aad: utf8.encode('header'));
  checks['AES-256-GCM round trip'] =
      utf8.decode(aead.open(nonce, box, aad: utf8.encode('header'))) ==
      'hello from openssl3';
  var rejected = false;
  try {
    aead.open(
      nonce,
      SealedBox(box.ciphertext, List.filled(16, 0)),
      aad: utf8.encode('header'),
    );
  } on AuthenticationException {
    rejected = true;
  }
  checks['AES-256-GCM rejects a bad tag'] = rejected;

  final ctr = Cipher.aesCtr(key);
  final iv = Random.bytes(16);
  checks['AES-256-CTR round trip'] =
      utf8.decode(ctr.decrypt(iv, ctr.encrypt(iv, message))) ==
      'hello from openssl3';

  final a = X25519.keyPair();
  final b = X25519.keyPair();
  checks['X25519 agreement'] = _eq(
    X25519.agree(a.privateKey, b.publicKey),
    X25519.agree(b.privateKey, a.publicKey),
  );

  final kem = MlKem768.keyPair();
  final enc = MlKem768.encaps(kem.publicKey);
  checks['ML-KEM-768 encaps/decaps'] = _eq(
    enc.sharedSecret,
    MlKem768.decaps(kem.privateKey, enc.ciphertext),
  );

  final dsa = MlDsa65.keyPair();
  final sig = MlDsa65.sign(dsa.privateKey, message);
  checks['ML-DSA-65 sign/verify'] =
      MlDsa65.verify(dsa.publicKey, message, sig) &&
      !MlDsa65.verify(dsa.publicKey, [...message, 0], sig);

  return SmokeResult(
    caps.versionString,
    caps.buildInfo?['target'] as String?,
    checks,
  );
}

bool _eq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
