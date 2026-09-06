// Minimal example for package:openssl3. Run with `dart run` (the build hook
// bundles libopenssl3_crypto automatically) or see example/cli in the
// repository for the full smoke test and example/flutter_app for Flutter.
import 'dart:convert';

import 'package:openssl3/evp.dart';
import 'package:openssl3/openssl3.dart' show OpenSSLCapabilities, initNoConfig;

void main() {
  initNoConfig();
  final caps = OpenSSLCapabilities.instance;
  print(caps.versionString); // OpenSSL 3.5.8 ...
  print('ML-KEM-768: ${caps.hasMlKem768}, ML-DSA-65: ${caps.hasMlDsa65}');

  // Authenticated encryption.
  final key = Random.privateBytes(32);
  final nonce = Random.bytes(12);
  final aead = Aead.aes256Gcm(key);
  final box = aead.seal(nonce, utf8.encode('hello'), aad: utf8.encode('v1'));
  print(utf8.decode(aead.open(nonce, box, aad: utf8.encode('v1')))); // hello

  // Post-quantum key encapsulation.
  final kem = MlKem768.keyPair();
  final enc = MlKem768.encaps(kem.publicKey);
  final shared = MlKem768.decaps(kem.seed!, enc.ciphertext);
  print(shared.length); // 32

  // Post-quantum signatures.
  final dsa = MlDsa65.keyPair();
  final sig = MlDsa65.sign(dsa.privateKey, utf8.encode('message'));
  print(MlDsa65.verify(dsa.publicKey, utf8.encode('message'), sig)); // true
}
