// Smoke test for package:openssl3: prints the bundled OpenSSL version and
// build info, then exercises AES-256-GCM, AES-256-CTR, X25519, ML-KEM-768 and
// ML-DSA-65 through package:openssl3/evp.dart. Exits non-zero on any failure,
// so CI can run the built bundle on a machine with no OpenSSL installed.
import 'dart:convert';
import 'dart:io';

import 'package:openssl3/evp.dart';
import 'package:openssl3/openssl3.dart' show OpenSSLCapabilities, initNoConfig;

void main(List<String> args) {
  final json = args.contains('--json');
  final report = <String, Object?>{};
  var failures = 0;

  void check(String name, bool ok, [Object? detail]) {
    report[name] = ok;
    if (!ok) failures++;
    if (!json) {
      stdout.writeln(
        '${ok ? 'ok  ' : 'FAIL'} $name${detail == null ? '' : '  $detail'}',
      );
    }
  }

  initNoConfig();
  final caps = OpenSSLCapabilities.instance;
  report['version'] = caps.versionString;
  report['version_number'] = '0x${caps.versionNumber.toRadixString(16)}';
  report['build_info'] = caps.buildInfo;
  if (!json) {
    stdout.writeln(caps.versionString);
    final info = caps.buildInfo;
    if (info != null) {
      stdout.writeln(
        'built for ${info['target']} from OpenSSL ${info['openssl_version']} '
        '@ ${(info['openssl_commit'] as String?)?.substring(0, 12)} with '
        '${info['compiler_version']}',
      );
    }
  }
  check('openssl 3.5.x', caps.versionNumber >> 20 == 0x305);
  check(
    'capabilities',
    caps.hasMlKem768 &&
        caps.hasMlDsa65 &&
        caps.hasX25519 &&
        caps.hasAesGcm &&
        caps.hasAesCtr,
  );

  // AES-256-GCM round trip with AAD.
  final key = Random.privateBytes(32);
  final nonce = Random.bytes(12);
  final message = utf8.encode('hello from openssl3');
  final aead = Aead.aes256Gcm(key);
  final box = aead.seal(nonce, message, aad: utf8.encode('header'));
  final opened = aead.open(nonce, box, aad: utf8.encode('header'));
  check('aes-256-gcm', utf8.decode(opened) == 'hello from openssl3');
  var tampered = false;
  try {
    aead.open(
      nonce,
      SealedBox(box.ciphertext, List.filled(16, 0)),
      aad: utf8.encode('header'),
    );
  } on AuthenticationException {
    tampered = true;
  }
  check('aes-256-gcm rejects bad tag', tampered);

  // AES-256-CTR (NoPorts session keys), streaming == one-shot.
  final ctr = Cipher.aesCtr(key);
  final iv = Random.bytes(16);
  final ct = ctr.encrypt(iv, message);
  final stream = ctr.decryptStream(iv);
  final pt = [
    ...stream.update(ct.sublist(0, 5)),
    ...stream.update(ct.sublist(5)),
    ...stream.finish(),
  ];
  check('aes-256-ctr', utf8.decode(pt) == 'hello from openssl3');

  // X25519 agreement.
  final a = X25519.keyPair();
  final b = X25519.keyPair();
  final sab = X25519.agree(a.privateKey, b.publicKey);
  final sba = X25519.agree(b.privateKey, a.publicKey);
  check('x25519', _eq(sab, sba), 'shared ${_hex(sab).substring(0, 16)}…');

  // ML-KEM-768 encaps/decaps.
  final kem = MlKem768.keyPair();
  final enc = MlKem768.encaps(kem.publicKey);
  final dec = MlKem768.decaps(kem.privateKey, enc.ciphertext);
  check(
    'ml-kem-768',
    _eq(enc.sharedSecret, dec),
    'ct ${enc.ciphertext.length} B',
  );

  // ML-DSA-65 sign/verify.
  final dsa = MlDsa65.keyPair();
  final sig = MlDsa65.sign(dsa.privateKey, message);
  check(
    'ml-dsa-65',
    MlDsa65.verify(dsa.publicKey, message, sig) &&
        !MlDsa65.verify(dsa.publicKey, [...message, 0], sig),
    'sig ${sig.length} B',
  );

  report['failures'] = failures;
  if (json) stdout.writeln(jsonEncode(report));
  if (failures > 0) {
    stderr.writeln('$failures check(s) failed');
    exit(1);
  }
}

bool _eq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
