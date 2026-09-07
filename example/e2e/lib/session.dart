/// Handshake and record layer for the e2e protocol, built entirely on
/// `package:openssl3/evp.dart`.
///
/// Handshake (one round trip):
///
///     client -> server  ClientHello: version, cipher, x25519_pub, mlkem768_pub
///     server -> client  ServerHello: x25519_pub, mlkem768_ct, mldsa65_sig
///
/// `mldsa65_sig` is the server identity's signature over
/// SHA-256(ClientHello || ServerHello-without-signature). The client pins the
/// server's ML-DSA-65 public key. Both sides then derive
///
///     ikm  = x25519(shared) || mlkem768(shared)
///     okm  = HKDF-SHA256(ikm, salt = transcript hash, info = "openssl3-e2e/1")
///
/// and split it into a client-to-server and a server-to-client key set.
///
/// Record layer ([Cipher] modes):
/// - `gcm`: payload = AES-256-GCM(nonce = salt4 || seq8, plaintext,
///   aad = frame header) || tag16.
/// - `ctr`: payload = AES-256-CTR(iv = salt4 || seq8 || 0000, plaintext) ||
///   HMAC-SHA256(macKey, header || ciphertext)16..32. This is the NoPorts
///   shape (unauthenticated CTR plus a separate MAC).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:openssl3/evp.dart';

import 'framing.dart';

const int protocolVersion = 1;

enum RecordCipher {
  gcm(0x01),
  ctr(0x02);

  final int id;
  const RecordCipher(this.id);

  static RecordCipher fromId(int id) => values.firstWhere(
    (c) => c.id == id,
    orElse: () => throw FormatException('unknown cipher id $id'),
  );

  static RecordCipher parse(String s) => values.firstWhere(
    (c) => c.name == s.toLowerCase(),
    orElse: () => throw FormatException('cipher must be gcm or ctr', s),
  );
}

/// Long-term server identity (ML-DSA-65). The seed is what you store.
final class ServerIdentity {
  final MlDsa65KeyPair keyPair;
  ServerIdentity(this.keyPair);

  factory ServerIdentity.generate() => ServerIdentity(MlDsa65.keyPair());
  factory ServerIdentity.fromSeed(List<int> seed) =>
      ServerIdentity(MlDsa65.keyPair(seed: seed));

  Uint8List get publicKey => keyPair.publicKey;

  /// SHA-256 of the public key, hex; what humans compare.
  String get fingerprint => _hex(Digest.sha256.hash(publicKey));
}

/// One direction of the record layer.
final class RecordKeys {
  final Uint8List key;
  final Uint8List nonceSalt; // 4 bytes
  final Uint8List macKey; // 32 bytes, ctr only
  const RecordKeys(this.key, this.nonceSalt, this.macKey);
}

final class SessionKeys {
  final RecordCipher cipher;
  final RecordKeys clientToServer;
  final RecordKeys serverToClient;
  final Uint8List transcriptHash;
  const SessionKeys(
    this.cipher,
    this.clientToServer,
    this.serverToClient,
    this.transcriptHash,
  );

  static SessionKeys derive(
    RecordCipher cipher,
    List<int> x25519Shared,
    List<int> kemShared,
    List<int> transcriptHash,
  ) {
    final okm = Hkdf.derive(
      ikm: [...x25519Shared, ...kemShared],
      salt: transcriptHash,
      info: utf8.encode('openssl3-e2e/$protocolVersion'),
      length: 2 * (32 + 4 + 32),
    );
    RecordKeys slice(int at) => RecordKeys(
      okm.sublist(at, at + 32),
      okm.sublist(at + 32, at + 36),
      okm.sublist(at + 36, at + 68),
    );
    return SessionKeys(
      cipher,
      slice(0),
      slice(68),
      Uint8List.fromList(transcriptHash),
    );
  }
}

/// Encrypts frames in one direction with strictly increasing sequence numbers.
final class RecordWriter {
  final RecordCipher cipher;
  final RecordKeys keys;
  final Aead? _aead;
  final Cipher? _ctr;
  final Hmac? _mac;
  int _seq = 0;

  RecordWriter(this.cipher, this.keys)
    : _aead = cipher == RecordCipher.gcm ? Aead.aes256Gcm(keys.key) : null,
      _ctr = cipher == RecordCipher.ctr ? Cipher.aesCtr(keys.key) : null,
      _mac = cipher == RecordCipher.ctr ? Hmac.sha256(keys.macKey) : null;

  int get nextSequence => _seq;

  /// Returns `header || protected payload` for [plaintext].
  Uint8List seal(int type, List<int> plaintext) {
    final seq = _seq++;
    switch (cipher) {
      case RecordCipher.gcm:
        final header = encodeHeader(type, seq, plaintext.length + 16);
        final box = _aead!.seal(
          _nonce12(keys.nonceSalt, seq),
          plaintext,
          aad: header,
        );
        return _concat([header, box.ciphertext, box.tag]);
      case RecordCipher.ctr:
        final header = encodeHeader(type, seq, plaintext.length + 32);
        final ct = _ctr!.encrypt(_iv16(keys.nonceSalt, seq), plaintext);
        final tag = _mac!.compute(_concat([header, ct]));
        return _concat([header, ct, tag]);
    }
  }
}

/// Decrypts frames in one direction, enforcing the sequence.
final class RecordReader {
  final RecordCipher cipher;
  final RecordKeys keys;
  final Aead? _aead;
  final Cipher? _ctr;
  final Hmac? _mac;
  int _expectedSeq = 0;

  RecordReader(this.cipher, this.keys)
    : _aead = cipher == RecordCipher.gcm ? Aead.aes256Gcm(keys.key) : null,
      _ctr = cipher == RecordCipher.ctr ? Cipher.aesCtr(keys.key) : null,
      _mac = cipher == RecordCipher.ctr ? Hmac.sha256(keys.macKey) : null;

  /// Opens [payload] for [header]; throws [AuthenticationException] on any
  /// tampering, reordering or replay.
  Uint8List open(FrameHeader header, Uint8List payload) {
    if (header.sequence != _expectedSeq) {
      throw const AuthenticationException();
    }
    _expectedSeq++;
    switch (cipher) {
      case RecordCipher.gcm:
        return _aead!.open(
          _nonce12(keys.nonceSalt, header.sequence),
          SealedBox.fromCombined(payload),
          aad: header.bytes,
        );
      case RecordCipher.ctr:
        if (payload.length < 32) throw const AuthenticationException();
        final ct = payload.sublist(0, payload.length - 32);
        final tag = payload.sublist(payload.length - 32);
        if (!_mac!.verify(_concat([header.bytes, ct]), tag)) {
          throw const AuthenticationException();
        }
        return _ctr!.decrypt(_iv16(keys.nonceSalt, header.sequence), ct);
    }
  }
}

/// What the client sends first.
final class ClientHello {
  final RecordCipher cipher;
  final Uint8List x25519Public;
  final Uint8List kemPublic;
  const ClientHello(this.cipher, this.x25519Public, this.kemPublic);

  Uint8List encode() => _concat([
    [protocolVersion, cipher.id],
    x25519Public,
    kemPublic,
  ]);

  static ClientHello decode(Uint8List b) {
    if (b.length != 2 + X25519.keyLength + MlKem768.publicKeyLength) {
      throw FormatException('bad ClientHello length ${b.length}');
    }
    if (b[0] != protocolVersion) {
      throw FormatException('unsupported protocol version ${b[0]}');
    }
    return ClientHello(
      RecordCipher.fromId(b[1]),
      b.sublist(2, 2 + X25519.keyLength),
      b.sublist(2 + X25519.keyLength),
    );
  }
}

final class ServerHello {
  final Uint8List x25519Public;
  final Uint8List kemCiphertext;
  final Uint8List signature;
  const ServerHello(this.x25519Public, this.kemCiphertext, this.signature);

  Uint8List get unsigned => _concat([x25519Public, kemCiphertext]);
  Uint8List encode() => _concat([unsigned, signature]);

  static ServerHello decode(Uint8List b) {
    const n = X25519.keyLength + MlKem768.ciphertextLength;
    if (b.length != n + MlDsa65.signatureLength) {
      throw FormatException('bad ServerHello length ${b.length}');
    }
    return ServerHello(
      b.sublist(0, X25519.keyLength),
      b.sublist(X25519.keyLength, n),
      b.sublist(n),
    );
  }
}

/// Server side of the handshake: consumes a ClientHello, produces the
/// ServerHello and the session keys.
(ServerHello, SessionKeys) serverHandshake(
  ClientHello hello,
  ServerIdentity identity,
) {
  final eph = X25519.keyPair();
  final x = X25519.agree(eph.privateKey, hello.x25519Public);
  final enc = MlKem768.encaps(hello.kemPublic);
  final unsigned = _concat([eph.publicKey, enc.ciphertext]);
  final transcript = Digest.sha256.hash(_concat([hello.encode(), unsigned]));
  final sig = MlDsa65.sign(identity.keyPair.privateKey, transcript);
  final keys = SessionKeys.derive(
    hello.cipher,
    x,
    enc.sharedSecret,
    transcript,
  );
  return (ServerHello(eph.publicKey, enc.ciphertext, sig), keys);
}

/// Client side: ephemeral keys, then completion once the ServerHello arrives.
final class ClientHandshake {
  final RecordCipher cipher;
  final X25519KeyPair _x;
  final MlKem768KeyPair _kem;
  late final ClientHello hello;

  ClientHandshake(this.cipher)
    : _x = X25519.keyPair(),
      _kem = MlKem768.keyPair() {
    hello = ClientHello(cipher, _x.publicKey, _kem.publicKey);
  }

  /// Verifies the server signature against [pinnedServerKey] and derives keys.
  /// Throws [HandshakeException] on a bad signature.
  SessionKeys complete(ServerHello server, List<int> pinnedServerKey) {
    final transcript = Digest.sha256.hash(
      _concat([hello.encode(), server.unsigned]),
    );
    if (!MlDsa65.verify(pinnedServerKey, transcript, server.signature)) {
      throw const HandshakeException('server signature does not verify');
    }
    final x = X25519.agree(_x.privateKey, server.x25519Public);
    final ss = MlKem768.decaps(_kem.seed!, server.kemCiphertext);
    return SessionKeys.derive(cipher, x, ss, transcript);
  }
}

final class HandshakeException implements Exception {
  final String message;
  const HandshakeException(this.message);
  @override
  String toString() => 'HandshakeException: $message';
}

Uint8List _nonce12(Uint8List salt4, int seq) {
  final b = ByteData(12);
  for (var i = 0; i < 4; i++) {
    b.setUint8(i, salt4[i]);
  }
  b.setUint64(4, seq);
  return b.buffer.asUint8List();
}

Uint8List _iv16(Uint8List salt4, int seq) {
  final b = ByteData(16);
  for (var i = 0; i < 4; i++) {
    b.setUint8(i, salt4[i]);
  }
  b.setUint64(4, seq);
  // Last 4 bytes are the CTR block counter, starting at 0.
  return b.buffer.asUint8List();
}

Uint8List _concat(List<List<int>> parts) {
  final total = parts.fold<int>(0, (n, p) => n + p.length);
  final out = Uint8List(total);
  var at = 0;
  for (final p in parts) {
    out.setRange(at, at + p.length, p);
    at += p.length;
  }
  return out;
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
