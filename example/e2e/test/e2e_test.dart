import 'dart:io';
import 'dart:typed_data';

import 'package:openssl3/evp.dart';
import 'package:openssl3_e2e/e2e.dart';
import 'package:openssl3_e2e/framing.dart';
import 'package:openssl3_e2e/session.dart';
import 'package:test/test.dart';

void main() {
  for (final cipher in RecordCipher.values) {
    group('end to end (${cipher.name})', () {
      late ServerSocket server;
      late ServerIdentity identity;
      late E2eServer e2e;

      setUp(() async {
        identity = ServerIdentity.generate();
        server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
        e2e = E2eServer(identity, log: (_) {});
      });
      tearDown(() => server.close());

      Future<Socket> connect() => Socket.connect(server.address, server.port);

      test(
        'transfers 4 MB with matching digests and a signed summary',
        () async {
          // Arm the accept before connecting; awaiting it first would deadlock.
          final serverSide = server.first.then(e2e.handle);
          final summary = await E2eClient(
            pinnedServerKey: identity.publicKey,
            cipher: cipher,
            totalBytes: 4 << 20,
            frameSize:
                61 * 1024 + 7, // odd size: exercises a partial last frame
            log: (_) {},
          ).run(await connect());
          final serverSummary = await serverSide;
          expect(summary.bytes, 4 << 20);
          expect(summary.frames, ((4 << 20) / (61 * 1024 + 7)).ceil());
          expect(summary.plaintextSha256, serverSummary.plaintextSha256);
          expect(summary.cipher, cipher);
        },
      );

      test('a flipped byte on the wire is rejected by both sides', () async {
        final serverSide = server.first.then(e2e.handle);
        final client = E2eClient(
          pinnedServerKey: identity.publicKey,
          cipher: cipher,
          totalBytes: 512 * 1024,
          frameSize: 64 * 1024,
          tamperFrame: 2,
          log: (_) {},
        ).run(await connect());
        await expectLater(serverSide, throwsA(isA<AuthenticationException>()));
        await expectLater(client, throwsA(anything));
      });

      test('a wrong pinned server key aborts the handshake', () async {
        final serverSide = server.first
            .then(e2e.handle)
            .then<void>((_) {}, onError: (Object _) {});
        await expectLater(
          E2eClient(
            pinnedServerKey: ServerIdentity.generate().publicKey,
            cipher: cipher,
            totalBytes: 1024,
            frameSize: 1024,
            log: (_) {},
          ).run(await connect()),
          throwsA(isA<HandshakeException>()),
        );
        await serverSide; // server sees the client go away; must not hang
      });
    });
  }

  group('record layer', () {
    test('sequence enforcement rejects replay', () {
      final keys = SessionKeys.derive(
        RecordCipher.gcm,
        List.filled(32, 1),
        List.filled(32, 2),
        List.filled(32, 3),
      );
      final w = RecordWriter(RecordCipher.gcm, keys.clientToServer);
      final r = RecordReader(RecordCipher.gcm, keys.clientToServer);
      final f0 = w.seal(FrameType.data, [1, 2, 3]);
      final f1 = w.seal(FrameType.data, [4, 5, 6]);
      FrameHeader h(Uint8List f) =>
          FrameHeader.decode(Uint8List.sublistView(f, 0, headerLength));
      expect(r.open(h(f0), f0.sublist(headerLength)), [1, 2, 3]);
      expect(
        () => r.open(h(f0), f0.sublist(headerLength)),
        throwsA(isA<AuthenticationException>()),
        reason: 'replay',
      );
      expect(r.open(h(f1), f1.sublist(headerLength)), [4, 5, 6]);
    });

    test('same inputs derive the same keys; different transcript differs', () {
      final a = SessionKeys.derive(RecordCipher.ctr, [1], [2], [3]);
      final b = SessionKeys.derive(RecordCipher.ctr, [1], [2], [3]);
      final c = SessionKeys.derive(RecordCipher.ctr, [1], [2], [4]);
      expect(a.clientToServer.key, b.clientToServer.key);
      expect(a.clientToServer.key, isNot(equals(c.clientToServer.key)));
      expect(a.clientToServer.key, isNot(equals(a.serverToClient.key)));
    });
  });

  test('parseSize and formatting', () {
    expect(parseSize('64K'), 65536);
    expect(parseSize('100M'), 100 << 20);
    expect(parseSize('2g'), 2 << 30);
    expect(parseSize('123'), 123);
    expect(() => parseSize('1x'), throwsFormatException);
    expect(formatBytes(1 << 20), '1.0 MBytes');
    expect(formatRate(125000000, const Duration(seconds: 1)), '1.00 Gbits/sec');
  });
}
