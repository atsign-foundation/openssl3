/// Server and client of the iperf3-style end-to-end test.
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:openssl3/evp.dart';

import 'framing.dart';
import 'session.dart';

export 'framing.dart' show formatBytes, formatRate, parseSize;
export 'session.dart' show RecordCipher, ServerIdentity, HandshakeException;

/// One reporting interval, iperf3 style.
final class Interval {
  final Duration start;
  final Duration end;
  final int bytes;
  const Interval(this.start, this.end, this.bytes);

  @override
  String toString() {
    String s(Duration d) =>
        (d.inMilliseconds / 1000).toStringAsFixed(1).padLeft(5);
    return '[${s(start)}-${s(end)} sec]  ${formatBytes(bytes).padLeft(13)}  '
        '${formatRate(bytes, end - start).padLeft(14)}';
  }
}

/// Final result agreed by both sides.
final class TransferSummary {
  final int bytes;
  final int frames;
  final Duration duration;
  final Uint8List plaintextSha256;
  final RecordCipher cipher;
  const TransferSummary({
    required this.bytes,
    required this.frames,
    required this.duration,
    required this.plaintextSha256,
    required this.cipher,
  });

  String get rate => formatRate(bytes, duration);

  @override
  String toString() =>
      '${formatBytes(bytes)} in $frames frames over '
      '${(duration.inMilliseconds / 1000).toStringAsFixed(2)} s = $rate '
      '(${cipher.name}, sha256 ${_hex(plaintextSha256).substring(0, 16)}…)';
}

/// `finish` payload: u64 bytes || u64 frames || sha256(32).
Uint8List _encodeFinish(int bytes, int frames, Uint8List sha) {
  final b = ByteData(16);
  b.setUint64(0, bytes);
  b.setUint64(8, frames);
  return Uint8List.fromList([...b.buffer.asUint8List(), ...sha]);
}

/// `summary` payload: u8 ok || u64 bytes || u64 frames || u64 micros ||
/// sha256(32), followed by the server identity's ML-DSA-65 signature over it.
Uint8List _encodeSummary(bool ok, TransferSummary s, ServerIdentity id) {
  final b = ByteData(25);
  b.setUint8(0, ok ? 1 : 0);
  b.setUint64(1, s.bytes);
  b.setUint64(9, s.frames);
  b.setUint64(17, s.duration.inMicroseconds);
  final body = Uint8List.fromList([
    ...b.buffer.asUint8List(),
    ...s.plaintextSha256,
  ]);
  return Uint8List.fromList([
    ...body,
    ...MlDsa65.sign(id.keyPair.privateKey, body),
  ]);
}

final class E2eServer {
  final ServerIdentity identity;
  final void Function(String) log;
  final Duration interval;

  E2eServer(
    this.identity, {
    this.log = print,
    this.interval = const Duration(seconds: 1),
  });

  /// Handles one connection to completion. Returns the verified summary, or
  /// throws (and closes the socket) on any protocol or authentication error.
  Future<TransferSummary> handle(Socket socket) async {
    socket.setOption(SocketOption.tcpNoDelay, true);
    final reader = ByteReader(socket);
    try {
      // Handshake.
      final h = await reader.readHeader();
      if (h.type != FrameType.clientHello || h.length > maxPayload) {
        throw const FormatException('expected ClientHello');
      }
      final hello = ClientHello.decode(await reader.read(h.length));
      final (serverHello, keys) = serverHandshake(hello, identity);
      final sh = serverHello.encode();
      socket.add(encodeHeader(FrameType.serverHello, 0, sh.length));
      socket.add(sh);
      await socket.flush();

      final rx = RecordReader(keys.cipher, keys.clientToServer);
      final tx = RecordWriter(keys.cipher, keys.serverToClient);
      final digest = Digest.sha256.start();
      final clock = Stopwatch()..start();
      var bytes = 0, frames = 0, intervalBytes = 0;
      var intervalStart = Duration.zero;

      while (true) {
        final fh = await reader.readHeader();
        if (fh.length > maxPayload) {
          throw const FormatException('frame too large');
        }
        final plain = rx.open(fh, await reader.read(fh.length));
        if (fh.type == FrameType.data) {
          digest.update(plain);
          bytes += plain.length;
          frames++;
          intervalBytes += plain.length;
          if (clock.elapsed - intervalStart >= interval) {
            log(
              Interval(intervalStart, clock.elapsed, intervalBytes).toString(),
            );
            intervalStart = clock.elapsed;
            intervalBytes = 0;
          }
          continue;
        }
        if (fh.type != FrameType.finish) {
          throw FormatException('unexpected frame type ${fh.type}');
        }
        clock.stop();
        if (intervalBytes > 0) {
          log(Interval(intervalStart, clock.elapsed, intervalBytes).toString());
        }
        final fin = ByteData.sublistView(plain);
        final theirBytes = fin.getUint64(0);
        final theirFrames = fin.getUint64(8);
        final theirSha = plain.sublist(16, 48);
        final ourSha = digest.finish();
        final ok =
            theirBytes == bytes &&
            theirFrames == frames &&
            constantTimeEq(theirSha, ourSha);
        final summary = TransferSummary(
          bytes: bytes,
          frames: frames,
          duration: clock.elapsed,
          plaintextSha256: ourSha,
          cipher: keys.cipher,
        );
        socket.add(
          tx.seal(FrameType.summary, _encodeSummary(ok, summary, identity)),
        );
        await socket.flush();
        log('server: ${ok ? 'OK' : 'MISMATCH'} $summary');
        if (!ok) throw StateError('client and server disagree on the transfer');
        return summary;
      }
    } finally {
      await reader.cancel();
      socket.destroy();
    }
  }

  /// Accepts connections until [once] completes one, or forever.
  Future<void> serve(ServerSocket server, {bool once = false}) async {
    log('server: listening on ${server.address.address}:${server.port}');
    log('server: identity ML-DSA-65 fingerprint ${identity.fingerprint}');
    await for (final socket in server) {
      try {
        await handle(socket);
      } catch (e) {
        log('server: connection failed: $e');
        if (once) rethrow;
      }
      if (once) break;
    }
  }
}

final class E2eClient {
  final Uint8List pinnedServerKey;
  final RecordCipher cipher;
  final int totalBytes;
  final int frameSize;
  final void Function(String) log;
  final Duration interval;

  /// Test hook: flip a byte in this data frame's payload after sealing.
  final int? tamperFrame;

  E2eClient({
    required this.pinnedServerKey,
    this.cipher = RecordCipher.gcm,
    this.totalBytes = 64 << 20,
    this.frameSize = 64 << 10,
    this.log = print,
    this.interval = const Duration(seconds: 1),
    this.tamperFrame,
  });

  Future<TransferSummary> run(Socket socket) async {
    socket.setOption(SocketOption.tcpNoDelay, true);
    final reader = ByteReader(socket);
    try {
      final hs = ClientHandshake(cipher);
      final hello = hs.hello.encode();
      socket.add(encodeHeader(FrameType.clientHello, 0, hello.length));
      socket.add(hello);
      await socket.flush();
      final sh = await reader.readHeader();
      if (sh.type != FrameType.serverHello || sh.length > maxPayload) {
        throw const FormatException('expected ServerHello');
      }
      final keys = hs.complete(
        ServerHello.decode(await reader.read(sh.length)),
        pinnedServerKey,
      );
      log(
        'client: handshake ok (X25519 + ML-KEM-768, ML-DSA-65 signed), '
        'cipher ${cipher.name}',
      );

      final tx = RecordWriter(keys.cipher, keys.clientToServer);
      final rx = RecordReader(keys.cipher, keys.serverToClient);
      final digest = Digest.sha256.start();
      final block = Uint8List(frameSize);
      // Deterministic, incompressible-looking payload (no RNG cost per frame).
      for (var i = 0; i < block.length; i++) {
        block[i] = (i * 2654435761) >> 7 & 0xff;
      }
      final clock = Stopwatch()..start();
      var sent = 0, frames = 0, intervalBytes = 0;
      var intervalStart = Duration.zero;
      while (sent < totalBytes) {
        final n = (totalBytes - sent).clamp(0, frameSize);
        final chunk = n == frameSize
            ? block
            : Uint8List.sublistView(block, 0, n);
        // Vary the first bytes so frames are not identical.
        chunk[0] = frames & 0xff;
        if (n > 1) chunk[1] = (frames >> 8) & 0xff;
        digest.update(chunk);
        final frame = tx.seal(FrameType.data, chunk);
        if (tamperFrame != null && frames == tamperFrame) {
          frame[headerLength + 8] ^= 0x01;
          log('client: TAMPERING with frame $frames on the wire');
        }
        socket.add(frame);
        sent += n;
        frames++;
        intervalBytes += n;
        if (frames % 16 == 0) await socket.flush();
        if (clock.elapsed - intervalStart >= interval) {
          log(Interval(intervalStart, clock.elapsed, intervalBytes).toString());
          intervalStart = clock.elapsed;
          intervalBytes = 0;
        }
      }
      final sha = digest.finish();
      socket.add(tx.seal(FrameType.finish, _encodeFinish(sent, frames, sha)));
      await socket.flush();
      clock.stop();
      if (intervalBytes > 0) {
        log(Interval(intervalStart, clock.elapsed, intervalBytes).toString());
      }

      final rh = await reader.readHeader();
      if (rh.type != FrameType.summary) {
        throw FormatException('expected summary, got ${rh.type}');
      }
      final plain = rx.open(rh, await reader.read(rh.length));
      final body = plain.sublist(0, 57);
      final sig = plain.sublist(57);
      if (!MlDsa65.verify(pinnedServerKey, body, sig)) {
        throw const HandshakeException('summary signature does not verify');
      }
      final b = ByteData.sublistView(body);
      final ok = b.getUint8(0) == 1;
      final summary = TransferSummary(
        bytes: b.getUint64(1),
        frames: b.getUint64(9),
        duration: Duration(microseconds: b.getUint64(17)),
        plaintextSha256: body.sublist(25, 57),
        cipher: keys.cipher,
      );
      final agree =
          ok &&
          summary.bytes == sent &&
          constantTimeEq(summary.plaintextSha256, sha);
      log(
        'client: server says ${ok ? 'OK' : 'MISMATCH'}; local ${formatBytes(sent)} '
        'in ${(clock.elapsed.inMilliseconds / 1000).toStringAsFixed(2)} s = '
        '${formatRate(sent, clock.elapsed)}; ${agree ? 'AGREE' : 'DISAGREE'}',
      );
      if (!agree) {
        throw StateError('client and server disagree on the transfer');
      }
      return summary;
    } finally {
      await reader.cancel();
      socket.destroy();
    }
  }
}

bool constantTimeEq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var d = 0;
  for (var i = 0; i < a.length; i++) {
    d |= a[i] ^ b[i];
  }
  return d == 0;
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
