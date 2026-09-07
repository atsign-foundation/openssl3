// iperf3-style end-to-end test for package:openssl3.
//
//   openssl3_e2e server [--port 15201] [--bind 0.0.0.0] [--once] [--seed HEX]
//   openssl3_e2e client --host H [--port 15201] --server-key HEX
//                       [--bytes 100M] [--frame 64K] [--cipher gcm|ctr] [--tamper N]
//   openssl3_e2e selftest [--bytes 32M] [--frame 64K] [--cipher gcm|ctr]
//
// The server prints its ML-DSA-65 public key (hex) and fingerprint on start;
// pass the key to the client with --server-key. `selftest` runs both ends in
// one process on a loopback port, for both ciphers, and also proves that a
// tampered frame and a wrong server key are rejected. Exit code 0 means every
// check passed.
import 'dart:io';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:openssl3/openssl3.dart' show OpenSSLCapabilities, initNoConfig;
import 'package:openssl3_e2e/e2e.dart';

Future<void> main(List<String> args) async {
  final parser = ArgParser()
    ..addCommand(
      'server',
      ArgParser()
        ..addOption('port', defaultsTo: '15201')
        ..addOption('bind', defaultsTo: '0.0.0.0')
        ..addOption(
          'seed',
          help: 'ML-DSA-65 identity seed (32 bytes hex); random if omitted',
        )
        ..addFlag('once', negatable: false, help: 'Exit after one transfer'),
    )
    ..addCommand(
      'client',
      ArgParser()
        ..addOption('host', defaultsTo: '127.0.0.1')
        ..addOption('port', defaultsTo: '15201')
        ..addOption(
          'server-key',
          help: 'Server ML-DSA-65 public key (hex), as printed by the server',
        )
        ..addOption('bytes', defaultsTo: '100M')
        ..addOption('frame', defaultsTo: '64K')
        ..addOption('cipher', defaultsTo: 'gcm', allowed: ['gcm', 'ctr'])
        ..addOption(
          'tamper',
          help: 'Flip a byte in data frame N (expect failure)',
        ),
    )
    ..addCommand(
      'selftest',
      ArgParser()
        ..addOption('bytes', defaultsTo: '32M')
        ..addOption('frame', defaultsTo: '64K')
        ..addOption('cipher', help: 'gcm or ctr; both when omitted'),
    )
    ..addFlag('help', abbr: 'h', negatable: false);

  final ArgResults opts;
  try {
    opts = parser.parse(args);
  } on FormatException catch (e) {
    stderr.writeln(e.message);
    _usage(parser);
    exit(64);
  }
  final cmd = opts.command;
  if (opts.flag('help') || cmd == null) {
    _usage(parser);
    exit(cmd == null ? 64 : 0);
  }

  initNoConfig();
  final caps = OpenSSLCapabilities.instance;
  stdout.writeln(
    '${caps.versionString} (${caps.buildInfo?['target'] ?? 'system libcrypto'})',
  );

  switch (cmd.name) {
    case 'server':
      await _server(cmd);
    case 'client':
      await _client(cmd);
    case 'selftest':
      await _selftestCommand(cmd);
  }
}

Future<void> _server(ArgResults cmd) async {
  final identity = cmd.option('seed') == null
      ? ServerIdentity.generate()
      : ServerIdentity.fromSeed(_unhex(cmd.option('seed')!));
  final server = await ServerSocket.bind(
    cmd.option('bind')!,
    int.parse(cmd.option('port')!),
  );
  stdout.writeln('server: public key ${_hex(identity.publicKey)}');
  try {
    await E2eServer(
      identity,
      log: stdout.writeln,
    ).serve(server, once: cmd.flag('once'));
  } catch (e) {
    // Only reachable with --once; a long-running server logs and carries on.
    stderr.writeln('server: FAIL $e');
    exit(1);
  } finally {
    await server.close();
  }
}

Future<void> _client(ArgResults cmd) async {
  final key = cmd.option('server-key');
  if (key == null) {
    stderr.writeln('--server-key is required (the server prints it)');
    exit(64);
  }
  final socket = await Socket.connect(
    cmd.option('host')!,
    int.parse(cmd.option('port')!),
  );
  final tamper = cmd.option('tamper');
  try {
    final summary = await E2eClient(
      pinnedServerKey: _unhex(key),
      cipher: RecordCipher.parse(cmd.option('cipher')!),
      totalBytes: parseSize(cmd.option('bytes')!),
      frameSize: parseSize(cmd.option('frame')!),
      tamperFrame: tamper == null ? null : int.parse(tamper),
      log: stdout.writeln,
    ).run(socket);
    if (tamper != null) {
      stderr.writeln('FAIL: tampered transfer was accepted: $summary');
      exit(1);
    }
    stdout.writeln('PASS: $summary');
  } catch (e) {
    if (tamper != null) {
      stdout.writeln('PASS: tampered frame rejected ($e)');
      return;
    }
    stderr.writeln('FAIL: $e');
    exit(1);
  }
}

Future<void> _selftestCommand(ArgResults cmd) async {
  final bytes = parseSize(cmd.option('bytes')!);
  final frame = parseSize(cmd.option('frame')!);
  final ciphers = cmd.option('cipher') == null
      ? RecordCipher.values
      : [RecordCipher.parse(cmd.option('cipher')!)];
  var failures = 0;
  for (final cipher in ciphers) {
    if (!await _selftest(cipher, bytes, frame)) failures++;
  }
  if (failures > 0) {
    stderr.writeln('$failures selftest(s) FAILED');
    exit(1);
  }
  stdout.writeln('selftest: all passed');
}

Future<bool> _selftest(RecordCipher cipher, int bytes, int frame) async {
  stdout.writeln(
    '--- selftest ${cipher.name}: ${formatBytes(bytes)} in '
    '${formatBytes(frame)} frames',
  );
  final identity = ServerIdentity.generate();
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  // Broadcast so several sequential accepts work. Each accept future is armed
  // BEFORE its client connects; awaiting the accept first would deadlock.
  final incoming = server.asBroadcastStream();
  void log(String s) => stdout.writeln('  $s');
  final e2eServer = E2eServer(identity, log: log);
  try {
    // 1. Honest transfer.
    final serverDone = incoming.first.then(e2eServer.handle);
    final summary = await E2eClient(
      pinnedServerKey: identity.publicKey,
      cipher: cipher,
      totalBytes: bytes,
      frameSize: frame,
      log: log,
    ).run(await Socket.connect(server.address, server.port));
    await serverDone;
    stdout.writeln('  PASS transfer: $summary');

    // 2. A tampered frame must be rejected by the server and seen by the client.
    final tamperedServer = incoming.first
        .then(e2eServer.handle)
        .then((_) => false, onError: (Object _) => true);
    final tamperedClient =
        E2eClient(
              pinnedServerKey: identity.publicKey,
              cipher: cipher,
              totalBytes: 8 * frame,
              frameSize: frame,
              tamperFrame: 3,
              log: (_) {},
            )
            .run(await Socket.connect(server.address, server.port))
            .then((_) => false, onError: (Object _) => true);
    final rejected = await tamperedServer && await tamperedClient;
    stdout.writeln(
      rejected
          ? '  PASS tamper: rejected by server, client saw the failure'
          : '  FAIL tamper: tampered frame was accepted',
    );

    // 3. A wrong pinned server key must abort the handshake.
    final wrongKeyServer = incoming.first
        .then(e2eServer.handle)
        .then((_) => false, onError: (Object _) => true);
    final wrongKey =
        await E2eClient(
              pinnedServerKey: ServerIdentity.generate().publicKey,
              cipher: cipher,
              totalBytes: frame,
              frameSize: frame,
              log: (_) {},
            )
            .run(await Socket.connect(server.address, server.port))
            .then((_) => false, onError: (Object e) => e is HandshakeException);
    await wrongKeyServer;
    stdout.writeln(
      wrongKey
          ? '  PASS identity: wrong server key rejected'
          : '  FAIL identity: wrong server key accepted',
    );
    return rejected && wrongKey;
  } finally {
    await server.close();
  }
}

void _usage(ArgParser p) {
  stdout.writeln('Usage: openssl3_e2e <server|client|selftest> [options]\n');
  for (final c in p.commands.entries) {
    stdout.writeln('${c.key}:\n${c.value.usage}\n');
  }
}

Uint8List _unhex(String s) {
  final t = s.replaceAll(RegExp(r'\s'), '');
  return Uint8List.fromList([
    for (var i = 0; i < t.length; i += 2)
      int.parse(t.substring(i, i + 2), radix: 16),
  ]);
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
