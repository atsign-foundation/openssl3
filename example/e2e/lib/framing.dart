/// Wire framing for the e2e protocol.
///
/// Every message is `header || payload` with a 13-byte big-endian header:
///
///     u8  type      (see [FrameType])
///     u64 sequence  (per direction, starts at 0, never repeats)
///     u32 length    (payload bytes)
///
/// The header doubles as AEAD associated data, so a frame cannot be reordered,
/// truncated or retyped without failing authentication.
library;

import 'dart:async';
import 'dart:typed_data';

abstract final class FrameType {
  static const int clientHello = 0x01;
  static const int serverHello = 0x02;
  static const int data = 0x10;
  static const int finish = 0x11;
  static const int summary = 0x20;
}

const int headerLength = 13;

/// Largest payload accepted on the wire (plaintext frames are far smaller).
const int maxPayload = 4 * 1024 * 1024;

Uint8List encodeHeader(int type, int sequence, int length) {
  final b = ByteData(headerLength);
  b.setUint8(0, type);
  b.setUint64(1, sequence);
  b.setUint32(9, length);
  return b.buffer.asUint8List();
}

final class FrameHeader {
  final int type;
  final int sequence;
  final int length;
  final Uint8List bytes;
  const FrameHeader(this.type, this.sequence, this.length, this.bytes);

  static FrameHeader decode(Uint8List bytes) {
    final b = ByteData.sublistView(bytes);
    return FrameHeader(b.getUint8(0), b.getUint64(1), b.getUint32(9), bytes);
  }
}

/// Reads exact byte counts from a stream of chunks, with a bounded buffer.
final class ByteReader {
  final StreamSubscription<List<int>> _sub;
  final List<Uint8List> _chunks = [];
  int _buffered = 0;
  int _offset = 0; // into _chunks.first
  Completer<void>? _wakeup;
  bool _done = false;
  Object? _error;

  ByteReader(Stream<List<int>> stream)
    : _sub = stream.listen(null, cancelOnError: true) {
    _sub
      ..onData((chunk) {
        _chunks.add(chunk is Uint8List ? chunk : Uint8List.fromList(chunk));
        _buffered += chunk.length;
        if (_buffered > 8 * maxPayload) _sub.pause();
        _wake();
      })
      ..onError((Object e) {
        _error = e;
        _done = true;
        _wake();
      })
      ..onDone(() {
        _done = true;
        _wake();
      });
  }

  void _wake() {
    final w = _wakeup;
    if (w != null && !w.isCompleted) w.complete();
  }

  /// Reads exactly [n] bytes, or throws [StateError] on a short stream.
  Future<Uint8List> read(int n) async {
    while (_buffered < n) {
      if (_error != null) throw _error!;
      if (_done) {
        throw StateError('connection closed (needed $n bytes, had $_buffered)');
      }
      final w = _wakeup = Completer<void>();
      await w.future;
    }
    final out = Uint8List(n);
    var written = 0;
    while (written < n) {
      final chunk = _chunks.first;
      final avail = chunk.length - _offset;
      final take = avail < n - written ? avail : n - written;
      out.setRange(written, written + take, chunk, _offset);
      written += take;
      _offset += take;
      if (_offset == chunk.length) {
        _chunks.removeAt(0);
        _offset = 0;
      }
    }
    _buffered -= n;
    if (_sub.isPaused && _buffered < 4 * maxPayload) _sub.resume();
    return out;
  }

  Future<FrameHeader> readHeader() async =>
      FrameHeader.decode(await read(headerLength));

  Future<void> cancel() => _sub.cancel();
}

/// Parses sizes like `64K`, `100M`, `2G` (powers of 1024) or plain bytes.
int parseSize(String s) {
  final m = RegExp(r'^(\d+)([kKmMgG]?)$').firstMatch(s.trim());
  if (m == null) throw FormatException('bad size', s);
  final n = int.parse(m[1]!);
  return switch (m[2]!.toLowerCase()) {
    'k' => n << 10,
    'm' => n << 20,
    'g' => n << 30,
    _ => n,
  };
}

String formatBytes(int bytes) {
  if (bytes >= 1 << 30) {
    return '${(bytes / (1 << 30)).toStringAsFixed(2)} GBytes';
  }
  if (bytes >= 1 << 20) {
    return '${(bytes / (1 << 20)).toStringAsFixed(1)} MBytes';
  }
  if (bytes >= 1 << 10) {
    return '${(bytes / (1 << 10)).toStringAsFixed(1)} KBytes';
  }
  return '$bytes Bytes';
}

String formatRate(int bytes, Duration d) {
  final secs = d.inMicroseconds / 1e6;
  if (secs <= 0) return '-';
  final mbits = bytes * 8 / 1e6 / secs;
  return mbits >= 1000
      ? '${(mbits / 1000).toStringAsFixed(2)} Gbits/sec'
      : '${mbits.toStringAsFixed(0)} Mbits/sec';
}
