# openssl3_e2e

An end-to-end test for `package:openssl3` in the spirit of iperf3: a client
streams authenticated-encrypted data to a server over TCP and both sides report
throughput.

What one run exercises:

- **Handshake**: X25519 and ML-KEM-768 (hybrid), transcript hashed with SHA-256,
  signed by the server's ML-DSA-65 identity, verified against a pinned key,
  session keys via HKDF-SHA256.
- **Record layer**: `gcm` (AES-256-GCM, counter nonces, frame header as AAD) or
  `ctr` (AES-256-CTR plus HMAC-SHA256, the NoPorts shape). Sequence numbers are
  enforced, so replay, reordering, truncation and bit flips all fail.
- **Verification**: both sides hash the plaintext; the server returns a signed
  summary and the client checks it.

```sh
# one process, both ciphers, plus tamper and wrong-key checks
dart run bin/openssl3_e2e.dart selftest --bytes 256M

# two machines
openssl3_e2e server --port 15201            # prints its public key
openssl3_e2e client --host <server> --server-key <hex> --bytes 1G --cipher gcm
openssl3_e2e client --host <server> --server-key <hex> --tamper 5   # must fail
```

Build a standalone bundle with `dart build cli`; the library ships in
`bundle/lib/`. Inside this repository the hook takes it from `../../out`.
Typical numbers on an Apple M-series laptop over loopback: about 2 Gbit/s with
GCM and 1.8 Gbit/s with CTR+HMAC at 64 KB frames, single-threaded Dart.
