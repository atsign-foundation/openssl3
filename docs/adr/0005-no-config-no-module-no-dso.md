# 0005 — `--openssldir` nowhere, `no-module no-dso`, `initNoConfig()`

Status: Accepted (2026-09-06)

## Context
A stock libcrypto reads `openssl.cnf` from `OPENSSLDIR` and may `dlopen` provider modules from
`MODULESDIR`. Both make behaviour depend on the host filesystem, which defeats the point of a
bundled library and is a code-loading surface in mobile sandboxes.

## Decision
Build with `no-module no-dso no-legacy no-engine` (default provider compiled in, nothing loaded
from disk) and `--openssldir=/nonexistent/openssl3`. Expose `initNoConfig()` which calls
`OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG | …)`; README tells consumers to call it once.

## Consequences
- Identical algorithm set everywhere; no FIPS module, no legacy provider (ADR-0008 Q11).
- `OPENSSL_CONF` env var is ignored by design.
