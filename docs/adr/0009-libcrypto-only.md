# 0009 — libcrypto only, no libssl

Status: Accepted (2026-09-06)

## Context
at_chops and NoPorts need EVP-level crypto (AES-GCM/CTR, X25519, ML-KEM-768, ML-DSA-65, hashing),
not TLS. libssl would roughly double the shipped size and the binding surface.

## Decision
Build and bind libcrypto only. libssl can be added later as a second code asset
(`libopenssl_assets_ssl`) with its own header set without breaking the existing asset id.

## Consequences
- No `SSL_*` symbols; `ssl.h`, `tls1.h`, `quic.h` and friends are excluded from bindings.
