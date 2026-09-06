# 0004 — Linux/musl toolchains mirror OpenSSL's own CI

Status: Accepted (2026-09-06)

## Context
Options for Linux glibc x64/arm64/riscv64 and musl x64/arm64: Zig (`zig cc`, pinned glibc floor,
one toolchain), or the gcc-based setup the OpenSSL project uses in its own CI
(`cross-compiles.yml`: Debian `gcc-<triple>` + `qemu-user`; `os-zoo.yml`: `alpine` container;
`windows.yml`: MSVC + NASM). `package:sqlite3` also uses apt cross-gcc.

## Decision
Use what OpenSSL uses: native gcc on `ubuntu-24.04` and `ubuntu-24.04-arm`,
`gcc-riscv64-linux-gnu` with `--cross-compile-prefix`, `alpine:3.20` containers for musl, MSVC
with NASM on Windows. No glibc floor pin: the runner image's glibc is the minimum, recorded in
the release manifest. Maintainer decision: only current distributions need support.

## Consequences
- Most-travelled path for OpenSSL itself; fewer surprises with assembly and Configure.
- Users on older glibc need `local_build` or `url_pattern`; Zig is documented as the fallback if
  a floor requirement appears.
