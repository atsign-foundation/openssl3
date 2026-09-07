# 0004 — Linux/musl toolchains mirror OpenSSL's own CI

Status: Accepted (2026-09-06)

## Context
Options for Linux glibc x64/arm64/riscv64 and musl x64/arm64: Zig (`zig cc`, pinned glibc floor,
one toolchain), or the gcc-based setup the OpenSSL project uses in its own CI
(`cross-compiles.yml`: Debian `gcc-<triple>` + `qemu-user`; `os-zoo.yml`: `alpine` container;
`windows.yml`: MSVC + NASM). `package:sqlite3` also uses apt cross-gcc.

## Decision
Use what OpenSSL uses: gcc, with the x64/arm64 glibc builds running inside `manylinux_2_28`
containers (glibc 2.28 floor, the images the Python ecosystem uses for portable Linux
binaries; the first Ubuntu 24.04-built library needed GLIBC_2.38 and did not load on Debian 12), `gcc-riscv64-linux-gnu` and `gcc-arm-linux-gnueabihf` (the latter inside `ubuntu:22.04` for a glibc 2.35 floor) with `--cross-compile-prefix`, `alpine:3.20`
containers for musl, MSVC with NASM on Windows. Containers are driven from the host by the Dart
tooling (`--docker`), since the Dart SDK is glibc-only and would not run in Alpine anyway.

## Consequences
- Most-travelled path for OpenSSL itself; fewer surprises with assembly and Configure.
- Users on older glibc need `local_build` or `url_pattern`; Zig is documented as the fallback if
  a floor requirement appears.
