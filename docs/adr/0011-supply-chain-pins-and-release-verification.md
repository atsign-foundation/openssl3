# 0011 — Supply-chain pins and release verification

Status: Accepted (2026-09-07)

## Context
ADR-0007 makes the hook refuse any byte whose sha256 is not compiled into the package. That
pins *what was released*, not *how it was produced*: a third-party action or base image
swapped under a floating tag would build a bad binary whose hash we would then pin faithfully.
Provenance attestations were being produced but nothing consumed them, and the upstream
tarball hash recorded for `local_build` was checked only against a checksum served next to it.

## Decision
- Every third-party action is pinned to a commit SHA (version in a trailing comment, so
  Dependabot keeps bumping it). The Docker images that compile shipped binaries are pinned by
  digest; images that merely consume the package in `verify.yml` keep floating on purpose.
- `release-check` runs `gh attestation verify` on every downloaded asset, requiring the signer
  workflow `build-natives.yml` of this repository at `refs/tags/<tag>`, before hashes are
  asserted or the tag is moved. Sidecar JSON files are attested too, so the whole download is
  covered.
- The upstream tarball is accepted only if (1) it matches the published checksum, (2) its
  detached PGP signature verifies against a key whose primary fingerprint appears in the pinned
  source tree's own `doc/fingerprints.txt` (keys fetched from openssl-library.org, a different
  origin from the tarball, with keyserver.ubuntu.com as fallback), and (3) it is byte-for-byte
  identical to `git archive --worktree-attributes` of the pinned submodule commit, which is how
  upstream's `util/mktar.sh` produces it.
- Binaries carry compiler hardening where the toolchain does not default to it:
  `-fstack-protector-strong -D_FORTIFY_SOURCE=2` on glibc and musl, `/guard:cf` on MSVC.
  `verify.dart` fails the build if the resulting `__stack_chk_fail` import or Control Flow
  Guard header flag is absent.

## Consequences
- A release now fails if openssl-library.org and keyserver.ubuntu.com are both unreachable, or
  if upstream changes how tarballs are cut. Both are worth a failed release rather than a guess.
- SHA pins make workflow diffs noisier; Dependabot PRs carry the version comment so review stays
  readable.
- Refreshing an image digest is a one-line manual edit (`docker buildx imagetools inspect`).
