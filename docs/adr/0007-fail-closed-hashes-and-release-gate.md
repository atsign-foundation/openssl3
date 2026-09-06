# 0007 — Fail-closed hashing and the release-PR gate

Status: Accepted (2026-09-06)

## Context
The hook must never load bytes it cannot verify, and hashes must never be typed by hand.

## Decision
`lib/src/manifest.dart` (generated) is the only source of truth and is compiled into the package.
A sha256 mismatch throws; there is no fallback. `release.yml` builds all natives, creates a draft
release, regenerates `manifest.dart` and opens a PR; a check on that PR's merge asserts the file
matches the release exactly (sqlite3's `write_asset_hashes.dart --assert` idea), runs
`dart pub publish --dry-run`, and moves the tag. Publishing to pub.dev is a manual step by the
maintainer.

## Consequences
- Two-step releases; documented in CONTRIBUTING.md.
- `local_path` is also verified unless `local_path_unverified: true` is set explicitly.
