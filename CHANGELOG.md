# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Other

- docs(readme): correct PING envelope type
- docs(repo): document .worktrees location for git worktrees
- feat(dn): add peerlist feature advertisement
- fix(dn): validate feature names in peerlist flow
- chore(arti): upgrade Arti deps and tighten operator guidance
- ci(github): add workspace CI workflow
- ci(arti): extend CI coverage beyond compile checks

## [0.2.0-alpha] - 2026-04-08

### Added

- Add handshake edge-case integration tests and reject directory peers

### Changed

- Migrate repository references to joinmarket-rs organisation

### Other

- docs: revise README and AGENTS.md for accuracy; add MIT LICENSE
- router: dual broadcast channel to route offer pubmsgs to takers only
- heartbeat: improve liveness probing strategy
- peer: refine !orderbook rate limiting strategy
- security: harden input parsing, fix clippy, add deny/audit tooling
- security: unified peer cap, random shard hasher, secp256k1 upgrade, remove dead code
- deps: upgrade metrics-exporter-prometheus 0.13 -> 0.15
- security: fix TOCTOU in admit_peer, validate hostname file, fix metrics registry
- deps: bump base64 0.21->0.22, fix bond endianness, clear stale audit suppressions
- docs(agents): add release process using git-cliff
- revert: remove dual broadcast channel system
- fix: drop unused msg param from dispatch_pubmsg
- fix(dn): harden admission, fix race conditions, and improve correctness
- fix(dn): increase peer channel capacity and distinguish drop reasons
- fix(dn): harden peer lifecycle, routing, and admission correctness
- chore(release): prepare v0.2.0-alpha
- fix(ci): bundle libsqlite3-sys for arti cross-compilation and allow workflow_dispatch

### Removed

- remove nick-sig validation from handshake

## [0.1.0-alpha.1] - 2026-03-31

### Added

- Add git-cliff for automated release notes
- Add unreleased changelog entries for recent changes

### Changed

- Align wire protocol commands with Python JoinMarket for compatibility
- Update changelog for v0.1.0-alpha.1 release

### Other

- Sync documentation with codebase and update .gitignore

### Removed

- Remove connection and maker registration rate limits

## [0.1.0-alpha] - 2026-03-24

### Added

- Add arti variant to release build matrix
- Bundle libsqlite3-sys for cross-platform arti builds
- Add SQLite dev library installation for arti CI builds
- Bundle SQLite for arti builds to eliminate system dependency

### Changed

- Update dependencies and migrate xsalsa20poly1305 to crypto_secretbox

### Other

- initial commit
- Clarify PoW documentation for tordaemon vs arti backends

### Removed

- Remove unused dependencies and sync docs with codebase

### Reverted

- Revert "Bundle libsqlite3-sys for cross-platform arti builds"

