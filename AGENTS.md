# joinmarket-rs — Agent Guidelines

## What You Are Building

A full Rust rewrite of [JoinMarket](https://github.com/JoinMarket-Org/joinmarket-clientserver),
developed in phases. Each JoinMarket tool is reimplemented as its own statically-linked binary,
sharing common protocol logic via the `joinmarket-core` library crate. Additional tools (yield
generator, coinjoin client, wallet) will follow in later phases as the core library matures.

**Why Rust?** The Python JoinMarket toolchain is hard to install (pip, virtualenvs, native
dependencies) and operationally fragile — especially the directory node, which consumes more memory as connections scale, can leave peers in inconsistent states on unexpected input, and requires ongoing operator attention. A Rust rewrite provides:
- **Single statically-linked binary** — no Python, no pip, no virtualenv. Download and run.
- **Memory-safe and crash-resistant** — no uncaught exceptions, predictable memory use.
- **Designed for scale** — 100k+ concurrent peer connections on a single server.
- **Easy to package** — one file, no runtime dependencies, works on any modern Linux/macOS/Windows.

**Current focus: `joinmarket-dn` (directory node)** — the first program in the suite. A pure-Rust
reimplementation of `start-dn.py` that is fully wire-compatible with existing Python JoinMarket
clients. It can embed Tor via Arti (no external `tor` daemon required).

**What the directory node does:**
- Registers itself as a Tor hidden service on port 5222
- Accepts inbound TCP connections from JoinMarket maker and taker peers over Tor
- Performs a JSON handshake with each peer and maintains a nick → onion registry
- Relays public messages (offers like `!sw0absoffer`, `!orderbook`, etc.) by broadcast to all connected peers
- Routes private messages by returning the target peer's onion address (directory does NOT relay private content)
- Responds to `GETPEERLIST` requests with the full maker list (makers only — never takers)
- Requires NO Bitcoin node, NO wallet, NO blockchain access

Full documentation: `docs/architecture.md`, `docs/protocol.md`, `docs/deployment.md`, `docs/development.md`.

---

## Build Commands

```bash
# Default build (C Tor daemon backend)
cargo build --release

# Arti (embedded Tor) backend build
cargo build --release --no-default-features --features joinmarket-dn/arti

# Check compilation without producing artifacts
cargo check --workspace

# Run clippy lints
cargo clippy --workspace -- -D warnings
```

## Test Commands

```bash
# Run all tests across the entire workspace
cargo test --workspace

# Run tests for a specific crate
cargo test -p joinmarket-core
cargo test -p joinmarket-dn

# Run a single test by name (partial match)
cargo test -p joinmarket-core onion::tests::test_valid_v3_address
cargo test -p joinmarket-dn test_maker_registration

# Run integration tests only (single-threaded to avoid port conflicts)
cargo test -p joinmarket-dn --test integration -- --test-threads=1

# Run integration tests on macOS (TMPDIR workaround)
TMPDIR=/private/tmp cargo test -p joinmarket-dn --test integration -- --test-threads=1

# Show test output even for passing tests
cargo test --workspace -- --nocapture
```

**Test layout:**
- Unit tests live in `#[cfg(test)] mod tests { ... }` blocks inside each source file.
- Integration tests live in `crates/joinmarket-dn/tests/integration.rs` and use `MockTorProvider`.
- Fixture data (real JoinMarket wire payloads) lives in `tests/fixtures/`.

---

## Workspace Layout

```
crates/
  joinmarket-core/   # Pure protocol library — no I/O, no async
  joinmarket-tor/    # TorProvider trait + backends (tordaemon | arti), MockTorProvider
  joinmarket-dn/     # Directory node binary + lib (server, router, peer, admission, ...)
docs/                # Architecture, protocol, deployment, development docs
tests/fixtures/      # Reference JoinMarket wire payloads
```

---

## Code Style Guidelines

### Formatting & Linting

- No `.rustfmt.toml` or `.clippy.toml` — use `rustfmt` defaults and `cargo clippy -- -D warnings`.
- Rust edition **2021**; minimum stable toolchain **1.75+**. No nightly features.
- `#![forbid(unsafe_code)]` is declared in `joinmarket-core/src/lib.rs` and
  `joinmarket-dn/src/lib.rs`. **No unsafe code anywhere.**
- **7-argument limit**: clippy enforces `too_many_arguments` (max 7). If a function needs
  more, group the extras into a named struct (e.g. `RateLimitState`, `MessageContext`).
- **Use `.is_some_and(|x| ...)` not `.map_or(false, |x| ...)`** — clippy flags the latter.

### Import Ordering

Group imports in this order, separated by blank lines:
1. `std::` standard library
2. Third-party crates
3. Local crate paths (`crate::`, `super::`, or sibling workspace crates)

```rust
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_util::sync::CancellationToken;

use joinmarket_core::handshake::PeerHandshake;
use crate::router::{MakerInfo, Router};
```

### Naming Conventions

| Item | Convention | Example |
|---|---|---|
| Types, traits, enums | `PascalCase` | `OnionAddress`, `ShardedRegistry` |
| Functions, methods, variables | `snake_case` | `register_maker`, `broadcast_pubmsg` |
| Constants | `SCREAMING_SNAKE_CASE` | `MAX_LINE_LEN`, `BROADCAST_CAPACITY` |
| Modules | `snake_case` | `sybil_guard`, `bond_registry` |
| Feature flags | `snake_case` | `tordaemon`, `arti` |

### Error Handling

**Dual strategy:**
- **`thiserror`** for domain/library error types. Use `#[from]` for automatic conversion.
- **`anyhow`** for application-level error propagation in `main.rs`, `server.rs`, `peer.rs`.

```rust
// Library error type (thiserror)
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("invalid onion address: {0}")]
    InvalidOnionAddress(#[from] crate::onion::OnionServiceAddrError),
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),
}

// Application-level (anyhow)
return Err(anyhow::anyhow!("pubmsg from_nick spoofing attempt"));
```

Never silently swallow errors. On unrecoverable peer errors, break the select loop and let the task exit.

**Always match error enums exhaustively** — never classify errors via `.to_string().contains(...)`.
An exhaustive `match &e { HandshakeError::InvalidOnionAddress(_) => ..., ... }` means the compiler
enforces that any future variant is handled and the correct metric/response is emitted for each case.

### Types — Use These, Not Alternatives

| Prefer | Instead of | Reason |
|---|---|---|
| `Arc<str>` | `String` | Nicks and broadcast payloads in registries are immutable and shared |
| `parking_lot::Mutex` | `std::sync::Mutex` | Lower overhead for sync shard locks |
| `DashMap<Arc<str>, PeerMeta>` | `Mutex<HashMap<...>>` | For concurrent peer metadata |
| `anyhow::Result` | custom error in `main` | Ergonomic top-level error propagation |

### Async Patterns

- Runtime: `#[tokio::main]` with `tokio = { version = "1", features = ["full"] }`.
- Use `tokio::select!` in all event-loop bodies (peer loop, accept loop).
- Use `CancellationToken` (from `tokio-util`) for graceful shutdown; thread it through every spawned task.
- Use `tokio::task::JoinSet` to track peer task lifetimes in the accept loop.
- Spawn blocking work with `tokio::task::spawn_blocking`; do not block the async runtime.
- Use `parking_lot::Mutex` (not `tokio::sync::Mutex`) for synchronous shard locks — they are held only for brief HashMap operations.

### Module Organization

- `lib.rs` is the crate root and only declares `pub mod` entries — no logic lives there.
- Each module is self-contained: its own types, error types, and `#[cfg(test)] mod tests`.
- No re-exports at the crate level; consumers explicitly import from submodules.

---

## Critical Behavioral Rules

These rules are invariants. Do not deviate from them.

### No `assert!` / `unwrap()` / `expect()` on Peer-Supplied Data

A panic inside an async peer task propagates as SIGABRT and kills the entire server process.
Always return `Err(...)` instead:

```rust
// WRONG — panics the process if an attacker sends malformed input:
assert_eq!(decoded.len(), 35, "...");

// RIGHT — returns a typed error; the caller disconnects the peer:
if decoded.len() != 35 {
    return Err(OnionAddressError::InvalidBase32(
        format!("expected 35 decoded bytes, got {}", decoded.len()),
    ));
}
```

This applies anywhere untrusted bytes pass through: `OnionAddress::parse`, `PeerHandshake::parse_json`,
`OnionEnvelope::parse`, fidelity bond parsing, etc. `expect()` is acceptable only on
values that are already validated or are program-internal invariants.

### Onion Address Validation

`OnionServiceAddr::parse()` must be called at **every** point an onion address enters the system:

1. **Handshake `location-string`** — parse immediately after JSON deserialisation, before any registry
   lookup. On failure: close connection immediately (no error response), increment
   `jm_admission_invalid_onion_total`.
2. **`MakerInfo.onion_address`** — store as `OnionServiceAddr`, never `String`.
3. **`TakerInfo.onion_address`** — store as `Option<OnionServiceAddr>`. `None` for takers without a
   hidden service; any present value must be valid.
4. **`SybilGuard` keys** — key by `OnionAddress` (host only, no port). Prevents port-variation sybil bypass.
5. **`config.rs` `directory_nodes`** — parse at startup; abort process on any invalid entry.

### Peer Classification

- `location-string` **empty** → Taker
- `location-string` **non-empty and valid** → Maker
- `location-string` **non-empty but invalid** → disconnect immediately; register as neither

### Message Framing

- Messages are `\n`-terminated. Use the custom `read_line_bounded()` helper (not bare `.lines()`).
- Maximum line length: **40,000 bytes** (matches Python JoinMarket's `MAX_LENGTH`). Disconnect peers that exceed this.
- Handshake timeout: **10 seconds**. Disconnect peers that do not complete handshake in time.

### Router Separation

`GETPEERLIST` (envelope type 791) returns **ONLY** the makers registry — never takers. Takers are
transient and must never appear in `PEERLIST` responses. Note: `GETPEERLIST` and `PEERLIST` are
envelope-level message types (integer discriminators), not `!`-prefixed JoinMarket commands.

### Allocation Rules

- Use **4 KB** `BufReader`/`BufWriter` (not the Tokio default 8 KB). JoinMarket messages are always under 2 KB.
- Use **`Arc<str>`** not `String` for nicks and broadcast payloads stored in the registry.
- Use **`ShardedRegistry<T>`** (64 `parking_lot::Mutex<HashMap<Arc<str>, T>>` shards) for maker/taker registries. Each registry holds its own `RandomState` seeded at construction; `shard_for` takes `&self` and uses `BuildHasher::hash_one()`. **Never use `DefaultHasher::new()`** — it is deterministic and allows an attacker to craft nicks that all land on one shard.
- Use **`DashMap<Arc<str>, PeerMeta>`** for peer metadata.
- Broadcast channel capacity: **256**. Peers that lag are disconnected with `RecvError::Lagged`.

### Tor Backend Feature Flags

`tordaemon` and `arti` features are mutually exclusive — a `compile_error!` enforces this. Never
enable both simultaneously. The default is `tordaemon`.

---

## Creating a Release

When tagging a new release, use **git-cliff** to generate the release notes and create the tag in one step:

```bash
# Let git-cliff auto-bump the version based on commit types (feat → minor, fix → patch, breaking → major)
git cliff --bump --output CHANGELOG.md
git add CHANGELOG.md
git commit -m "chore(release): prepare $(git cliff --bumped-version)"
git cliff --bump --tag $(git cliff --bumped-version)

# Or specify the version explicitly:
git cliff --tag v0.2.0 --output CHANGELOG.md
git add CHANGELOG.md
git commit -m "chore(release): prepare v0.2.0"
git tag v0.2.0
```

- `cliff.toml` is committed to the repo — do not generate changelogs without it.
- Release notes for a single tag (e.g., for a GitHub Release body) can be extracted with:
  ```bash
  git cliff --latest --strip header
  ```
- Always use annotated tags (`git tag -a`) or let git-cliff create them; lightweight tags are not recognised as release boundaries by default.
- Commit messages must follow [Conventional Commits](https://www.conventionalcommits.org/) so git-cliff can group and version correctly.

---

## Security Tooling

Three tools run against the workspace. All three must pass before a change is considered done.

```bash
cargo clippy --workspace -- -D warnings   # zero errors required
cargo deny check advisories bans licenses sources
cargo audit
```

### `cargo semver-checks`

The workspace crates are not published on crates.io, but `cargo semver-checks` works
against git tags via `--baseline-rev`. Check each library crate individually:

```bash
cargo semver-checks -p joinmarket-core --baseline-rev v0.1.0-alpha
```

- **Do not run at the workspace level** — `joinmarket-tor` has mutually exclusive
  `arti`/`tordaemon` features that the tool tries to enable simultaneously.
- `joinmarket-dn` is a binary crate; semver checks do not apply.
- `joinmarket-core` currently has **4 major semver violations** relative to `v0.1.0-alpha`
  (removed `MessageCommand` enum variants). Bump to `0.2.0` before the next release.

### `cargo deny` (v0.19+) — `deny.toml`

- **`[advisories]`** only accepts `ignore = [...]`. The old `vulnerability`, `unmaintained`,
  `yanked`, `notice` fields no longer exist in 0.19+; they were removed. Vulnerabilities are
  hard errors by default.
- **`[bans].wildcards`** — path-only workspace deps (`joinmarket-core = { path = "..." }`)
  have no version field and are flagged as wildcards. Use `wildcards = "warn"`, not `"deny"`.
- **Workspace crates must declare `license`** in their `Cargo.toml` (`license = "MIT"`);
  otherwise `cargo deny check licenses` errors on them as unlicensed.
- **Arti-only advisories** are suppressed in `deny.toml` with documented reasons. Do not
  remove those entries without confirming the upstream fix is available.

### Nick signature protocol (`nick-sig`)

Nick-sig handshake validation was implemented and then removed (commit `bfd69f9`).
The `NickSig` / `SigningKey` / `Nick::verify_signature()` API remains in
`joinmarket-core/src/nick.rs` for future use. Key facts if re-implementing:

- Message to sign: the nick string as bytes (`nick.as_bytes()`)
- Channel ID: `"onion-network"` (matches Python JoinMarket `hostid` in `onionmc.py`)
- Hash: `sha256(channel_id || message)`
- No Python client currently sends a `nick-sig` in the handshake — any
  implementation must default to lenient mode (absent = accepted) at first.

### `secp256k1` version notes

- We use **`secp256k1 = "0.30"`** with `features = ["global-context", "rand", "recovery"]`.
- `rand-std` was the feature name in 0.28/0.29; it was removed in 0.30. Use `rand` from 0.29 onwards.
- `RecoveryId::from_i32()` / `to_i32()` were removed in 0.30. Use `RecoveryId::try_from(i32)` and
  `i32::from(RecoveryId)` instead.
- `secp256k1::rand` is re-exported by the crate when the `rand` feature is enabled, so
  `secp256k1::rand::thread_rng()` still works in 0.30 without adding a separate `rand` import.
- Upgrading to 0.31+ also bumps the `rand` dep to 0.9 — that is a separate migration step.

### `cargo audit` (v0.22+) — `.cargo/audit.toml`

- **`[output].deny`** accepts only `["warnings", "unmaintained", "unsound", "yanked"]`.
  `"vulnerability"` is **not** a valid value and will fail to parse.
- **`[output].quiet`** has no serde default and **must** be specified (`quiet = false`).
  Omitting it causes a parse error.
- **Yanked crates cannot be selectively ignored** via `[advisories].ignore` (which only
  accepts advisory IDs like `RUSTSEC-...`). If a yanked crate is an arti-only transitive
  dep with no fix, remove `"yanked"` from `deny` rather than break CI.
- **Arti-only advisories** (RUSTSEC-2023-0071, RUSTSEC-2025-0141, RUSTSEC-2024-0436) and
  the yanked `unicode-segmentation 1.13.0` are documented and suppressed. They affect the
  `--features arti` build only; the default `tordaemon` build is unaffected.

---

## Documentation Maintenance

Whenever a new crate is added or there are significant architectural changes (new modules, renamed
files, restructured directories, changed APIs, new behaviours), update **all** affected docs before
considering the work done:

- **`README.md`** — workspace layout tree (simplified user-facing view)
- **`docs/architecture.md`** — workspace layout tree (detailed reference), crate/module descriptions, API signatures, dependency reference
- **`docs/protocol.md`** — if any wire protocol commands, message formats, or routing behaviours change
- **`docs/deployment.md`** — if CLI options, configuration, or operational requirements change
- **`docs/development.md`** — if implementation phases or testing strategy change

Both workspace trees must stay in sync with the actual filesystem. Never let a file exist on disk
without a corresponding entry in the trees, and never leave a tree entry that no longer exists on disk.
