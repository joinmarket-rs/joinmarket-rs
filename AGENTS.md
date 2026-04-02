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
- Use **`ShardedRegistry<T>`** (64 `parking_lot::Mutex<HashMap<Arc<str>, T>>` shards) for maker/taker registries.
- Use **`DashMap<Arc<str>, PeerMeta>`** for peer metadata.
- Broadcast channel capacity: **1024**. Peers that lag are disconnected with `RecvError::Lagged`.

### Tor Backend Feature Flags

`tordaemon` and `arti` features are mutually exclusive — a `compile_error!` enforces this. Never
enable both simultaneously. The default is `tordaemon`.

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
