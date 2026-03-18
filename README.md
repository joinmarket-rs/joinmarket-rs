# joinmarket-rs

A full Rust rewrite of [JoinMarket](https://github.com/JoinMarket-Org/joinmarket-clientserver), developed in phases. Each JoinMarket tool is reimplemented as its own statically-linked binary, sharing common protocol logic via the `joinmarket-core` library crate.

## Why rewrite in Rust?

JoinMarket is hard to install. The Python toolchain, `pip`, virtualenvs, and a growing list of native dependencies make it inaccessible for non-technical operators — precisely the people most needed to run infrastructure like directory nodes.

The directory node in particular has had reliability and stability issues in the Python implementation: memory growth under load, unhandled exceptions crashing the process, and difficulty deploying it as a hardened system service.

A Rust rewrite addresses both problems:

- **Single statically-linked binary** — no Python, no pip, no virtualenv. Download and run.
- **Memory-safe and crash-resistant** — no uncaught exceptions, predictable memory use
- **Designed for scale** — 100k+ concurrent peer connections on a single server
- **Easy to package** — one file, no runtime dependencies, works on any modern Linux

Programs ship as pre-built static binaries for Linux (x86\_64 and aarch64) as well as source. Building from source requires only `rustup` — no system libraries, no C toolchain beyond what Rust itself needs.

## Programs in this suite

| Program | Crate | Description | Status |
|---------|-------|-------------|--------|
| Directory node | [`joinmarket-dn`](#joinmarket-dn--directory-node) | Rendezvous server for maker/taker peer discovery | In progress |

Additional tools (yield generator, coinjoin client, wallet) will follow in later phases as the core library matures.

---

## joinmarket-dn — Directory node

The first program in the suite. A pure-Rust reimplementation of `start-dn.py`.

The Python directory node (`start-dn.py`) has been the most operationally painful part of running JoinMarket infrastructure. It requires a full Python environment, leaks memory under sustained load, and crashes on unexpected input from peers. Running it reliably as a system service requires considerable babysitting.

`joinmarket-dn` replaces it with a single binary: drop it on a server, point it at a Tor hidden service directory, and run it under systemd. It handles 100k+ concurrent peer connections and is fully wire-compatible with existing Python JoinMarket clients.

The directory node is a lightweight rendezvous server for the JoinMarket coinjoin protocol:

- Accepts inbound connections from JoinMarket maker and taker peers over Tor
- Performs a JSON handshake and maintains a nick → onion registry
- Relays public messages (`!ann`, `!orderbook`) by broadcast to all connected peers
- Routes private messages by returning the target peer's onion address (peers then connect directly — the directory does **not** relay private content)
- Responds to `!getpeers` with the full maker list (or a bond-weighted sample at scale)
- Broadcasts an operator MOTD during handshake
- Requires no Bitcoin node, no wallet, no blockchain access

## Workspace layout

```
joinmarket-rs/
├── crates/
│   ├── joinmarket-core/       # Pure protocol logic — no I/O, no async
│   │   ├── nick.rs            # Nick construction & verification
│   │   ├── onion.rs           # Tor v3 onion address validation
│   │   ├── message.rs         # JoinMarket message parsing & serialization
│   │   ├── handshake.rs       # Handshake JSON types & validation
│   │   ├── crypto.rs          # secp256k1 ECDSA + NaCl box primitives
│   │   ├── fidelity_bond.rs   # 252-byte fidelity bond proof parser
│   │   └── config.rs          # joinmarket.cfg INI parser
│   │
│   ├── joinmarket-tor/        # Tor integration layer
│   │   ├── provider.rs        # TorProvider trait
│   │   ├── ctor_backend.rs    # C Tor daemon backend (default)
│   │   ├── arti_backend.rs    # Arti embedded backend (feature-flagged)
│   │   └── mock.rs            # MockTorProvider for testing (local TCP)
│   │
│   └── joinmarket-dn/         # The binary
│       ├── main.rs            # CLI entry point (clap)
│       ├── server.rs          # Accept loop
│       ├── peer.rs            # Per-peer state machine
│       ├── router.rs          # ShardedRegistry + broadcast channel
│       ├── admission.rs       # AdmissionController (defence layers 2–5)
│       ├── sybil_guard.rs     # Layer 3: one active nick per onion
│       ├── bond_registry.rs   # Layer 4: UTXO deduplication
│       ├── heartbeat.rs       # Periodic liveness loop
│       └── metrics.rs         # Prometheus counters/gauges
│
├── tests/fixtures/            # Captured real JoinMarket wire payloads
└── docs/                      # Architecture, protocol, deployment, development guides
```

## Building

**Prerequisites:** Rust 1.75+ (stable). Install via [rustup](https://rustup.rs).

```bash
# Clone and build all crates
git clone https://github.com/takinbrrrr/joinmarket-rs
cd joinmarket-rs
cargo build --release

# The binary is at:
./target/release/joinmarket-dn
```

### Cargo features

Features are defined on the `joinmarket-tor` crate and are passed through to the binary via `--features`.

| Feature | Crate | What it enables | Default |
|---------|-------|-----------------|---------|
| `tordaemon` | `joinmarket-tor` | C Tor daemon backend (`CTorProvider`). Requires the `tor` binary on the host. PoW defence compiled in; activated at runtime with `--pow` (requires `--enable-gpl` C Tor build). | **On** |
| `arti` | `joinmarket-tor` | Arti embedded Tor backend (`ArtiTorProvider`). No external `tor` binary needed. Pulls in LGPL `equix`/`hashx` crates for PoW; activated at runtime with `--pow`. | Off |

**Default build (C Tor daemon backend):**

```bash
cargo build --release
```

The `tordaemon` feature is on by default. Point `--hidden-service-dir` at your existing C Tor hidden service directory and run the binary.

**Build with the Arti embedded backend:**

```bash
cargo build --release \
  --no-default-features \
  --features joinmarket-dn/arti
```

Then activate PoW at runtime with `--pow`:

```bash
joinmarket-dn --pow "My PoW-protected directory"
```

**Build with both backends:**

```bash
cargo build --release \
  --features joinmarket-dn/arti
```

> **PoW licensing note:** The `arti` feature pulls in the `equix` and `hashx` crates,
> which are LGPL-licensed. Binaries linked against them are LGPL-encumbered.
>
> The `tordaemon` feature supports PoW via C Tor's built-in defence, which requires a
> `tor` binary compiled with `--enable-gpl`. Without it, `--pow` logs a prominent warning
> and the node starts without Tor-level DoS protection.

## Testing

```bash
# Run all tests across the workspace
cargo test --workspace

# Run tests for a specific crate
cargo test -p joinmarket-core
cargo test -p joinmarket-dn

# Run a specific test
cargo test -p joinmarket-core onion::tests::test_valid_v3_address
```

There are currently **47 tests** across the workspace:

| Crate | Tests |
|-------|-------|
| `joinmarket-core` | 35 (nick, onion, message, handshake, crypto, fidelity bond, config) |
| `joinmarket-dn` | 12 (router, sybil guard, bond registry, admission control) |

## Running

```
joinmarket-dn [OPTIONS] [MOTD]

Options:
  --network <NET>             mainnet | testnet | signet [default: mainnet]
  --port <PORT>               Listening port [default: 5222]
  --metrics-port <PORT>       Prometheus metrics port [default: 9090]
  --pow                       Enable Tor PoW DoS defence (see note below)
  --state-dir <PATH>          Arti state directory — required for key persistence.
                              Arti stores the hidden service Ed25519 key here;
                              without it the .onion address changes on every restart.
                              Selects the Arti backend when both backends are compiled.
                              [only available when built with the `arti` feature]
  --hidden-service-dir <PATH> C Tor hidden service directory — required for key
                              persistence. C Tor stores the hidden service Ed25519 key
                              here; without it the .onion address changes on every
                              restart. Selects the C Tor backend when both backends
                              are compiled. [only available with the `tordaemon` feature]

When both `arti` and `tordaemon` features are compiled in, exactly one of
--state-dir or --hidden-service-dir must be provided; they are mutually exclusive
and the one supplied determines which backend is used.

Arguments:
  [MOTD]                      Message of the day sent to connecting peers
```

### Basic example

```bash
joinmarket-dn --network mainnet "Welcome to my directory node"
```

### Testnet example

```bash
joinmarket-dn --network testnet --port 5222 "Testnet directory node"
```

### C Tor backend (default build)

```bash
joinmarket-dn \
  --hidden-service-dir /var/lib/joinmarket/hs-keys \
  --network mainnet \
  "My directory node"
```

### Arti backend

```bash
joinmarket-dn \
  --state-dir /var/lib/joinmarket/arti-state \
  --network mainnet \
  "My directory node"
```

> Each backend option is only present at runtime when that feature was compiled in.
> When both features are compiled in, supply exactly one to select the backend.

### Log level

Set the `RUST_LOG` environment variable to control verbosity:

```bash
RUST_LOG=debug joinmarket-dn
RUST_LOG=joinmarket_dn=trace,joinmarket_core=info joinmarket-dn
```

## DoS defence layers

The directory node implements five layers of defence against abuse:

| Layer | Mechanism | Default |
|-------|-----------|---------|
| 1 | Tor PoW (Equi-X puzzles) | Off — pass `--pow` to enable |
| 2 | Connection rate limit: 3 connections/minute per onion | Always on |
| 3 | Sybil guard: one active nick per onion address | Always on |
| 4 | Fidelity bond UTXO deduplication | Always on |
| 5 | Maker registration throttle: 60 new makers/minute, 100k cap | Always on |

**PoW note:** `--pow` activates PoW at runtime. The `tordaemon` backend (default) requires a `tor` binary compiled with `--enable-gpl`; the `arti` backend requires the binary to be built with `--features arti`. Passing `--pow` without the required support causes the process to abort at startup rather than silently running unprotected.

## Peer routing

| Message | Behaviour |
|---------|-----------|
| `!ann`, `!orderbook` | Broadcast to all connected peers |
| `!getpeers` | Return full maker list (≤20k) or bond-weighted sample (>20k) |
| `!fill <nick> ...` | Look up target nick's onion address and return it to the sender; sender connects directly |
| `!ping` | Reply `!pong` |
| `!disconnect` | Close connection cleanly |

## Memory target

Designed for **100k concurrent peers** on a single server:

| Resource | Per peer | 100k total |
|----------|----------|------------|
| Tokio task stack | ~6 KB | ~600 MB |
| Read/write buffers (4 KB each) | 8 KB | ~800 MB |
| PeerState in slab | ~128 B | ~13 MB |
| Nick index entry | ~200 B | ~20 MB |
| **Total** | **~14 KB** | **~1.4 GB** |

## systemd service

```ini
[Unit]
Description=JoinMarket Directory Node (Rust)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/joinmarket-dn \
    --hidden-service-dir=/var/lib/joinmarket/hs-keys \
    "Greetings from a Rust directory node"
User=joinmarket
Restart=on-failure
RestartSec=10s
LimitNOFILE=500000
MemoryMax=20G

[Install]
WantedBy=multi-user.target
```

## Linux kernel tuning (for 100k+ peers)

```bash
# /etc/sysctl.d/99-joinmarket-dn.conf
fs.file-max = 2000000
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_rmem = 4096 4096 16384
net.ipv4.tcp_wmem = 4096 4096 16384
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.netfilter.nf_conntrack_max = 2000000
```

## Implementation status

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | `joinmarket-core`: nick, onion, message, handshake, crypto, fidelity bond, config | Complete |
| 2 | `joinmarket-tor`: TorProvider trait, MockTorProvider; Arti backend (feature-flagged) | Trait + mock complete; Arti backend pending |
| 3 | `joinmarket-dn`: accept loop, peer state machine, router, admission control | Complete (using mock Tor) |
| 4 | Interoperability testing against Python JoinMarket client on signet | Pending |
| 5 | Heartbeat eviction, Prometheus metrics, structured tracing, load testing | Pending |

## License

MIT
