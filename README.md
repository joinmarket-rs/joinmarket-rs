# joinmarket-rs

A full Rust rewrite of [JoinMarket](https://github.com/JoinMarket-Org/joinmarket-clientserver), developed in phases. Each JoinMarket tool is reimplemented as its own statically-linked binary, sharing common protocol logic via the `joinmarket-core` library crate.

## Why rewrite in Rust?

JoinMarket is hard to install. The Python toolchain, `pip`, virtualenvs, and a growing list of native dependencies make it inaccessible for many users.

The directory node in particular has had reliability and stability issues in the Python implementation: growing memory consumption under load, fragile error handling that can leave peers in inconsistent states, and difficulty deploying it as a hardened system service.

A Rust rewrite addresses both problems:

- **Single statically-linked binary** — no Python, no pip, no virtualenv. Download and run.
- **Memory-safe and crash-resistant** — no uncaught exceptions, predictable memory use
- **Designed for scale** — 100k+ concurrent peer connections on a single server
- **Easy to package** — one file, no runtime dependencies, works on any modern Linux, macOS, or Windows

Programs ship as pre-built static binaries for Linux (x86\_64 and aarch64), macOS (Apple Silicon and Intel), and Windows (x86\_64) as well as source. Building from source requires only `rustup` — no system libraries, no C toolchain beyond what Rust itself needs.

## Programs in this suite

| Program | Crate | Description | Status |
|---------|-------|-------------|--------|
| Directory node | [`joinmarket-dn`](#joinmarket-dn--directory-node) | Rendezvous server for maker/taker peer discovery | Alpha |

Additional tools (maker, taker, wallet) will follow in later phases as the core library matures.

---

## joinmarket-dn — Directory node

The first program in the suite. A pure-Rust reimplementation of `start-dn.py`.

The directory node is a critical piece of JoinMarket infrastructure — it is the rendezvous point through which every maker and taker discovers each other. The Python implementation (`start-dn.py`) requires a full Python environment, uses significantly more memory per connection, and can leave peers in inconsistent states on unexpected input. Running it reliably as a system service requires considerable effort.

`joinmarket-dn` replaces it with a single binary: drop it on a server, point it at a Tor hidden service directory, and run it under systemd. It is designed to handle over 100k concurrent peer connections and is fully wire-compatible with existing Python JoinMarket clients.

The directory node is a lightweight rendezvous server for the JoinMarket coinjoin protocol:

- Accepts inbound connections from JoinMarket maker and taker peers over Tor
- Performs a JSON handshake and maintains a nick → onion registry
- Relays public messages (offers, orderbook requests) by broadcast to all connected peers
- Relays private messages to the target peer and sends the sender's onion address so peers can connect directly
- Responds to peer list requests with the full maker list (or a bond-weighted sample at scale)
- Broadcasts an operator MOTD during handshake
- Requires no Bitcoin node or wallet

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
│       ├── admission.rs       # AdmissionController (defence layers 2–4)
│       ├── sybil_guard.rs     # Layer 2: one active nick per onion
│       ├── bond_registry.rs   # Layer 3: UTXO deduplication
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
git clone https://github.com/joinmarket-rs/joinmarket-rs
cd joinmarket-rs
cargo build --release

# The binary is at:
./target/release/joinmarket-dn
```

### Cargo features

Features are defined on the `joinmarket-tor` crate and are passed through to the binary via `--features`.

| Feature | Crate | What it enables | Default |
|---------|-------|-----------------|---------|
| `tordaemon` | `joinmarket-tor` | C Tor daemon backend (`CTorProvider`). Requires the `tor` binary on the host. PoW defence is configured externally via C Tor (requires a `tor` build with `--enable-gpl`); the directory node has no visibility into whether PoW is active. | **On** |
| `arti` | `joinmarket-tor` | Arti embedded Tor backend (`ArtiTorProvider`). No external `tor` binary needed. Pulls in LGPL `equix`/`hashx` crates for PoW; activated at runtime with `--pow`. | Off |

**Default build (C Tor daemon backend):**

```bash
cargo build --release
```

The `tordaemon` feature is on by default. Configure your existing C Tor hidden service directory in `joinmarket.cfg` and run the binary.

**Build with the Arti embedded backend:**

```bash
cargo build --release \
  --no-default-features \
  --features joinmarket-dn/arti
```

Then activate PoW at runtime with `--pow`:

```bash
joinmarket-dn --pow "My PoW-protected directory node"
```

> **PoW licensing note:** The `arti` feature pulls in the `equix` and `hashx` crates,
> which are LGPL-licensed. Binaries linked against them are LGPL-encumbered.
>
> The `tordaemon` feature supports PoW via C Tor's built-in defence, which requires a
> `tor` binary compiled with `--enable-gpl`. Without it, the node starts without
> Tor-level DoS protection.

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

Tests cover nick generation, onion address validation, message parsing, handshake logic, crypto primitives, fidelity bonds, config parsing, routing, sybil guard, bond registry, admission control, and end-to-end integration.

## Running

```
joinmarket-dn [OPTIONS] [OPERATOR_MESSAGE]

Options:
  --datadir <PATH>            Data directory [default: ~/.joinmarket].
                              Must contain joinmarket.cfg with [MESSAGING:onion]
                              and [BLOCKCHAIN] sections.
  --metrics-bind <ADDR>       Prometheus metrics bind address [default: 127.0.0.1:9090]
  --pow                       Enable Tor PoW DoS defence (requires a binary built
                              with --features arti)
                              [only available when built with the `arti` feature]

Network, port, hidden service directory, and other settings are read from
joinmarket.cfg (located in the data directory). If no config file exists,
a default one is created and the process exits for you to review it.

Arguments:
  [OPERATOR_MESSAGE]          Optional operator message appended to the MOTD
```

### Basic example

```bash
joinmarket-dn "Welcome to my directory node"
```

### Custom data directory

```bash
joinmarket-dn --datadir /var/lib/joinmarket "My directory node"
```

### With PoW (Arti build only)

```bash
joinmarket-dn --pow "My PoW-protected directory node"
```

### Log level

Set the `RUST_LOG` environment variable to control verbosity:

```bash
RUST_LOG=debug joinmarket-dn
RUST_LOG=joinmarket_dn=trace,joinmarket_core=info joinmarket-dn
```

## DoS defence layers

The directory node implements four layers of defence against abuse:

| Layer | Mechanism | Default |
|-------|-----------|---------|
| 1 | Tor PoW (Equi-X puzzles) | Off — `--pow` enables it with the `arti` backend; with `tordaemon`, PoW is configured externally via C Tor |
| 2 | Sybil guard: one active nick per onion address | Always on |
| 3 | Fidelity bond UTXO deduplication | Always on |
| 4 | Maker capacity cap: 100k concurrent makers | Always on |
| 5 | Per-peer pubmsg rate limit: 30 messages per minute | Always on |

**PoW note:** `--pow` is only available with the `arti` backend and activates Equi-X PoW puzzles at runtime. With the `tordaemon` backend, PoW is configured externally through C Tor itself (requires a `tor` binary compiled with `--enable-gpl`); the directory node has no way to detect whether C Tor has PoW enabled.

## Peer routing

Routing is driven by **envelope types** (integer discriminators), not `!`-prefixed commands.

| Envelope type | Behaviour |
|---------------|-----------|
| `PUBMSG` (687) | Broadcast to all connected peers (carries `!`-prefixed application commands like `!sw0absoffer`, `!orderbook`) |
| `PRIVMSG` (685) | Forward to the target peer; DN also sends the sender's onion address to the target via `PEERLIST` |
| `GETPEERLIST` (791) | Return full maker list (≤20k) or bond-weighted sample (>20k) as a `PEERLIST` (789) response |
| `PING` (797) | DN sends liveness probe; peer replies with `PONG` (799) |
| `DISCONNECT` (801) | Close connection cleanly |

## Memory target

Designed for **100k concurrent peers** on a single server:

| Resource | Per peer | 100k total |
|----------|----------|------------|
| Tokio task stack | ~6 KB | ~600 MB |
| Read/write buffers (4 KB each) | 8 KB | ~800 MB |
| PeerMeta in DashMap | ~128 B | ~13 MB |
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
    --datadir /var/lib/joinmarket \
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

**Arti backend note:** When built with the `arti` feature, Tor runs inside the DN process itself. The process makes outbound TCP connections to Tor relays in addition to accepting peer connections, so you may also need:

```bash
# Expand ephemeral port range for Arti's outbound Tor relay connections
net.ipv4.ip_local_port_range = 1024 65535

# Allow larger buffers for Tor relay traffic (the defaults above are
# tuned for JoinMarket's small messages on local sockets)
net.ipv4.tcp_rmem = 4096 16384 131072
net.ipv4.tcp_wmem = 4096 16384 131072
```

You should also increase `LimitNOFILE` in the systemd unit to account for both peer sockets and Tor relay connections.

## Implementation status

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | `joinmarket-core`: nick, onion, message, handshake, crypto, fidelity bond, config | Ongoing |
| 2 | `joinmarket-tor`: TorProvider trait, MockTorProvider, C Tor daemon backend, Arti embedded backend | Complete |
| 3 | `joinmarket-dn`: accept loop, peer state machine, router, admission control, heartbeat, metrics | Complete |
| 4 | Interoperability testing against Python JoinMarket client on signet | Complete |
| 5 | Heartbeat eviction, Prometheus metrics, structured tracing | Complete |
| 6 | Production load testing with real-world traffic | Pending |

## License

MIT
