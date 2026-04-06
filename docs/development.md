# joinmarket-rs — Development Guide

## Implementation Phases

### Phase 1 — `joinmarket-core` (Weeks 1–3)

- [ ] Nick generation, validation, base58 encoding
- [ ] `OnionAddress::parse()` — full Tor v3 structural validation (base32 decode, version byte, SHA3-256 checksum)
- [ ] `OnionServiceAddr::parse()` — location-string split + port validation
- [ ] Unit tests: known-good v3 addresses, v2 addresses (must reject), wrong checksum, wrong length, wrong version byte, port out of range
- [ ] `JmMessage` parse/serialize for all command types
- [ ] `PeerHandshake` / `DnHandshake` serde roundtrip + validation logic
- [ ] secp256k1 signing + verification
- [ ] `FidelityBondProof` 252-byte parser
- [ ] `joinmarket.cfg` INI parser
- [ ] Unit tests with fixtures from real Python JoinMarket captures
- [ ] Fuzz targets: `fuzz_parse_message`, `fuzz_parse_handshake`

### Phase 2 — `joinmarket-tor` (Weeks 4–5)

- [ ] `ArtiTorProvider::bootstrap()` with persistent state dir
- [ ] `launch_onion_service()` with stable key persistence
- [ ] PoW defence configuration (feature-flagged)
- [ ] `TorProvider` trait + `ArtiTorProvider` implementation
- [ ] Integration test: bootstrap Arti in test, create hidden service, connect back

### Phase 3 — `joinmarket-dn` MVP (Weeks 6–8)

- [ ] `main.rs` CLI with clap
- [ ] `server.rs` accept loop using `OnionServiceHandle`
- [ ] `peer.rs` state machine (AwaitingHandshake → Active → Disconnected)
- [ ] `router.rs` with separate maker/taker registries + broadcast channel
- [ ] `admission.rs` all five layers wired up
- [ ] `sybil_guard.rs`
- [ ] `bond_registry.rs`
- [ ] MOTD sent in handshake
- [ ] `GETPEERLIST` / `PEERLIST` response (full list ≤20k, sampled >20k)
- [ ] Graceful shutdown via `CancellationToken`
- [ ] **Milestone:** Rust DN completes handshake with real Python JoinMarket client

### Phase 4 — Interoperability Testing (Weeks 9–10)

- [ ] Run Python `yg-privacyenhanced.py` maker against Rust DN on signet
- [ ] Run Python `sendpayment.py` taker against Rust DN on signet
- [ ] Verify full coinjoin transaction completes end-to-end
- [ ] Capture and diff wire messages vs Python DN output

### Phase 5 — Hardening (Weeks 11–12)

- [ ] `heartbeat.rs` ping/pong liveness eviction
- [ ] `metrics.rs` all Prometheus metrics wired
- [ ] Prometheus HTTP endpoint on `--metrics-bind`
- [ ] Structured tracing spans (nick + connection_id per peer)
- [ ] `systemd` unit file
- [ ] Docker image (scratch + binary)
- [ ] Load test: 10k simulated peers
- [ ] `cargo-fuzz` CI integration

---

## Testing Strategy

### Unit tests (in `joinmarket-core`)

- Nick construction: known pubkey → known nick string (cross-check against Python test vectors)
- Message parsing: valid messages, malformed commands, missing fields, oversized
- Handshake validation: wrong proto-ver, wrong network, malformed nick
- `FidelityBondProof::parse_base64`: valid blobs and truncated/corrupted inputs
- Config parsing: realistic `joinmarket.cfg`

### Integration tests (`tests/integration/`)

1. Start Rust DN in-process (with mock Tor provider)
1. Connect two mock peers (one Maker, one Taker)
1. Assert offer commands (`!sw0absoffer`, `!cancel`, `!tbond`) are delivered to Takers but **not** to Makers
1. Assert all-peers commands (`!orderbook`, `!hp2`) are delivered to both Makers and Takers
1. Assert `GETPEERLIST` (envelope type 791) returns only the Maker
1. Assert PRIVMSG routing forwards to the target peer
1. Assert PING / PONG (envelope types 797/799) heartbeat clears disconnected peers

### Fuzz tests (planned)

Fuzz targets are not yet implemented. When added, they will live in a `fuzz/` directory:

```
fuzz/
├── fuzz_parse_message.rs     — arbitrary bytes into JmMessage::parse
└── fuzz_parse_handshake.rs   — arbitrary bytes into serde_json::from_str::<PeerHandshake>
```
