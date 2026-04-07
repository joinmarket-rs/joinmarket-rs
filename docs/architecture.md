# joinmarket-rs — Architecture Reference

## Workspace Structure

```
joinmarket-rs/
├── Cargo.toml                        # workspace manifest
├── crates/
│   ├── joinmarket-core/              # pure protocol logic, no I/O, no_std where possible
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── nick.rs               # nick construction & verification
│   │       ├── onion.rs              # Tor v3 onion address validation & newtype
│   │       ├── message.rs            # JoinMarket message parsing & serialization
│   │       ├── handshake.rs          # onion channel handshake JSON types
│   │       ├── crypto.rs             # secp256k1 + NaCl box primitives
│   │       ├── fidelity_bond.rs      # 252-byte fidelity bond proof parser
│   │       └── config.rs             # joinmarket.cfg INI parser
│   │
│   ├── joinmarket-tor/               # Tor integration layer (swappable backends)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── provider.rs           # TorProvider trait (swappable backends)
│   │       ├── ctor_backend.rs       # CTorProvider (feature = "tordaemon", default)
│   │       ├── arti_backend.rs       # ArtiTorProvider (feature = "arti")
│   │       └── mock.rs               # MockTorProvider for testing (local TCP)
│   │
│   └── joinmarket-dn/                # the binary
│       ├── Cargo.toml
│       ├── src/
│       │   ├── lib.rs
│       │   ├── main.rs               # CLI entry point (clap)
│       │   ├── server.rs             # accept loop + connection manager
│       │   ├── peer.rs               # per-peer state machine
│       │   ├── router.rs             # ShardedRegistry + broadcast channel
│       │   ├── admission.rs          # AdmissionController (all 4 defence layers)
│       │   ├── sybil_guard.rs        # Layer 2: onion → one active nick
│       │   ├── bond_registry.rs      # Layer 3: UTXO deduplication
│       │   ├── heartbeat.rs          # !ping/!pong liveness tracking
│       │   └── metrics.rs            # Prometheus counters/gauges
│       └── tests/
│           └── integration.rs        # end-to-end integration tests
│
├── tests/
│   └── fixtures/                     # captured real JoinMarket wire payloads
│       ├── handshake_maker.json
│       ├── handshake_taker.json
│       └── messages.txt
└── docs/
    ├── architecture.md               # this file
    ├── protocol.md                   # wire protocol reference
    ├── deployment.md                 # deployment guide
    └── development.md                # implementation phases & testing strategy
```

---

## Crate 1: `joinmarket-core`

Pure protocol logic. No I/O. No async. Every other crate depends on it.

### `nick.rs`

Nick format: `"J" + version_byte + base58(sha256(pubkey)[0..NICK_HASH_LEN])`, right-padded to 16 chars with `'O'`.

```rust
pub struct Nick(String);  // newtype wrapper

impl Nick {
    pub fn generate(network: Network) -> (Nick, SigningKey);
    pub fn verify_signature(&self, msg: &[u8], channel_id: &str, sig: &NickSig) -> bool;
    pub fn from_str(s: &str) -> Result<Nick, NickError>;  // validates format
}
```

Dependencies: `secp256k1`, `bitcoin_hashes`, `bs58`

### `onion.rs`

Tor v3 onion addresses have a precise, fully-specifiable structure. Validation is exact — not a best-effort regex. Every `onion_address` stored or relayed by the directory node must pass this check.

**Tor v3 address format:**

- 56 base32 characters (RFC 4648, lowercase) encoding 35 bytes
- The 35 decoded bytes are: `pubkey(32) || checksum(2) || version(1)`
- `version` must be `0x03`
- `checksum = sha3_256(".onion checksum" || pubkey || version)[0..2]`
- The full address string is `<56-char-base32>.onion` — always lowercase, always `.onion` suffix
- Total string length: 62 characters (`56 + len(".onion")`)

The `location-string` in a JoinMarket handshake is `<onion_address>:<port>`. Both components must be validated.

```rust
use sha3::{Digest, Sha3_256};

/// A validated Tor v3 onion address (without port).
/// Guaranteed to be structurally correct on construction.
/// Format: <56-lowercase-base32-chars>.onion
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OnionAddress(String);  // private inner field — only constructible via parse()

/// A validated onion address + port pair, as used in JoinMarket location-strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionServiceAddr {
    pub host: OnionAddress,
    pub port: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum OnionAddressError {
    #[error("wrong length: expected 62 chars (56 base32 + '.onion'), got {0}")]
    WrongLength(usize),
    #[error("missing '.onion' suffix")]
    MissingOnionSuffix,
    #[error("invalid base32 encoding: {0}")]
    InvalidBase32(String),
    #[error("wrong version byte: expected 0x03, got {0:#04x}")]
    WrongVersion(u8),
    #[error("checksum mismatch: address is corrupt or truncated")]
    ChecksumMismatch,
}

#[derive(Debug, thiserror::Error)]
pub enum OnionServiceAddrError {
    #[error("missing port in location-string (expected '<onion>:<port>')")]
    MissingPort,
    #[error("invalid port number: {0}")]
    InvalidPort(String),
    #[error("invalid onion address: {0}")]
    InvalidOnion(#[from] OnionAddressError),
}

impl OnionAddress {
    /// Parse and validate a Tor v3 onion address string.
    /// Accepts both lowercase and uppercase input; normalises to lowercase internally.
    /// Returns Err for v2 addresses, truncated addresses, bad checksums, etc.
    pub fn parse(s: &str) -> Result<Self, OnionAddressError> {
        let s = s.to_lowercase();

        // Length check: 56 base32 chars + ".onion" = 62
        if s.len() != 62 {
            return Err(OnionAddressError::WrongLength(s.len()));
        }

        // Suffix check
        if !s.ends_with(".onion") {
            return Err(OnionAddressError::MissingOnionSuffix);
        }

        let encoded = &s[..56];

        // Base32 decode — must produce exactly 35 bytes
        let decoded = data_encoding::BASE32_NOPAD
            .decode(encoded.to_uppercase().as_bytes())
            .map_err(|e| OnionAddressError::InvalidBase32(e.to_string()))?;

        // Must be exactly 35 bytes: pubkey(32) + checksum(2) + version(1)
        assert_eq!(decoded.len(), 35, "base32 decode of 56-char v3 onion must be 35 bytes");

        let pubkey   = &decoded[0..32];
        let checksum = &decoded[32..34];
        let version  =  decoded[34];

        // Version must be 0x03 (v3)
        if version != 0x03 {
            return Err(OnionAddressError::WrongVersion(version));
        }

        // Verify checksum: sha3_256(".onion checksum" || pubkey || version)[0..2]
        let mut hasher = Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(pubkey);
        hasher.update([version]);
        let hash = hasher.finalize();

        if &hash[0..2] != checksum {
            return Err(OnionAddressError::ChecksumMismatch);
        }

        Ok(OnionAddress(s))
    }

    /// Return the raw 32-byte Ed25519 public key embedded in the address.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        let encoded = &self.0[..56];
        let decoded = data_encoding::BASE32_NOPAD
            .decode(encoded.to_uppercase().as_bytes())
            .expect("already validated");
        decoded[0..32].try_into().expect("already validated")
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

impl std::fmt::Display for OnionAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl OnionServiceAddr {
    /// Parse a JoinMarket location-string of the form "<onion>:<port>".
    pub fn parse(s: &str) -> Result<Self, OnionServiceAddrError> {
        let (host_str, port_str) = s.rsplit_once(':')
            .ok_or(OnionServiceAddrError::MissingPort)?;
        let port = port_str.parse::<u16>()
            .map_err(|_| OnionServiceAddrError::InvalidPort(port_str.to_string()))?;
        let host = OnionAddress::parse(host_str)?;
        Ok(OnionServiceAddr { host, port })
    }

    pub fn as_location_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
```

Dependencies: `data-encoding` (for `BASE32_NOPAD`), `sha3`

**Enforcement points — every place an onion address enters the system:**

1. **Handshake `location-string`** — parsed immediately after JSON deserialisation, before any registry lookup. If `OnionServiceAddr::parse()` fails, send no error response; close the connection immediately and increment `jm_admission_invalid_onion_total`.
1. **`MakerInfo.onion_address`** — stored as `OnionServiceAddr`, not `String`. Cannot be constructed without passing validation.
1. **`TakerInfo.onion_address`** — stored as `Option<OnionServiceAddr>`. `None` for takers without a hidden service; if a value is present it must be valid.
1. **`SybilGuard` keys** — keyed by `OnionAddress` (the host part only, without port), not raw string. This prevents a trivial bypass where an attacker varies the port to register multiple nicks from one hidden service.
1. **`config.rs` `directory_nodes`** — each entry parsed via `OnionServiceAddr::parse()` at startup; the process aborts if any entry is invalid.

```rust
// Example: handshake validation in peer.rs
let location = OnionServiceAddr::parse(&handshake.location_string)
    .map_err(|e| {
        tracing::warn!(
            nick = %handshake.nick,
            location = %handshake.location_string,
            error = %e,
            "rejecting peer: invalid onion address in location-string"
        );
        metrics::counter!("jm_admission_invalid_onion_total").increment(1);
        HandshakeError::InvalidOnionAddress(e)
    })?;
// If we reach here, location is a valid OnionServiceAddr.
// Peer classification: Maker if location_string was non-empty and valid.
```

### `message.rs`

Messages are newline-terminated, whitespace-delimited strings prefixed with `!command`.

```rust
/// Application-level `!`-prefixed commands carried inside PUBMSG / PRIVMSG payloads.
/// Envelope-level types (GETPEERLIST, PEERLIST, PING, PONG, DISCONNECT) are integer
/// discriminators in `msg_type`, NOT `!`-commands — they are handled separately.
pub enum MessageCommand {
    // Public broadcast (offer announcements)
    AbsOffer, RelOffer, SwAbsOffer, SwRelOffer, Sw0AbsOffer, Sw0RelOffer,
    Orderbook, Cancel, Hp2, TBond,
    // Private (coinjoin negotiation)
    Fill, IoAuth, Auth, PubKey, Tx, Sig, Push, Error,
}

impl MessageCommand {
    /// Returns `true` for the six offer-announcement variants.
    pub fn is_offer(&self) -> bool;
}

pub struct JmMessage {
    pub command: MessageCommand,
    pub fields: Vec<String>,
    pub nick_sig: Option<NickSig>,
}

impl JmMessage {
    pub fn parse(raw: &str) -> Result<Self, ParseError>;
}
```

### `handshake.rs`

Two separate types for the two directions of the handshake exchange:

```rust
/// Inbound peer handshake (envelope type 793). The peer sends this first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHandshake {
    #[serde(rename = "app-name")]
    pub app_name: String,          // must be "joinmarket"
    pub directory: bool,           // true for directory nodes
    #[serde(rename = "location-string")]
    pub location_string: String,   // "xxxx.onion:5222" for makers, "" for takers
    #[serde(rename = "proto-ver")]
    pub proto_ver: u8,             // currently 5
    pub features: HashMap<String, serde_json::Value>,
    pub nick: String,
    pub network: String,           // "mainnet" | "testnet" | "signet"
}

/// Outbound directory handshake response (envelope type 795).
#[derive(Debug, Serialize)]
pub struct DnHandshake {
    #[serde(rename = "app-name")]
    pub app_name: String,
    pub directory: bool,
    #[serde(rename = "location-string")]
    pub location_string: String,
    #[serde(rename = "proto-ver-min")]
    pub proto_ver_min: u8,         // min/max range instead of single proto-ver
    #[serde(rename = "proto-ver-max")]
    pub proto_ver_max: u8,
    pub features: HashMap<String, serde_json::Value>,
    pub accepted: bool,
    pub nick: String,
    pub network: String,
    pub motd: String,              // MOTD is only sent by the directory node
}

// Validation rules (applied to PeerHandshake):
// - app_name == "joinmarket"
// - proto_ver == CURRENT_PROTO_VER (currently 5)
// - network matches our configured network
// - nick is well-formed (correct length, correct prefix byte)
// - features map: max 32 entries, no nested objects/arrays
// - location_string, if non-empty and not "NOT-SERVING-ONION", must parse as
//   a valid OnionServiceAddr (Tor v3 + valid port)
//   → if non-empty and fails OnionServiceAddr::parse(), DISCONNECT immediately
```

### `crypto.rs`

```rust
// secp256k1 ECDSA for nick anti-spoofing
pub struct SigningKey(secp256k1::SecretKey);
pub struct NickSig(secp256k1::ecdsa::Signature);
impl SigningKey {
    pub fn sign_message(&self, msg: &[u8], channel_id: &str) -> NickSig;
}

// NaCl box (X25519 + XSalsa20-Poly1305) for E2E encryption between maker/taker
// Directory node itself does not encrypt, but must parse encrypted message envelopes
pub struct EncryptionKey(x25519_dalek::StaticSecret);
pub struct EncryptedMessage { pub nonce: [u8; 24], pub ciphertext: Vec<u8> }
impl EncryptionKey {
    pub fn encrypt(&self, peer_pubkey: &[u8], plaintext: &[u8]) -> EncryptedMessage;
    pub fn decrypt(&self, peer_pubkey: &[u8], msg: &EncryptedMessage) -> Result<Vec<u8>, CryptoError>;
}
```

Dependencies: `secp256k1` (with `global-context` feature), `x25519-dalek`, `crypto_secretbox`

### `fidelity_bond.rs`

252-byte binary blob (base64-encoded in wire format):

```
nick_sig(72) + cert_sig(72) + cert_pubkey(33) + cert_expiry(2) +
utxo_pubkey(33) + txid(32) + vout(4) + timelock(4) = 252 bytes
```

```rust
pub struct FidelityBondProof {
    pub nick_sig:    [u8; 72],
    pub cert_sig:    [u8; 72],
    pub cert_pubkey: [u8; 33],
    pub cert_expiry: u16,
    pub utxo_pubkey: [u8; 33],
    pub txid:        [u8; 32],
    pub vout:        u32,
    pub timelock:    u32,
}

impl FidelityBondProof {
    pub fn parse_base64(encoded: &str) -> Result<Self, BondParseError>;
    // NOTE: directory node does NOT verify against blockchain.
    // It only parses and deduplicates UTXOs. Takers verify authenticity independently.
}
```

### `config.rs`

Parses the standard `joinmarket.cfg` INI format. The directory node uses only:

```ini
[BLOCKCHAIN]
blockchain_source = no-blockchain
network = mainnet  # or testnet, signet

[MESSAGING:onion]
type = onion
onion_serving_port = 5222
hidden_service_dir = ~/.joinmarket/hs-keys
directory_nodes = <self-onion>.onion:5222

[LOGGING]
console_log_level = INFO
```

---

## Crate 2: `joinmarket-tor`

Thin integration layer over `arti-client` and `tor-hsservice`. Exposes a `TorProvider` trait for swappable backends.

### `provider.rs`

```rust
pub type BoxReader = Box<dyn AsyncRead + Send + Unpin>;
pub type BoxWriter = Box<dyn AsyncWrite + Send + Unpin>;

pub struct IncomingConnection {
    pub reader: BoxReader,
    pub writer: BoxWriter,
    pub circuit_id: String,
}

#[async_trait]
pub trait TorProvider: Send + Sync {
    fn onion_address(&self) -> &str;
    async fn accept(&self) -> Result<IncomingConnection, TorError>;
}
```

### `arti_backend.rs` (feature = `"arti"`)

Bootstrap is an associated method on `ArtiTorProvider`. It bootstraps the Tor client, launches the
onion service, and waits up to 60 seconds for the `.onion` address to become available.

Onion service launch (PoW disabled unless `--pow` was passed on the command line):

```rust
impl ArtiTorProvider {
    pub async fn bootstrap(state_dir: &Path, pow_enabled: bool) -> Result<Self, TorError> { ... }
}
```

```rust
let mut builder = OnionServiceConfig::builder();
builder.nickname(nickname);
if pow_enabled {
    builder.enable_pow(true);
    builder.pow_rend_queue_depth(200_usize);
    tracing::info!("Tor PoW defence enabled (hs-pow-full, queue_depth=200)");
}
```

**Key persistence:** Arti stores the hidden service's Ed25519 identity key in its keystore keyed by `HsNickname`. The `state_dir` must be persistent across restarts to maintain a stable `.onion` address.

**PoW licensing note:** Arti's `hashx` and `equix` crates are LGPL-licensed. The binary linking them is LGPL-encumbered. The `arti` Cargo feature is **not** in `default` — operators must explicitly build with it and pass `--pow` at runtime to use it. This keeps standard builds free of LGPL obligations:

```toml
[features]
default = ["tordaemon"]      # C Tor daemon backend on by default
tordaemon = []               # CTorProvider; requires tor binary on host
arti = [...]                 # ArtiTorProvider — see joinmarket-tor/Cargo.toml
```

### `ctor_backend.rs` (feature = `"tordaemon"`, default)

Default backend. Reads the `.onion` address from `<hidden_service_dir>/hostname` (written by C Tor on first start) and binds a local TCP listener on `serving_host:serving_port`. Implements the same `TorProvider` trait.

C Tor must be pre-configured in `torrc` by the operator with the matching `HiddenServiceDir` and `HiddenServicePort`. There is no control-port connection — `CTorProvider` is a pure TCP listener. PoW defence for C Tor must also be configured in `torrc` by the operator; `--pow` is not available for tordaemon builds.

---

## Crate 3: `joinmarket-dn`

The binary. Depends on `joinmarket-core` and `joinmarket-tor`.

### `main.rs`

CLI via `clap`:

```
joinmarket-dn [OPTIONS] [OPERATOR_MESSAGE]

Options:
  --datadir <PATH>      Data directory [default: ~/.joinmarket].
                          Must contain joinmarket.cfg with [MESSAGING:onion]
                          and [BLOCKCHAIN] sections. Resolved at runtime via
                          $HOME; process aborts if $HOME is unset and --datadir
                          is not provided.
  --metrics-bind <ADDR>  Prometheus metrics bind address [default: 127.0.0.1:9090]
  --pow                  Enable Tor PoW DoS defence (requires a binary built
                           with --features arti)
                         [only present when built with the `arti` feature]

Network, port, hidden service directory, and other settings are read from
joinmarket.cfg (located in the data directory). If no config file exists,
a default one is created and the process exits for the operator to review it.

Arguments:
  [OPERATOR_MESSAGE]    Optional operator message appended to the MOTD
```

Startup sequence:

1. Parse CLI args, resolve datadir, load config
1. Initialize tracing
1. Start Prometheus metrics server
1. Bootstrap Tor (backend determined by compile-time feature flag)
1. Build MOTD string
1. Start heartbeat loop
1. Enter accept loop

### `peer.rs` — Per-Peer Handler

```
State: AwaitingHandshake → Active(Maker|Taker) → Disconnected
```

```rust
pub enum PeerRole { Maker, Taker }

/// Shared, read-only context for all peer tasks. Created once in the accept
/// loop and wrapped in `Arc` to avoid per-connection cloning.
pub struct PeerContext {
    pub router: Arc<Router>,
    pub admission: Arc<AdmissionController>,
    pub network: Arc<str>,
    pub motd: Arc<str>,
    pub directory_onion: Arc<str>,
    pub directory_nick: Arc<str>,
}
```

**Peer classification rule:** A peer is a Maker if its handshake `location-string` is non-empty AND passes `OnionServiceAddr::parse()`. A peer whose `location-string` is empty is a Taker. A peer whose `location-string` is non-empty but fails validation is **disconnected immediately** — it is neither registered as a Maker nor a Taker.

**Onion ownership is not verified:** `OnionServiceAddr::parse()` validates only the *format* of the claimed address (base32 encoding, SHA3-256 checksum, version byte `0x03`). It does not verify that the connecting peer controls the claimed onion. A peer may supply any syntactically valid address and be classified as a Maker; however, takers who later try to connect directly to that address will reach whoever actually runs it — not the claimer — so coinjoin completion is impossible without genuine ownership. This is a protocol-level limitation shared by Python JoinMarket; fixing it would require a circuit-binding ownership proof (signing a DN challenge with the onion's Ed25519 private key over the Tor circuit).

**Message framing:** Messages are `\n`-terminated strings. Maximum line length: 40,000 bytes (matching Python JoinMarket's `MAX_LENGTH`). Lines are read via a bounded `read_line_bounded()` helper that prevents OOM by rejecting lines before allocating beyond the limit. Peers that exceed this are disconnected.

**From-nick validation:** For both pubmsg and privmsg, the `from_nick` extracted from the message line is verified against the peer's authenticated nick. Mismatches cause immediate disconnect to prevent nick spoofing.

**Per-peer broadcast rate limiting:** Each peer is limited to 30 pubmsg broadcasts per 60-second window. Peers exceeding this limit are disconnected to prevent broadcast channel flooding.

**Handshake timeout:** 10 seconds. Disconnect peers that do not complete handshake within this window.

### `router.rs` — Separate Maker and Taker Registries

**IMPORTANT:** The `Router` maintains two separate registries. `GETPEERLIST` (envelope type 791) returns ONLY the makers registry — never takers. This is because:

- The full maker list must be returned (takers need complete market visibility to apply fidelity bond weighting, fee filters, and amount range matching — criteria the directory node is not privy to)
- Takers are transient; including them in `PEERLIST` responses would be incorrect and leak privacy

```rust
/// Broadcast message carrying the sender's nick for echo filtering.
/// Peers skip messages where `sender_nick` matches their own nick.
/// System messages (e.g., disconnect notifications) use an empty `sender_nick`.
pub struct BroadcastMsg {
    pub sender_nick: Arc<str>,
    pub payload: Arc<str>,
}

pub struct Router {
    makers: ShardedRegistry<MakerInfo>,            // nick → MakerInfo
    takers: ShardedRegistry<TakerInfo>,            // nick → TakerInfo (not exposed via GETPEERLIST)
    broadcast_tx: broadcast::Sender<BroadcastMsg>,
    peer_meta: DashMap<Arc<str>, PeerMeta>,        // per-peer metadata
    dn_nick: Mutex<String>,                        // directory node's own nick
    dn_location: Mutex<String>,                    // directory node's onion location
}

pub struct MakerInfo {
    pub nick: Arc<str>,
    pub onion_address: OnionServiceAddr,      // always valid — enforced at admission
    pub fidelity_bond: Option<Arc<FidelityBondProof>>,
    pub last_ann: Option<String>,             // most recent offer announcement text
}

pub struct TakerInfo {
    pub nick: Arc<str>,
    pub onion_address: Option<OnionServiceAddr>, // validated if present, else None
}

impl Router {
    pub fn register_maker(&self, info: MakerInfo);
    pub fn register_taker(&self, info: TakerInfo);
    pub fn deregister(&self, nick: &str);

    // Returns ALL makers — not sampled, not filtered.
    // At >20k active makers, returns random sample of ~4000 with metadata.
    pub fn get_peers_response(&self) -> PeersResponse;

    // For private message routing: return target's onion location-string
    // Searches makers first, then falls back to takers.
    pub fn locate_peer(&self, nick: &str) -> Option<String>;

    // Broadcast to all connected peers except sender.
    pub fn broadcast(&self, sender_nick: &str, msg: Arc<str>);
    // Broadcast a system message with no sender echo filter (e.g., disconnect notifications).
    pub fn broadcast_raw(&self, msg: Arc<str>);
    // Subscribe to the broadcast channel.
    pub fn subscribe(&self) -> broadcast::Receiver<BroadcastMsg>;
}

pub struct PeersResponse {
    pub peers: Vec<MakerInfo>,
    pub total_makers: usize,
    pub returned: usize,
    pub sampling: Option<&'static str>,
    pub request_more: bool,
}
```

**ShardedRegistry:** 64 shards, keyed by a hash of the full nick string modulo 64. Each shard is a `parking_lot::Mutex<HashMap<Arc<str>, PeerInfo>>`. The hash uses a `RandomState` seeded with OS random bytes at construction time (via `BuildHasher::hash_one()`), preventing an adversary from crafting nicks that all collide on one shard. This avoids a single global lock hot-spot at high peer counts and ensures even distribution across shards regardless of nick prefix patterns.

**Broadcast channel:** A single `tokio::sync::broadcast` channel (capacity 256) delivers public messages to all connected peers. All public commands (`!orderbook`, `!hp2`, offer announcements, `!cancel`, `!tbond`) flow through this channel. Both maker and taker peer tasks subscribe via `router.subscribe()`. When a peer falls behind by more than 256 slots it receives `RecvError::Lagged` and is disconnected; the metric `jm_broadcast_lag_evictions_total` tracks evictions.

### `admission.rs` — Multi-Layer Defence

All layers are enforced in order. A connection that fails any layer is rejected before consuming further resources.

```rust
pub struct AdmissionController {
    sybil_guard:   SybilGuard,             // Layer 2
    bond_registry: FidelityBondRegistry,   // Layer 3
    maker_count:   AtomicU32,              // Layer 4
    // Layer 1 (Tor PoW) is enforced by Arti before any Rust code runs
    // (arti feature only; not available for the tordaemon backend)
}

impl AdmissionController {
    // Call after successful handshake parse, before registering in Router
    pub fn admit_peer(
        &self,
        nick: &str,
        onion_addr: &OnionServiceAddr, // pre-validated — OnionServiceAddr is only constructible via parse()
        is_maker: bool,
        bond: Option<&FidelityBondProof>,
    ) -> Result<(), AdmissionError>;

    // Call on disconnect (cleanup all state — pass is_maker to decrement maker count)
    pub fn release_peer(&self, nick: &str, is_maker: bool);
}
```

#### Layer 1 — Tor PoW (opt-in via `--pow`)

Disabled by default. Available only for arti builds (`--features arti`). When `--pow` is passed, Arti calls `enable_pow(true)` and `pow_rend_queue_depth(200)` on the `OnionServiceConfig` builder (requires the `hs-pow-full` Cargo feature, included automatically). Dynamic Equi-X puzzle, effort scales automatically with queue depth, dormant when not under load. `--pow` is not available for tordaemon builds — operators must configure PoW in `torrc` manually for C Tor.

#### Layer 2 — Sybil Guard (`sybil_guard.rs`)

One active nick per onion address. If onion A already has nick X registered and attempts to register nick Y while X is still live, reject Y. If X has already disconnected (stale), allow Y (legitimate restart).

```rust
// Keyed by OnionAddress (host only, port excluded).
// This prevents an attacker varying the port number to register multiple nicks
// from the same hidden service while appearing to have distinct addresses.
// Both maps are protected by a single parking_lot::Mutex for atomic updates.
pub struct SybilGuard {
    inner: Mutex<SybilMaps>,  // atomic update of both directions
}
struct SybilMaps {
    onion_to_nick: HashMap<OnionAddress, String>,
    nick_to_onion: HashMap<String, OnionAddress>,
}

impl SybilGuard {
    pub fn register(&self, nick: &str, onion: &OnionAddress) -> Result<(), SybilError>;
    pub fn deregister(&self, nick: &str);
    pub fn is_nick_active(&self, nick: &str) -> bool;
}
```

#### Layer 3 — Fidelity Bond UTXO Deduplication (`bond_registry.rs`)

One fidelity bond UTXO may only be claimed by one nick at a time. Prevents a single locked UTXO from inflating its weight across many nicks.

```rust
// Both maps protected by a single parking_lot::Mutex for atomic updates.
pub struct FidelityBondRegistry {
    inner: Mutex<BondMaps>,
}

impl FidelityBondRegistry {
    pub fn register_bond(&self, nick: &str, bond: &FidelityBondProof) -> Result<(), BondError>;
    pub fn deregister_nick(&self, nick: &str);
}
```

Note: directory node does NOT verify bond against Bitcoin blockchain (`no-blockchain`). Takers verify independently. Deduplication alone is sufficient to prevent weight inflation.

#### Layer 4 — Maker Capacity Cap (`admission.rs`)

```rust
const MAX_CONCURRENT_MAKERS: u32 = 100_000;
```

Atomically reserves a slot via `fetch_add`; rolls back all prior layers on failure.

### `heartbeat.rs`

Three-step liveness sweep every minute. Clears zombie connections that TCP keepalive alone cannot detect (Tor circuits can be silently dropped).

**Timing constants:**
- Idle check interval: **60 seconds** (1 min)
- Write probe threshold: **600 seconds** (10 min idle)
- Hard evict threshold: **1500 seconds** (25 min idle)
- Pong timeout: **30 seconds**

**Algorithm (each sweep):**
1. **Hard-evict** peers idle >25 min (no probe — they are assumed dead)
2. **Probe** peers idle >10 min, branching on capability:
   - **Ping-capable peers**: send PING (envelope type 797); wait 30 s; evict non-responders.
   - **Non-ping makers** (Python JoinMarket clients): send a unicast `!orderbook` PUBMSG. The maker responds with offer privmsgs which flow through the normal receive path, updating `last_seen`. No explicit timeout — hard eviction at 25 min covers non-responders.
   - **Non-ping takers**: no probe; hard-evicted at 25 min if silent.
3. **Wait 30 seconds**, then evict ping-capable peers that did not respond with PONG (type 799)

```rust
pub async fn heartbeat_loop(router: Arc<Router>, shutdown: CancellationToken) {
    // Delayed start — waits one interval before first sweep
    // Uses tokio::select! with shutdown.cancelled() at each step
    // ...
}
```

### `metrics.rs`

Prometheus metrics via `metrics` + `metrics-exporter-prometheus` crates. Expose on `--metrics-bind` (default `127.0.0.1:9090`). Metrics are registered at usage sites via `metrics::counter!()`, `metrics::gauge!()`, etc.

```
# Peer counts
jm_peers_active{role="maker|taker"}         gauge
jm_peers_total_registered{role="maker|taker"} counter

# Handshake outcomes
jm_handshakes_total{result="ok|eof|error|timeout|parse_error|proto_mismatch|network_mismatch"}  counter

# Message routing
jm_router_locate_duration_seconds           histogram
jm_router_locate_hits_total                 counter
jm_router_locate_misses_total              counter

# Rate limiting
jm_pubmsg_rate_limit_disconnects_total     counter

# Admission defence layer hits
jm_admission_invalid_onion_total           counter  # bad location-string → disconnect
jm_admission_sybil_rejections_total        counter  # Layer 2
jm_admission_bond_dup_rejections_total     counter  # Layer 3
jm_admission_maker_cap_rejections_total    counter  # Layer 4

# Heartbeat
jm_heartbeat_evictions_total               counter
jm_heartbeat_ping_probes_total             counter  # !ping probes sent to ping-capable peers
jm_heartbeat_orderbook_probes_total        counter  # !orderbook probes sent to non-ping makers

jm_messages_broadcast_total                counter
jm_broadcast_lag_evictions_total           counter
```

---

## Key Routing Behaviours

### Public message (offers like `!sw0absoffer`, `!orderbook`, etc.)

1. Receive PUBMSG (envelope type 687) from peer
1. Validate `from_nick` matches the peer's authenticated nick (disconnect on mismatch)
1. Enforce per-peer rate limit (30 pubmsg per 60-second window)
1. If sender is a Maker and the message is an offer command, update `last_ann` in `MakerInfo`
1. Broadcast to all connected peers via `router.broadcast()`

### Private message routing (`!fill`, `!ioauth`, etc.)

1. Receive PRIVMSG (envelope type 685) from a peer
1. Validate `from_nick` matches the peer's authenticated nick (disconnect on mismatch)
1. Look up `target_nick` in Router via `locate_peer()` → get their onion address
1. Forward the PRIVMSG envelope to the target peer
1. Send a PEERLIST (type 789) to the target containing the sender's onion address, enabling direct peer-to-peer connection

### `GETPEERLIST` request (envelope type 791)

1. Receive GETPEERLIST from any peer
1. Call `router.get_peers_response()`
1. If `≤20,000` makers: return full list
1. If `>20,000` makers: return random sample of ~4,000 with metadata
1. Respond with PEERLIST (envelope type 789) containing comma-separated `nick;location` pairs

---

## Dependency Reference

### `joinmarket-core/Cargo.toml`

```toml
[dependencies]
secp256k1 = { version = "0.30", features = ["global-context", "rand", "recovery"] }
x25519-dalek = { version = "2", features = ["static_secrets", "getrandom"] }
crypto_secretbox = "0.1"     # XSalsa20Poly1305 for NaCl box encryption
bitcoin_hashes = "0.13"
bs58 = "0.5"
data-encoding = "2"          # BASE32_NOPAD for onion address decoding
sha3 = "0.10"                # Sha3_256 for onion address checksum verification
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
rand = "0.8"
base64 = "0.21"
```

### `joinmarket-tor/Cargo.toml`

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
futures = "0.3"
async-trait = "0.1"
anyhow = "1"
thiserror = "1"
tracing = "0.1"

[dependencies.arti-client]
version = "0.40"
default-features = false
features = ["onion-service-service", "hs-pow-full", "tokio", "rustls", "compression"]
optional = true

[dependencies.tor-hsservice]
version = "0.40"
optional = true

[dependencies.tor-rtcompat]
version = "0.40"
default-features = false
features = ["tokio", "rustls"]
optional = true

[dependencies.tor-cell]
version = "0.40"
optional = true

[dependencies.safelog]
version = "0.8"
optional = true


[features]
default = ["tordaemon"]
tordaemon = []   # C Tor daemon backend (CTorProvider); requires tor binary on host
arti = [         # Arti embedded Tor backend
    "dep:arti-client",
    "dep:tor-hsservice",
    "dep:tor-rtcompat",
    "dep:tor-cell",
    "dep:safelog",
]
```

### `joinmarket-dn/Cargo.toml`

```toml
[dependencies]
joinmarket-core = { path = "../joinmarket-core" }
joinmarket-tor = { path = "../joinmarket-tor", default-features = false }
tokio = { version = "1", features = ["full"] }
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
dashmap = "5"
parking_lot = "0.12"
rand = "0.8"
tokio-util = { version = "0.7", features = ["codec"] }
anyhow = "1"
thiserror = "1"
base64 = "0.21"
metrics = "0.22"
metrics-exporter-prometheus = { version = "0.15", default-features = false, features = ["http-listener"] }
```

---

## Memory Budget (Target: 100k concurrent peers)

| Resource            | Per-peer  | 100k total |
|---------------------|-----------|------------|
| Tokio task stack    | ~6 KB     | ~600 MB    |
| Read buffer (4 KB)  | 4 KB      | ~400 MB    |
| Write buffer (4 KB) | 4 KB      | ~400 MB    |
| PeerMeta in DashMap  | ~128 B    | ~13 MB     |
| Nick index entry    | ~200 B    | ~20 MB     |
| Broadcast handle    | ~80 B     | ~8 MB      |
| **Total**           | **~14 KB**| **~1.4 GB**|

Use 4 KB `BufReader`/`BufWriter` (not the default 8 KB). JoinMarket messages are always under 2 KB.

Use `Arc<str>` not `String` for nicks and broadcast payloads stored in the registry (immutable shared strings, one allocation per unique value).

Use `ShardedRegistry<T>` (64 `parking_lot::Mutex<HashMap<Arc<str>, T>>` shards) for maker/taker registries, and `DashMap<Arc<str>, PeerMeta>` for peer metadata.
