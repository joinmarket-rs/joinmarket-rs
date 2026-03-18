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
│       │   ├── admission.rs          # AdmissionController (all 5 defence layers)
│       │   ├── sybil_guard.rs        # Layer 3: onion → one active nick
│       │   ├── bond_registry.rs      # Layer 4: UTXO deduplication
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
    pub fn verify_signature(&self, msg: &[u8], sig: &NickSig) -> bool;
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
pub enum MessageCommand {
    Ann, Orderbook,                        // public broadcast
    Fill, AbsOrder, RelOrder, IoAuth,      // private coinjoin negotiation
    TxSigs, PushTx, Disconnect,
    Getpeers, Peers,                       // directory-specific
    Ping, Pong,                            // heartbeat
}

pub struct JmMessage {
    pub command: MessageCommand,
    pub fields: Vec<String>,
    pub nick_sig: Option<NickSig>,
}

impl JmMessage {
    pub fn parse(raw: &str) -> Result<Self, ParseError>;
    pub fn serialize(&self) -> String;
}
```

### `handshake.rs`

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeMessage {
    #[serde(rename = "app-name")]
    pub app_name: String,          // must be "joinmarket"
    pub directory: bool,           // true for directory nodes
    #[serde(rename = "location-string")]
    pub location_string: String,   // "xxxx.onion:5222"
    #[serde(rename = "proto-ver")]
    pub proto_ver: u8,             // currently 5
    pub features: HashMap<String, serde_json::Value>,
    pub nick: String,
    pub network: String,           // "mainnet" | "testnet" | "signet"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub motd: Option<String>,      // only sent by directory nodes
}

// Validation rules:
// - app_name == "joinmarket"
// - proto_ver == our configured version (currently 5)
// - network matches our configured network
// - nick is well-formed (correct length, correct prefix byte)
// - location_string, if non-empty, must parse as a valid OnionServiceAddr (Tor v3 + valid port)
//   → if location_string is non-empty and fails OnionServiceAddr::parse(), DISCONNECT immediately
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

Dependencies: `secp256k1` (with `global-context` feature), `x25519-dalek`, `xsalsa20poly1305`

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
#[async_trait]
pub trait TorProvider: Send + Sync {
    async fn listen(&self, port: u16) -> Result<Box<dyn IncomingStream>, TorError>;
    async fn connect(&self, addr: &str) -> Result<Box<dyn AsyncReadWrite>, TorError>;
    fn onion_address(&self) -> &str;
}
```

### `arti_backend.rs` (feature = `"arti"`)

Bootstrap sequence:

```rust
pub async fn bootstrap_tor(state_dir: &Path) -> Result<TorClient<PreferredRuntime>, ArtiError> {
    let config = TorClientConfig::builder()
        .storage()
            .cache_dir(state_dir.join("arti-cache"))
            .state_dir(state_dir.join("arti-state"))
            .build()?
        .build()?;
    TorClient::create_bootstrapped(config).await
}
```

Onion service launch (PoW disabled unless `--pow` was passed on the command line). Inside `ArtiTorProvider::bootstrap`:

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
arti = ["arti-client/onion-service-service", "equix", "hashx"]  # ArtiTorProvider + PoW
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
joinmarket-dn [OPTIONS] [MOTD]

Options:
  --datadir <PATH>     Data directory [default: the standard JoinMarket config directory:
                         Linux/macOS: ~/.joinmarket
                         Resolved at runtime via $HOME; process aborts if $HOME is unset
                         and --datadir is not provided]
  --config <PATH>      Config file [default: <datadir>/joinmarket.cfg]
  --network <NET>      mainnet | testnet | signet [default: mainnet]
  --port <PORT>        Listening port [default: 5222]
  --metrics-bind <ADDR> Prometheus metrics bind address [default: 127.0.0.1:9090]
  --pow                Enable Tor PoW DoS defence (off by default; only available
                         when built with --features arti; requires the hs-pow-full
                         feature which is included automatically)
                       [only present when built with the `arti` feature]
  --state-dir <PATH>   Arti state directory — required for key persistence.
                         Arti stores the hidden service Ed25519 key here; without it
                         the .onion address changes on every restart.
                         Selects the Arti backend when both backends are compiled.
                         [only present when built with the `arti` feature]
  --hidden-service-dir Path to the C Tor hidden service directory — required for key
                         persistence. C Tor stores the hidden service Ed25519 key here;
                         without it the .onion address changes on every restart.
                         Selects the C Tor backend when both backends are compiled.
                         [only present when built with the `tordaemon` feature]

When both `arti` and `tordaemon` features are compiled in, exactly one of
--state-dir or --hidden-service-dir must be provided; they are mutually exclusive
and the one supplied determines which Tor backend is used.

Arguments:
  [MOTD]               Message of the day sent to connecting peers
```

Startup sequence:

1. Parse config + CLI args
1. Bootstrap Arti (log progress to console)
1. Launch onion service → print `.onion` address to stdout
1. Start Prometheus metrics server
1. Start heartbeat loop
1. Enter accept loop

### `peer.rs` — Per-Peer State Machine

```
State: AwaitingHandshake → Active(Maker|Taker) → Disconnected
```

```rust
pub enum PeerRole { Maker, Taker }

pub struct PeerState {
    pub nick: Nick,
    pub onion_address: Option<OnionServiceAddr>, // None for takers without a hidden service
    pub role: PeerRole,
    pub connected_at: Instant,
    pub last_seen: Instant,
    pub awaiting_pong: bool,
}
```

**Peer classification rule:** A peer is a Maker if its handshake `location-string` is non-empty AND passes `OnionServiceAddr::parse()`. A peer whose `location-string` is empty is a Taker. A peer whose `location-string` is non-empty but fails validation is **disconnected immediately** — it is neither registered as a Maker nor a Taker.

**Message framing:** Messages are `\n`-terminated strings. Maximum line length: 40,000 bytes (matching Python JoinMarket's `MAX_LENGTH`). Lines are read via a bounded `read_line_bounded()` helper that prevents OOM by rejecting lines before allocating beyond the limit. Peers that exceed this are disconnected.

**From-nick validation:** For both pubmsg and privmsg, the `from_nick` extracted from the message line is verified against the peer's authenticated nick. Mismatches cause immediate disconnect to prevent nick spoofing.

**Per-peer broadcast rate limiting:** Each peer is limited to 30 pubmsg broadcasts per 60-second window. Peers exceeding this limit are disconnected to prevent broadcast channel flooding.

**Handshake timeout:** 10 seconds. Disconnect peers that do not complete handshake within this window.

### `router.rs` — Separate Maker and Taker Registries

**IMPORTANT:** The `Router` maintains two separate registries. `!getpeers` returns ONLY the makers registry — never takers. This is because:

- The full maker list must be returned (takers need complete market visibility to apply fidelity bond weighting, fee filters, and amount range matching — criteria the directory node is not privy to)
- Takers are transient; including them in `!getpeers` responses would be incorrect and leak privacy

```rust
pub struct Router {
    makers: ShardedRegistry,              // nick → MakerInfo
    takers: ShardedRegistry,              // nick → TakerInfo (not exposed via !getpeers)
    public_tx: broadcast::Sender<Arc<str>>, // one allocation per broadcast message
}

pub struct MakerInfo {
    pub nick: String,
    pub onion_address: OnionServiceAddr,      // always valid — enforced at admission
    pub fidelity_bond: Option<FidelityBondProof>,
    pub last_ann: Option<String>,  // most recent !ann message text
}

pub struct TakerInfo {
    pub nick: String,
    pub onion_address: Option<OnionServiceAddr>, // validated if present, else None
}

impl Router {
    pub fn register_maker(&self, info: MakerInfo);
    pub fn register_taker(&self, info: TakerInfo);
    pub fn deregister(&self, nick: &str);

    // Returns ALL makers — not sampled, not filtered.
    // At >20k active makers, returns bond-weighted sample of 3000-5000 with metadata.
    pub fn get_peers_response(&self) -> PeersResponse;

    // For private message routing: return target's onion address
    pub fn locate_peer(&self, nick: &str) -> Option<String>;

    // Broadcast public message to all connected peers except sender
    // Uses broadcast::Sender<Arc<str>> — one allocation regardless of peer count
    pub fn broadcast(&self, sender_nick: &str, msg: Arc<str>);
}

pub struct PeersResponse {
    pub peers: Vec<MakerInfo>,
    pub total_makers: usize,
    pub returned: usize,
    pub sampling: Option<&'static str>,  // "bond_weighted" if sampled, else None
    pub request_more: bool,
}
```

**ShardedRegistry:** 64 shards, keyed by a hash of the full nick string modulo 64 (using `DefaultHasher`). Each shard is a `parking_lot::Mutex<HashMap<Arc<str>, PeerInfo>>`. This avoids a single global lock hot-spot at high peer counts and ensures even distribution across shards regardless of nick prefix patterns.

**Broadcast channel:** Use `tokio::sync::broadcast::channel` with capacity 1024. All connected peer tasks hold a `Receiver`. When a peer lags (falls behind by >1024 messages), it receives `RecvError::Lagged` and is disconnected.

### `admission.rs` — Five-Layer Defence

All five layers are enforced in order. A connection that fails any layer is rejected before consuming further resources.

```rust
pub struct AdmissionController {
    connection_rate: ConnectionRateLimiter,  // Layer 2
    sybil_guard:     SybilGuard,             // Layer 3
    bond_registry:   FidelityBondRegistry,   // Layer 4
    maker_throttle:  MakerThrottle,          // Layer 5
    // Layer 1 (Tor PoW) is enforced by Arti before any Rust code runs
    // (arti feature only; not available for the tordaemon backend)
}

impl AdmissionController {
    // Call immediately after accept(), before reading any bytes
    pub fn check_connection(&self, onion_addr: &str) -> Result<(), AdmissionError>;

    // Call after successful handshake parse, before registering in Router
    pub fn admit_peer(
        &self,
        nick: &str,
        onion_addr: &OnionServiceAddr, // pre-validated — OnionServiceAddr is only constructible via parse()
        is_maker: bool,
        bond: Option<&FidelityBondProof>,
    ) -> Result<(), AdmissionError>;

    // Call on disconnect (cleanup all state)
    pub fn release_peer(&self, nick: &str);
}
```

#### Layer 1 — Tor PoW (opt-in via `--pow`)

Disabled by default. Available only for arti builds (`--features arti`). When `--pow` is passed, Arti calls `enable_pow(true)` and `pow_rend_queue_depth(200)` on the `OnionServiceConfig` builder (requires the `hs-pow-full` Cargo feature, included automatically). Dynamic Equi-X puzzle, effort scales automatically with queue depth, dormant when not under load. `--pow` is not available for tordaemon builds — operators must configure PoW in `torrc` manually for C Tor.

#### Layer 2 — Connection Rate Limiter (`admission.rs`)

```rust
// Sliding 60-second window per onion address
const MAX_CONNECTIONS_PER_ONION_PER_MINUTE: u32 = 3;

pub struct ConnectionRateLimiter {
    windows: DashMap<String, RateWindow>,  // onion_addr → sliding window
}
```

#### Layer 3 — Sybil Guard (`sybil_guard.rs`)

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
    pub fn register(&self, nick: &str, onion: &str) -> Result<(), SybilError>;
    pub fn deregister(&self, nick: &str);
    fn is_nick_active(&self, nick: &str) -> bool;
}
```

#### Layer 4 — Fidelity Bond UTXO Deduplication (`bond_registry.rs`)

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

#### Layer 5 — Maker Registration Throttle (`admission.rs`)

```rust
const MAX_NEW_MAKER_REGISTRATIONS_PER_MINUTE: u32 = 60;
const MAX_CONCURRENT_MAKERS: u32 = 100_000;

pub struct MakerThrottle {
    recent_registrations: Mutex<VecDeque<Instant>>,
    current_count: AtomicU32,
}
```

### `heartbeat.rs`

Every 60 seconds, send `!ping` to all active peers. Peers that do not respond with `!pong` within 10 seconds are deregistered and their connections closed. This clears zombie connections that TCP keepalive alone cannot detect (Tor circuits can be silently dropped).

```rust
pub async fn heartbeat_loop(router: Arc<Router>, shutdown: CancellationToken) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let timed_out = router.ping_all_and_collect_timeouts(
                    Duration::from_secs(10)
                ).await;
                for nick in timed_out {
                    router.deregister(&nick);
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }
}
```

### `metrics.rs`

Prometheus metrics via `metrics` + `metrics-exporter-prometheus` crates. Expose on `--metrics-bind` (default `127.0.0.1:9090`).

```
# Peer counts
jm_peers_active{role="maker"}           gauge
jm_peers_active{role="taker"}           gauge
jm_peers_total_registered{role}         counter

# Handshake outcomes
jm_handshakes_total{result="ok|timeout|proto_mismatch|network_mismatch"}  counter

# Message routing
jm_messages_broadcast_total             counter
jm_broadcast_lag_evictions_total        counter  # peers dropped for lagging
jm_router_locate_duration_seconds       histogram

# Admission defence layer hits
jm_admission_invalid_onion_total           counter  # bad location-string → disconnect
jm_admission_rate_limit_rejections_total   counter  # Layer 2
jm_admission_sybil_rejections_total        counter  # Layer 3
jm_admission_bond_dup_rejections_total     counter  # Layer 4
jm_admission_maker_cap_rejections_total    counter  # Layer 5

# Tor
# jm_pow_effort_current: not implemented — tor-hsservice 0.40 exposes no API
#   to query the current PoW effort level at runtime.
```

---

## Key Routing Behaviours

### Public message (`!ann`, `!orderbook`)

1. Receive message from peer
1. Validate nick signature
1. If sender is a Maker, update `last_ann` in `MakerInfo`
1. `router.broadcast(sender_nick, msg)` — fans out via broadcast channel to all peers

### Private message routing (`!fill`, `!ioauth`, etc.)

1. Receive `!fill <target_nick> <amount> ...` from a Taker
1. Look up `target_nick` in Router → get their onion address
1. Respond to sender with the target's onion address
1. **Do not relay the message content** — sender connects directly to target

### `!getpeers` request

1. Receive `!getpeers` from any peer
1. Call `router.get_peers_response()`
1. If `≤20,000` makers: return full list
1. If `>20,000` makers: return bond-weighted sample of 3,000–5,000 with metadata (`total_makers`, `returned`, `sampling: "bond_weighted"`, `request_more: true`)
1. Respond with `!peers <json_blob>`

Bond weight formula (for sampling at scale): `bond_value = (locked_coins × (exp(r × locktime) − 1))²`

---

## Dependency Reference

### `joinmarket-core/Cargo.toml`

```toml
[dependencies]
secp256k1 = { version = "0.28", features = ["global-context"] }
x25519-dalek = "2"
xsalsa20poly1305 = "0.9"
bitcoin_hashes = "0.13"
bs58 = "0.5"
data-encoding = "2"          # BASE32_NOPAD for onion address decoding
sha3 = "0.10"                # Sha3_256 for onion address checksum verification
serde = { version = "1", features = ["derive"] }
serde_json = "1"
ini = "1"
thiserror = "1"
```

### `joinmarket-tor/Cargo.toml`

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
futures = "0.3"
async-trait = "0.1"
anyhow = "1"
thiserror = "1"

[dependencies.arti-client]
version = "0.23"
features = ["onion-service-service"]
optional = true

[dependencies.tor-hsservice]
version = "0.23"
optional = true

[dependencies.tor-rtcompat]
version = "0.23"
optional = true

[dependencies.tor-keymgr]
version = "0.23"
optional = true

[features]
default = ["tordaemon"]
tordaemon = []               # CTorProvider (default); requires tor binary on host
arti = ["arti-client", "tor-hsservice", "tor-rtcompat", "tor-keymgr", "equix", "hashx"]
```

### `joinmarket-dn/Cargo.toml`

```toml
[dependencies]
joinmarket-core = { path = "../joinmarket-core" }
joinmarket-tor  = { path = "../joinmarket-tor" }
tokio = { version = "1", features = ["full"] }
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
dashmap = "5"
slab = "0.4"
metrics = "0.22"
metrics-exporter-prometheus = "0.13"
tokio-util = { version = "0.7", features = ["codec"] }
anyhow = "1"
thiserror = "1"
tokio-util = "0.7"
```

---

## Memory Budget (Target: 100k concurrent peers)

| Resource            | Per-peer  | 100k total |
|---------------------|-----------|------------|
| Tokio task stack    | ~6 KB     | ~600 MB    |
| Read buffer (4 KB)  | 4 KB      | ~400 MB    |
| Write buffer (4 KB) | 4 KB      | ~400 MB    |
| PeerState in slab   | ~128 B    | ~13 MB     |
| Nick index entry    | ~200 B    | ~20 MB     |
| Broadcast handle    | ~80 B     | ~8 MB      |
| **Total**           | **~14 KB**| **~1.4 GB**|

Use 4 KB `BufReader`/`BufWriter` (not the default 8 KB). JoinMarket messages are always under 2 KB.

Use `Arc<str>` not `String` for nicks and onion addresses stored in the registry (immutable shared strings, one allocation per unique value).

Use `slab::Slab<PeerState>` for contiguous peer state allocation.
