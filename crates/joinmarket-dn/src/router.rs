use std::collections::HashMap;
use std::hash::BuildHasher;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use joinmarket_core::onion::OnionServiceAddr;
use joinmarket_core::fidelity_bond::FidelityBondProof;
use dashmap::DashMap;

const SHARD_COUNT: usize = 64;
/// Broadcast channel capacity. All public messages are low-frequency
/// (startup announcements, !orderbook, !hp2, disconnect notifications).
const BROADCAST_CAPACITY: usize = 256;
/// Per-peer directed-message channel capacity.  Each privmsg relay pushes two
/// messages (the privmsg itself + a peerlist with the sender's location), and
/// busy makers can receive privmsgs from many takers concurrently.  The old
/// value of 16 was too small and caused silent message drops when a maker's Tor
/// circuit was slow to drain.  128 gives ample headroom.
pub(crate) const PEER_CHANNEL_CAPACITY: usize = 128;
const MAX_MAKERS_BEFORE_SAMPLE: usize = 20_000;
const SAMPLE_TARGET: usize = 4_000;

/// Result of attempting to send a directed message to a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendResult {
    /// Message was queued successfully.
    Ok,
    /// Peer exists but its channel is full (backpressure).
    ChannelFull,
    /// Peer not found in the registry or its channel is closed.
    NotFound,
}

/// Broadcast message carrying the sender's nick for echo filtering.
/// Peers skip messages where `sender_nick` matches their own nick.
/// System messages (e.g., disconnect notifications) use an empty `sender_nick`.
#[derive(Clone, Debug)]
pub struct BroadcastMsg {
    pub sender_nick: Arc<str>,
    pub payload: Arc<str>,
}

#[derive(Debug, Clone)]
pub struct MakerInfo {
    pub nick: Arc<str>,
    pub onion_address: OnionServiceAddr,
    pub fidelity_bond: Option<Arc<FidelityBondProof>>,
}

#[derive(Debug, Clone)]
pub struct TakerInfo {
    pub nick: Arc<str>,
    pub onion_address: Option<OnionServiceAddr>,
}

#[derive(Debug, Clone)]
pub struct PeerlistEntry {
    pub nick: Arc<str>,
    pub onion_address: OnionServiceAddr,
    pub advertised_features: Arc<[Arc<str>]>,
}

pub struct PeersResponse {
    pub peers: Vec<PeerlistEntry>,
    pub total_makers: usize,
    pub returned: usize,
    pub sampling: Option<&'static str>,
    pub request_more: bool,
}

const FEATURE_FLAG_PING: u8 = 0b0000_0001;
const FEATURE_FLAG_PEERLIST_FEATURES: u8 = 0b0000_0010;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedFeatures {
    known_flags: u8,
    advertised_sorted: Arc<[Arc<str>]>,
}

impl SupportedFeatures {
    pub fn new(advertised_true_features: Vec<String>) -> Self {
        let mut known_flags = 0u8;
        let mut advertised_sorted: Vec<Arc<str>> = advertised_true_features
            .into_iter()
            .map(|feature| {
                match feature.as_str() {
                    "ping" => known_flags |= FEATURE_FLAG_PING,
                    "peerlist_features" => known_flags |= FEATURE_FLAG_PEERLIST_FEATURES,
                    _ => {}
                }
                Arc::<str>::from(feature)
            })
            .collect();
        advertised_sorted.sort_unstable_by(|a, b| a.as_ref().cmp(b.as_ref()));
        SupportedFeatures {
            known_flags,
            advertised_sorted: advertised_sorted.into(),
        }
    }

    pub fn supports_ping(&self) -> bool {
        self.known_flags & FEATURE_FLAG_PING != 0
    }

    pub fn supports_peerlist_features(&self) -> bool {
        self.known_flags & FEATURE_FLAG_PEERLIST_FEATURES != 0
    }

    pub fn advertised(&self) -> Arc<[Arc<str>]> {
        self.advertised_sorted.clone()
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }
}

/// Consolidated per-peer metadata stored in a single DashMap.
struct PeerMeta {
    shutdown: CancellationToken,
    probe_tx: mpsc::Sender<Arc<str>>,
    supported_features: SupportedFeatures,
    is_maker: bool,
    last_seen: Instant,
    pong_pending: bool,
}

struct ShardedRegistry<T> {
    shards: Vec<Mutex<HashMap<Arc<str>, T>>>,
    /// Random seed chosen at construction time; prevents hash-flooding attacks
    /// where an adversary crafts nick strings that all map to the same shard.
    hash_builder: std::collections::hash_map::RandomState,
    /// Atomic entry count maintained by `insert`/`remove` so that `len()` is a
    /// single atomic load instead of locking all 64 shards.
    count: AtomicUsize,
}

impl<T: Clone> ShardedRegistry<T> {
    fn new() -> Self {
        ShardedRegistry {
            shards: (0..SHARD_COUNT)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            hash_builder: std::collections::hash_map::RandomState::new(),
            count: AtomicUsize::new(0),
        }
    }

    fn shard_for(&self, nick: &str) -> usize {
        self.hash_builder.hash_one(nick) as usize % SHARD_COUNT
    }

    fn insert(&self, nick: Arc<str>, info: T) {
        let idx = self.shard_for(&nick);
        let prev = self.shards[idx].lock().insert(nick, info);
        if prev.is_none() {
            self.count.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn remove(&self, nick: &str) -> bool {
        let idx = self.shard_for(nick);
        if self.shards[idx].lock().remove(nick).is_some() {
            self.count.fetch_sub(1, Ordering::AcqRel);
            true
        } else {
            false
        }
    }

    fn get(&self, nick: &str) -> Option<T> {
        let idx = self.shard_for(nick);
        self.shards[idx].lock().get(nick).cloned()
    }

    fn all_values(&self) -> Vec<T> {
        self.shards.iter()
            .flat_map(|s| s.lock().values().cloned().collect::<Vec<_>>())
            .collect()
    }

    /// Collect a random sample of at most `n` values from all shards without
    /// cloning every entry first.  Each shard is locked individually and its
    /// values are reservoir-sampled into the output vec, so at most `n` clones
    /// are performed regardless of the total registry size.
    fn sample_values(&self, n: usize) -> (Vec<T>, usize) {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut reservoir: Vec<T> = Vec::with_capacity(n);
        let mut total: usize = 0;
        for shard in &self.shards {
            let guard = shard.lock();
            for value in guard.values() {
                total += 1;
                if reservoir.len() < n {
                    reservoir.push(value.clone());
                } else {
                    // Reservoir sampling (Algorithm R)
                    let j = rng.gen_range(0..total);
                    if j < n {
                        reservoir[j] = value.clone();
                    }
                }
            }
        }
        (reservoir, total)
    }

    fn len(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }
}

pub struct Router {
    makers: ShardedRegistry<MakerInfo>,
    takers: ShardedRegistry<TakerInfo>,
    /// Broadcast channel for all connected peers.
    broadcast_tx: broadcast::Sender<BroadcastMsg>,
    /// Consolidated per-peer metadata (shutdown token, probe channel, ping support, last_seen, pong_pending).
    peer_meta: DashMap<Arc<str>, PeerMeta>,
    /// Directory node identity — set exactly once after Tor bootstrap via
    /// `set_identity`. `OnceLock` gives lock-free reads after initialisation
    /// and makes the "set once" contract explicit: any code that observes
    /// `None` knows the DN has not finished bootstrapping yet.
    dn_identity: std::sync::OnceLock<(Arc<str>, Arc<str>)>,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    pub fn new() -> Self {
        let (broadcast_tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Router {
            makers: ShardedRegistry::new(),
            takers: ShardedRegistry::new(),
            broadcast_tx,
            peer_meta: DashMap::new(),
            dn_identity: std::sync::OnceLock::new(),
        }
    }

    /// Subscribe to the broadcast channel.
    pub fn subscribe(&self) -> broadcast::Receiver<BroadcastMsg> {
        self.broadcast_tx.subscribe()
    }

    /// Set the directory node's own identity. Must be called exactly once
    /// after Tor bootstrap completes, before the accept loop starts.
    pub fn set_identity(&self, nick: String, location: String) {
        let pair = (Arc::from(nick.as_str()), Arc::from(location.as_str()));
        if self.dn_identity.set(pair).is_err() {
            tracing::warn!("set_identity called more than once; second call ignored");
        }
    }

    /// Returns the directory node's nick, or `None` before `set_identity` is called.
    pub fn dn_nick(&self) -> Option<Arc<str>> {
        self.dn_identity.get().map(|(n, _)| n.clone())
    }

    /// Returns the directory node's location-string, or `None` before `set_identity`.
    pub fn dn_location(&self) -> Option<Arc<str>> {
        self.dn_identity.get().map(|(_, l)| l.clone())
    }

    /// Returns `(nick, location)` as a pair once identity is set, or `None`
    /// before `set_identity` is called. Use this at call sites that need both
    /// to avoid two separate lock-free reads.
    pub fn dn_identity_pair(&self) -> Option<(Arc<str>, Arc<str>)> {
        self.dn_identity.get().map(|(n, l)| (n.clone(), l.clone()))
    }

    /// Send a message to a specific peer via its dedicated write channel.
    pub fn send_to_peer(&self, nick: &str, msg: Arc<str>) -> SendResult {
        if let Some(meta) = self.peer_meta.get(nick) {
            match meta.probe_tx.try_send(msg) {
                Ok(()) => SendResult::Ok,
                Err(mpsc::error::TrySendError::Full(_)) => SendResult::ChannelFull,
                Err(mpsc::error::TrySendError::Closed(_)) => SendResult::NotFound,
            }
        } else {
            SendResult::NotFound
        }
    }

    pub fn register_maker(&self, info: MakerInfo) {
        self.makers.insert(info.nick.clone(), info);
        let count = self.makers.len();
        metrics::gauge!("jm_peers_active", "role" => "maker").set(count as f64);
        metrics::counter!("jm_peers_total_registered", "role" => "maker").increment(1);
    }

    pub fn register_taker(&self, info: TakerInfo) {
        self.takers.insert(info.nick.clone(), info);
        let count = self.takers.len();
        metrics::gauge!("jm_peers_active", "role" => "taker").set(count as f64);
        metrics::counter!("jm_peers_total_registered", "role" => "taker").increment(1);
    }

    /// Deregister a peer from the appropriate role-specific registry.
    /// `is_maker` avoids a redundant lock + HashMap lookup on the wrong
    /// registry and ensures the gauge metric for the other role is not
    /// momentarily set to a stale value.
    pub fn deregister(&self, nick: &str, is_maker: bool) {
        if is_maker {
            self.makers.remove(nick);
            metrics::gauge!("jm_peers_active", "role" => "maker").set(self.makers.len() as f64);
        } else {
            self.takers.remove(nick);
            metrics::gauge!("jm_peers_active", "role" => "taker").set(self.takers.len() as f64);
        }
        self.peer_meta.remove(nick);
    }

    /// Register all per-peer metadata in a single insertion.
    /// Called after handshake is complete.
    pub fn register_peer_meta(
        &self,
        nick: &Arc<str>,
        token: CancellationToken,
        probe_tx: mpsc::Sender<Arc<str>>,
        supported_features: SupportedFeatures,
        is_maker: bool,
    ) {
        self.peer_meta.insert(nick.clone(), PeerMeta {
            shutdown: token,
            probe_tx,
            supported_features,
            is_maker,
            last_seen: Instant::now(),
            pong_pending: false,
        });
    }

    /// Update the `last_seen` timestamp for a peer. Called on every received message.
    pub fn update_last_seen(&self, nick: &str) {
        if let Some(mut meta) = self.peer_meta.get_mut(nick) {
            meta.last_seen = Instant::now();
        }
    }

    /// Returns `(nick, supports_ping, is_maker)` for all peers idle longer than `threshold`.
    pub fn collect_peers_for_probe(&self, threshold: Duration) -> Vec<(Arc<str>, bool, bool)> {
        self.peer_meta
            .iter()
            .filter(|e| e.value().last_seen.elapsed() >= threshold)
            .map(|e| (
                e.key().clone(),
                e.value().supported_features.supports_ping(),
                e.value().is_maker,
            ))
            .collect()
    }

    /// Hard evict all peers idle longer than `threshold` by cancelling their
    /// shutdown tokens. Removes them from `peer_meta`. Returns evicted nicks.
    pub fn collect_idle_peers(&self, threshold: Duration) -> Vec<Arc<str>> {
        let mut evicted = Vec::new();
        self.peer_meta.retain(|nick, meta| {
            if meta.last_seen.elapsed() >= threshold {
                meta.shutdown.cancel();
                evicted.push(nick.clone());
                false
            } else {
                true
            }
        });
        evicted
    }

    /// Record that `nick` responded to a `!ping`. Only relevant for ping-capable peers.
    pub fn record_pong(&self, nick: &str) {
        if let Some(mut meta) = self.peer_meta.get_mut(nick) {
            meta.pong_pending = false;
        }
    }

    /// Mark `nick` as awaiting a pong response.
    pub fn add_pong_pending(&self, nick: &str) {
        if let Some(mut meta) = self.peer_meta.get_mut(nick) {
            meta.pong_pending = true;
        }
    }

    /// Cancel shutdown tokens for all peers still awaiting a pong (they timed out),
    /// and return the list for logging/metrics.
    ///
    /// Uses `DashMap::retain` so the `pong_pending` check and the removal happen
    /// while holding the shard write lock.  `record_pong` also acquires that lock
    /// via `get_mut`, so the two operations are mutually exclusive per shard:
    /// a peer that calls `record_pong` concurrently either completes it before
    /// `retain` visits its shard (and is kept) or after (and is already removed).
    /// The previous two-phase approach (iterate-then-remove) had a window between
    /// the phases where a valid pong could arrive after the snapshot but before
    /// the removal, causing a healthy peer to be wrongly evicted.
    pub fn collect_pong_timeouts(&self) -> Vec<Arc<str>> {
        let mut timed_out = Vec::new();
        self.peer_meta.retain(|nick, meta| {
            if meta.pong_pending {
                meta.shutdown.cancel();
                timed_out.push(nick.clone());
                false  // remove from map
            } else {
                true   // keep
            }
        });
        timed_out
    }

    pub fn get_peers_response(&self) -> PeersResponse {
        let total_makers = self.makers.len();

        if total_makers <= MAX_MAKERS_BEFORE_SAMPLE {
            let all_makers = self.makers.all_values();
            let returned = all_makers.len();
            let peers = all_makers
                .into_iter()
                .map(|maker| self.maker_to_peerlist_entry(maker))
                .collect();
            PeersResponse {
                returned,
                peers,
                total_makers: returned,
                sampling: None,
                request_more: false,
            }
        } else {
            // Use reservoir sampling to pick SAMPLE_TARGET entries without
            // cloning the entire registry into a temporary Vec first.
            let (sample, actual_total) = self.makers.sample_values(SAMPLE_TARGET);
            let returned = sample.len();
            let peers = sample
                .into_iter()
                .map(|maker| self.maker_to_peerlist_entry(maker))
                .collect();
            PeersResponse {
                peers,
                total_makers: actual_total,
                returned,
                sampling: Some("random"),
                request_more: true,
            }
        }
    }

    pub fn locate_peer(&self, nick: &str) -> Option<String> {
        let start = std::time::Instant::now();
        let result = self.makers.get(nick)
            .map(|m| m.onion_address.as_location_string())
            .or_else(|| {
                self.takers.get(nick)
                    .and_then(|t| t.onion_address.as_ref().map(|a| a.as_location_string()))
            });
        metrics::histogram!("jm_router_locate_duration_seconds").record(start.elapsed().as_secs_f64());
        result
    }

    pub fn peer_supports_peerlist_features(&self, nick: &str) -> bool {
        self.peer_meta.get(nick)
            .is_some_and(|meta| meta.supported_features.supports_peerlist_features())
    }

    pub fn peer_advertised_features(&self, nick: &str) -> Option<Arc<[Arc<str>]>> {
        self.peer_meta.get(nick)
            .map(|meta| meta.supported_features.advertised())
    }

    fn maker_to_peerlist_entry(&self, maker: MakerInfo) -> PeerlistEntry {
        let advertised_features = self.peer_advertised_features(maker.nick.as_ref())
            .unwrap_or_default();
        PeerlistEntry {
            nick: maker.nick,
            onion_address: maker.onion_address,
            advertised_features,
        }
    }

    /// Broadcast to all connected peers (makers and takers).
    pub fn broadcast(&self, sender_nick: &str, msg: Arc<str>) {
        let _ = self.broadcast_tx.send(BroadcastMsg {
            sender_nick: Arc::from(sender_nick),
            payload: msg,
        });
        metrics::counter!("jm_messages_broadcast_total").increment(1);
    }

    /// Broadcast a system message (e.g., disconnect notification) to ALL peers.
    /// Uses an empty sender_nick so no peer filters it out.
    pub fn broadcast_raw(&self, msg: Arc<str>) {
        let _ = self.broadcast_tx.send(BroadcastMsg {
            sender_nick: Arc::from(""),
            payload: msg,
        });
    }

    pub fn maker_count(&self) -> usize {
        self.makers.len()
    }

    pub fn taker_count(&self) -> usize {
        self.takers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use joinmarket_core::onion::OnionServiceAddr;

    fn make_onion_addr() -> OnionServiceAddr {
        OnionServiceAddr::parse(
            "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion:5222"
        ).unwrap()
    }

    #[test]
    fn test_register_and_deregister_maker() {
        let router = Router::new();
        assert_eq!(router.maker_count(), 0);

        let nick: Arc<str> = "J5testNickOOOOOO".into();
        router.register_maker(MakerInfo {
            nick: nick.clone(),
            onion_address: make_onion_addr(),
            fidelity_bond: None,
        });

        assert_eq!(router.maker_count(), 1);
        assert_eq!(router.taker_count(), 0);

        router.deregister("J5testNickOOOOOO", true);
        assert_eq!(router.maker_count(), 0);
    }

    #[test]
    fn test_locate_maker() {
        let router = Router::new();
        let nick: Arc<str> = "J5testNickOOOOOO".into();
        let onion = make_onion_addr();

        router.register_maker(MakerInfo {
            nick: nick.clone(),
            onion_address: onion.clone(),
            fidelity_bond: None,
        });

        let located = router.locate_peer("J5testNickOOOOOO");
        assert!(located.is_some());
        assert_eq!(located.unwrap(), onion.as_location_string());
    }

    #[test]
    fn test_getpeers_returns_only_makers() {
        let router = Router::new();

        let maker_nick: Arc<str> = "J5makerNickOOOOO".into();
        router.register_maker(MakerInfo {
            nick: maker_nick,
            onion_address: make_onion_addr(),
            fidelity_bond: None,
        });

        let taker_nick: Arc<str> = "J5takerNickOOOOO".into();
        router.register_taker(TakerInfo {
            nick: taker_nick,
            onion_address: None,
        });

        let response = router.get_peers_response();
        assert_eq!(response.total_makers, 1);
        assert_eq!(response.peers.len(), 1);
        assert!(response.peers[0].nick.as_ref().contains("maker"));
    }

    #[test]
    fn test_record_pong_removes_from_pending() {
        let router = Router::new();
        let nick: Arc<str> = "J5testNickOOOOOO".into();
        let (tx, _rx) = mpsc::channel::<Arc<str>>(16);
        router.register_peer_meta(
            &nick,
            CancellationToken::new(),
            tx,
            SupportedFeatures::new(vec!["ping".to_string()]),
            false,
        );

        router.add_pong_pending("J5testNickOOOOOO");
        assert!(router.peer_meta.get("J5testNickOOOOOO").unwrap().pong_pending);

        router.record_pong("J5testNickOOOOOO");
        assert!(!router.peer_meta.get("J5testNickOOOOOO").unwrap().pong_pending);
    }

    #[test]
    fn test_update_last_seen() {
        let router = Router::new();
        let nick: Arc<str> = "J5testNickOOOOOO".into();
        let (tx, _rx) = mpsc::channel::<Arc<str>>(16);
        router.register_peer_meta(
            &nick,
            CancellationToken::new(),
            tx,
            SupportedFeatures::empty(),
            false,
        );

        // last_seen should be initialised and fresh
        assert!(router.peer_meta.get("J5testNickOOOOOO")
            .map(|m| m.last_seen.elapsed().as_secs() < 2).unwrap_or(false));

        router.update_last_seen("J5testNickOOOOOO");
        assert!(router.peer_meta.get("J5testNickOOOOOO")
            .map(|m| m.last_seen.elapsed().as_secs() < 2).unwrap_or(false));
    }

    #[test]
    fn test_supported_features_preserve_unknown_and_known_flags() {
        let features = SupportedFeatures::new(vec![
            "peerlist_features".to_string(),
            "ping".to_string(),
            "zeta".to_string(),
        ]);

        assert!(features.supports_ping());
        assert!(features.supports_peerlist_features());
        assert_eq!(
            features.advertised().iter().map(|f| f.as_ref()).collect::<Vec<_>>(),
            vec!["peerlist_features", "ping", "zeta"]
        );
    }

    #[test]
    fn test_peer_feature_lookup_helpers() {
        let router = Router::new();
        let nick: Arc<str> = "J5testNickOOOOOO".into();
        let (tx, _rx) = mpsc::channel::<Arc<str>>(16);
        router.register_peer_meta(
            &nick,
            CancellationToken::new(),
            tx,
            SupportedFeatures::new(vec!["peerlist_features".to_string(), "unknown".to_string()]),
            false,
        );

        assert!(router.peer_supports_peerlist_features("J5testNickOOOOOO"));
        assert_eq!(
            router.peer_advertised_features("J5testNickOOOOOO")
                .unwrap()
                .iter()
                .map(|f| f.as_ref())
                .collect::<Vec<_>>(),
            vec!["peerlist_features", "unknown"]
        );
    }

    #[test]
    fn test_collect_peers_for_probe_returns_idle() {
        let router = Router::new();
        let nick: Arc<str> = "J5testNickOOOOOO".into();
        let (tx, _rx) = mpsc::channel::<Arc<str>>(16);
        router.peer_meta.insert(nick.clone(), PeerMeta {
            shutdown: CancellationToken::new(),
            probe_tx: tx,
            supported_features: SupportedFeatures::empty(),
            is_maker: false,
            last_seen: Instant::now() - Duration::from_secs(65),
            pong_pending: false,
        });

        let idle = router.collect_peers_for_probe(Duration::from_secs(60));
        assert_eq!(idle.len(), 1);
        assert_eq!(idle[0].0.as_ref(), "J5testNickOOOOOO");
        assert!(!idle[0].1); // supports_ping == false
        assert!(!idle[0].2); // is_maker == false
    }

    #[test]
    fn test_collect_idle_peers_cancels_token() {
        let router = Router::new();
        let nick: Arc<str> = "J5testNickOOOOOO".into();
        let token = CancellationToken::new();
        let (tx, _rx) = mpsc::channel::<Arc<str>>(16);
        router.peer_meta.insert(nick.clone(), PeerMeta {
            shutdown: token.clone(),
            probe_tx: tx,
            supported_features: SupportedFeatures::empty(),
            is_maker: false,
            last_seen: Instant::now() - Duration::from_secs(700),
            pong_pending: false,
        });

        let evicted = router.collect_idle_peers(Duration::from_secs(600));
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].as_ref(), "J5testNickOOOOOO");
        assert!(token.is_cancelled());
        assert!(!router.peer_meta.contains_key("J5testNickOOOOOO"));
    }

    #[test]
    fn test_send_to_peer_closed_channel_returns_not_found() {
        let router = Router::new();
        let nick: Arc<str> = "J5testNickOOOOOO".into();
        let (tx, rx) = mpsc::channel::<Arc<str>>(16);
        router.peer_meta.insert(nick.clone(), PeerMeta {
            shutdown: CancellationToken::new(),
            probe_tx: tx,
            supported_features: SupportedFeatures::empty(),
            is_maker: false,
            last_seen: Instant::now(),
            pong_pending: false,
        });
        drop(rx); // close the receiver

        let frame: Arc<str> = "probe".into();
        assert_eq!(router.send_to_peer("J5testNickOOOOOO", frame), SendResult::NotFound);
    }

    #[test]
    fn test_send_to_peer_channel_full_returns_channel_full() {
        let router = Router::new();
        let nick: Arc<str> = "J5testNickOOOOOO".into();
        // Tiny channel of capacity 2 so we can fill it easily.
        let (tx, _rx) = mpsc::channel::<Arc<str>>(2);
        router.peer_meta.insert(nick.clone(), PeerMeta {
            shutdown: CancellationToken::new(),
            probe_tx: tx,
            supported_features: SupportedFeatures::empty(),
            is_maker: false,
            last_seen: Instant::now(),
            pong_pending: false,
        });

        // Fill the channel.
        assert_eq!(router.send_to_peer("J5testNickOOOOOO", "a".into()), SendResult::Ok);
        assert_eq!(router.send_to_peer("J5testNickOOOOOO", "b".into()), SendResult::Ok);
        // Third message should be dropped.
        assert_eq!(router.send_to_peer("J5testNickOOOOOO", "c".into()), SendResult::ChannelFull);
    }

    /// Regression test for the two-phase TOCTOU race in `collect_pong_timeouts`.
    ///
    /// Simulates the scenario where `record_pong` is called after the old
    /// Phase 1 snapshot but before Phase 2 removal.  With the `retain`-based
    /// fix the check and removal are atomic per shard, so a peer that clears
    /// `pong_pending` before `retain` visits its entry must be kept alive.
    #[test]
    fn test_pong_received_before_timeout_collection_keeps_peer() {
        let router = Router::new();
        let nick: Arc<str> = "J5testNickOOOOOO".into();
        let token = CancellationToken::new();
        let (tx, _rx) = mpsc::channel::<Arc<str>>(16);

        router.peer_meta.insert(nick.clone(), PeerMeta {
            shutdown: token.clone(),
            probe_tx: tx,
            supported_features: SupportedFeatures::new(vec!["ping".to_string()]),
            is_maker: false,
            last_seen: Instant::now(),
            pong_pending: true,  // ping was sent, awaiting pong
        });

        // Peer responds with pong before collect_pong_timeouts runs
        router.record_pong("J5testNickOOOOOO");
        assert!(!router.peer_meta.get("J5testNickOOOOOO").unwrap().pong_pending);

        // collect_pong_timeouts must NOT evict this peer
        let timed_out = router.collect_pong_timeouts();
        assert!(timed_out.is_empty(), "peer that ponged should not be evicted");
        assert!(!token.is_cancelled(), "shutdown token must not be cancelled");
        assert!(router.peer_meta.contains_key("J5testNickOOOOOO"), "peer must remain in map");
    }

    #[test]
    fn test_pong_timeout_evicts_non_responding_peer() {
        let router = Router::new();
        let nick: Arc<str> = "J5testNickOOOOOO".into();
        let token = CancellationToken::new();
        let (tx, _rx) = mpsc::channel::<Arc<str>>(16);

        router.peer_meta.insert(nick.clone(), PeerMeta {
            shutdown: token.clone(),
            probe_tx: tx,
            supported_features: SupportedFeatures::new(vec!["ping".to_string()]),
            is_maker: false,
            last_seen: Instant::now(),
            pong_pending: true,  // ping was sent, no pong received
        });

        // No record_pong call — peer never responded
        let timed_out = router.collect_pong_timeouts();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0].as_ref(), "J5testNickOOOOOO");
        assert!(token.is_cancelled(), "non-responding peer must be evicted");
        assert!(!router.peer_meta.contains_key("J5testNickOOOOOO"), "peer must be removed from map");
    }

    #[test]
    fn test_dn_identity_none_before_set() {
        let router = Router::new();
        assert!(router.dn_nick().is_none(), "dn_nick should be None before set_identity");
        assert!(router.dn_location().is_none());
        assert!(router.dn_identity_pair().is_none());
    }

    #[test]
    fn test_dn_identity_some_after_set() {
        let router = Router::new();
        router.set_identity(
            "J5testDirNickOOO".to_string(),
            "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion:5222".to_string(),
        );
        assert_eq!(router.dn_nick().as_deref(), Some("J5testDirNickOOO"));
        assert!(router.dn_location().is_some());
        let (nick, loc) = router.dn_identity_pair().unwrap();
        assert_eq!(nick.as_ref(), "J5testDirNickOOO");
        assert!(loc.contains(":5222"));
    }

    #[test]
    fn test_dn_identity_second_set_ignored() {
        let router = Router::new();
        router.set_identity("J5firstNickOOOOO".to_string(), "first.onion:5222".to_string());
        router.set_identity("J5secondNickOOOO".to_string(), "second.onion:5222".to_string());
        // First call wins; second is silently ignored
        assert_eq!(router.dn_nick().as_deref(), Some("J5firstNickOOOOO"));
    }

    #[test]
    fn test_shard_distribution_with_realistic_nicks() {
        // All JoinMarket nicks start with 'J5' — verify that the randomly-seeded
        // hash function distributes them across multiple shards, not just one.
        let registry = ShardedRegistry::<()>::new();
        let mut shard_counts = vec![0usize; SHARD_COUNT];
        for i in 0..1000 {
            let nick = format!("J5nick{:010}OO", i);
            let shard = registry.shard_for(&nick);
            shard_counts[shard] += 1;
        }
        let used_shards = shard_counts.iter().filter(|&&c| c > 0).count();
        // With 1000 nicks and 64 shards, we expect nearly all shards to be used
        assert!(used_shards >= 50, "only {} of {} shards used — distribution is too skewed", used_shards, SHARD_COUNT);
    }
}
