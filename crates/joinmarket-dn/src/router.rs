use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use joinmarket_core::onion::OnionServiceAddr;
use joinmarket_core::fidelity_bond::FidelityBondProof;
use dashmap::DashMap;

const SHARD_COUNT: usize = 64;
const BROADCAST_CAPACITY: usize = 1024;
const MAX_MAKERS_BEFORE_SAMPLE: usize = 20_000;
const SAMPLE_TARGET: usize = 4_000;

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
    pub last_ann: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TakerInfo {
    pub nick: Arc<str>,
    pub onion_address: Option<OnionServiceAddr>,
}

pub struct PeersResponse {
    pub peers: Vec<MakerInfo>,
    pub total_makers: usize,
    pub returned: usize,
    pub sampling: Option<&'static str>,
    pub request_more: bool,
}

/// Consolidated per-peer metadata stored in a single DashMap.
struct PeerMeta {
    shutdown: CancellationToken,
    probe_tx: mpsc::Sender<Arc<str>>,
    supports_ping: bool,
    last_seen: Instant,
    pong_pending: bool,
}

struct ShardedRegistry<T> {
    shards: Vec<Mutex<HashMap<Arc<str>, T>>>,
}

impl<T: Clone> ShardedRegistry<T> {
    fn new() -> Self {
        let shards = (0..SHARD_COUNT)
            .map(|_| Mutex::new(HashMap::new()))
            .collect();
        ShardedRegistry { shards }
    }

    fn shard_for(nick: &str) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        nick.hash(&mut hasher);
        hasher.finish() as usize % SHARD_COUNT
    }

    fn insert(&self, nick: Arc<str>, info: T) {
        let idx = Self::shard_for(&nick);
        self.shards[idx].lock().insert(nick, info);
    }

    fn remove(&self, nick: &str) {
        let idx = Self::shard_for(nick);
        self.shards[idx].lock().remove(nick);
    }

    fn get(&self, nick: &str) -> Option<T> {
        let idx = Self::shard_for(nick);
        self.shards[idx].lock().get(nick).cloned()
    }

    fn all_values(&self) -> Vec<T> {
        self.shards.iter()
            .flat_map(|s| s.lock().values().cloned().collect::<Vec<_>>())
            .collect()
    }

    fn len(&self) -> usize {
        self.shards.iter()
            .map(|s| s.lock().len())
            .sum()
    }
}

pub struct Router {
    makers: ShardedRegistry<MakerInfo>,
    takers: ShardedRegistry<TakerInfo>,
    broadcast_tx: broadcast::Sender<BroadcastMsg>,
    /// Consolidated per-peer metadata (shutdown token, probe channel, ping support, last_seen, pong_pending).
    peer_meta: DashMap<Arc<str>, PeerMeta>,
    /// Directory node's own nick (set after Tor bootstrap).
    dn_nick: Mutex<String>,
    /// Directory node's own location-string, e.g. "xxxx.onion:5222".
    dn_location: Mutex<String>,
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
            dn_nick: Mutex::new(String::new()),
            dn_location: Mutex::new(String::new()),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<BroadcastMsg> {
        self.broadcast_tx.subscribe()
    }

    /// Set the directory node's own identity (called once after Tor bootstrap).
    pub fn set_identity(&self, nick: String, location: String) {
        *self.dn_nick.lock() = nick;
        *self.dn_location.lock() = location;
    }

    /// Get the directory node's nick.
    pub fn dn_nick(&self) -> String {
        self.dn_nick.lock().clone()
    }

    /// Get the directory node's location-string (e.g. "xxxx.onion:5222").
    pub fn dn_location(&self) -> String {
        self.dn_location.lock().clone()
    }

    /// Send a message to a specific peer via its dedicated write channel.
    /// Returns true if the message was sent, false if the peer is not found, channel is closed, or full.
    pub fn send_to_peer(&self, nick: &str, msg: Arc<str>) -> bool {
        if let Some(meta) = self.peer_meta.get(nick) {
            meta.probe_tx.try_send(msg).is_ok()
        } else {
            false
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

    pub fn deregister(&self, nick: &str) {
        self.makers.remove(nick);
        self.takers.remove(nick);
        self.peer_meta.remove(nick);
        metrics::gauge!("jm_peers_active", "role" => "maker").set(self.makers.len() as f64);
        metrics::gauge!("jm_peers_active", "role" => "taker").set(self.takers.len() as f64);
    }

    /// Register all per-peer metadata in a single insertion.
    /// Called after handshake is complete.
    pub fn register_peer_meta(
        &self,
        nick: &Arc<str>,
        token: CancellationToken,
        probe_tx: mpsc::Sender<Arc<str>>,
        ping_capable: bool,
    ) {
        self.peer_meta.insert(nick.clone(), PeerMeta {
            shutdown: token,
            probe_tx,
            supports_ping: ping_capable,
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

    /// Returns `(nick, supports_ping)` for all peers idle longer than `threshold`.
    pub fn collect_peers_for_probe(&self, threshold: Duration) -> Vec<(Arc<str>, bool)> {
        self.peer_meta
            .iter()
            .filter(|e| e.value().last_seen.elapsed() >= threshold)
            .map(|e| (e.key().clone(), e.value().supports_ping))
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
    pub fn collect_pong_timeouts(&self) -> Vec<Arc<str>> {
        let mut timed_out = Vec::new();
        for entry in self.peer_meta.iter() {
            if entry.value().pong_pending {
                timed_out.push(entry.key().clone());
            }
        }
        for nick in &timed_out {
            if let Some((_, meta)) = self.peer_meta.remove(nick.as_ref()) {
                meta.shutdown.cancel();
            }
        }
        timed_out
    }

    pub fn get_peers_response(&self) -> PeersResponse {
        let all_makers = self.makers.all_values();
        let total_makers = all_makers.len();

        if total_makers <= MAX_MAKERS_BEFORE_SAMPLE {
            PeersResponse {
                returned: total_makers,
                peers: all_makers,
                total_makers,
                sampling: None,
                request_more: false,
            }
        } else {
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            let mut all_makers = all_makers;
            let (sampled, _) = all_makers.partial_shuffle(&mut rng, SAMPLE_TARGET);
            let sample: Vec<MakerInfo> = sampled.to_vec();
            let returned = sample.len();
            PeersResponse {
                peers: sample,
                total_makers,
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

    /// Update the `last_ann` field for a registered maker.
    pub fn update_maker_ann(&self, nick: &str, ann: String) {
        let idx = ShardedRegistry::<MakerInfo>::shard_for(nick);
        if let Some(info) = self.makers.shards[idx].lock().get_mut(nick) {
            info.last_ann = Some(ann);
        }
    }

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
            last_ann: None,
        });

        assert_eq!(router.maker_count(), 1);
        assert_eq!(router.taker_count(), 0);

        router.deregister("J5testNickOOOOOO");
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
            last_ann: None,
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
            last_ann: None,
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
        router.register_peer_meta(&nick, CancellationToken::new(), tx, true);

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
        router.register_peer_meta(&nick, CancellationToken::new(), tx, false);

        // last_seen should be initialised and fresh
        assert!(router.peer_meta.get("J5testNickOOOOOO")
            .map(|m| m.last_seen.elapsed().as_secs() < 2).unwrap_or(false));

        router.update_last_seen("J5testNickOOOOOO");
        assert!(router.peer_meta.get("J5testNickOOOOOO")
            .map(|m| m.last_seen.elapsed().as_secs() < 2).unwrap_or(false));
    }

    #[test]
    fn test_collect_peers_for_probe_returns_idle() {
        let router = Router::new();
        let nick: Arc<str> = "J5testNickOOOOOO".into();
        let (tx, _rx) = mpsc::channel::<Arc<str>>(16);
        router.peer_meta.insert(nick.clone(), PeerMeta {
            shutdown: CancellationToken::new(),
            probe_tx: tx,
            supports_ping: false,
            last_seen: Instant::now() - Duration::from_secs(65),
            pong_pending: false,
        });

        let idle = router.collect_peers_for_probe(Duration::from_secs(60));
        assert_eq!(idle.len(), 1);
        assert_eq!(idle[0].0.as_ref(), "J5testNickOOOOOO");
        assert!(!idle[0].1); // supports_ping == false
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
            supports_ping: false,
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
    fn test_send_to_peer_closed_channel_returns_false() {
        let router = Router::new();
        let nick: Arc<str> = "J5testNickOOOOOO".into();
        let (tx, rx) = mpsc::channel::<Arc<str>>(16);
        router.peer_meta.insert(nick.clone(), PeerMeta {
            shutdown: CancellationToken::new(),
            probe_tx: tx,
            supports_ping: false,
            last_seen: Instant::now(),
            pong_pending: false,
        });
        drop(rx); // close the receiver

        let frame: Arc<str> = "probe".into();
        assert!(!router.send_to_peer("J5testNickOOOOOO", frame));
    }

    #[test]
    fn test_shard_distribution_with_realistic_nicks() {
        // All JoinMarket nicks start with 'J5' — verify that the hash-based
        // shard function distributes them across multiple shards, not just one.
        let mut shard_counts = vec![0usize; SHARD_COUNT];
        for i in 0..1000 {
            let nick = format!("J5nick{:010}OO", i);
            let shard = ShardedRegistry::<()>::shard_for(&nick);
            shard_counts[shard] += 1;
        }
        let used_shards = shard_counts.iter().filter(|&&c| c > 0).count();
        // With 1000 nicks and 64 shards, we expect nearly all shards to be used
        assert!(used_shards >= 50, "only {} of {} shards used — distribution is too skewed", used_shards, SHARD_COUNT);
    }
}
