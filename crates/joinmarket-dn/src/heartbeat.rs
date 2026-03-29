use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use joinmarket_core::message::{OnionEnvelope, msg_type};
use crate::router::Router;

/// How often to sweep for idle peers.
const IDLE_CHECK_INTERVAL_SECS: u64 = 300; // 5 min

/// Peers idle longer than this receive a !ping probe (ping-capable peers only).
const WRITE_PROBE_THRESHOLD_SECS: u64 = 300; // 5 min

/// Peers idle longer than this are hard-evicted without a probe.
const HARD_EVICT_THRESHOLD_SECS: u64 = 900; // 15 min

/// How long to wait for a !pong after sending !ping to a ping-capable peer.
const PONG_TIMEOUT_SECS: u64 = 30;

pub async fn heartbeat_loop(router: Arc<Router>, shutdown: CancellationToken) {
    // Delay first sweep so we don't evict peers that just connected.
    let start = tokio::time::Instant::now() + Duration::from_secs(IDLE_CHECK_INTERVAL_SECS);
    let mut interval = tokio::time::interval_at(start, Duration::from_secs(IDLE_CHECK_INTERVAL_SECS));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let makers = router.maker_count();
                let takers = router.taker_count();
                tracing::debug!(makers, takers, "Heartbeat: idle sweep");

                // Step 1: Hard-evict peers idle > 15 min (no probe, just disconnect).
                let hard_evicted = router.collect_idle_peers(
                    Duration::from_secs(HARD_EVICT_THRESHOLD_SECS)
                );
                if !hard_evicted.is_empty() {
                    tracing::info!(count = hard_evicted.len(), "Heartbeat: hard evicting idle peers");
                    metrics::counter!("jm_heartbeat_evictions_total")
                        .increment(hard_evicted.len() as u64);
                    for nick in &hard_evicted {
                        tracing::debug!(%nick, "Hard evicted (idle > 15 min)");
                    }
                }

                // Step 2: Send !ping probes to ping-capable peers idle > 5 min.
                // Non-ping peers (Python clients) receive no probe — they will be
                // hard-evicted at 15 min if no message is received.
                let peers_to_probe = router.collect_peers_for_probe(
                    Duration::from_secs(WRITE_PROBE_THRESHOLD_SECS)
                );

                if peers_to_probe.is_empty() {
                    continue;
                }

                let ping_frame = build_ping_frame();
                let mut ping_sent = false;

                for (nick, supports_ping) in &peers_to_probe {
                    if *supports_ping && router.send_to_peer(nick, ping_frame.clone()) {
                        router.add_pong_pending(nick);
                        ping_sent = true;
                        tracing::debug!(%nick, "Sent !ping probe");
                    }
                    // Non-ping peers: no probe. They will be hard-evicted at 15 min
                    // if no message is received.
                }

                // Step 3: If !pings were sent, wait then evict non-responders.
                if ping_sent {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(PONG_TIMEOUT_SECS)) => {}
                        _ = shutdown.cancelled() => break,
                    }
                    let timed_out = router.collect_pong_timeouts();
                    if !timed_out.is_empty() {
                        tracing::info!(count = timed_out.len(), "Heartbeat: evicting peers that missed !pong");
                        metrics::counter!("jm_heartbeat_evictions_total")
                            .increment(timed_out.len() as u64);
                        for nick in &timed_out {
                            tracing::debug!(%nick, "Evicted: no !pong after ping probe");
                        }
                    }
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }

    tracing::info!("Heartbeat loop stopping");
}

/// Build a PING envelope.
fn build_ping_frame() -> Arc<str> {
    Arc::from(OnionEnvelope::new(msg_type::PING, "").serialize())
}
