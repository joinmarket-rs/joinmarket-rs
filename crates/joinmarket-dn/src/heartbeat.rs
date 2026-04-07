use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use joinmarket_core::message::{OnionEnvelope, make_pubmsg_line, msg_type};
use crate::router::Router;

/// How often to sweep for idle peers.
const IDLE_CHECK_INTERVAL_SECS: u64 = 60; // 1 min

/// Peers idle longer than this receive a probe.
const WRITE_PROBE_THRESHOLD_SECS: u64 = 600; // 10 min

/// Peers idle longer than this are hard-evicted without a probe.
const HARD_EVICT_THRESHOLD_SECS: u64 = 1500; // 25 min

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

                // Step 1: Hard-evict peers idle > 25 min (no probe, just disconnect).
                let hard_evicted = router.collect_idle_peers(
                    Duration::from_secs(HARD_EVICT_THRESHOLD_SECS)
                );
                if !hard_evicted.is_empty() {
                    tracing::info!(count = hard_evicted.len(), "Heartbeat: hard evicting idle peers");
                    metrics::counter!("jm_heartbeat_evictions_total")
                        .increment(hard_evicted.len() as u64);
                    for nick in &hard_evicted {
                        tracing::debug!(%nick, "Hard evicted (idle > 25 min)");
                    }
                }

                // Step 2: Probe idle peers (> 10 min) based on their capabilities:
                //   - Ping-capable peers: send !ping and wait for !pong.
                //   - Non-ping makers (Python clients): send a unicast !orderbook so
                //     the maker re-announces its offers. When the DN receives those
                //     offer pubmsgs it updates last_seen, keeping the maker alive.
                //   - Non-ping takers: no probe. Hard-evicted at 25 min if silent.
                let peers_to_probe = router.collect_peers_for_probe(
                    Duration::from_secs(WRITE_PROBE_THRESHOLD_SECS)
                );

                if peers_to_probe.is_empty() {
                    continue;
                }

                let ping_frame = build_ping_frame();
                // Build the !orderbook probe only when the DN identity is set.
                // If `set_identity` hasn't been called yet (shouldn't happen
                // given the 60-second initial delay, but defended here), an
                // orderbook probe with an empty nick would be a malformed frame.
                let orderbook_frame: Option<Arc<str>> = router
                    .dn_nick()
                    .map(|n| build_orderbook_probe_frame(&n));
                let mut ping_sent = false;

                for (nick, supports_ping, is_maker) in &peers_to_probe {
                    if *supports_ping {
                        if router.send_to_peer(nick, ping_frame.clone()) {
                            router.add_pong_pending(nick);
                            ping_sent = true;
                            metrics::counter!("jm_heartbeat_ping_probes_total").increment(1);
                            tracing::debug!(%nick, "Sent !ping probe");
                        }
                    } else if *is_maker {
                        // Non-ping maker: unicast !orderbook to elicit an offer
                        // re-announcement, which will refresh last_seen when received.
                        // Skipped if DN identity isn't set yet (orderbook_frame is None).
                        if let Some(ref frame) = orderbook_frame {
                            if router.send_to_peer(nick, frame.clone()) {
                                metrics::counter!("jm_heartbeat_orderbook_probes_total").increment(1);
                                tracing::debug!(%nick, "Sent !orderbook probe to non-ping maker");
                            }
                        }
                    }
                    // Non-ping takers: no probe. Hard-evicted at 25 min if silent.
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

/// Build a unicast !orderbook PUBMSG envelope addressed from the DN's own nick.
/// Sent to non-ping makers as a liveness probe: the maker will respond with its
/// offers as pubmsgs, which update `last_seen` when received by the DN.
fn build_orderbook_probe_frame(dn_nick: &str) -> Arc<str> {
    let line = make_pubmsg_line(dn_nick, "!orderbook");
    Arc::from(OnionEnvelope::new(msg_type::PUBMSG, line).serialize())
}
