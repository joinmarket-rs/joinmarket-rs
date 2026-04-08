use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use joinmarket_tor::provider::TorProvider;
use joinmarket_core::nick::Nick;

use crate::router::Router;
use crate::admission::AdmissionController;
use crate::peer::{handle_peer, PeerContext};

/// Hard ceiling on concurrent TCP connections regardless of role.
/// Connections that would exceed this are dropped before a task is spawned,
/// before a broadcast receiver is allocated, and before any handshake bytes
/// are read. This prevents a flood of taker connections from exhausting file
/// descriptors and Tokio task memory even after the per-role admission caps
/// inside `AdmissionController` are reached.
const MAX_CONCURRENT_CONNECTIONS: usize = 110_000;

pub async fn run_accept_loop(
    tor: Arc<dyn TorProvider>,
    router: Arc<Router>,
    admission: Arc<AdmissionController>,
    network: String,
    motd: String,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let directory_onion = tor.onion_address().to_string();

    let (directory_nick, _) = Nick::generate();
    let directory_nick = directory_nick.to_string();
    let directory_location = format!("{}:{}", directory_onion, crate::VIRTUAL_PORT);

    // Store DN identity in router so peers can include it in peerlist responses.
    router.set_identity(directory_nick.clone(), directory_location);

    tracing::info!("Accept loop started on {} (nick: {})", directory_onion, directory_nick);

    let ctx = Arc::new(PeerContext {
        router,
        admission,
        network: Arc::from(network.as_str()),
        motd: Arc::from(motd.as_str()),
        directory_onion: Arc::from(directory_onion.as_str()),
        directory_nick: Arc::from(directory_nick.as_str()),
    });

    let mut tasks = JoinSet::new();

    // Tracks every connection that currently has a live peer task, including
    // those still in the handshake phase. Decremented by a RAII guard inside
    // the spawned task so the count stays accurate even on panics.
    let active_connections = Arc::new(AtomicUsize::new(0));

    loop {
        tokio::select! {
            result = tor.accept() => {
                match result {
                    Ok(conn) => {
                        // Enforce the connection ceiling BEFORE spawning a task.
                        // This drops the connection at the OS level (RST) without
                        // allocating a broadcast receiver or reading any bytes.
                        let prev = active_connections.fetch_add(1, Ordering::AcqRel);
                        if prev >= MAX_CONCURRENT_CONNECTIONS {
                            active_connections.fetch_sub(1, Ordering::AcqRel);
                            metrics::counter!("jm_connections_rejected_capacity_total").increment(1);
                            tracing::warn!(
                                active = prev,
                                limit = MAX_CONCURRENT_CONNECTIONS,
                                "Connection limit reached; dropping incoming connection"
                            );
                            drop(conn);
                            continue;
                        }

                        let ctx = ctx.clone();
                        let peer_shutdown = shutdown.clone();

                        // RAII guard: decrement on task exit regardless of how
                        // handle_peer returns (normal, early return, or panic).
                        // Created *before* the spawn so the counter is decremented
                        // even if the spawn itself fails (extremely unlikely with
                        // Tokio, but defensive).
                        struct ConnectionGuard(Arc<AtomicUsize>);
                        impl Drop for ConnectionGuard {
                            fn drop(&mut self) {
                                self.0.fetch_sub(1, Ordering::AcqRel);
                            }
                        }
                        let guard = ConnectionGuard(active_connections.clone());

                        tasks.spawn(async move {
                            let _guard = guard;

                            handle_peer(
                                conn.reader,
                                conn.writer,
                                ctx,
                                peer_shutdown,
                            ).await;
                        });
                    }
                    Err(e) => {
                        tracing::error!("Accept error: {}", e);
                        // Brief pause to avoid tight loop on persistent errors
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
            // Reap completed peer tasks to avoid unbounded JoinSet growth
            Some(_) = tasks.join_next() => {}
            _ = shutdown.cancelled() => {
                tracing::info!("Accept loop shutting down");
                break;
            }
        }
    }

    // Wait for all peer tasks to finish cleanly
    tracing::info!("Waiting for {} peer tasks to drain", tasks.len());
    while tasks.join_next().await.is_some() {}

    Ok(())
}
