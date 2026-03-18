use std::sync::Arc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use joinmarket_tor::provider::TorProvider;
use joinmarket_core::nick::{Nick, Network as NickNetwork};

use crate::router::Router;
use crate::admission::AdmissionController;
use crate::peer::{handle_peer, PeerContext};

pub async fn run_accept_loop(
    tor: Arc<dyn TorProvider>,
    router: Arc<Router>,
    admission: Arc<AdmissionController>,
    network: String,
    motd: String,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let directory_onion = tor.onion_address().to_string();

    let nick_network = match network.as_str() {
        "testnet" => NickNetwork::Testnet,
        "signet"  => NickNetwork::Signet,
        _         => NickNetwork::Mainnet,
    };
    let (directory_nick, _) = Nick::generate(nick_network);
    let directory_nick = directory_nick.to_string();
    let directory_location = format!("{}:5222", directory_onion);

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

    loop {
        tokio::select! {
            result = tor.accept() => {
                match result {
                    Ok(conn) => {
                        let ctx = ctx.clone();
                        let peer_shutdown = shutdown.clone();

                        tasks.spawn(async move {
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
