//! Arti embedded Tor backend for the JoinMarket directory node.
//! Compiled only when the `arti` Cargo feature is enabled.

use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use arti_client::TorClient;
use arti_client::config::TorClientConfigBuilder;
use futures::{Stream, StreamExt};
use safelog::DisplayRedacted;
use tokio::sync::Mutex;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{
    HsNickname, RunningOnionService, StreamRequest,
    handle_rend_requests,
    config::OnionServiceConfig,
};
use tor_rtcompat::PreferredRuntime;

use crate::provider::{IncomingConnection, TorError, TorProvider};

/// Arti embedded Tor provider. Bootstraps a full Tor client in-process and
/// launches a hidden service whose Ed25519 identity key is persisted in `state_dir`.
pub struct ArtiTorProvider {
    onion_address: String,
    // Keep both alive: dropping either shuts down the onion service.
    _client: TorClient<PreferredRuntime>,
    _service: Arc<RunningOnionService>,
    stream_requests: Mutex<Pin<Box<dyn Stream<Item = StreamRequest> + Send>>>,
    conn_counter: AtomicU64,
}

impl ArtiTorProvider {
    /// Bootstrap Arti, launch the onion service, and wait for the address to be ready.
    ///
    /// `state_dir` is the base directory. Arti writes its state under
    /// `<state_dir>/arti-state/` and its consensus cache under
    /// `<state_dir>/arti-cache/`. The hidden service Ed25519 key lives inside the
    /// Arti keystore at `<state_dir>/arti-state/` and must not be deleted across
    /// restarts.
    pub async fn bootstrap(state_dir: &Path, pow_enabled: bool) -> Result<Self, TorError> {
        let config = TorClientConfigBuilder::from_directories(
            state_dir.join("arti-state"),
            state_dir.join("arti-cache"),
        )
        .build()
        .map_err(|e| TorError::BootstrapFailed(e.to_string()))?;

        tracing::info!(
            state_dir = %state_dir.display(),
            "Bootstrapping Arti Tor client…"
        );

        let client: TorClient<PreferredRuntime> = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| TorError::BootstrapFailed(e.to_string()))?;

        tracing::info!("Arti bootstrap complete, launching onion service…");

        let nickname = HsNickname::new("joinmarket-dn".to_string())
            .map_err(|e| TorError::OnionServiceFailed(e.to_string()))?;

        let mut builder = OnionServiceConfig::builder();
        builder.nickname(nickname);
        if pow_enabled {
            builder.enable_pow(true);
            builder.pow_rend_queue_depth(200_usize);
            tracing::info!("Tor PoW defence enabled (hs-pow-full, queue_depth=200)");
        }

        let svc_config = builder
            .build()
            .map_err(|e| TorError::OnionServiceFailed(e.to_string()))?;

        let (service, rend_stream) = client
            .launch_onion_service(svc_config)
            .map_err(|e| TorError::OnionServiceFailed(e.to_string()))?
            .ok_or_else(|| {
                TorError::OnionServiceFailed(
                    "an onion service named 'joinmarket-dn' is already running \
                     in this Arti instance"
                        .into(),
                )
            })?;

        let onion_address = wait_for_address(&service).await?;
        tracing::info!("Hidden service available at {}", onion_address);

        let stream_requests = Box::pin(handle_rend_requests(rend_stream));

        Ok(Self {
            onion_address,
            _client: client,
            _service: service,
            stream_requests: Mutex::new(stream_requests),
            conn_counter: AtomicU64::new(0),
        })
    }
}

/// Poll `service.onion_address()` until the key is loaded from the keystore,
/// up to 60 seconds. Returns an error if the address never becomes available.
async fn wait_for_address(service: &Arc<RunningOnionService>) -> Result<String, TorError> {
    for _ in 0..60 {
        if let Some(addr) = service.onion_address() {
            return Ok(addr.display_unredacted().to_string());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Err(TorError::OnionServiceFailed(
        "timed out waiting for onion address — ensure the Arti state directory \
         is writable and the keystore is accessible"
            .into(),
    ))
}

#[async_trait]
impl TorProvider for ArtiTorProvider {
    fn onion_address(&self) -> &str {
        &self.onion_address
    }

    async fn accept(&self) -> Result<IncomingConnection, TorError> {
        loop {
            let stream_req = {
                let mut guard = self.stream_requests.lock().await;
                guard.next().await
            };

            let req = stream_req.ok_or_else(|| {
                TorError::OnionServiceFailed("incoming stream channel closed".into())
            })?;

            match req.accept(Connected::new_empty()).await {
                Ok(data_stream) => {
                    let id = self.conn_counter.fetch_add(1, Ordering::Relaxed);
                    let (reader, writer) = tokio::io::split(data_stream);
                    return Ok(IncomingConnection {
                        reader: Box::new(reader),
                        writer: Box::new(writer),
                        // Tor onion service connections are anonymous; use a monotonic
                        // counter as the circuit identifier. Per-onion rate limiting
                        // (Layer 2) is enforced post-handshake once the client's
                        // location-string is known.
                        circuit_id: format!("arti-{}", id),
                    });
                }
                Err(e) => {
                    // A single stream can fail (e.g. client-side timeout) while the
                    // service remains healthy. Log and loop to the next request.
                    tracing::warn!("Failed to accept incoming stream: {}", e);
                }
            }
        }
    }
}
