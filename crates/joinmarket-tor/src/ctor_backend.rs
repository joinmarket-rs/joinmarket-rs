//! C Tor daemon backend — passive TCP server mode.
//!
//! Assumes an externally configured C Tor daemon with a hidden service already
//! running. Reads the `.onion` address from `<hidden_service_dir>/hostname`
//! and binds a TCP listener on `serving_host:serving_port` to accept
//! connections forwarded by C Tor.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use async_trait::async_trait;

use crate::provider::{IncomingConnection, TorError, TorProvider};

pub struct CTorProvider {
    onion_address: String,
    listener: Arc<Mutex<TcpListener>>,
    conn_counter: AtomicU64,
}

impl CTorProvider {
    /// Create a new provider by reading the onion address from
    /// `<hidden_service_dir>/hostname` and binding a TCP listener.
    ///
    /// * `hidden_service_dir` — directory where C Tor stores the hidden service
    ///   files, including `hostname`.
    /// * `serving_host` — local address to bind (e.g. `"127.0.0.1"`).
    /// * `serving_port` — local port to bind (must match the HiddenServicePort
    ///   target in `torrc`).
    pub async fn new(
        hidden_service_dir: &Path,
        serving_host: &str,
        serving_port: u16,
    ) -> Result<Self, TorError> {
        // Read the onion address from the hostname file
        let hostname_path = hidden_service_dir.join("hostname");
        let onion_address = tokio::fs::read_to_string(&hostname_path).await
            .map_err(|e| TorError::OnionServiceFailed(
                format!("read {}: {e}", hostname_path.display())
            ))?
            .trim()
            .to_string();

        if onion_address.is_empty() {
            return Err(TorError::OnionServiceFailed(
                format!("{} is empty", hostname_path.display())
            ));
        }

        // Bind TCP listener
        let bind_addr = format!("{serving_host}:{serving_port}");
        let listener = TcpListener::bind(&bind_addr).await
            .map_err(|e| TorError::OnionServiceFailed(format!("bind {bind_addr}: {e}")))?;

        tracing::info!("Hidden service available at {}", onion_address);

        Ok(CTorProvider {
            onion_address,
            listener: Arc::new(Mutex::new(listener)),
            conn_counter: AtomicU64::new(0),
        })
    }
}

#[async_trait]
impl TorProvider for CTorProvider {
    fn onion_address(&self) -> &str {
        &self.onion_address
    }

    async fn accept(&self) -> Result<IncomingConnection, TorError> {
        let (stream, _addr) = self.listener.lock().await.accept().await?;
        let id = self.conn_counter.fetch_add(1, Ordering::Relaxed);
        let (reader, writer) = tokio::io::split(stream);
        Ok(IncomingConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            circuit_id: format!("ctor-{id}"),
        })
    }
}
