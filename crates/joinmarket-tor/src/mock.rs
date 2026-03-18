//! Mock TorProvider for integration testing — no actual Tor networking.
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::net::TcpListener;

use crate::provider::{TorProvider, TorError, IncomingConnection};

/// A mock Tor provider that uses local TCP connections for testing.
pub struct MockTorProvider {
    onion_address: String,
    listener: Arc<Mutex<TcpListener>>,
    port: u16,
}

impl MockTorProvider {
    pub async fn new(onion_address: impl Into<String>) -> Result<Self, TorError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        Ok(MockTorProvider {
            onion_address: onion_address.into(),
            listener: Arc::new(Mutex::new(listener)),
            port,
        })
    }

    /// Returns the local TCP port this mock is listening on.
    pub fn local_port(&self) -> u16 {
        self.port
    }
}

#[async_trait]
impl TorProvider for MockTorProvider {
    fn onion_address(&self) -> &str {
        &self.onion_address
    }

    async fn accept(&self) -> Result<IncomingConnection, TorError> {
        let (stream, addr) = self.listener.lock().await.accept().await?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(IncomingConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            circuit_id: addr.to_string(),
        })
    }
}
