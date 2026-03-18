use async_trait::async_trait;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, Error)]
pub enum TorError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("onion service launch failed: {0}")]
    OnionServiceFailed(String),
    #[error("bootstrap failed: {0}")]
    BootstrapFailed(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type BoxReader = Box<dyn AsyncRead + Send + Unpin>;
pub type BoxWriter = Box<dyn AsyncWrite + Send + Unpin>;

pub struct IncomingConnection {
    pub reader: BoxReader,
    pub writer: BoxWriter,
    /// The source circuit ID or identifier (opaque string)
    pub circuit_id: String,
}

#[async_trait]
pub trait TorProvider: Send + Sync + 'static {
    /// Returns the onion address this provider is listening on.
    fn onion_address(&self) -> &str;

    /// Accept the next incoming connection on the hidden service.
    async fn accept(&self) -> Result<IncomingConnection, TorError>;
}
