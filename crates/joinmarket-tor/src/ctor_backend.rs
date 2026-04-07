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

        validate_onion_hostname(&onion_address).map_err(|e| TorError::OnionServiceFailed(
            format!("{} contains invalid onion address: {e}", hostname_path.display())
        ))?;

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

/// Validate that `addr` looks like a Tor v3 onion address (62 chars, valid
/// base32 prefix, `.onion` suffix). This catches common misconfigurations
/// (wrong file, v2 address, corrupted content) at startup rather than
/// letting the server run with an unusable address.
fn validate_onion_hostname(addr: &str) -> Result<(), String> {
    if addr.len() != 62 {
        return Err(format!(
            "wrong length: expected 62 chars (v3 onion address), got {}",
            addr.len()
        ));
    }
    if !addr.ends_with(".onion") {
        return Err("does not end with '.onion'".to_string());
    }
    let base32_part = &addr[..56];
    if !base32_part.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
        return Err("base32 prefix contains invalid characters (expected a-z and 2-7)".to_string());
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::validate_onion_hostname;

    const VALID: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

    #[test]
    fn test_valid_v3_address_accepted() {
        assert!(validate_onion_hostname(VALID).is_ok());
    }

    #[test]
    fn test_v2_address_rejected() {
        // v2 addresses are 22 chars
        let err = validate_onion_hostname("aaaaaaaaaaaaaaaa.onion").unwrap_err();
        assert!(err.contains("wrong length"), "{err}");
    }

    #[test]
    fn test_missing_onion_suffix_rejected() {
        // 56 base32 chars + ".test22" = 63 chars — right length ballpark but wrong suffix
        let bad = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.tes22";
        assert_eq!(bad.len(), 62);
        let err = validate_onion_hostname(bad).unwrap_err();
        assert!(err.contains(".onion"), "{err}");
    }

    #[test]
    fn test_invalid_base32_chars_rejected() {
        // Replace first char with '0' which is not valid base32
        let bad = format!("0{}.onion", &VALID[1..56]);
        let err = validate_onion_hostname(&bad).unwrap_err();
        assert!(err.contains("invalid characters"), "{err}");
    }

    #[test]
    fn test_uppercase_rejected() {
        // validate_onion_hostname expects lowercase (Tor writes lowercase).
        // Uppercase input has a wrong suffix (.ONION not .onion), so the
        // suffix check fires first.
        let upper = VALID.to_uppercase();
        let err = validate_onion_hostname(&upper).unwrap_err();
        assert!(err.contains(".onion") || err.contains("invalid characters"), "{err}");
    }

    #[test]
    fn test_empty_string_wrong_length() {
        let err = validate_onion_hostname("").unwrap_err();
        assert!(err.contains("wrong length"), "{err}");
    }
}
