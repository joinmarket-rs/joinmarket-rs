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

/// Validate that `addr` is a well-formed, cryptographically correct Tor v3
/// onion address.  Performs the same checks as `joinmarket_core::onion::
/// OnionAddress::parse`:
///
/// 1. Length == 62 chars (56 base32 + ".onion").
/// 2. `.onion` suffix present.
/// 3. Base32 decodes without error.
/// 4. Version byte (decoded[34]) == 0x03.
/// 5. SHA3-256 checksum over the public key matches decoded[32..34].
///
/// This catches common misconfigurations (wrong file, v2 address, corrupted
/// content, address truncated by an editor) at startup rather than letting the
/// server run with an address that cannot be reached.
fn validate_onion_hostname(addr: &str) -> Result<(), String> {
    use sha3::{Digest, Sha3_256};

    let lower = addr.to_lowercase();

    if lower.len() != 62 {
        return Err(format!(
            "wrong length: expected 62 chars (v3 onion address), got {}",
            lower.len()
        ));
    }
    if !lower.ends_with(".onion") {
        return Err("does not end with '.onion'".to_string());
    }

    let encoded = &lower[..56];
    let decoded = data_encoding::BASE32_NOPAD
        .decode(encoded.to_uppercase().as_bytes())
        .map_err(|e| format!("invalid base32 encoding: {e}"))?;

    if decoded.len() != 35 {
        return Err(format!(
            "base32 decoded to {} bytes, expected 35",
            decoded.len()
        ));
    }

    let pubkey   = &decoded[0..32];
    let checksum = &decoded[32..34];
    let version  =  decoded[34];

    if version != 0x03 {
        return Err(format!(
            "wrong version byte: expected 0x03, got {version:#04x}"
        ));
    }

    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([version]);
    let hash = hasher.finalize();

    if &hash[0..2] != checksum {
        return Err("checksum mismatch: address is corrupt or truncated".to_string());
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
        // '0' is not in the base32 alphabet (A-Z, 2-7); full decode now catches it.
        let bad = format!("0{}.onion", &VALID[1..56]);
        let err = validate_onion_hostname(&bad).unwrap_err();
        assert!(err.contains("base32"), "{err}");
    }

    #[test]
    fn test_uppercase_accepted() {
        // The validator now normalises to lowercase internally, so uppercase input
        // representing a valid v3 address must be accepted.
        let upper = VALID.to_uppercase();
        assert!(validate_onion_hostname(&upper).is_ok(),
            "uppercase valid address should be accepted after lowercasing");
    }

    #[test]
    fn test_checksum_mismatch_rejected() {
        // Corrupt the first character of VALID (keeping length and base32 charset
        // intact) to produce a valid-looking but cryptographically incorrect address.
        let mut chars: Vec<char> = VALID.chars().collect();
        chars[0] = if chars[0] == '2' { '3' } else { '2' };
        let corrupted: String = chars.into_iter().collect();
        let err = validate_onion_hostname(&corrupted).unwrap_err();
        assert!(err.contains("checksum") || err.contains("version"), "{err}");
    }

    #[test]
    fn test_empty_string_wrong_length() {
        let err = validate_onion_hostname("").unwrap_err();
        assert!(err.contains("wrong length"), "{err}");
    }
}
