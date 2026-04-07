use std::collections::HashMap;
use serde::{Deserialize, Serialize};

pub const CURRENT_PROTO_VER: u8 = 5;

/// Channel ID used when verifying nick signatures in the onion transport.
/// Matches the Python JoinMarket `hostid` for the onion message channel
/// (`onionmc.py`: `self.hostid = "onion-network"`).
pub const NICK_SIG_CHANNEL_ID: &str = "onion-network";

// ── Onion channel handshake types (wire-compatible with Python JoinMarket) ───

/// Inbound peer handshake (type=793).  The peer sends this first; the directory
/// reads it, validates, then replies with `DnHandshake` (type=795).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHandshake {
    #[serde(rename = "app-name")]
    pub app_name: String,
    pub directory: bool,
    #[serde(rename = "location-string")]
    pub location_string: String,
    /// Peer sends a single integer proto-ver.
    #[serde(rename = "proto-ver")]
    pub proto_ver: u8,
    pub features: HashMap<String, serde_json::Value>,
    pub nick: String,
    pub network: String,
    /// Optional recoverable ECDSA nick-ownership proof (base64, 65 bytes).
    /// If present, `validate()` verifies it; if absent, the peer is accepted
    /// in lenient mode (no Python client sends this yet).
    #[serde(rename = "nick-sig", default, skip_serializing_if = "Option::is_none")]
    pub nick_sig: Option<String>,
}

/// Maximum number of entries allowed in the handshake `features` map.
const MAX_FEATURES_ENTRIES: usize = 32;

impl PeerHandshake {
    pub fn parse_json(json: &str) -> Result<Self, HandshakeError> {
        let msg: PeerHandshake = serde_json::from_str(json)?;
        if msg.features.len() > MAX_FEATURES_ENTRIES {
            return Err(HandshakeError::TooManyFeatures(msg.features.len()));
        }
        // Reject deeply nested values (only scalars and single-level objects allowed)
        for (key, value) in &msg.features {
            if value.is_object() || value.is_array() {
                return Err(HandshakeError::NestedFeatureValue(key.clone()));
            }
        }
        Ok(msg)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("serialization is infallible for this type")
    }

    /// Extract fidelity bond proof from features map, if present.
    /// The bond is base64-encoded under `features["fidelity_bond"]`.
    pub fn fidelity_bond(&self) -> Option<crate::fidelity_bond::FidelityBondProof> {
        self.features.get("fidelity_bond")
            .and_then(|v| v.as_str())
            .and_then(|s| crate::fidelity_bond::FidelityBondProof::parse_base64(s).ok())
    }

    /// Returns true if the peer advertised `!ping`/`!pong` heartbeat support via
    /// `"features": {"ping": true}` in their handshake. Python clients never set
    /// this, so it defaults to false.
    pub fn supports_ping(&self) -> bool {
        self.features
            .get("ping")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// Validate handshake fields. Returns the parsed `OnionServiceAddr` if the
    /// peer advertised a non-empty, valid location-string.
    pub fn validate(&self, expected_network: &str) -> Result<Option<crate::onion::OnionServiceAddr>, HandshakeError> {
        if self.app_name != "joinmarket" {
            return Err(HandshakeError::WrongAppName(self.app_name.clone()));
        }
        if self.directory {
            return Err(HandshakeError::DirectoryNotAccepted);
        }
        if self.proto_ver != CURRENT_PROTO_VER {
            return Err(HandshakeError::ProtoVerMismatch {
                expected: CURRENT_PROTO_VER,
                got: self.proto_ver,
            });
        }
        if self.network != expected_network {
            return Err(HandshakeError::NetworkMismatch {
                expected: expected_network.to_string(),
                got: self.network.clone(),
            });
        }
        let nick_obj = crate::nick::Nick::from_str(&self.nick)
            .map_err(|_| HandshakeError::MalformedNick)?;
        if let Some(sig_b64) = &self.nick_sig {
            let sig = crate::nick::NickSig::from_base64(sig_b64)
                .map_err(|_| HandshakeError::NickSigInvalid)?;
            if !nick_obj.verify_signature(self.nick.as_bytes(), NICK_SIG_CHANNEL_ID, &sig) {
                return Err(HandshakeError::NickSigInvalid);
            }
        }
        if !self.location_string.is_empty()
            && self.location_string != crate::message::NOT_SERVING_ONION
        {
            let addr = crate::onion::OnionServiceAddr::parse(&self.location_string)?;
            return Ok(Some(addr));
        }
        Ok(None)
    }
}

/// Outbound directory handshake response (type=795).
/// Uses `proto-ver-min` / `proto-ver-max` instead of a single `proto-ver`, and
/// includes an `accepted` boolean.
#[derive(Debug, Serialize)]
pub struct DnHandshake {
    #[serde(rename = "app-name")]
    pub app_name: String,
    pub directory: bool,
    #[serde(rename = "location-string")]
    pub location_string: String,
    #[serde(rename = "proto-ver-min")]
    pub proto_ver_min: u8,
    #[serde(rename = "proto-ver-max")]
    pub proto_ver_max: u8,
    pub features: HashMap<String, serde_json::Value>,
    pub accepted: bool,
    pub nick: String,
    pub network: String,
    pub motd: String,
}

impl DnHandshake {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("infallible")
    }
}


#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("wrong app-name: expected 'joinmarket', got '{0}'")]
    WrongAppName(String),
    #[error("protocol version mismatch: expected {expected}, got {got}")]
    ProtoVerMismatch { expected: u8, got: u8 },
    #[error("network mismatch: expected '{expected}', got '{got}'")]
    NetworkMismatch { expected: String, got: String },
    #[error("directory nodes not accepted as peers")]
    DirectoryNotAccepted,
    #[error("malformed nick")]
    MalformedNick,
    #[error("nick signature verification failed")]
    NickSigInvalid,
    #[error("too many features entries: {0} (max {})", MAX_FEATURES_ENTRIES)]
    TooManyFeatures(usize),
    #[error("nested value not allowed in features key '{0}'")]
    NestedFeatureValue(String),
    #[error("invalid onion address in location-string: {0}")]
    InvalidOnionAddress(#[from] crate::onion::OnionServiceAddrError),
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),
}


#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn valid_handshake_json() -> &'static str {
        r#"{"app-name":"joinmarket","directory":false,"location-string":"","proto-ver":5,"features":{},"nick":"J5xhGSWE7VrxM7sO","network":"mainnet"}"#
    }

    #[test]
    fn test_parse_valid_handshake() {
        let msg = PeerHandshake::parse_json(valid_handshake_json()).unwrap();
        assert_eq!(msg.app_name, "joinmarket");
        assert_eq!(msg.proto_ver, 5);
        assert_eq!(msg.network, "mainnet");
        assert!(!msg.directory);
    }

    #[test]
    fn test_validate_ok() {
        let msg = PeerHandshake::parse_json(valid_handshake_json()).unwrap();
        assert!(msg.validate("mainnet").is_ok());
    }

    #[test]
    fn test_validate_wrong_network() {
        let msg = PeerHandshake::parse_json(valid_handshake_json()).unwrap();
        let err = msg.validate("testnet").unwrap_err();
        assert!(matches!(err, HandshakeError::NetworkMismatch { .. }));
    }

    #[test]
    fn test_validate_wrong_proto_ver() {
        let json = r#"{"app-name":"joinmarket","directory":false,"location-string":"","proto-ver":4,"features":{},"nick":"J5xhGSWE7VrxM7sO","network":"mainnet"}"#;
        let msg = PeerHandshake::parse_json(json).unwrap();
        let err = msg.validate("mainnet").unwrap_err();
        assert!(matches!(err, HandshakeError::ProtoVerMismatch { .. }));
    }

    #[test]
    fn test_validate_wrong_app_name() {
        let json = r#"{"app-name":"bitcoin","directory":false,"location-string":"","proto-ver":5,"features":{},"nick":"J5xhGSWE7VrxM7sO","network":"mainnet"}"#;
        let msg = PeerHandshake::parse_json(json).unwrap();
        let err = msg.validate("mainnet").unwrap_err();
        assert!(matches!(err, HandshakeError::WrongAppName(_)));
    }

    #[test]
    fn test_roundtrip_serialization() {
        let json = valid_handshake_json();
        let msg = PeerHandshake::parse_json(json).unwrap();
        let serialized = msg.to_json();
        let reparsed = PeerHandshake::parse_json(&serialized).unwrap();
        assert_eq!(msg.app_name, reparsed.app_name);
        assert_eq!(msg.proto_ver, reparsed.proto_ver);
        assert_eq!(msg.nick, reparsed.nick);
    }

    #[test]
    fn test_directory_node_handshake_rejected() {
        let json = r#"{"app-name":"joinmarket","directory":true,"location-string":"2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion:5222","proto-ver":5,"features":{},"nick":"J5xhGSWE7VrxM7sO","network":"mainnet"}"#;
        let msg = PeerHandshake::parse_json(json).unwrap();
        assert!(msg.directory);
        let err = msg.validate("mainnet").unwrap_err();
        assert!(matches!(err, HandshakeError::DirectoryNotAccepted));
    }

    #[test]
    fn test_peer_handshake_with_fidelity_bond() {
        // Create a valid 252-byte bond blob
        let blob = vec![0u8; 252];
        let bond_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        let json = format!(
            r#"{{"app-name":"joinmarket","directory":false,"location-string":"","proto-ver":5,"features":{{"fidelity_bond":"{bond_b64}"}},"nick":"J5xhGSWE7VrxM7sO","network":"mainnet"}}"#
        );
        let msg = PeerHandshake::parse_json(&json).unwrap();
        assert!(msg.fidelity_bond().is_some());
    }

    #[test]
    fn test_peer_handshake_no_bond() {
        let msg = PeerHandshake::parse_json(valid_handshake_json()).unwrap();
        assert!(msg.fidelity_bond().is_none());
    }

    /// Helper: produce a valid (nick, nick_sig_b64) pair for use in handshake tests.
    fn make_nick_with_sig() -> (String, String) {
        use crate::nick::{Nick, Network};
        let (nick, key) = Nick::generate(Network::Mainnet);
        let sig = key.sign_message(nick.as_str().as_bytes(), NICK_SIG_CHANNEL_ID);
        (nick.as_str().to_string(), sig.to_base64())
    }

    #[test]
    fn test_validate_no_nick_sig_is_accepted_lenient() {
        // No nick-sig field — current Python clients never send one.
        // The DN must accept these peers (lenient mode).
        let msg = PeerHandshake::parse_json(valid_handshake_json()).unwrap();
        assert!(msg.nick_sig.is_none());
        assert!(msg.validate("mainnet").is_ok());
    }

    #[test]
    fn test_validate_valid_nick_sig_accepted() {
        let (nick, sig_b64) = make_nick_with_sig();
        let json = format!(
            "{{\"app-name\":\"joinmarket\",\"directory\":false,\"location-string\":\"\",\"proto-ver\":5,\"features\":{{}},\"nick\":\"{nick}\",\"network\":\"mainnet\",\"nick-sig\":\"{sig_b64}\"}}"
        );
        let msg = PeerHandshake::parse_json(&json).unwrap();
        assert!(msg.nick_sig.is_some());
        assert!(msg.validate("mainnet").is_ok());
    }

    #[test]
    fn test_validate_invalid_nick_sig_rejected() {
        let (nick, _) = make_nick_with_sig();
        // Use a different key's signature — won't match this nick's pubkey hash.
        let (_, other_key) = crate::nick::Nick::generate(crate::nick::Network::Mainnet);
        let bad_sig = other_key.sign_message(nick.as_bytes(), NICK_SIG_CHANNEL_ID);
        let bad_sig_b64 = bad_sig.to_base64();
        let json = format!(
            "{{\"app-name\":\"joinmarket\",\"directory\":false,\"location-string\":\"\",\"proto-ver\":5,\"features\":{{}},\"nick\":\"{nick}\",\"network\":\"mainnet\",\"nick-sig\":\"{bad_sig_b64}\"}}"
        );
        let msg = PeerHandshake::parse_json(&json).unwrap();
        let err = msg.validate("mainnet").unwrap_err();
        assert!(matches!(err, HandshakeError::NickSigInvalid));
    }

    #[test]
    fn test_validate_malformed_nick_sig_rejected() {
        let (nick, _) = make_nick_with_sig();
        let json = format!(
            "{{\"app-name\":\"joinmarket\",\"directory\":false,\"location-string\":\"\",\"proto-ver\":5,\"features\":{{}},\"nick\":\"{nick}\",\"network\":\"mainnet\",\"nick-sig\":\"not-valid-base64!!!\"}}"
        );
        let msg = PeerHandshake::parse_json(&json).unwrap();
        let err = msg.validate("mainnet").unwrap_err();
        assert!(matches!(err, HandshakeError::NickSigInvalid));
    }

    #[test]
    fn test_validate_nick_sig_wrong_channel_id_rejected() {
        // Sign with the wrong channel_id — must not verify.
        let (nick, key) = crate::nick::Nick::generate(crate::nick::Network::Mainnet);
        let wrong_sig = key.sign_message(nick.as_str().as_bytes(), "wrong-channel");
        let wrong_sig_b64 = wrong_sig.to_base64();
        let nick_str = nick.as_str();
        let json = format!(
            "{{\"app-name\":\"joinmarket\",\"directory\":false,\"location-string\":\"\",\"proto-ver\":5,\"features\":{{}},\"nick\":\"{nick_str}\",\"network\":\"mainnet\",\"nick-sig\":\"{wrong_sig_b64}\"}}"
        );
        let msg = PeerHandshake::parse_json(&json).unwrap();
        let err = msg.validate("mainnet").unwrap_err();
        assert!(matches!(err, HandshakeError::NickSigInvalid));
    }
    #[test]
    fn test_nick_sig_not_serialized_when_none() {
        // nick_sig = None should not appear in the serialized JSON.
        let msg = PeerHandshake::parse_json(valid_handshake_json()).unwrap();
        assert!(msg.nick_sig.is_none());
        let serialized = msg.to_json();
        assert!(!serialized.contains("nick-sig"));
    }
}
