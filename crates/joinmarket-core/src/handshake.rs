use std::collections::HashMap;
use serde::{Deserialize, Serialize};

pub const CURRENT_PROTO_VER: u8 = 5;
pub const DN_SUPPORTED_FEATURE_NAMES: &[&str] = &["peerlist_features", "ping"];

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
}

/// Maximum number of entries allowed in the handshake `features` map.
const MAX_FEATURES_ENTRIES: usize = 32;
/// Maximum byte length for short string fields (app-name, network, nick).
/// Legitimate values are always short identifiers; this cap prevents oversized
/// strings from being heap-allocated and echoed into error-message display
/// strings or log entries.
const MAX_FIELD_LEN: usize = 64;
/// Maximum byte length for the `location-string` field.  A valid value is at
/// most 68 bytes: 62-char v3 onion + `:` + up to 5-digit port.  We use 72
/// for a small margin.
const MAX_LOCATION_LEN: usize = 72;
/// Maximum byte length of a single key in the `features` map.
/// Legitimate keys ("ping", "fidelity_bond") are very short.
const MAX_FEATURE_KEY_LEN: usize = 64;
/// Maximum byte length of a single scalar string value in the `features` map.
/// The largest legitimate value is `fidelity_bond` (~336 bytes base64 of 252).
const MAX_FEATURE_VALUE_LEN: usize = 512;

fn is_valid_feature_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

impl PeerHandshake {
    pub fn parse_json(json: &str) -> Result<Self, HandshakeError> {
        let msg: PeerHandshake = serde_json::from_str(json)?;
        // Reject oversized string fields before they can be stored, echoed into
        // error-message display strings, or written to log files.
        if msg.app_name.len() > MAX_FIELD_LEN
            || msg.network.len() > MAX_FIELD_LEN
            || msg.nick.len() > MAX_FIELD_LEN
            || msg.location_string.len() > MAX_LOCATION_LEN
        {
            return Err(HandshakeError::FieldTooLong);
        }
        if msg.features.len() > MAX_FEATURES_ENTRIES {
            return Err(HandshakeError::TooManyFeatures(msg.features.len()));
        }
        // Reject oversized feature keys, invalid feature names, oversized string
        // values, and nested structures.
        for (key, value) in &msg.features {
            if key.len() > MAX_FEATURE_KEY_LEN {
                return Err(HandshakeError::FieldTooLong);
            }
            if !is_valid_feature_name(key) {
                return Err(HandshakeError::InvalidFeatureName(key.clone()));
            }
            if value.as_str().is_some_and(|s| s.len() > MAX_FEATURE_VALUE_LEN) {
                return Err(HandshakeError::FieldTooLong);
            }
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

    /// Returns the names of all features explicitly advertised as JSON boolean
    /// `true`. Ordering is preserved from the underlying map iteration; callers
    /// that need deterministic output must sort the result themselves.
    pub fn advertised_true_features(&self) -> Vec<String> {
        self.features
            .iter()
            .filter_map(|(name, value)| value.as_bool().filter(|b| *b).map(|_| name.clone()))
            .collect()
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
        crate::nick::Nick::from_str(&self.nick)
            .map_err(|_| HandshakeError::MalformedNick)?;
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

pub fn dn_supported_feature_names() -> &'static [&'static str] {
    DN_SUPPORTED_FEATURE_NAMES
}

pub fn dn_supported_features() -> HashMap<String, serde_json::Value> {
    dn_supported_feature_names()
        .iter()
        .map(|name| ((*name).to_string(), serde_json::Value::Bool(true)))
        .collect()
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
    #[error("too many features entries: {0} (max {})", MAX_FEATURES_ENTRIES)]
    TooManyFeatures(usize),
    #[error("invalid feature name '{0}' (expected [a-z0-9_]+)")]
    InvalidFeatureName(String),
    #[error("nested value not allowed in features key '{0}'")]
    NestedFeatureValue(String),
    #[error("handshake field or feature value exceeds maximum allowed length")]
    FieldTooLong,
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
        // Compressed secp256k1 generator point G (valid curve point).
        let g: [u8; 33] = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95,
            0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59,
            0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        let mut blob = vec![0u8; 252];
        blob[144..177].copy_from_slice(&g); // cert_pubkey
        blob[179..212].copy_from_slice(&g); // utxo_pubkey
        let bond_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        let json = format!(
            r#"{{"app-name":"joinmarket","directory":false,"location-string":"","proto-ver":5,"features":{{"fidelity_bond":"{bond_b64}"}},"nick":"J5xhGSWE7VrxM7sO","network":"mainnet"}}"#
        );
        let msg = PeerHandshake::parse_json(&json).unwrap();
        assert!(msg.fidelity_bond().is_some());
    }

    #[test]
    fn test_validate_wrong_nick_version_byte() {
        // 'M' is not a valid JM version byte (Python always uses '5').
        // The nick must be rejected regardless of which network the DN serves.
        let json = r#"{"app-name":"joinmarket","directory":false,"location-string":"","proto-ver":5,"features":{},"nick":"JMxhGSWE7VrxM7sO","network":"mainnet"}"#;
        let msg = PeerHandshake::parse_json(json).unwrap();
        let err = msg.validate("mainnet").unwrap_err();
        assert!(matches!(err, HandshakeError::MalformedNick),
            "expected MalformedNick for invalid version byte, got {:?}", err);
    }

    #[test]
    fn test_peer_handshake_no_bond() {
        let msg = PeerHandshake::parse_json(valid_handshake_json()).unwrap();
        assert!(msg.fidelity_bond().is_none());
    }

    #[test]
    fn test_oversized_app_name_rejected() {
        // app_name > MAX_FIELD_LEN (64) must be rejected at parse time.
        let long_name = "x".repeat(65);
        let json = format!(
            "{{\"app-name\":\"{long_name}\",\"directory\":false,\"location-string\":\"\",\"proto-ver\":5,\"features\":{{}},\"nick\":\"J5xhGSWE7VrxM7sO\",\"network\":\"mainnet\"}}"
        );
        let err = PeerHandshake::parse_json(&json).unwrap_err();
        assert!(matches!(err, HandshakeError::FieldTooLong),
            "expected FieldTooLong, got {:?}", err);
    }

    #[test]
    fn test_oversized_network_rejected() {
        let long_net = "n".repeat(65);
        let json = format!(
            "{{\"app-name\":\"joinmarket\",\"directory\":false,\"location-string\":\"\",\"proto-ver\":5,\"features\":{{}},\"nick\":\"J5xhGSWE7VrxM7sO\",\"network\":\"{long_net}\"}}"
        );
        let err = PeerHandshake::parse_json(&json).unwrap_err();
        assert!(matches!(err, HandshakeError::FieldTooLong),
            "expected FieldTooLong, got {:?}", err);
    }

    #[test]
    fn test_oversized_feature_key_rejected() {
        let long_key = "k".repeat(65);
        let json = format!(
            "{{\"app-name\":\"joinmarket\",\"directory\":false,\"location-string\":\"\",\"proto-ver\":5,\"features\":{{\"{long_key}\":true}},\"nick\":\"J5xhGSWE7VrxM7sO\",\"network\":\"mainnet\"}}"
        );
        let err = PeerHandshake::parse_json(&json).unwrap_err();
        assert!(matches!(err, HandshakeError::FieldTooLong),
            "expected FieldTooLong, got {:?}", err);
    }

    #[test]
    fn test_advertised_true_features_preserves_unknown_features() {
        let json = r#"{"app-name":"joinmarket","directory":false,"location-string":"","proto-ver":5,"features":{"zeta":true,"ping":true,"alpha":true},"nick":"J5xhGSWE7VrxM7sO","network":"mainnet"}"#;
        let msg = PeerHandshake::parse_json(json).unwrap();
        let mut features = msg.advertised_true_features();
        features.sort_unstable();
        assert_eq!(features, vec!["alpha".to_string(), "ping".to_string(), "zeta".to_string()]);
    }

    #[test]
    fn test_advertised_true_features_ignores_non_boolean_true_values() {
        let json = r#"{"app-name":"joinmarket","directory":false,"location-string":"","proto-ver":5,"features":{"ping":true,"falsey":false,"stringy":"true","numbery":1,"nullish":null},"nick":"J5xhGSWE7VrxM7sO","network":"mainnet"}"#;
        let msg = PeerHandshake::parse_json(json).unwrap();
        assert_eq!(msg.advertised_true_features(), vec!["ping".to_string()]);
    }

    #[test]
    fn test_invalid_feature_name_rejected() {
        let json = r#"{"app-name":"joinmarket","directory":false,"location-string":"","proto-ver":5,"features":{"evil;D":true},"nick":"J5xhGSWE7VrxM7sO","network":"mainnet"}"#;
        let err = PeerHandshake::parse_json(json).unwrap_err();
        assert!(matches!(err, HandshakeError::InvalidFeatureName(name) if name == "evil;D"));
    }

    #[test]
    fn test_invalid_feature_name_variants_rejected() {
        for invalid in ["x,y", "ping+weird", "has space", "UpperCase", "hyphen-name", "", "pé"] {
            let json = format!(
                "{{\"app-name\":\"joinmarket\",\"directory\":false,\"location-string\":\"\",\"proto-ver\":5,\"features\":{{\"{invalid}\":true}},\"nick\":\"J5xhGSWE7VrxM7sO\",\"network\":\"mainnet\"}}"
            );
            let err = PeerHandshake::parse_json(&json).unwrap_err();
            assert!(matches!(err, HandshakeError::InvalidFeatureName(name) if name == invalid));
        }
    }

    #[test]
    fn test_dn_supported_features() {
        assert_eq!(dn_supported_feature_names(), &["peerlist_features", "ping"]);
        let features = dn_supported_features();
        assert_eq!(features.get("ping"), Some(&serde_json::Value::Bool(true)));
        assert_eq!(
            features.get("peerlist_features"),
            Some(&serde_json::Value::Bool(true))
        );
        assert_eq!(features.len(), 2);
    }

}
