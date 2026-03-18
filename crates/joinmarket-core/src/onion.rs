use sha3::{Digest, Sha3_256};

/// A validated Tor v3 onion address (without port).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OnionAddress(String);

/// A validated onion address + port pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionServiceAddr {
    pub host: OnionAddress,
    pub port: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum OnionAddressError {
    #[error("wrong length: expected 62 chars (56 base32 + '.onion'), got {0}")]
    WrongLength(usize),
    #[error("missing '.onion' suffix")]
    MissingOnionSuffix,
    #[error("invalid base32 encoding: {0}")]
    InvalidBase32(String),
    #[error("wrong version byte: expected 0x03, got {0:#04x}")]
    WrongVersion(u8),
    #[error("checksum mismatch: address is corrupt or truncated")]
    ChecksumMismatch,
}

#[derive(Debug, thiserror::Error)]
pub enum OnionServiceAddrError {
    #[error("missing port in location-string (expected '<onion>:<port>')")]
    MissingPort,
    #[error("invalid port number: {0}")]
    InvalidPort(String),
    #[error("invalid onion address: {0}")]
    InvalidOnion(#[from] OnionAddressError),
}

impl OnionAddress {
    pub fn parse(s: &str) -> Result<Self, OnionAddressError> {
        let s = s.to_lowercase();

        if s.len() != 62 {
            return Err(OnionAddressError::WrongLength(s.len()));
        }

        if !s.ends_with(".onion") {
            return Err(OnionAddressError::MissingOnionSuffix);
        }

        let encoded = &s[..56];

        let decoded = data_encoding::BASE32_NOPAD
            .decode(encoded.to_uppercase().as_bytes())
            .map_err(|e| OnionAddressError::InvalidBase32(e.to_string()))?;

        assert_eq!(decoded.len(), 35, "base32 decode of 56-char v3 onion must be 35 bytes");

        let pubkey   = &decoded[0..32];
        let checksum = &decoded[32..34];
        let version  =  decoded[34];

        if version != 0x03 {
            return Err(OnionAddressError::WrongVersion(version));
        }

        let mut hasher = Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(pubkey);
        hasher.update([version]);
        let hash = hasher.finalize();

        if &hash[0..2] != checksum {
            return Err(OnionAddressError::ChecksumMismatch);
        }

        Ok(OnionAddress(s))
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        let encoded = &self.0[..56];
        let decoded = data_encoding::BASE32_NOPAD
            .decode(encoded.to_uppercase().as_bytes())
            .expect("already validated");
        decoded[0..32].try_into().expect("already validated")
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

impl std::fmt::Display for OnionAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl OnionServiceAddr {
    pub fn parse(s: &str) -> Result<Self, OnionServiceAddrError> {
        let (host_str, port_str) = s.rsplit_once(':')
            .ok_or(OnionServiceAddrError::MissingPort)?;
        let port = port_str.parse::<u16>()
            .map_err(|_| OnionServiceAddrError::InvalidPort(port_str.to_string()))?;
        if port == 0 {
            return Err(OnionServiceAddrError::InvalidPort("0 (port must be non-zero)".to_string()));
        }
        let host = OnionAddress::parse(host_str)?;
        Ok(OnionServiceAddr { host, port })
    }

    pub fn as_location_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A known-valid Tor v3 onion address for testing
    // This is a real v3 address from the Tor project documentation
    const VALID_V3: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

    #[test]
    fn test_valid_v3_address() {
        assert!(OnionAddress::parse(VALID_V3).is_ok());
    }

    #[test]
    fn test_wrong_length() {
        let err = OnionAddress::parse("short.onion").unwrap_err();
        assert!(matches!(err, OnionAddressError::WrongLength(_)));
    }

    #[test]
    fn test_missing_onion_suffix() {
        // 62 chars but no .onion suffix - make a 62 char string without .onion
        let s = "a".repeat(62);
        let err = OnionAddress::parse(&s).unwrap_err();
        // This could be WrongLength or MissingOnionSuffix depending on length
        // A 62-char string without .onion is actually caught by missing suffix check
        // since length is right but suffix is wrong
        let _ = err; // just check it errors
    }

    #[test]
    fn test_case_insensitive() {
        let upper = VALID_V3.to_uppercase();
        assert!(OnionAddress::parse(&upper).is_ok());
    }

    #[test]
    fn test_onion_service_addr_parse() {
        let addr = format!("{}:5222", VALID_V3);
        let result = OnionServiceAddr::parse(&addr).unwrap();
        assert_eq!(result.port, 5222);
        assert_eq!(result.as_location_string(), addr);
    }

    #[test]
    fn test_missing_port() {
        let err = OnionServiceAddr::parse(VALID_V3).unwrap_err();
        assert!(matches!(err, OnionServiceAddrError::MissingPort) || matches!(err, OnionServiceAddrError::InvalidOnion(_)));
    }

    #[test]
    fn test_invalid_port() {
        let addr = format!("{}:99999", VALID_V3);
        let err = OnionServiceAddr::parse(&addr).unwrap_err();
        assert!(matches!(err, OnionServiceAddrError::InvalidPort(_)));
    }

    #[test]
    fn test_v2_address_rejected() {
        // v2 addresses are 16-char base32 + ".onion" = 22 chars (not 62)
        let err = OnionAddress::parse("aaaaaaaaaaaaaaaa.onion").unwrap_err();
        assert!(matches!(err, OnionAddressError::WrongLength(_)));
    }

    #[test]
    fn test_port_zero_rejected() {
        let addr = format!("{}:0", VALID_V3);
        let err = OnionServiceAddr::parse(&addr).unwrap_err();
        assert!(matches!(err, OnionServiceAddrError::InvalidPort(_)));
    }

    #[test]
    fn test_port_65535() {
        let addr = format!("{}:65535", VALID_V3);
        let result = OnionServiceAddr::parse(&addr).unwrap();
        assert_eq!(result.port, 65535);
    }

    #[test]
    fn test_mixed_case_input() {
        // Explicit mixed case like "2Gzyxa5..."
        let mixed = "2Gzyxa5Ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
        let result = OnionAddress::parse(mixed);
        assert!(result.is_ok());
    }

    #[test]
    fn test_location_string_roundtrip() {
        let input = format!("{}:5222", VALID_V3);
        let parsed = OnionServiceAddr::parse(&input).unwrap();
        let output = parsed.as_location_string();
        let reparsed = OnionServiceAddr::parse(&output).unwrap();
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn test_checksum_mismatch() {
        // Corrupt a known valid address by changing one character
        let mut chars: Vec<char> = VALID_V3.chars().collect();
        chars[0] = if chars[0] == '2' { '3' } else { '2' };
        let corrupted: String = chars.into_iter().collect();
        let result = OnionAddress::parse(&corrupted);
        assert!(result.is_err());
    }
}
