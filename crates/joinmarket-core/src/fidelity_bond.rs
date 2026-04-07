use base64::Engine;

#[derive(Debug, Clone)]
pub struct FidelityBondProof {
    pub nick_sig:    [u8; 72],
    pub cert_sig:    [u8; 72],
    pub cert_pubkey: [u8; 33],
    pub cert_expiry: u16,
    pub utxo_pubkey: [u8; 33],
    pub txid:        [u8; 32],
    pub vout:        u32,
    pub timelock:    u32,
}

#[derive(Debug, thiserror::Error)]
pub enum BondParseError {
    #[error("base64 decode error: {0}")]
    Base64Decode(String),
    #[error("wrong size: expected 252 bytes, got {0}")]
    WrongSize(usize),
}

impl FidelityBondProof {
    pub fn parse_base64(encoded: &str) -> Result<Self, BondParseError> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|e| BondParseError::Base64Decode(e.to_string()))?;

        if decoded.len() != 252 {
            return Err(BondParseError::WrongSize(decoded.len()));
        }

        let mut offset = 0;

        let mut nick_sig = [0u8; 72];
        nick_sig.copy_from_slice(&decoded[offset..offset + 72]);
        offset += 72;

        let mut cert_sig = [0u8; 72];
        cert_sig.copy_from_slice(&decoded[offset..offset + 72]);
        offset += 72;

        let mut cert_pubkey = [0u8; 33];
        cert_pubkey.copy_from_slice(&decoded[offset..offset + 33]);
        offset += 33;

        // Python serialises with struct.pack('<..H..II', ...) — little-endian.
        let cert_expiry = u16::from_le_bytes(decoded[offset..offset + 2].try_into().unwrap());
        offset += 2;

        let mut utxo_pubkey = [0u8; 33];
        utxo_pubkey.copy_from_slice(&decoded[offset..offset + 33]);
        offset += 33;

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&decoded[offset..offset + 32]);
        offset += 32;

        let vout = u32::from_le_bytes(decoded[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let timelock = u32::from_le_bytes(decoded[offset..offset + 4].try_into().unwrap());

        Ok(FidelityBondProof {
            nick_sig,
            cert_sig,
            cert_pubkey,
            cert_expiry,
            utxo_pubkey,
            txid,
            vout,
            timelock,
        })
    }

    pub fn utxo_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.txid,
            vout: self.vout,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn test_parse_valid_bond() {
        // Create a 252-byte blob and base64-encode it
        let blob = vec![0u8; 252];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&blob);
        let result = FidelityBondProof::parse_base64(&encoded).unwrap();
        assert_eq!(result.vout, 0);
        assert_eq!(result.timelock, 0);
    }

    #[test]
    fn test_parse_wrong_size() {
        let blob = vec![0u8; 100];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&blob);
        let err = FidelityBondProof::parse_base64(&encoded).unwrap_err();
        assert!(matches!(err, BondParseError::WrongSize(100)));
    }

    #[test]
    fn test_parse_251_bytes_rejected() {
        let blob = vec![0u8; 251];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&blob);
        let err = FidelityBondProof::parse_base64(&encoded).unwrap_err();
        assert!(matches!(err, BondParseError::WrongSize(251)));
    }

    #[test]
    fn test_parse_253_bytes_rejected() {
        let blob = vec![0u8; 253];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&blob);
        let err = FidelityBondProof::parse_base64(&encoded).unwrap_err();
        assert!(matches!(err, BondParseError::WrongSize(253)));
    }

    #[test]
    fn test_parse_invalid_base64() {
        let err = FidelityBondProof::parse_base64("not-valid-base64!!!").unwrap_err();
        assert!(matches!(err, BondParseError::Base64Decode(_)));
    }
}
