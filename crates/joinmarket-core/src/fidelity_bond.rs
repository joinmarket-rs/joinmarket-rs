use base64::Engine;
use secp256k1::PublicKey;

/// A parsed fidelity bond proof as transmitted in the handshake `features` map.
///
/// # Signature verification — intentionally not performed by the directory node
///
/// A complete bond proof contains two signatures (`nick_sig`, `cert_sig`) that
/// could be verified in-band without blockchain access.  The directory node
/// deliberately does **not** verify them for the following reasons:
///
/// 1. **Division of responsibility** — The DN is a routing layer, not a trust
///    authority.  Takers are responsible for validating bond proofs (including
///    on-chain UTXO existence and value) before selecting makers.  Duplicating
///    that logic here would couple the DN to the Bitcoin signing protocol.
///
/// 2. **No blockchain access** — Full bond validation requires confirming that
///    the claimed UTXO exists on-chain and has the correct value and timelock.
///    The DN runs without a Bitcoin node by design.
///
/// 3. **The DN's bond role is narrow** — The only bond-related enforcement the
///    DN performs is UTXO uniqueness (via `FidelityBondRegistry`): two makers
///    cannot claim the same UTXO simultaneously.  This prevents one maker from
///    borrowing another's bond to inflate their apparent reputation with the DN,
///    even though it does not prove the bond is cryptographically valid.
///
/// Do **not** add signature verification here without first re-evaluating the
/// DN's no-blockchain design constraint.
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
    #[error("bond contains an invalid secp256k1 public key")]
    InvalidPublicKey,
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
        // The length has been verified to be exactly 252 above, so these fixed-offset
        // slices are always exactly the right size.  Use `.expect()` with an explicit
        // invariant comment rather than a bare `.unwrap()` so the precondition is
        // documented and a future accidental length change yields a clear message.
        let cert_expiry = u16::from_le_bytes(
            decoded[offset..offset + 2]
                .try_into()
                .expect("slice is exactly 2 bytes: length invariant verified above"),
        );
        offset += 2;

        let mut utxo_pubkey = [0u8; 33];
        utxo_pubkey.copy_from_slice(&decoded[offset..offset + 33]);
        offset += 33;

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&decoded[offset..offset + 32]);
        offset += 32;

        let vout = u32::from_le_bytes(
            decoded[offset..offset + 4]
                .try_into()
                .expect("slice is exactly 4 bytes: length invariant verified above"),
        );
        offset += 4;

        let timelock = u32::from_le_bytes(
            decoded[offset..offset + 4]
                .try_into()
                .expect("slice is exactly 4 bytes: length invariant verified above"),
        );

        // Validate that cert_pubkey and utxo_pubkey are valid secp256k1 compressed
        // curve points.  This rejects trivially garbage bonds and prevents an attacker
        // from squatting a UTXO slot using garbage key bytes.  Full signature
        // verification (deliberately not performed here — see module doc-comment)
        // would also be required to block squatting by a party who knows the victim's
        // real pubkey.
        PublicKey::from_slice(&cert_pubkey)
            .map_err(|_| BondParseError::InvalidPublicKey)?;
        PublicKey::from_slice(&utxo_pubkey)
            .map_err(|_| BondParseError::InvalidPublicKey)?;

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

    /// Build a valid 252-byte bond blob that passes pubkey-point validation.
    /// Both cert_pubkey (offset 144) and utxo_pubkey (offset 179) are set to the
    /// compressed secp256k1 generator point G, which is a known-valid curve point.
    fn valid_bond_blob() -> Vec<u8> {
        // Compressed generator point G:
        // 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        let g: [u8; 33] = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95,
            0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59,
            0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        let mut blob = vec![0u8; 252];
        blob[144..177].copy_from_slice(&g); // cert_pubkey
        blob[179..212].copy_from_slice(&g); // utxo_pubkey
        blob
    }

    #[test]
    fn test_parse_valid_bond() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(valid_bond_blob());
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

    #[test]
    fn test_invalid_cert_pubkey_rejected() {
        // Use a valid-length blob but with garbage bytes at the cert_pubkey offset (144)
        // so it is not a valid secp256k1 point.
        let encoded = base64::engine::general_purpose::STANDARD.encode(vec![0xffu8; 252]);
        let err = FidelityBondProof::parse_base64(&encoded).unwrap_err();
        assert!(matches!(err, BondParseError::InvalidPublicKey),
            "expected InvalidPublicKey, got {:?}", err);
    }

    #[test]
    fn test_invalid_utxo_pubkey_rejected() {
        // cert_pubkey is valid (G), but utxo_pubkey (offset 179) is left as zeros.
        let g: [u8; 33] = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95,
            0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59,
            0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        let mut blob = vec![0u8; 252];
        blob[144..177].copy_from_slice(&g); // cert_pubkey = valid
        // utxo_pubkey at 179..212 remains all-zero — not a valid point
        let encoded = base64::engine::general_purpose::STANDARD.encode(&blob);
        let err = FidelityBondProof::parse_base64(&encoded).unwrap_err();
        assert!(matches!(err, BondParseError::InvalidPublicKey),
            "expected InvalidPublicKey for invalid utxo_pubkey, got {:?}", err);
    }
}
