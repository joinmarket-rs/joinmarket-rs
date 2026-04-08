use std::collections::HashMap;
use parking_lot::Mutex;
use joinmarket_core::fidelity_bond::{FidelityBondProof, OutPoint};

struct BondMaps {
    utxo_to_nick: HashMap<OutPointKey, String>,
    nick_to_utxo: HashMap<String, OutPointKey>,
}

pub struct FidelityBondRegistry {
    inner: Mutex<BondMaps>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OutPointKey {
    txid: [u8; 32],
    vout: u32,
}

impl From<&OutPoint> for OutPointKey {
    fn from(op: &OutPoint) -> Self {
        OutPointKey { txid: op.txid, vout: op.vout }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BondError {
    /// The UTXO outpoint is already registered to a different nick.
    /// The existing nick is intentionally *not* included in `Display` to prevent
    /// nick enumeration: an adversary who knows a victim's UTXO could otherwise
    /// probe the bond registry to learn which nick currently holds it.
    #[error("UTXO outpoint already claimed by another maker")]
    DuplicateUtxo,
}

impl Default for FidelityBondRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FidelityBondRegistry {
    pub fn new() -> Self {
        FidelityBondRegistry {
            inner: Mutex::new(BondMaps {
                utxo_to_nick: HashMap::new(),
                nick_to_utxo: HashMap::new(),
            }),
        }
    }

    pub fn register_bond(&self, nick: &str, bond: &FidelityBondProof) -> Result<(), BondError> {
        let outpoint = bond.utxo_outpoint();
        let key = OutPointKey::from(&outpoint);
        let mut maps = self.inner.lock();

        if let Some(existing_nick) = maps.utxo_to_nick.get(&key) {
            if existing_nick.as_str() != nick {
                // Log at DEBUG only to avoid exposing the existing nick in warn-level
                // output where an adversary probing with a known UTXO could read it.
                tracing::debug!(
                    txid = ?key.txid,
                    vout = key.vout,
                    "bond registry: UTXO already claimed by a different nick"
                );
                return Err(BondError::DuplicateUtxo);
            }
        }

        // Remove old UTXO mapping if this nick had one
        if let Some(old_key) = maps.nick_to_utxo.remove(nick) {
            maps.utxo_to_nick.remove(&old_key);
        }

        maps.utxo_to_nick.insert(key.clone(), nick.to_string());
        maps.nick_to_utxo.insert(nick.to_string(), key);
        Ok(())
    }

    pub fn deregister_nick(&self, nick: &str) {
        let mut maps = self.inner.lock();
        if let Some(key) = maps.nick_to_utxo.remove(nick) {
            maps.utxo_to_nick.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use joinmarket_core::fidelity_bond::FidelityBondProof;

    fn make_bond_with_vout(vout: u32) -> FidelityBondProof {
        // Compressed secp256k1 generator point G (valid curve point).
        let g: [u8; 33] = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95,
            0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59,
            0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        let mut blob = vec![0u8; 252];
        blob[144..177].copy_from_slice(&g); // cert_pubkey
        blob[179..212].copy_from_slice(&g); // utxo_pubkey
        // Set vout at offset 72+72+33+2+33+32 = 244
        blob[244..248].copy_from_slice(&vout.to_le_bytes());
        let encoded = base64::engine::general_purpose::STANDARD.encode(&blob);
        FidelityBondProof::parse_base64(&encoded).unwrap()
    }

    #[test]
    fn test_register_bond_ok() {
        let registry = FidelityBondRegistry::new();
        let bond = make_bond_with_vout(0);
        assert!(registry.register_bond("J5nickAAAAAAAA0", &bond).is_ok());
    }

    #[test]
    fn test_duplicate_utxo_rejected() {
        let registry = FidelityBondRegistry::new();
        let bond = make_bond_with_vout(0);
        registry.register_bond("J5nickAAAAAAAA0", &bond).unwrap();
        let err = registry.register_bond("J5nickBBBBBBBB0", &bond).unwrap_err();
        assert!(matches!(err, BondError::DuplicateUtxo));
    }

    #[test]
    fn test_deregister_frees_utxo() {
        let registry = FidelityBondRegistry::new();
        let bond = make_bond_with_vout(0);
        registry.register_bond("J5nickAAAAAAAA0", &bond).unwrap();
        registry.deregister_nick("J5nickAAAAAAAA0");
        // Now another nick can claim the same UTXO
        assert!(registry.register_bond("J5nickBBBBBBBB0", &bond).is_ok());
    }
}
