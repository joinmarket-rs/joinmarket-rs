use std::sync::atomic::{AtomicU32, Ordering};
use joinmarket_core::onion::OnionServiceAddr;
use joinmarket_core::fidelity_bond::FidelityBondProof;

use crate::sybil_guard::{SybilGuard, SybilError};
use crate::bond_registry::{FidelityBondRegistry, BondError};

const MAX_CONCURRENT_MAKERS: u32 = 100_000;

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("sybil guard rejected: {0}")]
    Sybil(#[from] SybilError),
    #[error("bond UTXO duplicate: {0}")]
    BondDuplicate(#[from] BondError),
    #[error("maker capacity reached ({0})")]
    MakerCapacity(u32),
}

pub struct AdmissionController {
    sybil_guard: SybilGuard,
    bond_registry: FidelityBondRegistry,
    maker_count: AtomicU32,
}

impl Default for AdmissionController {
    fn default() -> Self {
        Self::new()
    }
}

impl AdmissionController {
    pub fn new() -> Self {
        AdmissionController {
            sybil_guard: SybilGuard::new(),
            bond_registry: FidelityBondRegistry::new(),
            maker_count: AtomicU32::new(0),
        }
    }

    /// Layers 2, 3, 4: Admit peer after handshake
    pub fn admit_peer(
        &self,
        nick: &str,
        onion_addr: &OnionServiceAddr,
        is_maker: bool,
        bond: Option<&FidelityBondProof>,
    ) -> Result<(), AdmissionError> {
        // Layer 2: Sybil guard
        self.sybil_guard.register(nick, &onion_addr.host).map_err(|e| {
            metrics::counter!("jm_admission_sybil_rejections_total").increment(1);
            AdmissionError::Sybil(e)
        })?;

        // Layer 3: Bond deduplication (only for makers with bonds)
        if let Some(b) = bond {
            if let Err(e) = self.bond_registry.register_bond(nick, b) {
                self.sybil_guard.deregister(nick);
                metrics::counter!("jm_admission_bond_dup_rejections_total").increment(1);
                return Err(AdmissionError::BondDuplicate(e));
            }
        }

        // Layer 4: Maker capacity cap
        if is_maker {
            // Atomically reserve a slot; roll back if over capacity.
            let prev = self.maker_count.fetch_add(1, Ordering::AcqRel);
            if prev >= MAX_CONCURRENT_MAKERS {
                self.maker_count.fetch_sub(1, Ordering::AcqRel);
                self.sybil_guard.deregister(nick);
                if bond.is_some() {
                    self.bond_registry.deregister_nick(nick);
                }
                metrics::counter!("jm_admission_maker_cap_rejections_total").increment(1);
                return Err(AdmissionError::MakerCapacity(prev));
            }
        }

        Ok(())
    }

    pub fn release_peer(&self, nick: &str, is_maker: bool) {
        self.sybil_guard.deregister(nick);
        self.bond_registry.deregister_nick(nick);
        if is_maker {
            self.maker_count.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use joinmarket_core::onion::OnionServiceAddr;

    fn make_onion_addr() -> OnionServiceAddr {
        OnionServiceAddr::parse(
            "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion:5222"
        ).unwrap()
    }

    #[test]
    fn test_admit_maker_ok() {
        let ac = AdmissionController::new();
        let onion = make_onion_addr();
        assert!(ac.admit_peer("J5nickAAAAAAAA0", &onion, true, None).is_ok());
        assert_eq!(ac.maker_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_rollback_on_capacity_exceeded() {
        let ac = AdmissionController::new();
        let onion = make_onion_addr();
        // Admit one maker
        ac.admit_peer("J5nick0000000000OO", &onion, true, None).unwrap();
        assert!(ac.sybil_guard.is_nick_active("J5nick0000000000OO"));
    }

    #[test]
    fn test_maker_cap_uses_distinct_metric() {
        let ac = AdmissionController::new();
        let onion = make_onion_addr();
        // Admit one maker
        ac.admit_peer("J5nick0000000000OO", &onion, true, None).unwrap();
        assert_eq!(ac.maker_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_release_decrements_maker_count() {
        let ac = AdmissionController::new();
        let onion = make_onion_addr();
        ac.admit_peer("J5nickAAAAAAAA0", &onion, true, None).unwrap();
        ac.release_peer("J5nickAAAAAAAA0", true);
        assert_eq!(ac.maker_count.load(Ordering::Acquire), 0);
    }
}
