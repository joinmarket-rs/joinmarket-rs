use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use parking_lot::Mutex;
use joinmarket_core::onion::OnionServiceAddr;
use joinmarket_core::fidelity_bond::FidelityBondProof;

use crate::sybil_guard::{SybilGuard, SybilError};
use crate::bond_registry::{FidelityBondRegistry, BondError};

/// Maximum number of concurrently connected peers (makers + takers combined).
const MAX_CONCURRENT_PEERS: u32 = 100_000;

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("nick already connected: {0}")]
    DuplicateNick(String),
    #[error("sybil guard rejected: {0}")]
    Sybil(#[from] SybilError),
    #[error("bond UTXO duplicate: {0}")]
    BondDuplicate(#[from] BondError),
    #[error("peer capacity reached ({0})")]
    PeerCapacity(u32),
}

pub struct AdmissionController {
    /// Mutex-protected set of currently-admitted nicks. Checked and updated
    /// as the very first step of `admit_peer` to atomically prevent two
    /// concurrent tasks from racing through the multi-step admission pipeline
    /// with the same nick.
    admitted_nicks: Mutex<HashSet<String>>,
    sybil_guard: SybilGuard,
    bond_registry: FidelityBondRegistry,
    peer_count: AtomicU32,
}

impl Default for AdmissionController {
    fn default() -> Self {
        Self::new()
    }
}

impl AdmissionController {
    pub fn new() -> Self {
        AdmissionController {
            admitted_nicks: Mutex::new(HashSet::new()),
            sybil_guard: SybilGuard::new(),
            bond_registry: FidelityBondRegistry::new(),
            peer_count: AtomicU32::new(0),
        }
    }

    /// Layers 2, 3, 4: Admit peer after handshake
    pub fn admit_peer(
        &self,
        nick: &str,
        onion_addr: &OnionServiceAddr,
        bond: Option<&FidelityBondProof>,
    ) -> Result<(), AdmissionError> {
        // Layer 1: Nick uniqueness — atomically reserve the nick before any
        // subsequent checks so that two concurrent tasks for the same nick
        // cannot both pass the multi-step pipeline simultaneously.
        {
            let mut admitted = self.admitted_nicks.lock();
            if admitted.contains(nick) {
                metrics::counter!("jm_admission_duplicate_nick_total").increment(1);
                return Err(AdmissionError::DuplicateNick(nick.to_string()));
            }
            admitted.insert(nick.to_string());
        } // lock released before heavier checks

        // Layer 2: Sybil guard
        self.sybil_guard.register(nick, &onion_addr.host).map_err(|e| {
            self.admitted_nicks.lock().remove(nick);
            metrics::counter!("jm_admission_sybil_rejections_total").increment(1);
            AdmissionError::Sybil(e)
        })?;

        // Layer 3: Bond deduplication (only for makers with bonds)
        if let Some(b) = bond {
            if let Err(e) = self.bond_registry.register_bond(nick, b) {
                self.sybil_guard.deregister(nick);
                self.admitted_nicks.lock().remove(nick);
                metrics::counter!("jm_admission_bond_dup_rejections_total").increment(1);
                return Err(AdmissionError::BondDuplicate(e));
            }
        }

        // Layer 4: Global peer capacity cap (makers + takers combined).
        // Atomically reserve a slot; roll back all prior layers if over capacity.
        let prev = self.peer_count.fetch_add(1, Ordering::AcqRel);
        if prev >= MAX_CONCURRENT_PEERS {
            self.peer_count.fetch_sub(1, Ordering::AcqRel);
            self.sybil_guard.deregister(nick);
            if bond.is_some() {
                self.bond_registry.deregister_nick(nick);
            }
            self.admitted_nicks.lock().remove(nick);
            metrics::counter!("jm_admission_peer_cap_rejections_total").increment(1);
            return Err(AdmissionError::PeerCapacity(prev));
        }

        Ok(())
    }

    pub fn release_peer(&self, nick: &str) {
        self.sybil_guard.deregister(nick);
        self.bond_registry.deregister_nick(nick);
        self.peer_count.fetch_sub(1, Ordering::AcqRel);
        self.admitted_nicks.lock().remove(nick);
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

    fn make_onion_addr2() -> OnionServiceAddr {
        OnionServiceAddr::parse(
            "coinjointovy3eq5fjygdwpkbcdx63d7vd4g32mw7y553uj3kjjzkiqd.onion:5222"
        ).unwrap()
    }

    #[test]
    fn test_admit_maker_increments_peer_count() {
        let ac = AdmissionController::new();
        let onion = make_onion_addr();
        assert!(ac.admit_peer("J5nickAAAAAAAA0", &onion, None).is_ok());
        assert_eq!(ac.peer_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_duplicate_nick_rejected() {
        let ac = AdmissionController::new();
        let onion = make_onion_addr();
        ac.admit_peer("J5nickAAAAAAAA0", &onion, None).unwrap();
        // Second admission with same nick must fail even from a different onion
        let onion2 = make_onion_addr2();
        let err = ac.admit_peer("J5nickAAAAAAAA0", &onion2, None).unwrap_err();
        assert!(matches!(err, AdmissionError::DuplicateNick(_)));
    }

    #[test]
    fn test_duplicate_nick_released_allows_readmit() {
        let ac = AdmissionController::new();
        let onion = make_onion_addr();
        ac.admit_peer("J5nickAAAAAAAA0", &onion, None).unwrap();
        ac.release_peer("J5nickAAAAAAAA0");
        // After release the nick slot is free again
        assert!(ac.admit_peer("J5nickAAAAAAAA0", &onion, None).is_ok());
    }

    #[test]
    fn test_admit_taker_increments_peer_count() {
        let ac = AdmissionController::new();
        let onion = make_onion_addr();
        assert!(ac.admit_peer("J5nickAAAAAAAA0", &onion, None).is_ok());
        assert_eq!(ac.peer_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_makers_and_takers_share_cap() {
        let ac = AdmissionController::new();
        ac.admit_peer("J5nick0000000000OO", &make_onion_addr(), None).unwrap();
        ac.admit_peer("J5nick0000000001OO", &make_onion_addr2(), None).unwrap();
        assert_eq!(ac.peer_count.load(Ordering::Acquire), 2);
    }

    #[test]
    fn test_release_decrements_peer_count_for_maker() {
        let ac = AdmissionController::new();
        let onion = make_onion_addr();
        ac.admit_peer("J5nickAAAAAAAA0", &onion, None).unwrap();
        ac.release_peer("J5nickAAAAAAAA0");
        assert_eq!(ac.peer_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn test_release_decrements_peer_count_for_taker() {
        let ac = AdmissionController::new();
        let onion = make_onion_addr();
        ac.admit_peer("J5nickAAAAAAAA0", &onion, None).unwrap();
        ac.release_peer("J5nickAAAAAAAA0");
        assert_eq!(ac.peer_count.load(Ordering::Acquire), 0);
    }
}
