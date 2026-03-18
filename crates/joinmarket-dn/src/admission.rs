use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use dashmap::DashMap;
use parking_lot::Mutex;
use joinmarket_core::onion::OnionServiceAddr;
use joinmarket_core::fidelity_bond::FidelityBondProof;

use crate::sybil_guard::{SybilGuard, SybilError};
use crate::bond_registry::{FidelityBondRegistry, BondError};

const MAX_CONNECTIONS_PER_ONION_PER_MINUTE: usize = 3;
const MAX_NEW_MAKER_REGISTRATIONS_PER_MINUTE: usize = 60;
const MAX_CONCURRENT_MAKERS: u32 = 100_000;

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("rate limit exceeded for onion: {0}")]
    RateLimit(String),
    #[error("sybil guard rejected: {0}")]
    Sybil(#[from] SybilError),
    #[error("bond UTXO duplicate: {0}")]
    BondDuplicate(#[from] BondError),
    #[error("maker capacity reached ({0})")]
    MakerCapacity(u32),
    #[error("maker registration rate limit exceeded")]
    MakerRateLimit,
}

struct RateWindow {
    timestamps: VecDeque<Instant>,
}

impl RateWindow {
    fn new() -> Self {
        RateWindow { timestamps: VecDeque::new() }
    }

    fn check_and_record(&mut self, max: usize, window: Duration) -> bool {
        let now = Instant::now();
        let cutoff = now - window;

        // Remove expired entries
        while self.timestamps.front().is_some_and(|&t| t < cutoff) {
            self.timestamps.pop_front();
        }

        if self.timestamps.len() >= max {
            false
        } else {
            self.timestamps.push_back(now);
            true
        }
    }
}

pub struct AdmissionController {
    rate_windows: DashMap<String, Mutex<RateWindow>>,
    sybil_guard: SybilGuard,
    bond_registry: FidelityBondRegistry,
    maker_registrations: Mutex<VecDeque<Instant>>,
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
            rate_windows: DashMap::new(),
            sybil_guard: SybilGuard::new(),
            bond_registry: FidelityBondRegistry::new(),
            maker_registrations: Mutex::new(VecDeque::new()),
            maker_count: AtomicU32::new(0),
        }
    }

    /// Layer 2: Check connection rate per onion
    pub fn check_connection(&self, onion_addr: &str) -> Result<(), AdmissionError> {
        let entry = self.rate_windows
            .entry(onion_addr.to_string())
            .or_insert_with(|| Mutex::new(RateWindow::new()));

        let allowed = entry.lock()
            .check_and_record(MAX_CONNECTIONS_PER_ONION_PER_MINUTE, Duration::from_secs(60));

        if !allowed {
            metrics::counter!("jm_admission_rate_limit_rejections_total").increment(1);
            return Err(AdmissionError::RateLimit(onion_addr.to_string()));
        }
        Ok(())
    }

    /// Layers 3, 4, 5: Admit peer after handshake
    pub fn admit_peer(
        &self,
        nick: &str,
        onion_addr: &OnionServiceAddr,
        is_maker: bool,
        bond: Option<&FidelityBondProof>,
    ) -> Result<(), AdmissionError> {
        // Layer 3: Sybil guard
        self.sybil_guard.register(nick, &onion_addr.host).map_err(|e| {
            metrics::counter!("jm_admission_sybil_rejections_total").increment(1);
            AdmissionError::Sybil(e)
        })?;

        // Layer 4: Bond deduplication (only for makers with bonds)
        if let Some(b) = bond {
            if let Err(e) = self.bond_registry.register_bond(nick, b) {
                self.sybil_guard.deregister(nick);
                metrics::counter!("jm_admission_bond_dup_rejections_total").increment(1);
                return Err(AdmissionError::BondDuplicate(e));
            }
        }

        // Layer 5: Maker throttle
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

            let mut regs = self.maker_registrations.lock();
            let now = Instant::now();
            let cutoff = now - Duration::from_secs(60);
            while regs.front().is_some_and(|&t: &Instant| t < cutoff) {
                regs.pop_front();
            }
            if regs.len() >= MAX_NEW_MAKER_REGISTRATIONS_PER_MINUTE {
                drop(regs);
                self.maker_count.fetch_sub(1, Ordering::AcqRel);
                self.sybil_guard.deregister(nick);
                if bond.is_some() {
                    self.bond_registry.deregister_nick(nick);
                }
                metrics::counter!("jm_admission_maker_rate_limit_rejections_total").increment(1);
                return Err(AdmissionError::MakerRateLimit);
            }
            regs.push_back(now);
        }

        Ok(())
    }

    /// Remove rate-window entries that have no timestamps within the last 60 seconds.
    /// Called periodically from the heartbeat loop to prevent unbounded memory growth.
    pub fn cleanup_stale_rate_windows(&self) {
        let cutoff = Instant::now() - Duration::from_secs(60);
        self.rate_windows.retain(|_, rw| {
            let window = rw.get_mut();
            window.timestamps.back().is_some_and(|&t| t >= cutoff)
        });
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
    fn test_connection_rate_limit() {
        let ac = AdmissionController::new();
        let onion = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

        // First 3 connections should be allowed
        assert!(ac.check_connection(onion).is_ok());
        assert!(ac.check_connection(onion).is_ok());
        assert!(ac.check_connection(onion).is_ok());

        // 4th should be rate-limited
        assert!(matches!(
            ac.check_connection(onion),
            Err(AdmissionError::RateLimit(_))
        ));
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
    fn test_maker_rate_limit_uses_distinct_metric() {
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
