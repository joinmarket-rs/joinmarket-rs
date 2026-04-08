use std::collections::HashMap;
use parking_lot::Mutex;
use joinmarket_core::onion::OnionAddress;

struct SybilMaps {
    onion_to_nick: HashMap<OnionAddress, String>,
    nick_to_onion: HashMap<String, OnionAddress>,
}

pub struct SybilGuard {
    inner: Mutex<SybilMaps>,
}

#[derive(Debug, thiserror::Error)]
pub enum SybilError {
    /// The onion address is already registered to a different nick.
    /// The conflicting nick is intentionally *not* included in the `Display`
    /// output to prevent nick enumeration via admission-rejection log lines.
    #[error("onion address already has an active registration")]
    DuplicateOnion,
}

impl Default for SybilGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl SybilGuard {
    pub fn new() -> Self {
        SybilGuard {
            inner: Mutex::new(SybilMaps {
                onion_to_nick: HashMap::new(),
                nick_to_onion: HashMap::new(),
            }),
        }
    }

    pub fn register(&self, nick: &str, onion: &OnionAddress) -> Result<(), SybilError> {
        let mut maps = self.inner.lock();
        if let Some(existing_nick) = maps.onion_to_nick.get(onion) {
            if existing_nick != nick {
                // Log at DEBUG only — logging the existing nick at WARN would allow
                // an adversary to enumerate nick→onion mappings by probing with
                // controlled onion keys and reading warn-level log output.
                tracing::debug!(
                    onion = %onion.as_str(),
                    "sybil: onion already registered to a different nick"
                );
                return Err(SybilError::DuplicateOnion);
            }
        }
        maps.onion_to_nick.insert(onion.clone(), nick.to_string());
        maps.nick_to_onion.insert(nick.to_string(), onion.clone());
        Ok(())
    }

    pub fn deregister(&self, nick: &str) {
        let mut maps = self.inner.lock();
        if let Some(onion) = maps.nick_to_onion.remove(nick) {
            maps.onion_to_nick.remove(&onion);
        }
    }

    pub fn is_nick_active(&self, nick: &str) -> bool {
        self.inner.lock().nick_to_onion.contains_key(nick)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use joinmarket_core::onion::OnionAddress;

    fn test_onion() -> OnionAddress {
        OnionAddress::parse("2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion").unwrap()
    }

    #[test]
    fn test_register_ok() {
        let guard = SybilGuard::new();
        assert!(guard.register("J5nickAAAAAAAA0", &test_onion()).is_ok());
        assert!(guard.is_nick_active("J5nickAAAAAAAA0"));
    }

    #[test]
    fn test_sybil_rejected() {
        let guard = SybilGuard::new();
        guard.register("J5nickAAAAAAAA0", &test_onion()).unwrap();
        let err = guard.register("J5nickBBBBBBBB0", &test_onion()).unwrap_err();
        assert!(matches!(err, SybilError::DuplicateOnion));
    }

    #[test]
    fn test_reregister_after_deregister() {
        let guard = SybilGuard::new();
        guard.register("J5nickAAAAAAAA0", &test_onion()).unwrap();
        guard.deregister("J5nickAAAAAAAA0");
        // Now a new nick should be allowed from the same onion
        assert!(guard.register("J5nickBBBBBBBB0", &test_onion()).is_ok());
    }

    #[test]
    fn test_same_nick_same_onion_succeeds() {
        let guard = SybilGuard::new();
        guard.register("J5nickAAAAAAAA0", &test_onion()).unwrap();
        // Re-registration with same nick+onion should succeed
        assert!(guard.register("J5nickAAAAAAAA0", &test_onion()).is_ok());
    }

    #[test]
    fn test_concurrent_registration_consistency() {
        use std::sync::Arc;

        let guard = Arc::new(SybilGuard::new());
        let onion = test_onion();

        // Spawn multiple threads that try to register different nicks for the same onion.
        // Only one should succeed; the maps must remain consistent.
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let guard = guard.clone();
                let onion = onion.clone();
                std::thread::spawn(move || {
                    let nick = format!("J5nick{:010}OO", i);
                    guard.register(&nick, &onion)
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        // Exactly one nick should succeed (the first one to get the lock);
        // subsequent registrations for the same onion with different nicks fail.
        assert_eq!(ok_count, 1, "exactly one registration should succeed for the same onion");

        // Verify maps are consistent — the guard should report exactly one active nick
        let mut active_count = 0;
        for i in 0..10 {
            let nick = format!("J5nick{:010}OO", i);
            if guard.is_nick_active(&nick) {
                active_count += 1;
            }
        }
        assert_eq!(active_count, 1, "exactly one nick should be active");
    }
}
