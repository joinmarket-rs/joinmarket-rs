#![forbid(unsafe_code)]

pub mod nick;
pub mod onion;
pub mod message;
pub mod handshake;
pub mod crypto;
pub mod fidelity_bond;
pub mod config;

/// Version of the joinmarket-core library, used in MOTD generation.
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");
