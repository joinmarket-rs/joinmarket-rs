#![forbid(unsafe_code)]

pub mod server;
pub mod peer;
pub mod router;
pub mod admission;
pub mod sybil_guard;
pub mod bond_registry;
pub mod heartbeat;
pub mod metrics;

/// Version of the joinmarket-dn binary crate.
pub const DN_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The standard JoinMarket directory node virtual port, used both when
/// registering the hidden service and when advertising the DN's own
/// location-string to peers.
pub const VIRTUAL_PORT: u16 = 5222;
