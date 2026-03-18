use std::path::Path;
use std::sync::Arc;

pub mod provider;
pub mod mock;

#[cfg(feature = "arti")]
pub mod arti_backend;

#[cfg(feature = "tordaemon")]
pub mod ctor_backend;

/// Name of the compiled Tor backend.
#[cfg(feature = "tordaemon")]
pub const BACKEND_NAME: &str = "tordaemon";

/// Name of the compiled Tor backend.
#[cfg(feature = "arti")]
pub const BACKEND_NAME: &str = "arti";

// Mutually exclusive feature guard
#[cfg(all(feature = "arti", feature = "tordaemon"))]
compile_error!(
    "features `arti` and `tordaemon` are mutually exclusive; \
     build with `--no-default-features --features arti` to use the Arti backend"
);

/// Configuration for creating a Tor provider.
pub struct TorBackendConfig<'a> {
    /// Hidden service directory (tordaemon backend).
    pub hidden_service_dir: Option<&'a Path>,
    /// Local address to bind for the hidden service (tordaemon backend).
    pub serving_host: Option<&'a str>,
    /// Local port to bind for the hidden service (tordaemon backend).
    pub serving_port: u16,
    /// Arti state directory (arti backend).
    pub state_dir: Option<&'a Path>,
    /// Virtual onion service port advertised to peers.
    pub virtual_port: u16,
    /// Enable PoW defence.
    pub pow: bool,
}

/// Create a [`TorProvider`](provider::TorProvider) using the compile-time selected backend.
#[cfg(feature = "tordaemon")]
pub async fn create_provider(config: TorBackendConfig<'_>) -> Result<Arc<dyn provider::TorProvider>, anyhow::Error> {
    let hs_dir = config.hidden_service_dir
        .ok_or_else(|| {
            let serving_host = config.serving_host.unwrap_or("127.0.0.1");
            let serving_port = config.serving_port;
            anyhow::anyhow!(
                "hidden_service_dir not found in [MESSAGING:onion].\n\n\
                 This setting tells joinmarket-dn where C Tor stores the hidden service \
                 files. C Tor must be pre-configured with a matching HiddenServiceDir and \
                 HiddenServicePort in torrc; once started it writes the .onion address to \
                 <hidden_service_dir>/hostname, which joinmarket-dn reads on startup.\n\n\
                 Add the following to the [MESSAGING:onion] section of joinmarket.cfg:\n\n\
                 \thidden_service_dir = /var/lib/tor/joinmarket-hs\n\n\
                 And add the following to your torrc:\n\n\
                 \tHiddenServiceDir /var/lib/tor/joinmarket-hs\n\
                 \tHiddenServicePort 5222 {serving_host}:{serving_port}"
            )
        })?;
    let serving_host = config.serving_host.unwrap_or("127.0.0.1");
    let serving_port = config.serving_port;
    Ok(Arc::new(
        ctor_backend::CTorProvider::new(hs_dir, serving_host, serving_port).await?
    ))
}

/// Create a [`TorProvider`](provider::TorProvider) using the compile-time selected backend.
#[cfg(feature = "arti")]
pub async fn create_provider(config: TorBackendConfig<'_>) -> Result<Arc<dyn provider::TorProvider>, anyhow::Error> {
    let state_dir = config.state_dir
        .ok_or_else(|| anyhow::anyhow!("state_dir required for arti backend"))?;
    Ok(Arc::new(
        arti_backend::ArtiTorProvider::bootstrap(state_dir, config.pow).await?
    ))
}
