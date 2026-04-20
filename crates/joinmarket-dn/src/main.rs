use std::path::PathBuf;
use std::sync::Arc;

use clap::{Command, CommandFactory, FromArgMatches, Parser};
use tokio_util::sync::CancellationToken;

use joinmarket_dn::{admission, heartbeat, metrics, router, server, DN_VERSION, VIRTUAL_PORT};
use joinmarket_tor::TorBackendConfig;

#[derive(Parser, Debug)]
#[command(name = "joinmarket-dn")]
pub struct Args {
    /// Data directory (default: ~/.joinmarket).
    /// Must contain joinmarket.cfg with [MESSAGING:onion] and [BLOCKCHAIN] sections.
    #[arg(long)]
    pub datadir: Option<String>,

    /// Prometheus metrics bind address (default: 127.0.0.1:9090)
    #[arg(long, default_value = "127.0.0.1:9090")]
    pub metrics_bind: String,

    /// Enable Tor PoW DoS defence (requires a binary built with --features arti)
    #[cfg(feature = "arti")]
    #[arg(long)]
    pub pow: bool,

    /// Optional operator message appended to the MOTD
    pub operator_message: Option<String>,
}

fn build_command() -> Command {
    Args::command()
        .version(DN_VERSION)
        .about(format!("JoinMarket Directory Node (Rust) [{}]", joinmarket_tor::BACKEND_NAME))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = build_command().get_matches();
    let args = Args::from_arg_matches(&matches)?;

    // Resolve data directory
    let datadir: PathBuf = args.datadir
        .map(|s| expand_tilde(&s))
        .map(PathBuf::from)
        .or_else(|| std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".joinmarket")))
        .ok_or_else(|| anyhow::anyhow!("$HOME is unset; provide --datadir"))?;

    // Load configuration (creates a default file and exits if none exists)
    let config_path = datadir.join("joinmarket.cfg");
    let cfg = match joinmarket_core::config::DirectoryConfig::from_file(&config_path) {
        Ok(cfg) => cfg,
        Err(joinmarket_core::config::ConfigError::CreatedDefault(p)) => {
            eprintln!(
                "Created a new `joinmarket.cfg` at {}.\n\
                 Please review the settings and restart joinmarket-dn.",
                p.display()
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("failed to load {}: {e}", config_path.display());
            std::process::exit(1);
        }
    };

    // Warn if onion_serving_host is not a loopback address (defeats Tor anonymity)
    let serving_host = &cfg.onion_serving_host;
    if serving_host != "127.0.0.1" && serving_host != "::1" && serving_host != "localhost" {
        eprintln!(
            "WARNING: onion_serving_host is set to '{}' which is NOT a loopback address.\n\
             This exposes the service on clearnet and defeats Tor anonymity.\n\
             Set onion_serving_host = 127.0.0.1 unless you know what you are doing.",
            serving_host
        );
    }

    // Initialize tracing: RUST_LOG takes priority; fall back to console_log_level from config
    let fallback_level = map_log_level(&cfg.console_log_level);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(fallback_level))
        )
        .init();

    // Start Prometheus metrics server
    let metrics_addr: std::net::SocketAddr = args.metrics_bind.parse()
        .map_err(|e| anyhow::anyhow!("invalid --metrics-bind address '{}': {}", args.metrics_bind, e))?;
    if !metrics_addr.ip().is_loopback() {
        tracing::warn!(
            address = %metrics_addr,
            "Prometheus metrics endpoint is bound to a non-loopback address; \
             this exposes operational data publicly. Ensure this is intentional."
        );
    }
    metrics::init_metrics(metrics_addr)?;

    let shutdown = CancellationToken::new();

    // Handle ctrl-c
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("Shutdown signal received");
            shutdown.cancel();
        });
    }

    let router = Arc::new(router::Router::new());
    let admission = Arc::new(admission::AdmissionController::new());

    let network = cfg.network.clone();

    #[cfg(feature = "tordaemon")]
    let onion_serving_port = cfg.onion_serving_port;
    #[cfg(feature = "arti")]
    let onion_serving_port: u16 = VIRTUAL_PORT;

    tracing::info!(
        version = DN_VERSION,
        backend = joinmarket_tor::BACKEND_NAME,
        "JoinMarket Directory Node starting"
    );
    tracing::info!("Network: {}, Port: {}", network, onion_serving_port);

    // Bootstrap Tor backend
    let arti_state_dir = datadir.join("arti");
    let tor = joinmarket_tor::create_provider(TorBackendConfig {
        hidden_service_dir: cfg.hidden_service_dir.as_deref(),
        serving_host: Some(cfg.onion_serving_host.as_str()),
        serving_port: onion_serving_port,
        state_dir: Some(arti_state_dir.as_path()),
        virtual_port: VIRTUAL_PORT,
        #[cfg(feature = "arti")]
        pow: args.pow,
        #[cfg(not(feature = "arti"))]
        pow: false,
    }).await?;

    let node_location = format!("{}:{}", tor.onion_address(), VIRTUAL_PORT);
    tracing::info!("Onion address: {}", node_location);

    // Build MOTD: "DIRECTORY NODE: <onion:port>\nJOINMARKET VERSION: joinmarket-rs/<ver>\n<operator_message>"
    // The operator message is sanitised to prevent control-character injection and
    // social-engineering payloads from being forwarded to every connecting peer.
    let operator_msg = sanitise_motd(
        args.operator_message.as_deref().unwrap_or(""),
        512,
    );
    let motd = format!(
        "DIRECTORY NODE: {}\nJOINMARKET VERSION: joinmarket-rs/{}\n{}",
        node_location,
        joinmarket_core::CORE_VERSION,
        operator_msg,
    );

    // Start heartbeat loop
    let hb_router = router.clone();
    let hb_shutdown = shutdown.clone();
    let hb_handle = tokio::spawn(heartbeat::heartbeat_loop(hb_router, hb_shutdown));

    // Run accept loop (blocks until shutdown)
    server::run_accept_loop(
        tor,
        router,
        admission,
        network,
        motd,
        shutdown,
    ).await?;

    // Wait for heartbeat task to finish (it watches the same shutdown token)
    let _ = hb_handle.await;

    tracing::info!("Directory node stopped");

    // Return normally so that drop handlers run in order.  Previously this
    // called std::process::exit(0) to skip Tokio/Arti runtime teardown,
    // working around Arti internal tasks that can panic when the runtime
    // drops.  The #[tokio::main] macro wraps the runtime in a catch-all;
    // any such panic will be printed but will not prevent clean shutdown.
    // TODO: remove this comment once the upstream Arti shutdown bug is resolved.
    Ok(())
}

/// Sanitise a string for inclusion in the MOTD that is sent to every peer.
///
/// **Only ASCII graphic characters, spaces, and `\n` are preserved.**
/// All non-ASCII characters (including Unicode letters, emoji, etc.) are
/// silently stripped.  This is intentional: the MOTD is embedded in a JSON
/// string and forwarded to every connecting peer, so restricting to ASCII
/// prevents log-injection, framing corruption in clients that parse MOTD
/// naïvely, and social-engineering payloads injected via a compromised
/// operator-supplied CLI argument.
///
/// Total length is capped at `max_bytes` bytes (all remaining chars are ASCII,
/// so byte length equals character count after filtering).
fn sanitise_motd(s: &str, max_bytes: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if !(c.is_ascii_graphic() || c == ' ' || c == '\n') {
            continue;
        }
        if out.len() + c.len_utf8() > max_bytes {
            break;
        }
        out.push(c);
    }
    out
}

/// Expand a leading `~` to `$HOME`. Returns the string unchanged if it does
/// not start with `~` or if `$HOME` is unset.
fn expand_tilde(s: &str) -> String {
    if s.starts_with('~') {
        if let Ok(home) = std::env::var("HOME") {
            return s.replacen('~', &home, 1);
        }
    }
    s.to_string()
}

/// Map Python JoinMarket log level names to tracing directive strings.
///
/// Returns a compound EnvFilter directive that sets `error` as the global
/// default for all dependency crates, while applying the configured level
/// only to the joinmarket workspace crates.
fn map_log_level(level: &str) -> String {
    let crate_level = match level.to_uppercase().as_str() {
        "DEBUG" => "debug",
        "INFO" => "info",
        "WARNING" => "warn",
        "ERROR" => "error",
        _ => "info", // safe default for unrecognised values
    };
    // Global default: error for all crates; joinmarket crates use config level
    format!("error,joinmarket_dn={crate_level},joinmarket_core={crate_level},joinmarket_tor={crate_level}")
}

#[cfg(test)]
mod tests {
    use super::{build_command, DN_VERSION};

    #[test]
    fn version_flag_displays_binary_version() {
        let err = build_command()
            .try_get_matches_from(["joinmarket-dn", "--version"])
            .unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(err.to_string().contains(DN_VERSION));
    }
}
