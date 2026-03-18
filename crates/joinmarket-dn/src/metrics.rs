//! Prometheus metrics initialisation.
//!
//! Call `init_metrics(addr)` once at startup. After that, use the `metrics`
//! crate macros (`counter!`, `gauge!`, `histogram!`) anywhere in the codebase.

pub fn init_metrics(addr: std::net::SocketAddr) -> anyhow::Result<()> {
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| {
            if e.to_string().contains("Address in use") {
                anyhow::anyhow!(
                    "metrics address {} is already in use; specify a different address with --metrics-bind",
                    addr
                )
            } else {
                anyhow::anyhow!("failed to start metrics server on {}: {}", addr, e)
            }
        })?;
    tracing::info!("Prometheus metrics server listening on {}", addr);
    Ok(())
}
