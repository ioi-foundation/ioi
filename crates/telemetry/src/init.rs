// Path: crates/telemetry/src/init.rs
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Registry};

/// Initializes the global `tracing` subscriber for structured JSON logging.
pub fn init_tracing() {
    let fmt_layer = fmt::layer()
        .json()
        .with_target(true)
        .with_timer(fmt::time::UtcTime::rfc_3339());
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let subscriber = Registry::default().with(filter).with(fmt_layer);
    tracing_log::LogTracer::init().expect("Failed to set `log` to `tracing` bridge");
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set global subscriber");
}