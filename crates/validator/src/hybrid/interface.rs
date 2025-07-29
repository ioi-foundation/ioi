// Path: crates/validator/src/hybrid/interface.rs

use depin_sdk_core::error::ValidatorError;
use depin_sdk_core::validator::Container;
use serde::Deserialize;
use std::path::Path;
// FIX: Add imports for atomic state management
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use toml;

/// Configuration for the Interface container, loaded from `interface.toml`.
#[derive(Deserialize)]
pub struct InterfaceConfig {
    pub max_connections: u32,
    pub rate_limit_per_second: u64,
}

/// The InterfaceContainer manages raw network connections, protocol routing,
/// and basic DDoS protection for a hybrid validator's public-facing services.
pub struct InterfaceContainer {
    config: InterfaceConfig,
    // FIX: Use Arc<AtomicBool> for thread-safe state.
    running: Arc<AtomicBool>,
}

impl InterfaceContainer {
    pub fn new(config_path: &Path) -> anyhow::Result<Self> {
        let config_str = std::fs::read_to_string(config_path)?;
        let config: InterfaceConfig = toml::from_str(&config_str)?;
        Ok(Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
        })
    }
}

#[async_trait::async_trait]
impl Container for InterfaceContainer {
    async fn start(&self) -> Result<(), ValidatorError> {
        log::info!(
            "Starting InterfaceContainer with max {} connections...",
            self.config.max_connections
        );
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        log::info!("Stopping InterfaceContainer...");
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn id(&self) -> &'static str {
        "interface"
    }
}