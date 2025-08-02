// Path: crates/validator/src/hybrid/api.rs
use async_trait::async_trait;
use depin_sdk_api::validator::Container;
use depin_sdk_core::error::ValidatorError;
use serde::Deserialize;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use toml;

/// Configuration for the API container, loaded from `api.toml`.
#[derive(Deserialize)]
pub struct ApiConfig {
    pub listen_address: String,
    pub enabled_endpoints: Vec<String>,
}

/// The ApiContainer is responsible for implementing the public-facing JSON-RPC
/// or other state-query APIs for a hybrid validator.
pub struct ApiContainer {
    config: ApiConfig,
    running: Arc<AtomicBool>,
}

impl ApiContainer {
    pub fn new(config_path: &Path) -> anyhow::Result<Self> {
        let config_str = std::fs::read_to_string(config_path)?;
        let config: ApiConfig = toml::from_str(&config_str)?;
        Ok(Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
        })
    }
}

#[async_trait]
impl Container for ApiContainer {
    async fn start(&self) -> Result<(), ValidatorError> {
        log::info!(
            "Starting ApiContainer, listening on {}...",
            self.config.listen_address
        );
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        log::info!("Stopping ApiContainer...");
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn id(&self) -> &'static str {
        "api"
    }
}
