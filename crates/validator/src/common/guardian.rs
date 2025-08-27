// crates/validator/src/common/guardian.rs

use crate::config::GuardianConfig;
use anyhow::Result;
use async_trait::async_trait;
use depin_sdk_api::validator::Container;
use depin_sdk_client::security::SecurityChannel;
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_types::error::ValidatorError;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// The GuardianContainer is the root of trust.
#[derive(Debug, Clone)]
pub struct GuardianContainer {
    pub orchestration_channel: SecurityChannel,
    pub workload_channel: SecurityChannel,
    is_running: Arc<AtomicBool>,
}

impl GuardianContainer {
    pub fn new(_config: GuardianConfig) -> Result<Self> {
        Ok(Self {
            orchestration_channel: SecurityChannel::new("guardian", "orchestration"),
            workload_channel: SecurityChannel::new("guardian", "workload"),
            is_running: Arc::new(AtomicBool::new(false)),
        })
    }
    pub async fn attest_weights(&self, model_path: &str) -> Result<Vec<u8>, String> {
        let model_bytes = std::fs::read(model_path)
            .map_err(|e| format!("Failed to read agentic model file: {}", e))?;
        let local_hash = sha256(&model_bytes);
        log::info!(
            "[Guardian] Computed local model hash: {}",
            hex::encode(&local_hash)
        );
        Ok(local_hash)
    }
}

#[async_trait]
impl Container for GuardianContainer {
    async fn start(&self) -> Result<(), ValidatorError> {
        self.is_running.store(true, Ordering::SeqCst);
        log::info!("Guardian container started (mock).");
        Ok(())
    }
    async fn stop(&self) -> Result<(), ValidatorError> {
        self.is_running.store(false, Ordering::SeqCst);
        log::info!("Guardian container stopped (mock).");
        Ok(())
    }
    fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }
    fn id(&self) -> &'static str {
        "guardian"
    }
}