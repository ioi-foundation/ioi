// Path: crates/services/src/external_data/mod.rs
use async_trait::async_trait;
use depin_sdk_api::services::{BlockchainService, UpgradableService};
use depin_sdk_types::error::UpgradeError;
use depin_sdk_types::service_configs::Capabilities;
use std::any::Any;

#[derive(Debug, Clone)]
pub struct ExternalDataService;

impl Default for ExternalDataService {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalDataService {
    pub fn new() -> Self {
        Self
    }

    // The core logic for fetching data.
    pub async fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
        log::info!("[ExternalDataService] Fetching data from URL: {}", url);
        let response = reqwest::get(url).await.map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("Request failed with status: {}", response.status()));
        }
        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| e.to_string())
    }
}

// Implement the required traits for service management.
impl BlockchainService for ExternalDataService {
    fn id(&self) -> &'static str {
        "external_data"
    }

    fn abi_version(&self) -> u32 {
        1
    }

    fn state_schema(&self) -> &'static str {
        "v1"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::empty()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
impl UpgradableService for ExternalDataService {
    async fn prepare_upgrade(&mut self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        // This service is stateless, so the snapshot is empty.
        Ok(Vec::new())
    }
    async fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}