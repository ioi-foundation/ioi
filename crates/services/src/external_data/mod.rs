// Path: crates/services/src/external_data/mod.rs
use depin_sdk_api::impl_service_base;
use depin_sdk_api::services::{BlockchainService, ServiceType, UpgradableService};
use depin_sdk_types::error::UpgradeError;

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
    fn service_type(&self) -> ServiceType {
        ServiceType::ExternalData
    }
}

impl_service_base!(ExternalDataService);

impl UpgradableService for ExternalDataService {
    fn prepare_upgrade(&mut self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        // This service is stateless, so the snapshot is empty.
        Ok(Vec::new())
    }
    fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}