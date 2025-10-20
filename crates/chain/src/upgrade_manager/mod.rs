// Path: crates/chain/src/upgrade_manager/mod.rs

use crate::runtime_service::RuntimeBackedService;
use depin_sdk_api::runtime::Runtime;
use depin_sdk_api::services::UpgradableService;
use depin_sdk_api::state::StateAccessor;
use depin_sdk_types::error::CoreError;
use depin_sdk_types::keys::active_service_key;
use depin_sdk_types::service_configs::{Capabilities, MethodPermission};
use serde::Deserialize;
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;
use toml;

#[derive(Deserialize, Debug)]
struct ServiceManifest {
    id: String,
    abi_version: u32,
    state_schema: String,
    runtime: String,
    capabilities: Vec<String>,
}

/// Validates that a service ID conforms to the `[a-z0-9_]+` format.
fn validate_service_id(id: &str) -> Result<(), CoreError> {
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(CoreError::Upgrade(format!(
            "Invalid service_id: '{}'. Must be lowercase alphanumeric with underscores.",
            id
        )));
    }
    Ok(())
}

pub struct ModuleUpgradeManager {
    active_services: HashMap<String, Arc<dyn UpgradableService>>,
    upgrade_history: HashMap<String, Vec<u64>>,
    scheduled_upgrades: HashMap<u64, Vec<(String, String, Vec<u8>)>>,
    runtimes: HashMap<String, Arc<dyn Runtime>>,
}

impl fmt::Debug for ModuleUpgradeManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModuleUpgradeManager")
            .field("active_services", &self.active_services.keys())
            .field("upgrade_history", &self.upgrade_history)
            .field("scheduled_upgrades", &self.scheduled_upgrades)
            .field("runtimes", &self.runtimes.keys())
            .finish()
    }
}

impl ModuleUpgradeManager {
    pub fn new() -> Self {
        Self {
            active_services: HashMap::new(),
            upgrade_history: HashMap::new(),
            scheduled_upgrades: HashMap::new(),
            runtimes: HashMap::new(),
        }
    }

    pub fn register_service(&mut self, service: Arc<dyn UpgradableService>) {
        let service_id = service.id();
        if let Err(e) = validate_service_id(service_id) {
            // Use panic here because this is a developer error during setup, not a runtime issue.
            panic!(
                "FATAL: Attempted to register service with invalid ID '{}': {}",
                service_id, e
            );
        }
        log::info!("Registering service: {}", service_id);
        self.active_services.insert(service_id.to_string(), service);
        self.upgrade_history
            .entry(service_id.to_string())
            .or_default();
    }

    pub fn register_runtime(&mut self, id: &str, runtime: Arc<dyn Runtime>) {
        self.runtimes.insert(id.to_string(), runtime);
    }

    pub fn get_service(&self, service_id: &str) -> Option<Arc<dyn UpgradableService>> {
        self.active_services.get(service_id).cloned()
    }

    pub fn all_services(&self) -> Vec<Arc<dyn UpgradableService>> {
        let mut keys: Vec<_> = self.active_services.keys().cloned().collect();
        keys.sort();
        keys.into_iter()
            .filter_map(|k| self.active_services.get(&k).cloned())
            .collect()
    }

    pub fn get_service_as<T: Any>(&self) -> Option<&T> {
        for service in self.active_services.values() {
            if let Some(downcasted) = service.as_any().downcast_ref::<T>() {
                return Some(downcasted);
            }
        }
        None
    }

    pub fn schedule_upgrade(
        &mut self,
        service_id: String,
        manifest: String,
        artifact: Vec<u8>,
        activation_height: u64,
    ) -> Result<(), CoreError> {
        self.scheduled_upgrades
            .entry(activation_height)
            .or_default()
            .push((service_id, manifest, artifact));
        Ok(())
    }

    pub async fn apply_upgrades_at_height(
        &mut self,
        height: u64,
        state: &mut dyn StateAccessor,
    ) -> Result<usize, CoreError> {
        let upgrades = match self.scheduled_upgrades.remove(&height) {
            Some(upgrades) => upgrades,
            None => return Ok(0),
        };
        let mut applied_count = 0;
        for (service_id, manifest, artifact) in upgrades {
            match self
                .execute_upgrade(&service_id, &manifest, &artifact, state)
                .await
            {
                Ok(()) => {
                    applied_count += 1;
                    if let Some(history) = self.upgrade_history.get_mut(&service_id) {
                        history.push(height);
                    }
                }
                Err(e) => {
                    log::error!("Failed to upgrade service {}: {}", service_id, e);
                }
            }
        }
        Ok(applied_count)
    }

    pub async fn execute_upgrade(
        &mut self,
        service_id: &str,
        manifest_str: &str,
        artifact: &[u8],
        state: &mut dyn StateAccessor,
    ) -> Result<(), CoreError> {
        let manifest: ServiceManifest = toml::from_str(manifest_str)
            .map_err(|e| CoreError::Upgrade(format!("Invalid service manifest: {}", e)))?;

        validate_service_id(&manifest.id)?;
        if manifest.id != service_id {
            return Err(CoreError::Upgrade(format!(
                "Manifest ID '{}' does not match target service ID '{}'",
                manifest.id, service_id
            )));
        }

        let runtime = self.runtimes.get(&manifest.runtime).ok_or_else(|| {
            CoreError::Upgrade(format!(
                "Execution runtime '{}' not found",
                manifest.runtime
            ))
        })?;

        // This path is for installing a *new* service that wasn't present at genesis.
        if !self.active_services.contains_key(service_id) {
            log::info!("No active service for '{}'. Installing new.", service_id);
            let runnable = runtime
                .load(artifact)
                .await
                .map_err(|e| CoreError::Upgrade(e.to_string()))?;

            let new_service_arc = Arc::new(RuntimeBackedService::new(
                Box::leak(manifest.id.into_boxed_str()),
                manifest.abi_version,
                Box::leak(manifest.state_schema.into_boxed_str()),
                runnable,
                Capabilities::from_strings(&manifest.capabilities)?,
            ));

            self.register_service(new_service_arc as Arc<dyn UpgradableService>);
            state
                .insert(&active_service_key(service_id), &[])
                .map_err(|e| CoreError::Custom(e.to_string()))?;
            log::info!(
                "Successfully installed and registered new service '{}'",
                service_id
            );
            return Ok(());
        }

        // This path is for upgrading an *existing* service.
        let mut active_service_arc = self
            .active_services
            .remove(service_id)
            .ok_or_else(|| CoreError::ServiceNotFound(service_id.to_string()))?;

        let upgrade_result = (async {
            let active_service = Arc::get_mut(&mut active_service_arc)
                .ok_or_else(|| CoreError::Upgrade("Service in use".to_string()))?;
            let snapshot = active_service
                .prepare_upgrade(artifact)
                .await
                .map_err(|e| CoreError::Upgrade(e.to_string()))?;

            let runnable = runtime
                .load(artifact)
                .await
                .map_err(|e| CoreError::Upgrade(e.to_string()))?;

            let mut new_service_arc: Arc<dyn UpgradableService> =
                Arc::new(RuntimeBackedService::new(
                    Box::leak(manifest.id.into_boxed_str()),
                    manifest.abi_version,
                    Box::leak(manifest.state_schema.into_boxed_str()),
                    runnable,
                    Capabilities::from_strings(&manifest.capabilities)?,
                ));

            if new_service_arc.abi_version() != active_service.abi_version() {
                return Err(CoreError::Upgrade("Incompatible ABI version".into()));
            }

            let new_service = Arc::get_mut(&mut new_service_arc).ok_or_else(|| {
                CoreError::Upgrade("Failed to get mut ref to new service".to_string())
            })?;
            new_service
                .complete_upgrade(&snapshot)
                .await
                .map_err(|e| CoreError::Upgrade(e.to_string()))?;
            Ok(new_service_arc)
        })
        .await;

        match upgrade_result {
            Ok(new_service_arc) => {
                self.active_services
                    .insert(service_id.to_string(), new_service_arc);
                log::info!("Successfully swapped active service for '{}'", service_id);
                // --- FIX START: Ensure active key is written on upgrade path ---
                state
                    .insert(&active_service_key(service_id), &[])
                    .map_err(|e| CoreError::Custom(e.to_string()))?;
                // --- FIX END ---
                Ok(())
            }
            Err(e) => {
                log::error!(
                    "Upgrade for '{}' failed: {}. Restoring original.",
                    service_id,
                    e
                );
                self.active_services
                    .insert(service_id.to_string(), active_service_arc);
                Err(e)
            }
        }
    }

    pub fn get_upgrade_history(&self, service_id: &str) -> Vec<u64> {
        self.upgrade_history
            .get(service_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn check_all_health(&self) -> Vec<(String, bool)> {
        self.active_services
            .iter()
            .map(|(service_id, service)| {
                let is_healthy = service.health_check().is_ok();
                (service_id.clone(), is_healthy)
            })
            .collect()
    }
}