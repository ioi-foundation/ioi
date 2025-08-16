// Path: crates/chain/src/upgrade_manager/mod.rs

use depin_sdk_api::services::{ServiceType, UpgradableService};
use depin_sdk_types::error::CoreError;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

// ... (ServiceFactory, ModuleUpgradeManager struct, Debug impl, new() are unchanged) ...
type ServiceFactory =
    Box<dyn Fn(&[u8]) -> Result<Arc<dyn UpgradableService>, CoreError> + Send + Sync>;

pub struct ModuleUpgradeManager {
    active_services: HashMap<ServiceType, Arc<dyn UpgradableService>>,
    upgrade_history: HashMap<ServiceType, Vec<u64>>,
    scheduled_upgrades: HashMap<u64, Vec<(ServiceType, Vec<u8>)>>,
    service_factory: ServiceFactory,
}

impl fmt::Debug for ModuleUpgradeManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModuleUpgradeManager")
            .field("active_services", &self.active_services.keys())
            .field("upgrade_history", &self.upgrade_history)
            .field("scheduled_upgrades", &self.scheduled_upgrades)
            .finish()
    }
}

impl ModuleUpgradeManager {
    pub fn new(service_factory: ServiceFactory) -> Self {
        Self {
            active_services: HashMap::new(),
            upgrade_history: HashMap::new(),
            scheduled_upgrades: HashMap::new(),
            service_factory,
        }
    }

    pub fn register_service(&mut self, service: Arc<dyn UpgradableService>) {
        let service_type = service.service_type();
        log::info!("Registering service: {:?}", service_type);
        self.active_services.insert(service_type.clone(), service);
        self.upgrade_history.entry(service_type).or_default();
    }

    pub fn get_service(&self, service_type: &ServiceType) -> Option<Arc<dyn UpgradableService>> {
        self.active_services.get(service_type).cloned()
    }

    pub fn schedule_upgrade(
        &mut self,
        service_type: ServiceType,
        upgrade_data: Vec<u8>,
        activation_height: u64,
    ) -> Result<(), CoreError> {
        self.scheduled_upgrades
            .entry(activation_height)
            .or_default()
            .push((service_type, upgrade_data));
        Ok(())
    }

    pub fn apply_upgrades_at_height(&mut self, height: u64) -> Result<usize, CoreError> {
        let upgrades = match self.scheduled_upgrades.remove(&height) {
            Some(upgrades) => upgrades,
            None => return Ok(0),
        };
        let mut applied_count = 0;
        for (service_type, upgrade_data) in upgrades {
            match self.execute_upgrade(&service_type, &upgrade_data) {
                Ok(()) => {
                    applied_count += 1;
                    if let Some(history) = self.upgrade_history.get_mut(&service_type) {
                        history.push(height);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to upgrade service {service_type:?}: {e}");
                }
            }
        }
        Ok(applied_count)
    }

    pub fn execute_upgrade(
        &mut self,
        service_type: &ServiceType,
        new_module_wasm: &[u8],
    ) -> Result<(), CoreError> {
        // --- START FIX: HANDLE NEW INSTALLATIONS ---

        // Check if a service of this type already exists.
        if !self.active_services.contains_key(service_type) {
            // Case 1: New Service Installation
            log::info!(
                "No active service found for {:?}. Treating as new installation.",
                service_type
            );
            let new_service_arc = (self.service_factory)(new_module_wasm)?;
            // The WASM loader ensures the service_type in the blob matches what we expect.
            // A more robust implementation might double-check here.
            self.register_service(new_service_arc);
            log::info!("Successfully installed new service {:?}", service_type);
            return Ok(());
        }

        // Case 2: Existing Service Upgrade (the original logic)
        let mut active_service_arc = self.active_services.remove(service_type).unwrap(); // We just checked existence, so unwrap is safe.

        let upgrade_result = (|| {
            let active_service = Arc::get_mut(&mut active_service_arc).ok_or_else(|| {
                CoreError::UpgradeError(
                    "Cannot upgrade service: it is currently in use elsewhere.".to_string(),
                )
            })?;
            let snapshot = active_service
                .prepare_upgrade(new_module_wasm)
                .map_err(|e| CoreError::UpgradeError(e.to_string()))?;
            log::info!(
                "Prepared upgrade for {:?}, state snapshot size: {}",
                service_type,
                snapshot.len()
            );

            let mut new_service_arc = (self.service_factory)(new_module_wasm)?;
            log::info!(
                "Successfully instantiated new service module for {:?}",
                service_type
            );

            let new_service = Arc::get_mut(&mut new_service_arc).ok_or_else(|| {
                CoreError::UpgradeError(
                    "Failed to get mutable reference to new service".to_string(),
                )
            })?;
            new_service
                .complete_upgrade(&snapshot)
                .map_err(|e| CoreError::UpgradeError(e.to_string()))?;
            log::info!("Completed state migration for service {:?}", service_type);
            Ok(new_service_arc)
        })();

        match upgrade_result {
            Ok(new_service_arc) => {
                self.active_services
                    .insert(service_type.clone(), new_service_arc);
                log::info!("Successfully swapped active service for {:?}", service_type);
                Ok(())
            }
            Err(e) => {
                log::error!(
                    "Upgrade for {:?} failed: {}. Restoring original service.",
                    service_type,
                    e
                );
                self.active_services
                    .insert(service_type.clone(), active_service_arc);
                Err(e)
            }
        }
        // --- END FIX ---
    }

    // ... (rest of the impl is unchanged) ...
    pub fn get_upgrade_history(&self, service_type: &ServiceType) -> Vec<u64> {
        self.upgrade_history
            .get(service_type)
            .cloned()
            .unwrap_or_default()
    }
    pub fn check_all_health(&self) -> Vec<(ServiceType, bool)> {
        self.active_services
            .iter()
            .map(|(service_type, service)| {
                let is_healthy = service.health_check().is_ok();
                (service_type.clone(), is_healthy)
            })
            .collect()
    }
    pub fn start_all_services(&mut self) -> Result<(), CoreError> {
        for (service_type, service) in &self.active_services {
            service.start().map_err(|e| {
                CoreError::Custom(format!("Failed to start service {service_type:?}: {e}"))
            })?;
        }
        Ok(())
    }
    pub fn stop_all_services(&mut self) -> Result<(), CoreError> {
        for (service_type, service) in &self.active_services {
            service.stop().map_err(|e| {
                CoreError::Custom(format!("Failed to stop service {service_type:?}: {e}"))
            })?;
        }
        Ok(())
    }
    pub fn reset(&mut self) -> Result<(), CoreError> {
        self.stop_all_services()?;
        self.active_services.clear();
        self.upgrade_history.clear();
        self.scheduled_upgrades.clear();
        Ok(())
    }
}
