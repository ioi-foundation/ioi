// Path: crates/chain/src/upgrade_manager/mod.rs
// Change: Removed unused `mut` keyword from `active_service` variable declaration.

use depin_sdk_api::services::{ServiceType, UpgradableService};
use depin_sdk_types::error::CoreError;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

/// Manages runtime upgrades of blockchain services
pub struct ModuleUpgradeManager {
    /// Holds the currently active, concrete service implementations
    active_services: HashMap<ServiceType, Arc<dyn UpgradableService>>,
    /// Tracks upgrade history for each service type
    upgrade_history: HashMap<ServiceType, Vec<u64>>,
    /// Scheduled upgrades by block height
    scheduled_upgrades: HashMap<u64, Vec<(ServiceType, Vec<u8>)>>,
    /// A factory function to instantiate services from "WASM" blobs.
    /// In a real system, this would use a WASM runtime. Here, it's a stub
    /// for testing that deserializes markers to instantiate pre-compiled objects.
    service_factory:
        Box<dyn Fn(&[u8]) -> Result<Arc<dyn UpgradableService>, CoreError> + Send + Sync>,
}

// FIX: Manually implement Debug because Arc<dyn UpgradableService> does not implement Debug.
// This implementation prints the service types instead of the service objects themselves.
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
    /// Create a new module upgrade manager
    pub fn new(
        service_factory: Box<
            dyn Fn(&[u8]) -> Result<Arc<dyn UpgradableService>, CoreError> + Send + Sync,
        >,
    ) -> Self {
        Self {
            active_services: HashMap::new(),
            upgrade_history: HashMap::new(),
            scheduled_upgrades: HashMap::new(),
            service_factory,
        }
    }

    /// Register a service with the manager
    pub fn register_service(&mut self, service: Arc<dyn UpgradableService>) {
        let service_type = service.service_type();
        log::info!("Registering service: {:?}", service_type);
        self.active_services.insert(service_type.clone(), service);

        // Initialize upgrade history if not present
        self.upgrade_history.entry(service_type).or_default();
    }

    /// Get a service by type
    pub fn get_service(&self, service_type: &ServiceType) -> Option<Arc<dyn UpgradableService>> {
        self.active_services.get(service_type).cloned()
    }

    /// Schedule an upgrade for a specific block height
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

    /// Apply any upgrades scheduled for the given block height
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
                    // Record the upgrade in history
                    if let Some(history) = self.upgrade_history.get_mut(&service_type) {
                        history.push(height);
                    }
                }
                Err(e) => {
                    // Log error but continue with other upgrades
                    eprintln!("Failed to upgrade service {service_type:?}: {e}");
                }
            }
        }

        Ok(applied_count)
    }

    /// Execute an upgrade for a specific service
    pub fn execute_upgrade(
        &mut self,
        service_type: &ServiceType,
        new_module_wasm: &[u8],
    ) -> Result<(), CoreError> {
        // 1. Get active service.
        let active_service = self
            .active_services
            .get(service_type) // We only need an immutable borrow here
            .ok_or_else(|| CoreError::ServiceNotFound(format!("{:?}", service_type)))?;

        // 2. Call active_service.prepare_upgrade to get state snapshot.
        let snapshot = active_service
            .prepare_upgrade(new_module_wasm)
            .map_err(|e| CoreError::UpgradeError(e.to_string()))?;
        log::info!(
            "Prepared upgrade for {:?}, state snapshot size: {}",
            service_type,
            snapshot.len()
        );

        // 3. Load the new service from the WASM blob (simulated via factory).
        let mut new_service_arc = (self.service_factory)(new_module_wasm)?;
        log::info!(
            "Successfully instantiated new service module for {:?}",
            service_type
        );

        // 4. Instantiate the new service and call new_service.complete_upgrade.
        // We need a mutable reference, so we use Arc::get_mut. This is safe as we
        // hold the only strong reference before inserting it into the map.
        let new_service = Arc::get_mut(&mut new_service_arc).ok_or_else(|| {
            CoreError::UpgradeError("Failed to get mutable reference to new service".to_string())
        })?;
        new_service
            .complete_upgrade(&snapshot)
            .map_err(|e| CoreError::UpgradeError(e.to_string()))?;
        log::info!("Completed state migration for service {:?}", service_type);

        // 5. Atomically replace the service in the `active_services` map.
        self.active_services
            .insert(service_type.clone(), new_service_arc);
        log::info!("Successfully swapped active service for {:?}", service_type);

        Ok(())
    }

    /// Get upgrade history for a service
    pub fn get_upgrade_history(&self, service_type: &ServiceType) -> Vec<u64> {
        self.upgrade_history
            .get(service_type)
            .cloned()
            .unwrap_or_default()
    }

    /// Check health status of all services
    pub fn check_all_health(&self) -> Vec<(ServiceType, bool)> {
        self.active_services
            .iter()
            .map(|(service_type, service)| {
                let is_healthy = service.health_check().is_ok();
                (service_type.clone(), is_healthy)
            })
            .collect()
    }

    /// Start all registered services
    pub fn start_all_services(&mut self) -> Result<(), CoreError> {
        for (service_type, service) in &self.active_services {
            service.start().map_err(|e| {
                CoreError::Custom(format!("Failed to start service {service_type:?}: {e}"))
            })?;
        }
        Ok(())
    }

    /// Stop all registered services
    pub fn stop_all_services(&mut self) -> Result<(), CoreError> {
        for (service_type, service) in &self.active_services {
            service.stop().map_err(|e| {
                CoreError::Custom(format!("Failed to stop service {service_type:?}: {e}"))
            })?;
        }
        Ok(())
    }

    /// Reset the manager to initial state
    pub fn reset(&mut self) -> Result<(), CoreError> {
        // Stop all services first
        self.stop_all_services()?;

        // Clear all state
        self.active_services.clear();
        self.upgrade_history.clear();
        self.scheduled_upgrades.clear();

        Ok(())
    }
}
