use depin_sdk_core::services::{BlockchainService, ServiceType, UpgradableService};
use std::collections::HashMap;
use std::sync::Arc;

pub struct ModuleUpgradeManager {
    // Holds the currently active, concrete service implementations.
    active_services: HashMap<ServiceType, Arc<dyn UpgradableService>>,
}

impl ModuleUpgradeManager {
    pub fn new() -> Self {
        Self {
            active_services: HashMap::new(),
        }
    }

    pub fn register_service(&mut self, service: Arc<dyn UpgradableService>) {
        self.active_services.insert(service.service_type(), service);
    }

    pub fn get_service<T: 'static>(&self, service_type: &ServiceType) -> Option<Arc<T>> {
        self.active_services
            .get(service_type)
            .and_then(|service| service.clone().downcast_arc().ok())
    }

    // Called by the governance module when a SwapModule proposal passes.
    pub fn execute_upgrade(
        &mut self,
        service_type: &ServiceType,
        new_module_wasm: &[u8],
    ) -> Result<(), UpgradeError> {
        let active_service = self
            .active_services
            .get_mut(service_type)
            .ok_or(UpgradeError::ServiceNotFound)?;

        // 1. Prepare: Get the state snapshot from the current service.
        let snapshot = active_service.prepare_upgrade(new_module_wasm)?;

        // 2. Instantiate new service from WASM (or other format).
        let mut new_service = load_service_from_wasm(new_module_wasm)?;

        // 3. Complete: Migrate the state into the new service instance.
        new_service.complete_upgrade(&snapshot)?;

        // 4. Atomically swap the implementation.
        self.active_services
            .insert(service_type.clone(), Arc::new(new_service));

        Ok(())
    }
}
