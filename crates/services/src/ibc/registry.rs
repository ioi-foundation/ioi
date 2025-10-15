// Path: crates/services/src/ibc/registry.rs

//! Implements the `VerifierRegistry`, a service that manages multiple `InterchainVerifier`
//! instances for different blockchains.

use depin_sdk_api::ibc::InterchainVerifier;
use depin_sdk_api::impl_service_base;
use depin_sdk_api::services::{BlockchainService, ServiceType, UpgradableService};
use depin_sdk_types::error::UpgradeError;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

/// A service that holds and manages a collection of `InterchainVerifier` instances.
///
/// This registry acts as a dispatcher, allowing the core transaction logic to
/// select the correct light client verifier for a given `chain_id`.
pub struct VerifierRegistry {
    /// A map from a chain's unique string identifier to its verifier implementation.
    verifiers: HashMap<String, Arc<dyn InterchainVerifier>>,
}

impl fmt::Debug for VerifierRegistry {
    /// Custom Debug implementation to avoid printing the entire verifier state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifierRegistry")
            .field("registered_chains", &self.verifiers.keys())
            .finish()
    }
}

impl Default for VerifierRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierRegistry {
    /// Creates a new, empty `VerifierRegistry`.
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
        }
    }

    /// Registers a new `InterchainVerifier`. If a verifier for the same
    /// chain ID already exists, it will be replaced.
    pub fn register(&mut self, verifier: Arc<dyn InterchainVerifier>) {
        let chain_id = verifier.chain_id().to_string();
        log::info!(
            "[VerifierRegistry] Registering verifier for chain_id: {}",
            chain_id
        );
        self.verifiers.insert(chain_id, verifier);
    }

    /// Retrieves a verifier for a specific chain ID.
    pub fn get(&self, chain_id: &str) -> Option<Arc<dyn InterchainVerifier>> {
        self.verifiers.get(chain_id).cloned()
    }

    /// Returns a list of all registered chain IDs.
    pub fn registered_chains(&self) -> Vec<String> {
        self.verifiers.keys().cloned().collect()
    }
}

// --- Service Trait Implementations ---

impl BlockchainService for VerifierRegistry {
    fn service_type(&self) -> ServiceType {
        // Use a custom, descriptive name for this core IBC service.
        ServiceType::Custom("ibc_verifier_registry".to_string())
    }
}

// Use the standard macro to implement the base `Service` trait.
impl_service_base!(VerifierRegistry);

impl UpgradableService for VerifierRegistry {
    fn prepare_upgrade(&mut self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        // The registry itself is stateless; its "state" (the registered verifiers)
        // is configured at genesis or managed by governance transactions that call `register`.
        // Therefore, no state snapshot is needed for an upgrade of the registry logic.
        Ok(Vec::new())
    }

    fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        // Since the snapshot is empty, there is nothing to do to complete the upgrade.
        Ok(())
    }
}