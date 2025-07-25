use std::any::Any;
use std::collections::HashMap;

/// An identifier for a swappable service.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceType {
    Governance,
    Semantic,
    ExternalData,
    // ... other standard services
    Custom(String),
}

/// The base trait for any service managed by the chain.
pub trait BlockchainService: Any + Send + Sync {
    fn service_type(&self) -> ServiceType;
    // Potentially add methods for health checks, metrics, etc.
}

/// A trait for services that support runtime upgrades and rollbacks.
pub trait UpgradableService: BlockchainService {
    /// Prepares the service for an upgrade by validating the new implementation
    /// and providing a state snapshot for migration.
    fn prepare_upgrade(&self, new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError>; // Returns state snapshot

    /// Instantiates a new version of the service from a state snapshot.
    fn complete_upgrade(&mut self, snapshot: &[u8]) -> Result<(), UpgradeError>;
}
