// Path: crates/api/src/services/mod.rs
//! Traits for pluggable, upgradable blockchain services.

use crate::services::access::Service;
use depin_sdk_types::error::UpgradeError;
use std::hash::Hash;

pub mod access;

/// An identifier for a swappable service.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceType {
    /// A service for on-chain governance.
    Governance,
    /// A service for semantic data processing or validation.
    Semantic,
    /// A service for interacting with external data sources.
    ExternalData,
    /// A custom service type.
    Custom(String),
}

/// The base trait for any service managed by the chain.
pub trait BlockchainService: Service {
    /// Returns the unique type identifier for the service.
    fn service_type(&self) -> ServiceType;
}

/// A trait for services that support runtime upgrades and rollbacks.
pub trait UpgradableService: BlockchainService {
    /// Prepares the service for an upgrade by validating the new implementation
    /// and returning a state snapshot for migration.
    fn prepare_upgrade(&mut self, new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError>;

    /// Completes the upgrade by instantiating a new version of the service from a state snapshot.
    fn complete_upgrade(&mut self, snapshot: &[u8]) -> Result<(), UpgradeError>;

    /// Starts the service.
    fn start(&self) -> Result<(), UpgradeError> {
        Ok(())
    }

    /// Stops the service.
    fn stop(&self) -> Result<(), UpgradeError> {
        Ok(())
    }

    /// Checks the health of the service.
    fn health_check(&self) -> Result<(), UpgradeError> {
        Ok(())
    }
}