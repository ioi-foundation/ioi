// Path: crates/api/src/services/mod.rs
//! Traits for pluggable, upgradable blockchain services.

use crate::identity::CredentialsView;
use crate::lifecycle::OnEndBlock;
use crate::services::capabilities::IbcPayloadHandler;
use crate::transaction::decorator::TxDecorator;
use async_trait::async_trait;
use depin_sdk_types::error::UpgradeError;
use depin_sdk_types::service_configs::Capabilities;
use std::any::Any;
use std::hash::Hash;

pub mod access;
pub mod capabilities;

/// An identifier for a swappable service.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ServiceType {
    /// A service for on-chain governance.
    Governance,
    /// A service for agentic data processing or validation.
    Agentic,
    /// A service for interacting with external data sources.
    ExternalData,
    /// A custom service type.
    Custom(String),
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceType::Governance => write!(f, "governance"),
            ServiceType::Agentic => write!(f, "agentic"),
            ServiceType::ExternalData => write!(f, "external_data"),
            ServiceType::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// The base trait for any service managed by the chain.
pub trait BlockchainService: Any + Send + Sync {
    /// A unique, static string identifier for the service.
    /// This is used for deterministic sorting in the ServiceDirectory.
    fn id(&self) -> &'static str;

    /// The version of the ABI the service expects from the host.
    fn abi_version(&self) -> u32;

    /// A string identifying the schema of the state this service reads/writes.
    fn state_schema(&self) -> &'static str;

    /// Returns a bitmask of the capabilities this service implements.
    fn capabilities(&self) -> Capabilities;

    /// Provides access to the concrete type for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Attempts to downcast this service to a `TxDecorator` trait object.
    fn as_tx_decorator(&self) -> Option<&dyn TxDecorator> {
        None
    }
    /// Attempts to downcast this service to an `OnEndBlock` trait object.
    fn as_on_end_block(&self) -> Option<&dyn OnEndBlock> {
        None
    }
    /// Attempts to downcast this service to a `CredentialsView` trait object.
    fn as_credentials_view(&self) -> Option<&dyn CredentialsView> {
        None
    }
    /// Attempts to downcast this service to an `IbcPayloadHandler` trait object.
    fn as_ibc_handler(&self) -> Option<&dyn IbcPayloadHandler> {
        None
    }
}

/// A trait for services that support runtime upgrades and rollbacks.
#[async_trait]
pub trait UpgradableService: BlockchainService {
    /// Prepares the service for an upgrade by validating the new implementation
    /// and returning a state snapshot for migration.
    async fn prepare_upgrade(&mut self, new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError>;

    /// Completes the upgrade by instantiating a new version of the service from a state snapshot.
    async fn complete_upgrade(&mut self, snapshot: &[u8]) -> Result<(), UpgradeError>;

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
