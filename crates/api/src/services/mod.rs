// Path: crates/api/src/services/mod.rs
//! Traits for pluggable, upgradable blockchain services.

use crate::identity::CredentialsView;
use crate::lifecycle::OnEndBlock;
use crate::transaction::context::TxContext;
use crate::transaction::decorator::TxDecorator;
use async_trait::async_trait;
use ioi_types::error::{TransactionError, UpgradeError};
use ioi_types::service_configs::Capabilities;
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
///
/// # Storage Invariant: Namespaced Access
///
/// To ensure state isolation, all reads and writes performed by a service via the
/// `handle_service_call` method are automatically scoped to a private namespace.
///
/// *   **Runtime Access:** The `StateAccess` passed to the service is a `NamespacedStateAccess`.
///     Any key `k` accessed by the service is physically stored as:
///     `_service_data::{service_id}::{k}`.
///
/// *   **System Access:** Services can only access global system keys (e.g., `system::...`)
///     if the key prefix is explicitly listed in the service's `allowed_system_prefixes` configuration.
///
/// *   **Genesis & Testing Warning:** When seeding the initial state for a service in `genesis.json`
///     or during test setup, the automatic namespacing logic is **NOT** applied. You must manually
///     construct the full key using the helper:
///     `ioi_api::state::service_namespace_prefix(service_id) + your_key`.
#[async_trait]
pub trait BlockchainService: Any + Send + Sync {
    /// A unique, static, lowercase string identifier for the service.
    /// This is used for deterministic sorting and for dispatching `CallService` transactions.
    fn id(&self) -> &str;

    /// The version of the ABI the service expects from the host.
    fn abi_version(&self) -> u32;

    /// A string identifying the schema of the state this service reads/writes.
    fn state_schema(&self) -> &str;

    /// Returns a bitmask of the lifecycle capabilities (hooks) this service implements.
    fn capabilities(&self) -> Capabilities;

    /// Provides access to the concrete type for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Handles a generic, dispatched call from a `SystemTransaction::CallService` payload.
    /// This is the primary entry point for all on-chain service logic.
    ///
    /// # Default Implementation
    /// The default implementation returns an `Unsupported` error. Services must override
    /// this method to expose callable functions.
    async fn handle_service_call(
        &self,
        state: &mut dyn crate::state::StateAccess,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        // Mark parameters as used to satisfy the compiler under the default implementation.
        let _ = (state, method, params, ctx);
        Err(TransactionError::Unsupported(format!(
            "Service '{}' does not implement the handle_service_call capability or the method '{}'",
            self.id(),
            method
        )))
    }

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
}

/// A trait for services that support runtime upgrades and rollbacks.
#[async_trait]
pub trait UpgradableService: BlockchainService {
    /// Prepares the service for an upgrade by validating the new implementation
    /// and returning a state snapshot for migration.
    async fn prepare_upgrade(&self, new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError>;

    /// Completes the upgrade by instantiating a new version of the service from a state snapshot.
    async fn complete_upgrade(&self, snapshot: &[u8]) -> Result<(), UpgradeError>;

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
