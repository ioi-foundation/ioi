// Path: crates/core/src/validator/container/mod.rs

use crate::error::ValidatorError;
use async_trait::async_trait;

/// A trait for any component that can be started and stopped.
#[async_trait]
pub trait Container {
    /// A unique identifier for the container.
    fn id(&self) -> &'static str;
    /// Returns true if the container is currently running.
    fn is_running(&self) -> bool;
    /// Starts the container's logic.
    async fn start(&self) -> Result<(), ValidatorError>;
    /// Stops the container's logic.
    async fn stop(&self) -> Result<(), ValidatorError>;
}

/// A trait for the Guardian container, responsible for secure boot and attestation.
pub trait GuardianContainer: Container {
    /// Initiates the secure boot process.
    fn start_boot(&self) -> Result<(), ValidatorError>;
    /// Verifies the attestation of other containers.
    fn verify_attestation(&self) -> Result<bool, ValidatorError>;
}