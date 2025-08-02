// Path: crates/api/src/validator/types.rs
//! Defines validator model types and traits.

use depin_sdk_types::error::ValidatorError;

/// A trait representing a complete validator model.
pub trait ValidatorModel {
    /// An associated type representing the specific WorkloadContainer implementation this validator uses.
    /// This allows us to access it generically without knowing the validator's concrete type.
    type WorkloadContainerType;

    /// Starts the validator and all its containers.
    fn start(&self) -> Result<(), ValidatorError>;
    /// Stops the validator and all its containers.
    fn stop(&self) -> Result<(), ValidatorError>;
    /// Checks if the validator is running.
    fn is_running(&self) -> bool;
    /// Gets the type of the validator.
    fn validator_type(&self) -> ValidatorType;
    /// Provides generic access to the validator's workload container.
    fn workload_container(&self) -> &Self::WorkloadContainerType;
}

/// The different types of validator architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorType {
    /// A standard validator with Guardian, Orchestration, and Workload containers.
    Standard,
    /// A hybrid validator with additional Interface and API containers.
    Hybrid,
}
