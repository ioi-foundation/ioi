//! Validator type definitions
use crate::error::ValidatorError;

/// Validator model trait
pub trait ValidatorModel {
    /// An associated type representing the specific WorkloadContainer implementation this validator uses.
    /// This allows us to access it generically without knowing the validator's concrete type.
    type WorkloadContainerType;

    /// Start the validator
    fn start(&self) -> Result<(), ValidatorError>;

    /// Stop the validator
    fn stop(&self) -> Result<(), ValidatorError>;

    /// Check if the validator is running
    fn is_running(&self) -> bool;

    /// Get the validator type
    fn validator_type(&self) -> ValidatorType;

    /// Provides generic access to the validator's workload container.
    fn workload_container(&self) -> &Self::WorkloadContainerType;
}

/// Validator types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorType {
    /// Standard validator (3 containers)
    Standard,
    /// Hybrid validator (5 containers)
    Hybrid,
}