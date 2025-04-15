//! Validator type definitions

/// Validator model trait
pub trait ValidatorModel {
    /// Start the validator
    fn start(&self) -> Result<(), String>;
    
    /// Stop the validator
    fn stop(&self) -> Result<(), String>;
    
    /// Check if the validator is running
    fn is_running(&self) -> bool;
    
    /// Get the validator type
    fn validator_type(&self) -> ValidatorType;
}

/// Validator types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorType {
    /// Standard validator (3 containers)
    Standard,
    /// Hybrid validator (5 containers)
    Hybrid,
}
