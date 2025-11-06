// Path: crates/services/src/agentic/mod.rs
//! Agentic module implementation

use ioi_api::impl_service_base;

pub mod normaliser;
pub mod prompt_wrapper;

/// A service for agentic operations.
pub struct AgenticService {
    // Add your implementation fields here
}

// Implement the base BlockchainService trait using the helper macro.
// "agentic" is the unique, static ID for this service.
impl_service_base!(AgenticService, "agentic");
