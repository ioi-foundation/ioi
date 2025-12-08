// Path: crates/services/src/agentic/mod.rs
//! Agentic module implementation

use ioi_api::impl_service_base;

pub mod normaliser;
pub mod prompt_wrapper;
pub mod firewall; // [NEW]

/// A service for agentic operations.
pub struct AgenticService {
    // Add your implementation fields here
}

impl_service_base!(AgenticService, "agentic");