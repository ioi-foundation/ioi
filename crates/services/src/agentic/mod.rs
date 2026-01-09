// Path: crates/services/src/agentic/mod.rs
//! Agentic module implementation

use ioi_api::impl_service_base;

pub mod desktop;
pub mod firewall;
pub mod grounding; // [NEW] Visual Grounding logic
pub mod leakage;
pub mod normaliser;
pub mod prompt_wrapper;
pub mod session; // [NEW] Desktop Agent Service

/// A service for agentic operations.
pub struct AgenticService {
    // Add your implementation fields here
}

impl_service_base!(AgenticService, "agentic");
