// Path: crates/services/src/agentic/mod.rs
//! Agentic module implementation

use ioi_api::impl_service_base;

pub mod desktop;
pub mod firewall;
pub mod grounding;
pub mod intent;
pub mod leakage;
pub mod normaliser;
pub mod prompt_wrapper;
pub mod scrub_adapter;
pub mod scrubber;
pub mod session; // [NEW] Registered Intent Resolver

/// A service for agentic operations.
pub struct AgenticService {
    // Add your implementation fields here
}

impl_service_base!(AgenticService, "agentic");
