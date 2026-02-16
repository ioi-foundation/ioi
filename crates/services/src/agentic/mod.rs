// Path: crates/services/src/agentic/mod.rs
//! Agentic module implementation

use ioi_api::impl_service_base;

pub mod desktop;
pub mod evolution; // [NEW] Register Evolution module
pub mod firewall;
pub mod fitness;
pub mod grounding;
pub mod intent;
pub mod leakage;
pub mod normaliser;
pub mod optimizer;
pub mod pii_adapter;
pub mod pii_router;
pub mod pii_scrubber;
pub mod pii_substrate;
pub mod policy;
pub mod prompt_wrapper;
pub mod rules;
pub mod session;

/// A service for agentic operations.
pub struct AgenticService {
    // Add your implementation fields here
}

impl_service_base!(AgenticService, "agentic");
