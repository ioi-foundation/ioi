// Path: crates/services/src/Agentic/mod.rs
//! Agentic module implementation

use depin_sdk_api::impl_service_base;
use depin_sdk_api::services::{BlockchainService, ServiceType};

pub mod normaliser;
pub mod prompt_wrapper;

pub struct AgenticService {
    // Add your implementation fields here
}

impl BlockchainService for AgenticService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Agentic
    }
}

impl_service_base!(AgenticService);
