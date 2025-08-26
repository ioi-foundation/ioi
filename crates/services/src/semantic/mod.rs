// Path: crates/services/src/semantic/mod.rs
//! Semantic module implementation

use depin_sdk_api::impl_service_base;
use depin_sdk_api::services::{BlockchainService, ServiceType};

pub mod normaliser;
pub mod prompt_wrapper;

pub struct SemanticService {
    // Add your implementation fields here
}

impl BlockchainService for SemanticService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Semantic
    }
}

impl_service_base!(SemanticService);