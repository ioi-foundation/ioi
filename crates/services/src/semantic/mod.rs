//! Semantic module implementation

use depin_sdk_core::services::{BlockchainService, ServiceType};

pub struct SemanticService {
    // Add your implementation fields here
}

impl BlockchainService for SemanticService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Semantic
    }
}