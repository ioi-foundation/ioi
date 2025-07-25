//! External data module implementation

use depin_sdk_core::services::{BlockchainService, ServiceType};

pub struct ExternalDataService {
    // Add your implementation fields here
}

impl BlockchainService for ExternalDataService {
    fn service_type(&self) -> ServiceType {
        ServiceType::ExternalData
    }
}