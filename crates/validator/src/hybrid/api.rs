//! Implementation of API container

use crate::config::ApiConfig;
use depin_sdk_core::error::ValidatorError;
use depin_sdk_core::validator::Container;
use std::error::Error;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// API container for API implementation and state queries
pub struct ApiContainer {
    /// Parsed configuration for the API container.
    config: ApiConfig,
    /// Running status
    running: Arc<Mutex<bool>>,
}

impl ApiContainer {
    /// Create a new API container
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let config_str = std::fs::read_to_string(config_path.as_ref())?;
        let config: ApiConfig = toml::from_str(&config_str)?;

        println!("API container config loaded. Listen address: {}", config.listen_address);

        Ok(Self {
            config,
            running: Arc::new(Mutex::new(false)),
        })
    }
    /// Handle an API request
    pub fn handle_request(&self, endpoint: &str, params: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        if !self.is_running() {
            return Err("API container is not running".into());
        }
        println!("Handling API request to endpoint {}, {} bytes", endpoint, params.len());
        Ok(vec![9, 10, 11, 12])
    }
    /// Check if the container is running
    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }
}

impl Container for ApiContainer {
    fn start(&self) -> Result<(), ValidatorError> {
        let mut running = self.running.lock().unwrap();
        *running = true;
        println!("API container started successfully");
        Ok(())
    }

    fn stop(&self) -> Result<(), ValidatorError> {
        let mut running = self.running.lock().unwrap();
        *running = false;
        println!("API container stopped successfully");
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.is_running()
    }

    fn id(&self) -> &str {
        "api"
    }
}