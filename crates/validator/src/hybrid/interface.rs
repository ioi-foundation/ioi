//! Implementation of interface container

use crate::config::InterfaceConfig;
use depin_sdk_core::error::ValidatorError;
use depin_sdk_core::validator::Container;
use std::error::Error;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Interface container for connection handling and protocol routing
pub struct InterfaceContainer {
    /// Parsed configuration for the Interface container.
    config: InterfaceConfig,
    /// Running status
    running: Arc<Mutex<bool>>,
}

impl InterfaceContainer {
    /// Create a new interface container
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let config_str = std::fs::read_to_string(config_path.as_ref())?;
        let config: InterfaceConfig = toml::from_str(&config_str)?;

        println!("Interface container config loaded. Listen address: {}", config.listen_address);

        Ok(Self {
            config,
            running: Arc::new(Mutex::new(false)),
        })
    }
    /// Handle a client connection
    pub fn handle_connection(&self, addr: SocketAddr, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        if !self.is_running() {
            return Err("Interface container is not running".into());
        }
        println!("Handling connection from {}, {} bytes", addr, data.len());
        Ok(vec![5, 6, 7, 8])
    }
    /// Check if the container is running
    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }
}

impl Container for InterfaceContainer {
    fn start(&self) -> Result<(), ValidatorError> {
        let mut running = self.running.lock().unwrap();
        *running = true;
        println!("Interface container started successfully");
        Ok(())
    }

    fn stop(&self) -> Result<(), ValidatorError> {
        let mut running = self.running.lock().unwrap();
        *running = false;
        println!("Interface container stopped successfully");
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.is_running()
    }

    fn id(&self) -> &str {
        "interface"
    }
}