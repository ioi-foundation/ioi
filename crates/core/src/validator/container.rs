//! Container interface definitions

/// Container interface
pub trait Container {
    /// Start the container
    fn start(&self) -> Result<(), String>;
    
    /// Stop the container
    fn stop(&self) -> Result<(), String>;
    
    /// Check if the container is running
    fn is_running(&self) -> bool;
    
    /// Get the container ID
    fn id(&self) -> &str;
}

/// Guardian container interface
pub trait GuardianContainer: Container {
    /// Start the boot process
    fn start_boot(&self) -> Result<(), String>;
    
    /// Verify attestation
    fn verify_attestation(&self) -> Result<bool, String>;
}
