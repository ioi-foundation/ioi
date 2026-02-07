// Path: crates/zk-driver-succinct/src/config.rs
use serde::{Deserialize, Serialize};

/// Configuration for the Succinct ZK Driver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccinctDriverConfig {
    /// The expected hash of the Beacon VK (hex string). This serves as the trust anchor.
    pub beacon_vkey_hash: String,
    /// The raw bytes of the Beacon VK, required for actual verification in native mode.
    /// In mock mode, this can be empty.
    pub beacon_vkey_bytes: Vec<u8>,

    /// The expected hash of the State Inclusion VK (hex string). This serves as the trust anchor.
    pub state_inclusion_vkey_hash: String,
    /// The raw bytes of the State Inclusion VK, required for actual verification in native mode.
    /// In mock mode, this can be empty.
    pub state_inclusion_vkey_bytes: Vec<u8>,
}

impl Default for SuccinctDriverConfig {
    fn default() -> Self {
        Self {
            // Placeholders for development (Mock mode defaults)
            beacon_vkey_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            beacon_vkey_bytes: Vec::new(),
            state_inclusion_vkey_hash:
                "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            state_inclusion_vkey_bytes: Vec::new(),
        }
    }
}
