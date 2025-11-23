use serde::{Deserialize, Serialize};

/// Configuration for the Succinct ZK Driver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccinctDriverConfig {
    /// The Verification Key (vkey) hash for the Ethereum Beacon Update circuit.
    /// Usually a hex string or 32-byte array in SP1.
    pub beacon_vkey_hash: String,
    
    /// The Verification Key hash for the State Inclusion circuit (e.g. Verkle/MPT).
    pub state_inclusion_vkey_hash: String,
}

impl Default for SuccinctDriverConfig {
    fn default() -> Self {
        Self {
            // Placeholders for development
            beacon_vkey_hash: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            state_inclusion_vkey_hash: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        }
    }
}