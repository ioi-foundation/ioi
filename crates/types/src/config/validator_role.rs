// Path: crates/types/src/config/validator_role.rs
use serde::{Deserialize, Serialize};

/// Defines the functional role and hardware capabilities of a validator node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "config", rename_all = "PascalCase")]
pub enum ValidatorRole {
    /// Type A: Consensus Validator.
    /// Responsible for block ordering, ledger security, and signature verification.
    /// Hardware requirements: Consumer-grade CPU, moderate RAM.
    Consensus,

    /// Type B: Compute Validator.
    /// Responsible for DIM (Distributed Inference Mesh) execution and ZK proving.
    /// Hardware requirements: GPU acceleration.
    Compute {
        /// Hardware capability class (e.g., "nvidia-h100", "generic-cuda").
        accelerator_type: String,
        /// Available VRAM in bytes, used for model scheduling.
        vram_capacity: u64,
    },
}

impl Default for ValidatorRole {
    fn default() -> Self {
        Self::Consensus
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_serialization_consensus() {
        let role = ValidatorRole::Consensus;
        let toml = toml::to_string(&role).unwrap();
        
        // Enum tagging in TOML/Serde can vary, but usually looks like:
        // type = "Consensus"
        assert!(toml.contains("type = \"Consensus\""));

        let deserialized: ValidatorRole = toml::from_str(&toml).unwrap();
        assert_eq!(role, deserialized);
    }

    #[test]
    fn test_role_serialization_compute() {
        let role = ValidatorRole::Compute { 
            accelerator_type: "nvidia-h100".to_string(), 
            vram_capacity: 80 * 1024 * 1024 * 1024 
        };
        let toml = toml::to_string(&role).unwrap();
        
        println!("TOML Output:\n{}", toml);
        
        assert!(toml.contains("type = \"Compute\""));
        assert!(toml.contains("nvidia-h100"));
        
        let deserialized: ValidatorRole = toml::from_str(&toml).unwrap();
        assert_eq!(role, deserialized);
    }
    
    #[test]
    fn test_embedded_in_orchestration_config() {
        // Mocking the structure of OrchestrationConfig to ensure nesting works
        #[derive(Serialize, Deserialize)]
        struct MockConfig {
            chain_id: u32,
            validator_role: ValidatorRole,
        }
        
        let cfg = MockConfig {
            chain_id: 1,
            validator_role: ValidatorRole::Compute {
                accelerator_type: "cuda".into(),
                vram_capacity: 12345,
            }
        };
        
        let s = toml::to_string(&cfg).unwrap();
        let d: MockConfig = toml::from_str(&s).unwrap();
        assert_eq!(d.validator_role, cfg.validator_role);
    }
}