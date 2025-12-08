// Path: crates/services/src/agentic/firewall.rs

use serde_json::Value;
use anyhow::{anyhow, Result};
use ioi_crypto::algorithms::hash::sha256;

pub struct SemanticFirewall;

impl SemanticFirewall {
    /// Validates inputs against a DIM Template.
    /// This is a placeholder for future logic (spending limits, rate limits).
    pub fn preflight_check(_input: &[u8]) -> Result<()> {
        // Future: Check against active governance policies
        Ok(())
    }

    /// Converts raw inference output into Canonical JSON (RFC 8785).
    /// This is the "Determinism Boundary" that allows consensus on AI output.
    pub fn canonicalize(raw_output: &str) -> Result<Vec<u8>> {
        // Parse the raw string into a Value to handle whitespace/ordering normalization
        let value: Value = serde_json::from_str(raw_output)
            .map_err(|e| anyhow!("Failed to parse inference output as JSON: {}", e))?;

        // Use `serde_jcs` to produce the canonical byte representation.
        // This handles key sorting and number formatting rules.
        serde_jcs::to_vec(&value).map_err(|e| anyhow!("JCS canonicalization failed: {}", e))
    }

    /// Computes the Intent Hash from a canonicalized result.
    pub fn compute_intent_hash(canonical_bytes: &[u8]) -> Result<[u8; 32]> {
        let digest = sha256(canonical_bytes)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalization_determinism() {
        let json1 = r#"{"b": 1, "a": [2, 1]}"#;
        let json2 = r#"{  "a": [2, 1], "b": 1}"#; // Different whitespace and order

        let c1 = SemanticFirewall::canonicalize(json1).unwrap();
        let c2 = SemanticFirewall::canonicalize(json2).unwrap();

        assert_eq!(c1, c2, "Canonical output must be identical regardless of input formatting");
        
        // JCS implies keys are sorted: {"a":[2,1],"b":1}
        let s1 = String::from_utf8(c1).unwrap();
        assert!(s1.starts_with(r#"{"a""#)); 
    }
}