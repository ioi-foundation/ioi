// Path: crates/services/src/agentic/firewall.rs

use anyhow::{anyhow, Result};
use ioi_crypto::algorithms::hash::sha256;
use serde_json::Value;

pub struct SemanticFirewall;

impl SemanticFirewall {
    /// Validates inputs against a DIM Template.
    /// This stage is now fail-closed: non-canonical or empty inputs are rejected.
    pub fn preflight_check(input: &[u8]) -> Result<()> {
        if input.is_empty() {
            return Err(anyhow!(
                "semantic firewall preflight rejected empty input; no authoritative policy artifact can be derived"
            ));
        }
        let raw = std::str::from_utf8(input)
            .map_err(|e| anyhow!("semantic firewall preflight requires UTF-8 JSON: {}", e))?;
        let canonical = Self::canonicalize(raw)?;
        if canonical.is_empty() {
            return Err(anyhow!(
                "semantic firewall preflight rejected empty canonical payload"
            ));
        }
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
#[path = "firewall/tests.rs"]
mod tests;
