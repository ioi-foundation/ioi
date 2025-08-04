// crates/services/src/semantic/normaliser.rs
use depin_sdk_api::services::{BlockchainService, ServiceType};
use depin_sdk_crypto::algorithms::hash::sha256;
use serde_jcs::to_vec;
use serde_json::Value; // A crate for RFC 8785 Canonical JSON

pub struct OutputNormaliser;

impl BlockchainService for OutputNormaliser {
    fn service_type(&self) -> ServiceType {
        ServiceType::Custom("OutputNormaliser".to_string())
    }
}

impl OutputNormaliser {
    /// Normalises a raw JSON string according to RFC 8785 and computes its SHA-256 hash.
    /// This is the core function that guarantees deterministic output from non-deterministic inputs.
    pub fn normalise_and_hash(raw_json: &str) -> Result<Vec<u8>, String> {
        // Step 1: Parse the raw JSON into a structured format. This ignores whitespace and key order.
        let json_value: Value =
            serde_json::from_str(raw_json).map_err(|e| format!("JSON parsing failed: {}", e))?;

        // Step 2: Reserialize the structured JSON into a canonical byte vector.
        // This enforces key sorting, specific number/string formatting, and strips all insignificant whitespace.
        // This is the step that makes the output deterministic.
        let canonical_bytes =
            to_vec(&json_value).map_err(|e| format!("JCS canonicalization failed: {}", e))?;

        // Step 3: Hash the canonical bytes to get the final, unique intent hash.
        let intent_hash = sha256(&canonical_bytes);

        log::info!(
            "OutputNormaliser produced identical hash: {}",
            hex::encode(&intent_hash)
        );
        Ok(intent_hash)
    }
}
