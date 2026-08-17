// Path: crates/zk-driver-succinct/src/config.rs
use serde::{Deserialize, Serialize};

/// The governed verifying-key pin for the aft-continuity guest (AFT-CB
/// R4c). This value mirrors `crates/aft-proofs/vkey.json` — the governed
/// pin document — and a test asserts the two never drift. Changing it is
/// a protocol-parameter change: it lands only through a reviewed PR that
/// names the guest change forcing it. UNPINNED is a refusal state, never
/// a fallback.
pub const CANONICAL_COLLAPSE_CONTINUITY_VKEY_PIN: &str =
    "0x00ccba8a34fdefd3b465c31e26fe7f953da63e4cd371dbdf9179974e47a5cf02";

/// Configuration for the Succinct ZK Driver.
///
/// There is deliberately NO `Default` impl (AFT-CB R4c): a default-mock
/// configuration was the mock constructor's substance, and release code
/// must choose its trust anchors explicitly. Use [`SuccinctDriverConfig::pinned`]
/// for the governed AFT-continuity pin, or construct explicitly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccinctDriverConfig {
    /// The expected hash of the Beacon VK (hex string). This serves as the trust anchor.
    pub beacon_vkey_hash: String,
    /// The raw bytes of the Beacon VK, required for actual verification in native mode.
    /// Empty means unprovisioned: native verification refuses.
    pub beacon_vkey_bytes: Vec<u8>,

    /// The expected hash of the State Inclusion VK (hex string). This serves as the trust anchor.
    pub state_inclusion_vkey_hash: String,
    /// The raw bytes of the State Inclusion VK, required for actual verification in native mode.
    /// Empty means unprovisioned: native verification refuses.
    pub state_inclusion_vkey_bytes: Vec<u8>,

    /// The expected hash of the canonical-collapse continuity VK (hex string).
    pub canonical_collapse_continuity_vkey_hash: String,
    /// The 32-byte canonical vkey digest (`vk.bytes32()`) the SP1 backend
    /// verifies against. Empty means unprovisioned: verification refuses.
    pub canonical_collapse_continuity_vkey_bytes: Vec<u8>,
}

impl SuccinctDriverConfig {
    /// The governed configuration: the AFT canonical-collapse continuity
    /// lane pinned to [`CANONICAL_COLLAPSE_CONTINUITY_VKEY_PIN`]; the IBC
    /// lanes (beacon, state-inclusion) explicitly UNPROVISIONED — their
    /// native verification refuses until a deployment provisions real
    /// vkeys through its own governed configuration.
    pub fn pinned() -> Self {
        Self {
            beacon_vkey_hash: String::new(),
            beacon_vkey_bytes: Vec::new(),
            state_inclusion_vkey_hash: String::new(),
            state_inclusion_vkey_bytes: Vec::new(),
            canonical_collapse_continuity_vkey_hash:
                CANONICAL_COLLAPSE_CONTINUITY_VKEY_PIN.to_string(),
            canonical_collapse_continuity_vkey_bytes: pin_bytes(
                CANONICAL_COLLAPSE_CONTINUITY_VKEY_PIN,
            ),
        }
    }
}

/// Decodes a `0x`-prefixed 32-byte pin into its raw bytes. The pin is a
/// compile-time constant; a malformed pin is a programming error surfaced
/// at first use, and the empty vector it yields is a refusal state in
/// every verification path (never a silent accept).
fn pin_bytes(pin: &str) -> Vec<u8> {
    match hex::decode(pin.trim_start_matches("0x")) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod pin_tests {
    use super::*;

    /// The config pin and the governed pin document
    /// (`crates/aft-proofs/vkey.json`) must never drift: vkey.json is the
    /// governance surface, this constant is the enforcement surface.
    #[test]
    fn config_pin_matches_governed_vkey_document() {
        let doc_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../aft-proofs/vkey.json"
        );
        let doc = std::fs::read_to_string(doc_path)
            .expect("governed pin document crates/aft-proofs/vkey.json exists");
        let parsed: serde_json::Value =
            serde_json::from_str(&doc).expect("vkey.json parses");
        assert_eq!(
            parsed["vkey_bytes32"].as_str().expect("vkey_bytes32 field"),
            CANONICAL_COLLAPSE_CONTINUITY_VKEY_PIN,
            "config pin drifted from the governed vkey.json pin"
        );
    }

    #[test]
    fn pinned_config_carries_decoded_pin_bytes() {
        let cfg = SuccinctDriverConfig::pinned();
        assert_eq!(cfg.canonical_collapse_continuity_vkey_bytes.len(), 32);
        assert_eq!(
            format!(
                "0x{}",
                hex::encode(&cfg.canonical_collapse_continuity_vkey_bytes)
            ),
            CANONICAL_COLLAPSE_CONTINUITY_VKEY_PIN
        );
        assert!(cfg.beacon_vkey_bytes.is_empty(), "IBC lanes unprovisioned");
        assert!(cfg.state_inclusion_vkey_bytes.is_empty());
    }
}
