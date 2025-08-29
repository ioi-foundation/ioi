// crates/types/src/codec.rs

//! Defines the canonical, deterministic binary codec for all consensus-critical state.
//!
//! This module provides simple wrappers around `parity-scale-codec` (SCALE), which is
//! used in Substrate-based blockchains for its compact and deterministic properties.
//! By centralizing the codec logic here in the base `types` crate, we ensure that
//! all components use the exact same serialization format for state, preventing
//! consensus failures due to different binary representations of the same data.

use parity_scale_codec::{Decode, Encode};

/// Encodes a value into a deterministic, canonical byte representation using SCALE codec.
///
/// This function should be used for all data that is written to consensus-critical state
/// or is included in a hash for signing or replay protection.
///
/// # Arguments
///
/// * `v` - A reference to a value that implements the `parity_scale_codec::Encode` trait.
///
/// # Returns
///
/// A `Vec<u8>` containing the canonical SCALE-encoded bytes.
pub fn to_bytes_canonical<T: Encode>(v: &T) -> Vec<u8> {
    v.encode()
}

/// Decodes a value from a canonical byte representation using SCALE codec.
///
/// This function fails fast on any decoding error, returning a descriptive string. This is
/// critical for preventing invalid or malformed data from being processed in a consensus context.
///
/// # Arguments
///
/// * `b` - A byte slice containing the SCALE-encoded data.
///
/// # Returns
///
/// A `Result` containing the decoded value of type `T` on success, or a `String`
/// detailing the error on failure.
pub fn from_bytes_canonical<T: Decode>(b: &[u8]) -> Result<T, String> {
    T::decode(&mut &*b).map_err(|e| format!("canonical decode failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[derive(Encode, Decode, Debug, PartialEq, Eq)]
    struct TestStruct {
        id: u32,
        name: String,
        tags: Vec<u8>,
    }

    #[test]
    fn test_canonical_codec_roundtrip() {
        // Test with a simple struct
        let original_struct = TestStruct {
            id: 42,
            name: "test-data".to_string(),
            tags: vec![1, 2, 3],
        };

        let encoded = to_bytes_canonical(&original_struct);
        assert!(!encoded.is_empty());

        let decoded = from_bytes_canonical::<TestStruct>(&encoded).unwrap();
        assert_eq!(original_struct, decoded);

        // Test with a more complex structure (BTreeSet)
        let mut original_set = BTreeSet::new();
        original_set.insert([1u8; 32]);
        original_set.insert([2u8; 32]);
        original_set.insert([3u8; 32]);

        let encoded_set = to_bytes_canonical(&original_set);
        let decoded_set = from_bytes_canonical::<BTreeSet<[u8; 32]>>(&encoded_set).unwrap();

        assert_eq!(original_set, decoded_set);
    }

    #[test]
    fn test_canonical_decode_failure() {
        let original_struct = TestStruct {
            id: 99,
            name: "another-test".to_string(),
            tags: vec![10, 20, 30, 40, 50],
        };

        let mut encoded = to_bytes_canonical(&original_struct);
        // Truncate the encoded data to make it invalid
        encoded.pop();
        encoded.pop();

        let result = from_bytes_canonical::<TestStruct>(&encoded);
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("canonical decode failed"));
        assert!(error_msg.contains("Not enough data to fill buffer"));
    }
}
