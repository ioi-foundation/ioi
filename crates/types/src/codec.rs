// crates/types/src/codec.rs

//! Defines the canonical, deterministic binary codec for all consensus-critical state.
//!
//! This module provides simple wrappers around `parity-scale-codec` (SCALE), which is
//! used in Substrate-based blockchains for its compact and deterministic properties.
//! By centralizing the codec logic here in the base `types` crate, we ensure that
//! all components use the exact same serialization format for state, preventing
//! consensus failures due to different binary representations of the same data.

use parity_scale_codec::{Decode, DecodeAll, Encode};

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
pub fn to_bytes_canonical<T: Encode>(v: &T) -> Result<Vec<u8>, String> {
    Ok(v.encode())
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
    T::decode_all(&mut &*b).map_err(|e| format!("canonical decode failed: {}", e))
}

#[cfg(test)]
#[path = "codec/tests.rs"]
mod tests;
