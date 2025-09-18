// Path: crates/types/src/commitment.rs
//! Core types for commitment schemes.

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// A unique, string-based identifier for a commitment scheme.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Encode, Decode)]
pub struct SchemeIdentifier(pub String);

impl SchemeIdentifier {
    /// Creates a new scheme identifier from a string slice.
    pub fn new(value: &str) -> Self {
        Self(value.to_string())
    }
}
