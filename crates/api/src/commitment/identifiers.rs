// Path: crates/api/src/commitment/identifiers.rs
//! Defines the unique identifier for a commitment scheme.

/// A unique, string-based identifier for a commitment scheme.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SchemeIdentifier(pub String);

impl SchemeIdentifier {
    /// Creates a new scheme identifier from a string slice.
    pub fn new(value: &str) -> Self {
        Self(value.to_string())
    }
}
