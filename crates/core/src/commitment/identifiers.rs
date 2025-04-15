//! Scheme identifier definitions for different commitment types

/// Identifier for commitment schemes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SchemeIdentifier(pub String);

impl SchemeIdentifier {
    /// Create a new scheme identifier
    pub fn new(value: &str) -> Self {
        Self(value.to_string())
    }
}
