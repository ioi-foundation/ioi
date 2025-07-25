//! Value conversion utilities for IBC module
/// Trait for types that can be converted from/to bytes
/// This unifies the previously separate ValueConversion and FromBytes traits
pub trait ByteConvertible: Sized {
    /// Convert from bytes to this type
    fn from_bytes(bytes: &[u8]) -> Option<Self>;

    /// Convert this type to bytes
    fn to_bytes(&self) -> Vec<u8>;
}

// Implement for Vec<u8> which is the most common value type
impl ByteConvertible for Vec<u8> {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(bytes.to_vec())
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.clone()
    }
}
