// crates/crypto/src/algorithms/hash/mod.rs
//! Cryptographic hash functions using dcrypt

use crate::error::CryptoError;
use dcrypt::algorithms::hash::sha2::{Sha256 as DcryptSha256, Sha512 as DcryptSha512};
use dcrypt::algorithms::hash::HashFunction as DcryptHashFunction;
use dcrypt::algorithms::ByteSerializable;

/// Hash function trait
pub trait HashFunction {
    /// Hash a message and return the digest
    fn hash(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Get the digest size in bytes
    fn digest_size(&self) -> usize;

    /// Get the name of the hash function
    fn name(&self) -> &str;
}

/// SHA-256 hash function implementation using dcrypt
#[derive(Default, Clone)]
pub struct Sha256Hash;

impl HashFunction for Sha256Hash {
    fn hash(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Use dcrypt's SHA-256 implementation
        // FIX: Use `?` to propagate and convert the error from dcrypt::algorithms::Error to dcrypt::Error
        DcryptSha256::digest(message)
            .map(|d| d.to_bytes())
            .map_err(|e| CryptoError::OperationFailed(e.to_string()))
    }

    fn digest_size(&self) -> usize {
        32 // 256 bits = 32 bytes
    }

    fn name(&self) -> &str {
        "SHA-256"
    }
}

/// SHA-512 hash function implementation using dcrypt
#[derive(Default, Clone)]
pub struct Sha512Hash;

impl HashFunction for Sha512Hash {
    fn hash(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Use dcrypt's SHA-512 implementation
        // FIX: Use `?` to propagate and convert the error from dcrypt::algorithms::Error to dcrypt::Error
        DcryptSha512::digest(message)
            .map(|d| d.to_bytes())
            .map_err(|e| CryptoError::OperationFailed(e.to_string()))
    }

    fn digest_size(&self) -> usize {
        64 // 512 bits = 64 bytes
    }

    fn name(&self) -> &str {
        "SHA-512"
    }
}

/// Generic hasher that can use any hash function
pub struct GenericHasher<H: HashFunction> {
    /// Hash function implementation
    hash_function: H,
}

impl<H: HashFunction> GenericHasher<H> {
    /// Create a new hasher with the given hash function
    pub fn new(hash_function: H) -> Self {
        Self { hash_function }
    }

    /// Hash a message
    pub fn hash(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.hash_function.hash(message)
    }

    /// Get the digest size in bytes
    pub fn digest_size(&self) -> usize {
        self.hash_function.digest_size()
    }

    /// Get the name of the hash function
    pub fn name(&self) -> &str {
        self.hash_function.name()
    }
}

// Additional convenience functions
/// Create a SHA-256 hash of any type that can be referenced as bytes
pub fn sha256<T: AsRef<[u8]>>(data: T) -> Result<[u8; 32], CryptoError> {
    let hasher = Sha256Hash;
    // For convenience functions, a panic might be acceptable if hashing is considered infallible.
    // However, to align with the phase objective, we handle it.
    // In a non-test context, this might propagate the error.
    hasher
        .hash(data.as_ref())?
        .try_into()
        .map_err(|bytes: Vec<u8>| CryptoError::InvalidHashLength {
            expected: 32,
            got: bytes.len(),
        })
}

/// Create a SHA-512 hash of any type that can be referenced as bytes
pub fn sha512<T: AsRef<[u8]>>(data: T) -> Result<[u8; 64], CryptoError> {
    let hasher = Sha512Hash;
    hasher
        .hash(data.as_ref())?
        .try_into()
        .map_err(|bytes: Vec<u8>| CryptoError::InvalidHashLength {
            expected: 64,
            got: bytes.len(),
        })
}

#[cfg(test)]
mod tests;
