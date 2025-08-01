// crates/crypto/src/algorithms/hash/mod.rs
//! Cryptographic hash functions using dcrypt

use dcrypt::algorithms::hash::sha2::{Sha256 as DcryptSha256, Sha512 as DcryptSha512};
use dcrypt::algorithms::hash::HashFunction as DcryptHashFunction;
use dcrypt::algorithms::ByteSerializable;

/// Hash function trait
pub trait HashFunction {
    /// Hash a message and return the digest
    fn hash(&self, message: &[u8]) -> Vec<u8>;

    /// Get the digest size in bytes
    fn digest_size(&self) -> usize;

    /// Get the name of the hash function
    fn name(&self) -> &str;
}

/// SHA-256 hash function implementation using dcrypt
#[derive(Default, Clone)]
pub struct Sha256Hash;

impl HashFunction for Sha256Hash {
    fn hash(&self, message: &[u8]) -> Vec<u8> {
        // Use dcrypt's SHA-256 implementation
        match DcryptSha256::digest(message) {
            Ok(digest) => digest.to_bytes(),
            Err(_) => panic!("SHA-256 hashing failed"),
        }
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
    fn hash(&self, message: &[u8]) -> Vec<u8> {
        // Use dcrypt's SHA-512 implementation
        match DcryptSha512::digest(message) {
            Ok(digest) => digest.to_bytes(),
            Err(_) => panic!("SHA-512 hashing failed"),
        }
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
    pub fn hash(&self, message: &[u8]) -> Vec<u8> {
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
pub fn sha256<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    let hasher = Sha256Hash;
    hasher.hash(data.as_ref())
}

/// Create a SHA-512 hash of any type that can be referenced as bytes
pub fn sha512<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    let hasher = Sha512Hash;
    hasher.hash(data.as_ref())
}

#[cfg(test)]
mod tests;
