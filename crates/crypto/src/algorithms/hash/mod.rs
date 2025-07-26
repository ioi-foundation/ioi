// crates/crypto/src/traditional/hash/mod.rs
//! Implementation of cryptographic hash functions

use sha2::{Digest, Sha256, Sha512};

pub mod tests;

/// Hash function trait
pub trait HashFunction {
    /// Hash a message and return the digest
    fn hash(&self, message: &[u8]) -> Vec<u8>;
    
    /// Get the digest size in bytes
    fn digest_size(&self) -> usize;
    
    /// Get the name of the hash function
    fn name(&self) -> &str {
        // Default implementation returns a generic name
        "unknown-hash"
    }
}

/// SHA-256 hash function implementation
#[derive(Default, Clone)]
pub struct Sha256Hash;

impl HashFunction for Sha256Hash {
    fn hash(&self, message: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.finalize().to_vec()
    }
    
    fn digest_size(&self) -> usize {
        32 // 256 bits = 32 bytes
    }
    
    fn name(&self) -> &str {
        "SHA-256"
    }
}

/// SHA-512 hash function implementation
#[derive(Default, Clone)]
pub struct Sha512Hash;

impl HashFunction for Sha512Hash {
    fn hash(&self, message: &[u8]) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(message);
        hasher.finalize().to_vec()
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

/// Trait for types that can be hashed
pub trait Hashable {
    /// Convert this type to bytes for hashing
    fn to_hashable_bytes(&self) -> Vec<u8>;
    
    /// Hash this object with the provided hash function
    fn hash_with<H: HashFunction>(&self, hash_function: &H) -> Vec<u8> {
        hash_function.hash(&self.to_hashable_bytes())
    }
}

// Implement Hashable for common types
impl Hashable for [u8] {
    fn to_hashable_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl Hashable for str {
    fn to_hashable_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Hashable for String {
    fn to_hashable_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

// Additional convenience functions
/// Create a SHA-256 hash of any Hashable type
pub fn sha256<T: Hashable>(data: &T) -> Vec<u8> {
    data.hash_with(&Sha256Hash::default())
}

/// Create a SHA-512 hash of any Hashable type
pub fn sha512<T: Hashable>(data: &T) -> Vec<u8> {
    data.hash_with(&Sha512Hash::default())
}