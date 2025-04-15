//! Implementation of cryptographic hash functions

use sha2::{Sha256, Sha512, Digest};

/// Hash function trait
pub trait HashFunction {
    /// Hash a message
    fn hash(&self, message: &[u8]) -> Vec<u8>;
    
    /// Get the digest size in bytes
    fn digest_size(&self) -> usize;
}

/// SHA-256 hash function
#[derive(Default)]
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
}

/// SHA-512 hash function
#[derive(Default)]
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
}
