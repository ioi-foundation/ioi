// Path: crates/crypto/src/lib.rs
//! # DePIN SDK Cryptography
//!
//! Cryptographic implementations for the DePIN SDK including post-quantum algorithms.

pub mod algorithms;
pub mod kem;
pub mod security;
pub mod sign;

#[cfg(test)]
mod tests {
    // Simple canary test to verify test discovery is working
    #[test]
    fn test_crypto_canary() {}
}
