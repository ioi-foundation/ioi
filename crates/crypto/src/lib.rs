//! # DePIN SDK Cryptography
//!
//! Cryptographic implementations for the DePIN SDK including post-quantum algorithms.

pub mod dilithium;
pub mod elliptic;
pub mod hash;
pub mod kyber;
pub mod module_lwe;
pub mod security;

// Simpler test module structure - don't re-export test modules
#[cfg(test)]
mod tests {
    // Simple canary test to verify test discovery is working
    #[test]
    fn test_crypto_canary() {
        assert!(true, "Basic test discovery is working");
    }
}
