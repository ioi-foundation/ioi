//! # DePIN SDK Cryptography
//!
//! Cryptographic implementations for the DePIN SDK including post-quantum algorithms.

pub mod algorithms;
pub mod sign;
pub mod kem;
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
