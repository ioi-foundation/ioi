// Path: crates/crypto/src/lib.rs
//! # IOI Kernel Crypto Crate Lints
//!
//! This crate enforces a strict set of lints to ensure high-quality,
//! panic-free, and well-documented code. Panics are disallowed in non-test
//! code to promote robust error handling.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
//! # IOI Kernel Cryptography
//!
//! Cryptographic implementations for the IOI Kernel including post-quantum algorithms.

pub mod algorithms;
pub mod error;
pub mod kem;
pub mod key_store;
pub mod security;
pub mod sign;
pub mod transport;

#[cfg(test)]
mod tests {
    // Simple canary test to verify test discovery is working
    #[test]
    fn test_crypto_canary() {}
}
