//! Deterministic randomness for reproducible tests

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

/// Deterministic random number generator for tests
pub struct TestRng {
    /// Internal RNG with fixed seed
    rng: StdRng,
}

impl TestRng {
    /// Create a new test RNG with the specified seed
    pub fn new(seed: u64) -> Self {
        // Convert the u64 seed to a [u8; 32] seed array
        let mut seed_array = [0u8; 32];
        let seed_bytes = seed.to_le_bytes();
        // Copy the u64 bytes into the first 8 bytes of the seed array
        seed_array[..8].copy_from_slice(&seed_bytes);

        Self {
            rng: StdRng::from_seed(seed_array),
        }
    }

    /// Create a test RNG with the default seed 12345
    pub fn with_default_seed() -> Self {
        Self::new(12345)
    }

    /// Fill a buffer with random bytes
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }

    /// Generate a random value
    pub fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    /// Generate a random value
    pub fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }
}

// Implement Default trait instead of just a method named default
impl Default for TestRng {
    fn default() -> Self {
        Self::with_default_seed()
    }
}
