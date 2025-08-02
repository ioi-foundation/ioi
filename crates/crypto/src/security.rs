// Path: crates/crypto/src/security.rs
/// Post-quantum security level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// NIST Level 1 (approximately 128-bit classical security)
    Level1,
    /// NIST Level 2
    Level2,
    /// NIST Level 3 (approximately 192-bit classical security)
    Level3,
    /// NIST Level 5 (approximately 256-bit classical security)
    Level5,
}

impl SecurityLevel {
    /// Get the equivalent classical security bits
    pub fn classical_bits(&self) -> usize {
        match self {
            SecurityLevel::Level1 => 128,
            SecurityLevel::Level2 => 160,
            SecurityLevel::Level3 => 192,
            SecurityLevel::Level5 => 256,
        }
    }

    /// Get the equivalent quantum security bits
    pub fn quantum_bits(&self) -> usize {
        match self {
            SecurityLevel::Level1 => 64,
            SecurityLevel::Level2 => 80,
            SecurityLevel::Level3 => 96,
            SecurityLevel::Level5 => 128,
        }
    }
}
