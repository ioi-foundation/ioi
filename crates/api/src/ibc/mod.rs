// Path: crates/api/src/ibc/mod.rs
//! Defines traits and re-exports types for Inter-Blockchain Communication (IBC).

// Re-export core data structures from the `types` crate.
pub use depin_sdk_types::ibc::{
    BlockAnchor, DigestAlgo, FinalityEvidence, KeyCodec, MembershipWitness, ProofTarget,
    UniversalExecutionReceipt, UniversalProofFormat,
};

use crate::commitment::SchemeIdentifier;
use thiserror::Error;

/// Errors that can occur during proof translation.
#[derive(Error, Debug)]
pub enum TranslateError {
    /// The proof target (e.g., State, Log) is not supported by the translator.
    #[error("Unsupported proof target")]
    UnsupportedTarget,
    /// The source proof data is malformed or invalid.
    #[error("Invalid source proof data: {0}")]
    InvalidSourceProof(String),
    /// An unexpected error occurred during the translation process.
    #[error("Internal translation error: {0}")]
    Internal(String),
}

/// A trait for components that can translate a proof from one cryptographic scheme to another.
pub trait ProofTranslator: Send + Sync {
    /// Returns the identifier of the source commitment scheme.
    fn source_scheme(&self) -> SchemeIdentifier;
    /// Returns the identifier of the target (native) commitment scheme.
    fn target_scheme(&self) -> SchemeIdentifier;
    /// Translates a foreign proof into the native proof format.
    fn translate(
        &self,
        target: &ProofTarget,
        proof_data: &[u8],
        witness: &MembershipWitness,
    ) -> Result<Vec<u8>, TranslateError>;
}