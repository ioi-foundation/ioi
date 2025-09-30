//! Mock commitment scheme for testing

use crate::commitment::{CommitmentScheme, ProofContext, SchemeIdentifier, Selector};
use crate::error::CryptoError;

/// Mock commitment scheme implementation for testing
#[derive(Debug, Clone)]
pub struct MockCommitmentScheme;

/// Mock commitment for testing
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockCommitment(pub Vec<u8>);

impl AsRef<[u8]> for MockCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Mock proof for testing
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockProof {
    /// Selector used to create this proof
    pub selector: Selector,
    /// Value that this proof is for
    pub value: Vec<u8>,
}

impl CommitmentScheme for MockCommitmentScheme {
    type Commitment = MockCommitment;
    type Proof = MockProof;
    type Value = Vec<u8>;

    fn commit(&self, values: &[Option<Self::Value>]) -> Result<Self::Commitment, CryptoError> {
        // Implementation actually combines all values into a single commitment
        let mut combined = Vec::new();
        for data in values.iter().flatten() {
            combined.extend_from_slice(data.as_ref());
        }
        Ok(MockCommitment(combined))
    }

    fn create_proof(
        &self,
        selector: &Selector,
        value: &Self::Value,
    ) -> Result<Self::Proof, CryptoError> {
        // Store both selector and value in the proof
        Ok(MockProof {
            selector: selector.clone(),
            value: value.clone(),
        })
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        _selector: &Selector,
        value: &Self::Value,
        context: &ProofContext,
    ) -> bool {
        // 1. Check that selector types match
        if !matches!(&proof.selector, _selector) {
            return false;
        }

        // 2. Check value matches - comparing the raw bytes
        let value_slice: &[u8] = value.as_ref();
        if proof.value.as_slice() != value_slice {
            return false;
        }

        // 3. Use commitment in verification - in real world this would be cryptographic
        // For our mock, we'll check if the commitment contains the value
        let commitment_slice: &[u8] = commitment.as_ref();
        let contains_value = commitment_slice
            .windows(value_slice.len())
            .any(|window| window == value_slice);
        if !contains_value {
            return false;
        }

        // 4. Use context for additional verification parameters
        // In this mock, we'll check if a special "strict_verify" flag is set
        if let Some(strict_flag) = context.get_data("strict_verify") {
            if !strict_flag.is_empty() && strict_flag[0] == 1 {
                // In strict mode, we also check selector-specific rules
                match _selector {
                    Selector::Position(pos) => {
                        // Position-based verification
                        if let Selector::Position(proof_pos) = &proof.selector {
                            if pos != proof_pos {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                    Selector::Key(key) => {
                        // Key-based verification
                        if let Selector::Key(proof_key) = &proof.selector {
                            if key != proof_key {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                    _ => {
                        // For other selectors, just ensure they match exactly
                        if proof.selector != *_selector {
                            return false;
                        }
                    }
                }
            }
        }

        // If we made it here, verification passed
        true
    }

    fn scheme_id() -> SchemeIdentifier {
        SchemeIdentifier::new("mock")
    }
}

/// Helper functions for testing with mock commitment scheme
pub mod helpers {
    use super::*;

    /// Create a mock commitment from a single value
    pub fn create_commitment<T: AsRef<[u8]>>(value: T) -> MockCommitment {
        let scheme = MockCommitmentScheme;
        // Convert to Vec<u8> since the CommitmentScheme's Value type is Vec<u8>
        scheme
            .commit(&[Some(value.as_ref().to_vec())])
            .expect("mock commit failed")
    }

    /// Create a mock proof for a value with position selector
    pub fn create_position_proof<T: AsRef<[u8]>>(
        position: u64,
        value: T,
    ) -> Result<MockProof, CryptoError> {
        let scheme = MockCommitmentScheme;
        // Convert to Vec<u8> since the CommitmentScheme's Value type is Vec<u8>
        scheme.create_proof(&Selector::Position(position), &value.as_ref().to_vec())
    }

    /// Create a mock proof for a value with key selector
    pub fn create_key_proof<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        key: K,
        value: V,
    ) -> Result<MockProof, CryptoError> {
        let scheme = MockCommitmentScheme;
        // Convert to Vec<u8> since the CommitmentScheme's Value type is Vec<u8>
        scheme.create_proof(
            &Selector::Key(key.as_ref().to_vec()),
            &value.as_ref().to_vec(),
        )
    }

    /// Create a verification context for testing
    pub fn create_context(strict: bool) -> ProofContext {
        let mut context = ProofContext::default();
        if strict {
            context.add_data("strict_verify", vec![1]);
        }
        context
    }
}