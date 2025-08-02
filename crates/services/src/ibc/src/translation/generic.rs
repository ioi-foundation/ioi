//! Generic proof translator implementation

use std::any::Any;
use std::marker::PhantomData;

use crate::conversion::ByteConvertible;
use depin_sdk_api::commitment::{CommitmentScheme, SchemeIdentifier, Selector};
use depin_sdk_api::ibc::{ProofTranslator, UniversalProofFormat};
use std::collections::HashMap;

/// Generic proof translator between two commitment schemes
pub struct GenericProofTranslator<S, T>
where
    S: CommitmentScheme,
    T: CommitmentScheme,
{
    /// Source scheme
    source_scheme: S,
    /// Source scheme ID
    source_id: SchemeIdentifier,
    /// Target scheme
    target_scheme: T,
    /// Target scheme ID
    target_id: SchemeIdentifier,
    /// Phantom marker
    _phantom: PhantomData<(S, T)>,
}

impl<S, T> GenericProofTranslator<S, T>
where
    S: CommitmentScheme,
    T: CommitmentScheme,
{
    /// Create a new generic proof translator
    pub fn new(
        source_scheme: S,
        source_id: SchemeIdentifier,
        target_scheme: T,
        target_id: SchemeIdentifier,
    ) -> Self {
        Self {
            source_scheme,
            source_id,
            target_scheme,
            target_id,
            _phantom: PhantomData,
        }
    }
}

impl<S, T> ProofTranslator for GenericProofTranslator<S, T>
where
    S: CommitmentScheme,
    T: CommitmentScheme,
    T::Value: ByteConvertible,
{
    fn source_scheme(&self) -> SchemeIdentifier {
        self.source_id.clone()
    }

    fn target_scheme(&self) -> SchemeIdentifier {
        self.target_id.clone()
    }

    fn to_universal(
        &self,
        proof: &dyn Any,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Option<UniversalProofFormat> {
        // Try to downcast the proof to source scheme's proof type
        let source_proof = proof.downcast_ref::<S::Proof>()?;

        // Create universal proof format with scheme ID, key, and value
        Some(UniversalProofFormat {
            scheme_id: self.source_id.clone(),
            proof_data: vec![0; 32], // Placeholder - in real code we'd properly serialize
            metadata: HashMap::new(),
            key: key.to_vec(),
            value: value.map(|v| v.to_vec()),
        })
    }

    fn from_universal(&self, universal: &UniversalProofFormat) -> Option<Box<dyn Any>> {
        // Verify scheme ID matches
        if universal.scheme_id != self.source_id {
            log::warn!(
                "Scheme ID mismatch: expected {}, got {}",
                self.source_id.0,
                universal.scheme_id.0
            );
            return None;
        }

        // Convert the value to the target scheme's Value type if it exists
        let value_bytes = universal.value.as_ref()?;
        let target_value = T::Value::from_bytes(value_bytes)?;

        // Create a proof in the target scheme using a key selector
        let selector = if universal.key.is_empty() {
            log::warn!("Empty key in universal proof");
            None
        } else {
            Some(Selector::Key(universal.key.clone()))
        }?;

        // In a real implementation, we would properly deserialize and convert the proof
        match self.target_scheme.create_proof(&selector, &target_value) {
            Ok(target_proof) => Some(Box::new(target_proof)),
            Err(err) => {
                log::error!("Failed to create target proof: {}", err);
                None
            }
        }
    }
}
