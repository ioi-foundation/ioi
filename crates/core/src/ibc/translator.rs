//! Definition of the ProofTranslator trait

use std::any::Any;
use crate::commitment::SchemeIdentifier;
use crate::ibc::UniversalProofFormat;

/// Trait for translating between proof formats
pub trait ProofTranslator: Send + Sync + 'static {
    /// Get the source scheme identifier
    fn source_scheme(&self) -> SchemeIdentifier;
    
    /// Get the target scheme identifier
    fn target_scheme(&self) -> SchemeIdentifier;
    
    /// Convert a proof to the universal format
    fn to_universal(&self, proof: &dyn Any, key: &[u8], value: Option<&[u8]>) -> Option<UniversalProofFormat>;
    
    /// Convert from universal format to target scheme's proof
    fn from_universal(&self, universal: &UniversalProofFormat) -> Option<Box<dyn Any>>;
    
    /// Directly translate between schemes
    fn translate(&self, source_proof: &dyn Any, key: &[u8], value: Option<&[u8]>) -> Option<Box<dyn Any>> {
        let universal = self.to_universal(source_proof, key, value)?;
        self.from_universal(&universal)
    }
}
