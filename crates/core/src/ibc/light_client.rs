//! Definition of the LightClient trait

use crate::ibc::UniversalProofFormat;

/// Light client for IBC verification
pub trait LightClient: Send + Sync + 'static {
    /// Verify a proof in native format
    fn verify_native_proof(
        &self,
        commitment: &[u8],
        proof: &[u8],
        key: &[u8],
        value: &[u8]
    ) -> bool;
    
    /// Verify a proof in universal format
    fn verify_universal_proof(
        &self,
        commitment: &[u8],
        proof: &UniversalProofFormat,
        key: &[u8],
        value: &[u8]
    ) -> bool;
    
    /// Get supported commitment scheme IDs
    fn supported_schemes(&self) -> Vec<String>;
}
