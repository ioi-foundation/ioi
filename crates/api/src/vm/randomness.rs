// Path: crates/api/src/vm/randomness.rs

use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_types::app::BlockHeader;

/// A seed derived from consensus state that pins the randomness of an inference request.
/// This ensures that if the same request is replayed in the same block context,
/// the "random" sampling (temperature, top_p) yields the exact same token sequence.
#[derive(Debug, Clone, Copy)]
pub struct PinnedSeed(pub [u8; 32]);

impl PinnedSeed {
    /// Derives a seed from the block header and the specific request ID.
    pub fn derive(header: &BlockHeader, request_id: &[u8]) -> Self {
        // Seed = SHA256(Block_Rand_Seed || Request_ID)
        // Note: BlockHeader doesn't have a dedicated VRF seed yet, so we mix
        // resilient fields: ParentHash + Timestamp + OracleCounter.
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&header.parent_hash);
        preimage.extend_from_slice(&header.timestamp.to_be_bytes());
        preimage.extend_from_slice(&header.oracle_counter.to_be_bytes());
        preimage.extend_from_slice(request_id);

        // [FIX] Use dcrypt directly to break cycle
        let digest = Sha256::digest(&preimage)
            .map(|d| {
                let mut arr = [0u8; 32];
                // dcrypt digest returns GenericArray, we can copy from slice
                arr.copy_from_slice(d.as_ref());
                arr
            })
            // Infallible in practice for SHA256
            .unwrap_or([0u8; 32]);

        Self(digest)
    }

    /// Returns the seed as a u64 for standard RNGs.
    pub fn as_u64(&self) -> u64 {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&self.0[0..8]);
        u64::from_le_bytes(arr)
    }
}
