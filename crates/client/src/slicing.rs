// Path: crates/client/src/slicing.rs

use anyhow::{anyhow, Result};
use ioi_crypto::algorithms::hash::sha256;
use ioi_ipc::data::{ContextSlice, EncryptedSlice};
use ioi_ipc::security::{derive_session_key, encrypt_slice};
use rand::RngCore;

/// Configuration for the slicer.
#[derive(Debug, Clone)]
pub struct SlicerConfig {
    /// Maximum size of a single chunk (e.g. 4KB for page alignment).
    pub chunk_size: usize,
    /// Maximum number of chunks per slice.
    pub max_chunks_per_slice: usize,
}

impl Default for SlicerConfig {
    fn default() -> Self {
        Self {
            chunk_size: 4096,
            max_chunks_per_slice: 64, // ~256KB per slice
        }
    }
}

/// A utility to package raw data into encrypted, authenticated slices for the Data Plane.
pub struct SlicePackager {
    config: SlicerConfig,
}

impl SlicePackager {
    pub fn new(config: SlicerConfig) -> Self {
        Self { config }
    }

    /// Processes raw bytes into a list of EncryptedSlice objects.
    ///
    /// # Arguments
    /// * `session_id` - The unique 32-byte ID of the agent session.
    /// * `policy_hash` - The hash of the active firewall policy (binds data to rules).
    /// * `master_secret` - The shared secret (e.g. from mTLS) used to derive the session key.
    /// * `data` - The raw input data (e.g. a document file).
    pub fn package(
        &self,
        session_id: [u8; 32],
        policy_hash: [u8; 32],
        master_secret: &[u8],
        data: &[u8],
    ) -> Result<Vec<EncryptedSlice>> {
        // 1. Derive Session Key (HKDF)
        let session_key = derive_session_key(master_secret, &session_id)?;

        let mut encrypted_slices = Vec::new();

        // 2. Chunk the data
        let chunks: Vec<Vec<u8>> = data
            .chunks(self.config.chunk_size)
            .map(|c| c.to_vec())
            .collect();

        // 3. Group chunks into Slices
        for chunk_batch in chunks.chunks(self.config.max_chunks_per_slice) {
            let batch_vec = chunk_batch.to_vec();

            // Calculate Slice ID: Hash of concatenated chunks
            // This ensures content-addressability for caching/dedup.
            let mut hasher = Vec::new();
            for c in &batch_vec {
                hasher.extend_from_slice(c);
            }
            let slice_digest = sha256(&hasher)?;
            let mut slice_id = [0u8; 32];
            slice_id.copy_from_slice(slice_digest.as_ref());

            // Create Plaintext ContextSlice
            // Note: In Phase 2.4, traversal_proof is None (local only).
            // Phase 3 adds mHNSW proofs here.
            let context_slice = ContextSlice {
                slice_id,
                chunks: batch_vec,
                traversal_proof: None,
                // [FIX] Initialize missing fields with defaults for client-side packaging
                // Client-side packages don't necessarily come from an indexed SCS frame yet
                frame_id: 0,
                mhnsw_root: [0u8; 32],
            };

            // Serialize for Encryption (rkyv or bincode - using rkyv for consistency with DataPlane)
            // Using rkyv's to_bytes which returns AlignedVec
            let plaintext_bytes = rkyv::to_bytes::<_, 1024>(&context_slice)
                .map_err(|e| anyhow!("Serialization failed: {}", e))?;

            // 4. Encrypt with AAD Binding
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce);

            let aad = EncryptedSlice::compute_aad(&session_id, &policy_hash, &slice_id);

            let ciphertext = encrypt_slice(&session_key, &nonce, &plaintext_bytes, &aad)?;

            encrypted_slices.push(EncryptedSlice {
                ciphertext,
                iv: nonce,
                slice_id,
            });
        }

        Ok(encrypted_slices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_ipc::security::decrypt_slice;

    #[test]
    fn test_slice_roundtrip() {
        let packager = SlicePackager::new(SlicerConfig::default());

        let session_id = [1u8; 32];
        let policy_hash = [2u8; 32];
        let master_secret = [3u8; 32];
        let data = b"Hello world! This is a test of the context slicing system.";

        // Encrypt
        let slices = packager
            .package(session_id, policy_hash, &master_secret, data)
            .unwrap();
        assert_eq!(slices.len(), 1);

        let slice = &slices[0];

        // Decrypt
        let key = derive_session_key(&master_secret, &session_id).unwrap();
        let aad = EncryptedSlice::compute_aad(&session_id, &policy_hash, &slice.slice_id);

        let plaintext = decrypt_slice(&key, &slice.iv, &slice.ciphertext, &aad).unwrap();

        // Deserialize
        let archived = rkyv::check_archived_root::<ContextSlice>(&plaintext).unwrap();

        // Verify content
        assert_eq!(archived.chunks.len(), 1);
        // rkyv deserialized chunks access
        let chunk = &archived.chunks[0];
        // chunk is archived vector of u8, convert to slice for comparison
        assert_eq!(chunk.as_slice(), data);
    }
}
