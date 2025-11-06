// Path: crates/validator/src/standard/orchestration/remote_state_view.rs

use async_trait::async_trait;
use ioi_client::WorkloadClient;
use ioi_api::chain::{AnchoredStateView, RemoteStateView};
use ioi_api::state::Verifier;
use ioi_types::app::{StateAnchor, StateRoot};
use ioi_types::codec;
use ioi_types::error::{ChainError, StateError};
use ioi_types::{MAX_STATE_PROOF_BYTES, MAX_STATE_VALUE_BYTES};
use lru::LruCache;
use parity_scale_codec::Decode;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A concrete implementation of an anchored, proof-verifying remote state view.
pub struct DefaultAnchoredStateView<V: Verifier> {
    _anchor: StateAnchor,
    root: StateRoot,
    client: Arc<WorkloadClient>,
    verifier: V,
    proof_cache: Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>,
}

impl<V: Verifier> DefaultAnchoredStateView<V> {
    pub fn new(
        _anchor: StateAnchor,
        root: StateRoot,
        client: Arc<WorkloadClient>,
        verifier: V,
        proof_cache: Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>,
    ) -> Self {
        Self {
            _anchor,
            root,
            client,
            verifier,
            proof_cache,
        }
    }
}

#[async_trait]
impl<V> RemoteStateView for DefaultAnchoredStateView<V>
where
    V: Verifier + Send + Sync,
    V::Proof: Decode,
{
    fn height(&self) -> u64 {
        // Height is part of StateRef, but not directly in the view.
        // A full implementation might pass height in the constructor.
        0
    }

    fn state_root(&self) -> &[u8] {
        self.root.as_ref()
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
        let cache_key = (self.root.as_ref().to_vec(), key.to_vec());
        if let Some(cached_result) = self.proof_cache.lock().await.get(&cache_key) {
            log::trace!("[RemoteView] Proof cache hit for key {}", hex::encode(key));
            return Ok(cached_result.clone());
        }

        let response = self
            .client
            .query_state_at(self.root.clone(), key)
            .await
            .map_err(|e| ChainError::State(StateError::Backend(e.to_string())))?;

        if response.proof_bytes.len() > MAX_STATE_PROOF_BYTES {
            return Err(ChainError::State(StateError::Validation(
                "Proof size exceeds maximum limit".to_string(),
            )));
        }

        let proof: V::Proof = codec::from_bytes_canonical(&response.proof_bytes)
            .map_err(|e| ChainError::State(StateError::InvalidValue(e)))?;

        // FIX: Verify against the raw `self.root`, not the anchor.
        let root_commitment = self
            .verifier
            .commitment_from_bytes(self.root.as_ref())
            .map_err(ChainError::State)?;

        if let Err(e) = self
            .verifier
            .verify(&root_commitment, &proof, key, &response.membership)
        {
            log::error!(
                "CRITICAL: Proof verification failed for remote state read. Root: {}, Key Prefix: {}, Error: {}",
                hex::encode(&self.root.as_ref()), // Log the full raw root
                hex::encode(&key.get(..key.len().min(16)).unwrap_or_default()),
                e
            );
            return Err(ChainError::State(StateError::Validation(format!(
                "Proof verification failed for remote state read: {}",
                e
            ))));
        }

        if let Some(val) = response.membership.clone().into_option() {
            if val.len() > MAX_STATE_VALUE_BYTES {
                return Err(ChainError::State(StateError::Validation(
                    "State value size exceeds maximum limit".to_string(),
                )));
            }
        }

        let result = response.membership.into_option();
        self.proof_cache.lock().await.put(cache_key, result.clone());
        Ok(result)
    }
}

// Mark this implementation as an AnchoredStateView.
impl<V: Verifier + Send + Sync> AnchoredStateView for DefaultAnchoredStateView<V> where
    V::Proof: Decode
{
}
