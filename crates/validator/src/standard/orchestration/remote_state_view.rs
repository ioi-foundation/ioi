// Path: crates/validator/src/standard/orchestration/remote_state_view.rs

use async_trait::async_trait;
use depin_sdk_api::chain::StateView;
use depin_sdk_api::state::Verifier;
use depin_sdk_client::WorkloadClient;
use depin_sdk_types::app::{
    read_validator_sets, AccountId, ActiveKeyRecord, StateAnchor, StateRoot,
};
use depin_sdk_types::codec;
use depin_sdk_types::config::ConsensusType;
use depin_sdk_types::error::{ChainError, StateError};
use depin_sdk_types::keys::VALIDATOR_SET_KEY;
use depin_sdk_types::{MAX_STATE_PROOF_BYTES, MAX_STATE_VALUE_BYTES};
use lru::LruCache;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A read-only view that proxies reads to the workload over IPC and cryptographically
/// verifies the returned proofs against a trusted state root.
pub struct RemoteStateView<V: Verifier> {
    anchor: StateAnchor,
    root: StateRoot,
    client: Arc<WorkloadClient>,
    verifier: V,
    proof_cache: Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>,
}

impl<V: Verifier> RemoteStateView<V> {
    /// Creates a new trustless remote state view.
    pub fn new(
        anchor: StateAnchor,
        root: StateRoot,
        client: Arc<WorkloadClient>,
        verifier: V,
        _consensus: ConsensusType,
        proof_cache: Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>,
    ) -> Self {
        Self {
            anchor,
            root,
            client,
            verifier,
            proof_cache,
        }
    }
}

#[async_trait]
impl<V> StateView for RemoteStateView<V>
where
    V: Verifier + Send + Sync,
    V::Proof: for<'de> Deserialize<'de>,
{
    fn state_anchor(&self) -> &StateAnchor {
        &self.anchor
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

        let proof: V::Proof = bincode::deserialize(&response.proof_bytes)
            .map_err(|e| ChainError::State(StateError::InvalidValue(e.to_string())))?;

        let root_commitment = self
            .verifier
            .commitment_from_bytes(self.root.as_ref())
            .map_err(ChainError::State)?;

        if !self
            .verifier
            .verify(&root_commitment, &proof, key, &response.membership)
        {
            log::error!(
                "CRITICAL: Proof verification failed for remote state read. Root: {}, Key Prefix: {}",
                hex::encode(&self.root.as_ref()[..16]), hex::encode(&key[..key.len().min(16)])
            );
            return Err(ChainError::State(StateError::Validation(
                "Proof verification failed for remote state read".to_string(),
            )));
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

    async fn validator_set_legacy(&self) -> Result<Vec<AccountId>, ChainError> {
        // Legacy behavior: always expose the *current* set at the anchor.
        let raw = self
            .get(VALIDATOR_SET_KEY)
            .await?
            .ok_or_else(|| ChainError::State(StateError::KeyNotFound("ValidatorSet".into())))?;

        let sets = read_validator_sets(&raw).map_err(ChainError::State)?;
        let vs = &sets.current;

        if vs.validators.is_empty() && vs.total_weight > 0 {
            return Err(ChainError::State(StateError::InvalidValue(
                "Validator set invariant failed: empty set with non-zero weight".into(),
            )));
        }
        if vs
            .validators
            .windows(2)
            .any(|w| w[0].account_id >= w[1].account_id)
        {
            return Err(ChainError::State(StateError::InvalidValue(
                "Validator set invariant failed: not sorted by account_id".into(),
            )));
        }

        Ok(vs.validators.iter().map(|v| v.account_id).collect())
    }

    async fn active_consensus_key(&self, acct: &AccountId) -> Option<ActiveKeyRecord> {
        const KEY_PREFIX: &[u8] = b"identity::key_record::";
        let key = [KEY_PREFIX, acct.as_ref()].concat();
        let bytes = self.get(&key).await.ok()??;
        codec::from_bytes_canonical(&bytes).ok()
    }
}