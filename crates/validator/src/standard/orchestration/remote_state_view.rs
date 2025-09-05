// Path: crates/validator/src/standard/orchestration/remote_state_view.rs

use async_trait::async_trait;
use depin_sdk_api::chain::StateView;
use depin_sdk_api::state::Verifier;
use depin_sdk_client::WorkloadClient;
use depin_sdk_types::app::{AccountId, ActiveKeyRecord, StateAnchor, StateRoot};
use depin_sdk_types::codec;
use depin_sdk_types::config::ConsensusType;
use depin_sdk_types::error::{ChainError, StateError};
use depin_sdk_types::keys::{AUTHORITY_SET_KEY, STAKES_KEY_CURRENT, STAKES_KEY_NEXT};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// A read-only view that proxies reads to the workload over IPC and cryptographically
/// verifies the returned proofs against a trusted state root.
pub struct RemoteStateView<V: Verifier> {
    anchor: StateAnchor,
    root: StateRoot,
    client: Arc<WorkloadClient>,
    verifier: V,
    consensus: ConsensusType,
}

impl<V: Verifier> RemoteStateView<V> {
    /// Creates a new trustless remote state view.
    pub fn new(
        anchor: StateAnchor,
        root: StateRoot,
        client: Arc<WorkloadClient>,
        verifier: V,
        consensus: ConsensusType,
    ) -> Self {
        Self {
            anchor,
            root,
            client,
            verifier,
            consensus,
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
        let response = self
            .client
            .query_state_at(self.root.clone(), key)
            .await
            .map_err(|e| ChainError::State(StateError::Backend(e.to_string())))?;

        // In a production system with multiple schemes, one would assert that
        // response.scheme_id and response.version match the verifier's capabilities.
        // For example: `assert_eq!(response.scheme_id, self.verifier.scheme_id());`

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
            // CRITICAL: Proof verification failed. This could indicate a malicious or
            // faulty Workload container. Reject the state read.
            log::error!(
                "CRITICAL: Proof verification failed for remote state read. Root: {}, Key Prefix: {}",
                hex::encode(&self.root.as_ref()[..16]), hex::encode(&key[..key.len().min(16)])
            );
            return Err(ChainError::State(StateError::Validation(
                "Proof verification failed for remote state read".to_string(),
            )));
        }

        // The proof is valid, we can trust the result.
        Ok(response.membership.into_option())
    }

    async fn validator_set(&self) -> Result<Vec<AccountId>, ChainError> {
        // This method is now trustless because it uses the verified `get` method internally.
        match self.consensus {
            ConsensusType::ProofOfAuthority => {
                let bytes = self.get(AUTHORITY_SET_KEY).await?.ok_or_else(|| {
                    ChainError::State(StateError::KeyNotFound("Authority set".into()))
                })?;
                codec::from_bytes_canonical(&bytes)
                    .map_err(|e| ChainError::State(StateError::InvalidValue(e)))
            }
            ConsensusType::ProofOfStake => {
                // This must match the logic in consensus::proof_of_stake::read_stakes:
                // Read NEXT first, then fall back to CURRENT.
                let bytes_opt = match self.get(STAKES_KEY_NEXT).await {
                    Ok(Some(bytes)) => Ok(Some(bytes)),
                    Ok(None) => self.get(STAKES_KEY_CURRENT).await, // Fallback
                    Err(e) => Err(e),
                }?;

                let bytes = bytes_opt.ok_or_else(|| {
                    ChainError::State(StateError::KeyNotFound(
                        "Current or next stakes not found".into(),
                    ))
                })?;
                let stakes: BTreeMap<AccountId, u64> = codec::from_bytes_canonical(&bytes)
                    .map_err(|e| ChainError::State(StateError::InvalidValue(e)))?;
                let mut vs: Vec<AccountId> = stakes
                    .into_iter()
                    .filter(|(_, s)| *s > 0)
                    .map(|(a, _)| a)
                    .collect();
                vs.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
                Ok(vs)
            }
        }
    }

    async fn active_consensus_key(&self, acct: &AccountId) -> Option<ActiveKeyRecord> {
        const KEY_PREFIX: &[u8] = b"identity::key_record::";
        let key = [KEY_PREFIX, acct.as_ref()].concat();
        let bytes = self.get(&key).await.ok()??;
        codec::from_bytes_canonical(&bytes).ok()
    }
}