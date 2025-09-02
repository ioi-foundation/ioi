// Path: crates/validator/src/standard/orchestration/remote_state_view.rs

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;

use depin_sdk_api::chain::StateView;
use depin_sdk_client::WorkloadClient;
use depin_sdk_types::app::{AccountId, ActiveKeyRecord};
use depin_sdk_types::codec;
use depin_sdk_types::config::ConsensusType;
use depin_sdk_types::error::{ChainError, StateError};
use depin_sdk_types::keys::{STAKES_KEY_CURRENT, STAKES_KEY_NEXT};

/// A read-only view that proxies reads to the workload over IPC,
/// ensuring all reads are anchored to the specific state root held by this view.
pub struct RemoteStateView {
    root: [u8; 32],
    client: Arc<WorkloadClient>,
    consensus: ConsensusType,
}

impl RemoteStateView {
    pub fn new(root: [u8; 32], client: Arc<WorkloadClient>, consensus: ConsensusType) -> Self {
        Self {
            root,
            client,
            consensus,
        }
    }
}

#[async_trait]
impl StateView for RemoteStateView {
    fn state_root(&self) -> &[u8] {
        &self.root
    }

    async fn validator_set(&self) -> Result<Vec<AccountId>, ChainError> {
        match self.consensus {
            ConsensusType::ProofOfAuthority => self
                .client
                .get_validator_set_at(self.root)
                .await
                .map_err(|e| ChainError::State(StateError::Backend(e.to_string()))),
            ConsensusType::ProofOfStake => {
                // This must match the logic in consensus::proof_of_stake::read_stakes:
                // Read NEXT first, then fall back to CURRENT.
                let bytes_opt =
                    match self.client.query_state_at(self.root, STAKES_KEY_NEXT).await {
                        Ok(Some(bytes)) => Ok(Some(bytes)),
                        Ok(None) => {
                            self.client
                                .query_state_at(self.root, STAKES_KEY_CURRENT)
                                .await
                        } // Fallback
                        Err(e) => Err(e),
                    }
                    .map_err(|e| ChainError::State(StateError::Backend(e.to_string())))?;

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

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
        self.client
            .query_state_at(self.root, key)
            .await
            .map_err(|e| ChainError::State(StateError::Backend(e.to_string())))
    }

    async fn active_consensus_key(&self, acct: &AccountId) -> Option<ActiveKeyRecord> {
        self.client
            .get_active_key_at(self.root, acct)
            .await
            .ok()
            .flatten()
    }
}
