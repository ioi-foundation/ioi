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
use depin_sdk_types::keys::{AUTHORITY_SET_KEY, STAKES_KEY_CURRENT, STAKES_KEY_NEXT};

/// A read-only view that proxies reads to the workload over IPC.
/// NOTE: Like your local StateViewImpl, this currently ignores true root anchoring.
/// It exposes the parent root only for observability; reads return latest.
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
            ConsensusType::ProofOfAuthority => {
                let bytes = self
                    .client
                    .query_raw_state(AUTHORITY_SET_KEY)
                    .await
                    .map_err(|e| ChainError::State(StateError::Backend(e.to_string())))?
                    .ok_or_else(|| {
                        ChainError::State(StateError::KeyNotFound("Authority set not found".into()))
                    })?;
                codec::from_bytes_canonical(&bytes)
                    .map_err(|e| ChainError::State(StateError::InvalidValue(e)))
            }
            ConsensusType::ProofOfStake => {
                // Read NEXT, then fall back to CURRENT (important for genesis)
                let next = self
                    .client
                    .query_raw_state(STAKES_KEY_NEXT)
                    .await
                    .map_err(|e| ChainError::State(StateError::Backend(e.to_string())))?;
                let bytes = match next {
                    Some(b) => b,
                    None => self
                        .client
                        .query_raw_state(STAKES_KEY_CURRENT)
                        .await
                        .map_err(|e| ChainError::State(StateError::Backend(e.to_string())))?
                        .ok_or_else(|| {
                            ChainError::State(StateError::KeyNotFound(
                                "Current stakes not found".into(),
                            ))
                        })?,
                };
                let stakes: BTreeMap<AccountId, u64> = codec::from_bytes_canonical(&bytes)
                    .map_err(|e| ChainError::State(StateError::InvalidValue(e)))?;
                let mut validators: Vec<AccountId> = stakes
                    .into_iter()
                    .filter(|(_, s)| *s > 0)
                    .map(|(a, _)| a)
                    .collect();
                validators.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
                Ok(validators)
            }
        }
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
        self.client
            .query_raw_state(key)
            .await
            .map_err(|e| ChainError::State(StateError::Backend(e.to_string())))
    }

    async fn active_consensus_key(&self, acct: &AccountId) -> Option<ActiveKeyRecord> {
        let key = [b"identity::key_record::", acct.as_ref()].concat();
        self.client
            .query_raw_state(&key)
            .await
            .ok()
            .flatten()
            .and_then(|b| codec::from_bytes_canonical(&b).ok())
    }
}
