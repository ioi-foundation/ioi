// Path: crates/execution/src/app/view.rs

use super::PenaltyDelegator; // Added PenaltyDelegator to imports
use super::{
    load_aft_auxiliary_raw_state_value, resolve_execution_anchor_from_recent_blocks_or_replay_prefix,
    ExecutionMachine,
};
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, ChainView, RemoteStateView, StateRef};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::PenaltyMechanism;
use ioi_api::state::StateManager;
use ioi_api::storage::NodeStore;
use ioi_api::validator::WorkloadContainer;
use ioi_types::app::Membership;
use ioi_types::config::ConsensusType;
use ioi_types::error::ChainError;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct ChainStateView<ST: StateManager> {
    pub(crate) state_tree: Arc<RwLock<ST>>,
    pub(crate) store: Arc<dyn NodeStore>,
    pub(crate) height: u64,
    pub(crate) root: Vec<u8>,
    // Added to support gas_used lookups without scanning blocks
    pub(crate) gas_used: u64,
}

#[async_trait]
impl<ST: StateManager + Send + Sync + 'static> RemoteStateView for ChainStateView<ST> {
    fn height(&self) -> u64 {
        self.height
    }

    fn state_root(&self) -> &[u8] {
        &self.root
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
        let state = self.state_tree.read().await;
        let key_hex = hex::encode(key);

        let commitment = state.commitment_from_bytes(&self.root)?;
        let (membership, _proof) = state.get_with_proof_at(&commitment, key)?;
        let present = matches!(membership, Membership::Present(_));
        let aux_value = if present {
            None
        } else {
            load_aft_auxiliary_raw_state_value(self.store.as_ref(), key)?
        };
        tracing::info!(
            target = "state",
            event = "view_get",
            key = key_hex,
            root = hex::encode(&self.root),
            present = present || aux_value.is_some(),
            mode = "anchored",
        );
        Ok(match membership {
            Membership::Present(bytes) => Some(bytes),
            _ => aux_value,
        })
    }
}

#[async_trait]
impl<ST: StateManager + Send + Sync + 'static> AnchoredStateView for ChainStateView<ST> {
    async fn gas_used(&self) -> Result<u64, ChainError> {
        Ok(self.gas_used)
    }
}

#[async_trait]
impl<CS, ST> ChainView<CS, ST> for ExecutionMachine<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    async fn view_at(
        &self,
        state_ref: &StateRef,
    ) -> Result<Arc<dyn AnchoredStateView>, ChainError> {
        let (resolved_root_bytes, gas_used) =
            resolve_execution_anchor_from_recent_blocks_or_replay_prefix(
                &self.state.recent_blocks,
                &self.state.last_state_root,
                &self.state.recent_aft_recovered_state,
                state_ref.height,
                &state_ref.state_root,
            )
            .ok_or_else(|| {
                ChainError::UnknownStateAnchor(if state_ref.state_root.is_empty() {
                    "Cannot create view for empty state root".to_string()
                } else {
                    hex::encode(&state_ref.state_root)
                })
            })?;

        tracing::info!(
            target: "state",
            event = "view_at_resolved",
            root = hex::encode(&resolved_root_bytes)
        );

        let view = ChainStateView {
            state_tree: self.workload_container.state_tree(),
            store: self.workload_container.store.clone(),
            height: state_ref.height,
            root: resolved_root_bytes,
            gas_used,
        };
        Ok(Arc::new(view))
    }

    fn get_penalty_mechanism(&self) -> Box<dyn PenaltyMechanism + Send + Sync + '_> {
        Box::new(PenaltyDelegator {
            inner: &self.consensus_engine,
        })
    }

    fn consensus_type(&self) -> ConsensusType {
        self.consensus_engine.consensus_type()
    }

    fn workload_container(&self) -> &WorkloadContainer<ST> {
        &self.workload_container
    }
}
