// Path: crates/execution/src/app/view.rs

use super::{ExecutionMachine, PenaltyDelegator};
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, ChainView, RemoteStateView, StateRef};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::PenaltyMechanism;
use ioi_api::state::StateManager;
use ioi_api::validator::WorkloadContainer;
use ioi_types::app::Membership;
use ioi_types::config::ConsensusType;
use ioi_types::error::ChainError;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct ChainStateView<ST: StateManager> {
    state_tree: Arc<RwLock<ST>>,
    height: u64,
    root: Vec<u8>,
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
        // FIX: Removed the unused `use ioi_types::error::StateError;` statement.
        let state = self.state_tree.read().await;
        let key_hex = hex::encode(key);

        let commitment = state.commitment_from_bytes(&self.root)?;
        let (membership, _proof) = state.get_with_proof_at(&commitment, key)?;
        let present = matches!(membership, Membership::Present(_));
        tracing::info!(
            target = "state",
            event = "view_get",
            key = key_hex,
            root = hex::encode(&self.root),
            present,
            mode = "anchored",
        );
        Ok(match membership {
            Membership::Present(bytes) => Some(bytes),
            _ => None,
        })
    }
}

impl<ST: StateManager + Send + Sync + 'static> AnchoredStateView for ChainStateView<ST> {}

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
        let resolved_root_bytes = if state_ref.state_root.is_empty() {
            return Err(ChainError::UnknownStateAnchor(
                "Cannot create view for empty state root".to_string(),
            ));
        } else if self.state.last_state_root == state_ref.state_root {
            Some(self.state.last_state_root.clone())
        } else {
            self.state.recent_blocks.iter().rev().find_map(|b| {
                if b.header.state_root.as_ref() == state_ref.state_root {
                    tracing::info!(target: "state", event = "view_at_resolve", height = b.header.height, root = hex::encode(b.header.state_root.as_ref()));
                    Some(b.header.state_root.0.clone())
                } else {
                    None
                }
            })
        };

        let root = resolved_root_bytes
            .ok_or_else(|| ChainError::UnknownStateAnchor(hex::encode(&state_ref.state_root)))?;

        tracing::info!(target: "state", event = "view_at_resolved", root = hex::encode(&root));

        let view = ChainStateView {
            state_tree: self.workload_container.state_tree(),
            height: state_ref.height,
            root,
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