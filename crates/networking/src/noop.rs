// Path: crates/networking/src/noop.rs
use crate::traits::{BlockSync, MempoolGossip, NodeState, SyncError};
use async_trait::async_trait;
use ioi_types::app::{Block, ChainTransaction};
use libp2p::PeerId;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A no-op implementation of BlockSync for local/offline nodes.
/// This fulfills the trait requirements of the Orchestrator without binding ports.
#[derive(Debug)]
pub struct NoOpBlockSync {
    node_state: Arc<Mutex<NodeState>>,
    known_peers: Arc<Mutex<HashSet<PeerId>>>,
    local_peer_id: PeerId,
}

impl NoOpBlockSync {
    pub fn new() -> Self {
        Self {
            // In local mode, we are always considered "Synced" so the consensus engine starts immediately.
            node_state: Arc::new(Mutex::new(NodeState::Synced)),
            known_peers: Arc::new(Mutex::new(HashSet::new())),
            local_peer_id: PeerId::random(),
        }
    }
}

impl Default for NoOpBlockSync {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BlockSync for NoOpBlockSync {
    async fn start(&self) -> Result<(), SyncError> {
        Ok(())
    }
    async fn stop(&self) -> Result<(), SyncError> {
        Ok(())
    }
    async fn publish_block(&self, _block: &Block<ChainTransaction>) -> Result<(), SyncError> {
        Ok(())
    }
    fn get_node_state(&self) -> Arc<Mutex<NodeState>> {
        self.node_state.clone()
    }
    fn get_local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }
    fn get_known_peers(&self) -> Arc<Mutex<HashSet<PeerId>>> {
        self.known_peers.clone()
    }
}

#[async_trait]
impl MempoolGossip for NoOpBlockSync {
    async fn publish_transaction(&self, _tx: &ChainTransaction) -> Result<(), SyncError> {
        Ok(())
    }
}
