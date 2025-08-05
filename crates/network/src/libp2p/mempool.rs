// Path: crates/network/src/libp2p/mempool.rs

//! The part of the libp2p implementation handling the MempoolGossip trait.

use crate::traits::{MempoolGossip, SyncError};
use async_trait::async_trait;
use depin_sdk_types::app::ChainTransaction;

use super::{Libp2pSync, SwarmCommand};

#[async_trait]
impl MempoolGossip for Libp2pSync {
    async fn publish_transaction(&self, tx: &ChainTransaction) -> Result<(), SyncError> {
        let data = serde_json::to_vec(tx).map_err(|e| SyncError::Decode(e.to_string()))?;
        self.swarm_command_sender
            .send(SwarmCommand::PublishTransaction(data))
            .await
            .map_err(|e| SyncError::Network(e.to_string()))
    }
}
