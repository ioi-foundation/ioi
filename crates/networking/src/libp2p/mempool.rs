// Path: crates/network/src/libp2p/mempool.rs

//! The part of the libp2p implementation handling the MempoolGossip trait.

use crate::traits::{MempoolGossip, SyncError};
use async_trait::async_trait;
use ioi_api::transaction::TransactionModel;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::ChainTransaction;

use super::{Libp2pSync, SwarmCommand};

#[async_trait]
impl MempoolGossip for Libp2pSync {
    async fn publish_transaction(&self, tx: &ChainTransaction) -> Result<(), SyncError> {
        // Use a dummy model instance to access the canonical serializer
        let dummy_model =
            UnifiedTransactionModel::new(ioi_state::primitives::hash::HashCommitmentScheme::new());
        let data = dummy_model
            .serialize_transaction(tx)
            .map_err(|e| SyncError::Decode(e.to_string()))?;
        self.swarm_command_sender
            .send(SwarmCommand::PublishTransaction(data))
            .await
            .map_err(|e| SyncError::Network(e.to_string()))
    }
}
