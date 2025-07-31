// Path: crates/core/src/chain/mod.rs

use crate::app::{Block, ChainError, ChainStatus, ProtocolTransaction};
use crate::commitment::CommitmentScheme;
use crate::state::StateManager;
use crate::transaction::TransactionModel;
use crate::validator::WorkloadContainer;
use async_trait::async_trait;
use std::fmt::Debug;

/// A trait that defines the logic and capabilities of a sovereign chain state machine.
#[async_trait]
pub trait SovereignChain<CS, TM, ST>: Debug + Send
where
    CS: CommitmentScheme,
    TM: TransactionModel<CommitmentScheme = CS>,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    fn status(&self) -> &ChainStatus;
    fn transaction_model(&self) -> &TM;

    async fn process_transaction(
        &mut self,
        tx: &ProtocolTransaction,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError>;

    async fn process_block(
        &mut self,
        block: Block<ProtocolTransaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Result<Block<ProtocolTransaction>, ChainError>;

    /// Creates a new block template to be filled by a block producer.
    ///
    /// # Arguments
    /// * `transactions` - A vector of protocol-level transactions to include in the block.
    /// * `workload` - A reference to the workload container.
    /// * `current_validator_set` - The validator set from the last committed state.
    /// * `known_peers_bytes` - The current set of known validator peer IDs, as bytes,
    ///   used to propose an updated validator set for the new block.
    fn create_block(
        &self,
        transactions: Vec<ProtocolTransaction>,
        workload: &WorkloadContainer<ST>,
        current_validator_set: &Vec<Vec<u8>>,
        known_peers_bytes: &Vec<Vec<u8>>,
    ) -> Block<ProtocolTransaction>;

    fn get_block(&self, height: u64) -> Option<&Block<ProtocolTransaction>>;

    fn get_blocks_since(&self, height: u64) -> Vec<Block<ProtocolTransaction>>;

    /// Retrieves the active validator set from the committed state.
    async fn get_validator_set(&self, workload: &WorkloadContainer<ST>) -> Result<Vec<Vec<u8>>, ChainError>;

    /// Retrieves the active authority set from the committed state for PoA.
    async fn get_authority_set(&self, workload: &WorkloadContainer<ST>) -> Result<Vec<Vec<u8>>, ChainError>;
}