// Path: crates/core/src/chain/mod.rs

use crate::app::{Block, ChainError, ChainStatus};
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
        tx: &TM::Transaction,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError>;

    async fn process_block(
        &mut self,
        block: Block<TM::Transaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError>;

    fn create_block(
        &self,
        transactions: Vec<TM::Transaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Block<TM::Transaction>;

    fn get_block(&self, height: u64) -> Option<&Block<TM::Transaction>>;
}