// Path: crates/chain/src/traits.rs

//! This module defines the public traits that describe the core logic of a sovereign chain.

use depin_sdk_core::app::{Block, ChainError, ChainStatus};
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::state::{StateManager, StateTree};
use depin_sdk_core::transaction::TransactionModel;
use depin_sdk_core::validator::WorkloadContainer;

/// A trait that defines the logic and capabilities of a sovereign chain state machine.
// FIX: The `Sized` bound is removed, making this trait object-safe (`dyn`).
pub trait SovereignChain<CS, TM>
where
    CS: CommitmentScheme,
    TM: TransactionModel<CommitmentScheme = CS>,
{
    // FIX: `new` is removed from the trait. Construction is now an inherent method on the impl struct.

    // Accessor methods remain.
    fn status(&self) -> &ChainStatus;
    fn transaction_model(&self) -> &TM;

    fn process_transaction<ST>(
        &mut self,
        tx: &TM::Transaction,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError>
    where
        ST: StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
            + StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
            + Send + Sync + 'static;

    fn process_block<ST>(
        &mut self,
        block: Block<TM::Transaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError>
    where
        ST: StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
            + StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
            + Send + Sync + 'static,
        CS::Commitment: Send + Sync;

    fn create_block<ST>(
        &self,
        transactions: Vec<TM::Transaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Block<TM::Transaction>
    where
        ST: StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
            + StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
            + Send + Sync + 'static,
        CS::Commitment: Send + Sync;
    
    fn get_block(&self, height: u64) -> Option<&Block<TM::Transaction>>;
}