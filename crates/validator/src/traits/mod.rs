// Path: crates/validator/src/traits/mod.rs

use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::error::ValidatorError;
use depin_sdk_core::state::{StateManager, StateTree};
use depin_sdk_core::transaction::TransactionModel;
use std::future::Future;

/// Defines the logic for a workload execution container.
pub trait WorkloadLogic<ST: StateTree + ?Sized> {
    /// Executes a single transaction, validating it and applying it to the state tree.
    fn execute_transaction<CS, TM>(
        &self,
        tx: &TM::Transaction,
        model: &TM,
    ) -> impl Future<Output = Result<(), ValidatorError>> + Send
    where
        CS: CommitmentScheme<
            Commitment = <ST as StateTree>::Commitment,
            Proof = <ST as StateTree>::Proof,
        >,
        // FIX: Add Sync bounds to ensure thread safety for captured references.
        TM: TransactionModel<CommitmentScheme = CS> + Sync,
        TM::Transaction: Sync,
        ST: StateManager;
}