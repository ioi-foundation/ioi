// Path: crates/validator/src/standard/workload.rs

use crate::traits::WorkloadLogic;
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::error::ValidatorError;
use depin_sdk_core::state::{StateManager, StateTree};
use depin_sdk_core::transaction::TransactionModel;
use depin_sdk_core::validator::WorkloadContainer;

impl<ST> WorkloadLogic<ST> for WorkloadContainer<ST>
where
    // FIX: The bound must be StateManager (which implies StateTree) and Sized.
    ST: StateManager + Send + Sync,
{
    fn execute_transaction<CS, TM>(
        &self,
        tx: &TM::Transaction,
        model: &TM,
    ) -> impl std::future::Future<Output = Result<(), ValidatorError>> + Send
    where
        CS: CommitmentScheme<
            Commitment = <ST as StateTree>::Commitment,
            Proof = <ST as StateTree>::Proof,
        >,
        TM: TransactionModel<CommitmentScheme = CS> + Sync,
        TM::Transaction: Sync,
        // FIX: The bound `ST: StateManager` is now satisfied by the impl block's bounds.
        ST: StateManager,
    {
        async move {
            let state_tree_arc = self.state_tree();
            let mut state = state_tree_arc.lock().await;

            let is_valid = model
                .validate(tx, &*state)
                .map_err(|e| ValidatorError::Other(e.to_string()))?;
            if !is_valid {
                return Err(ValidatorError::Other(
                    "Transaction validation failed".to_string(),
                ));
            }

            model
                .apply(tx, &mut *state)
                .map_err(|e| ValidatorError::Other(e.to_string()))?;

            log::info!("Successfully executed transaction and updated state.");
            Ok(())
        }
    }
}