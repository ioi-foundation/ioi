// Path: crates/api/src/transaction/decorator.rs
//! Defines the trait for transaction pre-processing handlers (Ante Handlers).

use crate::services::BlockchainService;
use crate::state::StateAccessor;
use crate::transaction::context::TxContext;
use async_trait::async_trait;
use ioi_types::app::ChainTransaction;
use ioi_types::error::TransactionError;

/// A trait for services that perform pre-execution validation and state changes.
///
/// Decorators are run in a defined order before the core transaction logic.
/// Examples: fee deduction, signature verification, nonce incrementing.
#[async_trait]
pub trait TxDecorator: BlockchainService {
    /// Validates and processes a transaction before its main logic is executed.
    /// This method can perform read-only checks or mutate state (e.g., deduct fees).
    async fn ante_handle(
        &self,
        state: &mut dyn StateAccessor,
        tx: &ChainTransaction,
        ctx: &TxContext,
    ) -> Result<(), TransactionError>;
}
