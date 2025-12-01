// Path: crates/api/src/transaction/decorator.rs
//! Defines the trait for transaction pre-processing handlers (Ante Handlers).

use crate::services::BlockchainService;
use crate::state::StateAccess;
use crate::transaction::context::TxContext;
use async_trait::async_trait;
use ioi_types::app::ChainTransaction;
use ioi_types::error::TransactionError;

/// A trait for services that perform pre-execution validation and state changes.
///
/// Decorators are run in a defined order before the core transaction logic.
/// The execution is split into two phases to ensure atomicity:
/// 1. `validate_ante`: Read-only checks. If any decorator fails here, execution aborts with no side effects.
/// 2. `write_ante`: State mutations (e.g., fee deduction). Only runs if all validations pass.
#[async_trait]
pub trait TxDecorator: BlockchainService {
    /// Phase 1: Perform read-only validation checks.
    ///
    /// This method MUST NOT modify state. It should check preconditions like
    /// existence, permissions, or balance sufficiency.
    ///
    /// Implementations are passed an immutable reference to `StateAccess`,
    /// which enforces read-only access at the type level (via wrappers like `ReadOnlyNamespacedStateAccess`).
    async fn validate_ante(
        &self,
        state: &dyn StateAccess,
        tx: &ChainTransaction,
        ctx: &TxContext,
    ) -> Result<(), TransactionError>;

    /// Phase 2: Apply state mutations.
    ///
    /// This method is called only after all decorators have successfully passed `validate_ante`.
    /// It typically handles logic like fee deduction or nonce incrementing.
    ///
    /// The default implementation does nothing, which is suitable for decorators
    /// that perform pure validation without side effects.
    async fn write_ante(
        &self,
        state: &mut dyn StateAccess,
        tx: &ChainTransaction,
        ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        // Mark parameters as used to satisfy compiler warnings in default impl
        let _ = (state, tx, ctx);
        Ok(())
    }
}