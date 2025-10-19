// Path: crates/api/src/lifecycle/mod.rs
//! Defines traits for services that hook into the block processing lifecycle.

use crate::services::BlockchainService;
use crate::state::StateAccessor;
use crate::transaction::context::TxContext;
use async_trait::async_trait;
use depin_sdk_types::error::StateError;

/// A trait for services that need to perform actions at the end of a block.
#[async_trait]
pub trait OnEndBlock: BlockchainService {
    /// Called after all transactions in a block have been processed.
    async fn on_end_block(
        &self,
        state: &mut dyn StateAccessor,
        ctx: &TxContext,
    ) -> Result<(), StateError>;
}