// Path: crates/api/src/lifecycle.rs
//! Defines traits for services that hook into the block processing lifecycle.

use crate::services::access::Service;
use crate::state::StateAccessor;
use crate::transaction::context::TxContext;
use depin_sdk_types::error::StateError;

/// A trait for services that need to perform actions at the end of a block.
pub trait OnEndBlock: Service {
    /// Called after all transactions in a block have been processed.
    fn on_end_block(
        &self,
        state: &mut dyn StateAccessor,
        ctx: &TxContext,
    ) -> Result<(), StateError>;
}