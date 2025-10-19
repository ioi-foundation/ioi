// Path: crates/api/src/services/capabilities.rs
use crate::state::StateAccessor;
use crate::transaction::context::TxContext;
use depin_sdk_types::app::SystemPayload;
use depin_sdk_types::error::TransactionError;
use async_trait::async_trait;

#[async_trait(?Send)]
pub trait IbcPayloadHandler: Send + Sync {
    async fn handle_ibc_payload(
        &self,
        state: &mut dyn StateAccessor,
        payload: &SystemPayload,
        ctx: &mut TxContext, // Mutable for service-specific caching or resource pinning
    ) -> Result<(), TransactionError>;
}

pub trait ServiceCapabilities {
    fn as_ibc_handler(&self) -> Option<&dyn IbcPayloadHandler> {
        None
    }
    // Future capabilities (e.g., as_on_end_block) will be added here.
}