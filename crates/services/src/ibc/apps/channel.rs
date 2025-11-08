// Path: crates/services/src/ibc/apps/channel.rs

//! Implements the `ChannelManager` service, which serves as a placeholder for
//! an IBC application module (e.g., ICS-20 transfer).
//!
//! In the single-dispatch model, the core IBC state machine logic (handshakes,
//! packet ordering, timeouts) is handled by the generic `dispatch` function in
//! `VerifierRegistry`. This service's role is reduced to being the designated
//! "owner" of one or more IBC ports, a requirement for the ICS-26 routing and
//! handshake protocols to succeed.

use async_trait::async_trait;
use ioi_types::error::UpgradeError;
use ioi_api::impl_service_base;
use ioi_api::services::UpgradableService;

/// A service that acts as an IBC application module placeholder.
///
/// This struct is currently stateless. All channel and packet state is managed
/// directly on the underlying chain state via the `IbcExecutionContext` and
/// is accessed at the canonical ICS-24 paths. Future application-specific
/// logic (like handling ICS-20 `FungibleTokenPacketData`) would be added here.
#[derive(Debug, Default)]
pub struct ChannelManager {}

// Implement the base BlockchainService trait using the helper macro.
// "ibc_channel_manager" is the unique, static ID for this service.
impl_service_base!(ChannelManager, "ibc_channel_manager");

#[async_trait]
impl UpgradableService for ChannelManager {
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        // This service is stateless; all state is in the chain's StateAccessor.
        Ok(Vec::new())
    }

    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

impl ChannelManager {
    /// Creates a new `ChannelManager`.
    pub fn new() -> Self {
        Self {}
    }

    // All previous methods (`send_packet`, `recv_packet`, `acknowledge_packet`)
    // have been removed. This logic is now implicitly handled by the `dispatch`
    // function in `VerifierRegistry` calling into the `ibc-rs` handlers, which
    // use the `IbcExecutionContext` to modify state directly.
}