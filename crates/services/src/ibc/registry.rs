// Path: crates/services/src/ibc/registry.rs

//! Implements the `VerifierRegistry`, a service that manages multiple `InterchainVerifier`
//! instances for different blockchains.

use crate::ibc::channel::ChannelManager; // Import for orchestration
use async_trait::async_trait;
use depin_sdk_api::ibc::InterchainVerifier;
use depin_sdk_api::services::capabilities::IbcPayloadHandler;
use depin_sdk_api::services::{BlockchainService, UpgradableService};
use depin_sdk_api::state::StateAccessor;
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_types::app::SystemPayload;
use depin_sdk_types::error::{TransactionError, UpgradeError};
use depin_sdk_types::service_configs::Capabilities;
use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

/// A service that holds and manages a collection of `InterchainVerifier` instances.
///
/// This registry acts as a dispatcher, allowing the core transaction logic to
/// select the correct light client verifier for a given `chain_id`.
pub struct VerifierRegistry {
    /// A map from a chain's unique string identifier to its verifier implementation.
    verifiers: HashMap<String, Arc<dyn InterchainVerifier>>,
}

impl fmt::Debug for VerifierRegistry {
    /// Custom Debug implementation to avoid printing the entire verifier state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifierRegistry")
            .field("registered_chains", &self.verifiers.keys())
            .finish()
    }
}

impl Default for VerifierRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierRegistry {
    /// Creates a new, empty `VerifierRegistry`.
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
        }
    }

    /// Registers a new `InterchainVerifier`. If a verifier for the same
    /// chain ID already exists, it will be replaced.
    pub fn register(&mut self, verifier: Arc<dyn InterchainVerifier>) {
        let chain_id = verifier.chain_id().to_string();
        log::info!(
            "[VerifierRegistry] Registering verifier for chain_id: {}",
            chain_id
        );
        self.verifiers.insert(chain_id, verifier);
    }

    /// Retrieves a verifier for a specific chain ID.
    pub fn get(&self, chain_id: &str) -> Option<Arc<dyn InterchainVerifier>> {
        self.verifiers.get(chain_id).cloned()
    }

    /// Returns a list of all registered chain IDs.
    pub fn registered_chains(&self) -> Vec<String> {
        self.verifiers.keys().cloned().collect()
    }

    // Placeholder for fetching a trusted header. A real implementation would query
    // its own state to find the latest verified header for the given client.
    fn trusted_header(
        &self,
        _client_id: &str,
        _height: u64,
    ) -> Result<depin_sdk_types::ibc::Header, TransactionError> {
        Ok(depin_sdk_types::ibc::Header::Tendermint(
            depin_sdk_types::ibc::TendermintHeader {
                trusted_height: 0,
                data: vec![],
            },
        ))
    }
}

// --- Service Trait Implementations ---

impl BlockchainService for VerifierRegistry {
    fn id(&self) -> &'static str {
        "ibc_verifier_registry"
    }

    fn abi_version(&self) -> u32 {
        1
    }

    fn state_schema(&self) -> &'static str {
        "v1"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::IBC_HANDLER
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_ibc_handler(&self) -> Option<&dyn IbcPayloadHandler> {
        Some(self)
    }
}

impl UpgradableService for VerifierRegistry {
    fn prepare_upgrade(&mut self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        // The registry itself is stateless; its "state" (the registered verifiers)
        // is configured at genesis or managed by governance transactions that call `register`.
        // Therefore, no state snapshot is needed for an upgrade of the registry logic.
        Ok(Vec::new())
    }

    fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        // Since the snapshot is empty, there is nothing to do to complete the upgrade.
        Ok(())
    }
}

#[async_trait(?Send)]
impl IbcPayloadHandler for VerifierRegistry {
    async fn handle_ibc_payload(
        &self,
        state: &mut dyn StateAccessor,
        payload: &SystemPayload,
        ctx: &mut TxContext,
    ) -> Result<(), TransactionError> {
        match payload {
            SystemPayload::VerifyHeader {
                chain_id,
                header,
                finality,
            } => {
                let mut vctx = depin_sdk_api::ibc::VerifyCtx::default();
                self.get(chain_id)
                    .ok_or_else(|| {
                        TransactionError::Unsupported(format!(
                            "no verifier for chain '{}'",
                            chain_id
                        ))
                    })?
                    .verify_header(header, finality, &mut vctx)
                    .await
                    .map_err(|e| {
                        TransactionError::Invalid(format!("header verification failed: {}", e))
                    })
            }
            SystemPayload::RecvPacket {
                packet,
                proof,
                proof_height,
            } => {
                let mut vctx = depin_sdk_api::ibc::VerifyCtx::default();
                // In a full implementation, the trusted header would be retrieved from the client state.
                let header = self.trusted_header(&packet.source_channel, *proof_height)?;
                self.get(&packet.source_channel)
                    .ok_or_else(|| TransactionError::Unsupported("missing verifier".into()))?
                    .verify_inclusion(proof, &header, &mut vctx)
                    .await
                    .map_err(|e| {
                        TransactionError::Invalid(format!("inclusion proof failed: {}", e))
                    })?;

                let chm = ctx.services.get::<ChannelManager>().ok_or_else(|| {
                    TransactionError::Unsupported("ChannelManager service not installed".into())
                })?;
                chm.recv_packet(state, packet, *proof_height)
                    .map_err(|e| TransactionError::Invalid(e.to_string()))
            }
            _ => Err(TransactionError::Unsupported(
                "Payload not handled by IBC service".into(),
            )),
        }
    }
}
