// Path: crates/services/src/ibc/registry.rs

//! Implements the `VerifierRegistry`, a service that manages multiple `InterchainVerifier`
//! instances for different blockchains.

use crate::ibc::channel::ChannelManager; // Import for orchestration
use async_trait::async_trait;
use depin_sdk_api::ibc::InterchainVerifier;
use depin_sdk_api::services::{BlockchainService, UpgradableService};
use depin_sdk_api::state::StateAccessor;
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_types::{
    app::SystemPayload, // Kept for mapping legacy payloads if needed
    codec,
    error::{TransactionError, UpgradeError},
    ibc::{Finality, Header, InclusionProof, Packet},
    service_configs::Capabilities,
};
use parity_scale_codec::Decode;
use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

// --- Service Method Parameter Structs (The Service's Public ABI) ---

#[derive(Decode)]
struct VerifyHeaderParams {
    chain_id: String,
    header: Header,
    finality: Finality,
}

#[derive(Decode)]
struct RecvPacketParams {
    packet: Packet,
    proof: InclusionProof,
    proof_height: u64,
}

/// A service that holds and manages a collection of `InterchainVerifier` instances.
pub struct VerifierRegistry {
    /// A map from a chain's unique string identifier to its verifier implementation.
    verifiers: HashMap<String, Arc<dyn InterchainVerifier>>,
}

impl fmt::Debug for VerifierRegistry {
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

    /// Registers a new `InterchainVerifier`.
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

    // Placeholder for fetching a trusted header.
    fn trusted_header(&self, _client_id: &str, _height: u64) -> Result<Header, TransactionError> {
        Ok(Header::Tendermint(depin_sdk_types::ibc::TendermintHeader {
            trusted_height: 0,
            data: vec![],
        }))
    }
}

// --- Service Trait Implementations ---

#[async_trait]
impl BlockchainService for VerifierRegistry {
    fn id(&self) -> &str {
        "ibc" // The canonical service ID for all IBC operations.
    }

    fn abi_version(&self) -> u32 {
        1
    }

    fn state_schema(&self) -> &str {
        "v1"
    }

    fn capabilities(&self) -> Capabilities {
        // This service does not hook into any lifecycle events like OnEndBlock.
        // Its logic is purely reactive to `CallService` transactions.
        Capabilities::empty()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccessor,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        match method {
            "verify_header@v1" => {
                let p: VerifyHeaderParams = codec::from_bytes_canonical(params)?;
                let mut vctx = depin_sdk_api::ibc::VerifyCtx::default();
                self.get(&p.chain_id)
                    .ok_or_else(|| {
                        TransactionError::Unsupported(format!(
                            "no verifier for chain '{}'",
                            p.chain_id
                        ))
                    })?
                    .verify_header(&p.header, &p.finality, &mut vctx)
                    .await
                    .map_err(|e| {
                        TransactionError::Invalid(format!("header verification failed: {}", e))
                    })
            }
            "recv_packet@v1" => {
                let p: RecvPacketParams = codec::from_bytes_canonical(params)?;
                let mut vctx = depin_sdk_api::ibc::VerifyCtx::default();
                let header = self.trusted_header(&p.packet.source_channel, p.proof_height)?;
                self.get(&p.packet.source_channel)
                    .ok_or_else(|| TransactionError::Unsupported("missing verifier".into()))?
                    .verify_inclusion(&p.proof, &header, &mut vctx)
                    .await
                    .map_err(|e| {
                        TransactionError::Invalid(format!("inclusion proof failed: {}", e))
                    })?;

                let chm = ctx.services.get::<ChannelManager>().ok_or_else(|| {
                    TransactionError::Unsupported("ChannelManager service not installed".into())
                })?;
                chm.recv_packet(state, &p.packet, p.proof_height)
                    .map_err(|e| TransactionError::Invalid(e.to_string()))
            }
            _ => Err(TransactionError::Unsupported(format!(
                "IBC service does not support method '{}'",
                method
            ))),
        }
    }
}

#[async_trait]
impl UpgradableService for VerifierRegistry {
    async fn prepare_upgrade(&mut self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }

    async fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}
