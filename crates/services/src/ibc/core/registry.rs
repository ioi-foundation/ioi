// Path: crates/services/src/ibc/core/registry.rs

use crate::ibc::core::context::IbcExecutionContext;
use async_trait::async_trait;
use ibc::core::entrypoint::dispatch;
use ibc_core_client_types::msgs::MsgUpdateClient; // For optional decode preview
use ibc_core_client_types::Height;
use ibc_core_handler_types::msgs::MsgEnvelope;
use ibc_core_host_types::identifiers::PortId;
use ibc_core_router::{module::Module, router::Router};
use ibc_core_router_types::module::ModuleId;
use ibc_proto::cosmos::tx::v1beta1::TxBody;
use ibc_proto::Protobuf;
use ioi_api::ibc::{LightClient, VerifyCtx};
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::{StateAccess, StateOverlay};
use ioi_api::transaction::context::TxContext;
use ioi_types::error::{TransactionError, UpgradeError};
use ioi_types::ibc::{Header, InclusionProof, SubmitHeaderParams, VerifyStateParams};
use ioi_types::service_configs::Capabilities;
use prost::Message;
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::mem;
use std::sync::Arc;
use tracing;

struct RouterBox {
    modules: BTreeMap<ModuleId, Box<dyn Module>>,
    port_to_module: BTreeMap<PortId, ModuleId>,
}
impl Router for RouterBox {
    fn get_route(&self, id: &ModuleId) -> Option<&dyn Module> {
        self.modules.get(id).map(|m| m.as_ref())
    }
    fn get_route_mut(&mut self, id: &ModuleId) -> Option<&mut (dyn Module + '_)> {
        if let Some(b) = self.modules.get_mut(id) {
            Some(&mut **b)
        } else {
            None
        }
    }
    fn lookup_module(&self, port_id: &PortId) -> Option<ModuleId> {
        self.port_to_module.get(port_id).cloned()
    }
}

pub struct VerifierRegistry {
    verifiers: HashMap<String, Arc<dyn LightClient>>,
}

impl fmt::Debug for VerifierRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
        }
    }

    pub fn register(&mut self, verifier: Arc<dyn LightClient>) {
        let chain_id = verifier.chain_id().to_string();
        log::info!(
            "[VerifierRegistry] Registering verifier for chain_id: {}",
            chain_id
        );
        self.verifiers.insert(chain_id, verifier);
    }

    pub fn get(&self, chain_id: &str) -> Option<Arc<dyn LightClient>> {
        self.verifiers.get(chain_id).cloned()
    }
}

#[async_trait]
impl BlockchainService for VerifierRegistry {
    fn id(&self) -> &str {
        "ibc"
    }

    fn abi_version(&self) -> u32 {
        1
    }

    fn state_schema(&self) -> &str {
        "v1"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::empty()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        match method {
            "msg_dispatch@v1" => {
                // 1) Build an overlay bound to `state`
                let mut overlay = StateOverlay::new(state);

                // 2) Host metadata
                let host_height = Height::new(0, ctx.block_height)
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                let host_timestamp = ctx.block_timestamp;

                // 3) Decode TxBody with IBC Any messages
                let tx_body = TxBody::decode(params)
                    .map_err(|e| TransactionError::Invalid(format!("decode TxBody: {e}")))?;
                tracing::info!(target: "ibc", "msg_dispatch@v1: {} message(s)", tx_body.messages.len());

                // 4) Dispatch all messages INSIDE a scope so `exec_ctx` (which borrows `overlay`)
                //    is dropped BEFORE we commit the overlay.
                let emitted_events: Vec<_> = {
                    // context tied to overlay
                    let mut exec_ctx =
                        IbcExecutionContext::new(&mut overlay, host_height, host_timestamp);

                    // New diagnostic logging
                    tracing::debug!(
                        target: "ibc",
                        host_height = %exec_ctx.host_height,
                        host_timestamp = %exec_ctx.host_timestamp,
                        "Dispatching IBC messages with context"
                    );

                    // router that *owns* the module maps during dispatch
                    let mut router = RouterBox {
                        modules: mem::take(&mut exec_ctx.modules),
                        port_to_module: mem::take(&mut exec_ctx.port_to_module),
                    };

                    for any_msg in tx_body.messages {
                        // Optional peek to include richer context in logs (no behavioral change):
                        if std::env::var("DEPIN_IBC_DEBUG").ok().as_deref() == Some("1") {
                            tracing::debug!(target: "ibc",
                                any_type_url = %any_msg.type_url,
                                any_len = any_msg.value.len(),
                                "Dispatching IBC Any message");
                            if any_msg.type_url == "/ibc.core.client.v1.MsgUpdateClient" {
                                if let Ok(msg) = MsgUpdateClient::decode(&*any_msg.value) {
                                    tracing::debug!(target: "ibc",
                                        client_id = %msg.client_id,
                                        cm_type_url = %msg.client_message.type_url,
                                        cm_len = msg.client_message.value.len(),
                                        "UpdateClient payload preview");
                                }
                            }
                        }

                        let msg_envelope = MsgEnvelope::try_from(any_msg)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                        if let Err(e) = dispatch(&mut exec_ctx, &mut router, msg_envelope) {
                            // Surface the real cause instead of a generic wrapper:
                            tracing::error!(target: "ibc", error = ?e, "IBC dispatch error");
                            return Err(TransactionError::Invalid(format!(
                                "IBC message processing failed: {e:?}"
                            )));
                        }
                    }

                    // (optional) move maps back
                    exec_ctx.modules = router.modules;
                    exec_ctx.port_to_module = router.port_to_module;

                    // move out events; drop exec_ctx before overlay commit
                    exec_ctx.events
                };

                // 5) Now it is safe to consume the overlay and mutate `state`.
                let (inserts, deletes): (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>) =
                    overlay.into_ordered_batch();
                for (k, v) in inserts.into_iter() {
                    if std::env::var("DEPIN_IBC_DEBUG").ok().as_deref() == Some("1") {
                        tracing::debug!(target: "ibc.state", op="insert", path=%String::from_utf8_lossy(&k), bytes=v.len());
                    }
                    state.insert(&k, &v)?;
                }
                for k in deletes.into_iter() {
                    if std::env::var("DEPIN_IBC_DEBUG").ok().as_deref() == Some("1") {
                        tracing::debug!(target: "ibc.state", op="delete", path=%String::from_utf8_lossy(&k));
                    }
                    state.delete(&k)?;
                }

                // 6) Emit IBC events
                if !emitted_events.is_empty() {
                    tracing::info!(
                        target: "ibc",
                        "Dispatch produced {} IBC events",
                        emitted_events.len()
                    );
                    for event in emitted_events {
                        tracing::info!(target: "ibc_event", event = ?event);
                    }
                }

                Ok(())
            }

            // [NEW] Handle ZK Header Submission
            "submit_header@v1" => {
                let p: SubmitHeaderParams = ioi_types::codec::from_bytes_canonical(params)?;

                let verifier = self.verifiers.get(&p.chain_id).ok_or_else(|| {
                    TransactionError::Invalid(format!(
                        "No verifier registered for chain {}",
                        p.chain_id
                    ))
                })?;

                // Verify
                let mut verify_ctx = VerifyCtx::default();
                verifier
                    .verify_header(&p.header, &p.finality, &mut verify_ctx)
                    .await
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                // Persist Verified Header
                match p.header {
                    Header::Ethereum(h) => {
                        // Key: ibc::light_clients::{chain_id}::state_root::{state_root_hex}
                        let key = format!(
                            "ibc::light_clients::{}::state_root::{}",
                            p.chain_id,
                            hex::encode(h.state_root)
                        );

                        // We store the serialized header as proof of verification.
                        // Clone `h` here because we need to use `h.state_root` for logging later.
                        let value =
                            ioi_types::codec::to_bytes_canonical(&Header::Ethereum(h.clone()))
                                .map_err(TransactionError::Serialization)?;

                        // FIX: Use insert, not set
                        state.insert(key.as_bytes(), &value)?;
                        tracing::info!(
                            target: "ibc_zk",
                            event = "HeaderVerified",
                            chain_id = %p.chain_id,
                            root = %hex::encode(h.state_root)
                        );
                    }
                    _ => {
                        return Err(TransactionError::Invalid(
                            "Unsupported header type for ZK submission".into(),
                        ))
                    }
                }
                Ok(())
            }

            // [NEW] Handle Bridgeless State Verification
            "verify_state@v1" => {
                let p: VerifyStateParams = ioi_types::codec::from_bytes_canonical(params)?;

                let verifier = self.verifiers.get(&p.chain_id).ok_or_else(|| {
                    TransactionError::Invalid(format!(
                        "No verifier registered for chain {}",
                        p.chain_id
                    ))
                })?;

                // 1. Retrieve trusted root from state
                // For the E2E simulation using SimulatedGroth16, hash(proof) == root.
                // We use this property to find which root the user is claiming to prove against.
                let claimed_root_hash = match &p.proof {
                    InclusionProof::Evm { proof_bytes, .. } => {
                        // Use ioi_crypto::algorithms::hash::sha256 for consistency
                        ioi_crypto::algorithms::hash::sha256(proof_bytes).map_err(
                            |e: ioi_api::error::CryptoError| {
                                TransactionError::Invalid(e.to_string())
                            },
                        )?
                    }
                    _ => return Err(TransactionError::Invalid("Unsupported proof type".into())),
                };

                // Convert Digest to [u8; 32] explicitly
                let claimed_root: [u8; 32] = claimed_root_hash
                    .try_into()
                    .map_err(|_| TransactionError::Invalid("Proof hash length invalid".into()))?;

                let root_key = format!(
                    "ibc::light_clients::{}::state_root::{}",
                    p.chain_id,
                    hex::encode(claimed_root)
                );

                let stored_header_bytes =
                    state
                        .get(root_key.as_bytes())?
                        .ok_or(TransactionError::Invalid(
                            "Untrusted or unknown state root".into(),
                        ))?;

                let trusted_header: Header =
                    ioi_types::codec::from_bytes_canonical(&stored_header_bytes)
                        .map_err(TransactionError::Deserialization)?;

                // 2. Verify Inclusion
                let mut verify_ctx = VerifyCtx::default();
                verifier
                    .verify_inclusion(&p.proof, &trusted_header, &mut verify_ctx)
                    .await
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                // 3. Materialize Data (Bridgeless Oracle)
                // Key: ibc::verified::kv::{chain_id}::{path_hex}
                let storage_key = format!(
                    "ibc::verified::kv::{}::{}",
                    p.chain_id,
                    hex::encode(&p.path)
                );

                // FIX: Use insert, not set
                state.insert(storage_key.as_bytes(), &p.value)?;
                tracing::info!(
                    target: "ibc_zk",
                    event = "StateMaterialized",
                    chain_id = %p.chain_id,
                    path = %hex::encode(&p.path),
                    value_len = p.value.len()
                );

                Ok(())
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
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }

    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}
