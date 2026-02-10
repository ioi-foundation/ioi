// Path: crates/services/src/ibc/core/registry.rs

use crate::ibc::core::context::IbcExecutionContext;
use crate::ibc::light_clients::wasm::WasmLightClient;
use async_trait::async_trait;
use ibc::core::entrypoint::dispatch;
use ibc_core_client_types::Height;
use ibc_core_handler_types::msgs::MsgEnvelope;
use ibc_core_host_types::identifiers::PortId;
use ibc_core_router::{module::Module, router::Router};
use ibc_core_router_types::module::ModuleId;
use ibc_proto::cosmos::tx::v1beta1::TxBody;
use ioi_api::ibc::{LightClient, VerifyCtx};
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::{StateAccess, StateOverlay};
use ioi_api::transaction::context::TxContext;
use ioi_types::error::{CoreError, TransactionError, UpgradeError};
use ioi_types::ibc::{Header, InclusionProof, SubmitHeaderParams, VerifyStateParams};
use ioi_types::keys::UPGRADE_ARTIFACT_PREFIX;
use ioi_types::service_configs::Capabilities;
use ioi_vm_wasm::WasmRuntime;
use parity_scale_codec::Decode;
use prost::Message;
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::mem;
use std::sync::{Arc, RwLock};
use tracing;

use ibc_primitives::Timestamp;

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

/// Generates the storage key for mapping a client type string to its WASM artifact hash.
/// Key Format: `ibc::verifier::{client_type}`
fn verifier_map_key(client_type: &str) -> Vec<u8> {
    [b"ibc::verifier::", client_type.as_bytes()].concat()
}

/// The registry manages the set of supported Light Clients (Verifiers).
/// It supports both "Native" verifiers (hardcoded in Rust) and "Dynamic" verifiers (WASM).
pub struct VerifierRegistry {
    /// Native verifiers available in the binary.
    native_verifiers: HashMap<String, Arc<dyn LightClient>>,
    /// Cache for compiled WASM verifiers to avoid recompilation on every call.
    wasm_cache: RwLock<HashMap<String, Arc<WasmLightClient>>>,
    /// The shared WASM engine used to instantiate dynamic verifiers.
    wasm_runtime: Arc<WasmRuntime>,
}

impl fmt::Debug for VerifierRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifierRegistry")
            .field("native_chains", &self.native_verifiers.keys())
            .field("wasm_cache_size", &self.wasm_cache.read().unwrap().len())
            .finish()
    }
}

impl VerifierRegistry {
    /// Creates a new registry. Requires a WasmRuntime for dynamic loading capabilities.
    pub fn new(wasm_runtime: Arc<WasmRuntime>) -> Self {
        Self {
            native_verifiers: HashMap::new(),
            wasm_cache: RwLock::new(HashMap::new()),
            wasm_runtime,
        }
    }

    /// Registers a native (hardcoded) verifier.
    pub fn register(&mut self, verifier: Arc<dyn LightClient>) {
        let chain_id = verifier.chain_id().to_string();
        log::info!(
            "[VerifierRegistry] Registering native verifier for chain_id: {}",
            chain_id
        );
        self.native_verifiers.insert(chain_id, verifier);
    }

    /// Resolves a LightClient implementation for a specific chain/client type.
    ///
    /// Resolution Order:
    /// 1. Check Native Registry.
    /// 2. Check In-Memory WASM Cache.
    /// 3. Check On-Chain State for a dynamic registration, compile it, cache it, and return it.
    pub async fn resolve(
        &self,
        client_type: &str,
        state: &dyn StateAccess,
    ) -> Result<Arc<dyn LightClient>, CoreError> {
        // 1. Native Check
        if let Some(v) = self.native_verifiers.get(client_type) {
            return Ok(v.clone());
        }

        // 2. Cache Check (Read Lock)
        {
            let cache = self
                .wasm_cache
                .read()
                .map_err(|_| CoreError::Custom("WASM cache lock poisoned".into()))?;
            if let Some(v) = cache.get(client_type) {
                return Ok(v.clone());
            }
        }

        // 3. Dynamic Load from State
        // A. Look up the artifact hash for this client type
        let mapping_key = verifier_map_key(client_type);
        let artifact_hash_bytes = state
            .get(&mapping_key)
            .map_err(CoreError::from)?
            .ok_or_else(|| {
                CoreError::ServiceNotFound(format!(
                    "Verifier type '{}' not found in native registry or on-chain state",
                    client_type
                ))
            })?;

        // B. Look up the WASM blob
        let artifact_key = [UPGRADE_ARTIFACT_PREFIX, &artifact_hash_bytes].concat();
        let wasm_bytes = state
            .get(&artifact_key)
            .map_err(CoreError::from)?
            .ok_or_else(|| {
                CoreError::Custom(format!(
                    "Verifier artifact missing for hash: {}",
                    hex::encode(&artifact_hash_bytes)
                ))
            })?;

        // C. Compile and Instantiate
        tracing::info!(target: "ibc", "Compiling dynamic WASM verifier for type '{}'", client_type);
        // [FIX] Use the public engine() accessor
        let client = WasmLightClient::new(self.wasm_runtime.engine(), &wasm_bytes)?;
        let client_arc = Arc::new(client);

        // D. Update Cache
        {
            let mut cache = self
                .wasm_cache
                .write()
                .map_err(|_| CoreError::Custom("WASM cache lock poisoned".into()))?;
            cache.insert(client_type.to_string(), client_arc.clone());
        }

        Ok(client_arc)
    }

    /// Legacy synchronous get (deprecated, mainly for native-only paths).
    /// Prefer `resolve` which handles dynamic loading.
    pub fn get(&self, chain_id: &str) -> Option<Arc<dyn LightClient>> {
        self.native_verifiers.get(chain_id).cloned()
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

                // [FIX] Convert raw u64 nanoseconds back to ibc_primitives::Timestamp for internal IBC logic
                let host_timestamp = Timestamp::from_nanoseconds(ctx.block_timestamp);

                // 3) Decode TxBody with IBC Any messages
                let tx_body = TxBody::decode(params)
                    .map_err(|e| TransactionError::Invalid(format!("decode TxBody: {e}")))?;
                tracing::info!(target: "ibc", "msg_dispatch@v1: {} message(s)", tx_body.messages.len());

                // 4) Dispatch all messages INSIDE a scope
                let emitted_events: Vec<_> = {
                    let mut exec_ctx =
                        IbcExecutionContext::new(&mut overlay, host_height, host_timestamp);

                    tracing::debug!(
                        target: "ibc",
                        host_height = %exec_ctx.host_height,
                        host_timestamp = %exec_ctx.host_timestamp,
                        "Dispatching IBC messages with context"
                    );

                    let mut router = RouterBox {
                        modules: mem::take(&mut exec_ctx.modules),
                        port_to_module: mem::take(&mut exec_ctx.port_to_module),
                    };

                    for any_msg in tx_body.messages {
                        // Debug logging...
                        if std::env::var("DEPIN_IBC_DEBUG").ok().as_deref() == Some("1") {
                            tracing::debug!(target: "ibc", any_type_url = %any_msg.type_url, "Dispatching IBC Any");
                        }

                        let msg_envelope = MsgEnvelope::try_from(any_msg)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                        if let Err(e) = dispatch(&mut exec_ctx, &mut router, msg_envelope) {
                            tracing::error!(target: "ibc", error = ?e, "IBC dispatch error");
                            return Err(TransactionError::Invalid(format!(
                                "IBC message processing failed: {e:?}"
                            )));
                        }
                    }

                    exec_ctx.modules = router.modules;
                    exec_ctx.port_to_module = router.port_to_module;
                    exec_ctx.events
                };

                // 5) Commit overlay
                let (inserts, deletes): (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>) =
                    overlay.into_ordered_batch();
                for (k, v) in inserts.into_iter() {
                    state.insert(&k, &v)?;
                }
                for k in deletes.into_iter() {
                    state.delete(&k)?;
                }

                // 6) Emit events
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

            // [NEW] Handle ZK Header Submission via Dynamic Resolution
            "submit_header@v1" => {
                let p: SubmitHeaderParams = ioi_types::codec::from_bytes_canonical(params)?;

                // Use resolve() to support dynamic WASM verifiers
                let verifier = self
                    .resolve(&p.chain_id, state)
                    .await
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                // Verify
                let mut verify_ctx = VerifyCtx::default();
                verifier
                    .verify_header(&p.header, &p.finality, &mut verify_ctx)
                    .await
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                // Persist Verified Header
                match p.header {
                    Header::Ethereum(h) => {
                        let key = format!(
                            "ibc::light_clients::{}::state_root::{}",
                            p.chain_id,
                            hex::encode(h.state_root)
                        );
                        let value =
                            ioi_types::codec::to_bytes_canonical(&Header::Ethereum(h.clone()))
                                .map_err(TransactionError::Serialization)?;

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

            // [NEW] Handle Bridgeless State Verification via Dynamic Resolution
            "verify_state@v1" => {
                let p: VerifyStateParams = ioi_types::codec::from_bytes_canonical(params)?;

                // Use resolve() to support dynamic WASM verifiers
                let verifier = self
                    .resolve(&p.chain_id, state)
                    .await
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                // 1. Retrieve trusted root
                let claimed_root_hash = match &p.proof {
                    InclusionProof::Evm { proof_bytes, .. } => {
                        ioi_crypto::algorithms::hash::sha256(proof_bytes)
                            .map_err(|e| TransactionError::Invalid(e.to_string()))?
                    }
                    _ => return Err(TransactionError::Invalid("Unsupported proof type".into())),
                };

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

                // 3. Materialize Data
                let storage_key = format!(
                    "ibc::verified::kv::{}::{}",
                    p.chain_id,
                    hex::encode(&p.path)
                );

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

            // [NEW] Dynamic Verifier Registration (Governance Only)
            "register_verifier@v1" => {
                #[derive(Decode)]
                struct RegisterVerifierParams {
                    client_type: String,
                    artifact: Vec<u8>,
                }
                let p: RegisterVerifierParams = ioi_types::codec::from_bytes_canonical(params)
                    .map_err(TransactionError::Deserialization)?;

                tracing::info!(
                    target: "ibc_registry",
                    "Registering dynamic verifier for client_type='{}' ({} bytes)",
                    p.client_type,
                    p.artifact.len()
                );

                // 1. Hash the artifact
                let artifact_hash = ioi_crypto::algorithms::hash::sha256(&p.artifact)
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                // 2. Store the artifact (if not exists)
                let artifact_key = [UPGRADE_ARTIFACT_PREFIX, &artifact_hash].concat();
                if state.get(&artifact_key)?.is_none() {
                    state.insert(&artifact_key, &p.artifact)?;
                }

                // 3. Map client_type -> artifact_hash
                let map_key = verifier_map_key(&p.client_type);
                state.insert(&map_key, &artifact_hash)?;

                // 4. Invalidate local cache to ensure next resolve() picks up the new logic
                {
                    let mut cache = self
                        .wasm_cache
                        .write()
                        .map_err(|_| TransactionError::Invalid("Lock poisoned".into()))?;
                    cache.remove(&p.client_type);
                }

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
