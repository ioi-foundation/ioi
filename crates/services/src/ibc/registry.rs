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
    codec,
    error::{StateError, TransactionError, UpgradeError},
    ibc::{Finality, Header, InclusionProof, Packet},
    service_configs::Capabilities,
};
use parity_scale_codec::Decode;
use std::any::Any;
// --- Additional Imports for msg_dispatch@v1 ---
use crate::ibc::light_client::tendermint::MockClientCtx;
use ibc_client_tendermint::types::proto::v1::{
    ClientState as RawTmClientState, ConsensusState as RawTmConsensusState, Header as RawTmHeader,
};
use ibc_client_tendermint::{
    client_state::ClientState as TmClientState,
    consensus_state::ConsensusState as TmConsensusState, types::Header as TmHeader,
};
// --- FIX START: Add all required trait imports ---
use ibc_core_client_context::client_state::{
    ClientStateCommon, ClientStateExecution, ClientStateValidation,
};
use ibc_core_client_context::{ClientExecutionContext, ClientValidationContext};
// --- FIX END ---
use ibc_core_client_types::error::ClientError as IbcClientError;
use ibc_core_client_types::msgs::MsgUpdateClient;
use ibc_core_client_types::Height as IbcHeight;
use ibc_core_handler_types::error::ContextError;
use ibc_core_host_types::{
    identifiers::ClientId,
    path::{ClientConsensusStatePath, ClientStatePath},
};
use ibc_primitives::Timestamp;
use ibc_proto::cosmos::tx::v1beta1::TxBody;
use ibc_proto::Protobuf as _;
use prost::Message; // Import the Message trait for .decode()

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use tracing; // Added to resolve the compilation error

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

// --- NEW: Context struct for the state-mutating `update_state` call ---
struct HostClientExecutionContext<'a> {
    state_accessor: &'a mut dyn StateAccessor,
    client_id: ClientId,
    host_height: IbcHeight,
    host_timestamp: Timestamp,
}

impl<'a> ibc_core_client_context::ExtClientValidationContext for HostClientExecutionContext<'a> {
    fn host_timestamp(&self) -> Result<Timestamp, ContextError> {
        Ok(self.host_timestamp)
    }
    fn host_height(&self) -> Result<IbcHeight, ContextError> {
        Ok(self.host_height)
    }
    fn consensus_state_heights(
        &self,
        _client_id: &ClientId,
    ) -> Result<Vec<IbcHeight>, ContextError> {
        // We don't need this for simple updates; return empty so callers short-circuit.
        Ok(Vec::new())
    }
    fn next_consensus_state(
        &self,
        _client_id: &ClientId,
        _height: &IbcHeight,
    ) -> Result<Option<Self::ConsensusStateRef>, ContextError> {
        Ok(None)
    }
    fn prev_consensus_state(
        &self,
        _client_id: &ClientId,
        _height: &IbcHeight,
    ) -> Result<Option<Self::ConsensusStateRef>, ContextError> {
        Ok(None)
    }
}

impl<'a> ClientValidationContext for HostClientExecutionContext<'a> {
    type ClientStateRef = TmClientState;
    type ConsensusStateRef = TmConsensusState;

    fn client_state(&self, _client_id: &ClientId) -> Result<Self::ClientStateRef, ContextError> {
        let path = ClientStatePath::new(self.client_id.clone());
        let bytes = self
            .state_accessor
            .get(path.to_string().as_bytes())
            .map_err(|e| IbcClientError::Other {
                description: e.to_string(),
            })?
            .ok_or_else(|| IbcClientError::Other {
                description: "Client state not found".to_string(),
            })?;
        TmClientState::try_from(RawTmClientState::decode(&*bytes).map_err(|e| {
            IbcClientError::Other {
                description: e.to_string(),
            }
        })?)
        .map_err(|e| {
            IbcClientError::ClientSpecific {
                description: e.to_string(),
            }
            .into()
        })
    }

    fn consensus_state(
        &self,
        path: &ClientConsensusStatePath,
    ) -> Result<Self::ConsensusStateRef, ContextError> {
        let bytes = self
            .state_accessor
            .get(path.to_string().as_bytes())
            .map_err(|e| IbcClientError::Other {
                description: e.to_string(),
            })?
            .ok_or_else(|| IbcClientError::Other {
                description: "Consensus state not found".to_string(),
            })?;
        TmConsensusState::try_from(RawTmConsensusState::decode(&*bytes).map_err(|e| {
            IbcClientError::Other {
                description: e.to_string(),
            }
        })?)
        .map_err(|e| {
            IbcClientError::ClientSpecific {
                description: e.to_string(),
            }
            .into()
        })
    }

    fn client_update_meta(
        &self,
        client_id: &ClientId,
        height: &IbcHeight,
    ) -> Result<(Timestamp, IbcHeight), ContextError> {
        Err(ContextError::ClientError(
            IbcClientError::UpdateMetaDataNotFound {
                client_id: client_id.clone(),
                height: *height,
            },
        ))
    }
}

// --- FIX: Add the missing `where` clause to the impl block ---
impl<'a> ClientExecutionContext for HostClientExecutionContext<'a>
where
    <Self as ClientValidationContext>::ClientStateRef: From<TmClientState>,
{
    type ClientStateMut = <Self as ClientValidationContext>::ClientStateRef;

    fn store_client_state(
        &mut self,
        path: ClientStatePath,
        client_state: Self::ClientStateMut,
    ) -> Result<(), ContextError> {
        let bytes = <TmClientState as ibc_proto::Protobuf<RawTmClientState>>::encode_vec(
            client_state.into(),
        );
        self.state_accessor
            .insert(path.to_string().as_bytes(), &bytes)
            .map_err(|e| {
                IbcClientError::Other {
                    description: e.to_string(),
                }
                .into()
            })
    }

    fn store_consensus_state(
        &mut self,
        path: ClientConsensusStatePath,
        consensus_state: Self::ConsensusStateRef,
    ) -> Result<(), ContextError> {
        let bytes = <TmConsensusState as ibc_proto::Protobuf<RawTmConsensusState>>::encode_vec(
            consensus_state,
        );
        self.state_accessor
            .insert(path.to_string().as_bytes(), &bytes)
            .map_err(|e| {
                IbcClientError::Other {
                    description: e.to_string(),
                }
                .into()
            })
    }

    fn delete_consensus_state(
        &mut self,
        path: ClientConsensusStatePath,
    ) -> Result<(), ContextError> {
        self.state_accessor
            .delete(path.to_string().as_bytes())
            .map_err(|e| {
                IbcClientError::Other {
                    description: e.to_string(),
                }
                .into()
            })
    }
    fn store_update_meta(
        &mut self,
        _client_id: ClientId,
        _height: IbcHeight,
        _host_timestamp: Timestamp,
        _host_height: IbcHeight,
    ) -> Result<(), ContextError> {
        // No-op: for now we don't persist update metadata. This is sufficient to
        // allow updates to proceed and prevents a panic.
        Ok(())
    }
    fn delete_update_meta(
        &mut self,
        _client_id: ClientId,
        _height: IbcHeight,
    ) -> Result<(), ContextError> {
        // No-op until we add pruning of update metadata.
        Ok(())
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
            "msg_dispatch@v1" => {
                let tx_body = TxBody::decode(params).map_err(|e| {
                    // The gateway serializes the TxBody, so we decode it here.
                    TransactionError::Invalid(format!("Failed to decode TxBody: {}", e))
                })?;

                tracing::info!(
                    target = "ibc",
                    "msg_dispatch@v1: decoding TxBody with {} message(s)",
                    tx_body.messages.len()
                );
                for any_msg in tx_body.messages {
                    if any_msg.type_url == "/ibc.core.client.v1.MsgUpdateClient" {
                        let msg = MsgUpdateClient::decode_vec(&any_msg.value).map_err(|e| {
                            TransactionError::Invalid(format!(
                                "Failed to decode MsgUpdateClient: {}",
                                e
                            ))
                        })?;

                        // 1. Fetch current client state
                        let client_id = msg.client_id.clone();
                        let client_state: TmClientState = MockClientCtx {
                            state_accessor: state,
                            client_id: client_id.clone(),
                            current_block_height: ctx.block_height,
                            host_height_override: None,
                            host_timestamp_override: None,
                        }
                        .client_state(&client_id)
                        .map_err(|e| {
                            TransactionError::State(StateError::Validation(e.to_string()))
                        })?;

                        // 2. Decode the header and build the validation context (for host height/ts only)
                        let tm_header = <TmHeader as ibc_proto::Protobuf<RawTmHeader>>::decode_vec(
                            &msg.client_message.value,
                        )
                        .map_err(|e| {
                            TransactionError::Invalid(format!(
                                "Failed to decode Tendermint Header from Any: {}",
                                e
                            ))
                        })?;

                        let header_height_u64: u64 = tm_header
                            .signed_header
                            .header
                            .height
                            .try_into()
                            .map_err(|_| {
                                TransactionError::Invalid("header height overflow".into())
                            })?;

                        let rev = client_state.latest_height().revision_number();
                        let host_h = IbcHeight::new(rev, header_height_u64.saturating_add(1))
                            .map_err(|e| {
                                TransactionError::Invalid(format!("invalid Height: {e}"))
                            })?;
                        let hdr_secs = u64::try_from(
                            tendermint_proto::google::protobuf::Timestamp::from(
                                tm_header.signed_header.header.time,
                            )
                            .seconds,
                        )
                        .unwrap_or(0);
                        let host_ts = Timestamp::from_nanoseconds(
                            hdr_secs.saturating_add(1).saturating_mul(1_000_000_000),
                        )
                        .map_err(|e| TransactionError::Invalid(format!("timestamp build: {e}")))?;

                        let mock_ctx = MockClientCtx {
                            state_accessor: state,
                            client_id: client_id.clone(),
                            current_block_height: header_height_u64.saturating_add(1),
                            host_height_override: Some(host_h),
                            host_timestamp_override: Some(host_ts),
                        };

                        // 3. Step 1: Perform read-only verification using the DOMAIN message.
                        client_state
                            .verify_client_message(&mock_ctx, &client_id, tm_header.clone().into())
                            .map_err(|e| {
                                tracing::error!(target="ibc", client=%msg.client_id, error=%e, "MsgUpdateClient verification failed");
                                TransactionError::Invalid(format!("IBC header verification failed: {e}"))
                            })?;

                        // 4. Step 2: If verification passes, perform the stateful update
                        let mut exec_ctx = HostClientExecutionContext {
                            state_accessor: state,
                            client_id: client_id.clone(),
                            host_height: host_h,
                            host_timestamp: host_ts,
                        };

                        client_state
                            .update_state(&mut exec_ctx, &client_id, tm_header.into())
                            .map_err(|e| {
                                // Extra visibility if state update is rejected by ibc-rs
                                tracing::error!(target="ibc", client=%msg.client_id, error=%e, "MsgUpdateClient update_state failed");
                                TransactionError::Invalid(format!("IBC state update failed: {e}"))
                            })?;

                        tracing::info!(
                            target = "ibc",
                            "[IBC Service] MsgUpdateClient applied for client {}",
                            client_id
                        );
                    }
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
    async fn prepare_upgrade(&mut self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }

    async fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}
