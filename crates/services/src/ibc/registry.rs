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
use ibc_client_tendermint::client_state::ClientState as TmClientState;
use ibc_client_tendermint::types::proto::v1::{
    ClientState as RawTmClientState, ConsensusState as RawTmConsensusState, Header as RawTmHeader,
};
use ibc_client_tendermint::types::Header as TmHeader;
use ibc_core_client_context::client_state::{ClientStateCommon, ClientStateValidation};
use ibc_core_client_context::ClientValidationContext;
use ibc_core_client_types::msgs::MsgUpdateClient;
use ibc_core_client_types::Height as IbcHeight;
use ibc_core_host_types::path::{ClientConsensusStatePath, ClientStatePath};
use ibc_primitives::Timestamp;
use ibc_proto::cosmos::tx::v1beta1::TxBody;
use ibc_proto::{ibc::core::client::v1::Height as RawHeight, Protobuf as _};
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

                        // Expect Tendermint header as client_message
                        let tm_header_any = msg.client_message;
                        if tm_header_any.type_url != "/ibc.lightclients.tendermint.v1.Header" {
                            return Err(TransactionError::Unsupported(
                                "Unsupported IBC client message type".into(),
                            ));
                        }
                        let tm_header = <TmHeader as ibc_proto::Protobuf<RawTmHeader>>::decode_vec(
                            &tm_header_any.value,
                        )
                        .map_err(|e| {
                            TransactionError::Invalid(format!(
                                "Failed to decode Tendermint Header from Any: {}",
                                e
                            ))
                        })?;

                        // 1. Build a validation context aligned with the header being verified.
                        let client_id = msg.client_id.clone();
                        let header_height_u64: u64 = tm_header
                            .signed_header
                            .header
                            .height
                            .try_into()
                            .map_err(|_| {
                                TransactionError::Invalid("header height overflow".into())
                            })?;

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

                        let h2 = u64::try_from(tm_header.signed_header.header.height).unwrap_or(0);
                        tracing::info!(
                            target = "ibc",
                            client = %msg.client_id,
                            h2,
                            "verifying MsgUpdateClient"
                        );

                        // 2. Verify the header using the correctly configured context.
                        let mock_ctx = MockClientCtx {
                            state_accessor: state,
                            client_id: client_id.clone(),
                            current_block_height: header_height_u64.saturating_add(1),
                            host_height_override: Some(host_h),
                            host_timestamp_override: Some(host_ts),
                        };
                        client_state
                            .verify_client_message(&mock_ctx, &msg.client_id, tm_header.clone().into())
                            .map_err(|e| {
                                tracing::error!(target="ibc", client=%msg.client_id, error=%e, "MsgUpdateClient verification failed");
                                TransactionError::Invalid(format!("IBC header verification failed: {e}"))
                            })?;

                        // 3. If verification passes, compute the new states to persist.
                        let new_height = IbcHeight::new(rev, header_height_u64).map_err(|e| {
                            TransactionError::Invalid(format!("invalid Height: {e}"))
                        })?;
                        let consensus_state =
                            ibc_client_tendermint::consensus_state::ConsensusState::from(
                                tm_header.signed_header.header.clone(),
                            );

                        // 4. Build updated client state (set latest_height) with a minimal raw round-trip
                        let raw =
                            <TmClientState as ibc_proto::Protobuf<RawTmClientState>>::encode_vec(
                                client_state,
                            );
                        let mut raw_cs = RawTmClientState::decode(raw.as_slice()).map_err(|e| {
                            TransactionError::Invalid(format!("decode client state: {e}"))
                        })?;
                        raw_cs.latest_height = Some(RawHeight {
                            revision_number: new_height.revision_number(),
                            revision_height: new_height.revision_height(),
                        });
                        let updated_client_state =
                            TmClientState::try_from(raw_cs).map_err(|e| {
                                TransactionError::Invalid(format!("rebuild client state: {e}"))
                            })?;

                        // 5. Persist the new client and consensus states to the state tree.
                        let client_state_path = ClientStatePath::new(msg.client_id.clone());
                        let consensus_state_path = ClientConsensusStatePath::new(
                            msg.client_id,
                            new_height.revision_number(),
                            new_height.revision_height(),
                        );
                        state.insert(
                            client_state_path.to_string().as_bytes(),
                            &<TmClientState as ibc_proto::Protobuf<RawTmClientState>>::encode_vec(
                                updated_client_state,
                            ),
                        )?;
                        state.insert(
                            consensus_state_path.to_string().as_bytes(),
                            &<ibc_client_tendermint::consensus_state::ConsensusState as ibc_proto::Protobuf<RawTmConsensusState>>::encode_vec(consensus_state),
                        )?;

                        tracing::info!(
                            target = "ibc",
                            "[IBC Service] MsgUpdateClient applied: {} -> {}",
                            client_state_path.0,
                            new_height
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
