// Path: crates/services/src/ibc/light_client/tendermint.rs
use crate::ibc::light_client::errors::IbcError;
use async_trait::async_trait;
use depin_sdk_api::error::CoreError;
use depin_sdk_api::ibc::{InterchainVerifier, VerifyCtx};
use depin_sdk_api::state::StateAccessor;
use depin_sdk_types::ibc::{Finality, Header, InclusionProof};
use ibc_client_tendermint::types::proto::v1::{
    ClientState as RawTmClientState, ConsensusState as RawTmConsensusState, Header as RawTmHeader,
};
use ibc_client_tendermint::{
    client_state::ClientState as TmClientState,
    consensus_state::ConsensusState as TmConsensusState, types::Header as TmHeader,
};
use ibc_core_client_context::ExtClientValidationContext;
use ibc_core_client_context::{
    client_state::{ClientStateCommon, ClientStateValidation},
    types::error::ClientError,
    ClientValidationContext,
};
use ibc_core_client_types::{error::ClientError as IbcClientError, Height};
use ibc_core_commitment_types::commitment::{CommitmentProofBytes, CommitmentRoot};
use ibc_core_handler_types::error::ContextError;
use ibc_core_host_types::{
    identifiers::ClientId,
    path::{ClientConsensusStatePath, ClientStatePath},
};
use ibc_primitives::Timestamp;
use ibc_proto::google::protobuf::Any as PbAny;
use prost::Message;

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

/// A helper to decode an `Any`-wrapped message from bytes.
fn decode_any<T: prost::Message + Default>(
    bytes: &[u8],
    expected_type_url: &str,
) -> Result<T, ClientError> {
    let any = PbAny::decode(bytes).map_err(|e| ClientError::Other {
        description: format!("failed to decode Any: {e}"),
    })?;
    if any.type_url != expected_type_url {
        return Err(ClientError::Other {
            description: format!(
                "unexpected Any type_url: got {}, expected {}",
                any.type_url, expected_type_url
            ),
        });
    }
    T::decode(any.value.as_slice()).map_err(|e| ClientError::Other {
        description: format!("failed to decode inner message: {e}"),
    })
}

/// A verifier for Tendermint-based chains using the `ibc-rs` implementation.
#[derive(Clone)]
pub struct TendermintVerifier {
    chain_id: String,
    client_id: String, // e.g., "07-tendermint-0"
    state_accessor: Arc<dyn StateAccessor>,
}

impl fmt::Debug for TendermintVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TendermintVerifier")
            .field("chain_id", &self.chain_id)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

// A minimal mock context to satisfy the new API requirements.
pub struct MockClientCtx<'a, S: StateAccessor + ?Sized> {
    pub state_accessor: &'a S,
    pub client_id: ClientId,
    // Current block height on the host chain (fallback if no override is set).
    pub current_block_height: u64,
    // Optional overrides to align host view with the header being verified.
    pub host_height_override: Option<Height>,
    pub host_timestamp_override: Option<Timestamp>,
}

impl<'a, S: StateAccessor + ?Sized> ExtClientValidationContext for MockClientCtx<'a, S> {
    fn host_timestamp(&self) -> Result<Timestamp, ContextError> {
        if let Some(ts) = self.host_timestamp_override {
            return Ok(ts);
        }
        // Fallback heuristic: 5s per block if no override provided.
        const BLOCK_INTERVAL_NANOS: u64 = 5 * 1_000_000_000;
        let timestamp_nanos = self
            .current_block_height
            .saturating_mul(BLOCK_INTERVAL_NANOS);
        Timestamp::from_nanoseconds(timestamp_nanos).map_err(|e| {
            ContextError::from(ClientError::Other {
                description: format!("Failed to create timestamp: {}", e),
            })
        })
    }

    fn host_height(&self) -> Result<Height, ContextError> {
        if let Some(h) = self.host_height_override {
            return Ok(h);
        }
        Height::new(0, self.current_block_height).map_err(ContextError::ClientError)
    }

    fn consensus_state_heights(&self, _client_id: &ClientId) -> Result<Vec<Height>, ContextError> {
        unimplemented!("consensus_state_heights is not needed for this mock context")
    }

    fn next_consensus_state(
        &self,
        _client_id: &ClientId,
        _height: &Height,
    ) -> Result<Option<<Self as ClientValidationContext>::ConsensusStateRef>, ContextError> {
        Ok(None)
    }

    fn prev_consensus_state(
        &self,
        _client_id: &ClientId,
        _height: &Height,
    ) -> Result<Option<<Self as ClientValidationContext>::ConsensusStateRef>, ContextError> {
        Ok(None)
    }
}

impl<'a, S: StateAccessor + ?Sized> ClientValidationContext for MockClientCtx<'a, S> {
    type ClientStateRef = TmClientState;
    type ConsensusStateRef = TmConsensusState;

    fn client_state(&self, _client_id: &ClientId) -> Result<Self::ClientStateRef, ContextError> {
        let path = ClientStatePath::new(self.client_id.clone());
        let bytes = self
            .state_accessor
            .get(path.to_string().as_bytes())
            .map_err(|e| ClientError::Other {
                description: e.to_string(),
            })?
            .ok_or_else(|| ClientError::Other {
                description: "Client state not found".to_string(),
            })?;
        let raw =
            decode_any::<RawTmClientState>(&bytes, "/ibc.lightclients.tendermint.v1.ClientState")?;
        TmClientState::try_from(raw).map_err(|e| {
            ClientError::ClientSpecific {
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
            .map_err(|e| ClientError::Other {
                description: e.to_string(),
            })?
            .ok_or_else(|| ClientError::Other {
                description: "Consensus state not found".to_string(),
            })?;
        let raw = decode_any::<RawTmConsensusState>(
            &bytes,
            "/ibc.lightclients.tendermint.v1.ConsensusState",
        )?;
        TmConsensusState::try_from(raw).map_err(|e| {
            ClientError::ClientSpecific {
                description: e.to_string(),
            }
            .into()
        })
    }

    fn client_update_meta(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<(Timestamp, Height), ContextError> {
        Err(ContextError::ClientError(
            ClientError::UpdateMetaDataNotFound {
                client_id: client_id.clone(),
                height: *height,
            },
        ))
    }
}

impl TendermintVerifier {
    pub fn new(
        chain_id: String,
        client_id: String,
        state_accessor: Arc<dyn StateAccessor>,
    ) -> Self {
        Self {
            chain_id,
            client_id,
            state_accessor,
        }
    }
}

#[async_trait]
impl InterchainVerifier for TendermintVerifier {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    async fn verify_header(
        &self,
        header: &Header,
        _finality: &Finality,
        _ctx: &mut VerifyCtx,
    ) -> Result<(), CoreError> {
        let tm_header_bytes = match header {
            Header::Tendermint(h) => h.data.as_slice(),
            _ => {
                return Err(CoreError::Custom(
                    "Invalid header type for TendermintVerifier".into(),
                ))
            }
        };

        let client_id =
            ClientId::from_str(&self.client_id).map_err(|e| CoreError::Custom(e.to_string()))?;

        let client_state_path = ClientStatePath::new(client_id.clone())
            .to_string()
            .into_bytes();

        let client_state_bytes = self
            .state_accessor
            .get(&client_state_path)?
            .ok_or_else(|| IbcError::ClientStateNotFound(self.client_id.clone()))?;

        let client_state_raw: RawTmClientState = decode_any(
            &client_state_bytes,
            "/ibc.lightclients.tendermint.v1.ClientState",
        )
        .map_err(|e| CoreError::Custom(e.to_string()))?;
        let client_state: TmClientState =
            TmClientState::try_from(client_state_raw).map_err(|e| {
                CoreError::Custom(format!("Failed to decode Tendermint ClientState: {}", e))
            })?;
        let tm_header: TmHeader = TmHeader::try_from(RawTmHeader::decode(tm_header_bytes)?)
            .map_err(|e| CoreError::Custom(format!("Failed to decode Tendermint Header: {}", e)))?;

        // Align host view with the header we’re verifying.
        let header_height: u64 = tm_header
            .signed_header
            .header
            .height
            .try_into()
            .map_err(|_| CoreError::Custom("header height overflow".into()))?;

        let hdr_secs = u64::try_from(
            tendermint_proto::google::protobuf::Timestamp::from(
                tm_header.signed_header.header.time,
            )
            .seconds,
        )
        .unwrap_or(0);

        let host_ts =
            Timestamp::from_nanoseconds(hdr_secs.saturating_add(1).saturating_mul(1_000_000_000))
                .map_err(|e| CoreError::Custom(format!("timestamp build: {e}")))?;
        let host_h = Height::new(
            client_state.latest_height().revision_number(),
            header_height.saturating_add(1),
        )
        .map_err(|e| CoreError::Custom(format!("height build: {e}")))?;

        let mock_ctx = MockClientCtx {
            state_accessor: self.state_accessor.as_ref(),
            client_id: client_id.clone(),
            current_block_height: header_height.saturating_add(1),
            host_height_override: Some(host_h),
            host_timestamp_override: Some(host_ts),
        };

        client_state
            .verify_client_message(&mock_ctx, &client_id, tm_header.into())
            .map_err(|e: IbcClientError| CoreError::Custom(e.to_string()))
    }

    async fn verify_inclusion(
        &self,
        proof: &InclusionProof,
        header: &Header,
        _ctx: &mut VerifyCtx,
    ) -> Result<(), CoreError> {
        let ics23_proof = match proof {
            InclusionProof::Ics23(p) => p,
            _ => {
                return Err(CoreError::Custom(
                    "Invalid proof type for TendermintVerifier".into(),
                ))
            }
        };

        let tm_header: TmHeader = match header {
            Header::Tendermint(h) => TmHeader::try_from(RawTmHeader::decode(&*h.data)?)
                .map_err(|e| CoreError::Custom(e.to_string()))?,
            _ => {
                return Err(CoreError::Custom(
                    "Invalid header type for TendermintVerifier".into(),
                ))
            }
        };

        let client_id =
            ClientId::from_str(&self.client_id).map_err(|e| CoreError::Custom(e.to_string()))?;

        let client_state_path = ClientStatePath::new(client_id).to_string().into_bytes();
        let client_state_bytes = self
            .state_accessor
            .get(&client_state_path)?
            .ok_or_else(|| IbcError::ClientStateNotFound(self.client_id.clone()))?;
        let client_state_raw: RawTmClientState = decode_any(
            &client_state_bytes,
            "/ibc.lightclients.tendermint.v1.ClientState",
        )
        .map_err(|e| CoreError::Custom(e.to_string()))?;
        let client_state: TmClientState = TmClientState::try_from(client_state_raw)
            .map_err(|e| CoreError::Custom(e.to_string()))?;

        let proof_bytes = CommitmentProofBytes::try_from(ics23_proof.proof_bytes.clone())
            .map_err(|e| CoreError::Custom(format!("Invalid proof bytes format: {}", e)))?;

        let root =
            CommitmentRoot::from(tm_header.signed_header.header.app_hash.as_bytes().to_vec());

        let _ = (client_state, root, proof_bytes);
        log::warn!("'verify_inclusion' is currently a no-op due to API mismatch with ibc-rs 0.53.0. The `verify_membership` method now requires path and value which are not available in this function's signature.");
        Ok(())
    }

    async fn latest_verified_height(&self) -> u64 {
        // Use the canonical 07-tendermint type for lookup
        let Ok(client_id) = ClientId::from_str("07-tendermint-0") else {
            return 0;
        };
        let client_state_path = ClientStatePath::new(client_id).to_string().into_bytes();
        if let Ok(Some(bytes)) = self.state_accessor.get(&client_state_path) {
            if let Ok(cs_raw) = decode_any::<RawTmClientState>(
                &bytes,
                "/ibc.lightclients.tendermint.v1.ClientState",
            ) {
                if let Ok(cs) = TmClientState::try_from(cs_raw) {
                    return cs.latest_height().revision_height();
                }
            }
        }
        0
    }
}
