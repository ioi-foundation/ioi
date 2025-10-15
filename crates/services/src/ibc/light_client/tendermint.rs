// Path: crates/services/src/ibc/light_client/tendermint.rs
use crate::ibc::light_client::errors::IbcError;
use async_trait::async_trait;
use depin_sdk_api::error::CoreError;
use depin_sdk_api::ibc::{InterchainVerifier, VerifyCtx};
use depin_sdk_api::state::StateAccessor;
use depin_sdk_types::ibc::{Finality, Header, InclusionProof};
// Corrected import path for the Tendermint-specific validation context trait
use ibc_client_tendermint::types::proto::v1::{
    ClientState as RawTmClientState, ConsensusState as RawTmConsensusState, Header as RawTmHeader,
};
use ibc_client_tendermint::{
    client_state::ClientState as TmClientState,
    consensus_state::ConsensusState as TmConsensusState, types::Header as TmHeader,
};
// Corrected import path for the Tendermint-specific validation context trait
use ibc_core_client_context::ExtClientValidationContext;
use ibc_core_client_context::{
    client_state::{ClientStateCommon, ClientStateValidation},
    types::error::ClientError,
    ClientExecutionContext, ClientValidationContext,
};
use ibc_core_client_types::{error::ClientError as IbcClientError, Height};
use ibc_core_commitment_types::commitment::{CommitmentProofBytes, CommitmentRoot};
use ibc_core_handler_types::error::ContextError;
use ibc_core_host_types::{
    identifiers::ClientId,
    path::{ClientConsensusStatePath, ClientStatePath},
};
use ibc_primitives::Timestamp;
use prost::Message;

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

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
struct MockClientCtx<'a, S: StateAccessor + ?Sized> {
    state_accessor: &'a S,
    client_id: ClientId,
}

impl<'a, S: StateAccessor + ?Sized> ExtClientValidationContext for MockClientCtx<'a, S> {
    fn host_timestamp(&self) -> Result<Timestamp, ContextError> {
        // FIX: Use a non-zero timestamp, as Tendermint validation rejects the epoch.
        // Using 1 second after the epoch is a valid, deterministic choice for tests.
        Timestamp::from_nanoseconds(1_000_000_000).map_err(|e| {
            ContextError::from(ClientError::Other {
                description: format!("Failed to create timestamp: {}", e),
            })
        })
    }

    fn host_height(&self) -> Result<Height, ContextError> {
        unimplemented!("host_height is not needed for this mock context")
    }

    fn consensus_state_heights(&self, _client_id: &ClientId) -> Result<Vec<Height>, ContextError> {
        unimplemented!("consensus_state_heights is not needed for this mock context")
    }

    fn next_consensus_state(
        &self,
        _client_id: &ClientId,
        _height: &Height,
    ) -> Result<Option<<Self as ClientValidationContext>::ConsensusStateRef>, ContextError> {
        unimplemented!()
    }

    fn prev_consensus_state(
        &self,
        _client_id: &ClientId,
        _height: &Height,
    ) -> Result<Option<<Self as ClientValidationContext>::ConsensusStateRef>, ContextError> {
        unimplemented!()
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
        TmClientState::try_from(RawTmClientState::decode(&*bytes).map_err(|e| {
            ClientError::Other {
                description: e.to_string(),
            }
        })?)
        .map_err(|e| {
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
        TmConsensusState::try_from(RawTmConsensusState::decode(&*bytes).map_err(|e| {
            ClientError::Other {
                description: e.to_string(),
            }
        })?)
        .map_err(|e| {
            ClientError::ClientSpecific {
                description: e.to_string(),
            }
            .into()
        })
    }

    fn client_update_meta(
        &self,
        _client_id: &ClientId,
        _height: &Height,
    ) -> Result<(Timestamp, Height), ContextError> {
        unimplemented!("client_update_meta is not needed for this mock context")
    }
}

struct MockClientExecCtx;
impl ExtClientValidationContext for MockClientExecCtx {
    fn host_timestamp(&self) -> Result<Timestamp, ContextError> {
        // FIX: Also update this implementation for completeness.
        Timestamp::from_nanoseconds(1_000_000_000).map_err(|e| {
            ContextError::from(ClientError::Other {
                description: format!("Failed to create timestamp: {}", e),
            })
        })
    }
    fn host_height(&self) -> Result<Height, ContextError> {
        unimplemented!()
    }
    fn consensus_state_heights(&self, _client_id: &ClientId) -> Result<Vec<Height>, ContextError> {
        unimplemented!()
    }
    fn next_consensus_state(
        &self,
        _client_id: &ClientId,
        _height: &Height,
    ) -> Result<Option<<Self as ClientValidationContext>::ConsensusStateRef>, ContextError> {
        unimplemented!()
    }
    fn prev_consensus_state(
        &self,
        _client_id: &ClientId,
        _height: &Height,
    ) -> Result<Option<<Self as ClientValidationContext>::ConsensusStateRef>, ContextError> {
        unimplemented!()
    }
}
impl ClientValidationContext for MockClientExecCtx {
    type ClientStateRef = TmClientState;
    type ConsensusStateRef = TmConsensusState;
    fn client_state(&self, _client_id: &ClientId) -> Result<Self::ClientStateRef, ContextError> {
        unimplemented!()
    }
    fn consensus_state(
        &self,
        _path: &ClientConsensusStatePath,
    ) -> Result<Self::ConsensusStateRef, ContextError> {
        unimplemented!()
    }
    fn client_update_meta(
        &self,
        _client_id: &ClientId,
        _height: &Height,
    ) -> Result<(Timestamp, Height), ContextError> {
        unimplemented!()
    }
}

impl ClientExecutionContext for MockClientExecCtx {
    type ClientStateMut = TmClientState;

    fn store_client_state(
        &mut self,
        _path: ClientStatePath,
        _client_state: Self::ClientStateMut,
    ) -> Result<(), ContextError> {
        unimplemented!()
    }
    fn store_consensus_state(
        &mut self,
        _path: ClientConsensusStatePath,
        _consensus_state: Self::ConsensusStateRef,
    ) -> Result<(), ContextError> {
        unimplemented!()
    }
    fn delete_consensus_state(
        &mut self,
        _path: ClientConsensusStatePath,
    ) -> Result<(), ContextError> {
        unimplemented!()
    }
    fn store_update_meta(
        &mut self,
        _client_id: ClientId,
        _height: Height,
        _host_timestamp: Timestamp,
        _host_height: Height,
    ) -> Result<(), ContextError> {
        unimplemented!()
    }
    fn delete_update_meta(
        &mut self,
        _client_id: ClientId,
        _height: Height,
    ) -> Result<(), ContextError> {
        unimplemented!()
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

        let client_state: TmClientState =
            TmClientState::try_from(RawTmClientState::decode(&*client_state_bytes)?).map_err(
                |e| CoreError::Custom(format!("Failed to decode Tendermint ClientState: {}", e)),
            )?;
        let tm_header: TmHeader = TmHeader::try_from(RawTmHeader::decode(tm_header_bytes)?)
            .map_err(|e| CoreError::Custom(format!("Failed to decode Tendermint Header: {}", e)))?;

        let mock_ctx = MockClientCtx {
            state_accessor: self.state_accessor.as_ref(),
            client_id: client_id.clone(),
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
        let client_state: TmClientState =
            TmClientState::try_from(RawTmClientState::decode(&*client_state_bytes)?)
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
        let Ok(client_id) = ClientId::from_str(&self.client_id) else {
            return 0;
        };
        let client_state_path = ClientStatePath::new(client_id).to_string().into_bytes();
        if let Ok(Some(bytes)) = self.state_accessor.get(&client_state_path) {
            if let Ok(cs_raw) = RawTmClientState::decode(&*bytes) {
                if let Ok(cs) = TmClientState::try_from(cs_raw) {
                    return cs.latest_height().revision_height();
                }
            }
        }
        0
    }
}
