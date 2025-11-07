// Path: crates/services/src/ibc/light_client/tendermint.rs
use crate::ibc::light_client::errors::IbcError;
use async_trait::async_trait;
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
use ibc_core_commitment_types::specs::ProofSpecs;
use ibc_core_handler_types::error::ContextError;
use ibc_core_host_types::{
    identifiers::ClientId,
    path::{ClientConsensusStatePath, ClientStatePath},
};
use ibc_primitives::Timestamp;
use ibc_proto::google::protobuf::Any as PbAny;

// ✅ Verify at the Merkle layer
use ibc_core_commitment_types::merkle::MerkleProof as IbcMerkleProof;
use ibc_proto::ibc::core::commitment::v1::{
    MerklePath as PbMerklePath, MerkleProof as RawMerkleProof, MerkleRoot as PbMerkleRoot,
};
use ibc_proto::ics23 as pb_ics23;
// NEW: Tendermint ProofOps support
use tendermint_proto::crypto::ProofOps as TmProofOps;
// (Field name is `r#type` on ProofOp due to Rust keyword; we don't need the type itself in imports.)

use ics23::HostFunctionsManager;
use ioi_api::error::CoreError;
use ioi_api::ibc::{InterchainVerifier, VerifyCtx};
use ioi_api::state::StateAccessor;
use ioi_types::ibc::{Finality, Header, InclusionProof};
use prost::Message;

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

/// A helper to build a Merkle path that includes the "ibc" store prefix.
fn pb_merkle_path_with_ibc_prefix(path_str: &str) -> PbMerklePath {
    let mut segments: Vec<String> = path_str
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    // Ensure the multistore prefix is present for this API variant.
    if segments.first().map(|s| s.as_str()) != Some("ibc") {
        segments.insert(0, "ibc".to_string());
    }

    PbMerklePath { key_path: segments }
}

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

/// Convert a Tendermint `ProofOps` (possibly containing ICS-23 ops) into an IBC MerkleProof.
fn tm_proofops_to_ibc_merkle(raw: TmProofOps) -> Result<IbcMerkleProof, CoreError> {
    // Typical pattern: a single op where `op.r#type` contains "ics23" and `op.data`
    // holds a serialized `ics23.CommitmentProof`. But be tolerant and collect any ICS-23 ops.
    let mut proofs: Vec<pb_ics23::CommitmentProof> = Vec::new();
    for op in raw.ops {
        // Heuristic: many stacks label the op type with "ics23" or "iavl". We don't hard fail if it doesn't match.
        // Try to decode the op.data as an ICS-23 CommitmentProof; if it works, include it.
        if let Ok(cp) = pb_ics23::CommitmentProof::decode(op.data.as_slice()) {
            proofs.push(cp);
        }
    }
    if proofs.is_empty() {
        return Err(CoreError::Custom(
            "tendermint ProofOps contained no decodable ICS-23 CommitmentProof".into(),
        ));
    }
    let raw_mp = RawMerkleProof { proofs };
    IbcMerkleProof::try_from(raw_mp)
        .map_err(|e| CoreError::Custom(format!("convert ProofOps->MerkleProof: {e}")))
}

fn decode_merkle_proof_flex(bytes: &[u8]) -> Result<IbcMerkleProof, CoreError> {
    // Path A: The bytes are a google.protobuf.Any wrapper.
    if let Ok(any) = PbAny::decode(bytes) {
        let t = any.type_url.trim_start_matches('/');

        // A0) Any -> Tendermint ProofOps -> (extract ICS-23) -> MerkleProof
        if t == "tendermint.crypto.ProofOps"
            || t == "tendermint.crypto.merkle.ProofOps"
            || t == "type.googleapis.com/tendermint.crypto.ProofOps"
            || t == "type.googleapis.com/tendermint.crypto.merkle.ProofOps"
        {
            let tm = TmProofOps::decode(any.value.as_slice())
                .map_err(|e| CoreError::Custom(format!("decode Any(ProofOps): {e}")))?;
            return tm_proofops_to_ibc_merkle(tm);
        }

        // 1) Any -> MerkleProof
        if t == "ibc.core.commitment.v1.MerkleProof"
            || t == "type.googleapis.com/ibc.core.commitment.v1.MerkleProof"
        {
            let raw = RawMerkleProof::decode(any.value.as_slice())
                .map_err(|e| CoreError::Custom(format!("decode Any(MerkleProof): {e}")))?;
            return IbcMerkleProof::try_from(raw)
                .map_err(|e| CoreError::Custom(format!("convert Any(MerkleProof): {e}")));
        }

        // 2) Any -> ICS23 CommitmentProof -> wrap into MerkleProof
        if t == "ics23.CommitmentProof"
            || t == "cosmos.ics23.v1.CommitmentProof"
            || t == "cosmos.crypto.ics23.v1.CommitmentProof"
            || t == "type.googleapis.com/ics23.CommitmentProof"
            || t == "type.googleapis.com/cosmos.crypto.ics23.v1.CommitmentProof"
        {
            let cp = pb_ics23::CommitmentProof::decode(any.value.as_slice())
                .map_err(|e| CoreError::Custom(format!("decode Any(CommitmentProof): {e}")))?;
            let raw = RawMerkleProof { proofs: vec![cp] };
            return IbcMerkleProof::try_from(raw).map_err(|e| {
                CoreError::Custom(format!("convert Any(CommitmentProof)->MerkleProof: {e}"))
            });
        }

        // Unknown Any type_url: fall through to raw attempts below using `any.value`.
        // Try to be helpful by attempting all variants on the inner bytes.
        if let Ok(tm) = TmProofOps::decode(any.value.as_slice()) {
            // If inner bytes are actually ProofOps, extract ICS-23 and return.
            return tm_proofops_to_ibc_merkle(tm);
        }
        if let Ok(raw) = RawMerkleProof::decode(any.value.as_slice()) {
            return IbcMerkleProof::try_from(raw)
                .map_err(|e| CoreError::Custom(format!("convert Any.value(MerkleProof): {e}")));
        }
        if let Ok(cp) = pb_ics23::CommitmentProof::decode(any.value.as_slice()) {
            let raw = RawMerkleProof { proofs: vec![cp] };
            return IbcMerkleProof::try_from(raw).map_err(|e| {
                CoreError::Custom(format!(
                    "convert Any.value(CommitmentProof)->MerkleProof: {e}"
                ))
            });
        }

        return Err(CoreError::Custom(format!(
            "unsupported Any type_url '{}' and inner bytes not ProofOps/MerkleProof/CommitmentProof",
            t
        )));
    }

    // Path B: Outer bytes are MerkleProof directly.
    if let Ok(raw) = RawMerkleProof::decode(bytes) {
        return IbcMerkleProof::try_from(raw)
            .map_err(|e| CoreError::Custom(format!("convert MerkleProof: {e}")));
    }

    // Path B2: Outer bytes are Tendermint ProofOps directly.
    if let Ok(tm) = TmProofOps::decode(bytes) {
        return tm_proofops_to_ibc_merkle(tm);
    }

    // Path C: Outer bytes are ICS23 CommitmentProof directly.
    if let Ok(cp) = pb_ics23::CommitmentProof::decode(bytes) {
        let raw = RawMerkleProof { proofs: vec![cp] };
        return IbcMerkleProof::try_from(raw)
            .map_err(|e| CoreError::Custom(format!("convert CommitmentProof->MerkleProof: {e}")));
    }

    Err(CoreError::Custom(
        "proof bytes are neither Any(ProofOps|MerkleProof|CommitmentProof) nor raw ProofOps/MerkleProof/CommitmentProof".into(),
    ))
}

/// A verifier for Tendermint-based chains using the `ibc-rs` implementation.
#[derive(Clone)]
pub struct TendermintVerifier {
    chain_id: String,
    client_id: String, // e.g., "07-tendermint-0"
    state_accessor: Arc<dyn StateAccessor>,
}

impl fmt::Debug for TendermintVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        // 0) Inputs
        let p = match proof {
            InclusionProof::Ics23(p) => p,
            _ => {
                return Err(CoreError::Custom(
                    "TendermintVerifier expects ICS-23 proof".into(),
                ))
            }
        };

        // 1) Extract app_hash (state root) and proof height from the Tendermint header.
        let raw_header: RawTmHeader = match header {
            Header::Tendermint(h) => RawTmHeader::decode(&*h.data).map_err(|e| {
                CoreError::Custom(format!("failed to decode Tendermint header bytes: {e}"))
            })?,
            _ => {
                return Err(CoreError::Custom(
                    "Invalid header type for TendermintVerifier".into(),
                ))
            }
        };

        let (app_hash_bytes, proof_height): (Vec<u8>, u64) = {
            let sh = raw_header
                .signed_header
                .as_ref()
                .ok_or_else(|| CoreError::Custom("header missing signed_header".into()))?;
            let hdr = sh
                .header
                .as_ref()
                .ok_or_else(|| CoreError::Custom("header missing inner header".into()))?;

            let h: u64 = hdr.height.try_into().unwrap_or(0);
            (hdr.app_hash.clone(), h)
        };

        // Merkle root is the proto type expected by this verify method (taken by value).
        let merkle_root = PbMerkleRoot {
            hash: app_hash_bytes,
        };

        // 2) Build a Merkle path that *includes* the "ibc" store prefix (this method variant has no prefix arg).
        let pb_path = pb_merkle_path_with_ibc_prefix(&p.path);

        // 3) Decode proof bytes robustly (Any/MerkleProof/CommitmentProof)
        let merkle_proof: IbcMerkleProof = decode_merkle_proof_flex(&p.proof_bytes)?;

        // 4) Cosmos proof specs and verification.
        let proof_specs = ProofSpecs::cosmos();

        // NOTE: In this ibc-rs snapshot, verify_membership takes:
        //   (&ProofSpecs, MerkleRoot (by value), MerklePath (by value), value, height)
        merkle_proof
            .verify_membership::<HostFunctionsManager>(
                &proof_specs,
                merkle_root,     // by value (not &)
                pb_path,         // by value (not &)
                p.value.clone(), // expected value bytes
                proof_height,    // proof height from the header
            )
            .map_err(|e| CoreError::Custom(format!("ICS-23 membership check failed: {e}")))?;

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
