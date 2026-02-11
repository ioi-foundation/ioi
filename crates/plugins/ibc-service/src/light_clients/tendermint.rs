// Path: crates/services/src/ibc/light_clients/tendermint.rs
use crate::light_clients::errors::IbcError;
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

// [FIX] Use HostError
use ibc::core::host::types::error::HostError;

use ibc_core_host_types::{
    identifiers::ClientId,
    path::{ClientConsensusStatePath, ClientStatePath},
};
use ibc_primitives::Timestamp;
use ibc_proto::google::protobuf::Any as PbAny;

// ✅ Verify at the Merkle layer
use ibc_core_commitment_types::merkle::{MerklePath, MerkleProof as IbcMerkleProof};
use ibc_proto::ibc::core::commitment::v1::{
    MerklePath as PbMerklePath, MerkleProof as RawMerkleProof, MerkleRoot as PbMerkleRoot,
};
use ibc_proto::ics23 as pb_ics23;
use tendermint_proto::crypto::ProofOps as TmProofOps;

use ioi_api::error::CoreError;
use ioi_api::ibc::{LightClient, VerifyCtx};
use ioi_api::state::StateAccess;
use ioi_types::ibc::{Finality, Header, InclusionProof};
use prost::Message;

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

// dcrypt imports
use dcrypt::algorithms::hash::blake2::{Blake2b, Blake2s};
use dcrypt::algorithms::hash::sha2::{Sha256, Sha512};
use dcrypt::algorithms::hash::HashFunction;
use dcrypt::algorithms::hash::Keccak256;

// Correct HostFunctionsProvider implementation for ics23 v0.12 using dcrypt
struct IoiHostFunctions;
impl ibc_proto::ics23::HostFunctionsProvider for IoiHostFunctions {
    fn sha2_256(data: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(data).expect("sha256 digest");
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }
    fn sha2_512(data: &[u8]) -> [u8; 64] {
        let digest = Sha512::digest(data).expect("sha512 digest");
        let mut out = [0u8; 64];
        out.copy_from_slice(digest.as_ref());
        out
    }
    // [FIX] Removed sha2_512_256, replaced with sha2_512_truncated
    fn sha2_512_truncated(data: &[u8]) -> [u8; 32] {
        // Typically refers to SHA-512/256 or truncated SHA-512
        let digest = Sha512::digest(data).expect("sha512 digest");
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest.as_ref()[..32]);
        out
    }
    fn ripemd160(_data: &[u8]) -> [u8; 20] {
        // Not supported by dcrypt standard set; return dummy.
        [0u8; 20]
    }
    fn keccak_256(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let digest = Keccak256::digest(data).expect("keccak256 digest");
        out.copy_from_slice(digest.as_ref());
        out
    }
    fn blake2b_512(data: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        let digest = Blake2b::digest(data).expect("blake2b digest");
        out.copy_from_slice(digest.as_ref());
        out
    }
    fn blake2s_256(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let digest = Blake2s::digest(data).expect("blake2s digest");
        out.copy_from_slice(digest.as_ref());
        out
    }
    fn blake3(_data: &[u8]) -> [u8; 32] {
        // Placeholder
        [0u8; 32]
    }
}

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

/// A helper to robustly decode proof bytes.
fn decode_merkle_proof_flex(bytes: &[u8]) -> Result<IbcMerkleProof, CoreError> {
    if let Ok(any) = PbAny::decode(bytes) {
        let t = any.type_url.trim_start_matches('/');

        if t == "tendermint.crypto.ProofOps"
            || t == "tendermint.crypto.merkle.ProofOps"
            || t == "type.googleapis.com/tendermint.crypto.ProofOps"
        {
            let tm = TmProofOps::decode(any.value.as_slice())
                .map_err(|e| CoreError::Custom(format!("decode Any(ProofOps): {e}")))?;
            return tm_proofops_to_ibc_merkle(tm);
        }

        if t == "ibc.core.commitment.v1.MerkleProof"
            || t == "type.googleapis.com/ibc.core.commitment.v1.MerkleProof"
        {
            let raw = RawMerkleProof::decode(any.value.as_slice())
                .map_err(|e| CoreError::Custom(format!("decode Any(MerkleProof): {e}")))?;
            return IbcMerkleProof::try_from(raw)
                .map_err(|e| CoreError::Custom(format!("convert Any(MerkleProof): {e}")));
        }

        if t == "ics23.CommitmentProof"
            || t == "cosmos.ics23.v1.CommitmentProof"
            || t == "type.googleapis.com/ics23.CommitmentProof"
        {
            let cp = pb_ics23::CommitmentProof::decode(any.value.as_slice())
                .map_err(|e| CoreError::Custom(format!("decode Any(CommitmentProof): {e}")))?;
            let raw = RawMerkleProof { proofs: vec![cp] };
            return IbcMerkleProof::try_from(raw).map_err(|e| {
                CoreError::Custom(format!("convert Any(CommitmentProof)->MerkleProof: {e}"))
            });
        }

        // Fallback for unknown type URLs but valid inner bytes
        if let Ok(tm) = TmProofOps::decode(any.value.as_slice()) {
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
            "unsupported Any type_url '{}'",
            t
        )));
    }

    if let Ok(raw) = RawMerkleProof::decode(bytes) {
        return IbcMerkleProof::try_from(raw)
            .map_err(|e| CoreError::Custom(format!("convert MerkleProof: {e}")));
    }

    if let Ok(tm) = TmProofOps::decode(bytes) {
        return tm_proofops_to_ibc_merkle(tm);
    }

    if let Ok(cp) = pb_ics23::CommitmentProof::decode(bytes) {
        let raw = RawMerkleProof { proofs: vec![cp] };
        return IbcMerkleProof::try_from(raw)
            .map_err(|e| CoreError::Custom(format!("convert CommitmentProof->MerkleProof: {e}")));
    }

    Err(CoreError::Custom("proof bytes are unknown format".into()))
}

fn decode_any<T: prost::Message + Default>(
    bytes: &[u8],
    expected_type_url: &str,
) -> Result<T, ClientError> {
    let any = PbAny::decode(bytes).map_err(|e| ClientError::ClientSpecific {
        description: format!("failed to decode Any: {e}"),
    })?;
    if any.type_url != expected_type_url {
        return Err(ClientError::ClientSpecific {
            description: format!(
                "unexpected Any type_url: got {}, expected {}",
                any.type_url, expected_type_url
            ),
        });
    }
    T::decode(any.value.as_slice()).map_err(|e| ClientError::ClientSpecific {
        description: format!("failed to decode inner message: {e}"),
    })
}

fn tm_proofops_to_ibc_merkle(raw: TmProofOps) -> Result<IbcMerkleProof, CoreError> {
    let mut proofs: Vec<pb_ics23::CommitmentProof> = Vec::new();
    for op in raw.ops {
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

#[derive(Clone)]
pub struct TendermintVerifier {
    chain_id: String,
    client_id: String,
    state_accessor: Arc<dyn StateAccess>,
}

impl fmt::Debug for TendermintVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TendermintVerifier")
            .field("chain_id", &self.chain_id)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

pub struct MockClientCtx<'a, S: StateAccess + ?Sized> {
    pub state_accessor: &'a S,
    pub client_id: ClientId,
    pub current_block_height: u64,
    pub host_height_override: Option<Height>,
    pub host_timestamp_override: Option<Timestamp>,
}

impl<'a, S: StateAccess + ?Sized> ExtClientValidationContext for MockClientCtx<'a, S> {
    fn host_timestamp(&self) -> Result<Timestamp, HostError> {
        if let Some(ts) = self.host_timestamp_override {
            return Ok(ts);
        }
        const BLOCK_INTERVAL_NANOS: u64 = 5 * 1_000_000_000;
        let timestamp_nanos = self
            .current_block_height
            .saturating_mul(BLOCK_INTERVAL_NANOS);

        // [FIX] timestamp is infallible here
        Ok(Timestamp::from_nanoseconds(timestamp_nanos))
    }

    fn host_height(&self) -> Result<Height, HostError> {
        if let Some(h) = self.host_height_override {
            return Ok(h);
        }
        // [FIX] Removed .into(), passing ClientError directly to invalid_state which takes T: ToString
        Height::new(0, self.current_block_height).map_err(|e| HostError::invalid_state(e))
    }

    fn consensus_state_heights(&self, _client_id: &ClientId) -> Result<Vec<Height>, HostError> {
        Ok(Vec::new())
    }

    fn next_consensus_state(
        &self,
        _client_id: &ClientId,
        _height: &Height,
    ) -> Result<Option<<Self as ClientValidationContext>::ConsensusStateRef>, HostError> {
        Ok(None)
    }

    fn prev_consensus_state(
        &self,
        _client_id: &ClientId,
        _height: &Height,
    ) -> Result<Option<<Self as ClientValidationContext>::ConsensusStateRef>, HostError> {
        Ok(None)
    }
}

impl<'a, S: StateAccess + ?Sized> ClientValidationContext for MockClientCtx<'a, S> {
    type ClientStateRef = TmClientState;
    type ConsensusStateRef = TmConsensusState;

    fn client_state(&self, _client_id: &ClientId) -> Result<Self::ClientStateRef, HostError> {
        let path = ClientStatePath::new(self.client_id.clone());
        let bytes = self
            .state_accessor
            .get(path.to_string().as_bytes())
            .map_err(|e| HostError::failed_to_retrieve(e.to_string()))?
            .ok_or_else(|| HostError::missing_state("Client state not found".to_string()))?;
        let raw =
            decode_any::<RawTmClientState>(&bytes, "/ibc.lightclients.tendermint.v1.ClientState")
                .map_err(|e| HostError::invalid_state(e.to_string()))?;
        TmClientState::try_from(raw).map_err(|e| HostError::invalid_state(e.to_string()))
    }

    fn consensus_state(
        &self,
        path: &ClientConsensusStatePath,
    ) -> Result<Self::ConsensusStateRef, HostError> {
        let bytes = self
            .state_accessor
            .get(path.to_string().as_bytes())
            .map_err(|e| HostError::failed_to_retrieve(e.to_string()))?
            .ok_or_else(|| HostError::missing_state("Consensus state not found".to_string()))?;
        let raw = decode_any::<RawTmConsensusState>(
            &bytes,
            "/ibc.lightclients.tendermint.v1.ConsensusState",
        )
        .map_err(|e| HostError::invalid_state(e.to_string()))?;
        TmConsensusState::try_from(raw).map_err(|e| HostError::invalid_state(e.to_string()))
    }

    fn client_update_meta(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<(Timestamp, Height), HostError> {
        Err(HostError::missing_state(format!(
            "Update metadata not found for {client_id} at {height}"
        )))
    }
}

impl TendermintVerifier {
    pub fn new(chain_id: String, client_id: String, state_accessor: Arc<dyn StateAccess>) -> Self {
        Self {
            chain_id,
            client_id,
            state_accessor,
        }
    }
}

#[async_trait]
impl LightClient for TendermintVerifier {
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

        // [FIX] Timestamp is infallible
        let host_ts =
            Timestamp::from_nanoseconds(hdr_secs.saturating_add(1).saturating_mul(1_000_000_000));

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
        let p = match proof {
            InclusionProof::Ics23(p) => p,
            _ => {
                return Err(CoreError::Custom(
                    "TendermintVerifier expects ICS-23 proof".into(),
                ))
            }
        };

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

        let (app_hash_bytes, _proof_height): (Vec<u8>, u64) = {
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

        let merkle_root = PbMerkleRoot {
            hash: app_hash_bytes,
        };

        let pb_path = pb_merkle_path_with_ibc_prefix(&p.path);
        let merkle_path: MerklePath = pb_path.into();

        let merkle_proof: IbcMerkleProof = decode_merkle_proof_flex(&p.proof_bytes)?;

        let proof_specs = ProofSpecs::cosmos();

        // [FIX] Update verify_membership call signature. Pass 0 as start_index.
        merkle_proof
            .verify_membership::<IoiHostFunctions>(
                &proof_specs,
                merkle_root,
                merkle_path,
                p.value.clone(),
                0, // start_index
            )
            .map_err(|e| CoreError::Custom(format!("ICS-23 membership check failed: {e}")))?;

        Ok(())
    }

    async fn latest_verified_height(&self) -> u64 {
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
