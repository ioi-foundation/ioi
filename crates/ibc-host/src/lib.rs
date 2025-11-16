// Path: crates/ibc-host/src/lib.rs
#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use ibc_proto::ics23::CommitmentProof;
use ioi_api::state::Verifier;
use ioi_client::WorkloadClient;
use ioi_crypto::algorithms::hash::sha256;
use ioi_networking::libp2p::SwarmCommand;
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ChainId, ChainTransaction, SignHeader,
        SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
    },
    codec,
};
use libp2p::identity::Keypair;
use lru::LruCache;
use parity_scale_codec::Decode;
use prost::Message;
use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc};
use tokio::sync::{mpsc, Mutex};
use tracing;

// --------------------------------------------------------------------------------------
// Local SCALE wire types for IAVL proofs (mirror of commitment/src/tree/iavl/proof.rs).
// This avoids importing the private `proof` module across crate boundaries.
// Keep field and variant order exactly in sync with the canonical types.
// --------------------------------------------------------------------------------------
mod iavl_wire {
    use parity_scale_codec::Decode;

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub enum HashOp {
        NoHash,
        Sha256,
    }

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub enum LengthOp {
        NoPrefix,
        VarProto,
    }

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub enum IavlProof {
        Existence(ExistenceProof),
        NonExistence(NonExistenceProof),
    }

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub struct ExistenceProof {
        pub key: Vec<u8>,
        pub value: Vec<u8>,
        pub leaf: LeafOp,
        pub path: Vec<InnerOp>,
    }

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub struct NonExistenceProof {
        pub missing_key: Vec<u8>,
        pub left: Option<ExistenceProof>,
        pub right: Option<ExistenceProof>,
    }

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub struct LeafOp {
        pub hash: HashOp,
        pub prehash_key: HashOp,
        pub prehash_value: HashOp,
        pub length: LengthOp,
        pub prefix: Vec<u8>,
    }

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub enum Side {
        Left,
        Right,
    }

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub struct InnerOp {
        pub version: u64,
        pub height: i32,
        pub size: u64,
        pub split_key: Vec<u8>,
        pub side: Side,
        pub sibling_hash: [u8; 32],
    }
}
use iavl_wire::{
    ExistenceProof, HashOp, IavlProof, InnerOp, LeafOp, LengthOp, NonExistenceProof, Side,
};

use ics23::HostFunctionsManager;

#[derive(Debug, Clone)]
pub struct QueryHostResponse {
    pub value: Vec<u8>,
    pub proof: Option<Vec<u8>>,
    pub height: u64,
}

#[async_trait]
pub trait IbcHost: Send + Sync {
    async fn query(&self, path: &str, height: Option<u64>) -> Result<QueryHostResponse>;
    async fn submit_ibc_messages(&self, msgs_pb: Vec<u8>) -> Result<[u8; 32]>;
    async fn commitment_root(&self, height: Option<u64>) -> Result<(Vec<u8>, u64)>;
}

// [SCALE-IAVL START]
// Inlined helpers for SCALE/IAVL proof root computation
fn decode_scale_iavl_proof(bytes: &[u8]) -> Option<IavlProof> {
    if let Ok(inner) = codec::from_bytes_canonical::<Vec<u8>>(bytes) {
        if let Ok(p) = IavlProof::decode(&mut &*inner) {
            return Some(p);
        }
    }
    IavlProof::decode(&mut &*bytes).ok()
}

#[inline]
fn hash_leaf_canonical(
    leaf_op: &LeafOp,
    key: &[u8],
    value: &[u8],
) -> Result<[u8; 32], anyhow::Error> {
    fn apply_hash(op: &HashOp, data: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        match op {
            HashOp::NoHash => Ok(data.to_vec()),
            HashOp::Sha256 => Ok(sha256(data)?.to_vec()),
        }
    }

    fn apply_length(op: &LengthOp, data: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        match op {
            LengthOp::NoPrefix => Ok(data.to_vec()),
            LengthOp::VarProto => {
                let mut len_prefixed =
                    Vec::with_capacity(prost::length_delimiter_len(data.len()) + data.len());
                prost::encode_length_delimiter(data.len(), &mut len_prefixed)?;
                len_prefixed.extend_from_slice(data);
                Ok(len_prefixed)
            }
        }
    }

    let hashed_key = apply_hash(&leaf_op.prehash_key, key)?;
    let hashed_value = apply_hash(&leaf_op.prehash_value, value)?;

    let mut data = Vec::new();
    data.extend_from_slice(&leaf_op.prefix);
    data.extend_from_slice(&apply_length(&leaf_op.length, &hashed_key)?);
    data.extend_from_slice(&apply_length(&leaf_op.length, &hashed_value)?);

    match leaf_op.hash {
        HashOp::Sha256 => sha256(&data).map_err(|e| anyhow!("sha256: {e}")),
        HashOp::NoHash => {
            let hash_vec = sha256(&data)?;
            let mut h = [0u8; 32];
            h.copy_from_slice(&hash_vec[..32]);
            Ok(h)
        }
    }
}

#[inline]
fn hash_inner_canonical(op: &InnerOp, left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32]> {
    let mut data = Vec::with_capacity(1 + 8 + 4 + 8 + 4 + op.split_key.len() + 32 + 32);
    data.push(0x01);
    data.extend_from_slice(&op.version.to_le_bytes());
    data.extend_from_slice(&op.height.to_le_bytes());
    data.extend_from_slice(&op.size.to_le_bytes());
    data.extend_from_slice(&(op.split_key.len() as u32).to_le_bytes());
    data.extend_from_slice(&op.split_key);
    data.extend_from_slice(left);
    data.extend_from_slice(right);
    sha256(&data).map_err(|e| anyhow!("sha256: {e}"))
}

fn compute_iavl_root_from_existence(p: &ExistenceProof) -> Result<[u8; 32]> {
    let mut acc = hash_leaf_canonical(&p.leaf, &p.key, &p.value)?;
    for step in &p.path {
        let (left, right) = match step.side {
            Side::Left => (step.sibling_hash, acc),
            Side::Right => (acc, step.sibling_hash),
        };
        acc = hash_inner_canonical(step, &left, &right)?;
    }
    Ok(acc)
}

fn compute_iavl_root_from_nonexistence(p: &NonExistenceProof) -> Result<[u8; 32]> {
    match (&p.left, &p.right) {
        (Some(l), None) => compute_iavl_root_from_existence(l),
        (None, Some(r)) => compute_iavl_root_from_existence(r),
        (Some(l), Some(r)) => {
            let rl = compute_iavl_root_from_existence(l)?;
            let rr = compute_iavl_root_from_existence(r)?;
            if rl != rr {
                return Err(anyhow!("non-existence neighbors yield different roots"));
            }
            Ok(rl)
        }
        (None, None) => Err(anyhow!("non-existence proof has no neighbors")),
    }
}

fn root_from_scale_iavl_bytes(proof_bytes: &[u8]) -> Option<Vec<u8>> {
    let p = decode_scale_iavl_proof(proof_bytes)?;
    let root = match p {
        IavlProof::Existence(ex) => compute_iavl_root_from_existence(&ex),
        IavlProof::NonExistence(nex) => compute_iavl_root_from_nonexistence(&nex),
    }
    .ok()?;
    Some(root.to_vec())
}
// [SCALE-IAVL END]

/// Helper to compute the Merkle root from a raw ICS23 proof (prost bytes).
/// Supports single `ExistenceProof`, `BatchProof` (first existence entry),
/// and `CompressedBatchProof` (first compressed existence entry).
pub fn existence_root_from_proof_bytes(proof_pb: &[u8]) -> Result<Vec<u8>> {
    // 1.1: Provenance Logging
    let mut input_variant = "unknown";
    let result = (|| {
        // The main logic is wrapped in a closure to allow early returns
        // while still executing the log statement at the end.
        if let Some(root) = root_from_scale_iavl_bytes(proof_pb) {
            input_variant = "scale_native";
            return Ok(root);
        }
        use ibc_proto::ics23::batch_entry;
        use ibc_proto::ics23::commitment_proof::Proof as PbProofVariant;
        use ibc_proto::ics23::compressed_batch_entry;
        use ibc_proto::ics23::{
            CommitmentProof as PbCommitmentProof, ExistenceProof as PbExistenceProof,
        };

        let cp: PbCommitmentProof =
            CommitmentProof::decode(proof_pb).context("decode ICS-23 CommitmentProof")?;

        let ex_pb: PbExistenceProof = match cp.proof.ok_or_else(|| anyhow!("empty ICS-23 proof"))? {
            PbProofVariant::Exist(ex) => {
                input_variant = "raw(commitment_proof)";
                ex
            }
            PbProofVariant::Batch(b) => {
                input_variant = "raw(batch_proof)";
                let ex = b
                    .entries
                    .into_iter()
                    .find_map(|entry| match entry.proof {
                        Some(batch_entry::Proof::Exist(ex)) => Some(ex),
                        _ => None,
                    })
                    .ok_or_else(|| anyhow!("batch proof missing existence entry"))?;
                ex
            }
            PbProofVariant::Compressed(c) => {
                input_variant = "raw(compressed_batch_proof)";
                let first = c
                    .entries
                    .get(0)
                    .ok_or_else(|| anyhow!("compressed proof missing entries"))?;
                let comp_exist = match &first.proof {
                    Some(compressed_batch_entry::Proof::Exist(ex)) => ex,
                    _ => return Err(anyhow!("first compressed entry is not existence proof")),
                };
                let mut path: Vec<ibc_proto::ics23::InnerOp> =
                    Vec::with_capacity(comp_exist.path.len());
                for &idx in &comp_exist.path {
                    let u = usize::try_from(idx).map_err(|_| anyhow!("negative inner-op index"))?;
                    let op = c
                        .lookup_inners
                        .get(u)
                        .ok_or_else(|| anyhow!("inner-op index {} out of range", u))?
                        .clone();
                    path.push(op);
                }
                PbExistenceProof {
                    key: comp_exist.key.clone(),
                    value: comp_exist.value.clone(),
                    leaf: comp_exist.leaf.clone(),
                    path,
                }
            }
            PbProofVariant::Nonexist(_) => {
                return Err(anyhow!(
                    "non-existence proof cannot be used to compute root"
                ))
            }
        };

        let ex_native: ics23::ExistenceProof = ex_pb
            .try_into()
            .map_err(|_| anyhow!("convert prost ExistenceProof -> native ics23::ExistenceProof"))?;
        ics23::calculate_existence_root::<HostFunctionsManager>(&ex_native)
            .map(|r| r.to_vec())
            .map_err(|e| anyhow!("calculate_existence_root: {e}"))
    })(); // Immediately call the closure.

    tracing::debug!(
        target = "ibc.proof",
        event = "root_recompute",
        input_variant = %input_variant,
        proof_len = proof_pb.len(),
        result = if result.is_ok() { "ok" } else { "err" },
        root_len = result.as_ref().map(|r| r.len()).unwrap_or(0),
    );

    result
}

pub struct DefaultIbcHost<V: Verifier> {
    workload_client: Arc<WorkloadClient>,
    _verifier: V, // Keep verifier for type parameter matching, though not used directly here
    tx_pool: Arc<Mutex<std::collections::VecDeque<ChainTransaction>>>,
    swarm_commander: mpsc::Sender<SwarmCommand>,
    signer: Keypair,
    nonce_manager: Arc<Mutex<BTreeMap<AccountId, u64>>>,
    chain_id: ChainId,
    idempotency_cache: Arc<Mutex<LruCache<[u8; 32], [u8; 32]>>>,
}

impl<V: Verifier + 'static> DefaultIbcHost<V> {
    pub fn new(
        workload_client: Arc<WorkloadClient>,
        verifier: V,
        tx_pool: Arc<Mutex<std::collections::VecDeque<ChainTransaction>>>,
        swarm_commander: mpsc::Sender<SwarmCommand>,
        signer: Keypair,
        nonce_manager: Arc<Mutex<BTreeMap<AccountId, u64>>>,
        chain_id: ChainId,
    ) -> Self {
        tracing::debug!(
            target = "mempool",
            "host tx_pool ptr = {:p}",
            Arc::as_ptr(&tx_pool)
        );
        Self {
            workload_client,
            _verifier: verifier,
            tx_pool,
            swarm_commander,
            signer,
            nonce_manager,
            chain_id,
            idempotency_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(1024).unwrap(),
            ))),
        }
    }
}

#[async_trait]
impl<V: Verifier + Send + Sync + 'static> IbcHost for DefaultIbcHost<V> {
    async fn query(&self, path: &str, height: Option<u64>) -> Result<QueryHostResponse> {
        let query_height = if let Some(h) = height {
            h
        } else {
            self.workload_client.get_status().await?.height
        };

        let block = self
            .workload_client
            .get_block_by_height(query_height)
            .await?
            .ok_or_else(|| anyhow!("Block at height {} not found for query", query_height))?;

        let response = self
            .workload_client
            .query_state_at(block.header.state_root, path.as_bytes())
            .await?;

        // --- START REFACTOR ---
        // Unwrap the HashProof to expose the canonical IavlProof bytes.
        use ioi_state::primitives::hash::HashProof;
        use ioi_types::codec::from_bytes_canonical;

        let canonical_proof_bytes = from_bytes_canonical::<HashProof>(&response.proof_bytes)
            .map(|hash_proof| hash_proof.value)
            .map_err(|e| anyhow!("Failed to unwrap HashProof from workload: {}", e))?;
        // --- END REFACTOR ---

        Ok(QueryHostResponse {
            value: response.membership.into_option().unwrap_or_default(),
            proof: Some(canonical_proof_bytes), // Now contains raw IavlProof bytes
            height: query_height,
        })
    }

    async fn submit_ibc_messages(&self, msgs_pb: Vec<u8>) -> Result<[u8; 32]> {
        let msgs_hash = sha256(&msgs_pb)?;
        if let Some(tx_hash) = self.idempotency_cache.lock().await.get(&msgs_hash) {
            return Ok(*tx_hash);
        }

        // The account_id MUST be derived from the keypair that is present in the genesis state.
        // For the test setup, the orchestrator's identity keypair IS the validator.
        let account_id = AccountId(account_id_from_key_material(
            SignatureSuite::Ed25519,
            &self.signer.public().encode_protobuf(),
        )?);

        let nonce = {
            let mut manager = self.nonce_manager.lock().await;
            let n = manager.entry(account_id).or_insert(0); // Use the correct account_id here.
            let current = *n;
            *n += 1;
            current
        };

        let tx = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id,
                nonce,
                chain_id: self.chain_id,
                tx_version: 1,
            },
            payload: SystemPayload::CallService {
                service_id: "ibc".to_string(),
                method: "msg_dispatch@v1".to_string(),
                params: msgs_pb,
            },
            signature_proof: SignatureProof::default(), // Will be filled in
        }));

        // A proper implementation would use a signer trait here.
        // For now, we manually sign.
        let (signed_tx, tx_bytes) = {
            if let ChainTransaction::System(mut sys_tx) = tx {
                let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
                sys_tx.signature_proof = SignatureProof {
                    suite: SignatureSuite::Ed25519,
                    public_key: self.signer.public().encode_protobuf(),
                    signature: self.signer.sign(&sign_bytes)?,
                };
                let final_tx = ChainTransaction::System(sys_tx);
                let bytes = codec::to_bytes_canonical(&final_tx).map_err(|e| anyhow!(e))?;
                (final_tx, bytes)
            } else {
                unreachable!();
            }
        };
        let tx_hash = sha256(&tx_bytes)?;

        {
            let mut pool = self.tx_pool.lock().await;
            let before = pool.len();
            pool.push_back(signed_tx);
            let after = pool.len();
            tracing::debug!(
                target = "mempool",
                "pushed IBC tx: account_id={}, before={}, after={}, nonce={}",
                hex::encode(account_id.as_ref()),
                before,
                after,
                nonce
            );
        }
        self.swarm_commander
            .send(SwarmCommand::PublishTransaction(tx_bytes))
            .await?;
        tracing::debug!(target = "mempool", "gossiped IBC tx to swarm");

        self.idempotency_cache.lock().await.put(msgs_hash, tx_hash);
        Ok(tx_hash)
    }

    async fn commitment_root(&self, height: Option<u64>) -> Result<(Vec<u8>, u64)> {
        let query_height = if let Some(h) = height {
            h
        } else {
            self.workload_client.get_status().await?.height
        };

        let block = self
            .workload_client
            .get_block_by_height(query_height)
            .await?
            .ok_or_else(|| anyhow!("Block at height {} not found", query_height))?;

        Ok((block.header.state_root.0, query_height))
    }
}
