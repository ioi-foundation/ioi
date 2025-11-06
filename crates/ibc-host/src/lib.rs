// Path: crates/ibc-host/src/lib.rs
#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use ioi_client::WorkloadClient;
use ibc_core_host_types::path::NextClientSequencePath;
use ibc_proto::ics23::CommitmentProof;
use ioi_api::state::Verifier;
use ioi_crypto::algorithms::hash::sha256;
use ioi_networking::libp2p::SwarmCommand;
use ioi_state::primitives::hash::HashProof; // NEW
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
        pub version: u64,
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
use iavl_wire::{ExistenceProof, IavlProof, InnerOp, LeafOp, NonExistenceProof, Side};

// ✅ Use the re-exported provider (module `host_functions` is private)
use ics23::HostFunctionsManager;

#[derive(Debug, Clone)]
pub struct QueryHostResponse {
    pub value: Vec<u8>,
    pub proof: Option<Vec<u8>>,
    pub height: u64,
}

#[async_trait]
pub trait IbcHost: Send + Sync {
    async fn query(
        &self,
        path: &str,
        height: Option<u64>,
        latest: bool,
    ) -> Result<QueryHostResponse>;
    async fn submit_ibc_messages(&self, msgs_pb: Vec<u8>) -> Result<[u8; 32]>;
    async fn commitment_root(&self, height: Option<u64>, latest: bool) -> Result<(Vec<u8>, u64)>;
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
fn hash_leaf_canonical(leaf: &LeafOp, key: &[u8], value: &[u8]) -> Result<[u8; 32]> {
    let mut data = Vec::with_capacity(1 + 8 + 4 + 8 + 4 + key.len() + 4 + value.len());
    data.push(0x00);
    data.extend_from_slice(&leaf.version.to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes()); // height
    data.extend_from_slice(&1u64.to_le_bytes()); // size
    data.extend_from_slice(&(key.len() as u32).to_le_bytes());
    data.extend_from_slice(key);
    data.extend_from_slice(&(value.len() as u32).to_le_bytes());
    data.extend_from_slice(value);
    sha256(&data).map_err(|e| anyhow!("sha256: {e}"))
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
            Side::Left => (acc, step.sibling_hash),
            Side::Right => (step.sibling_hash, acc),
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
fn compute_root_from_proof_bytes(proof_pb: &[u8]) -> Result<Vec<u8>> {
    // [00] Peel outer HashProof wrapper first (IAVLTree<HashCommitmentScheme>)
    if let Ok(hp) = codec::from_bytes_canonical::<HashProof>(proof_pb) {
        // The actual IAVL/ICS‑23 payload lives in hp.value
        return compute_root_from_proof_bytes(&hp.value);
    }

    // [00] Peel SCALE(Vec<u8>) wrapper and recurse: the inner may be IAVL *or* ICS‑23/ProofOps/JSON.
    if let Ok(inner) = codec::from_bytes_canonical::<Vec<u8>>(proof_pb) {
        // Try IAVL first on the inner
        if let Some(root) = root_from_scale_iavl_bytes(&inner) {
            return Ok(root);
        }
        // Then recurse to reuse all other decoders (ICS‑23, ProofOps, JSON, etc.)
        if let Ok(root) = compute_root_from_proof_bytes(&inner) {
            return Ok(root);
        }
    }

    // [01] Peel 0x‑prefixed hex and recurse
    if let Ok(s) = std::str::from_utf8(proof_pb) {
        if let Some(stripped) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            if stripped.len() % 2 == 0 && stripped.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Ok(raw) = hex::decode(stripped) {
                    return compute_root_from_proof_bytes(&raw);
                }
            }
        }
    }

    // [+] ADDED: First, try the native SCALE/IAVL format.
    if let Some(root) = root_from_scale_iavl_bytes(proof_pb) {
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
        PbProofVariant::Exist(ex) => ex,

        PbProofVariant::Batch(b) => {
            // Take the first Existence entry
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
            // Reconstruct the first ExistenceProof from compressed form.
            let first = c
                .entries
                .get(0)
                .ok_or_else(|| anyhow!("compressed proof missing entries"))?;

            let comp_exist = match &first.proof {
                Some(compressed_batch_entry::Proof::Exist(ex)) => ex,
                _ => return Err(anyhow!("first compressed entry is not existence proof")),
            };

            // Build the path by mapping indices into lookup_inners.
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

    // Convert prost proof -> native ics23 proof, then compute the root.
    let ex_native: ics23::ExistenceProof = ex_pb
        .try_into()
        .map_err(|_| anyhow!("convert prost ExistenceProof -> native ics23::ExistenceProof"))?;

    // ✅ Specify the host functions provider and convert to Vec<u8>
    ics23::calculate_existence_root::<HostFunctionsManager>(&ex_native)
        .map(|r| r.to_vec())
        .map_err(|e| anyhow!("calculate_existence_root: {e}"))
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
    async fn query(
        &self,
        path: &str,
        height: Option<u64>,
        latest: bool,
    ) -> Result<QueryHostResponse> {
        if (height.is_some() && latest) || (height.is_none() && !latest) {
            return Err(anyhow!(
                "Exactly one of 'height' or 'latest' must be specified"
            ));
        }

        let (query_height, state_root) = if latest {
            let status = self.workload_client.get_status().await?;
            let root = self.workload_client.get_state_root().await?;
            (status.height, root)
        } else {
            let h = height.unwrap();
            let header = self
                .workload_client
                .get_block_by_height(h)
                .await?
                .ok_or_else(|| anyhow!("Block at height {} not found", h))?;
            (h, header.state_root)
        };

        let response = self
            .workload_client
            .query_state_at(state_root, path.as_bytes())
            .await?;

        Ok(QueryHostResponse {
            value: response.membership.into_option().unwrap_or_default(),
            proof: Some(response.proof_bytes),
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

    async fn commitment_root(&self, height: Option<u64>, latest: bool) -> Result<(Vec<u8>, u64)> {
        let path = NextClientSequencePath.to_string();
        let query_response = self.query(&path, height, latest).await?;
        let proof_bytes = query_response
            .proof
            .ok_or_else(|| anyhow!("commitment_root: query for known path returned no proof"))?;
        let root = compute_root_from_proof_bytes(&proof_bytes)?;
        Ok((root, query_response.height))
    }
}
