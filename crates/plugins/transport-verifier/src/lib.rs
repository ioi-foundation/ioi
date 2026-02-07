// Path: crates/ibc-host/src/lib.rs
#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use ibc_proto::ics23::CommitmentProof;
use ioi_api::chain::WorkloadClientApi;
use ioi_api::state::{service_namespace_prefix, Verifier};
use ioi_client::WorkloadClient;
use ioi_networking::libp2p::SwarmCommand;
use ioi_state::tree::iavl::{self, IavlProof};
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

// Import for MerkleProof decoding
use ibc_proto::ibc::core::commitment::v1::MerkleProof as PbMerkleProof;
use ioi_crypto::algorithms::hash::sha256;

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

/// A trait for submitting transactions to the node's mempool.
/// This decouples `ibc-host` from the concrete `Mempool` implementation in `ioi-validator`.
#[async_trait]
pub trait TransactionPool: Send + Sync {
    async fn add(&self, tx: ChainTransaction) -> Result<()>;
}

// ... [Proof decoding helpers unchanged] ...

/// Decodes an IavlProof from bytes that might be wrapped in a `Vec<u8>` envelope (SCALE).
fn decode_scale_iavl_proof(bytes: &[u8]) -> Option<IavlProof> {
    if let Ok(inner) = codec::from_bytes_canonical::<Vec<u8>>(bytes) {
        if let Ok(p) = IavlProof::decode(&mut &*inner) {
            return Some(p);
        }
    }
    IavlProof::decode(&mut &*bytes).ok()
}

/// Extracts the root hash from a native IAVL proof.
fn root_from_scale_iavl_bytes(proof_bytes: &[u8]) -> Option<Vec<u8>> {
    let p = decode_scale_iavl_proof(proof_bytes)?;
    let root_arr = iavl::proof::compute_root_from_proof(&p).ok()?;
    Some(root_arr.to_vec())
}

/// Helper to compute the Merkle root from a raw ICS23 proof (prost bytes).
pub fn existence_root_from_proof_bytes(proof_pb: &[u8]) -> Result<Vec<u8>> {
    let mut input_variant = "unknown";
    let result = (|| {
        // 1. Attempt to decode as a native IAVL proof first (fast path for internal services).
        if let Some(root) = root_from_scale_iavl_bytes(proof_pb) {
            input_variant = "scale_native";
            return Ok(root);
        }

        // 2. Try decoding as a MerkleProof (standard IBC format from gateway).
        if let Ok(mp) = PbMerkleProof::decode(proof_pb) {
            if !mp.proofs.is_empty() {
                input_variant = "raw(merkle_proof)";
                // Use the first proof in the path.
                let first_cp = &mp.proofs[0];
                return compute_root_from_commitment_proof(first_cp);
            }
        }

        // 3. Fallback to standard ICS-23 CommitmentProof decoding (direct).
        let cp: CommitmentProof =
            CommitmentProof::decode(proof_pb).context("decode ICS-23 CommitmentProof")?;
        input_variant = "raw(commitment_proof)";
        compute_root_from_commitment_proof(&cp)
    })();

    tracing::debug!(
        target: "ibc.proof",
        event = "root_recompute",
        input_variant = %input_variant,
        proof_len = proof_pb.len(),
        result = if result.is_ok() { "ok" } else { "err" },
        root_len = result.as_ref().map(|r| r.len()).unwrap_or(0),
    );

    result
}

// Helper to share logic between MerkleProof unwrapping and direct CommitmentProof handling.
fn compute_root_from_commitment_proof(cp: &CommitmentProof) -> Result<Vec<u8>> {
    use ibc_proto::ics23::batch_entry;
    use ibc_proto::ics23::commitment_proof::Proof as PbProofVariant;
    use ibc_proto::ics23::compressed_batch_entry;
    use ibc_proto::ics23::ExistenceProof as PbExistenceProof;

    let ex_pb: PbExistenceProof = match cp
        .proof
        .as_ref()
        .ok_or_else(|| anyhow!("empty ICS-23 proof"))?
    {
        PbProofVariant::Exist(ex) => ex.clone(),
        PbProofVariant::Batch(b) => b
            .entries
            .iter()
            .find_map(|entry| match &entry.proof {
                Some(batch_entry::Proof::Exist(ex)) => Some(ex.clone()),
                _ => None,
            })
            .ok_or_else(|| anyhow!("batch proof missing existence entry"))?,
        PbProofVariant::Compressed(c) => {
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

    if ex_native.key.is_empty() {
        return Err(anyhow!("Existence proof key is empty"));
    }

    ics23::calculate_existence_root::<HostFunctionsManager>(&ex_native)
        .map(|r| r.to_vec())
        .map_err(|e| anyhow!("calculate_existence_root: {e}"))
}

pub struct DefaultIbcHost<V: Verifier> {
    workload_client: Arc<WorkloadClient>,
    _verifier: V,
    tx_pool: Arc<dyn TransactionPool>,
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
        tx_pool: Arc<dyn TransactionPool>,
        swarm_commander: mpsc::Sender<SwarmCommand>,
        signer: Keypair,
        nonce_manager: Arc<Mutex<BTreeMap<AccountId, u64>>>,
        chain_id: ChainId,
    ) -> Self {
        tracing::debug!(
            target: "mempool",
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

        let ns_prefix = service_namespace_prefix("ibc");
        let full_key = [ns_prefix.as_slice(), path.as_bytes()].concat();

        let response = self
            .workload_client
            .query_state_at(block.header.state_root, &full_key)
            .await?;

        use ioi_state::primitives::hash::HashProof;
        use ioi_types::codec::from_bytes_canonical;

        let canonical_proof_bytes = from_bytes_canonical::<HashProof>(&response.proof_bytes)
            .map(|hash_proof| hash_proof.value)
            .map_err(|e| anyhow!("Failed to unwrap HashProof from workload: {}", e))?;

        Ok(QueryHostResponse {
            value: response.membership.into_option().unwrap_or_default(),
            proof: Some(canonical_proof_bytes),
            height: query_height,
        })
    }

    async fn submit_ibc_messages(&self, msgs_pb: Vec<u8>) -> Result<[u8; 32]> {
        let msgs_hash = sha256(&msgs_pb)?;
        if let Some(tx_hash) = self.idempotency_cache.lock().await.get(&msgs_hash) {
            return Ok(*tx_hash);
        }

        let account_id = AccountId(account_id_from_key_material(
            SignatureSuite::ED25519,
            &self.signer.public().encode_protobuf(),
        )?);

        let nonce = {
            let mut manager = self.nonce_manager.lock().await;
            let n = manager.entry(account_id).or_insert(0);
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
                session_auth: None, // [FIX] Initialize session_auth
            },
            payload: SystemPayload::CallService {
                service_id: "ibc".to_string(),
                method: "msg_dispatch@v1".to_string(),
                params: msgs_pb,
            },
            signature_proof: SignatureProof::default(),
        }));

        let (signed_tx, tx_bytes) = {
            if let ChainTransaction::System(mut sys_tx) = tx {
                let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
                sys_tx.signature_proof = SignatureProof {
                    suite: SignatureSuite::ED25519,
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

        let tx_hash = signed_tx.hash().map_err(|e| anyhow!(e))?;

        self.tx_pool.add(signed_tx).await?;

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
