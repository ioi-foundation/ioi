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
        SignatureProof, SignatureSuite, StateRoot, SystemPayload, SystemTransaction,
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

/// The height an IBC query or commitment root is served at: the caller's height, or else the
/// latest COMMITTED (Agentgres-admitted) height, never the durable status, which counts signed but
/// uncommitted blocks (FU-N11-DURABLE-STATUS-1 D2a, C5). Since D2a RED-4 the anchor resolution
/// below runs `ioi_api::chain::committed_query_anchor`, which inlines this same rule, so only this
/// crate's tests still call it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn resolve_query_height(
    client: &(dyn WorkloadClientApi + '_),
    height: Option<u64>,
) -> Result<u64> {
    match height {
        Some(height) => Ok(height),
        None => Ok(client.get_committed_status().await?.height),
    }
}

/// The state root and height an IBC query or commitment root is served at (FU-N11-DURABLE-STATUS-1
/// D2a round 2, C5; both `query` and `commitment_root` go through it). For "latest", the
/// COMMITTED tip's root as the workload's admitted-tip marker holds it, never a re-read of the
/// block stored at that height. Before any admission (no tip) and for an explicit height, the
/// root of the block stored at the resolved height (the committed height 0, genesis, before the
/// first admission). FU-N11-DURABLE-STATUS-1 D2a RED-4: the logic MOVED unchanged to
/// `ioi_api::chain::committed_query_anchor` (the admitted-index harness reads C5 through it); the
/// one visible difference is the not-found error's text, now prefixed by ChainError's display.
pub(crate) async fn resolve_query_anchor(
    client: &(dyn WorkloadClientApi + '_),
    height: Option<u64>,
) -> Result<(StateRoot, u64)> {
    Ok(ioi_api::chain::committed_query_anchor(client, height).await?)
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
        let (query_root, query_height) =
            resolve_query_anchor(self.workload_client.as_ref(), height).await?;

        let ns_prefix = service_namespace_prefix("ibc");
        let full_key = [ns_prefix.as_slice(), path.as_bytes()].concat();

        let response = self
            .workload_client
            .query_state_at(query_root, &full_key)
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
        let (query_root, query_height) =
            resolve_query_anchor(self.workload_client.as_ref(), height).await?;
        Ok((query_root.0, query_height))
    }
}

#[cfg(test)]
mod committed_height_tests {
    //! FU-N11-DURABLE-STATUS-1 D2a RED-C5: the IBC host serves "latest" at the COMMITTED height.
    use super::{resolve_query_anchor, resolve_query_height};
    use ioi_api::storage::AdmittedTip;
    use ioi_api::chain::{BlockExecutionReceipt, QueryStateResponse, WorkloadClientApi};
    use ioi_types::app::{AccountId, Block, ChainStatus, ChainTransaction, StateAnchor, StateRoot};
    use ioi_types::error::ChainError;

    /// Polls a future that completes without waking (the client below never awaits I/O).
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(output) => output,
            std::task::Poll::Pending => panic!("the status-only client never pends"),
        }
    }

    fn unused<T>() -> Result<T, ChainError> {
        Err(ChainError::Transaction("unused by the status-only client".into()))
    }

    /// A workload client whose durable status (`get_status`) runs ahead of its committed status.
    #[derive(Debug)]
    struct StatusOnlyClient {
        durable: u64,
        committed: u64,
    }

    #[async_trait::async_trait]
    impl WorkloadClientApi for StatusOnlyClient {
        async fn process_block(
            &self,
            _block: Block<ChainTransaction>,
        ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>, Vec<BlockExecutionReceipt>), ChainError>
        {
            unused()
        }
        async fn get_blocks_range(
            &self,
            _since: u64,
            _max_blocks: u32,
            _max_bytes: u32,
        ) -> Result<Vec<Block<ChainTransaction>>, ChainError> {
            unused()
        }
        async fn get_block_by_height(
            &self,
            _height: u64,
        ) -> Result<Option<Block<ChainTransaction>>, ChainError> {
            unused()
        }
        async fn check_transactions_at(
            &self,
            _anchor: StateAnchor,
            _expected_timestamp_secs: u64,
            _txs: Vec<ChainTransaction>,
        ) -> Result<Vec<Result<(), String>>, ChainError> {
            unused()
        }
        async fn query_state_at(
            &self,
            _root: StateRoot,
            _key: &[u8],
        ) -> Result<QueryStateResponse, ChainError> {
            unused()
        }
        async fn query_raw_state(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
            unused()
        }
        async fn prefix_scan(&self, _prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ChainError> {
            unused()
        }
        async fn get_staked_validators(
            &self,
        ) -> Result<std::collections::BTreeMap<AccountId, u64>, ChainError> {
            unused()
        }
        async fn get_genesis_status(&self) -> Result<bool, ChainError> {
            unused()
        }
        async fn update_block_header(&self, _block: Block<ChainTransaction>) -> Result<(), ChainError> {
            unused()
        }
        async fn get_state_root(&self) -> Result<StateRoot, ChainError> {
            unused()
        }
        async fn get_status(&self) -> Result<ChainStatus, ChainError> {
            Ok(ChainStatus {
                height: self.durable,
                ..Default::default()
            })
        }
        async fn get_committed_status(&self) -> Result<ChainStatus, ChainError> {
            Ok(ChainStatus {
                height: self.committed,
                ..Default::default()
            })
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn an_ibc_query_without_a_height_is_served_at_the_committed_height() {
        let client = StatusOnlyClient {
            durable: 9,
            committed: 4,
        };
        assert_eq!(
            block_on(resolve_query_height(&client, None)).expect("latest height"),
            4
        );
        assert_eq!(
            block_on(resolve_query_height(&client, Some(7))).expect("explicit height"),
            7,
            "an explicit height is served as asked"
        );
    }

    // --- D2a round 2 (RED-3), B1 (i): "latest" is anchored at the MARKER's root -----------------

    /// The block a workload stores at `height` with root `[root; 32]`.
    fn stored_block(height: u64, root: u8) -> Block<ChainTransaction> {
        use ioi_types::app::{BlockHeader, QuorumCertificate, SignatureSuite};
        Block {
            header: BlockHeader {
                height,
                view: 0,
                parent_hash: [1; 32],
                parent_state_root: StateRoot(vec![2; 32]),
                state_root: StateRoot(vec![root; 32]),
                transactions_root: vec![3; 32],
                timestamp: 1_700_000_000 + height,
                timestamp_ms: (1_700_000_000 + height) * 1_000,
                gas_used: 0,
                validator_set: vec![vec![4; 32]],
                producer_account_id: AccountId([5; 32]),
                producer_key_suite: SignatureSuite::ED25519,
                producer_pubkey_hash: [6; 32],
                producer_pubkey: vec![7; 32],
                oracle_counter: 0,
                oracle_trace_hash: [0; 32],
                guardian_certificate: None,
                sealed_finality_proof: None,
                canonical_order_certificate: None,
                timeout_certificate: None,
                aft_timeout_certificate: None,
                parent_qc: QuorumCertificate::default(),
                previous_canonical_collapse_commitment_hash: [0; 32],
                canonical_collapse_extension_certificate: None,
                publication_frontier: None,
                signature: Vec::new(),
            },
            transactions: Vec::new(),
        }
    }

    /// A workload whose block at the admitted height 3 was REWRITTEN after admission (its stored
    /// root is 0xB4, e.g. height 4's uncommitted root) while its admitted-tip marker still holds
    /// the admitted root 0xA3. Every other stored height h has root h.
    #[derive(Debug)]
    struct RewrittenStoreClient;

    const ADMITTED_HEIGHT: u64 = 3;

    #[async_trait::async_trait]
    impl WorkloadClientApi for RewrittenStoreClient {
        async fn process_block(
            &self,
            _block: Block<ChainTransaction>,
        ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>, Vec<BlockExecutionReceipt>), ChainError>
        {
            unused()
        }
        async fn get_blocks_range(
            &self,
            _since: u64,
            _max_blocks: u32,
            _max_bytes: u32,
        ) -> Result<Vec<Block<ChainTransaction>>, ChainError> {
            unused()
        }
        async fn get_block_by_height(
            &self,
            height: u64,
        ) -> Result<Option<Block<ChainTransaction>>, ChainError> {
            let root = if height == ADMITTED_HEIGHT { 0xB4 } else { height as u8 };
            Ok(Some(stored_block(height, root)))
        }
        async fn check_transactions_at(
            &self,
            _anchor: StateAnchor,
            _expected_timestamp_secs: u64,
            _txs: Vec<ChainTransaction>,
        ) -> Result<Vec<Result<(), String>>, ChainError> {
            unused()
        }
        async fn query_state_at(
            &self,
            _root: StateRoot,
            _key: &[u8],
        ) -> Result<QueryStateResponse, ChainError> {
            unused()
        }
        async fn query_raw_state(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
            unused()
        }
        async fn prefix_scan(&self, _prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ChainError> {
            unused()
        }
        async fn get_staked_validators(
            &self,
        ) -> Result<std::collections::BTreeMap<AccountId, u64>, ChainError> {
            unused()
        }
        async fn get_genesis_status(&self) -> Result<bool, ChainError> {
            unused()
        }
        async fn update_block_header(&self, _block: Block<ChainTransaction>) -> Result<(), ChainError> {
            unused()
        }
        async fn get_state_root(&self) -> Result<StateRoot, ChainError> {
            unused()
        }
        async fn get_status(&self) -> Result<ChainStatus, ChainError> {
            Ok(ChainStatus {
                height: 9,
                ..Default::default()
            })
        }
        async fn get_committed_status(&self) -> Result<ChainStatus, ChainError> {
            Ok(ChainStatus {
                height: ADMITTED_HEIGHT,
                ..Default::default()
            })
        }
        async fn get_committed_tip(&self) -> Result<Option<AdmittedTip>, ChainError> {
            Ok(Some(AdmittedTip {
                height: ADMITTED_HEIGHT,
                block_hash: [0xA3; 32],
                state_root: vec![0xA3; 32],
            }))
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// RED-3 (fails at 079937616: "latest" re-reads the block stored at the committed height,
    /// lib.rs:237-250 (query) and :332-340 (commitment_root); resolve_query_anchor keeps that at
    /// RED-3). The IBC
    /// host's latest query and commitment root are anchored at the admitted marker's root even
    /// after the stored block at that height changed.
    #[test]
    fn the_latest_ibc_anchor_is_the_marker_root_after_the_stored_block_changes() {
        assert_eq!(
            block_on(resolve_query_anchor(&RewrittenStoreClient, None)).expect("latest anchor"),
            (StateRoot(vec![0xA3; 32]), ADMITTED_HEIGHT),
            "the committed root is the marker's, never a re-read of mutable block storage"
        );
    }

    /// CONTROL (passes at RED-3): an explicit height is anchored at that stored block, as asked.
    #[test]
    fn an_explicit_ibc_height_is_anchored_at_that_stored_block() {
        assert_eq!(
            block_on(resolve_query_anchor(&RewrittenStoreClient, Some(2))).expect("explicit anchor"),
            (StateRoot(vec![2; 32]), 2)
        );
    }
}
