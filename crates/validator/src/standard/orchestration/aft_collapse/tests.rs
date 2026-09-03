use super::*;
use async_trait::async_trait;
use ioi_api::app::ChainStatus;
use ioi_api::chain::{AnchoredStateView, ChainView, QueryStateResponse};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::{ConsensusControl, ConsensusDecision, PenaltyMechanism};
use ioi_api::state::{StateAccess, StateManager};
use ioi_types::app::{
    canonical_collapse_commitment, canonical_collapse_commitment_hash_from_object,
    canonical_collapse_continuity_public_inputs, canonical_collapse_extension_certificate,
    canonical_collapse_recursive_proof_hash,
    set_canonical_collapse_archived_recovered_history_anchor, AccountId, BlockHeader,
    CanonicalCollapseContinuityProofSystem, CanonicalCollapseExtensionCertificate, ConsensusVote,
    FailureReport, QuorumCertificate, SignatureSuite, StateAnchor, StateRoot,
};
use ioi_types::error::{ChainError, ConsensusError, TransactionError};
use libp2p::PeerId;
use std::any::Any;
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;
use zk_driver_succinct::simulated_continuity_proof_bytes;

#[derive(Debug, Default)]
struct TestWorkloadClient {
    raw_state: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
    blocks: Mutex<BTreeMap<u64, Block<ChainTransaction>>>,
    raw_state_reads: AtomicUsize,
    block_reads: AtomicUsize,
}

impl TestWorkloadClient {
    async fn seed_collapse(&self, collapse: &CanonicalCollapseObject) {
        self.raw_state.lock().await.insert(
            aft_canonical_collapse_object_key(collapse.height),
            codec::to_bytes_canonical(collapse).expect("encode collapse"),
        );
    }

    async fn seed_block(&self, block: &Block<ChainTransaction>) {
        let mut blocks = self.blocks.lock().await;
        blocks.insert(block.header.height, block.clone());
    }

    fn reset_read_counts(&self) {
        self.raw_state_reads.store(0, Ordering::Relaxed);
        self.block_reads.store(0, Ordering::Relaxed);
    }

    fn raw_state_reads(&self) -> usize {
        self.raw_state_reads.load(Ordering::Relaxed)
    }

    fn block_reads(&self) -> usize {
        self.block_reads.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl WorkloadClientApi for TestWorkloadClient {
    async fn process_block(
        &self,
        _block: Block<ChainTransaction>,
    ) -> std::result::Result<
        (
            Block<ChainTransaction>,
            Vec<Vec<u8>>,
            Vec<ioi_api::chain::BlockExecutionReceipt>,
        ),
        ChainError,
    > {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_blocks_range(
        &self,
        _since: u64,
        _max_blocks: u32,
        _max_bytes: u32,
    ) -> std::result::Result<Vec<Block<ChainTransaction>>, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_block_by_height(
        &self,
        height: u64,
    ) -> std::result::Result<Option<Block<ChainTransaction>>, ChainError> {
        self.block_reads.fetch_add(1, Ordering::Relaxed);
        Ok(self.blocks.lock().await.get(&height).cloned())
    }

    async fn check_transactions_at(
        &self,
        _anchor: StateAnchor,
        _expected_timestamp_secs: u64,
        _txs: Vec<ChainTransaction>,
    ) -> std::result::Result<Vec<std::result::Result<(), String>>, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn query_state_at(
        &self,
        _root: StateRoot,
        _key: &[u8],
    ) -> std::result::Result<QueryStateResponse, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn query_raw_state(
        &self,
        key: &[u8],
    ) -> std::result::Result<Option<Vec<u8>>, ChainError> {
        self.raw_state_reads.fetch_add(1, Ordering::Relaxed);
        Ok(self.raw_state.lock().await.get(key).cloned())
    }

    async fn prefix_scan(
        &self,
        _prefix: &[u8],
    ) -> std::result::Result<Vec<(Vec<u8>, Vec<u8>)>, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_staked_validators(
        &self,
    ) -> std::result::Result<BTreeMap<AccountId, u64>, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_genesis_status(&self) -> std::result::Result<bool, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn update_block_header(
        &self,
        _block: Block<ChainTransaction>,
    ) -> std::result::Result<(), ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_state_root(&self) -> std::result::Result<StateRoot, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    async fn get_status(&self) -> std::result::Result<ChainStatus, ChainError> {
        Err(ChainError::ExecutionClient("unused in tests".into()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Minimal consensus engine that only implements the committed-collapse memory
/// the live observation path actually consults, so query-count behaviour can be
/// measured against the real function rather than a re-implementation.
#[derive(Debug, Default)]
struct TestConsensusEngine {
    committed_collapses: BTreeMap<u64, CanonicalCollapseObject>,
    observed_heights: Vec<u64>,
}

#[async_trait]
impl PenaltyMechanism for TestConsensusEngine {
    async fn apply_penalty(
        &self,
        _state: &mut dyn StateAccess,
        _report: &FailureReport,
    ) -> std::result::Result<(), TransactionError> {
        Ok(())
    }
}

impl ConsensusControl for TestConsensusEngine {
    fn experimental_sample_tip(&self) -> Option<([u8; 32], u32)> {
        None
    }

    fn observe_experimental_sample(&mut self, _hash: [u8; 32]) {}
}

#[async_trait]
impl ConsensusEngine<ChainTransaction> for TestConsensusEngine {
    async fn decide(
        &mut self,
        _our_account_id: &AccountId,
        _height: u64,
        _view: u64,
        _parent_view: &dyn AnchoredStateView,
        _known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<ChainTransaction> {
        ConsensusDecision::Stall
    }

    async fn handle_block_proposal<CS, ST>(
        &mut self,
        _block: Block<ChainTransaction>,
        _chain_view: &dyn ChainView<CS, ST>,
    ) -> std::result::Result<(), ConsensusError>
    where
        CS: CommitmentScheme + Send + Sync,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
        Ok(())
    }

    async fn handle_vote(
        &mut self,
        _vote: ConsensusVote,
    ) -> std::result::Result<(), ConsensusError> {
        Ok(())
    }

    async fn handle_view_change(
        &mut self,
        _from: PeerId,
        _proof_bytes: &[u8],
    ) -> std::result::Result<(), ConsensusError> {
        Ok(())
    }

    fn observe_committed_block(
        &mut self,
        header: &BlockHeader,
        collapse: Option<&CanonicalCollapseObject>,
    ) -> bool {
        self.observed_heights.push(header.height);
        if let Some(collapse) = collapse {
            self.committed_collapses
                .insert(header.height, collapse.clone());
        }
        true
    }

    fn canonical_collapse_for_committed_height(
        &self,
        height: u64,
    ) -> Option<CanonicalCollapseObject> {
        self.committed_collapses.get(&height).cloned()
    }

    fn reset(&mut self, _height: u64) {}
}

/// Builds a contiguous, link-correct committed chain of `depth` heights and the
/// canonical collapse object each height collapses to.
fn build_live_chain(depth: u64) -> (Vec<Block<ChainTransaction>>, Vec<CanonicalCollapseObject>) {
    let mut blocks = Vec::new();
    let mut collapses: Vec<CanonicalCollapseObject> = Vec::new();
    for height in 1..=depth {
        let previous = collapses.last().cloned();
        let block = chain_block(height, previous.as_ref());
        let collapse = derive_canonical_collapse_object_with_previous(
            &block.header,
            &block.transactions,
            previous.as_ref(),
        )
        .expect("chain collapse");
        blocks.push(block);
        collapses.push(collapse);
    }
    (blocks, collapses)
}

fn chain_block(height: u64, prior: Option<&CanonicalCollapseObject>) -> Block<ChainTransaction> {
    let mut block = sample_block();
    block.header.height = height;
    block.header.view = height;
    block.header.state_root = StateRoot(vec![height as u8; 32]);
    block.header.transactions_root = vec![(height as u8).wrapping_add(0x80); 32];
    block.header.previous_canonical_collapse_commitment_hash = [0u8; 32];
    block.header.canonical_collapse_extension_certificate = None;
    block.header.canonical_order_certificate = None;
    block.header.canonical_order_certificate = Some(
        ioi_types::app::build_reference_canonical_order_certificate(&block.header, &[])
            .expect("reference order cert"),
    );

    if let Some(prior) = prior {
        let extension =
            canonical_collapse_extension_certificate(height, prior).expect("extension certificate");
        align_block_parent_to_previous_result(&mut block, prior);
        block.header.previous_canonical_collapse_commitment_hash =
            canonical_collapse_commitment_hash_from_object(prior).expect("previous hash");
        block.header.canonical_collapse_extension_certificate = Some(extension);
    }

    block
}

async fn seeded_chain_client(
    blocks: &[Block<ChainTransaction>],
    collapses: &[CanonicalCollapseObject],
) -> TestWorkloadClient {
    let client = TestWorkloadClient::default();
    for block in blocks {
        client.seed_block(block).await;
    }
    for collapse in collapses {
        client.seed_collapse(collapse).await;
    }
    client
}

fn warm_engine(admitted: &[CanonicalCollapseObject]) -> Arc<Mutex<TestConsensusEngine>> {
    let mut engine = TestConsensusEngine::default();
    for collapse in admitted {
        let height = collapse.height;
        engine.committed_collapses.insert(height, collapse.clone());
    }
    Arc::new(Mutex::new(engine))
}

fn sample_block() -> Block<ChainTransaction> {
    let mut header = ioi_types::app::BlockHeader {
        height: 2,
        view: 5,
        parent_hash: [1u8; 32],
        parent_state_root: StateRoot(vec![2u8; 32]),
        state_root: StateRoot(vec![7u8; 32]),
        transactions_root: vec![8u8; 32],
        timestamp: 1_750_000_111,
        timestamp_ms: 1_750_000_111_000,
        gas_used: 33,
        validator_set: vec![vec![6u8; 32]],
        producer_account_id: AccountId([10u8; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [11u8; 32],
        producer_pubkey: vec![12u8; 32],
        signature: vec![13u8; 64],
        oracle_counter: 99,
        oracle_trace_hash: [14u8; 32],
        guardian_certificate: None,
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        timeout_certificate: None,
        aft_timeout_certificate: None,
        parent_qc: QuorumCertificate::default(),
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
    };
    header.canonical_order_certificate = Some(
        ioi_types::app::build_reference_canonical_order_certificate(&header, &[])
            .expect("reference order cert"),
    );

    Block {
        header,
        transactions: Vec::new(),
    }
}

/// Relabels a collapse object's continuity proof as `SuccinctSp1V1`, carrying
/// the zk plugin's own simulated recipe bytes. The kernel no longer defines
/// any mock succinct bytes (AFT-CB P0.3): the types-level verifier rejects
/// every succinct-labeled proof until a real backend lands (R4c), so this
/// helper is only useful to (a) exercise the backend ROUTING directly and
/// (b) prove the reservation rejection on persisted paths.
fn bind_simulated_succinct_continuity(collapse: &mut CanonicalCollapseObject) {
    let proof = &mut collapse.continuity_recursive_proof;
    let public_inputs = canonical_collapse_continuity_public_inputs(
        &proof.commitment,
        proof.previous_canonical_collapse_commitment_hash,
        proof.payload_hash,
        proof.previous_recursive_proof_hash,
    );
    proof.proof_system = CanonicalCollapseContinuityProofSystem::SuccinctSp1V1;
    proof.proof_bytes =
        simulated_continuity_proof_bytes(&public_inputs).expect("simulated succinct proof bytes");
}

fn align_block_parent_to_previous_result(
    block: &mut Block<ChainTransaction>,
    previous: &CanonicalCollapseObject,
) {
    block.header.parent_state_root = StateRoot(previous.resulting_state_root_hash.to_vec());
}

#[test]
fn verify_canonical_collapse_backend_refuses_succinct_without_native_backend() {
    // Backend ROUTING: the validator routes SuccinctSp1V1 to the zk
    // driver, which since AFT-CB R4c has NO simulated lane — a build
    // without the native SP1 backend refuses even bytes that satisfy the
    // retired simulated recipe. (This test suite builds the driver
    // non-native.)
    let mut collapse = CanonicalCollapseObject {
        height: 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [1u8; 32],
        resulting_state_root_hash: [2u8; 32],
    };
    ioi_types::app::bind_canonical_collapse_continuity(&mut collapse, None)
        .expect("bind continuity");
    bind_simulated_succinct_continuity(&mut collapse);

    let err = verify_canonical_collapse_backend(&collapse)
        .expect_err("succinct-labeled proof must refuse without the native backend");
    assert!(
        err.to_string().contains("native SP1 backend"),
        "refusal names the missing backend, got: {err}"
    );
}

#[tokio::test]
async fn require_persisted_aft_canonical_collapse_accepts_matching_state() {
    let mut block = sample_block();
    let previous = CanonicalCollapseObject {
        height: block.header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [1u8; 32],
        resulting_state_root_hash: [2u8; 32],
    };
    let mut previous = previous;
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    align_block_parent_to_previous_result(&mut block, &previous);
    block.header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
    block.header.canonical_collapse_extension_certificate = Some(
        canonical_collapse_extension_certificate(block.header.height, &previous)
            .expect("extension certificate"),
    );
    let collapse = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        Some(&previous),
    )
    .expect("collapse");
    let previous_key = aft_canonical_collapse_object_key(previous.height);
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        previous_key,
        codec::to_bytes_canonical(&previous).expect("encode previous"),
    );
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&collapse).expect("encode collapse"),
    );

    let loaded = require_persisted_aft_canonical_collapse_for_block(&client, &block)
        .await
        .expect("persisted collapse");
    assert_eq!(loaded, collapse);
}

#[tokio::test]
async fn require_persisted_aft_canonical_collapse_accepts_archived_anchor_upgrade() {
    let mut block = sample_block();
    let previous = CanonicalCollapseObject {
        height: block.header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [0x21u8; 32],
        resulting_state_root_hash: [0x22u8; 32],
    };
    let mut previous = previous;
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    align_block_parent_to_previous_result(&mut block, &previous);
    block.header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
    block.header.canonical_collapse_extension_certificate = Some(
        canonical_collapse_extension_certificate(block.header.height, &previous)
            .expect("extension certificate"),
    );
    let derived = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        Some(&previous),
    )
    .expect("collapse");
    let mut persisted = derived.clone();
    set_canonical_collapse_archived_recovered_history_anchor(
        &mut persisted,
        [0x31u8; 32],
        [0x32u8; 32],
        [0x33u8; 32],
    )
    .expect("anchor upgrade");
    let previous_key = aft_canonical_collapse_object_key(previous.height);
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        previous_key,
        codec::to_bytes_canonical(&previous).expect("encode previous"),
    );
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&persisted).expect("encode collapse"),
    );

    let loaded = require_persisted_aft_canonical_collapse_for_block(&client, &block)
        .await
        .expect("persisted collapse");
    assert_eq!(loaded, persisted);
}

#[tokio::test]
async fn require_persisted_aft_canonical_collapse_rejects_corrupted_previous_chain() {
    // The persisted predecessor chain is HashPcdV1; corrupting the persisted
    // predecessor's proof bytes must fail durable-state advancement.
    let mut block = sample_block();
    let previous = CanonicalCollapseObject {
        height: block.header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [5u8; 32],
        resulting_state_root_hash: [6u8; 32],
    };
    let mut previous = previous;
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    align_block_parent_to_previous_result(&mut block, &previous);
    block.header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
    block.header.canonical_collapse_extension_certificate = Some(
        canonical_collapse_extension_certificate(block.header.height, &previous)
            .expect("extension certificate"),
    );
    let collapse = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        Some(&previous),
    )
    .expect("collapse");
    let mut corrupted_previous = previous.clone();
    corrupted_previous.continuity_recursive_proof.proof_bytes[0] ^= 0xFF;

    let previous_key = aft_canonical_collapse_object_key(previous.height);
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        previous_key,
        codec::to_bytes_canonical(&corrupted_previous).expect("encode previous"),
    );
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&collapse).expect("encode collapse"),
    );

    let error = require_persisted_aft_canonical_collapse_for_block(&client, &block)
        .await
        .expect_err("corrupted predecessor chain should fail");
    assert!(
        error
            .to_string()
            .contains("canonical collapse proof bytes mismatch"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn require_persisted_aft_canonical_collapse_rejects_mismatch() {
    let mut block = sample_block();
    let previous = CanonicalCollapseObject {
        height: block.header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [1u8; 32],
        resulting_state_root_hash: [2u8; 32],
    };
    let mut previous = previous;
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    block.header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
    block.header.canonical_collapse_extension_certificate = Some(
        canonical_collapse_extension_certificate(block.header.height, &previous)
            .expect("extension certificate"),
    );
    let mut collapse = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        Some(&previous),
    )
    .expect("collapse");
    collapse.resulting_state_root_hash = [42u8; 32];
    ioi_types::app::bind_canonical_collapse_continuity(&mut collapse, Some(&previous))
        .expect("rebind mutated collapse continuity");
    let previous_key = aft_canonical_collapse_object_key(previous.height);
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        previous_key,
        codec::to_bytes_canonical(&previous).expect("encode previous"),
    );
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&collapse).expect("encode collapse"),
    );

    let error = require_persisted_aft_canonical_collapse_for_block(&client, &block)
        .await
        .expect_err("mismatched collapse should fail");
    assert!(
        error
            .to_string()
            .contains("persisted canonical collapse object does not match"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn require_persisted_aft_canonical_collapse_rejects_missing_previous_link() {
    let block = sample_block();
    let collapse = CanonicalCollapseObject {
        height: block.header.height,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [9u8; 32],
        resulting_state_root_hash: [10u8; 32],
    };
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&collapse).expect("encode collapse"),
    );

    let error = require_persisted_aft_canonical_collapse_for_block(&client, &block)
        .await
        .expect_err("missing previous continuity link should fail");
    assert!(
        error
            .to_string()
            .contains("missing persisted canonical collapse object for height 1"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn resolve_live_aft_canonical_collapse_accepts_archived_anchor_upgrade() {
    let mut block = sample_block();
    let previous = CanonicalCollapseObject {
        height: block.header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [0x41u8; 32],
        resulting_state_root_hash: [0x42u8; 32],
    };
    let mut previous = previous;
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    align_block_parent_to_previous_result(&mut block, &previous);
    block.header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
    block.header.canonical_collapse_extension_certificate = Some(
        canonical_collapse_extension_certificate(block.header.height, &previous)
            .expect("extension certificate"),
    );
    let mut persisted = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        Some(&previous),
    )
    .expect("collapse");
    set_canonical_collapse_archived_recovered_history_anchor(
        &mut persisted,
        [0x51u8; 32],
        [0x52u8; 32],
        [0x53u8; 32],
    )
    .expect("anchor upgrade");
    let previous_key = aft_canonical_collapse_object_key(previous.height);
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        previous_key,
        codec::to_bytes_canonical(&previous).expect("encode previous"),
    );
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&persisted).expect("encode collapse"),
    );

    let resolved = resolve_live_aft_canonical_collapse_for_block(
        ConsensusType::Aft,
        &client,
        Some(&previous),
        &block,
    )
    .await
    .expect("live collapse");
    assert_eq!(resolved, Some(persisted));
}

#[tokio::test]
async fn require_persisted_aft_canonical_collapse_rejects_succinct_labeled_previous_until_real_backend(
) {
    // AFT-CB R4c: SuccinctSp1V1 is a reserved wire variant. Even a persisted
    // predecessor whose bytes satisfy the zk plugin's simulated recipe (so
    // the backend ROUTING would accept it) must fail durable-state
    // advancement, because the types-level verifier refuses every
    // succinct-labeled proof until a real backend lands. The header links
    // are built manually because the extension-certificate builder itself
    // refuses succinct-labeled predecessors.
    let mut block = sample_block();
    let previous = CanonicalCollapseObject {
        height: block.header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [11u8; 32],
        resulting_state_root_hash: [12u8; 32],
    };
    let mut previous = previous;
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    bind_simulated_succinct_continuity(&mut previous);
    block.header.parent_state_root = StateRoot(previous.resulting_state_root_hash.to_vec());
    block.header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
    block.header.canonical_collapse_extension_certificate =
        Some(CanonicalCollapseExtensionCertificate {
            predecessor_commitment: canonical_collapse_commitment(&previous),
            predecessor_recursive_proof_hash: canonical_collapse_recursive_proof_hash(
                &previous.continuity_recursive_proof,
            )
            .expect("predecessor proof hash"),
        });
    let previous_key = aft_canonical_collapse_object_key(previous.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        previous_key,
        codec::to_bytes_canonical(&previous).expect("encode previous"),
    );

    let error = require_persisted_aft_canonical_collapse_for_block(&client, &block)
        .await
        .expect_err("succinct-labeled predecessor should fail");
    let message = error.to_string();
    assert!(
        // Either refusal layer is the honest outcome (AFT-CB R4c): the
        // types-level reference runtime refuses succinct-labeled proofs
        // it cannot own, and the driver refuses without the native SP1
        // backend. Both are refusals, never a weaker mismatch error.
        message.contains("reserved for a real succinct backend")
            || message.contains("requires the native SP1 backend"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn require_persisted_aft_canonical_collapse_rejects_corrupted_persisted_proof_bytes() {
    // The persisted CURRENT collapse carries corrupted HashPcdV1 proof
    // bytes; the persisted-chain walk must reject it even though the
    // derived expectation itself is valid.
    let mut block = sample_block();
    let previous = CanonicalCollapseObject {
        height: block.header.height - 1,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
        ordering: Default::default(),
        sealing: None,
        transactions_root_hash: [13u8; 32],
        resulting_state_root_hash: [14u8; 32],
    };
    let mut previous = previous;
    ioi_types::app::bind_canonical_collapse_continuity(&mut previous, None)
        .expect("bind previous continuity");
    block.header.parent_state_root = StateRoot(previous.resulting_state_root_hash.to_vec());
    block.header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
    block.header.canonical_collapse_extension_certificate = Some(
        canonical_collapse_extension_certificate(block.header.height, &previous)
            .expect("extension certificate"),
    );
    let collapse = derive_canonical_collapse_object_with_previous(
        &block.header,
        &block.transactions,
        Some(&previous),
    )
    .expect("collapse");
    let mut persisted = collapse.clone();
    persisted.continuity_recursive_proof.proof_bytes.reverse();
    let previous_key = aft_canonical_collapse_object_key(previous.height);
    let key = aft_canonical_collapse_object_key(block.header.height);
    let client = TestWorkloadClient::default();
    client.raw_state.lock().await.insert(
        previous_key,
        codec::to_bytes_canonical(&previous).expect("encode previous"),
    );
    client.raw_state.lock().await.insert(
        key,
        codec::to_bytes_canonical(&persisted).expect("encode collapse"),
    );

    let error = require_persisted_aft_canonical_collapse_for_block(&client, &block)
        .await
        .expect_err("corrupted persisted proof bytes should fail");
    assert!(
        error
            .to_string()
            .contains("persisted canonical collapse continuity verification failed"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn warm_live_observation_reads_are_bounded_independently_of_retained_height() {
    // Steady state: the engine already holds every prior height, so observing
    // the next height must cost a fixed number of reads — one block, the
    // predecessor collapse it reconciles against, and the collapse at the
    // observed height. Re-walking retained history would make this grow with
    // the chain.
    let mut measurements = Vec::new();
    for depth in [4u64, 12u64] {
        let (blocks, collapses) = build_live_chain(depth);
        let client = seeded_chain_client(&blocks, &collapses).await;
        let engine = warm_engine(&collapses[..(depth as usize - 1)]);

        client.reset_read_counts();
        let accepted = observe_live_committed_chain_through_block(
            &engine,
            ConsensusType::Aft,
            &client,
            blocks.last().expect("tip block"),
        )
        .await
        .expect("warm live observation");

        assert!(accepted, "warm observation at depth {depth} rejected");
        let observed = engine.lock().await.observed_heights.clone();
        assert_eq!(observed, vec![depth], "warm over-observed");
        measurements.push((depth, client.raw_state_reads(), client.block_reads()));
    }

    for (depth, raw_state_reads, block_reads) in &measurements {
        // One block, the predecessor collapse, the observed collapse.
        let reads = (*raw_state_reads, *block_reads);
        assert_eq!(reads, (2, 1), "warm depth {depth} reads {reads:?}");
    }
    let warm_reads = measurements[0].1;
    assert_eq!(warm_reads, measurements[1].1, "warm reads grew");
}

#[tokio::test]
async fn cold_live_hydration_reads_scale_linearly_with_depth() {
    // A cold engine has no admitted anchor, so it must hydrate the contiguous
    // chain — but exactly once, verifying each link directly against the link
    // below it. Re-verifying every prefix would make the read count triangular.
    let mut measurements = Vec::new();
    for depth in [4u64, 8u64] {
        let (blocks, collapses) = build_live_chain(depth);
        let client = seeded_chain_client(&blocks, &collapses).await;
        let engine = Arc::new(Mutex::new(TestConsensusEngine::default()));

        client.reset_read_counts();
        let accepted = observe_live_committed_chain_through_block(
            &engine,
            ConsensusType::Aft,
            &client,
            blocks.last().expect("tip block"),
        )
        .await
        .expect("cold live hydration");

        assert!(accepted, "cold hydration at depth {depth} rejected");
        let observed = engine.lock().await.observed_heights.clone();
        let expected_heights = (1..=depth).collect::<Vec<_>>();
        assert_eq!(observed, expected_heights, "cold hydration");
        measurements.push((depth, client.raw_state_reads(), client.block_reads()));
    }

    for (depth, raw_state_reads, block_reads) in &measurements {
        // Height 1 reads only its own collapse; every height above it reads its
        // predecessor and itself. One block read per hydrated height.
        let reads = (*raw_state_reads, *block_reads);
        let expected = ((2 * depth - 1) as usize, *depth as usize);
        assert_eq!(reads, expected, "cold depth {depth} reads {reads:?}");
    }
    let (shallow_depth, shallow_reads, _) = measurements[0];
    let (deep_depth, deep_reads, _) = measurements[1];
    let growth = deep_reads - shallow_reads;
    assert_eq!(growth, 2 * (deep_depth - shallow_depth) as usize);
}

#[tokio::test]
async fn live_observation_refuses_persisted_predecessor_that_diverges_from_admitted_anchor() {
    let (blocks, collapses) = build_live_chain(3);
    let admitted_predecessor = collapses[1].clone();

    // Case 1: same commitment, rewritten recursive proof. A commitment-only
    // boundary comparison would accept this.
    let mut tampered_proof = admitted_predecessor.clone();
    tampered_proof.continuity_recursive_proof.proof_bytes[0] ^= 0xFF;
    let tampered_commitment = canonical_collapse_commitment(&tampered_proof);
    let admitted_commitment = canonical_collapse_commitment(&admitted_predecessor);
    assert_eq!(tampered_commitment, admitted_commitment);

    // Case 2: a genuinely different predecessor at the same height.
    let mut forked = admitted_predecessor.clone();
    forked.resulting_state_root_hash = [0x7eu8; 32];
    ioi_types::app::bind_canonical_collapse_continuity(&mut forked, Some(&collapses[0]))
        .expect("rebind forked predecessor");

    for (label, persisted_previous) in [("tampered", tampered_proof), ("forked", forked)] {
        let client = seeded_chain_client(&blocks, &collapses[..1]).await;
        client.seed_collapse(&persisted_previous).await;

        let error = resolve_live_aft_canonical_collapse_for_block(
            ConsensusType::Aft,
            &client,
            Some(&admitted_predecessor),
            &blocks[2],
        )
        .await
        .expect_err("a divergent persisted predecessor must be refused");
        assert!(
            error
                .to_string()
                .contains("does not match the canonical collapse object already admitted"),
            "unexpected error for the {label} predecessor: {error}"
        );
    }
}

#[tokio::test]
async fn live_observation_accepts_late_enriched_persisted_predecessor() {
    // Same-slot publication enriches a persisted collapse object after live
    // observation has already admitted it: the archived recovered-history anchor
    // and the ordering bundle land late and sit outside the continuity payload
    // by construction. The boundary comparison must tolerate exactly those, or
    // the asymptote publication path refuses its own predecessor.
    let (blocks, collapses) = build_live_chain(3);
    let admitted_predecessor = collapses[1].clone();
    let mut enriched = admitted_predecessor.clone();
    set_canonical_collapse_archived_recovered_history_anchor(
        &mut enriched,
        [0x61u8; 32],
        [0x62u8; 32],
        [0x63u8; 32],
    )
    .expect("anchor upgrade");
    enriched.ordering.bulletin_close_hash = [0x64u8; 32];
    enriched.ordering.bulletin_retrievability_profile_hash = [0x65u8; 32];
    enriched.ordering.bulletin_shard_manifest_hash = [0x66u8; 32];
    enriched.ordering.bulletin_custody_receipt_hash = [0x67u8; 32];

    let client = seeded_chain_client(&blocks, &collapses[..1]).await;
    client.seed_collapse(&enriched).await;

    let resolved = resolve_live_aft_canonical_collapse_for_block(
        ConsensusType::Aft,
        &client,
        Some(&admitted_predecessor),
        &blocks[2],
    )
    .await
    .expect("late-enriched predecessor must still anchor the successor");
    assert_eq!(resolved, Some(collapses[2].clone()));
}

#[tokio::test]
async fn cold_live_hydration_refuses_corrupt_intermediate_link() {
    let (blocks, collapses) = build_live_chain(5);
    let client = seeded_chain_client(&blocks, &collapses).await;
    let mut corrupted = collapses[2].clone();
    corrupted.continuity_recursive_proof.proof_bytes[0] ^= 0xFF;
    client.seed_collapse(&corrupted).await;
    let engine = Arc::new(Mutex::new(TestConsensusEngine::default()));

    let error = observe_live_committed_chain_through_block(
        &engine,
        ConsensusType::Aft,
        &client,
        blocks.last().expect("tip block"),
    )
    .await
    .expect_err("a corrupt intermediate link must be refused");

    assert!(
        error
            .to_string()
            .contains("persisted canonical collapse continuity verification failed for height 3"),
        "unexpected error: {error}"
    );
    let observed = engine.lock().await.observed_heights.clone();
    assert_eq!(observed, vec![1, 2], "hydration skipped the bad link");
}

#[tokio::test]
async fn cold_live_hydration_refuses_missing_collapse_ancestor() {
    let (mut blocks, collapses) = build_live_chain(3);
    // Height 1 carries no external finality, so it collapses to nothing, and
    // nothing is persisted for it either: height 2 has no ancestor to extend.
    blocks[0].header.signature.clear();
    blocks[0].header.canonical_order_certificate = None;
    blocks[0].header.oracle_counter = 0;
    blocks[0].header.oracle_trace_hash = [0u8; 32];
    let client = seeded_chain_client(&blocks, &collapses[1..]).await;
    let engine = Arc::new(Mutex::new(TestConsensusEngine::default()));

    let error = observe_live_committed_chain_through_block(
        &engine,
        ConsensusType::Aft,
        &client,
        blocks.last().expect("tip block"),
    )
    .await
    .expect_err("a missing collapse ancestor must be refused");

    assert!(
        error
            .to_string()
            .contains("missing previous canonical collapse object for height 2"),
        "unexpected error: {error}"
    );
}

#[test]
fn collapse_backed_aft_status_skips_speculative_tip() {
    let durable = sample_block();
    let mut speculative = durable.clone();
    speculative.header.height += 1;
    speculative.header.signature.clear();
    speculative.header.guardian_certificate = None;
    speculative.header.canonical_order_certificate = None;
    speculative.header.oracle_counter = 0;
    speculative.header.oracle_trace_hash = [0u8; 32];

    let base = ChainStatus {
        height: speculative.header.height,
        latest_timestamp: speculative.header.timestamp,
        total_transactions: 99,
        is_running: true,
        latest_timestamp_ms: speculative.header.timestamp_ms,
    };

    let derived = collapse_backed_aft_status(&base, [&speculative, &durable]);
    assert_eq!(derived.height, durable.header.height);
    assert_eq!(derived.latest_timestamp, durable.header.timestamp);
    assert_eq!(derived.latest_timestamp_ms, durable.header.timestamp_ms);
    assert_eq!(derived.total_transactions, base.total_transactions);
}

#[test]
fn collapse_backed_aft_status_returns_zero_when_no_durable_block_exists() {
    let mut speculative = sample_block();
    speculative.header.signature.clear();
    speculative.header.guardian_certificate = None;
    speculative.header.canonical_order_certificate = None;
    speculative.header.oracle_counter = 0;
    speculative.header.oracle_trace_hash = [0u8; 32];

    let base = ChainStatus {
        height: speculative.header.height,
        latest_timestamp: speculative.header.timestamp,
        total_transactions: 11,
        is_running: true,
        latest_timestamp_ms: speculative.header.timestamp_ms,
    };

    let derived = collapse_backed_aft_status(&base, [&speculative]);
    assert_eq!(derived.height, 0);
    assert_eq!(derived.latest_timestamp, 0);
    assert_eq!(derived.latest_timestamp_ms, 0);
    assert_eq!(derived.total_transactions, base.total_transactions);
    assert!(derived.is_running);
}
