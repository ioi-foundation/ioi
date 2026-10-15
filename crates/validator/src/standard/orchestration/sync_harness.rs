// Path: crates/validator/src/standard/orchestration/sync_harness.rs
//! A test harness for the sync handlers (P7 round 2, build Ruling 12): a real `MainLoopContext`
//! over small mock collaborators, so `handle_blocks_response`, `handle_status_response`,
//! `start_catchup_to_peer` and the retry path run through their REAL call sites.
//!
//! The collaborators:
//! - `HarnessWorkload`: an in-memory workload holding blocks by height;
//! - `HarnessViewResolver`: anchored views holding nothing (the mock engine does not read them),
//!   or an error for a configured parent root ("the parent state is unavailable");
//! - `HarnessEngine`: a consensus engine whose `verify_synced_certificate` answers per certified
//!   block hash: verified (default), refuted, or "cannot evaluate here";
//! - a real `RuntimeFinalityCoordinator` in a temp dir (single-authority profile), whose admitted
//!   height is the sync floor;
//! - stubs for the collaborators the sync paths never touch.

use super::context::{MainLoopContext, SyncProgress};
use super::mempool::Mempool;
use super::runtime_finality::{runtime_finality_initial_head, RuntimeFinalityCoordinator};
use async_trait::async_trait;
use ioi_api::chain::{
    AnchoredStateView, BlockExecutionReceipt, ChainStateMachine, ChainView, LiveStateView,
    PreparedBlock, QueryStateResponse, RemoteStateView, StateRef, ViewResolver, WorkloadClientApi,
};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::{ConsensusControl, ConsensusDecision, ConsensusEngine, PenaltyMechanism};
#[allow(unused_imports)]
use ioi_api::crypto::{SerializableKey, SigningKey};
use ioi_api::state::{StateAccess, StateManager};
use ioi_api::validator::WorkloadContainer;
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::{LocalSafetyModel, PiiInspection, PiiRiskSurface, SafetyVerdict};
use ioi_networking::libp2p::SwarmCommand;
use ioi_networking::traits::NodeState;
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::verifier::IAVLHashVerifier;
use ioi_state::tree::iavl::IAVLTree;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::{
    AccountId, Block, BlockHeader, ChainStatus, ChainTransaction, ConsensusVote, FailureReport,
    QuorumCertificate, SignatureSuite, StateAnchor, StateRoot,
};
use ioi_types::config::{ConsensusType, OrchestrationConfig};
use ioi_types::error::{ChainError, ConsensusError, StateError, TransactionError, VmError};
use libp2p::identity::Keypair;
use libp2p::PeerId;
use lru::LruCache;
use std::any::Any;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, watch, Mutex};

pub(super) type HarnessCs = HashCommitmentScheme;
pub(super) type HarnessSt = IAVLTree<HashCommitmentScheme>;
pub(super) type HarnessContext =
    MainLoopContext<HarnessCs, HarnessSt, HarnessEngine, IAVLHashVerifier>;

// --- The workload -----------------------------------------------------------------------------

#[derive(Debug, Default)]
pub(super) struct HarnessWorkload {
    pub(super) blocks: std::sync::Mutex<BTreeMap<u64, Block<ChainTransaction>>>,
    /// FU-N11-DURABLE-STATUS-1 D2a round 2 (RED-3): every admitted-tip record presented to this
    /// workload, as (capability, tip), in order (the publisher spy).
    pub(super) admitted_tip_records:
        std::sync::Mutex<Vec<([u8; 32], ioi_api::storage::AdmittedTip)>>,
    /// The admission capability this workload accepts (`None`: it accepts no record).
    pub(super) accepted_capability: std::sync::Mutex<Option<[u8; 32]>>,
    /// This workload's admitted-tip marker.
    pub(super) committed_tip: std::sync::Mutex<Option<ioi_api::storage::AdmittedTip>>,
}

impl HarnessWorkload {
    fn tip(&self) -> u64 {
        self.blocks
            .lock()
            .unwrap()
            .keys()
            .next_back()
            .copied()
            .unwrap_or(0)
    }
}

#[async_trait]
impl WorkloadClientApi for HarnessWorkload {
    async fn process_block(
        &self,
        block: Block<ChainTransaction>,
    ) -> Result<
        (
            Block<ChainTransaction>,
            Vec<Vec<u8>>,
            Vec<BlockExecutionReceipt>,
        ),
        ChainError,
    > {
        self.blocks
            .lock()
            .unwrap()
            .insert(block.header.height, block.clone());
        Ok((block, Vec::new(), Vec::new()))
    }

    async fn replace_unfinalized_tip(
        &self,
        _expected_target: Block<ChainTransaction>,
        _expected_live_tip: Block<ChainTransaction>,
        replacement: Block<ChainTransaction>,
        _recognized_height: u64,
    ) -> Result<
        (
            Block<ChainTransaction>,
            Vec<Vec<u8>>,
            Vec<BlockExecutionReceipt>,
        ),
        ChainError,
    > {
        let mut blocks = self.blocks.lock().unwrap();
        blocks.retain(|height, _| *height < replacement.header.height);
        blocks.insert(replacement.header.height, replacement.clone());
        Ok((replacement, Vec::new(), Vec::new()))
    }

    async fn get_blocks_range(
        &self,
        since: u64,
        max_blocks: u32,
        _max_bytes: u32,
    ) -> Result<Vec<Block<ChainTransaction>>, ChainError> {
        Ok(self
            .blocks
            .lock()
            .unwrap()
            .range(since..)
            .take(max_blocks as usize)
            .map(|(_, block)| block.clone())
            .collect())
    }

    async fn get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<Block<ChainTransaction>>, ChainError> {
        Ok(self.blocks.lock().unwrap().get(&height).cloned())
    }

    async fn check_transactions_at(
        &self,
        _anchor: StateAnchor,
        _expected_timestamp_secs: u64,
        _txs: Vec<ChainTransaction>,
    ) -> Result<Vec<Result<(), String>>, ChainError> {
        Ok(Vec::new())
    }

    async fn query_state_at(
        &self,
        _root: StateRoot,
        _key: &[u8],
    ) -> Result<QueryStateResponse, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused by the sync harness".into(),
        ))
    }

    async fn query_raw_state(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
        Ok(None)
    }

    async fn prefix_scan(&self, _prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ChainError> {
        Ok(Vec::new())
    }

    async fn get_staked_validators(&self) -> Result<BTreeMap<AccountId, u64>, ChainError> {
        Ok(BTreeMap::new())
    }

    async fn get_genesis_status(&self) -> Result<bool, ChainError> {
        Ok(true)
    }

    async fn update_block_header(&self, block: Block<ChainTransaction>) -> Result<(), ChainError> {
        self.blocks
            .lock()
            .unwrap()
            .insert(block.header.height, block);
        Ok(())
    }

    async fn get_state_root(&self) -> Result<StateRoot, ChainError> {
        Ok(StateRoot(vec![0; 32]))
    }

    async fn get_status(&self) -> Result<ChainStatus, ChainError> {
        Ok(ChainStatus {
            height: self.tip(),
            ..Default::default()
        })
    }

    async fn get_execution_status(&self) -> Result<ChainStatus, ChainError> {
        self.get_status().await
    }

    async fn get_committed_tip(
        &self,
    ) -> Result<Option<ioi_api::storage::AdmittedTip>, ChainError> {
        Ok(self.committed_tip.lock().unwrap().clone())
    }

    async fn record_admitted_tip_with_capability(
        &self,
        _witness: ioi_api::chain::AdmissionWitness,
        capability: &[u8; 32],
        tip: ioi_api::storage::AdmittedTip,
    ) -> Result<(), ChainError> {
        self.admitted_tip_records
            .lock()
            .unwrap()
            .push((*capability, tip.clone()));
        if *self.accepted_capability.lock().unwrap() != Some(*capability) {
            return Err(ChainError::Transaction(
                "admitted-tip record refused: the workload capability does not match".into(),
            ));
        }
        *self.committed_tip.lock().unwrap() = Some(tip);
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// --- Views ------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct EmptyView {
    root: Vec<u8>,
}

#[async_trait]
impl RemoteStateView for EmptyView {
    async fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
        Ok(None)
    }
    fn height(&self) -> u64 {
        0
    }
    fn state_root(&self) -> &[u8] {
        &self.root
    }
}

#[async_trait]
impl AnchoredStateView for EmptyView {
    async fn gas_used(&self) -> Result<u64, ChainError> {
        Ok(0)
    }
}

pub(super) struct HarnessViewResolver {
    pub(super) workload: Arc<dyn WorkloadClientApi>,
    /// Parent state roots whose anchored view is unavailable.
    pub(super) unavailable_roots: std::sync::Mutex<HashSet<Vec<u8>>>,
    /// The chain-view inputs the gossip path takes from the node's resolver (its `cfg(test)` arm
    /// of `gossip_chain_view_inputs`; P7 round 3). The harness engine reads no views.
    pub(super) verifier: IAVLHashVerifier,
    pub(super) proof_cache: Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>,
}

#[async_trait]
impl ViewResolver for HarnessViewResolver {
    type Verifier = IAVLHashVerifier;

    async fn resolve_anchored(
        &self,
        r: &StateRef,
    ) -> Result<Arc<dyn AnchoredStateView>, ChainError> {
        if self
            .unavailable_roots
            .lock()
            .unwrap()
            .contains(&r.state_root)
        {
            return Err(ChainError::UnknownStateAnchor(hex::encode(&r.state_root)));
        }
        Ok(Arc::new(EmptyView {
            root: r.state_root.clone(),
        }))
    }

    async fn resolve_live(&self) -> Result<Arc<dyn LiveStateView>, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused by the sync harness".into(),
        ))
    }

    async fn genesis_root(&self) -> Result<Vec<u8>, ChainError> {
        Ok(vec![0; 32])
    }

    fn workload_client(&self) -> &Arc<dyn WorkloadClientApi> {
        &self.workload
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// --- The consensus engine -------------------------------------------------------------------

/// What the engine answers for a synced certificate over a given block hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CertificateAnswer {
    /// The certificate verifies.
    Verified,
    /// The certificate is refuted (bad signatures, wrong block).
    Refuted,
    /// The engine cannot evaluate it here (a missing async-parent proof, unavailable keys).
    CannotEvaluate,
}

#[derive(Debug, Default)]
pub(super) struct HarnessEngine {
    /// Per certified block hash; absent = `Verified`.
    pub(super) answers: HashMap<[u8; 32], CertificateAnswer>,
    /// Every certificate the engine was asked about, in order.
    pub(super) asked: Vec<QuorumCertificate>,
    /// Gossiped proposals (by block hash) this engine refuses as stale-view proposals (a
    /// later-view timeout certificate formed at their height) while no quorum certificate held
    /// here certifies them (P7 round 3, N1). Every other proposal is accepted.
    pub(super) stale: HashSet<[u8; 32]>,
    /// Blocks an authenticated quorum certificate held here certifies.
    pub(super) certified: HashSet<[u8; 32]>,
    /// Gossiped proposals (by block hash) this engine refuses for another reason (they fail
    /// verification), certified or not.
    pub(super) invalid: HashSet<[u8; 32]>,
    /// Every proposal `handle_block_proposal` was given, by block hash, in order.
    pub(super) proposals: Vec<[u8; 32]>,
}

/// The engine's refusal of a stale-view proposal, as the harness engine reports it: the real
/// engine's typed error (ioi-consensus `vote_safety.rs`).
pub(super) fn harness_stale_refusal(header: &BlockHeader) -> ConsensusError {
    ConsensusError::StaleViewProposal {
        height: header.height,
        view: header.view,
        superseding_view: header.view + 1,
    }
}

#[async_trait]
impl PenaltyMechanism for HarnessEngine {
    async fn apply_penalty(
        &self,
        _state: &mut dyn StateAccess,
        _report: &FailureReport,
    ) -> Result<(), TransactionError> {
        Ok(())
    }
}

impl ConsensusControl for HarnessEngine {
    fn experimental_sample_tip(&self) -> Option<([u8; 32], u32)> {
        None
    }
    fn observe_experimental_sample(&mut self, _hash: [u8; 32]) {}
}

#[async_trait]
impl ConsensusEngine<ChainTransaction> for HarnessEngine {
    async fn decide(
        &mut self,
        _our_account_id: &AccountId,
        _height: u64,
        _view: u64,
        _parent_view: &dyn AnchoredStateView,
        _known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<ChainTransaction> {
        ConsensusDecision::WaitForBlock
    }

    async fn handle_block_proposal<CS, ST>(
        &mut self,
        block: Block<ChainTransaction>,
        _chain_view: &dyn ChainView<CS, ST>,
    ) -> Result<(), ConsensusError>
    where
        CS: CommitmentScheme + Send + Sync,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
        let block_hash = harness_hash(&block);
        self.proposals.push(block_hash);
        if self.invalid.contains(&block_hash) {
            return Err(ConsensusError::BlockVerificationFailed(
                "harness: the proposal fails verification".into(),
            ));
        }
        if self.stale.contains(&block_hash) && !self.certified.contains(&block_hash) {
            return Err(harness_stale_refusal(&block.header));
        }
        Ok(())
    }

    async fn handle_vote(&mut self, _vote: ConsensusVote) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn holds_certificate_for(&self, _height: u64, block_hash: &[u8; 32]) -> bool {
        self.certified.contains(block_hash)
    }

    async fn handle_view_change(
        &mut self,
        _from: PeerId,
        _proof_bytes: &[u8],
    ) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn reset(&mut self, _height: u64) {}

    async fn verify_synced_certificate(
        &mut self,
        qc: &QuorumCertificate,
        _view: &dyn AnchoredStateView,
    ) -> Result<(), ConsensusError> {
        self.asked.push(qc.clone());
        match self
            .answers
            .get(&qc.block_hash)
            .copied()
            .unwrap_or(CertificateAnswer::Verified)
        {
            CertificateAnswer::Verified => Ok(()),
            CertificateAnswer::Refuted => Err(ConsensusError::BlockVerificationFailed(
                "harness: the certificate's signatures do not verify".into(),
            )),
            CertificateAnswer::CannotEvaluate => Err(ConsensusError::DependencyNotFound(
                "harness: the asynchronous parent proof is not held here".into(),
            )),
        }
    }
}

// --- Stubs for collaborators the sync paths never touch -----------------------------------------

struct StubChain {
    status: ChainStatus,
}

impl std::fmt::Debug for StubChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StubChain")
    }
}

#[async_trait]
impl ChainView<HarnessCs, HarnessSt> for StubChain {
    async fn view_at(
        &self,
        _state_ref: &StateRef,
    ) -> Result<Arc<dyn AnchoredStateView>, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused by the sync harness".into(),
        ))
    }
    fn get_penalty_mechanism(&self) -> Box<dyn PenaltyMechanism + Send + Sync + '_> {
        unimplemented!("unused by the sync harness")
    }
    fn consensus_type(&self) -> ConsensusType {
        ConsensusType::Aft
    }
    fn workload_container(&self) -> &WorkloadContainer<HarnessSt> {
        unimplemented!("unused by the sync harness")
    }
}

#[async_trait]
impl ChainStateMachine<HarnessCs, UnifiedTransactionModel<HarnessCs>, HarnessSt> for StubChain {
    fn status(&self) -> &ChainStatus {
        &self.status
    }
    fn status_mut(&mut self) -> &mut ChainStatus {
        &mut self.status
    }
    fn transaction_model(&self) -> &UnifiedTransactionModel<HarnessCs> {
        unimplemented!("unused by the sync harness")
    }
    async fn prepare_block(
        &self,
        _block: Block<ChainTransaction>,
    ) -> Result<PreparedBlock, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused by the sync harness".into(),
        ))
    }
    async fn commit_block(
        &mut self,
        _prepared: PreparedBlock,
    ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError> {
        Err(ChainError::ExecutionClient(
            "unused by the sync harness".into(),
        ))
    }
    fn create_block(
        &self,
        _transactions: Vec<ChainTransaction>,
        _current_validator_set: &[Vec<u8>],
        _known_peers_bytes: &[Vec<u8>],
        _producer_keypair: &Keypair,
        _expected_timestamp: u64,
        _view: u64,
    ) -> Result<Block<ChainTransaction>, ChainError> {
        Err(ChainError::ExecutionClient(
            "unused by the sync harness".into(),
        ))
    }
    fn get_block(&self, _height: u64) -> Option<&Block<ChainTransaction>> {
        None
    }
    fn get_blocks_since(&self, _height: u64) -> Vec<Block<ChainTransaction>> {
        Vec::new()
    }
    async fn get_validator_set_for(&self, _height: u64) -> Result<Vec<Vec<u8>>, ChainError> {
        Ok(Vec::new())
    }
    async fn get_staked_validators(&self) -> Result<BTreeMap<AccountId, u64>, ChainError> {
        Ok(BTreeMap::new())
    }
    async fn get_next_staked_validators(&self) -> Result<BTreeMap<AccountId, u64>, ChainError> {
        Ok(BTreeMap::new())
    }
}

struct StubSafety;

#[async_trait]
impl LocalSafetyModel for StubSafety {
    async fn classify_intent(&self, _input: &str) -> anyhow::Result<SafetyVerdict> {
        Err(anyhow::anyhow!("unused by the sync harness"))
    }
    async fn detect_pii(&self, _input: &str) -> anyhow::Result<Vec<(usize, usize, String)>> {
        Ok(Vec::new())
    }
    async fn inspect_pii(
        &self,
        _input: &str,
        _risk_surface: PiiRiskSurface,
    ) -> anyhow::Result<PiiInspection> {
        Err(anyhow::anyhow!("unused by the sync harness"))
    }
}

struct StubOs;

#[async_trait]
impl OsDriver for StubOs {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(None)
    }
    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        Ok(None)
    }
    async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
        Ok(false)
    }
    async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
        Ok(())
    }
    async fn get_clipboard(&self) -> Result<String, VmError> {
        Ok(String::new())
    }
}

// --- Blocks -----------------------------------------------------------------------------------

/// A block at `height` on `parent`, with `parent_qc` naming that parent at `height - 1`;
/// `salt` varies the block's bytes (a conflicting sibling has another salt).
pub(super) fn harness_block(parent: [u8; 32], height: u64, salt: u8) -> Block<ChainTransaction> {
    Block {
        header: BlockHeader {
            height,
            view: 0,
            parent_hash: parent,
            parent_state_root: StateRoot(vec![height.saturating_sub(1) as u8; 32]),
            state_root: StateRoot(vec![height as u8; 32]),
            transactions_root: ioi_types::app::canonical_transactions_root(&[]).unwrap(),
            timestamp: 1_700_000_000 + height,
            timestamp_ms: 1_700_000_000_000 + height,
            gas_used: 0,
            validator_set: vec![vec![5; 32]],
            producer_account_id: AccountId([6; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [7; 32],
            producer_pubkey: vec![8; 32],
            oracle_counter: 0,
            oracle_trace_hash: [0; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            parent_qc: QuorumCertificate {
                height: height.saturating_sub(1),
                view: 0,
                block_hash: parent,
                signatures: vec![(AccountId([9; 32]), vec![1; 64])],
                aggregated_signature: Vec::new(),
                signers_bitfield: Vec::new(),
            },
            // The salt varies the header's hash (this field is in the signing preimage) without
            // touching the fields the runtime-finality coordinator binds.
            previous_canonical_collapse_commitment_hash: [salt; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            timeout_certificate: None,
            aft_timeout_certificate: None,
            signature: vec![1; 64],
        },
        transactions: Vec::new(),
    }
}

pub(super) fn harness_hash(block: &Block<ChainTransaction>) -> [u8; 32] {
    block.header.hash().unwrap().try_into().unwrap()
}

// --- The harness --------------------------------------------------------------------------------

pub(super) struct Harness {
    pub(super) context: HarnessContext,
    pub(super) workload: Arc<HarnessWorkload>,
    pub(super) resolver: Arc<HarnessViewResolver>,
    pub(super) swarm: mpsc::Receiver<SwarmCommand>,
    /// The admitted chain (heights 1..=floor), as the coordinator and the workload hold it.
    pub(super) admitted: Vec<Block<ChainTransaction>>,
    _dir: tempfile::TempDir,
}

impl Harness {
    /// A context whose Agentgres floor (admitted height) is `floor`: blocks 1..=floor are staged,
    /// admitted and held by the workload. The node is Synced with no sync session.
    pub(super) async fn new(floor: u64) -> Self {
        Self::with_profile(
            floor,
            ioi_types::config::RuntimeFinalityProfile::SingleAuthorityV1,
        )
        .await
    }

    /// A harness whose Agentgres profile is `profile`. Under `BftConsensusAftV1` nothing can be
    /// admitted here (native AFT evidence is out of the harness's scope), so `floor` must be 0.
    pub(super) async fn with_profile(
        floor: u64,
        profile: ioi_types::config::RuntimeFinalityProfile,
    ) -> Self {
        assert!(
            floor == 0 || profile == ioi_types::config::RuntimeFinalityProfile::SingleAuthorityV1,
            "the harness admits only under the single-authority profile"
        );
        let dir = tempfile::tempdir().unwrap();
        let seed = [42u8; 32];
        let key = ioi_crypto::sign::eddsa::Ed25519PrivateKey::from_bytes(&seed).unwrap();
        let mut coordinator = RuntimeFinalityCoordinator::open(
            dir.path().join("finality"),
            "harness".into(),
            profile,
            "harness-writer".into(),
            || runtime_finality_initial_head(None),
            format!(
                "key://test/{}",
                hex::encode(key.public_key().unwrap().as_bytes())
            ),
            &seed,
        )
        .unwrap();
        let workload = Arc::new(HarnessWorkload::default());
        let mut admitted = Vec::new();
        let mut parent = [0u8; 32];
        for height in 1..=floor {
            let block = harness_block(parent, height, 0);
            parent = harness_hash(&block);
            coordinator.stage_block(block.clone(), Vec::new()).unwrap();
            coordinator
                .admit_single_authority(parent, 1_700_000_000_000 + height)
                .unwrap();
            workload
                .blocks
                .lock()
                .unwrap()
                .insert(height, block.clone());
            admitted.push(block);
        }
        let resolver = Arc::new(HarnessViewResolver {
            workload: workload.clone() as Arc<dyn WorkloadClientApi>,
            unavailable_roots: std::sync::Mutex::new(HashSet::new()),
            verifier: IAVLHashVerifier,
            proof_cache: Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(16).unwrap(),
            ))),
        });
        let (swarm_tx, swarm_rx) = mpsc::channel(4096);
        let (quv_tx, _quv_rx) = mpsc::channel(16);
        let (kick_tx, _kick_rx) = mpsc::unbounded_channel();
        let (tip_tx, _tip_rx) = watch::channel(super::ingestion::ChainTipInfo {
            height: floor,
            timestamp: 0,
            timestamp_ms: 0,
            gas_used: 0,
            state_root: Vec::new(),
            genesis_root: Vec::new(),
            validator_set: Vec::new(),
        });
        let (event_tx, _event_rx) = tokio::sync::broadcast::channel(16);
        let config: OrchestrationConfig = serde_json::from_value(serde_json::json!({
            "consensus_type": "Aft",
            "rpc_listen_address": "127.0.0.1:0",
            "aft_safety_mode": "classic_bft",
            "aft_pq_outbox_dir": dir.path().join("outbox").to_string_lossy(),
        }))
        .unwrap();
        let local_keypair = Keypair::generate_ed25519();
        let signer = Arc::new(crate::common::LocalSigner::new(
            ioi_crypto::sign::eddsa::Ed25519KeyPair::generate().unwrap(),
        ));
        let context = HarnessContext {
            config: config.clone(),
            chain_id: config.chain_id,
            genesis_hash: [0; 32],
            genesis_root: vec![0; 32],
            chain_ref: Arc::new(Mutex::new(StubChain {
                status: ChainStatus {
                    height: floor,
                    ..Default::default()
                },
            })),
            view_resolver: resolver.clone(),
            tx_pool_ref: Arc::new(Mempool::new()),
            swarm_commander: swarm_tx,
            quv_swarm_commander: quv_tx,
            consensus_engine_ref: Arc::new(Mutex::new(HarnessEngine::default())),
            node_state: Arc::new(Mutex::new(NodeState::Synced)),
            local_keypair,
            pqc_signer: None,
            local_validator_account_id: None,
            aft_pq_local_account_id: None,
            known_peers_ref: Arc::new(Mutex::new(HashSet::new())),
            peer_accounts_ref: Arc::new(Mutex::new(HashMap::new())),
            aft_pq_peer_keys: None,
            aft_pq_handoff_only_accounts: HashSet::new(),
            aft_quv_staged_successor: None,
            aft_pq_configuration_hash: None,
            aft_async_membership: None,
            aft_async_custody_key: None,
            aft_cross_path_signing_fence: None,
            aft_quv_member: None,
            aft_quv_handoff_envelope: None,
            aft_quv_certified_handoff: None,
            aft_quv_certified_handoff_block: None,
            aft_quv_certified_handoff_parent_block: None,
            aft_quv_handoff_store: None,
            aft_quv_push_inflight: HashSet::new(),
            aft_quv_push_admission: BTreeMap::new(),
            aft_quv_admission: Arc::new(super::quv::admission::QuvOperationAdmissionV0::new(
                std::iter::empty(),
            )),
            aft_quv_preparation_notify: Arc::new(tokio::sync::Notify::new()),
            aft_quv_operations: Arc::new(Mutex::new(HashMap::new())),
            aft_async_sessions: BTreeMap::new(),
            aft_async_finalized: BTreeMap::new(),
            aft_async_finalized_batches: BTreeMap::new(),
            aft_async_executed: BTreeMap::new(),
            configured_bootstrap_peers: 0,
            is_quarantined: Arc::new(AtomicBool::new(false)),
            aft_quv_retired: false,
            pending_attestations: HashMap::new(),
            last_committed_block: admitted.last().cloned(),
            last_executed_block: admitted.last().cloned(),
            recent_executed_headers: BTreeMap::new(),
            last_tip_vote_replay: None,
            last_production_attempt: None,
            rejected_aft_replacements: LruCache::new(std::num::NonZeroUsize::new(16).unwrap()),
            consensus_kick_tx: kick_tx,
            consensus_kick_scheduled: Arc::new(AtomicBool::new(false)),
            next_due_wakeup_at_ms: Arc::new(AtomicU64::new(0)),
            sync_progress: None,
            sync_peer_cooldown: Default::default(),
            stale_proposals: Default::default(),
            nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
            signer,
            batch_verifier: Arc::new(ioi_crypto::sign::batch::CpuBatchVerifier::new()),
            tx_status_cache: Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(16).unwrap(),
            ))),
            tip_sender: tip_tx,
            receipt_map: Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(16).unwrap(),
            ))),
            safety_model: Arc::new(StubSafety),
            inference_runtime: Arc::new(ioi_api::vm::inference::mock::MockInferenceRuntime),
            os_driver: Arc::new(StubOs),
            memory_runtime: None,
            event_broadcaster: event_tx,
            runtime_finality: Arc::new(Mutex::new(coordinator)),
        };
        Self {
            context,
            workload,
            resolver,
            swarm: swarm_rx,
            admitted,
            _dir: dir,
        }
    }

    /// The hash of the admitted block at `height` (0 = the genesis parent).
    pub(super) fn admitted_hash(&self, height: u64) -> [u8; 32] {
        if height == 0 {
            return [0; 32];
        }
        harness_hash(&self.admitted[height as usize - 1])
    }

    /// Opens a sync session toward `target` with the given tip, at the floor.
    pub(super) async fn start_session(&mut self, target: PeerId, tip: u64) {
        let floor = self.admitted.len() as u64;
        self.context.known_peers_ref.lock().await.insert(target);
        *self.context.node_state.lock().await = NodeState::Syncing;
        self.context.sync_progress = Some(SyncProgress {
            target: Some(target),
            tip,
            next: floor,
            inflight: true,
            req_id: 1,
            requested_at: std::time::Instant::now(),
            retry_not_before: None,
            authority: Default::default(),
        });
    }

    pub(super) async fn answer(&self, block_hash: [u8; 32], answer: CertificateAnswer) {
        self.context
            .consensus_engine_ref
            .lock()
            .await
            .answers
            .insert(block_hash, answer);
    }

    pub(super) fn quarantined(&self) -> bool {
        self.context.is_quarantined.load(Ordering::SeqCst)
    }

    pub(super) fn refused(&self, peer: &PeerId) -> bool {
        self.context
            .sync_progress
            .as_ref()
            .is_some_and(|progress| !progress.authority.may_target(peer))
    }

    /// The peers sync requested blocks from, drained from the swarm channel.
    pub(super) fn drain_requests(&mut self) -> Vec<PeerId> {
        let mut peers = Vec::new();
        while let Ok(command) = self.swarm.try_recv() {
            if let SwarmCommand::SendBlocksRequest { peer, .. } = command {
                peers.push(peer);
            }
        }
        peers
    }

    /// Lets every pending retry backoff expire.
    pub(super) fn expire_backoff(&mut self) {
        if let Some(progress) = self.context.sync_progress.as_mut() {
            progress.retry_not_before = None;
        }
    }

    /// The same harness with its context behind the shared lock the network-event path takes
    /// (`events::handle_network_event`).
    pub(super) fn shared(self) -> SharedHarness {
        SharedHarness {
            context: Arc::new(Mutex::new(self.context)),
            workload: self.workload,
            admitted: self.admitted,
            _swarm: self.swarm,
            _dir: self._dir,
        }
    }
}

/// A [`Harness`] whose context is shared (`Arc<Mutex<_>>`), for the network-event path.
pub(super) struct SharedHarness {
    pub(super) context: Arc<Mutex<HarnessContext>>,
    pub(super) workload: Arc<HarnessWorkload>,
    pub(super) admitted: Vec<Block<ChainTransaction>>,
    _swarm: mpsc::Receiver<SwarmCommand>,
    _dir: tempfile::TempDir,
}

impl SharedHarness {
    /// The hash of the admitted block at `height` (0 = the genesis parent).
    pub(super) fn admitted_hash(&self, height: u64) -> [u8; 32] {
        if height == 0 {
            return [0; 32];
        }
        harness_hash(&self.admitted[height as usize - 1])
    }

    /// The hash of the block the workload holds at `height`, if any.
    pub(super) fn held_hash(&self, height: u64) -> Option<[u8; 32]> {
        self.workload
            .blocks
            .lock()
            .unwrap()
            .get(&height)
            .map(harness_hash)
    }
}

#[allow(dead_code)]
fn _assert_state_error_is_used(_: StateError) {}
