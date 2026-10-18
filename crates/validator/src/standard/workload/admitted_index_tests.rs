// Path: crates/validator/src/standard/workload/admitted_index_tests.rs
//! FU-N11-DURABLE-STATUS-1 D2a RED-4 (written against 5c77c9ca0, the GREEN-3 admission-floor
//! fence): the ADMITTED INDEX that replaces the fence (review round 2's consensus between NET and
//! the IOI Director, d2a/review2/RECOMMENDATION.md). Every committed read comes from ONE index
//! record (height -> admitted block hash, state root, header timestamp); only the admission
//! publication writes the index; the publisher emits only ledger truths; there is no fence.
//!
//! ONE HARNESS, the real workload end of the IPC:
//! - the REAL `ChainControlImpl` gRPC handlers over a real `RpcContext`: a real `RedbEpochStore`
//!   in a temp dir and a real `ExecutionMachine` (the Solo engine, an empty IAVL tree);
//! - served over loopback gRPC, read through the REAL shared `WorkloadClient` every consumer holds
//!   (C5's IBC host, C6's licence check, C7's trusted root).
//! The workload executes genesis and heights 1..=N+1 (the store writes the workload's commit
//! makes), and the admission publication records 1..=N through the real RecordAdmittedTip handler
//! with the workload's capability (the RPC the orchestration's publisher sends; the ledger to
//! publisher leg is T2's). Then each T1 test performs its writes through the UNAUTHENTICATED
//! handlers and the store API and reads EVERY committed surface for every admitted height and for
//! N+1:
//! - the by-height record (`NodeStore::get_admitted_record`, `WorkloadClientApi::get_admitted_record`:
//!   the RED-4 scaffold; the gRPC by-height query is GREEN-4's proto change);
//! - C5: `resolve_query_anchor(Some(h))` and `(None)` (moved unchanged into
//!   `ioi_api::chain::committed_query_anchor` at RED-4, so this harness runs the IBC host's code);
//! - C7: `committed_state_root`; C6: the committed status the licence check reads (its height is
//!   the licence-expiry committed height);
//! - GetCommittedTip, from the handler (height, hash, root AND timestamp) and through the client.
//! T1 PASSES iff: every value equals the admission record or is an error; N+1 is an error; no read
//! returns a rewritten root or a pair mixing two observations; every index row is served; and
//! every mutating write SUCCEEDED (no fence in the path). Each test collects EVERY violation and
//! reports them by class, so a failure names all of its causes.
//!
//! Also here: T2 (the publisher, built outside its module, publishes only the ledger head), RED-5's
//! B1 (ii) (a ledger bootstrapped on an executed, never-admitted block publishes nothing), T5
//! through the publication handler (write-once), T6 (restart). The store-layer T5/T6 and the
//! IN-FLIGHT cases (vi)/(vii), which this crate cannot hold deterministically (the store's caches
//! and its write lock are private to ioi-storage), are in ioi-storage
//! `redb_epoch_store::admitted_index_tests`.

use crate::standard::orchestration::runtime_finality::{
    canonical_block_head, runtime_finality_initial_head, RuntimeFinalityCoordinator,
};
use crate::standard::orchestration::AdmissionCapabilitySource;
use crate::standard::workload::admitted_tip::{write_capability_file, WorkloadCapability};
use crate::standard::workload::ipc::grpc_blockchain::ChainControlImpl;
use crate::standard::workload::ipc::RpcContext;
use async_trait::async_trait;
use ioi_api::chain::{committed_query_anchor, committed_state_root, WorkloadClientApi};
#[allow(unused_imports)]
use ioi_api::crypto::{SerializableKey, SigningKey};
use ioi_api::services::access::ServiceDirectory;
use ioi_api::state::VmStateAccessor;
use ioi_api::storage::{AdmittedRecord, AdmittedTip, CommitInput, NodeStore, RootHash};
use ioi_api::validator::WorkloadContainer;
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::{ExecutionContext, ExecutionOutput, VirtualMachine};
use ioi_client::WorkloadClient;
use ioi_consensus::solo::SoloEngine;
use ioi_consensus::Consensus;
use ioi_execution::ExecutionMachine;
use ioi_ipc::blockchain::chain_control_server::{ChainControl, ChainControlServer};
use ioi_ipc::blockchain::{
    GetStatusRequest, RecordAdmittedTipRequest, ReplaceUnfinalizedTipRequest,
};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_storage::RedbEpochStore;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::{
    canonical_sealed_finality_proof_signing_bytes, canonical_transactions_root, AccountId, Block,
    BlockHeader, ChainTransaction, QuorumCertificate, SealedFinalityProof, SignatureProof,
    SignatureSuite, StateRoot,
};
use ioi_types::codec;
use ioi_types::config::{
    CommitmentSchemeType, ConsensusType, RuntimeFinalityProfile, StateTreeType, WorkloadConfig,
};
use ioi_types::error::VmError;
use libp2p::identity::Keypair;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use tonic::Request;

/// Heights 1..=N are admitted; N + 1 is executed by the workload and never admitted.
const N: u64 = 4;
/// The workload's per-boot admission capability in this harness.
const CAPABILITY: [u8; 32] = [0x5A; 32];
const ORACLE_TRACE: [u8; 32] = [0x7A; 32];

type Cs = HashCommitmentScheme;
type St = IAVLTree<HashCommitmentScheme>;

// --- Blocks ------------------------------------------------------------------------------------

fn hash_of(block: &Block<ChainTransaction>) -> [u8; 32] {
    block
        .header
        .hash()
        .expect("identity hash")
        .try_into()
        .expect("32-byte hash")
}

/// The producer's signature over the identity hash, the oracle counter and the oracle trace (the
/// payload consensus verifies).
fn header_signature(header: &BlockHeader, producer: &Keypair) -> Vec<u8> {
    let mut payload = header.hash().expect("identity hash");
    payload.extend_from_slice(&header.oracle_counter.to_be_bytes());
    payload.extend_from_slice(&header.oracle_trace_hash);
    producer.sign(&payload).expect("sign the header")
}

/// A sealed finality proof for `header` in `epoch`, signed by the block's own producer and bound
/// to its oracle counter and trace (the wrapper GREEN-3's fence verifies; it does not check the
/// epoch's committee).
fn finality_proof(header: &BlockHeader, epoch: u64, producer: &Keypair) -> SealedFinalityProof {
    let mut proof = SealedFinalityProof {
        epoch,
        guardian_counter: header.oracle_counter,
        guardian_trace_hash: header.oracle_trace_hash,
        ..Default::default()
    };
    let bytes = canonical_sealed_finality_proof_signing_bytes(&proof).expect("proof signing bytes");
    proof.proof_signature = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key: producer.public().encode_protobuf(),
        signature: producer.sign(&bytes).expect("sign the proof"),
    };
    proof
}

/// The block executed at `height` on `parent`, with state root `[root; 32]`. With `evidence` it
/// carries its producer's verifying signature and an epoch-1 sealed finality proof.
fn block_at(
    height: u64,
    parent: [u8; 32],
    root: u8,
    producer: &Keypair,
    evidence: bool,
) -> Block<ChainTransaction> {
    let mut block = Block {
        header: BlockHeader {
            height,
            view: 0,
            parent_hash: parent,
            parent_state_root: StateRoot(vec![0x22; 32]),
            state_root: StateRoot(vec![root; 32]),
            transactions_root: canonical_transactions_root(&[]).expect("empty transactions root"),
            timestamp: 1_700_000_000 + height,
            timestamp_ms: (1_700_000_000 + height) * 1_000,
            gas_used: 0,
            validator_set: vec![vec![5; 32]],
            producer_account_id: AccountId([6; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [7; 32],
            producer_pubkey: producer.public().encode_protobuf(),
            oracle_counter: 40 + height,
            oracle_trace_hash: ORACLE_TRACE,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            aft_timeout_certificate: None,
            parent_qc: QuorumCertificate {
                height: height.saturating_sub(1),
                view: 0,
                block_hash: parent,
                signatures: vec![(AccountId([9; 32]), vec![1; 64])],
                aggregated_signature: Vec::new(),
                signers_bitfield: Vec::new(),
            },
            previous_canonical_collapse_commitment_hash: [0; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            signature: vec![1; 64],
        },
        transactions: Vec::new(),
    };
    if evidence {
        block.header.signature = header_signature(&block.header, producer);
        block.header.sealed_finality_proof = Some(finality_proof(&block.header, 1, producer));
    }
    block
}

/// Genesis (height 0) and heights 1..=N+1, parent-linked (height 1 on the zero hash, the Agentgres
/// genesis head), each with root 0xA0 + height.
fn executed_chain(producer: &Keypair, evidence: bool) -> Vec<Block<ChainTransaction>> {
    let mut blocks = vec![block_at(0, [0; 32], 0xA0, producer, false)];
    let mut parent = [0u8; 32];
    for height in 1..=N + 1 {
        let block = block_at(height, parent, 0xA0 + height as u8, producer, evidence);
        parent = hash_of(&block);
        blocks.push(block);
    }
    blocks
}

/// What the admission publication records for `block`.
fn record_of(block: &Block<ChainTransaction>) -> AdmittedRecord {
    AdmittedRecord {
        height: block.header.height,
        block_hash: hash_of(block),
        state_root: block.header.state_root.0.clone(),
        timestamp: block.header.timestamp,
    }
}

fn tip_of(record: &AdmittedRecord) -> AdmittedTip {
    AdmittedTip {
        height: record.height,
        block_hash: record.block_hash,
        state_root: record.state_root.clone(),
    }
}

/// `block` with another state root and a later timestamp (another identity): a rewrite or a
/// replacement of the same height.
fn rewritten(block: &Block<ChainTransaction>, root: u8) -> Block<ChainTransaction> {
    let mut rewritten = block.clone();
    rewritten.header.state_root = StateRoot(vec![root; 32]);
    rewritten.header.timestamp += 60;
    rewritten.header.timestamp_ms += 60_000;
    rewritten
}

fn commit_input(block: &Block<ChainTransaction>) -> CommitInput {
    CommitInput {
        height: block.header.height,
        root: RootHash(
            block
                .header
                .state_root
                .0
                .as_slice()
                .try_into()
                .expect("32-byte root"),
        ),
        unique_nodes_for_height: Vec::new(),
        new_nodes: Vec::new(),
    }
}

fn short(bytes: &[u8]) -> String {
    hex::encode(&bytes[..bytes.len().min(4)])
}

fn show(record: &AdmittedRecord) -> String {
    format!(
        "(height {}, hash {}.., root {}.., timestamp {})",
        record.height,
        short(&record.block_hash),
        short(&record.state_root),
        record.timestamp
    )
}

// --- The workload's collaborators the harness never exercises ------------------------------------

/// A VM that runs nothing (no block here carries a transaction).
struct NoVm;

#[async_trait]
impl VirtualMachine for NoVm {
    async fn execute(
        &self,
        _contract_bytecode: &[u8],
        _entrypoint: &str,
        _input_data: &[u8],
        _state_accessor: &dyn VmStateAccessor,
        _execution_context: ExecutionContext,
    ) -> Result<ExecutionOutput, VmError> {
        Err(VmError::Initialization(
            "the admitted-index harness runs no contract".into(),
        ))
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

fn workload_config() -> WorkloadConfig {
    WorkloadConfig {
        runtimes: Vec::new(),
        state_tree: StateTreeType::IAVL,
        commitment_scheme: CommitmentSchemeType::Hash,
        consensus_type: ConsensusType::Solo,
        genesis_file: String::new(),
        state_file: String::new(),
        srs_file_path: None,
        fuel_costs: Default::default(),
        initial_services: Vec::new(),
        service_policies: ioi_types::config::default_service_policies(),
        min_finality_depth: 0,
        keep_recent_heights: 0,
        epoch_size: 1024,
        gc_interval_secs: 3600,
        zk_config: Default::default(),
        inference: Default::default(),
        fast_inference: None,
        reasoning_inference: None,
        connectors: Default::default(),
        mcp_servers: Default::default(),
        mcp_mode: Default::default(),
    }
}

/// Opens the workload's store; after a stop, the previous handle drains asynchronously (the
/// server's connection tasks and the store's persistence thread), so a reopen retries.
async fn open_store(path: &Path) -> RedbEpochStore {
    let mut last = None;
    for _ in 0..500 {
        match RedbEpochStore::open(path, 1024) {
            Ok(store) => return store,
            Err(error) => last = Some(error),
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the workload store did not open: {last:?}");
}

/// Serves the workload's ChainControl on an ephemeral loopback port.
async fn serve(chain: Arc<ChainControlImpl<Cs, St>>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let address = listener.local_addr().expect("local address");
    let incoming = tonic::transport::server::TcpIncoming::from_listener(listener, true, None)
        .expect("incoming");
    let server = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(ChainControlServer::from_arc(chain))
            .serve_with_incoming(incoming)
            .await;
    });
    (address.to_string(), server)
}

/// The shared workload client as the node binaries build it (no data plane in this harness).
async fn shared_client(address: &str) -> WorkloadClient {
    std::env::set_var("IOI_SHMEM_ID", "ioi-d2a-red4-no-such-region");
    std::env::set_var("IOI_SHMEM_CONNECT_RETRIES", "0");
    WorkloadClient::new(address, "", "", "")
        .await
        .expect("workload client")
}

// --- The violations a run collects ----------------------------------------------------------------

/// Every violation one T1 run found, by class. T1's PASS condition is that the first four classes
/// are empty; `refused_reads` (a consumer surface refusing an admitted height) is allowed by T1 and
/// reported, and is a failure only in the no-write control.
#[derive(Default)]
struct Report {
    /// A mutating write that did not succeed, or did not land (a fence in its path).
    refused_writes: Vec<String>,
    /// A read that returned a value other than the admission record: a rewritten root, or a
    /// response mixing the record with another observation (e.g. a stored block's timestamp).
    wrong_values: Vec<String>,
    /// A read served for a height that was never admitted (N + 1, or anything with no admission).
    served_unadmitted: Vec<String>,
    /// An admitted height whose by-height RECORD was not served (the index holds every row).
    missing_records: Vec<String>,
    /// A consumer surface that refused an admitted height (allowed by T1's PASS condition).
    refused_reads: Vec<String>,
}

impl Report {
    fn write<E: std::fmt::Display>(&mut self, what: &str, result: Result<(), E>) {
        if let Err(error) = result {
            self.refused_writes.push(format!("{what}: {error}"));
        }
    }

    /// A by-height record read at an admitted height.
    fn record(
        &mut self,
        what: &str,
        read: Result<Option<AdmittedRecord>, String>,
        expected: &AdmittedRecord,
    ) {
        match read {
            Ok(Some(got)) if &got == expected => {}
            Ok(Some(got)) => self.wrong_values.push(format!(
                "{what} = {}; the admission recorded {}",
                show(&got),
                show(expected)
            )),
            Ok(None) => self
                .missing_records
                .push(format!("{what}: no record for an admitted height")),
            Err(error) => self
                .missing_records
                .push(format!("{what}: refused for an admitted height: {error}")),
        }
    }

    /// A C5 anchor read at an admitted height (or "latest" with `expected` the max record).
    fn anchor(
        &mut self,
        what: &str,
        read: Result<(StateRoot, u64), String>,
        expected: &AdmittedRecord,
    ) {
        match read {
            Ok((root, height)) if root.0 == expected.state_root && height == expected.height => {}
            Ok((root, height)) => self.wrong_values.push(format!(
                "{what} = (root {}.., height {height}); the admission recorded {}",
                short(&root.0),
                show(expected)
            )),
            Err(error) => self.refused_reads.push(format!("{what}: {error}")),
        }
    }

    fn render(&self) -> String {
        let mut out = String::new();
        for (class, entries) in [
            ("write refused", &self.refused_writes),
            ("wrong value", &self.wrong_values),
            ("served unadmitted", &self.served_unadmitted),
            ("missing record", &self.missing_records),
            ("refused read (allowed)", &self.refused_reads),
        ] {
            out.push_str(&format!("  {class}: {}\n", entries.len()));
            for entry in entries {
                out.push_str(&format!("    [{class}] {entry}\n"));
            }
        }
        out
    }

    /// T1's PASS condition.
    fn assert_t1(&self, test: &str) {
        let pass = self.refused_writes.is_empty()
            && self.wrong_values.is_empty()
            && self.served_unadmitted.is_empty()
            && self.missing_records.is_empty();
        assert!(pass, "{test}: T1 VIOLATED\n{}", self.render());
        eprintln!("{test}: T1 held\n{}", self.render());
    }

    /// The no-write control: T1's condition AND every admitted height served on every surface.
    fn assert_served_everywhere(&self, test: &str) {
        let pass = self.refused_writes.is_empty()
            && self.wrong_values.is_empty()
            && self.served_unadmitted.is_empty()
            && self.missing_records.is_empty()
            && self.refused_reads.is_empty();
        assert!(
            pass,
            "{test}: NOT SERVED FROM THE RECORDS\n{}",
            self.render()
        );
    }
}

// --- The workload under test ----------------------------------------------------------------------

/// The real workload end of the IPC (see the module docs).
struct Workload {
    store: Arc<RedbEpochStore>,
    chain: Arc<ChainControlImpl<Cs, St>>,
    client: WorkloadClient,
    server: tokio::task::JoinHandle<()>,
    address: String,
    /// NET-DECISIONS 7: the harness SERIALIZES its tests with a process-wide lock, held for each
    /// workload's lifetime, because it sets IOI_SHMEM_* process-wide for the shared client.
    _serial: tokio::sync::MutexGuard<'static, ()>,
}

/// The process-wide lock that serializes this harness's tests (see `Workload::_serial`).
fn harness_serial() -> &'static tokio::sync::Mutex<()> {
    static SERIAL: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    SERIAL.get_or_init(|| tokio::sync::Mutex::new(()))
}

impl Workload {
    async fn start(store_path: &Path) -> Self {
        let serial = harness_serial().lock().await;
        let store = Arc::new(open_store(store_path).await);
        let container = Arc::new(
            WorkloadContainer::new(
                workload_config(),
                IAVLTree::new(HashCommitmentScheme::new()),
                Box::new(NoVm),
                None,
                ServiceDirectory::default(),
                store.clone() as Arc<dyn NodeStore>,
            )
            .expect("workload container"),
        );
        let machine = ExecutionMachine::new(
            HashCommitmentScheme::new(),
            UnifiedTransactionModel::new(HashCommitmentScheme::new()),
            1.into(),
            Vec::new(),
            Consensus::Solo(SoloEngine::new()),
            container.clone(),
            BTreeMap::new(),
            Arc::new(StubOs),
        )
        .expect("execution machine");
        let chain = Arc::new(ChainControlImpl {
            ctx: Arc::new(RpcContext {
                machine: Arc::new(tokio::sync::Mutex::new(machine)),
                workload: container,
                data_plane: None,
                admission_capability: WorkloadCapability::from_bytes(CAPABILITY),
            }),
        });
        let (address, server) = serve(chain.clone()).await;
        let client = shared_client(&address).await;
        Self {
            store,
            chain,
            client,
            server,
            address,
            _serial: serial,
        }
    }

    /// Stops the server and drops every handle on the store (the "process" ends).
    async fn stop(self) {
        let Self {
            store,
            chain,
            client,
            server,
            address: _,
            _serial,
        } = self;
        drop(client);
        server.abort();
        let _ = server.await;
        drop(chain);
        drop(store);
        drop(_serial);
    }

    /// Executes `blocks` into the store as the workload's commit writes them (genesis by
    /// put_block, as the execution app does at first boot; every later height by one
    /// state-and-block commit, as the IAVL and Jellyfish backends do) and moves the machine's
    /// executed tip to the last of them.
    async fn execute(&self, blocks: &[Block<ChainTransaction>]) {
        for block in blocks {
            let bytes = codec::to_bytes_canonical(block).expect("block bytes");
            if block.header.height == 0 {
                self.store
                    .put_block(0, &bytes)
                    .await
                    .expect("store genesis");
            } else {
                self.store
                    .commit_block_with_payload(commit_input(block), &bytes)
                    .await
                    .expect("execute the height");
            }
        }
        self.set_executed_tip(blocks).await;
    }

    /// The machine's executed tip (what a process_block or a tip replacement leaves behind).
    async fn set_executed_tip(&self, blocks: &[Block<ChainTransaction>]) {
        let tip = blocks.last().expect("an executed tip").clone();
        let mut machine = self.chain.ctx.machine.lock().await;
        machine.state.status.height = tip.header.height;
        machine.state.status.latest_timestamp = tip.header.timestamp;
        machine.state.status.latest_timestamp_ms = tip.header.timestamp_ms;
        machine.state.last_state_root = tip.header.state_root.0.clone();
        machine.state.recent_blocks = blocks
            .iter()
            .filter(|block| block.header.height > 0)
            .cloned()
            .collect();
    }

    /// Records `block` through the REAL RecordAdmittedTip handler, with the workload's capability:
    /// the call the orchestration's admitted-tip publisher makes over the IPC (the index's only
    /// writer).
    async fn admit(&self, block: &Block<ChainTransaction>) -> Result<(), tonic::Status> {
        self.chain
            .record_admitted_tip(Request::new(RecordAdmittedTipRequest {
                height: block.header.height,
                block_hash: hash_of(block).to_vec(),
                state_root: block.header.state_root.0.clone(),
                capability: CAPABILITY.to_vec(),
                // GREEN-4 (the marked fixture line): the admitted header's timestamp, as the
                // publisher sends it from the ledger's staged block.
                timestamp: block.header.timestamp,
            }))
            .await
            .map(|_| ())
    }

    /// A write the harness made must also have LANDED (the store holds exactly the written block),
    /// or the attack it stands for proves nothing.
    fn check_landed(&self, what: &str, block: &Block<ChainTransaction>, report: &mut Report) {
        match self.store.get_block_by_height(block.header.height) {
            Ok(Some(stored)) if &stored == block => {}
            other => report.refused_writes.push(format!(
                "{what}: acknowledged, but the store holds {:?} instead of the written block",
                other.map(|stored| stored.map(|stored| short(&hash_of(&stored))))
            )),
        }
    }

    /// UpdateBlockHeader through the shared client, over the unauthenticated IPC.
    async fn update_block_header(
        &self,
        what: &str,
        block: &Block<ChainTransaction>,
        report: &mut Report,
    ) {
        let result = WorkloadClientApi::update_block_header(&self.client, block.clone())
            .await
            .map_err(|error| error.to_string());
        let succeeded = result.is_ok();
        report.write(what, result);
        if succeeded {
            self.check_landed(what, block, report);
        }
    }

    /// A state-and-block commit through the store API (what a replacement or a re-execution
    /// commits at that height).
    async fn commit_through_the_store(
        &self,
        what: &str,
        block: &Block<ChainTransaction>,
        report: &mut Report,
    ) {
        let bytes = codec::to_bytes_canonical(block).expect("block bytes");
        let result = self
            .store
            .commit_block_with_payload(commit_input(block), &bytes)
            .await
            .map_err(|error| error.to_string());
        let succeeded = result.is_ok();
        report.write(what, result);
        if succeeded {
            self.check_landed(what, block, report);
        }
    }

    /// Every committed surface, for every admitted height in `records` (1..=N), for N + 1 and for
    /// "latest".
    async fn read_every_committed_surface(&self, records: &[AdmittedRecord], report: &mut Report) {
        for record in records {
            let height = record.height;
            report.record(
                &format!("store index[{height}]"),
                self.store
                    .get_admitted_record(height)
                    .map_err(|error| error.to_string()),
                record,
            );
            report.record(
                &format!("client get_admitted_record({height})"),
                WorkloadClientApi::get_admitted_record(&self.client, height)
                    .await
                    .map_err(|error| error.to_string()),
                record,
            );
            report.anchor(
                &format!("C5 resolve_query_anchor(Some({height}))"),
                committed_query_anchor(&self.client, Some(height))
                    .await
                    .map_err(|error| error.to_string()),
                record,
            );
        }
        self.read_unadmitted(N + 1, report).await;
        let latest = records.last().expect("records 1..=N");
        self.read_latest(latest, report).await;
    }

    /// A height that was never admitted: every by-height surface refuses it.
    async fn read_unadmitted(&self, height: u64, report: &mut Report) {
        if let Ok(Some(record)) = self.store.get_admitted_record(height) {
            report.served_unadmitted.push(format!(
                "store index[{height}] = {} for a height never admitted",
                show(&record)
            ));
        }
        if let Ok(Some(record)) = WorkloadClientApi::get_admitted_record(&self.client, height).await
        {
            report.served_unadmitted.push(format!(
                "client get_admitted_record({height}) = {} for a height never admitted",
                show(&record)
            ));
        }
        if let Ok((root, served)) = committed_query_anchor(&self.client, Some(height)).await {
            report.served_unadmitted.push(format!(
                "C5 resolve_query_anchor(Some({height})) = (root {}.., height {served}): a block never admitted",
                short(&root.0)
            ));
        }
    }

    /// "latest": every surface is the max record, in one observation.
    async fn read_latest(&self, latest: &AdmittedRecord, report: &mut Report) {
        match self
            .chain
            .get_committed_tip(Request::new(GetStatusRequest {}))
            .await
        {
            Ok(response) => {
                let tip = response.into_inner();
                if tip.height != latest.height
                    || tip.block_hash != latest.block_hash.to_vec()
                    || tip.state_root != latest.state_root
                    || tip.latest_timestamp != latest.timestamp
                {
                    report.wrong_values.push(format!(
                        "GetCommittedTip (handler) = (height {}, hash {}.., root {}.., timestamp {}); the max record is {}",
                        tip.height,
                        short(&tip.block_hash),
                        short(&tip.state_root),
                        tip.latest_timestamp,
                        show(latest)
                    ));
                }
            }
            Err(status) => report
                .refused_reads
                .push(format!("GetCommittedTip (handler): {status}")),
        }
        match WorkloadClientApi::get_committed_tip(&self.client).await {
            Ok(Some(tip)) if tip == tip_of(latest) => {}
            Ok(Some(tip)) => report.wrong_values.push(format!(
                "client get_committed_tip = (height {}, hash {}.., root {}..); the max record is {}",
                tip.height,
                short(&tip.block_hash),
                short(&tip.state_root),
                show(latest)
            )),
            Ok(None) => report
                .refused_reads
                .push("client get_committed_tip: none, although 1..=N are admitted".into()),
            Err(error) => report
                .refused_reads
                .push(format!("client get_committed_tip: {error}")),
        }
        report.anchor(
            "C5 resolve_query_anchor(None)",
            committed_query_anchor(&self.client, None)
                .await
                .map_err(|error| error.to_string()),
            latest,
        );
        match committed_state_root(&self.client).await {
            Ok(root) if root.0 == latest.state_root => {}
            Ok(root) => report.wrong_values.push(format!(
                "C7 committed_state_root = {}..; the max record is {}",
                short(&root.0),
                show(latest)
            )),
            Err(error) => report
                .refused_reads
                .push(format!("C7 committed_state_root: {error}")),
        }
        // C6: the committed status the licence check reads; its height is the licence-expiry
        // committed height, and its timestamp must be the record's (one observation).
        match WorkloadClientApi::get_committed_status(&self.client).await {
            Ok(status)
                if status.height == latest.height
                    && status.latest_timestamp == latest.timestamp => {}
            Ok(status) => report.wrong_values.push(format!(
                "C6 get_committed_status = (height {}, timestamp {}); the max record is {}",
                status.height,
                status.latest_timestamp,
                show(latest)
            )),
            Err(error) => report
                .refused_reads
                .push(format!("C6 get_committed_status: {error}")),
        }
    }

    /// Nothing admitted: no surface serves a committed tip, and none falls back to a stored block.
    async fn read_no_tip(&self, report: &mut Report) {
        if let Ok(response) = self
            .chain
            .get_committed_tip(Request::new(GetStatusRequest {}))
            .await
        {
            let tip = response.into_inner();
            if !tip.block_hash.is_empty() || tip.height != 0 {
                report.served_unadmitted.push(format!(
                    "GetCommittedTip (handler) = (height {}, hash {}..) with nothing admitted",
                    tip.height,
                    short(&tip.block_hash)
                ));
            }
        }
        if let Ok(Some(tip)) = WorkloadClientApi::get_committed_tip(&self.client).await {
            report.served_unadmitted.push(format!(
                "client get_committed_tip = height {} with nothing admitted",
                tip.height
            ));
        }
        if let Ok((root, height)) = committed_query_anchor(&self.client, None).await {
            report.served_unadmitted.push(format!(
                "C5 resolve_query_anchor(None) = (root {}.., height {height}) with nothing admitted: the no-tip fallback reads the committed status, then the block stored at that height (two observations, the second of mutable storage)",
                short(&root.0)
            ));
        }
        if let Ok(root) = committed_state_root(&self.client).await {
            report.served_unadmitted.push(format!(
                "C7 committed_state_root = {}.. with nothing admitted",
                short(&root.0)
            ));
        }
        if let Ok(status) = WorkloadClientApi::get_committed_status(&self.client).await {
            if status.height != 0 || status.latest_timestamp != 0 {
                report.served_unadmitted.push(format!(
                    "C6 get_committed_status = (height {}, timestamp {}) with nothing admitted",
                    status.height, status.latest_timestamp
                ));
            }
        }
    }
}

/// The T1 starting point: the workload executed genesis and 1..=N+1 (each with its producer's
/// signature and an epoch-1 sealed proof), and the admission publication recorded 1..=N.
async fn admitted_workload(
    dir: &tempfile::TempDir,
) -> (
    Workload,
    Keypair,
    Vec<Block<ChainTransaction>>,
    Vec<AdmittedRecord>,
) {
    let producer = Keypair::generate_ed25519();
    let blocks = executed_chain(&producer, true);
    let workload = Workload::start(&dir.path().join("state.db")).await;
    workload.execute(&blocks).await;
    let mut records = Vec::new();
    for block in &blocks[1..=N as usize] {
        workload.admit(block).await.unwrap_or_else(|status| {
            panic!(
                "the admission publication records admitted height {}: {status}",
                block.header.height
            )
        });
        records.push(record_of(block));
    }
    (workload, producer, blocks, records)
}

// --- T1: the adopt gate ---------------------------------------------------------------------------

/// T1 CONTROL (no write; RED-4: fails at 5c77c9ca0). With nothing written after admission, every
/// committed surface serves the admission record for every admitted height (no refusal: the
/// index serves them all), and N+1 is refused. Fails at 5c77c9ca0: no store keeps an index (the
/// `get_admitted_record` defaults return None: 8 missing records), and C5's explicit height is
/// served from the stored block above the marker (transport-verifier lib.rs:208-213 at 5c77c9ca0:
/// N+1 served).
#[tokio::test]
async fn t1_0_control_without_any_write_every_committed_surface_serves_the_admission_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (workload, _producer, _blocks, records) = admitted_workload(&dir).await;
    let mut report = Report::default();
    workload
        .read_every_committed_surface(&records, &mut report)
        .await;
    report.assert_served_everywhere("T1-0 control");
}

/// T1 (i), RED-4. UpdateBlockHeader(h < N) with ANOTHER STATE ROOT, for every h in 1..N, over the
/// unauthenticated IPC: each write SUCCEEDS and lands, and no committed read changes. Fails at
/// 5c77c9ca0: the fence refuses every write (grpc_blockchain.rs:440-456 ->
/// header_update_respects_admission_floor :645-673, a different consensus identity), plus the
/// missing index and N+1 served (as T1-0).
#[tokio::test]
async fn t1_i_update_block_header_below_the_max_with_another_state_root_changes_no_committed_read()
{
    let dir = tempfile::tempdir().expect("tempdir");
    let (workload, _producer, blocks, records) = admitted_workload(&dir).await;
    let mut report = Report::default();
    for height in 1..N {
        let mut other_root = blocks[height as usize].clone();
        other_root.header.state_root = StateRoot(vec![0xB0 + height as u8; 32]);
        workload
            .update_block_header(
                &format!("UpdateBlockHeader({height}) with another state root"),
                &other_root,
                &mut report,
            )
            .await;
    }
    workload
        .read_every_committed_surface(&records, &mut report)
        .await;
    report.assert_t1("T1 (i)");
}

/// T1 (ii), RED-4. UpdateBlockHeader(h < N) with STRIPPED EVIDENCE: height 1 without its
/// signature, height 2 without its sealed proof, height 3 without both. Each write SUCCEEDS and
/// lands; no committed read changes. Fails at 5c77c9ca0: the fence refuses the strips
/// (redb_epoch_store.rs:125-136 via grpc_blockchain.rs:666-673), plus the missing index and N+1.
#[tokio::test]
async fn t1_ii_update_block_header_below_the_max_with_stripped_evidence_changes_no_committed_read()
{
    let dir = tempfile::tempdir().expect("tempdir");
    let (workload, _producer, blocks, records) = admitted_workload(&dir).await;
    let mut report = Report::default();
    for (height, strip_signature, strip_proof) in
        [(1u64, true, false), (2, false, true), (3, true, true)]
    {
        let mut stripped = blocks[height as usize].clone();
        if strip_signature {
            stripped.header.signature = Vec::new();
        }
        if strip_proof {
            stripped.header.sealed_finality_proof = None;
        }
        workload
            .update_block_header(
                &format!(
                    "UpdateBlockHeader({height}) stripped (signature: {strip_signature}, sealed proof: {strip_proof})"
                ),
                &stripped,
                &mut report,
            )
            .await;
    }
    workload
        .read_every_committed_surface(&records, &mut report)
        .await;
    report.assert_t1("T1 (ii)");
}

/// T1 (iii), RED-4 (the IOI Director's point 3, kept in the form NET and the Director agreed: the
/// workload decides nothing from a proof). UpdateBlockHeader(h < N) with a WRONG-EPOCH sealed proof
/// (epoch 2, signed by the block's producer and bound to its oracle counter and trace, i.e. what
/// GREEN-3's wrapper accepts without checking the epoch's committee). Each write SUCCEEDS; no
/// committed read changes. At 5c77c9ca0 the fence ACCEPTS these writes (round-2 finding 4); the
/// test fails there on the missing index and N+1 only.
#[tokio::test]
async fn t1_iii_update_block_header_below_the_max_with_a_wrong_epoch_proof_changes_no_committed_read(
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let (workload, producer, blocks, records) = admitted_workload(&dir).await;
    let mut report = Report::default();
    for height in 1..N {
        let mut wrong_epoch = blocks[height as usize].clone();
        wrong_epoch.header.sealed_finality_proof =
            Some(finality_proof(&wrong_epoch.header, 2, &producer));
        workload
            .update_block_header(
                &format!("UpdateBlockHeader({height}) with an epoch-2 sealed proof"),
                &wrong_epoch,
                &mut report,
            )
            .await;
    }
    workload
        .read_every_committed_surface(&records, &mut report)
        .await;
    report.assert_t1("T1 (iii)");
}

/// T1 (iv), RED-4. ReplaceUnfinalizedTip BELOW N (target N-1, the caller claiming recognized
/// height 0):
/// (a) the REAL handler: the request must reach the execution machine, i.e. nothing in front of
///     it refuses on the admitted height. This Solo-engine fixture cannot complete a replacement
///     (an AFT machine with rollback snapshots needs the consensus-aft feature and real AFT
///     commits; and N-1 is beyond the two-projection bound, execution app/mod.rs:155 and :201),
///     so "reached" is the machine's own refusal, "tip replacement is available only to the
///     canonical AFT profile" (app/mod.rs:583);
/// (b) the replacement's DURABLE effect at the nearest layer the fixture reaches: its
///     state-and-block commit at N-1 through the store API, and the executed tip rolled back to
///     it. It SUCCEEDS; no committed read changes.
/// Fails at 5c77c9ca0: (a) is refused by the fence (grpc_blockchain.rs:270-281 ->
/// replacement_respects_admission_floor :702-714), (b) by the store fence
/// (redb_epoch_store.rs:1043 -> :821-851), plus the missing index.
#[tokio::test]
async fn t1_iv_a_tip_replacement_below_the_max_changes_no_committed_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (workload, _producer, blocks, records) = admitted_workload(&dir).await;
    let mut report = Report::default();
    let target = blocks[(N - 1) as usize].clone();
    let live_tip = blocks[(N + 1) as usize].clone();
    let replacement = rewritten(&target, 0xC0 + (N - 1) as u8);
    let request = ReplaceUnfinalizedTipRequest {
        replacement_block_bytes: codec::to_bytes_canonical(&replacement).expect("bytes"),
        expected_tip_height: N - 1,
        expected_parent_state_root: target.header.parent_state_root.0.clone(),
        expected_state_root: target.header.state_root.0.clone(),
        expected_transactions_root: target.header.transactions_root.clone(),
        recognized_height: 0,
        expected_target_block_bytes: codec::to_bytes_canonical(&target).expect("bytes"),
        expected_live_tip_block_bytes: codec::to_bytes_canonical(&live_tip).expect("bytes"),
    };
    match workload
        .chain
        .replace_unfinalized_tip(Request::new(request))
        .await
    {
        Ok(_) => {}
        Err(status) if status.message().contains("canonical AFT profile") => {}
        Err(status) => report.refused_writes.push(format!(
            "ReplaceUnfinalizedTip({}) was refused before it reached the execution machine: {status}",
            N - 1
        )),
    }
    workload
        .commit_through_the_store(
            &format!("the replacement's commit at {}", N - 1),
            &replacement,
            &mut report,
        )
        .await;
    let mut executed = blocks[..(N - 1) as usize].to_vec();
    executed.push(replacement);
    workload.set_executed_tip(&executed).await;
    workload
        .read_every_committed_surface(&records, &mut report)
        .await;
    report.assert_t1("T1 (iv)");
}

/// T1 (v), RED-4. Prune VERSIONS[1..=N], then CommitState(h, B != A) at the pruned heights N-1 and
/// N through the store API. The writes SUCCEED; no committed read changes (the record, not a state
/// version, is the committed root). At 5c77c9ca0 the writes succeed too (a pruned version may be
/// re-created, redb_epoch_store.rs:154-165, R-STATE-RECREATE); the test fails there on the missing
/// index and N+1 only.
#[tokio::test]
async fn t1_v_prune_then_commit_another_root_at_a_pruned_height_changes_no_committed_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (workload, _producer, _blocks, records) = admitted_workload(&dir).await;
    let mut report = Report::default();
    report.write(
        "prune VERSIONS below N+1",
        workload
            .store
            .prune_batch(N + 1, &[], 1_000)
            .map(|_| ())
            .map_err(|error| error.to_string()),
    );
    for height in [N - 1, N] {
        let other_root = RootHash([0xD0 + height as u8; 32]);
        let what = format!("CommitState({height}) with another root after the prune");
        let result = workload
            .store
            .commit_block(CommitInput {
                height,
                root: other_root,
                unique_nodes_for_height: Vec::new(),
                new_nodes: Vec::new(),
            })
            .await
            .map_err(|error| error.to_string());
        let succeeded = result.is_ok();
        report.write(&what, result);
        if succeeded {
            match workload.store.root_for_height(height) {
                Ok(Some(root)) if root == other_root => {}
                other => report.refused_writes.push(format!(
                    "{what}: acknowledged, but VERSIONS[{height}] is {other:?}"
                )),
            }
        }
    }
    workload
        .read_every_committed_surface(&records, &mut report)
        .await;
    report.assert_t1("T1 (v)");
}

/// T1 (vii), RED-4. A REPLACEMENT in flight during a "latest" read, at this harness's layer (the
/// write landed; held truly IN FLIGHT, mid-write, at the store layer in ioi-storage
/// `admitted_index_tests::t1_vii_*`): the workload replaces the admitted max N (another root and a
/// later timestamp) and re-executes N+1 on the replaced branch, through the store API, and its
/// executed tip moves there. Both commits SUCCEED; every "latest" read is still the max record,
/// including its timestamp (one observation: no response pairs record N with the replacement's
/// timestamp). Fails at 5c77c9ca0: the store fence refuses the commit at N
/// (redb_epoch_store.rs:1043 -> :821-851), N+1 is served (C5 explicit), plus the missing index.
#[tokio::test]
async fn t1_vii_a_replacement_of_the_max_during_a_latest_read_changes_no_committed_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (workload, _producer, blocks, records) = admitted_workload(&dir).await;
    let mut report = Report::default();
    let replaced_max = rewritten(&blocks[N as usize], 0xC0 + N as u8);
    let mut replaced_next = rewritten(&blocks[(N + 1) as usize], 0xC0 + (N + 1) as u8);
    replaced_next.header.parent_hash = hash_of(&replaced_max);
    workload
        .commit_through_the_store(
            &format!("the replacement's commit at the admitted max {N}"),
            &replaced_max,
            &mut report,
        )
        .await;
    workload
        .commit_through_the_store(
            &format!("the re-executed {} on the replaced branch", N + 1),
            &replaced_next,
            &mut report,
        )
        .await;
    let mut executed = blocks[..N as usize].to_vec();
    executed.push(replaced_max);
    executed.push(replaced_next);
    workload.set_executed_tip(&executed).await;
    workload
        .read_every_committed_surface(&records, &mut report)
        .await;
    report.assert_t1("T1 (vii)");
}

/// T1 (no tip), RED-4 (round-2 BLOCKER 2, both halves). The workload executed genesis and 1..=N+1
/// and NOTHING is admitted: every committed read refuses. No explicit height is served from a
/// stored block, and "latest" does not fall back to the committed status and then the block stored
/// at that height (two observations). Fails at 5c77c9ca0: C5 serves every stored height
/// (transport-verifier lib.rs:208-213) and "latest" falls back to the stored genesis block
/// (lib.rs:203-213 -> resolve_query_height :189).
#[tokio::test]
async fn t1_no_tip_with_nothing_admitted_every_committed_read_refuses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let producer = Keypair::generate_ed25519();
    let blocks = executed_chain(&producer, true);
    let workload = Workload::start(&dir.path().join("state.db")).await;
    workload.execute(&blocks).await;
    let mut report = Report::default();
    for height in 0..=N + 1 {
        workload.read_unadmitted(height, &mut report).await;
    }
    workload.read_no_tip(&mut report).await;
    report.assert_t1("T1 (no tip)");
}

// --- T5 through the publication handler -----------------------------------------------------------

/// T5 at the publication path (the IOI Director), RED-4. A re-publication of an ADMITTED height
/// through the RecordAdmittedTip handler: the identical record (a restart redrive, a reconcile, a
/// parent_hash gap-fill walk) is an idempotent no-op below the max and at it; another block hash
/// with the same root (the stored-block cross-check passes) is refused; every index row and the
/// max stay as admitted. Fails at 5c77c9ca0: the identical re-publication of height 2 is refused
/// ("cannot move back", redb_epoch_store.rs:1396-1401), and there is no index.
#[tokio::test]
async fn t5_a_republication_through_the_record_handler_never_rewrites_an_index_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (workload, _producer, blocks, records) = admitted_workload(&dir).await;
    for height in [2, N] {
        if let Err(status) = workload.admit(&blocks[height as usize]).await {
            panic!(
                "an identical re-publication of admitted height {height} is an idempotent no-op: {status}"
            );
        }
    }
    for height in [2, N] {
        let mut other_identity = blocks[height as usize].clone();
        other_identity.header.view = 9;
        assert!(
            workload.admit(&other_identity).await.is_err(),
            "index[{height}] is written once: another block hash (same root) is refused"
        );
    }
    for record in &records {
        assert_eq!(
            workload
                .store
                .get_admitted_record(record.height)
                .ok()
                .flatten(),
            Some(record.clone()),
            "index[{}] is the admission record",
            record.height
        );
    }
    assert_eq!(
        workload.store.get_admitted_tip().ok().flatten(),
        records.last().map(tip_of),
        "the max entry did not move"
    );
}

// --- T6: restart ------------------------------------------------------------------------------------

/// T6 (the IOI Director), RED-4. After the workload stops (its server, machine and every store
/// handle dropped) and starts again on the same store file (a new machine, server and shared
/// client), every committed read returns the same records: the index is durable, not a cache.
/// Fails at 5c77c9ca0: no index (8 missing records) and N+1 served.
#[tokio::test]
async fn t6_after_the_workload_and_its_store_reopen_every_committed_read_returns_the_same_records()
{
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.db");
    let producer = Keypair::generate_ed25519();
    let blocks = executed_chain(&producer, true);
    let records: Vec<AdmittedRecord> = blocks[1..=N as usize].iter().map(record_of).collect();
    {
        let workload = Workload::start(&path).await;
        workload.execute(&blocks).await;
        for block in &blocks[1..=N as usize] {
            workload.admit(block).await.unwrap_or_else(|status| {
                panic!(
                    "the admission publication records admitted height {}: {status}",
                    block.header.height
                )
            });
        }
        workload.stop().await;
    }
    let restarted = Workload::start(&path).await;
    restarted.set_executed_tip(&blocks).await;
    let mut report = Report::default();
    restarted
        .read_every_committed_surface(&records, &mut report)
        .await;
    report.assert_served_everywhere("T6 restart");
}

// --- T2: the publisher emits only ledger truths ---------------------------------------------------

/// A single-authority Agentgres ledger in `dir` (as the sync harness opens one).
fn open_ledger(dir: &Path) -> RuntimeFinalityCoordinator {
    let seed = [42u8; 32];
    let key = ioi_crypto::sign::eddsa::Ed25519PrivateKey::from_bytes(&seed).expect("ledger key");
    RuntimeFinalityCoordinator::open(
        dir.join("finality"),
        "admitted-index".into(),
        RuntimeFinalityProfile::SingleAuthorityV1,
        "admitted-index-writer".into(),
        || runtime_finality_initial_head(None),
        format!(
            "key://test/{}",
            hex::encode(key.public_key().expect("ledger public key").as_bytes())
        ),
        &seed,
    )
    .expect("open the ledger")
}

/// The capability file this boot's workload wrote (0600, in a private 0700 directory).
fn capability_file(dir: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let private = dir.join("workload-capability");
    std::fs::create_dir_all(&private).expect("capability directory");
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
        .expect("private directory");
    let path = private.join("workload-admission.capability");
    write_capability_file(&path, &WorkloadCapability::from_bytes(CAPABILITY))
        .expect("write the capability file");
    path
}

/// T2, RED-4 (round-2 BLOCKER 1 by construction). A module OUTSIDE the publisher's module (this
/// one) builds a publisher from the workload's capability file and calls its ONE operation
/// (`RuntimeFinalityCoordinator::publish_admitted_head` since GREEN-4: the publisher is installed
/// in the ledger, whose own head it publishes) while the workload's executed tip, and the ledger's
/// newest STAGED block, is N+1, which Agentgres never admitted.
/// - CONTROL: the operation publishes the ledger's canonical head N: index[N] is N's record.
/// - THE CALL: the same operation again is refused or a no-op: index[N+1] stays empty, and
///   index[N] and the max entry are unchanged.
/// Fails at 5c77c9ca0 at the control: the publication reaches the marker (the scaffold is today's
/// reconcile, runtime_finality.rs:306-315 -> publish :277-302) but there is no index to read N's
/// record from. (The caller-supplied-tip API that IS the blocker, `publish(tip)` :277 and
/// `reconcile(block)` :306, cannot be called from a test that must compile at GREEN-4, where they
/// are deleted; their absence is a GREEN-4 check, see the manifest.)
#[tokio::test]
async fn t2_a_publisher_built_outside_its_module_publishes_only_the_ledger_head() {
    let dir = tempfile::tempdir().expect("tempdir");
    let producer = Keypair::generate_ed25519();
    let blocks = executed_chain(&producer, false);

    let mut ledger = open_ledger(dir.path());
    for block in &blocks[1..=N as usize] {
        ledger
            .stage_block(block.clone(), Vec::new())
            .expect("stage an admitted block");
        ledger
            .admit_single_authority(hash_of(block), 1_700_000_000_000 + block.header.height)
            .expect("Agentgres admits the block");
    }
    ledger
        .stage_block(blocks[(N + 1) as usize].clone(), Vec::new())
        .expect("stage N+1, never admitted");
    let ledger = tokio::sync::Mutex::new(ledger);

    let workload = Workload::start(&dir.path().join("state.db")).await;
    workload.execute(&blocks).await;
    // Built HERE, outside runtime_finality, from the workload's capability file; installed in the
    // ledger, whose ledger-reading publication is the publisher's only operation (GREEN-4,
    // NET-DECISIONS 1; the declared T2 fixture line). RED-5: through the capability SOURCE, the
    // only constructor reachable outside the publisher's module after GREEN-5 (no assertion
    // changed).
    let source = AdmissionCapabilitySource::file(capability_file(dir.path()), &workload.address);
    ledger
        .lock()
        .await
        .install_admission_capability(source)
        .expect("install the publisher");

    RuntimeFinalityCoordinator::publish_admitted_head(&ledger)
        .await
        .expect("CONTROL: the ledger's canonical head publishes");
    let head = record_of(&blocks[N as usize]);
    assert_eq!(
        workload.store.get_admitted_record(N).ok().flatten(),
        Some(head.clone()),
        "CONTROL: index[N] is the ledger head's record"
    );

    let _ = RuntimeFinalityCoordinator::publish_admitted_head(&ledger).await;
    assert_eq!(
        workload.store.get_admitted_record(N + 1).ok().flatten(),
        None,
        "the executed, staged, never-admitted N+1 is never published"
    );
    assert_eq!(
        workload.store.get_admitted_record(N).ok().flatten(),
        Some(head.clone()),
        "index[N] is unchanged"
    );
    assert_eq!(
        workload.store.get_admitted_tip().ok().flatten(),
        Some(tip_of(&head)),
        "the max entry is unchanged"
    );
}

// --- RED-5 B1 (ii): the reviewer's case, outside the publisher's module -----------------------------

/// A single-authority Agentgres ledger in `dir` (as `open_ledger` opens one) whose BOOTSTRAP
/// canonical head, the spine genesis's `initial_canonical_head`, is `initial`.
fn open_ledger_bootstrapped_at(dir: &Path, initial: String) -> RuntimeFinalityCoordinator {
    let seed = [42u8; 32];
    let key = ioi_crypto::sign::eddsa::Ed25519PrivateKey::from_bytes(&seed).expect("ledger key");
    RuntimeFinalityCoordinator::open(
        dir.join("finality"),
        "admitted-index".into(),
        RuntimeFinalityProfile::SingleAuthorityV1,
        "admitted-index-writer".into(),
        move || Ok(initial),
        format!(
            "key://test/{}",
            hex::encode(key.public_key().expect("ledger public key").as_bytes())
        ),
        &seed,
    )
    .expect("open the ledger on a bootstrap head")
}

/// RED-5 B1 (ii) (review round 3 BLOCKER B1, the reviewer's case; DISPOSITION condition 1). In a
/// module OUTSIDE the publisher's (this one), against the REAL workload: a ledger whose BOOTSTRAP
/// head is B (height 1), which the workload EXECUTED and the ledger STAGED but Agentgres never
/// admitted (zero admissions), gets its publisher through the only constructor reachable here
/// (the capability source) and publishes: nothing is indexed (no row, no max entry).
/// CONTROL (iii): Agentgres admits B's child B' (height 2) on that bootstrap head; the publication
/// indexes B' and never B, not even as B''s parent. Fails at 9ad9cf0e4 at the first check: B is
/// published from `last_admitted_block` (runtime_finality.rs:1852-1866 there) and the workload's
/// handler indexes it (B is the block stored at height 1).
#[tokio::test]
async fn b1_ii_a_ledger_bootstrapped_on_an_executed_unadmitted_block_publishes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let producer = Keypair::generate_ed25519();
    let blocks = executed_chain(&producer, false);
    let (b, child) = (&blocks[1], &blocks[2]);

    let mut ledger = open_ledger_bootstrapped_at(
        dir.path(),
        canonical_block_head(b).expect("B's canonical head"),
    );
    ledger
        .stage_block(b.clone(), Vec::new())
        .expect("stage B, never admitted");
    let ledger = tokio::sync::Mutex::new(ledger);

    let workload = Workload::start(&dir.path().join("state.db")).await;
    workload.execute(&blocks).await;
    let source = AdmissionCapabilitySource::file(capability_file(dir.path()), &workload.address);
    ledger
        .lock()
        .await
        .install_admission_capability(source)
        .expect("install the publisher");

    let first = RuntimeFinalityCoordinator::publish_admitted_head(&ledger).await;
    let rows: Vec<u64> = (0..=N + 1)
        .filter(|height| {
            workload
                .store
                .get_admitted_record(*height)
                .ok()
                .flatten()
                .is_some()
        })
        .collect();
    assert!(
        rows.is_empty(),
        "the never-admitted bootstrap head B is not indexed: rows {rows:?} (publication {first:?})"
    );
    assert_eq!(
        workload.store.get_admitted_tip().ok().flatten(),
        None,
        "no max entry"
    );
    first.expect("a bootstrap head is not an admission: nothing to publish");

    {
        let mut ledger = ledger.lock().await;
        ledger
            .stage_block(child.clone(), Vec::new())
            .expect("stage B'");
        ledger
            .admit_single_authority(hash_of(child), 1_700_000_000_002)
            .expect("Agentgres admits B' on the bootstrap head B");
    }
    RuntimeFinalityCoordinator::publish_admitted_head(&ledger)
        .await
        .expect("CONTROL: the admitted B' publishes");
    let admitted = record_of(child);
    assert_eq!(
        workload.store.get_admitted_record(2).ok().flatten(),
        Some(admitted.clone()),
        "CONTROL: index[2] is the admitted B' record"
    );
    assert_eq!(
        workload.store.get_admitted_record(1).ok().flatten(),
        None,
        "B is never indexed, not even as the parent of the admitted B'"
    );
    assert_eq!(
        workload.store.get_admitted_tip().ok().flatten(),
        Some(tip_of(&admitted)),
        "the max entry is B'"
    );
}
