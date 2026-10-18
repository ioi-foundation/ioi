// Path: crates/validator/src/standard/orchestration/admitted_tip_publisher_tests.rs
//! FU-N11-DURABLE-STATUS-1 D2a: the ADMITTED-INDEX PUBLICATION. RED-3's publisher tests (V9-V15),
//! rewritten at GREEN-4 for the publisher's new shape: the publisher holds only the workload's
//! admission capability and a PRIVATE gRPC channel, and the coordinator's ledger-reading
//! `RuntimeFinalityCoordinator::publish_admitted_head` is its one operation (it publishes the
//! Agentgres ledger's head, then fills any gap below it by a parent_hash walk).
//!
//! The ledger is the sync harness's REAL `RuntimeFinalityCoordinator` (single-authority profile).
//! The workload is a SPY ChainControl served over loopback gRPC (the publisher's real private
//! channel reaches it): it records every RecordAdmittedTip as (capability, record), accepts only
//! the capability it is told to, and answers GetAdmittedRecord from the rows it accepted.
//!
//! RED-5 (review round 3, d2a/review3/DISPOSITION.md): every publisher is installed through the
//! capability SOURCE (`AdmissionCapabilitySource`), the only way to a publisher outside its module
//! after GREEN-5. New: B1 as a DATA rule (a block is published only as the head of a COMMITTED
//! admission effect in the ledger's own spine; the bootstrap head never is), the M2 negative pins
//! of the gap walk (a competing candidate; an ancestor at the wrong height), and m3 (the walk
//! resumes past held rows, bounded per call).
//!
//! RED-6 (review round 4, d2a/review4/DISPOSITION.md): a second publisher install is refused and the first stays
//! (finding 1(b), a GUARD); a span whose bottom staged envelope is missing is cleared and a later walk fills the rows it
//! skipped (finding 3, a RED). Finding 1(a)'s GUARD (a PRESENT effect naming another head) needs runtime_finality's
//! private access to forge the spine, so it lives in that module's tests and uses this spy.

use super::runtime_finality::{
    admit_available, canonical_block_head, reconcile_workload_admitted_tip,
    runtime_finality_initial_head, RuntimeFinalityCoordinator,
};
use super::sync_harness::{harness_block, harness_hash, Harness};
use super::AdmissionCapabilitySource;
use crate::standard::workload::admitted_tip::{write_capability_file, WorkloadCapability};
use ioi_api::storage::AdmittedRecord;
use ioi_ipc::blockchain::chain_control_server::{ChainControl, ChainControlServer};
use ioi_ipc::blockchain::{
    GetAdmittedRecordRequest, GetAdmittedRecordResponse, GetBlocksRangeRequest,
    GetBlocksRangeResponse, GetCommittedTipResponse, GetGenesisStatusRequest,
    GetGenesisStatusResponse, GetStatusRequest, GetStatusResponse, ProcessBlockRequest,
    ProcessBlockResponse, RecordAdmittedTipRequest, RecordAdmittedTipResponse,
    ReplaceUnfinalizedTipRequest, UpdateBlockHeaderRequest, UpdateBlockHeaderResponse,
};
use ioi_types::app::{Block, ChainTransaction};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};

/// The capability the workload accepts in most tests. (RED-6: `pub(super)`, with the spy and `serve`, for
/// runtime_finality's forged-spine fixture, which needs that module's private access.)
pub(super) const CAPABILITY: [u8; 32] = [0x5A; 32];
/// A restarted workload's rotated capability.
const ROTATED: [u8; 32] = [0x6B; 32];

/// The workload end of the publisher's private channel (see the module docs).
#[derive(Default)]
pub(super) struct SpyWorkload {
    accepted: Mutex<Option<[u8; 32]>>,
    presented: Mutex<Vec<([u8; 32], AdmittedRecord)>>,
    index: Mutex<BTreeMap<u64, AdmittedRecord>>,
    /// RED-5 m3: the 1-based number of the presented record the workload refuses, ONCE (an
    /// interruption in the middle of a gap fill).
    refuse_once_at: Mutex<Option<usize>>,
}

impl SpyWorkload {
    pub(super) fn accepting(capability: [u8; 32]) -> Arc<Self> {
        let spy = Self::default();
        *spy.accepted.lock().unwrap() = Some(capability);
        Arc::new(spy)
    }
    /// Rows the workload already holds (a publication of earlier heights that did land).
    fn holding(self: Arc<Self>, rows: &[AdmittedRecord]) -> Arc<Self> {
        for row in rows {
            self.index.lock().unwrap().insert(row.height, row.clone());
        }
        self
    }
    /// The workload refuses the `n`th presented record once (it is unavailable for that call).
    fn refusing_once_at(self: Arc<Self>, n: usize) -> Arc<Self> {
        *self.refuse_once_at.lock().unwrap() = Some(n);
        self
    }
    pub(super) fn presented(&self) -> Vec<([u8; 32], AdmittedRecord)> {
        self.presented.lock().unwrap().clone()
    }
    /// The heights the workload's index holds, ascending.
    fn heights(&self) -> Vec<u64> {
        self.index.lock().unwrap().keys().copied().collect()
    }
    /// RED-6: the workload no longer holds these rows (rows lost outside the append-only index model).
    fn forget(&self, heights: &[u64]) {
        let mut index = self.index.lock().unwrap();
        for height in heights {
            index.remove(height);
        }
    }
    fn index(&self) -> Vec<AdmittedRecord> {
        self.index.lock().unwrap().values().cloned().collect()
    }
}

fn unimplemented_rpc<T>() -> Result<Response<T>, Status> {
    Err(Status::unimplemented(
        "not served by the admitted-index spy",
    ))
}

#[tonic::async_trait]
impl ChainControl for SpyWorkload {
    async fn process_block(
        &self,
        _request: Request<ProcessBlockRequest>,
    ) -> Result<Response<ProcessBlockResponse>, Status> {
        unimplemented_rpc()
    }
    async fn replace_unfinalized_tip(
        &self,
        _request: Request<ReplaceUnfinalizedTipRequest>,
    ) -> Result<Response<ProcessBlockResponse>, Status> {
        unimplemented_rpc()
    }
    async fn get_blocks_range(
        &self,
        _request: Request<GetBlocksRangeRequest>,
    ) -> Result<Response<GetBlocksRangeResponse>, Status> {
        unimplemented_rpc()
    }
    async fn update_block_header(
        &self,
        _request: Request<UpdateBlockHeaderRequest>,
    ) -> Result<Response<UpdateBlockHeaderResponse>, Status> {
        unimplemented_rpc()
    }
    async fn get_genesis_status(
        &self,
        _request: Request<GetGenesisStatusRequest>,
    ) -> Result<Response<GetGenesisStatusResponse>, Status> {
        unimplemented_rpc()
    }
    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        unimplemented_rpc()
    }
    async fn get_execution_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        unimplemented_rpc()
    }
    async fn get_committed_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        unimplemented_rpc()
    }
    async fn record_admitted_tip(
        &self,
        request: Request<RecordAdmittedTipRequest>,
    ) -> Result<Response<RecordAdmittedTipResponse>, Status> {
        let request = request.into_inner();
        let capability: [u8; 32] = request
            .capability
            .as_slice()
            .try_into()
            .map_err(|_| Status::permission_denied("the capability is not 32 bytes"))?;
        let record = AdmittedRecord {
            height: request.height,
            block_hash: request
                .block_hash
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("block_hash must be 32 bytes"))?,
            state_root: request.state_root,
            timestamp: request.timestamp,
        };
        let count = {
            let mut presented = self.presented.lock().unwrap();
            presented.push((capability, record.clone()));
            presented.len()
        };
        {
            let mut refuse = self.refuse_once_at.lock().unwrap();
            if *refuse == Some(count) {
                *refuse = None;
                return Err(Status::unavailable(
                    "the workload was interrupted during the gap fill",
                ));
            }
        }
        if *self.accepted.lock().unwrap() != Some(capability) {
            return Err(Status::permission_denied(
                "the workload capability does not match",
            ));
        }
        self.index.lock().unwrap().insert(record.height, record);
        Ok(Response::new(RecordAdmittedTipResponse {}))
    }
    async fn get_committed_tip(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetCommittedTipResponse>, Status> {
        unimplemented_rpc()
    }
    async fn get_admitted_record(
        &self,
        request: Request<GetAdmittedRecordRequest>,
    ) -> Result<Response<GetAdmittedRecordResponse>, Status> {
        let height = request.into_inner().height;
        Ok(Response::new(
            match self.index.lock().unwrap().get(&height).cloned() {
                None => GetAdmittedRecordResponse::default(),
                Some(record) => GetAdmittedRecordResponse {
                    height: record.height,
                    block_hash: record.block_hash.to_vec(),
                    state_root: record.state_root,
                    timestamp: record.timestamp,
                },
            },
        ))
    }
}

/// Serves `spy` on an ephemeral loopback port and returns its address.
pub(super) async fn serve(spy: Arc<SpyWorkload>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let address = listener.local_addr().expect("local address");
    let incoming = tonic::transport::server::TcpIncoming::from_listener(listener, true, None)
        .expect("incoming");
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(ChainControlServer::from_arc(spy))
            .serve_with_incoming(incoming)
            .await;
    });
    address.to_string()
}

/// The record Agentgres admission publishes for `block`: its height, hash, root and the
/// ADMITTED HEADER's timestamp.
fn record_of(block: &Block<ChainTransaction>) -> AdmittedRecord {
    AdmittedRecord {
        height: block.header.height,
        block_hash: harness_hash(block),
        state_root: block.header.state_root.0.clone(),
        timestamp: block.header.timestamp,
    }
}

/// A private (0700) directory holding a capability file with `capability`.
fn capability_file(dir: &tempfile::TempDir, capability: [u8; 32]) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let private = dir.path().join("workload-capability");
    std::fs::create_dir_all(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = private.join("workload-admission.capability");
    write_capability_file(&path, &WorkloadCapability::from_bytes(capability)).unwrap();
    path
}

/// Installs the publisher built from `source` in the harness's ledger (once, at startup). RED-5:
/// through the capability SOURCE, the only way to a publisher outside its module after GREEN-5
/// (each V9-V15 call site migrated; no assertion changed).
async fn install(h: &Harness, source: AdmissionCapabilitySource) {
    install_in(&h.context.runtime_finality, source).await;
}

/// Installs the publisher built from `source` in `ledger` (once, at startup).
async fn install_in(
    ledger: &tokio::sync::Mutex<RuntimeFinalityCoordinator>,
    source: AdmissionCapabilitySource,
) {
    ledger
        .lock()
        .await
        .install_admission_capability(source)
        .expect("install the publisher at startup");
}

// --- B2: the publisher is the capability holder ---------------------------------------------------

/// V9 (RED-3 B2), INVERTED at GREEN-4: it called `publisher.publish(&workload, tip)` with a
/// caller-supplied tip through the shared client; now the coordinator's ledger-reading
/// publication presents the publisher's OWN capability over its PRIVATE channel, for the ledger's
/// head (height 3), and the workload indexes exactly that record (timestamp included). Heights 1
/// and 2 are already indexed, so the gap walk stops at once.
#[tokio::test]
async fn the_publisher_presents_its_own_capability_for_the_admitted_tip() {
    let h = Harness::new(3).await;
    let spy = SpyWorkload::accepting(CAPABILITY)
        .holding(&[record_of(&h.admitted[0]), record_of(&h.admitted[1])]);
    let address = serve(spy.clone()).await;
    install(
        &h,
        AdmissionCapabilitySource::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
    )
    .await;
    RuntimeFinalityCoordinator::publish_admitted_head(&h.context.runtime_finality)
        .await
        .expect("the publisher's capability records the ledger head");
    let head = record_of(&h.admitted[2]);
    assert_eq!(spy.presented(), vec![(CAPABILITY, head.clone())]);
    assert_eq!(spy.index().last(), Some(&head));
}

/// V10 (RED-3 B2 GUARD), INVERTED at GREEN-4 to the coordinator's publication: a publisher without
/// a capability (no capability file) sends nothing, and the workload's index is unchanged.
#[tokio::test]
async fn a_publisher_without_a_capability_sends_nothing_and_the_marker_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::new(3).await;
    let spy = SpyWorkload::accepting(CAPABILITY);
    let address = serve(spy.clone()).await;
    install(
        &h,
        AdmissionCapabilitySource::file(dir.path().join("missing.capability"), &address),
    )
    .await;
    assert!(
        RuntimeFinalityCoordinator::publish_admitted_head(&h.context.runtime_finality)
            .await
            .is_err()
    );
    assert!(spy.presented().is_empty(), "nothing is presented");
    assert!(spy.index().is_empty());
}

// --- m4: a workload restart rotates the capability ------------------------------------------------

/// V11 (RED-3 m4), INVERTED at GREEN-4 to the coordinator's publication: the workload restarted and
/// rotated its capability (the file now holds the new one); the refused publication re-reads the
/// file once and succeeds.
#[tokio::test]
async fn after_a_workload_restart_the_publisher_rereads_the_rotated_capability_once_and_publishes()
{
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::new(3).await;
    let spy = SpyWorkload::accepting(ROTATED)
        .holding(&[record_of(&h.admitted[0]), record_of(&h.admitted[1])]);
    let address = serve(spy.clone()).await;
    let path = capability_file(&dir, CAPABILITY);
    install(&h, AdmissionCapabilitySource::file(path.clone(), &address)).await;
    // The workload restarts: a new capability, written to the same private file.
    write_capability_file(&path, &WorkloadCapability::from_bytes(ROTATED)).unwrap();
    RuntimeFinalityCoordinator::publish_admitted_head(&h.context.runtime_finality)
        .await
        .expect("the re-read capability records the ledger head");
    let head = record_of(&h.admitted[2]);
    assert_eq!(
        spy.presented(),
        vec![(CAPABILITY, head.clone()), (ROTATED, head.clone())],
        "one refused attempt with the old capability, then one with the re-read one"
    );
    assert_eq!(spy.index().last(), Some(&head));
}

/// V12 (RED-3 m4), INVERTED at GREEN-4 to the coordinator's publication: when the re-read
/// capability is still refused, the publication fails after AT MOST one retry (no loop), and the
/// index is unchanged.
#[tokio::test]
async fn a_refusal_after_the_reread_is_returned_without_a_retry_loop() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::new(3).await;
    let spy = SpyWorkload::accepting(ROTATED);
    let address = serve(spy.clone()).await;
    let path = capability_file(&dir, CAPABILITY);
    install(&h, AdmissionCapabilitySource::file(path, &address)).await;
    assert!(
        RuntimeFinalityCoordinator::publish_admitted_head(&h.context.runtime_finality)
            .await
            .is_err()
    );
    let presented = spy.presented();
    assert!(
        !presented.is_empty() && presented.len() <= 2,
        "one attempt, and at most one retry after the re-read: {} attempts",
        presented.len()
    );
    assert!(presented
        .iter()
        .all(|(capability, _)| *capability == CAPABILITY));
    assert!(spy.index().is_empty());
}

/// V13 (RED-3 m4), INVERTED at GREEN-4: it called `publisher.reconcile(&workload, block)` with a
/// caller-supplied block; now the publication takes no block at all. With nothing admitted (the
/// genesis head) it sends nothing; with an admitted ledger it publishes the ledger's head.
#[tokio::test]
async fn the_publisher_reconciles_the_latest_admitted_tip() {
    let empty = Harness::new(0).await;
    let spy = SpyWorkload::accepting(CAPABILITY);
    let address = serve(spy.clone()).await;
    install(
        &empty,
        AdmissionCapabilitySource::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
    )
    .await;
    RuntimeFinalityCoordinator::publish_admitted_head(&empty.context.runtime_finality)
        .await
        .expect("nothing admitted: nothing to publish");
    assert!(
        spy.presented().is_empty(),
        "no record without an admitted block"
    );

    let h = Harness::new(2).await;
    let spy = SpyWorkload::accepting(CAPABILITY).holding(&[record_of(&h.admitted[0])]);
    let address = serve(spy.clone()).await;
    install(
        &h,
        AdmissionCapabilitySource::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
    )
    .await;
    RuntimeFinalityCoordinator::publish_admitted_head(&h.context.runtime_finality)
        .await
        .expect("publish the ledger head");
    assert_eq!(
        spy.presented(),
        vec![(CAPABILITY, record_of(&h.admitted[1]))]
    );
}

// --- M3 and m4 through the REAL admission path ----------------------------------------------------

/// V14 (RED-3 M3 spy), INVERTED at GREEN-4: the spy is now the workload end of the publisher's
/// private channel (it was the shared client's record method). Agentgres admission of block 2
/// through the REAL `admit_available` publishes exactly block 2's record, with the publisher's
/// capability and block 2's header timestamp (an M-noadmit mutant that drops the call fails here).
#[tokio::test]
async fn the_admission_path_publishes_the_admitted_blocks_tip_through_the_publisher() {
    let mut h = Harness::new(1).await;
    let spy = SpyWorkload::accepting(CAPABILITY).holding(&[record_of(&h.admitted[0])]);
    let address = serve(spy.clone()).await;
    install(
        &h,
        AdmissionCapabilitySource::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
    )
    .await;
    let b2 = harness_block(h.admitted_hash(1), 2, 0);
    h.context
        .runtime_finality
        .lock()
        .await
        .stage_block(b2.clone(), Vec::new())
        .expect("stage block 2");
    h.workload.blocks.lock().unwrap().insert(2, b2.clone());

    Box::pin(admit_available(&mut h.context, Some(&b2)))
        .await
        .expect("admit block 2");

    assert_eq!(
        spy.presented(),
        vec![(CAPABILITY, record_of(&b2))],
        "the admission published the admitted block's record once, through the publisher"
    );
    assert_eq!(spy.index().last(), Some(&record_of(&b2)));
}

/// V15 (RED-3 m4), INVERTED at GREEN-4: blocks 1 and 2 were admitted while the workload recorded
/// nothing (it was down). The startup reconcile publishes the ledger head (2) and then FILLS the
/// gap below it by the parent_hash walk (1): before GREEN-4 it published the head only.
#[tokio::test]
async fn startup_reconciles_the_workload_marker_to_the_latest_admitted_block() {
    let h = Harness::new(2).await;
    let spy = SpyWorkload::accepting(CAPABILITY);
    let address = serve(spy.clone()).await;
    install(
        &h,
        AdmissionCapabilitySource::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
    )
    .await;
    assert!(
        spy.index().is_empty(),
        "nothing was recorded while it was down"
    );

    Box::pin(reconcile_workload_admitted_tip(&h.context))
        .await
        .expect("reconcile at startup");

    let (first, latest) = (record_of(&h.admitted[0]), record_of(&h.admitted[1]));
    assert_eq!(
        spy.presented(),
        vec![(CAPABILITY, latest.clone()), (CAPABILITY, first.clone())],
        "the head, then the gap below it"
    );
    assert_eq!(spy.index(), vec![first, latest]);
}

/// GREEN-4 PIN (no RED: the walk is GREEN-4's; NET-DECISIONS 1 and 4). A publication was missed at
/// height 3 (the workload holds 1 and 2). The ledger head is 4: the publication publishes 4, then
/// walks parent_hash down and fills 3; the heights the workload holds (2 and 1) are not presented
/// again. (RED-5: wording only, true of GREEN-4's stop at 2 and of GREEN-5's walk past held rows.)
#[tokio::test]
async fn the_publication_fills_a_gap_below_the_head_by_its_parent_hash_walk() {
    let h = Harness::new(4).await;
    let spy = SpyWorkload::accepting(CAPABILITY)
        .holding(&[record_of(&h.admitted[0]), record_of(&h.admitted[1])]);
    let address = serve(spy.clone()).await;
    install(
        &h,
        AdmissionCapabilitySource::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
    )
    .await;
    RuntimeFinalityCoordinator::publish_admitted_head(&h.context.runtime_finality)
        .await
        .expect("publish the head and fill the gap");
    assert_eq!(
        spy.presented(),
        vec![
            (CAPABILITY, record_of(&h.admitted[3])),
            (CAPABILITY, record_of(&h.admitted[2])),
        ],
        "the head, then the missed height; no height the workload holds is presented again"
    );
    assert_eq!(
        spy.index(),
        h.admitted.iter().map(record_of).collect::<Vec<_>>()
    );
}

// --- RED-5 (review round 3): B1 as a DATA rule ----------------------------------------------------

/// A single-authority ledger (opened as the sync harness opens one) whose BOOTSTRAP canonical head,
/// the spine genesis's `initial_canonical_head`, is `initial`.
fn ledger_bootstrapped_at(
    dir: &tempfile::TempDir,
    initial: String,
) -> tokio::sync::Mutex<RuntimeFinalityCoordinator> {
    use ioi_api::crypto::SerializableKey;
    let seed = [42u8; 32];
    let key = ioi_crypto::sign::eddsa::Ed25519PrivateKey::from_bytes(&seed).unwrap();
    tokio::sync::Mutex::new(
        RuntimeFinalityCoordinator::open(
            dir.path().join("finality"),
            "bootstrap-head".into(),
            ioi_types::config::RuntimeFinalityProfile::SingleAuthorityV1,
            "bootstrap-head-writer".into(),
            move || Ok(initial),
            format!(
                "key://test/{}",
                hex::encode(key.public_key().unwrap().as_bytes())
            ),
            &seed,
        )
        .expect("open a ledger on a bootstrap head"),
    )
}

/// RED-5 B1 (i) (review round 3 BLOCKER B1; DISPOSITION condition 1). A fresh ledger whose
/// BOOTSTRAP head is B1, a block that was executed and STAGED but that Agentgres never admitted
/// (zero admissions): the publication publishes NOTHING. B1 is the spine's initial canonical head,
/// not the head of a committed admission effect. Fails at 9ad9cf0e4: `last_admitted_block`
/// returns whatever staged block the canonical head names (runtime_finality.rs:1852-1866 there),
/// so B1's record is presented and indexed.
#[tokio::test]
async fn b1_i_a_bootstrap_head_that_was_never_admitted_is_never_published() {
    let dir = tempfile::tempdir().unwrap();
    let b1 = harness_block([0; 32], 1, 0);
    let ledger = ledger_bootstrapped_at(&dir, canonical_block_head(&b1).unwrap());
    ledger
        .lock()
        .await
        .stage_block(b1.clone(), Vec::new())
        .expect("stage B1, never admitted");
    let spy = SpyWorkload::accepting(CAPABILITY);
    let address = serve(spy.clone()).await;
    install_in(
        &ledger,
        AdmissionCapabilitySource::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
    )
    .await;

    let result = RuntimeFinalityCoordinator::publish_admitted_head(&ledger).await;
    assert!(
        spy.presented().is_empty(),
        "the never-admitted bootstrap head is not presented: {:?}",
        spy.presented()
    );
    assert!(spy.index().is_empty(), "no row");
    result.expect("a bootstrap head is not an admission: nothing to publish");
}

/// RED-5 B1 (i), the same rule for every block of the gap walk. The bootstrap head B1 (staged,
/// never admitted) is the PARENT of B2, which Agentgres does admit. The publication publishes B2
/// only: the walk stops at B1, the head of no committed admission effect. Fails at 9ad9cf0e4: the
/// walk follows B2's parent_hash to the staged B1 and publishes it (runtime_finality.rs:1808-1830
/// there).
#[tokio::test]
async fn b1_i_the_gap_walk_never_publishes_a_bootstrap_parent_of_an_admitted_block() {
    let dir = tempfile::tempdir().unwrap();
    let b1 = harness_block([0; 32], 1, 0);
    let b2 = harness_block(harness_hash(&b1), 2, 0);
    let ledger = ledger_bootstrapped_at(&dir, canonical_block_head(&b1).unwrap());
    {
        let mut coordinator = ledger.lock().await;
        coordinator
            .stage_block(b1.clone(), Vec::new())
            .expect("stage B1, never admitted");
        coordinator
            .stage_block(b2.clone(), Vec::new())
            .expect("stage B2");
        coordinator
            .admit_single_authority(harness_hash(&b2), 1_700_000_000_002)
            .expect("Agentgres admits B2 on the bootstrap head B1");
    }
    let spy = SpyWorkload::accepting(CAPABILITY);
    let address = serve(spy.clone()).await;
    install_in(
        &ledger,
        AdmissionCapabilitySource::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
    )
    .await;

    RuntimeFinalityCoordinator::publish_admitted_head(&ledger)
        .await
        .expect("publish the admitted head");
    assert_eq!(
        spy.presented(),
        vec![(CAPABILITY, record_of(&b2))],
        "the admitted B2 only; never its bootstrap parent B1"
    );
    assert_eq!(spy.index(), vec![record_of(&b2)]);
}

/// RED-5 B1 (iii) CONTROL (a GUARD: it passes at 9ad9cf0e4 and kills a rule that refuses a REAL
/// admission). The same B1 bytes on an ordinary ledger (bootstrap head = the zero hash, B1's
/// parent): staged only, nothing is published; after Agentgres admits B1, B1 is published.
#[tokio::test]
async fn b1_iii_after_a_real_admission_the_same_block_is_published() {
    let dir = tempfile::tempdir().unwrap();
    let b1 = harness_block([0; 32], 1, 0);
    let ledger = ledger_bootstrapped_at(&dir, runtime_finality_initial_head(None).unwrap());
    ledger
        .lock()
        .await
        .stage_block(b1.clone(), Vec::new())
        .expect("stage B1");
    let spy = SpyWorkload::accepting(CAPABILITY);
    let address = serve(spy.clone()).await;
    install_in(
        &ledger,
        AdmissionCapabilitySource::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
    )
    .await;

    RuntimeFinalityCoordinator::publish_admitted_head(&ledger)
        .await
        .expect("nothing admitted: nothing to publish");
    assert!(spy.presented().is_empty(), "a staged block is not admitted");

    ledger
        .lock()
        .await
        .admit_single_authority(harness_hash(&b1), 1_700_000_000_001)
        .expect("Agentgres admits B1");
    RuntimeFinalityCoordinator::publish_admitted_head(&ledger)
        .await
        .expect("publish the admitted B1");
    assert_eq!(spy.presented(), vec![(CAPABILITY, record_of(&b1))]);
    assert_eq!(spy.index(), vec![record_of(&b1)]);
}

// --- RED-5 (review round 3 MAJOR M2): negative pins of the gap walk ---------------------------------

/// RED-5 M2 GUARD (passes at 9ad9cf0e4; killed by M-walk-by-height). Heights 1..=4 are admitted;
/// the workload holds 1 and 2 (3 was missed). Two height-3 candidates that Agentgres never
/// admitted are staged beside the admitted B3, one with a smaller and one with a larger block hash
/// than B3, so a walk that chooses "the staged block at height 3" by hash order picks a
/// competitor. The walk follows B4's parent_hash: index[3] is B3's record and no competitor is
/// ever presented.
#[tokio::test]
async fn a_competing_staged_candidate_off_the_admitted_parent_chain_is_never_published() {
    let h = Harness::new(4).await;
    let b3 = harness_hash(&h.admitted[2]);
    let candidates: Vec<_> = (1..=u8::MAX)
        .map(|salt| harness_block(h.admitted_hash(2), 3, salt))
        .collect();
    let below = candidates
        .iter()
        .find(|candidate| harness_hash(candidate) < b3)
        .expect("a competitor whose hash is below B3's")
        .clone();
    let above = candidates
        .iter()
        .find(|candidate| harness_hash(candidate) > b3)
        .expect("a competitor whose hash is above B3's")
        .clone();
    {
        let mut coordinator = h.context.runtime_finality.lock().await;
        for competitor in [&below, &above] {
            coordinator
                .stage_block(competitor.clone(), Vec::new())
                .expect("stage a never-admitted competitor at height 3");
        }
    }
    let spy = SpyWorkload::accepting(CAPABILITY)
        .holding(&[record_of(&h.admitted[0]), record_of(&h.admitted[1])]);
    let address = serve(spy.clone()).await;
    install(
        &h,
        AdmissionCapabilitySource::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
    )
    .await;

    RuntimeFinalityCoordinator::publish_admitted_head(&h.context.runtime_finality)
        .await
        .expect("publish the head and fill the gap");
    let competitors = [record_of(&below), record_of(&above)];
    assert!(
        spy.presented()
            .iter()
            .all(|(_, record)| !competitors.contains(record)),
        "no competing candidate is ever presented: {:?}",
        spy.presented()
    );
    assert_eq!(
        spy.presented(),
        vec![
            (CAPABILITY, record_of(&h.admitted[3])),
            (CAPABILITY, record_of(&h.admitted[2])),
        ],
        "the head, then the admitted B3 by B4's parent_hash"
    );
    assert_eq!(
        spy.index(),
        h.admitted.iter().map(record_of).collect::<Vec<_>>(),
        "index[3] is the admitted B3's record"
    );
}

/// RED-5 M2 GUARD (passes at 9ad9cf0e4; killed by M-walk-no-height-check). Agentgres admitted
/// B1..B3 and then X at height 5 whose parent_hash is B3 (height 3): single-authority admission
/// binds the parent, not height continuity (d2a/red5/NOTES.md (1); the OPEN-FACT expect below names
/// the case where it does not). The workload holds nothing. The publication publishes X; the walk
/// stops at X's parent B3, whose height is not X's height - 1, publishes nothing at or below it
/// (B3, though admitted, is not the block at height 4), and REPORTS the malformed link.
#[tokio::test]
async fn an_admitted_ancestor_at_the_wrong_height_stops_the_gap_walk() {
    let h = Harness::new(3).await;
    let x = harness_block(h.admitted_hash(3), 5, 0);
    {
        let mut coordinator = h.context.runtime_finality.lock().await;
        coordinator
            .stage_block(x.clone(), Vec::new())
            .expect("stage X at height 5 on B3");
        coordinator
            .admit_single_authority(harness_hash(&x), 1_700_000_000_005)
            .expect("OPEN-FACT: single-authority admission refused a height-skipping child of the admitted head");
    }
    let spy = SpyWorkload::accepting(CAPABILITY);
    let address = serve(spy.clone()).await;
    install(
        &h,
        AdmissionCapabilitySource::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
    )
    .await;

    let result =
        RuntimeFinalityCoordinator::publish_admitted_head(&h.context.runtime_finality).await;
    assert_eq!(
        spy.presented(),
        vec![(CAPABILITY, record_of(&x))],
        "X only; nothing at or below its wrong-height parent"
    );
    assert_eq!(spy.index(), vec![record_of(&x)]);
    assert!(
        result.is_err(),
        "the malformed parent link is reported, not silently accepted"
    );
}

// --- RED-5 (review round 3 m3): the gap walk resumes, bounded per call ------------------------------

/// RED-5 m3. Heights 1..=70 are admitted (above the per-call limit of 64) and the workload holds
/// none of them. The first publication is INTERRUPTED after a parent write: the head (70) and its
/// parent (69) land, the third record (68) is refused once. Each later publication continues PAST
/// the rows the workload holds to the first absent one, fills at most 64 heights per call, and
/// repeated publications complete the index. Fails at 9ad9cf0e4 at the second call: the walk stops
/// at the first held row (69), so no publication ever fills 68..1 (runtime_finality.rs:1813-1815
/// there).
#[tokio::test]
async fn an_interrupted_gap_fill_resumes_past_held_rows_bounded_per_call() {
    const HEIGHTS: u64 = 70;
    const PER_CALL_LIMIT: usize = 64;
    let h = Harness::new(HEIGHTS).await;
    let spy = SpyWorkload::accepting(CAPABILITY).refusing_once_at(3);
    let address = serve(spy.clone()).await;
    install(
        &h,
        AdmissionCapabilitySource::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
    )
    .await;

    let first =
        RuntimeFinalityCoordinator::publish_admitted_head(&h.context.runtime_finality).await;
    assert!(
        first.is_err(),
        "the interrupted publication reports the refusal"
    );
    assert_eq!(
        spy.heights(),
        vec![HEIGHTS - 1, HEIGHTS],
        "the head and its parent landed before the interruption"
    );

    RuntimeFinalityCoordinator::publish_admitted_head(&h.context.runtime_finality)
        .await
        .expect("the second publication resumes");
    let second = spy.heights();
    assert!(
        second.contains(&(HEIGHTS - 2)),
        "progress: the walk passed the held row {} and filled {}: {second:?}",
        HEIGHTS - 1,
        HEIGHTS - 2
    );
    let lowest = second[0];
    assert_eq!(
        second,
        (lowest..=HEIGHTS).collect::<Vec<_>>(),
        "the rows are one contiguous run down from the head"
    );
    assert!(
        second.len() <= 2 + PER_CALL_LIMIT,
        "bounded: one publication fills at most {PER_CALL_LIMIT} heights, got {} rows",
        second.len()
    );

    RuntimeFinalityCoordinator::publish_admitted_head(&h.context.runtime_finality)
        .await
        .expect("the third publication resumes");
    assert_eq!(
        spy.index(),
        h.admitted.iter().map(record_of).collect::<Vec<_>>(),
        "three publications index every admitted height with its record"
    );
}

// --- RED-6 (review round 4): an unpinned refusal and a stuck span ---------------------------------

/// RED-6 GUARD (D2a review round 4, finding 1(b); passes at e331375ae, killed by M-second-install-replaces). A SECOND
/// install of the admitted-tip publisher is refused, and the FIRST publisher stays installed: the publication presents
/// the first install's capability.
#[tokio::test]
async fn a_second_publisher_install_is_refused_and_the_first_publisher_still_sends() {
    let h = Harness::new(3).await;
    let spy = SpyWorkload::accepting(CAPABILITY)
        .holding(&[record_of(&h.admitted[0]), record_of(&h.admitted[1])]);
    let address = serve(spy.clone()).await;
    install(
        &h,
        AdmissionCapabilitySource::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
    )
    .await;
    let second = h
        .context
        .runtime_finality
        .lock()
        .await
        .install_admission_capability(AdmissionCapabilitySource::in_process(
            WorkloadCapability::from_bytes(ROTATED),
            &address,
        ));
    assert!(second.is_err(), "a second install is refused");
    RuntimeFinalityCoordinator::publish_admitted_head(&h.context.runtime_finality)
        .await
        .expect("the first publisher publishes the ledger head");
    assert_eq!(
        spy.presented(),
        vec![(CAPABILITY, record_of(&h.admitted[2]))],
        "the FIRST install's publisher (its capability) sends"
    );
}

/// RED-6 (D2a review round 4, finding 3). Heights 1..=4 are admitted and the first publication fills the index; its span
/// runs from 4 down to 1. Then the span's BOTTOM staged envelope (block 1's) disappears while its index row stays, and the
/// workload loses rows 2 and 3, inside the span. Of the next two publications at most one errs: the unusable span is
/// cleared, and a later publication walks from the head and fills 3 and 2 again (it stops at block 2, whose parent's
/// envelope is gone). Fails at e331375ae: the span is kept, every later publication jumps to the missing envelope and errs
/// (runtime_finality.rs:1913 there), and rows 2 and 3 stay absent.
#[tokio::test]
async fn a_span_whose_bottom_envelope_is_missing_is_cleared_and_a_later_walk_fills_the_skipped_rows(
) {
    let h = Harness::new(4).await;
    let spy = SpyWorkload::accepting(CAPABILITY);
    let address = serve(spy.clone()).await;
    install(
        &h,
        AdmissionCapabilitySource::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
    )
    .await;
    RuntimeFinalityCoordinator::publish_admitted_head(&h.context.runtime_finality)
        .await
        .expect("the first publication fills the index");
    assert_eq!(
        spy.heights(),
        vec![1, 2, 3, 4],
        "the first publication's walk"
    );

    let envelope = h
        .context
        .runtime_finality
        .lock()
        .await
        .consequence_runtime_root()
        .join("staged")
        .join(format!("{}.scale", hex::encode(h.admitted_hash(1))));
    std::fs::remove_file(&envelope).expect("remove the span bottom's staged envelope");
    spy.forget(&[2, 3]);

    let second =
        RuntimeFinalityCoordinator::publish_admitted_head(&h.context.runtime_finality).await;
    let third =
        RuntimeFinalityCoordinator::publish_admitted_head(&h.context.runtime_finality).await;
    assert_eq!(
        spy.heights(),
        vec![1, 2, 3, 4],
        "a later publication walks from the head and fills the rows the stuck span skipped \
         (second: {second:?}, third: {third:?})"
    );
    let errors = [second.is_err(), third.is_err()]
        .iter()
        .filter(|failed| **failed)
        .count();
    assert!(
        errors <= 1,
        "the missing envelope errs at most once ({errors} errors)"
    );
}
