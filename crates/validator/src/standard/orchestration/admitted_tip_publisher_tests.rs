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

use super::runtime_finality::{
    admit_available, reconcile_workload_admitted_tip, AdmittedTipPublisher,
    RuntimeFinalityCoordinator,
};
use super::sync_harness::{harness_block, harness_hash, Harness};
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

/// The capability the workload accepts in most tests.
const CAPABILITY: [u8; 32] = [0x5A; 32];
/// A restarted workload's rotated capability.
const ROTATED: [u8; 32] = [0x6B; 32];

/// The workload end of the publisher's private channel (see the module docs).
#[derive(Default)]
struct SpyWorkload {
    accepted: Mutex<Option<[u8; 32]>>,
    presented: Mutex<Vec<([u8; 32], AdmittedRecord)>>,
    index: Mutex<BTreeMap<u64, AdmittedRecord>>,
}

impl SpyWorkload {
    fn accepting(capability: [u8; 32]) -> Arc<Self> {
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
    fn presented(&self) -> Vec<([u8; 32], AdmittedRecord)> {
        self.presented.lock().unwrap().clone()
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
        self.presented
            .lock()
            .unwrap()
            .push((capability, record.clone()));
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
async fn serve(spy: Arc<SpyWorkload>) -> String {
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

/// Installs `publisher` in the harness's ledger (once, at startup).
async fn install(h: &Harness, publisher: AdmittedTipPublisher) {
    h.context
        .runtime_finality
        .lock()
        .await
        .install_admitted_tip_publisher(publisher)
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
        AdmittedTipPublisher::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
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
        AdmittedTipPublisher::from_capability_file(dir.path().join("missing.capability"), &address),
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
    install(
        &h,
        AdmittedTipPublisher::from_capability_file(path.clone(), &address),
    )
    .await;
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
    install(
        &h,
        AdmittedTipPublisher::from_capability_file(path, &address),
    )
    .await;
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
        AdmittedTipPublisher::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
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
        AdmittedTipPublisher::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
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
        AdmittedTipPublisher::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
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
        AdmittedTipPublisher::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
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
/// walks parent_hash down and fills 3, and stops at 2, which the workload holds.
#[tokio::test]
async fn the_publication_fills_a_gap_below_the_head_by_its_parent_hash_walk() {
    let h = Harness::new(4).await;
    let spy = SpyWorkload::accepting(CAPABILITY)
        .holding(&[record_of(&h.admitted[0]), record_of(&h.admitted[1])]);
    let address = serve(spy.clone()).await;
    install(
        &h,
        AdmittedTipPublisher::in_process(WorkloadCapability::from_bytes(CAPABILITY), &address),
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
        "the head, then the missed height; the walk stops at the first height the workload holds"
    );
    assert_eq!(
        spy.index(),
        h.admitted.iter().map(record_of).collect::<Vec<_>>()
    );
}
