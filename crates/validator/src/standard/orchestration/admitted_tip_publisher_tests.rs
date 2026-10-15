// Path: crates/validator/src/standard/orchestration/admitted_tip_publisher_tests.rs
//! FU-N11-DURABLE-STATUS-1 D2a round 2 (RED-3, written against 079937616): the admitted-tip
//! PUBLISHER, the orchestration's only holder of the workload admission capability (B2), its
//! recovery after a workload restart (m4), and the admission path's call into it (M3, a spy).
//!
//! The workload is the sync harness's `HarnessWorkload`, which records every admitted-tip record
//! presented to it as (capability, tip) and advances its marker only for the capability it
//! accepts. The admission-path tests drive the REAL `admit_available` over the harness context
//! (a real `RuntimeFinalityCoordinator`, single-authority profile).

use super::runtime_finality::{
    admit_available, reconcile_workload_admitted_tip, AdmittedTipPublisher,
};
use super::sync_harness::{harness_block, harness_hash, Harness, HarnessWorkload};
use crate::standard::workload::admitted_tip::{write_capability_file, WorkloadCapability};
use ioi_api::storage::AdmittedTip;
use ioi_types::app::{Block, ChainTransaction};

/// The capability the workload accepts in most tests.
const CAPABILITY: [u8; 32] = [0x5A; 32];
/// A restarted workload's rotated capability.
const ROTATED: [u8; 32] = [0x6B; 32];

fn workload_accepting(capability: [u8; 32]) -> HarnessWorkload {
    let workload = HarnessWorkload::default();
    *workload.accepted_capability.lock().unwrap() = Some(capability);
    workload
}

fn records(workload: &HarnessWorkload) -> Vec<([u8; 32], AdmittedTip)> {
    workload.admitted_tip_records.lock().unwrap().clone()
}

fn marker(workload: &HarnessWorkload) -> Option<AdmittedTip> {
    workload.committed_tip.lock().unwrap().clone()
}

/// The tip Agentgres admission publishes for `block`.
fn tip_of(block: &Block<ChainTransaction>) -> AdmittedTip {
    AdmittedTip {
        height: block.header.height,
        block_hash: harness_hash(block),
        state_root: block.header.state_root.0.clone(),
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

// --- B2: the publisher is the capability holder ---------------------------------------------------

/// B2, RED-3 (fails at 079937616: there is no publisher; the capability rides the shared workload
/// client, client workload_client/mod.rs:148-150 and :335-339, and the RED-3 publisher is a stub).
/// The publisher presents ITS capability for the admitted tip, and the workload records it.
#[tokio::test]
async fn the_publisher_presents_its_own_capability_for_the_admitted_tip() {
    let workload = workload_accepting(CAPABILITY);
    let publisher = AdmittedTipPublisher::in_process(WorkloadCapability::from_bytes(CAPABILITY));
    let block = harness_block([0; 32], 3, 0);
    publisher
        .publish(&workload, tip_of(&block))
        .await
        .expect("the publisher's capability records the admitted tip");
    assert_eq!(records(&workload), vec![(CAPABILITY, tip_of(&block))]);
    assert_eq!(marker(&workload), Some(tip_of(&block)));
}

/// B2, GUARD (passes at RED-3; pins fail-closed: a mutant that presents zeros or a default
/// capability fails here). A publisher without a capability (no capability file) sends nothing,
/// and the marker is unchanged.
#[tokio::test]
async fn a_publisher_without_a_capability_sends_nothing_and_the_marker_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let workload = workload_accepting(CAPABILITY);
    let publisher =
        AdmittedTipPublisher::from_capability_file(dir.path().join("missing.capability"));
    let block = harness_block([0; 32], 3, 0);
    assert!(publisher.publish(&workload, tip_of(&block)).await.is_err());
    assert!(records(&workload).is_empty(), "nothing is presented");
    assert_eq!(marker(&workload), None);
}

// --- m4: a workload restart rotates the capability ------------------------------------------------

/// m4, RED-3 (fails at 079937616: the orchestration reads the capability file once,
/// node/src/bin/orchestration.rs:297-313, and every later publication fails; the RED-3 publisher
/// is a stub). The workload restarted and rotated its capability (the file now holds the new one):
/// the refused publication re-reads the file once and succeeds.
#[tokio::test]
async fn after_a_workload_restart_the_publisher_rereads_the_rotated_capability_once_and_publishes()
{
    let dir = tempfile::tempdir().unwrap();
    let path = capability_file(&dir, CAPABILITY);
    let publisher = AdmittedTipPublisher::from_capability_file(path.clone());
    // The workload restarts: a new capability, written to the same private file.
    write_capability_file(&path, &WorkloadCapability::from_bytes(ROTATED)).unwrap();
    let workload = workload_accepting(ROTATED);
    let block = harness_block([0; 32], 3, 0);
    publisher
        .publish(&workload, tip_of(&block))
        .await
        .expect("the re-read capability records the admitted tip");
    assert_eq!(
        records(&workload),
        vec![(CAPABILITY, tip_of(&block)), (ROTATED, tip_of(&block))],
        "one refused attempt with the old capability, then one with the re-read one"
    );
    assert_eq!(marker(&workload), Some(tip_of(&block)));
}

/// m4, RED-3 (fails at 079937616 and on the RED-3 stub: nothing is presented at all). When the
/// re-read capability is still refused, the publication fails after AT MOST one retry (no loop),
/// and the marker is unchanged.
#[tokio::test]
async fn a_refusal_after_the_reread_is_returned_without_a_retry_loop() {
    let dir = tempfile::tempdir().unwrap();
    let path = capability_file(&dir, CAPABILITY);
    let publisher = AdmittedTipPublisher::from_capability_file(path);
    let workload = workload_accepting(ROTATED);
    let block = harness_block([0; 32], 3, 0);
    assert!(publisher.publish(&workload, tip_of(&block)).await.is_err());
    let presented = records(&workload);
    assert!(
        !presented.is_empty() && presented.len() <= 2,
        "one attempt, and at most one retry after the re-read: {} attempts",
        presented.len()
    );
    assert!(presented.iter().all(|(capability, _)| *capability == CAPABILITY));
    assert_eq!(marker(&workload), None);
}

/// m4, RED-3 (fails at 079937616: nothing reconciles the workload's marker; the RED-3 publisher is
/// a stub). Reconciling publishes the latest admitted block's tip; with no admitted block it
/// publishes nothing.
#[tokio::test]
async fn the_publisher_reconciles_the_latest_admitted_tip() {
    let workload = workload_accepting(CAPABILITY);
    let publisher = AdmittedTipPublisher::in_process(WorkloadCapability::from_bytes(CAPABILITY));
    let block = harness_block([0; 32], 5, 0);
    publisher
        .reconcile(&workload, Some(&block))
        .await
        .expect("reconcile to the latest admitted block");
    assert_eq!(records(&workload), vec![(CAPABILITY, tip_of(&block))]);
    assert_eq!(marker(&workload), Some(tip_of(&block)));
    publisher
        .reconcile(&workload, None)
        .await
        .expect("nothing admitted: nothing to reconcile");
    assert_eq!(records(&workload).len(), 1, "no record without an admitted block");
}

// --- M3 and m4 through the REAL admission path ----------------------------------------------------

/// M3, RED-3 (fails at 079937616: committed_status_publication calls the SHARED workload client's
/// record_admitted_tip, runtime_finality.rs:1146-1150 and :1197-1229, never a publisher). Agentgres
/// admission of block 2 publishes exactly block 2's tip through the coordinator's publisher, with
/// the publisher's capability (an M-noadmit mutant that drops the call fails here).
#[tokio::test]
async fn the_admission_path_publishes_the_admitted_blocks_tip_through_the_publisher() {
    let mut h = Harness::new(1).await;
    *h.workload.accepted_capability.lock().unwrap() = Some(CAPABILITY);
    h.context
        .runtime_finality
        .lock()
        .await
        .install_admitted_tip_publisher(AdmittedTipPublisher::in_process(
            WorkloadCapability::from_bytes(CAPABILITY),
        ))
        .expect("install the publisher at startup");
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
        records(&h.workload),
        vec![(CAPABILITY, tip_of(&b2))],
        "the admission published the admitted block's tip once, through the publisher"
    );
    assert_eq!(marker(&h.workload), Some(tip_of(&b2)));
}

/// m4, RED-3 (fails at 079937616: no startup reconciliation exists; the RED-3
/// reconcile_workload_admitted_tip is a stub). Blocks 1 and 2 were admitted while the workload's
/// marker was not recorded (e.g. the workload was down): reconciling at startup publishes the
/// latest admitted block's tip through the publisher.
#[tokio::test]
async fn startup_reconciles_the_workload_marker_to_the_latest_admitted_block() {
    let h = Harness::new(2).await;
    *h.workload.accepted_capability.lock().unwrap() = Some(CAPABILITY);
    h.context
        .runtime_finality
        .lock()
        .await
        .install_admitted_tip_publisher(AdmittedTipPublisher::in_process(
            WorkloadCapability::from_bytes(CAPABILITY),
        ))
        .expect("install the publisher at startup");
    assert_eq!(marker(&h.workload), None, "nothing was recorded while it was down");

    Box::pin(reconcile_workload_admitted_tip(&h.context))
        .await
        .expect("reconcile at startup");

    let latest = h.admitted[1].clone();
    assert_eq!(records(&h.workload), vec![(CAPABILITY, tip_of(&latest))]);
    assert_eq!(marker(&h.workload), Some(tip_of(&latest)));
}
