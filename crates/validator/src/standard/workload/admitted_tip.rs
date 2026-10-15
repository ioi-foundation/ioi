// Path: crates/validator/src/standard/workload/admitted_tip.rs

//! The workload's Agentgres-admitted tip marker (FU-N11-DURABLE-STATUS-1 D2a).
//!
//! The orchestration's Agentgres admission records each admitted block here. Every COMMITTED read
//! (the IBC host's latest height, licence expiry, a trusted state root) reports this marker, never
//! the durable status, which counts signed but uncommitted blocks. Only the admission path may
//! advance it: a record must present the workload's per-boot capability, and the admitted block's
//! execution surface must match the block the workload stores at that height.

use anyhow::{anyhow, Result};
use ioi_api::storage::{AdmittedTip, NodeStore};
use ioi_types::app::{Block, ChainStatus, ChainTransaction};

/// The per-boot capability that authorizes advancing the admitted-tip marker.
#[derive(Clone, PartialEq, Eq)]
pub struct WorkloadCapability([u8; 32]);

impl WorkloadCapability {
    /// Wraps capability bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The capability bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A fresh capability for this boot (32 bytes from the OS RNG).
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// Writes this boot's capability for a split-process orchestration: the file is REPLACED (a
/// previous boot's file is never kept), readable only by its owner (0600), inside a directory no
/// group or other user can read. A refusal leaves no capability file, so the orchestration cannot
/// record admissions and the committed height stays 0 (fail-closed).
pub fn write_capability_file(path: &std::path::Path, capability: &WorkloadCapability) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let directory = path
        .parent()
        .ok_or_else(|| anyhow!("the workload capability path has no parent directory"))?;
    let mode = std::fs::metadata(directory)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(anyhow!(
            "refusing to write the workload capability into {}: mode {:o} lets group or other \
             users read it (the directory must be private, e.g. 0700)",
            directory.display(),
            mode & 0o777
        ));
    }
    let staging = directory.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("workload-capability"),
        std::process::id()
    ));
    let _ = std::fs::remove_file(&staging);
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staging)?;
        file.write_all(capability.as_bytes())?;
        file.sync_all()?;
    }
    // An atomic replace: a previous boot's file is never kept.
    std::fs::rename(&staging, path)?;
    Ok(())
}

/// Where a split-process workload writes, and its orchestration reads, the admission capability:
/// `IOI_WORKLOAD_CAPABILITY_FILE`, else `$CERTS_DIR/workload-capability/workload-admission.capability`.
pub fn capability_file_path_from_env() -> Option<std::path::PathBuf> {
    if let Ok(path) = std::env::var("IOI_WORKLOAD_CAPABILITY_FILE") {
        if !path.is_empty() {
            return Some(path.into());
        }
    }
    std::env::var("CERTS_DIR")
        .ok()
        .filter(|dir| !dir.is_empty())
        .map(|dir| {
            std::path::Path::new(&dir)
                .join("workload-capability")
                .join("workload-admission.capability")
        })
}

/// Creates the capability's parent directory 0700 when it does not exist, then writes the file. An
/// existing directory is used only if it is private (the writer refuses one others can read).
pub fn write_capability_file_creating_private_dir(
    path: &std::path::Path,
    capability: &WorkloadCapability,
) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if let Some(directory) = path.parent() {
        if !directory.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)?;
        }
    }
    write_capability_file(path, capability)
}

/// Reads the capability a workload wrote for this boot.
pub fn read_capability_file(path: &std::path::Path) -> Result<WorkloadCapability> {
    let bytes = std::fs::read(path)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("the workload capability file is not 32 bytes"))?;
    Ok(WorkloadCapability(bytes))
}

impl std::fmt::Debug for WorkloadCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorkloadCapability(<redacted>)")
    }
}

/// The marker half of a node store.
pub trait AdmittedTipStore {
    /// The persisted marker, or `None` before the first admission.
    fn admitted_tip(&self) -> Result<Option<AdmittedTip>>;
    /// Persists the marker (the store enforces monotonicity).
    fn record_admitted_tip(&self, tip: &AdmittedTip) -> Result<()>;
}

impl<T: NodeStore + ?Sized> AdmittedTipStore for T {
    fn admitted_tip(&self) -> Result<Option<AdmittedTip>> {
        Ok(self.get_admitted_tip()?)
    }

    fn record_admitted_tip(&self, tip: &AdmittedTip) -> Result<()> {
        Ok(self.put_admitted_tip(tip)?)
    }
}

/// Checks a presented capability against the workload's own.
pub fn verify_capability(expected: &WorkloadCapability, presented: &[u8]) -> Result<()> {
    if presented.len() != expected.0.len() {
        return Err(anyhow!(
            "admitted-tip record refused: the workload capability is missing or malformed"
        ));
    }
    // Constant time: every byte is compared whatever the first mismatch.
    let difference = expected
        .0
        .iter()
        .zip(presented)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if difference != 0 {
        return Err(anyhow!(
            "admitted-tip record refused: the workload capability does not match"
        ));
    }
    Ok(())
}

/// Records an admitted tip for an authorized caller whose tip matches the stored block's
/// execution surface. A refusal leaves the marker unchanged.
pub fn record_admitted_tip_checked<M: AdmittedTipStore + ?Sized>(
    marker: &M,
    expected: &WorkloadCapability,
    presented: &[u8],
    tip: &AdmittedTip,
    stored: Option<&Block<ChainTransaction>>,
) -> Result<()> {
    verify_capability(expected, presented)?;
    let stored = stored.ok_or_else(|| {
        anyhow!(
            "admitted-tip record refused: the workload stores no block at height {}",
            tip.height
        )
    })?;
    if stored.header.height != tip.height || stored.header.state_root.0 != tip.state_root {
        return Err(anyhow!(
            "admitted-tip record refused: the admitted block's execution surface differs from \
             the block the workload stores at height {}",
            tip.height
        ));
    }
    marker.record_admitted_tip(tip)
}

/// The RecordAdmittedTip handler's logic as a pure function (FU-N11-DURABLE-STATUS-1 D2a round 2,
/// M3; extracted unchanged from workload/ipc/grpc_blockchain.rs, which now only calls it): decodes
/// the request, reads the block the workload stores at the tip's height, and records the tip only
/// for the workload's own capability and a stored block with the same execution surface (height
/// and state root). Every refusal leaves the marker unchanged.
pub fn handle_record_admitted_tip<M, F>(
    marker: &M,
    expected: &WorkloadCapability,
    request: ioi_ipc::blockchain::RecordAdmittedTipRequest,
    stored_block: F,
) -> std::result::Result<(), tonic::Status>
where
    M: AdmittedTipStore + ?Sized,
    F: FnOnce(u64) -> Result<Option<Block<ChainTransaction>>>,
{
    let block_hash: [u8; 32] = request
        .block_hash
        .as_slice()
        .try_into()
        .map_err(|_| tonic::Status::invalid_argument("block_hash must be 32 bytes"))?;
    let tip = AdmittedTip {
        height: request.height,
        block_hash,
        state_root: request.state_root,
    };
    let stored = stored_block(tip.height).map_err(|e| tonic::Status::internal(e.to_string()))?;
    record_admitted_tip_checked(marker, expected, &request.capability, &tip, stored.as_ref())
        .map_err(|e| tonic::Status::permission_denied(e.to_string()))
}

/// The committed chain status: the admitted-tip marker's height (0 when there is no marker).
pub fn committed_status<M: AdmittedTipStore + ?Sized>(
    marker: &M,
    durable: &ChainStatus,
    stored: impl Fn(u64) -> Option<Block<ChainTransaction>>,
) -> Result<ChainStatus> {
    let mut status = durable.clone();
    status.latest_timestamp = 0;
    status.latest_timestamp_ms = 0;
    status.height = 0;
    if let Some(tip) = marker.admitted_tip()? {
        status.height = tip.height;
        if let Some(block) = stored(tip.height) {
            status.latest_timestamp = block.header.timestamp;
            status.latest_timestamp_ms = block.header.timestamp_ms;
        }
    }
    Ok(status)
}

/// The admission gate's CANARY (test code only): the gate's clippy run over the test target must
/// flag exactly this one construction, proving the AdmissionWitness ban fires.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn admission_gate_canary() -> ioi_api::chain::AdmissionWitness {
    ioi_api::chain::AdmissionWitness::from_agentgres_admission()
}

#[cfg(test)]
mod tests {
    //! RED-W1b (execution surface), RED-W2 (capability), RED-W3 (no marker = height 0).
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct MemoryMarker(RefCell<Option<AdmittedTip>>);

    impl AdmittedTipStore for MemoryMarker {
        fn admitted_tip(&self) -> Result<Option<AdmittedTip>> {
            Ok(self.0.borrow().clone())
        }
        fn record_admitted_tip(&self, tip: &AdmittedTip) -> Result<()> {
            *self.0.borrow_mut() = Some(tip.clone());
            Ok(())
        }
    }

    const CAPABILITY: [u8; 32] = [0x5A; 32];

    fn stored_block(height: u64, root: u8) -> Block<ChainTransaction> {
        use ioi_types::app::{AccountId, BlockHeader, QuorumCertificate, SignatureSuite, StateRoot};
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

    fn tip(height: u64, root: u8) -> AdmittedTip {
        AdmittedTip {
            height,
            block_hash: [height as u8; 32],
            state_root: vec![root; 32],
        }
    }

    #[test]
    fn only_the_workload_capability_advances_the_marker() {
        let marker = MemoryMarker::default();
        let expected = WorkloadCapability::from_bytes(CAPABILITY);
        let block = stored_block(3, 0xB3);
        for presented in [&[][..], &[0x00; 32][..], &[0x5A; 31][..]] {
            assert!(
                record_admitted_tip_checked(&marker, &expected, presented, &tip(3, 0xB3), Some(&block))
                    .is_err(),
                "a missing, wrong or short capability is refused"
            );
            assert_eq!(marker.admitted_tip().unwrap(), None, "the marker is unchanged");
        }
        record_admitted_tip_checked(&marker, &expected, &CAPABILITY, &tip(3, 0xB3), Some(&block))
            .expect("the workload capability records the admitted tip");
        assert_eq!(marker.admitted_tip().unwrap(), Some(tip(3, 0xB3)));
    }

    #[test]
    fn a_tip_whose_execution_surface_differs_from_the_stored_block_is_refused() {
        let marker = MemoryMarker::default();
        let expected = WorkloadCapability::from_bytes(CAPABILITY);
        let block = stored_block(3, 0xB3);
        assert!(
            record_admitted_tip_checked(&marker, &expected, &CAPABILITY, &tip(3, 0xEE), Some(&block))
                .is_err(),
            "a state root that differs from the stored block's is refused"
        );
        assert!(
            record_admitted_tip_checked(&marker, &expected, &CAPABILITY, &tip(3, 0xB3), None)
                .is_err(),
            "a tip whose block the workload does not store is refused"
        );
        assert_eq!(marker.admitted_tip().unwrap(), None, "the marker is unchanged");
    }

    #[test]
    fn a_previous_boots_capability_file_is_replaced_and_its_capability_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("workload-capability");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = private.join("workload-admission.capability");

        let previous_boot = WorkloadCapability::generate();
        write_capability_file(&path, &previous_boot).unwrap();
        let this_boot = WorkloadCapability::generate();
        assert_ne!(previous_boot, this_boot, "every boot draws a new capability");
        write_capability_file(&path, &this_boot).expect("this boot replaces the stale file");
        assert_eq!(read_capability_file(&path).unwrap(), this_boot);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "only the owner can read the capability"
        );

        let marker = MemoryMarker::default();
        let block = stored_block(3, 0xB3);
        assert!(
            record_admitted_tip_checked(
                &marker,
                &this_boot,
                previous_boot.as_bytes(),
                &tip(3, 0xB3),
                Some(&block)
            )
            .is_err(),
            "a stale capability from a previous boot is refused"
        );
        assert_eq!(marker.admitted_tip().unwrap(), None);
    }

    #[test]
    fn a_capability_file_is_never_written_into_a_directory_others_can_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = shared.join("workload-admission.capability");
        assert!(
            write_capability_file(&path, &WorkloadCapability::generate()).is_err(),
            "a group- or world-readable directory is refused"
        );
        assert!(!path.exists(), "a refusal leaves no capability file (fail-closed)");
    }

    #[test]
    fn the_committed_status_is_the_marker_never_the_durable_height() {
        let durable = ChainStatus {
            height: 7,
            ..Default::default()
        };
        let empty = MemoryMarker::default();
        assert_eq!(
            committed_status(&empty, &durable, |h| Some(stored_block(h, h as u8)))
                .unwrap()
                .height,
            0,
            "no marker (a fresh node, or before the first admission) reports height 0"
        );
        let marked = MemoryMarker::default();
        marked.record_admitted_tip(&tip(3, 3)).unwrap();
        assert_eq!(
            committed_status(&marked, &durable, |h| Some(stored_block(h, h as u8)))
                .unwrap()
                .height,
            3
        );
    }

    // --- D2a round 2 (RED-3) ----------------------------------------------------------------------

    /// m5, RED-3 (fails at 079937616: committed_status clones the durable status and keeps its
    /// executed total_transactions, admitted_tip.rs:202). The committed status does not track a
    /// transaction count for the committed tip: it reports 0, never the executed (possibly
    /// uncommitted) count, with or without a marker.
    #[test]
    fn the_committed_status_reports_no_executed_transaction_count() {
        let durable = ChainStatus {
            height: 7,
            total_transactions: 42,
            ..Default::default()
        };
        let marked = MemoryMarker::default();
        marked.record_admitted_tip(&tip(3, 3)).unwrap();
        assert_eq!(
            committed_status(&marked, &durable, |h| Some(stored_block(h, h as u8)))
                .unwrap()
                .total_transactions,
            0,
            "the executed count (which includes uncommitted blocks) is not reported as committed"
        );
        let empty = MemoryMarker::default();
        assert_eq!(
            committed_status(&empty, &durable, |h| Some(stored_block(h, h as u8)))
                .unwrap()
                .total_transactions,
            0
        );
    }

    /// A RecordAdmittedTip request as the orchestration's client encodes it.
    fn record_request(
        height: u64,
        root: u8,
        capability: Vec<u8>,
    ) -> ioi_ipc::blockchain::RecordAdmittedTipRequest {
        ioi_ipc::blockchain::RecordAdmittedTipRequest {
            height,
            block_hash: vec![height as u8; 32],
            state_root: vec![root; 32],
            capability,
        }
    }

    /// M3, GUARD (passes at RED-3, where the handler logic is extracted unchanged; pins the
    /// handler's authentication, which no 079937616 test reached: removing it from the handler
    /// fails here). No, wrong or short capability: refused with PermissionDenied, and an EXISTING
    /// marker stays unchanged; the workload's capability then advances it (the control).
    #[test]
    fn the_record_handler_refuses_a_missing_or_wrong_capability_and_keeps_the_existing_marker() {
        let marker = MemoryMarker::default();
        marker.record_admitted_tip(&tip(3, 0xB3)).unwrap();
        let expected = WorkloadCapability::from_bytes(CAPABILITY);
        for presented in [Vec::new(), vec![0x00; 32], vec![0x5A; 31]] {
            let status = handle_record_admitted_tip(
                &marker,
                &expected,
                record_request(4, 0xB4, presented),
                |height| Ok(Some(stored_block(height, 0xB4))),
            )
            .expect_err("a missing, wrong or short capability is refused");
            assert_eq!(status.code(), tonic::Code::PermissionDenied);
            assert_eq!(
                marker.admitted_tip().unwrap(),
                Some(tip(3, 0xB3)),
                "the existing marker is unchanged"
            );
        }
        handle_record_admitted_tip(
            &marker,
            &expected,
            record_request(4, 0xB4, CAPABILITY.to_vec()),
            |height| Ok(Some(stored_block(height, 0xB4))),
        )
        .expect("the workload's capability advances the marker");
        assert_eq!(marker.admitted_tip().unwrap(), Some(tip(4, 0xB4)));
    }

    /// M3, GUARD (passes at RED-3; pins the height conjunct of the execution-surface check,
    /// admitted_tip.rs:186, which no 079937616 test isolated). The workload's lookup at the tip's
    /// height 4 yields a block whose header says height 3 with the SAME root: refused, and the
    /// existing marker stays.
    #[test]
    fn the_record_handler_refuses_a_tip_at_the_wrong_height_with_the_same_root() {
        let marker = MemoryMarker::default();
        marker.record_admitted_tip(&tip(3, 0xB3)).unwrap();
        let expected = WorkloadCapability::from_bytes(CAPABILITY);
        let status = handle_record_admitted_tip(
            &marker,
            &expected,
            record_request(4, 0xB4, CAPABILITY.to_vec()),
            |_| Ok(Some(stored_block(3, 0xB4))),
        )
        .expect_err("a stored block at another height is refused even with the same root");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert_eq!(marker.admitted_tip().unwrap(), Some(tip(3, 0xB3)));
    }
}
