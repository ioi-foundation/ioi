// Path: crates/validator/src/standard/workload/admitted_tip.rs

//! The workload's Agentgres-admitted tip marker (FU-N11-DURABLE-STATUS-1 D2a).
//!
//! The orchestration's Agentgres admission publication records each admitted block here, in the
//! workload store's ADMITTED INDEX (one row per height, written once). Every COMMITTED read (the
//! IBC host's explicit and latest heights, licence expiry, a trusted state root, GetCommittedTip)
//! is served from ONE row, never from the durable status (which counts signed but uncommitted
//! blocks) and never from a stored block. Only the publication writes the index: a record must
//! present the workload's per-boot capability, and its execution surface must match the block the
//! workload stores at that height.

use anyhow::{anyhow, Result};
use ioi_api::storage::{AdmittedRecord, NodeStore};
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

/// The admitted-index half of a node store (FU-N11-DURABLE-STATUS-1 D2a GREEN-4).
pub trait AdmittedTipStore {
    /// The index's max row (the committed tip), or `None` before the first admission.
    fn latest_admitted_record(&self) -> Result<Option<AdmittedRecord>>;
    /// The index's row for `height`, or `None` when the height is not admitted.
    fn admitted_record(&self, height: u64) -> Result<Option<AdmittedRecord>>;
    /// Writes one row (the store enforces write-once per height).
    fn record_admitted(&self, record: &AdmittedRecord) -> Result<()>;
}

impl<T: NodeStore + ?Sized> AdmittedTipStore for T {
    fn latest_admitted_record(&self) -> Result<Option<AdmittedRecord>> {
        Ok(self.get_latest_admitted_record()?)
    }

    fn admitted_record(&self, height: u64) -> Result<Option<AdmittedRecord>> {
        Ok(self.get_admitted_record(height)?)
    }

    fn record_admitted(&self, record: &AdmittedRecord) -> Result<()> {
        Ok(self.put_admitted_record(record)?)
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

/// Records one admitted block for an authorized caller whose record matches the stored block's
/// execution surface (a consistency check that fails closed). A refusal leaves the index unchanged.
pub fn record_admitted_tip_checked<M: AdmittedTipStore + ?Sized>(
    marker: &M,
    expected: &WorkloadCapability,
    presented: &[u8],
    record: &AdmittedRecord,
    stored: Option<&Block<ChainTransaction>>,
) -> Result<()> {
    verify_capability(expected, presented)?;
    let stored = stored.ok_or_else(|| {
        anyhow!(
            "admitted-tip record refused: the workload stores no block at height {}",
            record.height
        )
    })?;
    if stored.header.height != record.height || stored.header.state_root.0 != record.state_root {
        return Err(anyhow!(
            "admitted-tip record refused: the admitted block's execution surface differs from \
             the block the workload stores at height {}",
            record.height
        ));
    }
    marker.record_admitted(record)
}

/// The RecordAdmittedTip handler's logic as a pure function: decodes the request into an admitted
/// record (its timestamp is the ADMITTED header's, from the request; the workload never fills it
/// from the block it stores), reads the block the workload stores at that height, and records it
/// only for the workload's own capability and a stored block with the same execution surface
/// (height and state root). Every refusal leaves the index unchanged.
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
    let record = AdmittedRecord {
        height: request.height,
        block_hash,
        state_root: request.state_root,
        timestamp: request.timestamp,
    };
    let stored = stored_block(record.height).map_err(|e| tonic::Status::internal(e.to_string()))?;
    record_admitted_tip_checked(marker, expected, &request.capability, &record, stored.as_ref())
        .map_err(|e| tonic::Status::permission_denied(e.to_string()))
}

/// The committed chain status: the height and timestamp of the admitted index's MAX ROW (height 0
/// when nothing is admitted), from that one record. `total_transactions` is NOT tracked for the
/// committed tip and is always 0 (the durable count includes executed but uncommitted blocks).
pub fn committed_status<M: AdmittedTipStore + ?Sized>(
    marker: &M,
    durable: &ChainStatus,
) -> Result<ChainStatus> {
    let mut status = durable.clone();
    status.height = 0;
    status.latest_timestamp = 0;
    status.latest_timestamp_ms = 0;
    status.total_transactions = 0;
    if let Some(record) = marker.latest_admitted_record()? {
        status.height = record.height;
        status.latest_timestamp = record.timestamp;
        status.latest_timestamp_ms = record.timestamp.saturating_mul(1_000);
    }
    Ok(status)
}

/// The committed tip as GetCommittedTip serves it: height, block hash, state root and timestamp,
/// all from the admitted index's MAX ROW. With nothing admitted every field is empty or 0 (an
/// empty block hash means no tip).
pub fn committed_tip_response<M: AdmittedTipStore + ?Sized>(
    marker: &M,
) -> Result<ioi_ipc::blockchain::GetCommittedTipResponse> {
    Ok(match marker.latest_admitted_record()? {
        None => ioi_ipc::blockchain::GetCommittedTipResponse::default(),
        Some(record) => ioi_ipc::blockchain::GetCommittedTipResponse {
            height: record.height,
            block_hash: record.block_hash.to_vec(),
            state_root: record.state_root,
            latest_timestamp: record.timestamp,
        },
    })
}

/// One admitted index row as GetAdmittedRecord serves it. A height that is not admitted gets an
/// empty response (an empty block hash): the caller refuses; nothing comes from a stored block.
pub fn admitted_record_response<M: AdmittedTipStore + ?Sized>(
    marker: &M,
    height: u64,
) -> Result<ioi_ipc::blockchain::GetAdmittedRecordResponse> {
    Ok(match marker.admitted_record(height)? {
        None => ioi_ipc::blockchain::GetAdmittedRecordResponse::default(),
        Some(record) => ioi_ipc::blockchain::GetAdmittedRecordResponse {
            height: record.height,
            block_hash: record.block_hash.to_vec(),
            state_root: record.state_root,
            timestamp: record.timestamp,
        },
    })
}

#[cfg(test)]
mod tests {
    //! RED-W1b (execution surface), RED-W2 (capability), RED-W3 (no admission = height 0), the
    //! RED-3 handler pins, and the GREEN-4 record pins, over an in-memory admitted index.
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MemoryMarker(RefCell<BTreeMap<u64, AdmittedRecord>>);

    impl AdmittedTipStore for MemoryMarker {
        fn latest_admitted_record(&self) -> Result<Option<AdmittedRecord>> {
            Ok(self.0.borrow().values().next_back().cloned())
        }
        fn admitted_record(&self, height: u64) -> Result<Option<AdmittedRecord>> {
            Ok(self.0.borrow().get(&height).cloned())
        }
        fn record_admitted(&self, record: &AdmittedRecord) -> Result<()> {
            self.0.borrow_mut().insert(record.height, record.clone());
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

    /// The admission record of height `height` with root `[root; 32]`; its timestamp is the
    /// admitted header's (`1_700_000_000 + height`, as `stored_block`'s).
    fn tip(height: u64, root: u8) -> AdmittedRecord {
        AdmittedRecord {
            height,
            block_hash: [height as u8; 32],
            state_root: vec![root; 32],
            timestamp: 1_700_000_000 + height,
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
            assert_eq!(marker.latest_admitted_record().unwrap(), None, "the index is unchanged");
        }
        record_admitted_tip_checked(&marker, &expected, &CAPABILITY, &tip(3, 0xB3), Some(&block))
            .expect("the workload capability records the admitted tip");
        assert_eq!(marker.latest_admitted_record().unwrap(), Some(tip(3, 0xB3)));
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
        assert_eq!(marker.latest_admitted_record().unwrap(), None, "the index is unchanged");
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
        assert_eq!(marker.latest_admitted_record().unwrap(), None);
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
            committed_status(&empty, &durable).unwrap().height,
            0,
            "no admission (a fresh node, or before the first admission) reports height 0"
        );
        let marked = MemoryMarker::default();
        marked.record_admitted(&tip(3, 3)).unwrap();
        assert_eq!(committed_status(&marked, &durable).unwrap().height, 3);
    }

    /// m5, RED-3. The committed status does not track a transaction count for the committed tip:
    /// it reports 0, never the executed (possibly uncommitted) count, with or without a record.
    #[test]
    fn the_committed_status_reports_no_executed_transaction_count() {
        let durable = ChainStatus {
            height: 7,
            total_transactions: 42,
            ..Default::default()
        };
        let marked = MemoryMarker::default();
        marked.record_admitted(&tip(3, 3)).unwrap();
        assert_eq!(
            committed_status(&marked, &durable).unwrap().total_transactions,
            0,
            "the executed count (which includes uncommitted blocks) is not reported as committed"
        );
        let empty = MemoryMarker::default();
        assert_eq!(committed_status(&empty, &durable).unwrap().total_transactions, 0);
    }

    /// A RecordAdmittedTip request as the orchestration's publisher encodes it.
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
            timestamp: 1_700_000_000 + height,
        }
    }

    /// M3, GUARD (RED-3). No, wrong or short capability: refused with PermissionDenied, and an
    /// EXISTING row stays; the workload's capability then records the next height.
    #[test]
    fn the_record_handler_refuses_a_missing_or_wrong_capability_and_keeps_the_existing_marker() {
        let marker = MemoryMarker::default();
        marker.record_admitted(&tip(3, 0xB3)).unwrap();
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
                marker.latest_admitted_record().unwrap(),
                Some(tip(3, 0xB3)),
                "the existing row is unchanged"
            );
        }
        handle_record_admitted_tip(
            &marker,
            &expected,
            record_request(4, 0xB4, CAPABILITY.to_vec()),
            |height| Ok(Some(stored_block(height, 0xB4))),
        )
        .expect("the workload's capability records the next height");
        assert_eq!(marker.latest_admitted_record().unwrap(), Some(tip(4, 0xB4)));
    }

    /// GREEN-3 PIN, INVERTED at GREEN-4 (it asserted the response's timestamp came from the stored
    /// block). The committed tip is served from the admitted index's max row ALONE: height, block
    /// hash, state root and TIMESTAMP from the record; there is no stored-block input at all. Empty
    /// before the first admission.
    #[test]
    fn the_committed_tip_response_is_the_marker_not_the_stored_block() {
        let empty = MemoryMarker::default();
        let none = committed_tip_response(&empty).unwrap();
        assert!(none.block_hash.is_empty(), "nothing admitted: no tip");
        assert_eq!(none.height, 0);

        let marked = MemoryMarker::default();
        let admitted = AdmittedRecord {
            timestamp: 1_699_999_999,
            ..tip(3, 0xA3)
        };
        marked.record_admitted(&admitted).unwrap();
        let response = committed_tip_response(&marked).unwrap();
        assert_eq!(response.height, 3);
        assert_eq!(response.block_hash, vec![3u8; 32]);
        assert_eq!(response.state_root, vec![0xA3; 32], "the record's root");
        assert_eq!(
            response.latest_timestamp, 1_699_999_999,
            "the RECORD's timestamp (the admitted header's), never a stored block's"
        );
        let status = committed_status(&marked, &ChainStatus::default()).unwrap();
        assert_eq!(status.latest_timestamp, 1_699_999_999, "the committed status agrees");
    }

    /// M3, GUARD (RED-3; the height conjunct of the execution-surface check). The workload's lookup
    /// at the record's height 4 yields a block whose header says height 3 with the SAME root:
    /// refused, and the existing row stays.
    #[test]
    fn the_record_handler_refuses_a_tip_at_the_wrong_height_with_the_same_root() {
        let marker = MemoryMarker::default();
        marker.record_admitted(&tip(3, 0xB3)).unwrap();
        let expected = WorkloadCapability::from_bytes(CAPABILITY);
        let status = handle_record_admitted_tip(
            &marker,
            &expected,
            record_request(4, 0xB4, CAPABILITY.to_vec()),
            |_| Ok(Some(stored_block(3, 0xB4))),
        )
        .expect_err("a stored block at another height is refused even with the same root");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert_eq!(marker.latest_admitted_record().unwrap(), Some(tip(3, 0xB3)));
    }

    /// GREEN-4 PIN (no RED: the request had no timestamp before GREEN-4). The handler records the
    /// ADMITTED header's timestamp from the request, even when the block the workload stores at
    /// that height carries another one (the workload never fills it from BLOCKS[h], CRITIC F8).
    #[test]
    fn the_record_handler_records_the_admitted_headers_timestamp_from_the_request() {
        let marker = MemoryMarker::default();
        let expected = WorkloadCapability::from_bytes(CAPABILITY);
        let mut request = record_request(4, 0xB4, CAPABILITY.to_vec());
        request.timestamp = 1_234;
        handle_record_admitted_tip(&marker, &expected, request, |height| {
            Ok(Some(stored_block(height, 0xB4)))
        })
        .expect("recorded");
        assert_eq!(
            marker.admitted_record(4).unwrap().map(|record| record.timestamp),
            Some(1_234),
            "the request's timestamp, not the stored block's (1_700_000_004)"
        );
        let response = admitted_record_response(&marker, 4).unwrap();
        assert_eq!(response.timestamp, 1_234);
        assert!(
            admitted_record_response(&marker, 5).unwrap().block_hash.is_empty(),
            "a height that is not admitted gets an empty record"
        );
    }
}
