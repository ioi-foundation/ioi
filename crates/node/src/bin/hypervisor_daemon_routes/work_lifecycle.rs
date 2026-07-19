//! Durable append-only storage adapter for the shared work-lifecycle kernel.
//!
//! No owner route is rebound here yet. GoalRun, WorkRun, AutomationRun,
//! HarnessInvocation, ContextCell, and external-handle owners must explicitly
//! call this adapter at their own legal transition boundary. The mounted status
//! route therefore reports mechanism availability and live-integration gaps
//! separately.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, Json};
use ioi_services::agentic::runtime::kernel::work_lifecycle::{
    admit_work_lifecycle_record, build_snapshot_and_archive, legal_transition_table,
    WorkLifecycleAdmissionOutcome, WorkLifecycleArchiveSegment, WorkLifecycleError,
    WorkLifecycleObjectKind, WorkLifecycleProjection, WorkLifecycleRecord, WorkLifecycleSnapshot,
    WorkLifecycleState,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const RECORD_DIR: &str = "work-lifecycle-records";
const PROJECTION_DIR: &str = "work-lifecycle-projections";
const ARCHIVE_DIR: &str = "work-lifecycle-archives";
const SNAPSHOT_DIR: &str = "work-lifecycle-snapshots";

static STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn store_lock() -> &'static Mutex<()> {
    STORE_LOCK.get_or_init(|| Mutex::new(()))
}

fn durable_ref_key(value: &str) -> String {
    let readable: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    let readable = if readable.trim_matches('_').is_empty() {
        "ref"
    } else {
        readable.as_str()
    };
    let digest = Sha256::digest(value.as_bytes());
    format!("{readable}-{digest:x}")
}

fn object_record_dir(data_dir: &str, object_ref: &str) -> PathBuf {
    Path::new(data_dir)
        .join(RECORD_DIR)
        .join(durable_ref_key(object_ref))
}

fn record_path(data_dir: &str, object_ref: &str, record_id: &str) -> PathBuf {
    object_record_dir(data_dir, object_ref).join(format!("{}.json", durable_ref_key(record_id)))
}

fn projection_path(data_dir: &str, object_ref: &str) -> PathBuf {
    Path::new(data_dir)
        .join(PROJECTION_DIR)
        .join(format!("{}.json", durable_ref_key(object_ref)))
}

fn archive_path(data_dir: &str, object_ref: &str, archive_ref: &str) -> PathBuf {
    Path::new(data_dir)
        .join(ARCHIVE_DIR)
        .join(durable_ref_key(object_ref))
        .join(format!("{}.json", durable_ref_key(archive_ref)))
}

fn snapshot_path(data_dir: &str, object_ref: &str, snapshot_ref: &str) -> PathBuf {
    Path::new(data_dir)
        .join(SNAPSHOT_DIR)
        .join(durable_ref_key(object_ref))
        .join(format!("{}.json", durable_ref_key(snapshot_ref)))
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn write_immutable_json(path: &Path, value: &impl serde::Serialize) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("immutable record has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| io::Error::other(format!("record encoding failed: {error}")))?;
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(&bytes)?;
            file.sync_all()?;
            sync_dir(parent)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if std::fs::read(path)? == bytes {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "immutable work-lifecycle identity is occupied by different bytes",
                ))
            }
        }
        Err(error) => Err(error),
    }
}

fn replace_projection_json(path: &Path, value: &impl serde::Serialize) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("projection has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| io::Error::other(format!("projection encoding failed: {error}")))?;
    let temp = parent.join(format!(
        ".{}.tmp-{:x}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("projection"),
        now_nanos()
    ));
    let write = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        sync_dir(parent)
    })();
    if write.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    write
}

#[derive(Debug)]
pub(crate) enum WorkLifecycleStoreError {
    Kernel(WorkLifecycleError),
    Io(io::Error),
    Invalid(String),
}

impl std::fmt::Display for WorkLifecycleStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kernel(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "work-lifecycle I/O failed: {error}"),
            Self::Invalid(message) => write!(formatter, "invalid work-lifecycle store: {message}"),
        }
    }
}

impl From<WorkLifecycleError> for WorkLifecycleStoreError {
    fn from(value: WorkLifecycleError) -> Self {
        Self::Kernel(value)
    }
}

impl From<io::Error> for WorkLifecycleStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

fn load_object_records(
    data_dir: &str,
    object_ref: &str,
) -> Result<Vec<WorkLifecycleRecord>, WorkLifecycleStoreError> {
    let directory = object_record_dir(data_dir, object_ref);
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut by_id = BTreeMap::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let record: WorkLifecycleRecord =
            serde_json::from_slice(&std::fs::read(&path)?).map_err(|error| {
                WorkLifecycleStoreError::Invalid(format!(
                    "record {} is malformed: {error}",
                    path.display()
                ))
            })?;
        if record.object_ref != object_ref {
            return Err(WorkLifecycleStoreError::Invalid(format!(
                "record {} belongs to foreign object {}",
                record.record_id, record.object_ref
            )));
        }
        if path != record_path(data_dir, object_ref, &record.record_id) {
            return Err(WorkLifecycleStoreError::Invalid(format!(
                "record {} is stored under a noncanonical filename",
                record.record_id
            )));
        }
        if by_id.insert(record.record_id.clone(), record).is_some() {
            return Err(WorkLifecycleStoreError::Invalid(
                "duplicate work-lifecycle record identity".into(),
            ));
        }
    }
    Ok(by_id.into_values().collect())
}

fn order_and_replay_records(
    records: Vec<WorkLifecycleRecord>,
) -> Result<(Vec<WorkLifecycleRecord>, WorkLifecycleState), WorkLifecycleStoreError> {
    if records.is_empty() {
        return Ok((Vec::new(), WorkLifecycleState::default()));
    }
    let mut remaining: BTreeMap<String, WorkLifecycleRecord> = records
        .into_iter()
        .map(|record| (record.record_id.clone(), record))
        .collect();
    let genesis_ids: Vec<String> = remaining
        .values()
        .filter(|record| record.expected_head.is_none())
        .map(|record| record.record_id.clone())
        .collect();
    if genesis_ids.len() != 1 {
        return Err(WorkLifecycleStoreError::Invalid(format!(
            "work-lifecycle history has {} genesis candidates; exactly one is required",
            genesis_ids.len()
        )));
    }
    let mut ordered = Vec::with_capacity(remaining.len());
    let mut state = WorkLifecycleState::default();
    let genesis = remaining
        .remove(&genesis_ids[0])
        .expect("selected genesis remains present");
    admit_work_lifecycle_record(&mut state, &genesis)?;
    ordered.push(genesis);
    while !remaining.is_empty() {
        let head = state
            .projection
            .as_ref()
            .expect("genesis creates projection")
            .head
            .clone();
        let candidate_ids: Vec<String> = remaining
            .values()
            .filter(|record| record.expected_head.as_deref() == Some(head.as_str()))
            .map(|record| record.record_id.clone())
            .collect();
        match candidate_ids.as_slice() {
            [] => {
                return Err(WorkLifecycleStoreError::Invalid(
                    "work-lifecycle history has a gap, orphan, or predecessor mismatch".into(),
                ));
            }
            [candidate_id] => {
                let record = remaining
                    .remove(candidate_id)
                    .expect("selected successor remains present");
                admit_work_lifecycle_record(&mut state, &record)?;
                ordered.push(record);
            }
            _ => {
                return Err(WorkLifecycleStoreError::Invalid(
                    "work-lifecycle history forks at one expected head".into(),
                ));
            }
        }
    }
    Ok((ordered, state))
}

fn load_work_lifecycle_state_unlocked(
    data_dir: &str,
    object_ref: &str,
) -> Result<WorkLifecycleState, WorkLifecycleStoreError> {
    let (_, state) = order_and_replay_records(load_object_records(data_dir, object_ref)?)?;
    let path = projection_path(data_dir, object_ref);
    let (present, projected) = match std::fs::read(&path) {
        Ok(bytes) => (
            true,
            serde_json::from_slice::<WorkLifecycleProjection>(&bytes).ok(),
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (false, None),
        Err(error) => return Err(error.into()),
    };
    match state.projection.as_ref() {
        Some(rebuilt) => {
            if projected.as_ref() != Some(rebuilt) {
                replace_projection_json(&path, rebuilt)?;
            }
        }
        None if present => {
            return Err(WorkLifecycleStoreError::Invalid(
                "projection exists without append-only record truth".into(),
            ));
        }
        None => {}
    }
    Ok(state)
}

#[allow(dead_code)]
pub(crate) fn load_work_lifecycle_state(
    data_dir: &str,
    object_ref: &str,
) -> Result<WorkLifecycleState, WorkLifecycleStoreError> {
    let _guard = store_lock()
        .lock()
        .map_err(|_| WorkLifecycleStoreError::Invalid("store lock poisoned".into()))?;
    load_work_lifecycle_state_unlocked(data_dir, object_ref)
}

#[allow(dead_code)]
pub(crate) fn commit_work_lifecycle_record(
    data_dir: &str,
    record: &WorkLifecycleRecord,
) -> Result<(WorkLifecycleAdmissionOutcome, WorkLifecycleState), WorkLifecycleStoreError> {
    let _guard = store_lock()
        .lock()
        .map_err(|_| WorkLifecycleStoreError::Invalid("store lock poisoned".into()))?;
    let mut state = load_work_lifecycle_state_unlocked(data_dir, &record.object_ref)?;
    let outcome = admit_work_lifecycle_record(&mut state, record)?;
    if outcome == WorkLifecycleAdmissionOutcome::Replay {
        let stored: WorkLifecycleRecord = serde_json::from_slice(&std::fs::read(record_path(
            data_dir,
            &record.object_ref,
            &record.record_id,
        ))?)
        .map_err(|error| {
            WorkLifecycleStoreError::Invalid(format!(
                "idempotent replay record is malformed: {error}"
            ))
        })?;
        if &stored != record {
            return Err(WorkLifecycleStoreError::Invalid(
                "idempotency replay hash exists but record identity/bytes do not match".into(),
            ));
        }
        return Ok((outcome, state));
    }
    write_immutable_json(
        &record_path(data_dir, &record.object_ref, &record.record_id),
        record,
    )?;
    replace_projection_json(
        &projection_path(data_dir, &record.object_ref),
        state.projection.as_ref().expect("applied record projects"),
    )?;
    Ok((outcome, state))
}

#[allow(dead_code)]
pub(crate) fn compact_work_lifecycle_object(
    data_dir: &str,
    object_ref: &str,
    archive_ref: &str,
    snapshot_ref: &str,
    created_at_ms: i64,
) -> Result<(WorkLifecycleArchiveSegment, WorkLifecycleSnapshot), WorkLifecycleStoreError> {
    let _guard = store_lock()
        .lock()
        .map_err(|_| WorkLifecycleStoreError::Invalid("store lock poisoned".into()))?;
    let (ordered, _) = order_and_replay_records(load_object_records(data_dir, object_ref)?)?;
    let (archive, snapshot) =
        build_snapshot_and_archive(&ordered, archive_ref, snapshot_ref, created_at_ms)?;
    write_immutable_json(&archive_path(data_dir, object_ref, archive_ref), &archive)?;
    write_immutable_json(
        &snapshot_path(data_dir, object_ref, snapshot_ref),
        &snapshot,
    )?;
    Ok((archive, snapshot))
}

fn count_json_files(path: &Path) -> usize {
    std::fs::read_dir(path)
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| {
                    entry.path().extension().and_then(|value| value.to_str()) == Some("json")
                })
                .count()
        })
        .unwrap_or(0)
}

fn count_nested_json_files(path: &Path) -> usize {
    std::fs::read_dir(path)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| {
                    if entry.path().is_dir() {
                        count_nested_json_files(&entry.path())
                    } else if entry.path().extension().and_then(|value| value.to_str())
                        == Some("json")
                    {
                        1
                    } else {
                        0
                    }
                })
                .sum()
        })
        .unwrap_or(0)
}

pub(crate) async fn handle_work_lifecycle_status(
    State(state): State<std::sync::Arc<super::DaemonState>>,
) -> Json<Value> {
    let root = Path::new(&state.data_dir);
    let object_kinds: Vec<Value> = WorkLifecycleObjectKind::ALL
        .into_iter()
        .map(|kind| {
            json!({
                "object_kind": kind.as_str(),
                "legal_transition_count": legal_transition_table(kind).len(),
            })
        })
        .collect();
    Json(json!({
        "schema_version": "ioi.hypervisor.work-lifecycle-status.v1",
        "kernel": "available",
        "durable_append_store": "available",
        "projection_rebuild": "available",
        "snapshot_archive": "available_without_automatic_pruning",
        "object_kinds": object_kinds,
        "durable_counts": {
            "records": count_nested_json_files(&root.join(RECORD_DIR)),
            "projections": count_json_files(&root.join(PROJECTION_DIR)),
            "archives": count_nested_json_files(&root.join(ARCHIVE_DIR)),
            "snapshots": count_nested_json_files(&root.join(SNAPSHOT_DIR)),
        },
        "live_owner_route_bindings": [],
        "live_owner_route_status": "not_bound",
        "nonclaims": [
            "this status route does not claim GoalRun, GoalGroundingLoop, WorkRun, AutomationRun, HarnessInvocation, ContextCell, or external-handle write routes currently append these records",
            "the shared kernel checks the declared authority class and nonempty grant refs but does not independently verify grant signatures, scope, expiry, or revocation; each owner PEP must do so before commit",
            "snapshot/archive output is durable but automatic retention pruning and archive-only resume are not yet enabled",
            "cancellation fanout is a deterministic plan; child owners still must execute and receipt drain, fence, timeout, compensation, and ambiguous-effect reconciliation"
        ]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_services::agentic::runtime::kernel::work_lifecycle::{
        seal_record, ChildReferenceBody, ChildReferenceOperation, ChildRelationKind,
        EffectRecoveryClass, PhaseTransitionBody, WorkLifecycleAuthorityClass,
        WorkLifecycleRecordType, WORK_LIFECYCLE_RECORD_SCHEMA,
    };

    fn transition(
        record_id: &str,
        from: Option<&str>,
        to: &str,
        expected_head: Option<String>,
    ) -> WorkLifecycleRecord {
        let mut record = WorkLifecycleRecord {
            schema_version: WORK_LIFECYCLE_RECORD_SCHEMA.into(),
            record_id: record_id.into(),
            record_hash: String::new(),
            record_type: WorkLifecycleRecordType::PhaseTransition,
            object_kind: WorkLifecycleObjectKind::WorkRun,
            object_ref: "work_run://one".into(),
            owner_ref: "system://one".into(),
            expected_head,
            resulting_head: String::new(),
            idempotency_key: record_id.into(),
            authority_class: WorkLifecycleAuthorityClass::Daemon,
            authority_ref: "daemon://one".into(),
            authority_grant_refs: vec!["grant://one".into()],
            decision_receipt_ref: None,
            evidence_refs: vec![],
            receipt_refs: vec![format!("receipt://{record_id}")],
            transition: Some(PhaseTransitionBody {
                from_phase: from.map(str::to_string),
                to_phase: to.into(),
                cancellation_intent: None,
            }),
            child_reference: None,
            occurred_at_ms: if from.is_some() { 1_200 } else { 1_000 },
        };
        seal_record(&mut record).unwrap();
        record
    }

    fn child(state: &WorkLifecycleState, record_id: &str) -> WorkLifecycleRecord {
        let projection = state.projection.as_ref().unwrap();
        let mut record = WorkLifecycleRecord {
            schema_version: WORK_LIFECYCLE_RECORD_SCHEMA.into(),
            record_id: record_id.into(),
            record_hash: String::new(),
            record_type: WorkLifecycleRecordType::ChildReference,
            object_kind: projection.object_kind,
            object_ref: projection.object_ref.clone(),
            owner_ref: projection.owner_ref.clone(),
            expected_head: Some(projection.head.clone()),
            resulting_head: String::new(),
            idempotency_key: record_id.into(),
            authority_class: WorkLifecycleAuthorityClass::Daemon,
            authority_ref: "daemon://one".into(),
            authority_grant_refs: vec!["grant://one".into()],
            decision_receipt_ref: None,
            evidence_refs: vec![],
            receipt_refs: vec![format!("receipt://{record_id}")],
            transition: None,
            child_reference: Some(ChildReferenceBody {
                operation: ChildReferenceOperation::Attach,
                relation_kind: ChildRelationKind::HarnessInvocation,
                child_ref: "harness_invocation://one".into(),
                effect_recovery_class: EffectRecoveryClass::Ambiguous,
            }),
            occurred_at_ms: 1_100,
        };
        seal_record(&mut record).unwrap();
        record
    }

    #[test]
    fn crash_before_projection_rebuilds_same_phase_and_head() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        let genesis = transition("work-lifecycle://one/1", None, "pending", None);
        let (_, state) = commit_work_lifecycle_record(data_dir, &genesis).unwrap();
        let attached = child(&state, "work-lifecycle://one/2");
        let (_, state) = commit_work_lifecycle_record(data_dir, &attached).unwrap();
        let running = transition(
            "work-lifecycle://one/3",
            Some("pending"),
            "running",
            Some(state.projection.as_ref().unwrap().head.clone()),
        );

        // Immutable fact reaches disk, process dies before projection replace.
        write_immutable_json(
            &record_path(data_dir, &running.object_ref, &running.record_id),
            &running,
        )
        .unwrap();
        let rebuilt = load_work_lifecycle_state(data_dir, &running.object_ref).unwrap();
        assert_eq!(rebuilt.projection.as_ref().unwrap().active_phase, "running");
        assert_eq!(
            rebuilt.projection.as_ref().unwrap().head,
            running.resulting_head
        );
        assert_eq!(
            commit_work_lifecycle_record(data_dir, &running).unwrap().0,
            WorkLifecycleAdmissionOutcome::Replay
        );
    }

    #[test]
    fn store_refuses_fork_gap_tamper_and_sanitized_path_collision() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        let genesis = transition("work-lifecycle://one/1", None, "pending", None);
        write_immutable_json(
            &record_path(data_dir, &genesis.object_ref, &genesis.record_id),
            &genesis,
        )
        .unwrap();
        let mut state = WorkLifecycleState::default();
        admit_work_lifecycle_record(&mut state, &genesis).unwrap();
        let head = state.projection.as_ref().unwrap().head.clone();
        let left = transition(
            "work-lifecycle://one/2-left",
            Some("pending"),
            "running",
            Some(head.clone()),
        );
        let right = transition(
            "work-lifecycle://one/2-right",
            Some("pending"),
            "canceled",
            Some(head),
        );
        write_immutable_json(
            &record_path(data_dir, &left.object_ref, &left.record_id),
            &left,
        )
        .unwrap();
        write_immutable_json(
            &record_path(data_dir, &right.object_ref, &right.record_id),
            &right,
        )
        .unwrap();
        assert!(load_work_lifecycle_state(data_dir, &genesis.object_ref)
            .unwrap_err()
            .to_string()
            .contains("forks"));

        let first = "work-lifecycle://a?b";
        let second = "work-lifecycle://a/b";
        assert_eq!(
            first.replace(|character: char| !character.is_ascii_alphanumeric(), "_"),
            second.replace(|character: char| !character.is_ascii_alphanumeric(), "_")
        );
        assert_ne!(
            record_path(data_dir, "work_run://collision", first),
            record_path(data_dir, "work_run://collision", second)
        );

        let tampered = tempfile::tempdir().unwrap();
        let tampered_dir = tampered.path().to_str().unwrap();
        let path = record_path(tampered_dir, &genesis.object_ref, &genesis.record_id);
        write_immutable_json(&path, &genesis).unwrap();
        let mut value = serde_json::to_value(&genesis).unwrap();
        value["owner_ref"] = Value::String("system://tampered".into());
        std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        assert!(load_work_lifecycle_state(tampered_dir, &genesis.object_ref).is_err());

        let gapped = tempfile::tempdir().unwrap();
        let gapped_dir = gapped.path().to_str().unwrap();
        write_immutable_json(
            &record_path(gapped_dir, &genesis.object_ref, &genesis.record_id),
            &genesis,
        )
        .unwrap();
        let gap = transition(
            "work-lifecycle://one/3",
            Some("pending"),
            "running",
            Some("sha256:missing".into()),
        );
        write_immutable_json(
            &record_path(gapped_dir, &gap.object_ref, &gap.record_id),
            &gap,
        )
        .unwrap();
        assert!(load_work_lifecycle_state(gapped_dir, &genesis.object_ref)
            .unwrap_err()
            .to_string()
            .contains("gap"));
    }

    #[test]
    fn snapshot_archive_retains_receipt_lineage() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        let genesis = transition("work-lifecycle://archive/1", None, "pending", None);
        let (_, state) = commit_work_lifecycle_record(data_dir, &genesis).unwrap();
        let attached = child(&state, "work-lifecycle://archive/2");
        commit_work_lifecycle_record(data_dir, &attached).unwrap();
        let (archive, snapshot) = compact_work_lifecycle_object(
            data_dir,
            &genesis.object_ref,
            "work-lifecycle-archive://one",
            "work-lifecycle-snapshot://one",
            5_000,
        )
        .unwrap();
        assert_eq!(archive.receipt_lineage_refs.len(), 2);
        assert_eq!(snapshot.receipt_lineage_refs, archive.receipt_lineage_refs);
        assert!(archive_path(data_dir, &genesis.object_ref, &archive.archive_ref).exists());
        assert!(snapshot_path(data_dir, &genesis.object_ref, &snapshot.snapshot_ref).exists());
    }
}
