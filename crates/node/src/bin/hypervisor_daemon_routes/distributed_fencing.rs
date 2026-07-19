//! Durable per-System active-writer fence projection and daemon PEP adapter.
//!
//! This is intentionally not a public failover controller. It durably commits
//! already-authorized writer transitions and lets real effect boundaries
//! reject stale or mismatched System-scoped work before invoking the effect.
//! Active-transition grant refs and revocation snapshots are compared exactly
//! here but are not independently signature/revocation-reverified by this
//! partial module; no public promotion route is mounted.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ioi_services::agentic::runtime::kernel::distributed_fencing::{
    admit_consequential_effect, admit_writer_epoch_transition, sha256_value, ActiveSystemFence,
    AutonomousSystemWriterEpochTransition, ConsequentialEffectFenceContext, EffectOwnerBinding,
    FenceDenial, ReadConsistency,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const TRANSITION_DIR: &str = "autonomous-system-writer-epoch-transitions";
const ACTIVE_FENCE_DIR: &str = "autonomous-system-active-fences";
const NODE_IDENTITY_DIR: &str = "autonomous-system-node-config";
const NODE_IDENTITY_FILE: &str = "executing-node.json";
pub(crate) const EFFECT_CONTEXT_FIELD: &str = "consequential_effect_fence_context";

static FENCE_STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn store_lock() -> &'static Mutex<()> {
    FENCE_STORE_LOCK.get_or_init(|| Mutex::new(()))
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

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

fn active_path(data_dir: &str, system_id: &str) -> PathBuf {
    Path::new(data_dir)
        .join(ACTIVE_FENCE_DIR)
        .join(format!("{}.json", durable_ref_key(system_id)))
}

fn transition_path(data_dir: &str, transition_id: &str) -> PathBuf {
    Path::new(data_dir)
        .join(TRANSITION_DIR)
        .join(format!("{}.json", durable_ref_key(transition_id)))
}

fn node_identity_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir)
        .join(NODE_IDENTITY_DIR)
        .join(NODE_IDENTITY_FILE)
}

fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn write_immutable_json(path: &Path, value: &impl serde::Serialize) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("immutable record has no parent directory"))?;
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
            let existing = std::fs::read(path)?;
            if existing == bytes {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "immutable writer-transition slot is occupied by different bytes",
                ))
            }
        }
        Err(error) => Err(error),
    }
}

fn replace_projection_json(path: &Path, value: &impl serde::Serialize) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("active projection has no parent directory"))?;
    std::fs::create_dir_all(parent)?;
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| io::Error::other(format!("projection encoding failed: {error}")))?;
    let temp = parent.join(format!(
        ".{}.tmp-{:x}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("active"),
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
pub(crate) enum FenceStoreError {
    Denied(FenceDenial),
    Io(io::Error),
    InvalidRecord(String),
    MissingActiveFence(String),
}

impl std::fmt::Display for FenceStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied(denial) => write!(formatter, "{}: {}", denial.code, denial.message),
            Self::Io(error) => write!(formatter, "fence store I/O failed: {error}"),
            Self::InvalidRecord(message) => write!(formatter, "invalid fence record: {message}"),
            Self::MissingActiveFence(system_id) => {
                write!(
                    formatter,
                    "System '{system_id}' has no durable active writer fence"
                )
            }
        }
    }
}

impl From<FenceDenial> for FenceStoreError {
    fn from(value: FenceDenial) -> Self {
        Self::Denied(value)
    }
}

impl From<io::Error> for FenceStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

fn load_immutable_transitions(
    data_dir: &str,
) -> Result<Vec<AutonomousSystemWriterEpochTransition>, FenceStoreError> {
    let directory = Path::new(data_dir).join(TRANSITION_DIR);
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
        let bytes = std::fs::read(&path)?;
        let transition: AutonomousSystemWriterEpochTransition = serde_json::from_slice(&bytes)
            .map_err(|error| {
                FenceStoreError::InvalidRecord(format!(
                    "immutable writer transition {} is malformed: {error}",
                    path.display()
                ))
            })?;
        if path != transition_path(data_dir, &transition.transition_id) {
            return Err(FenceStoreError::InvalidRecord(format!(
                "immutable writer transition {} is stored under a noncanonical or collision-prone filename",
                transition.transition_id
            )));
        }
        if by_id
            .insert(transition.transition_id.clone(), transition)
            .is_some()
        {
            return Err(FenceStoreError::InvalidRecord(
                "immutable writer-transition store contains a duplicate transition identity".into(),
            ));
        }
    }
    Ok(by_id.into_values().collect())
}

fn replay_system_transition_chain(
    data_dir: &str,
    system_id: &str,
) -> Result<Option<ActiveSystemFence>, FenceStoreError> {
    let mut remaining: BTreeMap<String, AutonomousSystemWriterEpochTransition> =
        load_immutable_transitions(data_dir)?
            .into_iter()
            .filter(|transition| transition.system_id == system_id)
            .map(|transition| (transition.transition_id.clone(), transition))
            .collect();
    if remaining.is_empty() {
        return Ok(None);
    }
    let genesis_ids: Vec<String> = remaining
        .values()
        .filter(|transition| {
            transition.transition_kind == "genesis"
                && transition.predecessor_transition_ref.is_none()
                && transition.predecessor_transition_hash.is_none()
        })
        .map(|transition| transition.transition_id.clone())
        .collect();
    if genesis_ids.len() != 1 {
        return Err(FenceStoreError::InvalidRecord(format!(
            "System '{system_id}' writer-transition history has {} genesis roots; exactly one is required",
            genesis_ids.len()
        )));
    }
    let genesis = remaining
        .remove(&genesis_ids[0])
        .expect("selected genesis remains present");
    let mut last_committed_at_ms = genesis.committed_at_ms;
    let mut active = admit_writer_epoch_transition(None, &genesis, genesis.committed_at_ms)?;

    while !remaining.is_empty() {
        let candidate_ids: Vec<String> = remaining
            .values()
            .filter(|transition| {
                transition.predecessor_transition_ref.as_deref()
                    == Some(active.transition_id.as_str())
                    && transition.predecessor_transition_hash.as_deref()
                        == Some(active.transition_hash.as_str())
            })
            .map(|transition| transition.transition_id.clone())
            .collect();
        match candidate_ids.as_slice() {
            [] => {
                return Err(FenceStoreError::InvalidRecord(format!(
                    "System '{system_id}' writer-transition history has a gap, orphan, or predecessor-hash mismatch after {}",
                    active.transition_id
                )));
            }
            [candidate_id] => {
                let candidate = remaining
                    .remove(candidate_id)
                    .expect("selected successor remains present");
                if candidate.committed_at_ms < last_committed_at_ms {
                    return Err(FenceStoreError::InvalidRecord(format!(
                        "System '{system_id}' writer-transition commit time regresses at {}",
                        candidate.transition_id
                    )));
                }
                active = admit_writer_epoch_transition(
                    Some(&active),
                    &candidate,
                    candidate.committed_at_ms,
                )?;
                last_committed_at_ms = candidate.committed_at_ms;
            }
            _ => {
                return Err(FenceStoreError::InvalidRecord(format!(
                    "System '{system_id}' writer-transition history forks after {}",
                    active.transition_id
                )));
            }
        }
    }
    Ok(Some(active))
}

fn load_active_system_fence_unlocked(
    data_dir: &str,
    system_id: &str,
) -> Result<Option<ActiveSystemFence>, FenceStoreError> {
    let rebuilt = replay_system_transition_chain(data_dir, system_id)?;
    let path = active_path(data_dir, system_id);
    let (projection_present, projected) = match std::fs::read(&path) {
        Ok(bytes) => (
            true,
            serde_json::from_slice::<ActiveSystemFence>(&bytes).ok(),
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (false, None),
        Err(error) => return Err(error.into()),
    };
    match rebuilt {
        Some(rebuilt) => {
            if projected.as_ref() != Some(&rebuilt) {
                replace_projection_json(&path, &rebuilt)?;
            }
            Ok(Some(rebuilt))
        }
        None if projection_present => Err(FenceStoreError::InvalidRecord(format!(
            "System '{system_id}' has an active projection without immutable transition truth"
        ))),
        None => Ok(None),
    }
}

pub(crate) fn load_active_system_fence(
    data_dir: &str,
    system_id: &str,
) -> Result<Option<ActiveSystemFence>, FenceStoreError> {
    let _guard = store_lock()
        .lock()
        .map_err(|_| FenceStoreError::InvalidRecord("fence-store lock poisoned".into()))?;
    load_active_system_fence_unlocked(data_dir, system_id)
}

/// Startup reconciliation for every durable System fence. Immutable
/// transitions are truth; active files are rebuildable projections. Any
/// malformed record, filename mismatch, fork, gap, or orphan active projection
/// refuses startup rather than leaving a stale writer active indefinitely.
pub(crate) fn recover_all_active_system_fences(data_dir: &str) -> Result<usize, FenceStoreError> {
    let _guard = store_lock()
        .lock()
        .map_err(|_| FenceStoreError::InvalidRecord("fence-store lock poisoned".into()))?;
    let mut system_ids: BTreeSet<String> = load_immutable_transitions(data_dir)?
        .into_iter()
        .map(|transition| transition.system_id)
        .collect();
    // Repair every projection addressable from immutable truth before scanning
    // for orphan active files; a malformed/stale derived file is recoverable,
    // while an active file with no transition chain is not.
    for system_id in &system_ids {
        load_active_system_fence_unlocked(data_dir, system_id)?;
    }
    let active_directory = Path::new(data_dir).join(ACTIVE_FENCE_DIR);
    match std::fs::read_dir(&active_directory) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }
                let active: ActiveSystemFence = serde_json::from_slice(&std::fs::read(&path)?)
                    .map_err(|error| {
                        FenceStoreError::InvalidRecord(format!(
                            "active System fence projection {} is malformed during startup recovery: {error}",
                            path.display()
                        ))
                    })?;
                if path != active_path(data_dir, &active.system_id) {
                    return Err(FenceStoreError::InvalidRecord(format!(
                        "active System fence for {} is stored under a noncanonical or collision-prone filename",
                        active.system_id
                    )));
                }
                system_ids.insert(active.system_id);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    for system_id in &system_ids {
        load_active_system_fence_unlocked(data_dir, system_id)?;
    }
    Ok(system_ids.len())
}

/// Freeze the operator-supplied daemon node identity into local startup
/// configuration. A conflicting identity refuses startup; no request route can
/// author or rotate this record.
pub(crate) fn initialize_executing_node_identity(
    data_dir: &str,
    configured_node_id: Option<&str>,
) -> Result<(), FenceStoreError> {
    let Some(node_id) = configured_node_id else {
        return Ok(());
    };
    if node_id.trim().is_empty() || !node_id.starts_with("node://") {
        return Err(FenceStoreError::InvalidRecord(
            "configured autonomous-System node identity must be a nonempty node:// ref".into(),
        ));
    }
    write_immutable_json(
        &node_identity_path(data_dir),
        &serde_json::json!({
            "schema_version": "ioi.hypervisor.autonomous-system-node-config.v1",
            "node_id": node_id
        }),
    )?;
    Ok(())
}

fn load_executing_node_id(data_dir: &str) -> Result<String, FenceStoreError> {
    let bytes = std::fs::read(node_identity_path(data_dir)).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            FenceStoreError::InvalidRecord(
                "System-scoped effects are unavailable because this daemon has no trusted autonomous-System node identity configuration".into(),
            )
        } else {
            FenceStoreError::Io(error)
        }
    })?;
    let record: Value = serde_json::from_slice(&bytes).map_err(|error| {
        FenceStoreError::InvalidRecord(format!("node identity configuration is malformed: {error}"))
    })?;
    record
        .get("node_id")
        .and_then(Value::as_str)
        .filter(|node_id| !node_id.trim().is_empty() && node_id.starts_with("node://"))
        .map(str::to_string)
        .ok_or_else(|| {
            FenceStoreError::InvalidRecord(
                "node identity configuration has no valid node:// identity".into(),
            )
        })
}

/// Commit one immutable transition and update the rebuildable active
/// projection. The in-process lock serializes the daemon's single writer; the
/// transition's own durable continuity-CAS proof binds the cross-node head.
pub(crate) fn commit_writer_epoch_transition(
    data_dir: &str,
    transition: &AutonomousSystemWriterEpochTransition,
    now_ms: i64,
) -> Result<ActiveSystemFence, FenceStoreError> {
    let _guard = store_lock()
        .lock()
        .map_err(|_| FenceStoreError::InvalidRecord("fence-store lock poisoned".into()))?;
    let current = load_active_system_fence_unlocked(data_dir, &transition.system_id)?;
    if let Some(active) = current.as_ref() {
        if active.transition_id == transition.transition_id
            && active.transition_hash == transition.transition_hash
        {
            let stored: AutonomousSystemWriterEpochTransition = serde_json::from_slice(
                &std::fs::read(transition_path(data_dir, &transition.transition_id))?,
            )
            .map_err(|error| {
                FenceStoreError::InvalidRecord(format!(
                    "immutable writer transition is malformed during idempotent commit replay: {error}"
                ))
            })?;
            if &stored == transition {
                return Ok(active.clone());
            }
            return Err(FenceStoreError::InvalidRecord(
                "writer-transition identity/hash replay does not equal immutable stored bytes"
                    .into(),
            ));
        }
    }
    let next = admit_writer_epoch_transition(current.as_ref(), transition, now_ms)?;
    write_immutable_json(
        &transition_path(data_dir, &transition.transition_id),
        transition,
    )?;
    replace_projection_json(&active_path(data_dir, &transition.system_id), &next)?;
    Ok(next)
}

#[derive(Debug, Clone)]
pub(crate) struct GeneratedSystemEffectAdmission {
    pub active_fence: ActiveSystemFence,
    pub context: ConsequentialEffectFenceContext,
}

#[derive(Debug, Clone)]
pub(crate) struct DurableReadEvidence {
    pub consistency: ReadConsistency,
    pub watermark: String,
    pub state_root: String,
}

pub(crate) fn durable_read_evidence_from_owner(
    owner_record: &Value,
) -> Result<DurableReadEvidence, FenceStoreError> {
    let evidence = owner_record
        .get("system_fence_read_evidence")
        .ok_or_else(|| {
            FenceStoreError::InvalidRecord(
                "System-scoped owner has no durable system_fence_read_evidence".into(),
            )
        })?;
    let consistency = evidence.get("consistency").cloned().ok_or_else(|| {
        FenceStoreError::InvalidRecord("durable read evidence has no consistency posture".into())
    })?;
    let consistency: ReadConsistency = serde_json::from_value(consistency).map_err(|error| {
        FenceStoreError::InvalidRecord(format!(
            "durable read consistency posture is invalid: {error}"
        ))
    })?;
    let field = |name: &str| {
        evidence
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                FenceStoreError::InvalidRecord(format!(
                    "durable read evidence has no nonempty {name}"
                ))
            })
    };
    Ok(DurableReadEvidence {
        consistency,
        watermark: field("watermark")?,
        state_root: field("state_root")?,
    })
}

/// Generate and verify a System effect context from durable owner/session/fence
/// facts and trusted daemon startup configuration. Caller-authored contexts are
/// always refused. The optional grant/lease inputs must come from a durable
/// daemon-owned session/lease record; when absent, the active transition's own
/// grant and timing ceiling are used for internal domain admission.
pub(crate) fn generate_and_admit_system_scoped_effect(
    data_dir: &str,
    owner_record: &Value,
    resource_id: &str,
    effect_kind: &str,
    effect_payload: &Value,
    durable_authority_grant_ref: Option<&str>,
    durable_authority_lease_expires_at_ms: Option<i64>,
    require_durable_authority_binding: bool,
    durable_read_evidence: Option<&DurableReadEvidence>,
    idempotency_key: &str,
    now_ms: i64,
) -> Result<Option<GeneratedSystemEffectAdmission>, FenceStoreError> {
    if effect_payload.get(EFFECT_CONTEXT_FIELD).is_some() {
        return Err(FenceStoreError::InvalidRecord(format!(
            "{EFFECT_CONTEXT_FIELD} is daemon-generated evidence and cannot be supplied by a caller"
        )));
    }
    let Some(system_value) = owner_record.get("system_id") else {
        return Ok(None);
    };
    if system_value.is_null() {
        return Ok(None);
    }
    let system_id = system_value
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            FenceStoreError::InvalidRecord(
                "System-scoped owner has a non-string or empty system_id".into(),
            )
        })?;
    if resource_id.trim().is_empty() || effect_kind.trim().is_empty() {
        return Err(FenceStoreError::InvalidRecord(
            "PEP-derived resource and effect identities must be nonempty".into(),
        ));
    }
    let active = load_active_system_fence(data_dir, system_id)?
        .ok_or_else(|| FenceStoreError::MissingActiveFence(system_id.to_string()))?;
    let executing_node_id = load_executing_node_id(data_dir)?;
    if require_durable_authority_binding
        && (durable_authority_grant_ref.map_or(true, |grant| grant.trim().is_empty())
            || durable_authority_lease_expires_at_ms.is_none())
    {
        return Err(FenceStoreError::InvalidRecord(
            "this effect requires a durable daemon-owned authority grant and lease expiry".into(),
        ));
    }
    let read_evidence = durable_read_evidence.ok_or_else(|| {
        FenceStoreError::InvalidRecord(
            "System-scoped effect has no durable observed read consistency, watermark, and state root"
                .into(),
        )
    })?;
    let _resource = active
        .resource_fences
        .iter()
        .find(|resource| resource.resource_id == resource_id)
        .ok_or_else(|| {
            FenceStoreError::InvalidRecord(
                "owner-derived resource has no active consequential-effect fence".into(),
            )
        })?;
    let authority_grant_ref = durable_authority_grant_ref
        .filter(|grant| !grant.trim().is_empty())
        .map(str::to_string)
        .or_else(|| active.authority_grant_refs.first().cloned())
        .ok_or_else(|| {
            FenceStoreError::InvalidRecord(
                "active System fence has no authority grant for this effect".into(),
            )
        })?;
    let writer_lease_expires_at_ms = durable_authority_lease_expires_at_ms
        .unwrap_or(active.timing_evidence_expires_at_ms)
        .min(active.timing_evidence_expires_at_ms);
    let payload_hash = sha256_value(effect_payload)?;
    let context = ConsequentialEffectFenceContext {
        schema_version:
            ioi_services::agentic::runtime::kernel::distributed_fencing::EFFECT_FENCE_CONTEXT_SCHEMA
                .to_string(),
        system_id: system_id.to_string(),
        executing_node_id: executing_node_id.clone(),
        resource_id: resource_id.to_string(),
        effect_kind: effect_kind.to_string(),
        exact_payload_hash: payload_hash.clone(),
        deployment_profile_root: active.deployment_profile_root.clone(),
        node_membership_epoch: active.writer.membership_epoch,
        node_membership_root: active.writer.membership_root.clone(),
        writer_transition_ref: active.transition_id.clone(),
        writer_transition_hash: active.transition_hash.clone(),
        writer_epoch: active.writer_epoch,
        writer_lease_expires_at_ms,
        authority_grant_ref,
        authority_revocation_snapshot_ref: active.authority_revocation_snapshot_ref.clone(),
        authority_revocation_epoch: active.authority_revocation_epoch,
        read_consistency: read_evidence.consistency,
        read_watermark: read_evidence.watermark.clone(),
        read_state_root: read_evidence.state_root.clone(),
        idempotency_key: idempotency_key.to_string(),
        evaluated_at_ms: now_ms,
        expires_at_ms: writer_lease_expires_at_ms,
    };
    let owner = EffectOwnerBinding {
        system_id,
        executing_node_id: &executing_node_id,
        resource_id,
        effect_kind,
        exact_payload_hash: &payload_hash,
    };
    admit_consequential_effect(&active, &context, &owner, now_ms)?;
    Ok(Some(GeneratedSystemEffectAdmission {
        active_fence: active,
        context,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_services::agentic::runtime::kernel::distributed_fencing::{
        transition_content_hash, ConsequentialResourceFence, ContinuityCasProof, ReadConsistency,
        TransitionTimingEvidence, WriterMembership, WRITER_TRANSITION_SCHEMA,
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NOW: i64 = 50_000;

    fn transition(resource_id: &str) -> AutonomousSystemWriterEpochTransition {
        let mut transition = AutonomousSystemWriterEpochTransition {
            schema_version: WRITER_TRANSITION_SCHEMA.into(),
            transition_id: "writer-transition://sys-one/1".into(),
            transition_hash: String::new(),
            transition_kind: "genesis".into(),
            system_id: "system://one".into(),
            deployment_profile_ref: "deployment-profile://one/v1".into(),
            deployment_profile_root: "sha256:deployment".into(),
            failover_profile_ref: "failover-profile://one/v1".into(),
            failover_profile_root: "sha256:failover".into(),
            ordering_profile_ref: "ordering-profile://one/v1".into(),
            ordering_profile_root: "sha256:ordering".into(),
            predecessor_transition_ref: None,
            predecessor_transition_hash: None,
            prior_writer_epoch: 0,
            new_writer_epoch: 1,
            prior_writer: None,
            successor_writer: WriterMembership {
                node_id: "node://one".into(),
                membership_epoch: 3,
                membership_root: "sha256:membership".into(),
            },
            verified_state_root: "sha256:state".into(),
            catchup_receipt_ref: "receipt://catchup".into(),
            state_root_verification_ref: "verification://root".into(),
            authority_grant_refs: vec!["authority-grant://writer".into()],
            authority_revocation_snapshot_ref: "revocation-snapshot://4".into(),
            authority_revocation_epoch: 4,
            displaced_writer_fence_receipt_refs: vec![],
            timing_evidence: TransitionTimingEvidence {
                observed_at_ms: 49_000,
                expires_at_ms: 60_000,
                effects_not_before_ms: 49_500,
                displaced_writer_leases_expire_at_ms: 49_000,
                revocation_propagation_complete_at_ms: 49_250,
                max_clock_uncertainty_ms: 250,
            },
            continuity_cas: ContinuityCasProof {
                mechanism: "witness_quorum_cas".into(),
                substrate_ref: "continuity://one".into(),
                expected_head: None,
                resulting_head: String::new(),
                proof_ref: "cas-proof://one".into(),
            },
            resource_fences: vec![ConsequentialResourceFence {
                resource_id: resource_id.into(),
                allowed_effects: vec!["connector.read".into()],
                minimum_read_consistency: ReadConsistency::LinearizedDomain,
                read_watermark: "seq:8".into(),
            }],
            lost_suffix_record_ref: None,
            committed_at_ms: 49_500,
        };
        let hash = transition_content_hash(&transition).unwrap();
        transition.transition_hash = hash.clone();
        transition.continuity_cas.resulting_head = hash;
        transition
    }

    fn successor_transition(
        prior: &ActiveSystemFence,
        transition_id: &str,
    ) -> AutonomousSystemWriterEpochTransition {
        let mut transition = transition(&prior.resource_fences[0].resource_id);
        transition.transition_id = transition_id.into();
        transition.transition_kind = "promotion".into();
        transition.predecessor_transition_ref = Some(prior.transition_id.clone());
        transition.predecessor_transition_hash = Some(prior.transition_hash.clone());
        transition.prior_writer_epoch = prior.writer_epoch;
        transition.new_writer_epoch = prior.writer_epoch + 1;
        transition.prior_writer = Some(prior.writer.clone());
        transition.successor_writer = WriterMembership {
            node_id: format!("node://{}", prior.writer_epoch + 1),
            membership_epoch: prior.writer.membership_epoch + 1,
            membership_root: format!("sha256:membership-{}", prior.writer_epoch + 1),
        };
        transition.displaced_writer_fence_receipt_refs =
            vec![format!("receipt://fence/{}", prior.writer_epoch)];
        transition.continuity_cas.expected_head = Some(prior.transition_hash.clone());
        transition.continuity_cas.proof_ref = format!("cas-proof://{}", prior.writer_epoch + 1);
        transition.transition_hash.clear();
        transition.continuity_cas.resulting_head.clear();
        let hash = transition_content_hash(&transition).unwrap();
        transition.transition_hash = hash.clone();
        transition.continuity_cas.resulting_head = hash;
        transition
    }

    fn payload() -> Value {
        json!({ "connector_session_id": "session-1", "limit": 10 })
    }

    fn read_evidence() -> DurableReadEvidence {
        DurableReadEvidence {
            consistency: ReadConsistency::LinearizedDomain,
            watermark: "seq:8".into(),
            state_root: "sha256:state".into(),
        }
    }

    #[test]
    fn transition_cas_advances_and_stale_head_leaves_projection_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        let resource_id = "data-source:one";
        let transition = transition(resource_id);
        let active = commit_writer_epoch_transition(data_dir, &transition, NOW).unwrap();
        assert_eq!(active.writer_epoch, 1);
        assert_eq!(
            load_active_system_fence(data_dir, "system://one").unwrap(),
            Some(active.clone())
        );

        let next = successor_transition(&active, "writer-transition://sys-one/2");
        // Simulate a crash after immutable truth fsync but before the
        // rebuildable active projection is replaced. Restart/load must replay
        // the chain and atomically restore the exact latest projection.
        write_immutable_json(&transition_path(data_dir, &next.transition_id), &next).unwrap();
        assert_eq!(recover_all_active_system_fences(data_dir).unwrap(), 1);
        let active = load_active_system_fence(data_dir, "system://one")
            .unwrap()
            .unwrap();
        assert_eq!(active.writer_epoch, 2);
        assert_eq!(
            serde_json::from_slice::<ActiveSystemFence>(
                &std::fs::read(active_path(data_dir, "system://one")).unwrap()
            )
            .unwrap(),
            active
        );
        assert_eq!(
            commit_writer_epoch_transition(data_dir, &next, NOW).unwrap(),
            active,
            "idempotent retry after crash must return the rebuilt head"
        );

        let mut stale = successor_transition(&active, "writer-transition://sys-one/3");
        stale.continuity_cas.expected_head = Some("sha256:stale".into());
        stale.transition_hash.clear();
        stale.continuity_cas.resulting_head.clear();
        let hash = transition_content_hash(&stale).unwrap();
        stale.transition_hash = hash.clone();
        stale.continuity_cas.resulting_head = hash;
        assert!(commit_writer_epoch_transition(data_dir, &stale, NOW).is_err());
        assert_eq!(
            load_active_system_fence(data_dir, "system://one")
                .unwrap()
                .unwrap()
                .writer_epoch,
            2
        );
    }

    #[test]
    fn transition_history_refuses_forks_gaps_and_tamper() {
        let forked = tempfile::tempdir().unwrap();
        let forked_dir = forked.path().to_str().unwrap();
        let genesis = transition("data-source:one");
        write_immutable_json(
            &transition_path(forked_dir, &genesis.transition_id),
            &genesis,
        )
        .unwrap();
        let active =
            admit_writer_epoch_transition(None, &genesis, genesis.committed_at_ms).unwrap();
        let left = successor_transition(&active, "writer-transition://sys-one/2-left");
        let right = successor_transition(&active, "writer-transition://sys-one/2-right");
        write_immutable_json(&transition_path(forked_dir, &left.transition_id), &left).unwrap();
        write_immutable_json(&transition_path(forked_dir, &right.transition_id), &right).unwrap();
        assert!(load_active_system_fence(forked_dir, "system://one")
            .unwrap_err()
            .to_string()
            .contains("forks"));

        let gapped = tempfile::tempdir().unwrap();
        let gapped_dir = gapped.path().to_str().unwrap();
        write_immutable_json(
            &transition_path(gapped_dir, &genesis.transition_id),
            &genesis,
        )
        .unwrap();
        let mut gap = successor_transition(&active, "writer-transition://sys-one/3");
        gap.predecessor_transition_ref = Some("writer-transition://sys-one/missing".into());
        gap.transition_hash.clear();
        gap.continuity_cas.resulting_head.clear();
        let hash = transition_content_hash(&gap).unwrap();
        gap.transition_hash = hash.clone();
        gap.continuity_cas.resulting_head = hash;
        write_immutable_json(&transition_path(gapped_dir, &gap.transition_id), &gap).unwrap();
        assert!(load_active_system_fence(gapped_dir, "system://one")
            .unwrap_err()
            .to_string()
            .contains("gap"));

        let tampered = tempfile::tempdir().unwrap();
        let tampered_dir = tampered.path().to_str().unwrap();
        let path = transition_path(tampered_dir, &genesis.transition_id);
        write_immutable_json(&path, &genesis).unwrap();
        let mut bytes = serde_json::to_value(&genesis).unwrap();
        bytes["verified_state_root"] = Value::String("sha256:tampered".into());
        std::fs::write(&path, serde_json::to_vec_pretty(&bytes).unwrap()).unwrap();
        assert!(load_active_system_fence(tampered_dir, "system://one").is_err());
    }

    #[test]
    fn authority_record_paths_are_collision_resistant() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        let first = "writer-transition://system/a?b";
        let second = "writer-transition://system/a/b";
        assert_eq!(
            first.replace(|character: char| !character.is_ascii_alphanumeric(), "_"),
            second.replace(|character: char| !character.is_ascii_alphanumeric(), "_")
        );
        assert_ne!(
            transition_path(data_dir, first),
            transition_path(data_dir, second)
        );
        assert_ne!(
            active_path(data_dir, "system://a?b"),
            active_path(data_dir, "system://a/b")
        );
    }

    #[test]
    fn immutable_transition_slot_refuses_different_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("transition.json");
        write_immutable_json(&path, &json!({ "head": 1 })).unwrap();
        let denial = write_immutable_json(&path, &json!({ "head": 2 })).unwrap_err();
        assert_eq!(denial.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(path).unwrap()).unwrap(),
            json!({ "head": 1 })
        );
    }

    #[test]
    fn system_owned_effect_requires_exact_fence_before_invoker() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        let resource_id = "data-source:one";
        let transition = transition(resource_id);
        commit_writer_epoch_transition(data_dir, &transition, NOW).unwrap();
        initialize_executing_node_identity(data_dir, Some("node://one")).unwrap();
        let owner =
            json!({ "source_id": "one", "source_ref": resource_id, "system_id": "system://one" });
        let valid = payload();
        let calls = AtomicUsize::new(0);
        let generated = generate_and_admit_system_scoped_effect(
            data_dir,
            &owner,
            resource_id,
            "connector.read",
            &valid,
            Some("authority-grant://writer"),
            Some(55_000),
            true,
            Some(&read_evidence()),
            "connector-session-1",
            NOW,
        )
        .map(|admission| {
            calls.fetch_add(1, Ordering::SeqCst);
            admission.unwrap()
        })
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(generated.active_fence.writer.node_id, "node://one");
        assert_eq!(generated.context.executing_node_id, "node://one");
        assert_eq!(
            generated.context.exact_payload_hash,
            sha256_value(&valid).unwrap()
        );

        let denied_invocations = AtomicUsize::new(0);
        let mut caller_authored = valid.clone();
        caller_authored[EFFECT_CONTEXT_FIELD] =
            serde_json::to_value(generated.context.clone()).unwrap();
        let cases = [
            (
                caller_authored,
                resource_id,
                "connector.read",
                Some("authority-grant://writer"),
                Some(55_000),
            ),
            (
                valid.clone(),
                "data-source:other",
                "connector.read",
                Some("authority-grant://writer"),
                Some(55_000),
            ),
            (
                valid.clone(),
                resource_id,
                "wallet.transfer",
                Some("authority-grant://writer"),
                Some(55_000),
            ),
            (
                valid.clone(),
                resource_id,
                "connector.read",
                Some("authority-grant://foreign"),
                Some(55_000),
            ),
            (
                valid.clone(),
                resource_id,
                "connector.read",
                Some("authority-grant://writer"),
                Some(NOW - 1),
            ),
            (valid.clone(), resource_id, "connector.read", None, None),
        ];
        for (effect, derived_resource, derived_effect, grant, lease_expiry) in cases {
            let result = generate_and_admit_system_scoped_effect(
                data_dir,
                &owner,
                derived_resource,
                derived_effect,
                &effect,
                grant,
                lease_expiry,
                true,
                Some(&read_evidence()),
                "connector-session-1",
                NOW,
            )
            .map(|_| denied_invocations.fetch_add(1, Ordering::SeqCst));
            assert!(result.is_err());
        }
        assert_eq!(denied_invocations.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn deposed_or_unconfigured_daemon_node_cannot_invoke() {
        for (name, configured_node) in [("missing", None), ("deposed", Some("node://deposed"))] {
            let directory = tempfile::tempdir().unwrap();
            let data_dir = directory.path().to_str().unwrap();
            let resource_id = "data-source:one";
            let active =
                commit_writer_epoch_transition(data_dir, &transition(resource_id), NOW).unwrap();
            if let Some(node_id) = configured_node {
                initialize_executing_node_identity(data_dir, Some(node_id)).unwrap();
            }
            let owner = json!({ "system_id": "system://one" });
            let calls = AtomicUsize::new(0);
            let result = generate_and_admit_system_scoped_effect(
                data_dir,
                &owner,
                resource_id,
                "connector.read",
                &payload(),
                Some(&active.authority_grant_refs[0]),
                Some(55_000),
                true,
                Some(&read_evidence()),
                name,
                NOW,
            )
            .map(|_| calls.fetch_add(1, Ordering::SeqCst));
            assert!(result.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn non_system_owner_keeps_existing_effect_path() {
        let directory = tempfile::tempdir().unwrap();
        let result = generate_and_admit_system_scoped_effect(
            directory.path().to_str().unwrap(),
            &json!({ "source_id": "legacy" }),
            "data-source:legacy",
            "connector.read",
            &json!({ "limit": 1 }),
            None,
            None,
            false,
            None,
            "legacy",
            NOW,
        )
        .unwrap();
        assert!(result.is_none());
    }
}
