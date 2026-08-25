//! Shared WorkLifecycle append-only log mechanics.
//!
//! Implements the append-only mechanics layer for
//! `WorkLifecycleRecordEnvelope`, `WorkLifecycleProjectionEnvelope`,
//! `CancellationFanoutPlanEnvelope`, `WorkLifecycleArchiveSegmentEnvelope`, and
//! `WorkLifecycleSnapshotEnvelope`, exactly as specified in
//! `docs/architecture/foundations/objects/work-results-and-lifecycle.md` and the
//! shared-mechanics section of
//! `docs/architecture/components/daemon-runtime/doctrine.md`:
//! content commitment, exact-head compare-and-swap, object-scoped idempotency,
//! append-only child references, a rebuildable active projection, deterministic
//! cancellation planning, and immutable archive/snapshot continuity where resume
//! plus an append-only tail reconstructs the same truth as full replay.
//!
//! This layer owns **mechanics only** (INV-35, ADR 0034 sub-ruling 1). It does
//! not own GoalRun, GoalGroundingLoop, WorkRun, AutomationRun, HarnessInvocation,
//! ContextCell, or external-handle state, and it does not flatten their phases
//! into a universal lifecycle. Each kind keeps its own legal-edge and
//! transition-authority table; the per-kind decision is delegated to a
//! [`LegalEdgeGate`] the owning route/service supplies, so the shared kernel is
//! the single bounding site without acquiring any domain object's write
//! authority. GoalRun creation now composes this kernel through its owner-side
//! gate, without moving Session/launch/thread/HarnessInvocation truth into it.
//!
//! Records, plans, projections, archive segments, and snapshots are round-tripped
//! through the generated projections whose `Deserialize` validates against the
//! registered schema, so a non-conforming object cannot leave this module.

use std::collections::BTreeMap;

use ioi_types::app::generated::architecture_contracts::{
    CancellationFanoutPlanV1, WorkLifecycleArchiveSegmentV1, WorkLifecycleProjectionV1,
    WorkLifecycleRecordV1, WorkLifecycleSnapshotV1,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const WORK_LIFECYCLE_RECORD_SCHEMA_VERSION: &str = "ioi.work-lifecycle-record.v1";
pub const WORK_LIFECYCLE_PROJECTION_SCHEMA_VERSION: &str = "ioi.work-lifecycle-projection.v1";
pub const CANCELLATION_FANOUT_PLAN_SCHEMA_VERSION: &str = "ioi.cancellation-fanout-plan.v1";
pub const WORK_LIFECYCLE_ARCHIVE_SEGMENT_SCHEMA_VERSION: &str =
    "ioi.work-lifecycle-archive-segment.v1";
pub const WORK_LIFECYCLE_SNAPSHOT_SCHEMA_VERSION: &str = "ioi.work-lifecycle-snapshot.v1";

/// Fields excluded from the content commitment. Canon: "the content commitment
/// covers every field except `record_hash` and `resulting_head`; both excluded
/// fields then equal that exact commitment."
const UNCOMMITTED_FIELDS: [&str; 2] = ["record_hash", "resulting_head"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkLifecycleLogError {
    code: &'static str,
    message: String,
}

impl WorkLifecycleLogError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

type LogResult<T> = Result<T, WorkLifecycleLogError>;

/// Per-kind legal-edge and transition-authority gate.
///
/// The shared kernel owns integrity/replay mechanics but never the domain
/// object's write authority (doctrine: "never acquire the domain object's write
/// authority"). The kind-specific legal phase and authority table stays with its
/// owner, which implements this trait; the kernel invokes it as the single
/// bounding point and fails the edge closed when it refuses, so illegal
/// transitions and authority drift are rejected here without the table living
/// here.
pub trait LegalEdgeGate {
    /// Authorize one transition. `prior` is the current head record for the
    /// object (`None` at genesis); `candidate` is the record being appended,
    /// before its `record_hash`/`resulting_head` are stamped. Return `Err(reason)`
    /// to refuse the edge.
    fn authorize(&self, prior: Option<&Value>, candidate: &Value) -> Result<(), String>;
}

/// Outcome of an append attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendOutcome {
    /// A new record was committed.
    Appended,
    /// An object-scoped idempotency key replayed with identical bytes; the
    /// original record is returned unchanged.
    IdempotentReplay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkLifecycleAppendRecord {
    pub outcome: AppendOutcome,
    pub record: Value,
    pub resulting_head: String,
}

/// One active typed child, projected from attach/detach records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveChild {
    pub relation_kind: String,
    pub child_ref: String,
    pub effect_recovery_class: String,
}

/// Cancellation intent admitted on a cancel edge.
#[derive(Debug, Clone, Default)]
pub struct CancellationIntent {
    pub requested_by_ref: String,
    pub reason: String,
    pub compensation_policy_ref: Option<String>,
    pub effect_reconciliation_policy_ref: Option<String>,
    pub timeout_at_ms: Option<i64>,
}

/// Rebuilt fold state shared by projection, snapshot, and resume so that resume
/// plus a tail is byte-identical to a full replay.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectionState {
    object_kind: String,
    object_ref: String,
    owner_ref: String,
    active_phase: String,
    head: String,
    last_record_ref: String,
    last_occurred_at_ms: i64,
    record_count: u64,
    active_children: BTreeMap<(String, String), ActiveChild>,
    cancellation_intent: Option<Value>,
    receipt_lineage: Vec<String>,
    idempotency: BTreeMap<String, String>,
}

/// A resumed projection plus the idempotency decisions carried across the
/// compaction boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumedProjection {
    pub projection: Value,
    pub idempotency_record_hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct WorkLifecycleLogCore;

impl WorkLifecycleLogCore {
    /// Content commitment over every field except the two excluded ones.
    pub fn commitment(&self, record: &Value) -> LogResult<String> {
        let object = record.as_object().ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_log_record_not_object",
                "a lifecycle record must be a JSON object",
            )
        })?;
        let mut committed = Map::new();
        for (key, value) in object {
            if UNCOMMITTED_FIELDS.contains(&key.as_str()) {
                continue;
            }
            committed.insert(key.clone(), value.clone());
        }
        Ok(sha256_commit(&canonical_json(&Value::Object(committed))))
    }

    /// Append one record under exact-head compare-and-swap and object-scoped
    /// idempotency, with no per-kind authority gate.
    ///
    /// `log` is the existing record sequence for one object, in append order.
    /// Fails closed on duplicate genesis, fork, gap, orphan, invalid hash,
    /// regressed timestamp, owner drift, or a changed-bytes idempotency
    /// collision.
    pub fn plan_append(
        &self,
        log: &[Value],
        candidate: &Value,
    ) -> LogResult<WorkLifecycleAppendRecord> {
        self.plan_append_inner(log, candidate, None)
    }

    /// Append one record and additionally authorize the transition through the
    /// kind-specific [`LegalEdgeGate`]. A genuine append is refused when the gate
    /// refuses; an idempotent replay of an already-admitted record is returned
    /// unchanged without re-consulting the gate.
    pub fn plan_append_gated(
        &self,
        log: &[Value],
        candidate: &Value,
        gate: &dyn LegalEdgeGate,
    ) -> LogResult<WorkLifecycleAppendRecord> {
        self.plan_append_inner(log, candidate, Some(gate))
    }

    fn plan_append_inner(
        &self,
        log: &[Value],
        candidate: &Value,
        gate: Option<&dyn LegalEdgeGate>,
    ) -> LogResult<WorkLifecycleAppendRecord> {
        let object = candidate.as_object().ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_log_record_not_object",
                "a lifecycle record must be a JSON object",
            )
        })?;

        let schema_version = str_field(object, "schema_version").unwrap_or_default();
        if schema_version != WORK_LIFECYCLE_RECORD_SCHEMA_VERSION {
            return Err(WorkLifecycleLogError::new(
                "work_lifecycle_log_schema_version_invalid",
                format!("expected {WORK_LIFECYCLE_RECORD_SCHEMA_VERSION}, got {schema_version}"),
            ));
        }

        let object_ref = str_field(object, "object_ref").ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_log_object_ref_required",
                "record requires object_ref",
            )
        })?;

        let owner_ref = str_field(object, "owner_ref").ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_log_owner_ref_required",
                "record requires owner_ref",
            )
        })?;

        // Exactly one of phase_transition / child_reference, matching record_type.
        let record_type = str_field(object, "record_type").unwrap_or_default();
        let has_phase = object
            .get("phase_transition")
            .is_some_and(|value| !value.is_null());
        let has_child = object
            .get("child_reference")
            .is_some_and(|value| !value.is_null());
        if has_phase == has_child {
            return Err(WorkLifecycleLogError::new(
                "work_lifecycle_log_payload_cardinality_invalid",
                "exactly one of phase_transition and child_reference must be non-null",
            ));
        }
        let expected_type = if has_phase {
            "phase_transition"
        } else {
            "child_reference"
        };
        if record_type != expected_type {
            return Err(WorkLifecycleLogError::new(
                "work_lifecycle_log_record_type_mismatch",
                format!("record_type {record_type} does not match the non-null payload"),
            ));
        }

        let idempotency_key = str_field(object, "idempotency_key").ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_log_idempotency_key_required",
                "record requires idempotency_key",
            )
        })?;
        let occurred_at_ms = object
            .get("occurred_at_ms")
            .and_then(Value::as_i64)
            .ok_or_else(|| {
                WorkLifecycleLogError::new(
                    "work_lifecycle_log_occurred_at_required",
                    "record requires integer occurred_at_ms",
                )
            })?;

        let commitment = self.commitment(candidate)?;

        // Object-scoped idempotency, evaluated before head mechanics so a
        // genuine replay of the current head record does not read as a fork.
        for existing in log {
            let Some(existing_object) = existing.as_object() else {
                continue;
            };
            if str_field(existing_object, "object_ref").as_deref() != Some(object_ref.as_str()) {
                continue;
            }
            if str_field(existing_object, "idempotency_key").as_deref()
                != Some(idempotency_key.as_str())
            {
                continue;
            }
            let existing_commitment = self.commitment(existing)?;
            if existing_commitment == commitment {
                return Ok(WorkLifecycleAppendRecord {
                    outcome: AppendOutcome::IdempotentReplay,
                    resulting_head: existing_commitment,
                    record: existing.clone(),
                });
            }
            return Err(WorkLifecycleLogError::new(
                "work_lifecycle_log_idempotency_conflict",
                "idempotency key reused with different bytes",
            ));
        }

        let scoped: Vec<&Value> = log
            .iter()
            .filter(|entry| {
                entry
                    .as_object()
                    .and_then(|entry| str_field(entry, "object_ref"))
                    .as_deref()
                    == Some(object_ref.as_str())
            })
            .collect();

        let expected_head = object
            .get("expected_head")
            .and_then(|value| value.as_str().map(str::to_string));

        let prior_head_record = scoped.last().copied();

        match (scoped.last(), expected_head.as_deref()) {
            // Genesis.
            (None, None) => {}
            (None, Some(head)) => {
                return Err(WorkLifecycleLogError::new(
                    "work_lifecycle_log_orphan_successor",
                    format!("no genesis record exists but expected_head is {head}"),
                ));
            }
            (Some(_), None) => {
                return Err(WorkLifecycleLogError::new(
                    "work_lifecycle_log_duplicate_genesis",
                    "a genesis record already exists for this object",
                ));
            }
            (Some(current), Some(head)) => {
                let current_object = current.as_object().ok_or_else(|| {
                    WorkLifecycleLogError::new(
                        "work_lifecycle_log_record_not_object",
                        "stored record is not an object",
                    )
                })?;
                let current_head =
                    str_field(current_object, "resulting_head").ok_or_else(|| {
                        WorkLifecycleLogError::new(
                            "work_lifecycle_log_head_missing",
                            "stored record has no resulting_head",
                        )
                    })?;
                // Stored integrity: the head must equal its own commitment.
                let recomputed = self.commitment(current)?;
                if recomputed != current_head {
                    return Err(WorkLifecycleLogError::new(
                        "work_lifecycle_log_invalid_stored_hash",
                        "stored record hash does not match its content commitment",
                    ));
                }
                if head != current_head {
                    return Err(WorkLifecycleLogError::new(
                        "work_lifecycle_log_head_mismatch",
                        "expected_head does not match the current head (fork or gap)",
                    ));
                }
                // Owner drift: a successor may not re-home the object to a new
                // owner. The owner is fixed at genesis.
                if str_field(current_object, "owner_ref").as_deref() != Some(owner_ref.as_str()) {
                    return Err(WorkLifecycleLogError::new(
                        "work_lifecycle_log_owner_drift",
                        "owner_ref may not change across an object's chain",
                    ));
                }
                let current_time = current_object
                    .get("occurred_at_ms")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                if occurred_at_ms < current_time {
                    return Err(WorkLifecycleLogError::new(
                        "work_lifecycle_log_timestamp_regression",
                        "occurred_at_ms may not regress",
                    ));
                }
            }
        }

        // Per-kind legal-edge and authority gate. Runs after mechanics pass and
        // only for a genuine append, at the single bounding site.
        if let Some(gate) = gate {
            gate.authorize(prior_head_record, candidate)
                .map_err(|reason| {
                    WorkLifecycleLogError::new(
                        "work_lifecycle_log_authority_refused",
                        format!("transition refused by the kind-specific authority gate: {reason}"),
                    )
                })?;
        }

        let mut committed = object.clone();
        committed.insert("record_hash".into(), json!(commitment));
        committed.insert("resulting_head".into(), json!(commitment));
        let record = Value::Object(committed);

        // Contract gate: the generated projection validates against the
        // registered schema, so a non-conforming record cannot be emitted.
        serde_json::from_value::<WorkLifecycleRecordV1>(record.clone()).map_err(|error| {
            WorkLifecycleLogError::new(
                "work_lifecycle_log_projection_invalid",
                format!("record does not satisfy the registered schema: {error}"),
            )
        })?;

        Ok(WorkLifecycleAppendRecord {
            outcome: AppendOutcome::Appended,
            record,
            resulting_head: commitment,
        })
    }

    /// Reconstruct one object's record chain in append order from an unordered
    /// record set, by walking `expected_head` -> `resulting_head` links from
    /// genesis.
    ///
    /// Storage order is not trusted. Fails closed on a missing or duplicate
    /// genesis, a fork (two records claiming the same predecessor), an
    /// orphan/gap (records that no chain walk reaches), or owner drift.
    pub fn reconstruct_chain(&self, records: &[Value]) -> LogResult<Vec<Value>> {
        if records.is_empty() {
            return Ok(Vec::new());
        }

        let mut genesis: Option<&Value> = None;
        let mut by_predecessor: BTreeMap<String, &Value> = BTreeMap::new();

        for record in records {
            let object = record.as_object().ok_or_else(|| {
                WorkLifecycleLogError::new(
                    "work_lifecycle_log_record_not_object",
                    "stored record is not an object",
                )
            })?;
            match object.get("expected_head").and_then(Value::as_str) {
                None => {
                    if genesis.is_some() {
                        return Err(WorkLifecycleLogError::new(
                            "work_lifecycle_log_duplicate_genesis",
                            "more than one genesis record exists for this object",
                        ));
                    }
                    genesis = Some(record);
                }
                Some(predecessor) => {
                    if by_predecessor
                        .insert(predecessor.to_string(), record)
                        .is_some()
                    {
                        return Err(WorkLifecycleLogError::new(
                            "work_lifecycle_log_fork_detected",
                            format!("two records claim predecessor {predecessor}"),
                        ));
                    }
                }
            }
        }

        let Some(genesis) = genesis else {
            return Err(WorkLifecycleLogError::new(
                "work_lifecycle_log_missing_genesis",
                "record set has no genesis record",
            ));
        };

        let owner = genesis
            .as_object()
            .and_then(|object| str_field(object, "owner_ref"))
            .ok_or_else(|| {
                WorkLifecycleLogError::new(
                    "work_lifecycle_log_owner_ref_required",
                    "genesis record requires owner_ref",
                )
            })?;

        let mut chain = vec![genesis.clone()];
        let mut head = self.stored_head(genesis)?;
        while let Some(next) = by_predecessor.remove(&head) {
            if next
                .as_object()
                .and_then(|object| str_field(object, "owner_ref"))
                .as_deref()
                != Some(owner.as_str())
            {
                return Err(WorkLifecycleLogError::new(
                    "work_lifecycle_log_owner_drift",
                    "owner_ref may not change across an object's chain",
                ));
            }
            head = self.stored_head(next)?;
            chain.push(next.clone());
        }

        if !by_predecessor.is_empty() {
            return Err(WorkLifecycleLogError::new(
                "work_lifecycle_log_orphan_records",
                format!(
                    "{} record(s) are unreachable from genesis (gap or orphan)",
                    by_predecessor.len()
                ),
            ));
        }

        Ok(chain)
    }

    /// Read a stored record's head, verifying it equals its own commitment.
    fn stored_head(&self, record: &Value) -> LogResult<String> {
        let stored = record
            .as_object()
            .and_then(|object| str_field(object, "resulting_head"))
            .ok_or_else(|| {
                WorkLifecycleLogError::new(
                    "work_lifecycle_log_head_missing",
                    "stored record has no resulting_head",
                )
            })?;
        if self.commitment(record)? != stored {
            return Err(WorkLifecycleLogError::new(
                "work_lifecycle_log_invalid_stored_hash",
                "stored record hash does not match its content commitment",
            ));
        }
        Ok(stored)
    }

    /// Rebuild the active typed child set from append-only attach/detach facts.
    pub fn project_active_children(&self, log: &[Value]) -> LogResult<Vec<ActiveChild>> {
        Ok(self.fold_children(log)?.into_values().collect())
    }

    fn fold_children(&self, log: &[Value]) -> LogResult<BTreeMap<(String, String), ActiveChild>> {
        let mut active: BTreeMap<(String, String), ActiveChild> = BTreeMap::new();
        for entry in log {
            let Some(object) = entry.as_object() else {
                continue;
            };
            let Some(child) = object.get("child_reference").filter(|v| !v.is_null()) else {
                continue;
            };
            let Some(child) = child.as_object() else {
                continue;
            };
            let operation = str_field(child, "operation").unwrap_or_default();
            let relation_kind = str_field(child, "relation_kind").unwrap_or_default();
            let child_ref = str_field(child, "child_ref").unwrap_or_default();
            if relation_kind.is_empty() || child_ref.is_empty() {
                return Err(WorkLifecycleLogError::new(
                    "work_lifecycle_log_child_reference_incomplete",
                    "child_reference requires relation_kind and child_ref",
                ));
            }
            let key = (relation_kind.clone(), child_ref.clone());
            match operation.as_str() {
                "attach" => {
                    active.insert(
                        key,
                        ActiveChild {
                            relation_kind,
                            child_ref,
                            effect_recovery_class: str_field(child, "effect_recovery_class")
                                .unwrap_or_else(|| "none".to_string()),
                        },
                    );
                }
                "detach" => {
                    active.remove(&key);
                }
                other => {
                    return Err(WorkLifecycleLogError::new(
                        "work_lifecycle_log_child_operation_invalid",
                        format!("unknown child_reference operation {other}"),
                    ));
                }
            }
        }
        Ok(active)
    }

    /// Fold an ordered chain into the rebuildable projection state.
    fn fold_state(&self, chain: &[Value]) -> LogResult<ProjectionState> {
        let Some((genesis, rest)) = chain.split_first() else {
            return Err(WorkLifecycleLogError::new(
                "work_lifecycle_log_empty_chain",
                "cannot project an empty chain",
            ));
        };
        let genesis_object = genesis.as_object().ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_log_record_not_object",
                "genesis record is not an object",
            )
        })?;

        let object_kind = str_field(genesis_object, "object_kind").ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_log_object_kind_required",
                "genesis record requires object_kind",
            )
        })?;
        let object_ref = str_field(genesis_object, "object_ref").ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_log_object_ref_required",
                "genesis record requires object_ref",
            )
        })?;
        let owner_ref = str_field(genesis_object, "owner_ref").ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_log_owner_ref_required",
                "genesis record requires owner_ref",
            )
        })?;

        let mut state = ProjectionState {
            object_kind,
            object_ref,
            owner_ref,
            active_phase: genesis_to_phase(genesis_object)?,
            head: self.stored_head(genesis)?,
            last_record_ref: str_field(genesis_object, "record_id").ok_or_else(|| {
                WorkLifecycleLogError::new(
                    "work_lifecycle_log_record_id_required",
                    "record requires record_id",
                )
            })?,
            last_occurred_at_ms: genesis_object
                .get("occurred_at_ms")
                .and_then(Value::as_i64)
                .unwrap_or_default(),
            record_count: 1,
            active_children: BTreeMap::new(),
            cancellation_intent: None,
            receipt_lineage: Vec::new(),
            idempotency: BTreeMap::new(),
        };
        self.apply_record(&mut state, genesis, true)?;
        for record in rest {
            self.apply_record(&mut state, record, false)?;
        }
        Ok(state)
    }

    /// Apply one record's deltas to fold state. `is_genesis` skips the fields
    /// already seeded from genesis so they are not double-counted.
    fn apply_record(
        &self,
        state: &mut ProjectionState,
        record: &Value,
        is_genesis: bool,
    ) -> LogResult<()> {
        let object = record.as_object().ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_log_record_not_object",
                "record is not an object",
            )
        })?;

        if !is_genesis {
            state.record_count = state.record_count.saturating_add(1);
            state.head = self.stored_head(record)?;
            state.last_record_ref = str_field(object, "record_id").ok_or_else(|| {
                WorkLifecycleLogError::new(
                    "work_lifecycle_log_record_id_required",
                    "record requires record_id",
                )
            })?;
            state.last_occurred_at_ms = object
                .get("occurred_at_ms")
                .and_then(Value::as_i64)
                .unwrap_or(state.last_occurred_at_ms);

            if let Some(phase) = object.get("phase_transition").filter(|v| !v.is_null()) {
                let phase_object = phase.as_object().ok_or_else(|| {
                    WorkLifecycleLogError::new(
                        "work_lifecycle_log_phase_transition_invalid",
                        "phase_transition must be an object",
                    )
                })?;
                state.active_phase = str_field(phase_object, "to_phase").ok_or_else(|| {
                    WorkLifecycleLogError::new(
                        "work_lifecycle_log_to_phase_required",
                        "phase_transition requires to_phase",
                    )
                })?;
                if let Some(intent) = phase_object
                    .get("cancellation_intent")
                    .filter(|v| !v.is_null())
                {
                    state.cancellation_intent = Some(intent.clone());
                }
            }
        }

        if let Some(child) = object.get("child_reference").filter(|v| !v.is_null()) {
            let child_object = child.as_object().ok_or_else(|| {
                WorkLifecycleLogError::new(
                    "work_lifecycle_log_child_reference_invalid",
                    "child_reference must be an object",
                )
            })?;
            let operation = str_field(child_object, "operation").unwrap_or_default();
            let relation_kind = str_field(child_object, "relation_kind").unwrap_or_default();
            let child_ref = str_field(child_object, "child_ref").unwrap_or_default();
            if relation_kind.is_empty() || child_ref.is_empty() {
                return Err(WorkLifecycleLogError::new(
                    "work_lifecycle_log_child_reference_incomplete",
                    "child_reference requires relation_kind and child_ref",
                ));
            }
            let key = (relation_kind.clone(), child_ref.clone());
            match operation.as_str() {
                "attach" => {
                    state.active_children.insert(
                        key,
                        ActiveChild {
                            relation_kind,
                            child_ref,
                            effect_recovery_class: str_field(child_object, "effect_recovery_class")
                                .unwrap_or_else(|| "none".to_string()),
                        },
                    );
                }
                "detach" => {
                    state.active_children.remove(&key);
                }
                other => {
                    return Err(WorkLifecycleLogError::new(
                        "work_lifecycle_log_child_operation_invalid",
                        format!("unknown child_reference operation {other}"),
                    ));
                }
            }
        }

        for receipt in object
            .get("receipt_refs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if !state.receipt_lineage.iter().any(|seen| seen == receipt) {
                state.receipt_lineage.push(receipt.to_string());
            }
        }

        if let Some(key) = str_field(object, "idempotency_key") {
            if let Some(hash) = str_field(object, "record_hash") {
                state.idempotency.insert(key, hash);
            }
        }

        Ok(())
    }

    /// Project one object's rebuildable active state from its record log.
    ///
    /// The log is reconstructed first, so an unordered or tampered log fails
    /// closed rather than producing a false projection.
    pub fn project(&self, log: &[Value]) -> LogResult<Value> {
        let chain = self.reconstruct_chain(log)?;
        let state = self.fold_state(&chain)?;
        self.projection_value(&state)
    }

    fn projection_value(&self, state: &ProjectionState) -> LogResult<Value> {
        let projection = json!({
            "schema_version": WORK_LIFECYCLE_PROJECTION_SCHEMA_VERSION,
            "object_kind": state.object_kind,
            "object_ref": state.object_ref,
            "owner_ref": state.owner_ref,
            "active_phase": state.active_phase,
            "head": state.head,
            "last_record_ref": state.last_record_ref,
            "last_occurred_at_ms": state.last_occurred_at_ms,
            "record_count": state.record_count,
            "active_children": children_index(&state.active_children),
            "cancellation_intent": state.cancellation_intent.clone().unwrap_or(Value::Null),
            "receipt_lineage_refs": state.receipt_lineage,
        });
        serde_json::from_value::<WorkLifecycleProjectionV1>(projection.clone()).map_err(
            |error| {
                WorkLifecycleLogError::new(
                    "work_lifecycle_projection_invalid",
                    format!("projection does not satisfy the registered schema: {error}"),
                )
            },
        )?;
        Ok(projection)
    }

    /// Write an immutable archive segment covering an object's chain through the
    /// given head.
    ///
    /// The chain is reconstructed and its final head must equal `through_head`.
    /// `archive_root` is a deterministic commitment over the ordered record
    /// hashes, so any change to the archived bytes changes the root. The segment
    /// carries the records verbatim; it never rewrites or prunes them.
    pub fn plan_archive_segment(
        &self,
        archive_ref: &str,
        log: &[Value],
        through_head: &str,
        created_at_ms: i64,
    ) -> LogResult<Value> {
        let chain = self.reconstruct_chain(log)?;
        let state = self.fold_state(&chain)?;
        if state.head != through_head {
            return Err(WorkLifecycleLogError::new(
                "work_lifecycle_archive_head_mismatch",
                "through_head does not match the reconstructed chain head",
            ));
        }

        let archive_root = self.archive_root(&chain)?;
        let segment = json!({
            "schema_version": WORK_LIFECYCLE_ARCHIVE_SEGMENT_SCHEMA_VERSION,
            "archive_ref": archive_ref,
            "object_kind": state.object_kind,
            "object_ref": state.object_ref,
            "through_head": state.head,
            "archive_root": archive_root,
            "records": chain,
            "receipt_lineage_refs": state.receipt_lineage,
            "created_at_ms": created_at_ms,
        });
        serde_json::from_value::<WorkLifecycleArchiveSegmentV1>(segment.clone()).map_err(
            |error| {
                WorkLifecycleLogError::new(
                    "work_lifecycle_archive_invalid",
                    format!("archive segment does not satisfy the registered schema: {error}"),
                )
            },
        )?;
        Ok(segment)
    }

    /// Deterministic archive root over the ordered record hashes.
    fn archive_root(&self, chain: &[Value]) -> LogResult<String> {
        let mut hashes = Vec::with_capacity(chain.len());
        for record in chain {
            let head = self.stored_head(record)?;
            hashes.push(Value::String(head));
        }
        Ok(sha256_commit(&canonical_json(&Value::Array(hashes))))
    }

    /// Write a snapshot bound to an archive segment's root and head.
    ///
    /// The snapshot retains the resumable projection and the idempotency
    /// decisions and receipt lineage of the archived records, so hot-log records
    /// may later leave the active segment without losing replay parity. The
    /// snapshot is a checkpoint, never a license to discard the archive.
    pub fn plan_snapshot(
        &self,
        snapshot_ref: &str,
        archive_segment: &Value,
        created_at_ms: i64,
    ) -> LogResult<Value> {
        let segment = archive_segment.as_object().ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_snapshot_archive_invalid",
                "archive segment must be an object",
            )
        })?;

        // The bound archive must itself be a conforming, integrity-checked
        // segment before a snapshot can rest on it.
        serde_json::from_value::<WorkLifecycleArchiveSegmentV1>(archive_segment.clone()).map_err(
            |error| {
                WorkLifecycleLogError::new(
                    "work_lifecycle_snapshot_archive_invalid",
                    format!("bound archive segment is not conforming: {error}"),
                )
            },
        )?;

        let archive_ref = str_field(segment, "archive_ref").ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_snapshot_archive_ref_required",
                "archive segment requires archive_ref",
            )
        })?;
        let archive_root = str_field(segment, "archive_root").ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_snapshot_archive_root_required",
                "archive segment requires archive_root",
            )
        })?;
        let records: Vec<Value> = segment
            .get("records")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let chain = self.reconstruct_chain(&records)?;
        let state = self.fold_state(&chain)?;

        // The snapshot head and root must be exactly those the archive commits.
        let recomputed_root = self.archive_root(&chain)?;
        if recomputed_root != archive_root {
            return Err(WorkLifecycleLogError::new(
                "work_lifecycle_snapshot_archive_root_mismatch",
                "recomputed archive root does not match the bound segment",
            ));
        }
        if str_field(segment, "through_head").as_deref() != Some(state.head.as_str()) {
            return Err(WorkLifecycleLogError::new(
                "work_lifecycle_snapshot_head_mismatch",
                "archive through_head does not match the reconstructed head",
            ));
        }

        let projection = self.projection_value(&state)?;
        let snapshot = json!({
            "schema_version": WORK_LIFECYCLE_SNAPSHOT_SCHEMA_VERSION,
            "snapshot_ref": snapshot_ref,
            "archive_ref": archive_ref,
            "archive_root": archive_root,
            "through_head": state.head,
            "resume_state": {
                "projection": projection,
                "idempotency_record_hashes": idempotency_value(&state.idempotency),
            },
            "receipt_lineage_refs": state.receipt_lineage,
            "created_at_ms": created_at_ms,
        });
        serde_json::from_value::<WorkLifecycleSnapshotV1>(snapshot.clone()).map_err(|error| {
            WorkLifecycleLogError::new(
                "work_lifecycle_snapshot_invalid",
                format!("snapshot does not satisfy the registered schema: {error}"),
            )
        })?;
        Ok(snapshot)
    }

    /// Resume from a snapshot and apply an append-only tail, reconstructing the
    /// same projection and idempotency decisions as a full replay of the whole
    /// chain.
    ///
    /// The tail must chain from the snapshot's `through_head`. Each tail record
    /// is integrity-checked and may not regress time, fork, or drift owner.
    pub fn resume_and_project(
        &self,
        snapshot: &Value,
        tail: &[Value],
    ) -> LogResult<ResumedProjection> {
        let snapshot_object = snapshot.as_object().ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_resume_snapshot_invalid",
                "snapshot must be an object",
            )
        })?;
        serde_json::from_value::<WorkLifecycleSnapshotV1>(snapshot.clone()).map_err(|error| {
            WorkLifecycleLogError::new(
                "work_lifecycle_resume_snapshot_invalid",
                format!("snapshot does not satisfy the registered schema: {error}"),
            )
        })?;

        let through_head = str_field(snapshot_object, "through_head").ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_resume_through_head_required",
                "snapshot requires through_head",
            )
        })?;
        let resume_state = snapshot_object
            .get("resume_state")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                WorkLifecycleLogError::new(
                    "work_lifecycle_resume_state_required",
                    "snapshot requires resume_state",
                )
            })?;
        let projection = resume_state
            .get("projection")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                WorkLifecycleLogError::new(
                    "work_lifecycle_resume_projection_required",
                    "resume_state requires projection",
                )
            })?;
        let idempotency = resume_state
            .get("idempotency_record_hashes")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                WorkLifecycleLogError::new(
                    "work_lifecycle_resume_idempotency_required",
                    "resume_state requires idempotency_record_hashes",
                )
            })?;

        let mut state = seed_state_from_projection(projection, idempotency)?;
        if state.head != through_head {
            return Err(WorkLifecycleLogError::new(
                "work_lifecycle_resume_head_mismatch",
                "snapshot projection head does not match through_head",
            ));
        }

        // The tail must chain from the snapshot head onward, in order.
        let mut expected_head = through_head.clone();
        for record in tail {
            let object = record.as_object().ok_or_else(|| {
                WorkLifecycleLogError::new(
                    "work_lifecycle_resume_record_invalid",
                    "tail record is not an object",
                )
            })?;
            let record_expected = str_field(object, "expected_head").ok_or_else(|| {
                WorkLifecycleLogError::new(
                    "work_lifecycle_resume_tail_orphan",
                    "tail record has no expected_head",
                )
            })?;
            if record_expected != expected_head {
                return Err(WorkLifecycleLogError::new(
                    "work_lifecycle_resume_tail_gap",
                    "tail record does not chain from the snapshot head",
                ));
            }
            if str_field(object, "owner_ref").as_deref() != Some(state.owner_ref.as_str()) {
                return Err(WorkLifecycleLogError::new(
                    "work_lifecycle_log_owner_drift",
                    "owner_ref may not change across an object's chain",
                ));
            }
            let occurred = object
                .get("occurred_at_ms")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            if occurred < state.last_occurred_at_ms {
                return Err(WorkLifecycleLogError::new(
                    "work_lifecycle_log_timestamp_regression",
                    "occurred_at_ms may not regress",
                ));
            }
            self.apply_record(&mut state, record, false)?;
            expected_head = state.head.clone();
        }

        let projection = self.projection_value(&state)?;
        Ok(ResumedProjection {
            projection,
            idempotency_record_hashes: state.idempotency,
        })
    }

    /// Derive a `CancellationFanoutPlan` over active typed children.
    ///
    /// Canon: the edge is refused when a compensatable active child has no
    /// compensation policy, or an ambiguous/irreversible active child has no
    /// effect-reconciliation policy. The plan never claims child completion.
    pub fn plan_cancellation_fanout(
        &self,
        object_ref: &str,
        source_head: &str,
        log: &[Value],
        intent: &CancellationIntent,
    ) -> LogResult<Value> {
        if intent.requested_by_ref.trim().is_empty() {
            return Err(WorkLifecycleLogError::new(
                "work_lifecycle_cancellation_requester_required",
                "cancellation requires requested_by_ref",
            ));
        }

        let active = self.project_active_children(log)?;
        let mut targets = Vec::new();

        for child in &active {
            let mut actions: Vec<&str> = Vec::new();
            match child.effect_recovery_class.as_str() {
                "none" | "reversible" => {
                    actions.push("request_cancel");
                    actions.push("drain");
                }
                "compensatable" => {
                    if intent.compensation_policy_ref.is_none() {
                        return Err(WorkLifecycleLogError::new(
                            "work_lifecycle_cancellation_compensation_policy_required",
                            format!(
                                "compensatable active child {} requires a compensation policy",
                                child.child_ref
                            ),
                        ));
                    }
                    actions.push("request_cancel");
                    actions.push("drain");
                    actions.push("compensate");
                }
                "irreversible" => {
                    if intent.effect_reconciliation_policy_ref.is_none() {
                        return Err(WorkLifecycleLogError::new(
                            "work_lifecycle_cancellation_reconciliation_policy_required",
                            format!(
                                "irreversible active child {} requires an effect-reconciliation policy",
                                child.child_ref
                            ),
                        ));
                    }
                    actions.push("fence");
                    actions.push("reconcile_irreversible_effect");
                }
                "ambiguous" => {
                    if intent.effect_reconciliation_policy_ref.is_none() {
                        return Err(WorkLifecycleLogError::new(
                            "work_lifecycle_cancellation_reconciliation_policy_required",
                            format!(
                                "ambiguous active child {} requires an effect-reconciliation policy",
                                child.child_ref
                            ),
                        ));
                    }
                    actions.push("fence");
                    actions.push("reconcile_ambiguous_effect");
                }
                other => {
                    return Err(WorkLifecycleLogError::new(
                        "work_lifecycle_cancellation_recovery_class_invalid",
                        format!("unknown effect_recovery_class {other}"),
                    ));
                }
            }

            // Relation-specific release actions.
            match child.relation_kind.as_str() {
                "context_cell" => actions.push("close_context"),
                "context_lease" => actions.push("revoke_lease"),
                _ => {}
            }

            if intent.timeout_at_ms.is_some() {
                actions.push("wait_until_timeout");
            }
            actions.push("preserve_receipt_lineage");
            actions.dedup();

            targets.push(json!({
                "relation_kind": child.relation_kind,
                "target_ref": child.child_ref,
                "actions": actions,
                "timeout_at_ms": intent.timeout_at_ms,
            }));
        }

        let plan = json!({
            "schema_version": CANCELLATION_FANOUT_PLAN_SCHEMA_VERSION,
            "object_ref": object_ref,
            "source_head": source_head,
            "requested_by_ref": intent.requested_by_ref,
            "reason": intent.reason,
            "compensation_policy_ref": intent.compensation_policy_ref,
            "effect_reconciliation_policy_ref": intent.effect_reconciliation_policy_ref,
            "targets": targets,
            "requires_completion_receipt": true,
        });

        serde_json::from_value::<CancellationFanoutPlanV1>(plan.clone()).map_err(|error| {
            WorkLifecycleLogError::new(
                "work_lifecycle_cancellation_projection_invalid",
                format!("plan does not satisfy the registered schema: {error}"),
            )
        })?;

        Ok(plan)
    }
}

/// Group the active child set into a typed relation index:
/// `{ relation_kind: [ { child_ref, effect_recovery_class }, ... ] }`.
fn children_index(active: &BTreeMap<(String, String), ActiveChild>) -> Value {
    let mut index: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for child in active.values() {
        index
            .entry(child.relation_kind.clone())
            .or_default()
            .push(json!({
                "child_ref": child.child_ref,
                "effect_recovery_class": child.effect_recovery_class,
            }));
    }
    let mut object = Map::new();
    for (relation_kind, children) in index {
        object.insert(relation_kind, Value::Array(children));
    }
    Value::Object(object)
}

fn idempotency_value(idempotency: &BTreeMap<String, String>) -> Value {
    let mut object = Map::new();
    for (key, hash) in idempotency {
        object.insert(key.clone(), Value::String(hash.clone()));
    }
    Value::Object(object)
}

/// Rebuild fold state from a snapshot's projection and idempotency map, so a
/// resumed fold begins in exactly the state a full replay would have reached.
fn seed_state_from_projection(
    projection: &Map<String, Value>,
    idempotency: &Map<String, Value>,
) -> LogResult<ProjectionState> {
    let field = |key: &str| -> LogResult<String> {
        str_field(projection, key).ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_resume_projection_incomplete",
                format!("resume projection requires {key}"),
            )
        })
    };

    let mut active_children: BTreeMap<(String, String), ActiveChild> = BTreeMap::new();
    if let Some(index) = projection.get("active_children").and_then(Value::as_object) {
        for (relation_kind, children) in index {
            let Some(children) = children.as_array() else {
                continue;
            };
            for child in children {
                let Some(child) = child.as_object() else {
                    continue;
                };
                let child_ref = str_field(child, "child_ref").ok_or_else(|| {
                    WorkLifecycleLogError::new(
                        "work_lifecycle_resume_child_invalid",
                        "resume active child requires child_ref",
                    )
                })?;
                active_children.insert(
                    (relation_kind.clone(), child_ref.clone()),
                    ActiveChild {
                        relation_kind: relation_kind.clone(),
                        child_ref,
                        effect_recovery_class: str_field(child, "effect_recovery_class")
                            .unwrap_or_else(|| "none".to_string()),
                    },
                );
            }
        }
    }

    let receipt_lineage = projection
        .get("receipt_lineage_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();

    let mut idempotency_map = BTreeMap::new();
    for (key, hash) in idempotency {
        if let Some(hash) = hash.as_str() {
            idempotency_map.insert(key.clone(), hash.to_string());
        }
    }

    Ok(ProjectionState {
        object_kind: field("object_kind")?,
        object_ref: field("object_ref")?,
        owner_ref: field("owner_ref")?,
        active_phase: field("active_phase")?,
        head: field("head")?,
        last_record_ref: field("last_record_ref")?,
        last_occurred_at_ms: projection
            .get("last_occurred_at_ms")
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        record_count: projection
            .get("record_count")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        active_children,
        cancellation_intent: projection
            .get("cancellation_intent")
            .filter(|value| !value.is_null())
            .cloned(),
        receipt_lineage,
        idempotency: idempotency_map,
    })
}

fn genesis_to_phase(genesis: &Map<String, Value>) -> LogResult<String> {
    let phase = genesis
        .get("phase_transition")
        .filter(|v| !v.is_null())
        .and_then(Value::as_object)
        .ok_or_else(|| {
            WorkLifecycleLogError::new(
                "work_lifecycle_log_genesis_not_phase_transition",
                "genesis record must carry an initial phase_transition",
            )
        })?;
    str_field(phase, "to_phase").ok_or_else(|| {
        WorkLifecycleLogError::new(
            "work_lifecycle_log_to_phase_required",
            "genesis phase_transition requires to_phase",
        )
    })
}

fn sha256_commit(canonical: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

/// Deterministic canonical JSON: object keys sorted, no insignificant space.
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            let inner: Vec<String> = sorted
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        Value::String((*key).clone()),
                        canonical_json(value)
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

fn str_field(object: &Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBJECT: &str = "work_run://run-1";
    const OWNER: &str = "project://alpha";

    fn genesis() -> Value {
        json!({
            "schema_version": WORK_LIFECYCLE_RECORD_SCHEMA_VERSION,
            "record_id": "work-lifecycle://run-1/0",
            "record_hash": "",
            "record_type": "phase_transition",
            "object_kind": "work_run",
            "object_ref": OBJECT,
            "owner_ref": OWNER,
            "expected_head": Value::Null,
            "resulting_head": "",
            "idempotency_key": "genesis-1",
            "authority_class": "daemon",
            "authority_ref": "actor://daemon",
            "authority_grant_refs": [],
            "decision_receipt_ref": Value::Null,
            "evidence_refs": [],
            "receipt_refs": ["receipt://run-1/create"],
            "phase_transition": { "from_phase": Value::Null, "to_phase": "pending" },
            "child_reference": Value::Null,
            "occurred_at_ms": 1_000,
        })
    }

    fn attach(id: &str, key: &str, class: &str, head: &str, at: i64) -> Value {
        json!({
            "schema_version": WORK_LIFECYCLE_RECORD_SCHEMA_VERSION,
            "record_id": format!("work-lifecycle://run-1/{id}"),
            "record_hash": "",
            "record_type": "child_reference",
            "object_kind": "work_run",
            "object_ref": OBJECT,
            "owner_ref": OWNER,
            "expected_head": head,
            "resulting_head": "",
            "idempotency_key": key,
            "authority_class": "daemon",
            "authority_ref": "actor://daemon",
            "authority_grant_refs": [],
            "decision_receipt_ref": Value::Null,
            "evidence_refs": [],
            "receipt_refs": [format!("receipt://run-1/{id}")],
            "phase_transition": Value::Null,
            "child_reference": {
                "operation": "attach",
                "relation_kind": "harness_invocation",
                "child_ref": format!("harness_invocation://{id}"),
                "effect_recovery_class": class,
            },
            "occurred_at_ms": at,
        })
    }

    fn phase(id: &str, key: &str, to_phase: &str, head: &str, at: i64) -> Value {
        json!({
            "schema_version": WORK_LIFECYCLE_RECORD_SCHEMA_VERSION,
            "record_id": format!("work-lifecycle://run-1/{id}"),
            "record_hash": "",
            "record_type": "phase_transition",
            "object_kind": "work_run",
            "object_ref": OBJECT,
            "owner_ref": OWNER,
            "expected_head": head,
            "resulting_head": "",
            "idempotency_key": key,
            "authority_class": "daemon",
            "authority_ref": "actor://daemon",
            "authority_grant_refs": [],
            "decision_receipt_ref": Value::Null,
            "evidence_refs": [],
            "receipt_refs": [format!("receipt://run-1/{id}")],
            "phase_transition": { "from_phase": "pending", "to_phase": to_phase },
            "child_reference": Value::Null,
            "occurred_at_ms": at,
        })
    }

    fn commit(core: &WorkLifecycleLogCore, log: &mut Vec<Value>, candidate: Value) -> String {
        let planned = core.plan_append(log, &candidate).unwrap();
        log.push(planned.record);
        planned.resulting_head
    }

    #[test]
    fn genesis_commits_and_head_equals_commitment() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let head = commit(&core, &mut log, genesis());
        assert!(head.starts_with("sha256:"));
        assert_eq!(log[0]["record_hash"].as_str().unwrap(), head);
        assert_eq!(log[0]["resulting_head"].as_str().unwrap(), head);
    }

    #[test]
    fn duplicate_genesis_fails_closed() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        commit(&core, &mut log, genesis());
        let mut second = genesis();
        second["idempotency_key"] = json!("genesis-2");
        second["record_id"] = json!("work-lifecycle://run-1/0b");
        let err = core.plan_append(&log, &second).unwrap_err();
        assert_eq!(err.code(), "work_lifecycle_log_duplicate_genesis");
    }

    #[test]
    fn orphan_successor_fails_closed() {
        let core = WorkLifecycleLogCore;
        let err = core
            .plan_append(
                &[],
                &attach(
                    "a",
                    "k-a",
                    "none",
                    &format!("sha256:{}", "0".repeat(64)),
                    2_000,
                ),
            )
            .unwrap_err();
        assert_eq!(err.code(), "work_lifecycle_log_orphan_successor");
    }

    #[test]
    fn fork_on_stale_head_fails_closed() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let head = commit(&core, &mut log, genesis());
        commit(&core, &mut log, attach("a", "k-a", "none", &head, 2_000));
        let err = core
            .plan_append(&log, &attach("b", "k-b", "none", &head, 3_000))
            .unwrap_err();
        assert_eq!(err.code(), "work_lifecycle_log_head_mismatch");
    }

    #[test]
    fn idempotent_replay_returns_the_original() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let head = commit(&core, &mut log, genesis());
        let record = attach("a", "k-a", "none", &head, 2_000);
        commit(&core, &mut log, record.clone());
        let replay = core.plan_append(&log, &record).unwrap();
        assert_eq!(replay.outcome, AppendOutcome::IdempotentReplay);
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn idempotency_key_reuse_with_changed_bytes_fails() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let head = commit(&core, &mut log, genesis());
        commit(&core, &mut log, attach("a", "k-a", "none", &head, 2_000));
        let mut changed = attach("a", "k-a", "reversible", &head, 2_000);
        changed["record_id"] = json!("work-lifecycle://run-1/a2");
        let err = core.plan_append(&log, &changed).unwrap_err();
        assert_eq!(err.code(), "work_lifecycle_log_idempotency_conflict");
    }

    #[test]
    fn payload_cardinality_is_enforced() {
        let core = WorkLifecycleLogCore;
        let mut both = genesis();
        both["child_reference"] = json!({
            "operation": "attach",
            "relation_kind": "work_run",
            "child_ref": "work_run://x",
            "effect_recovery_class": "none",
        });
        assert_eq!(
            core.plan_append(&[], &both).unwrap_err().code(),
            "work_lifecycle_log_payload_cardinality_invalid"
        );

        let mut mismatched = genesis();
        mismatched["record_type"] = json!("child_reference");
        assert_eq!(
            core.plan_append(&[], &mismatched).unwrap_err().code(),
            "work_lifecycle_log_record_type_mismatch"
        );
    }

    #[test]
    fn timestamp_regression_fails_closed() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let head = commit(&core, &mut log, genesis());
        let err = core
            .plan_append(&log, &attach("a", "k-a", "none", &head, 10))
            .unwrap_err();
        assert_eq!(err.code(), "work_lifecycle_log_timestamp_regression");
    }

    #[test]
    fn tampered_stored_hash_fails_closed() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let head = commit(&core, &mut log, genesis());
        log[0]["occurred_at_ms"] = json!(9_999);
        let err = core
            .plan_append(&log, &attach("a", "k-a", "none", &head, 2_000))
            .unwrap_err();
        assert_eq!(err.code(), "work_lifecycle_log_invalid_stored_hash");
    }

    #[test]
    fn owner_drift_on_successor_fails_closed() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let head = commit(&core, &mut log, genesis());
        let mut foreign = attach("a", "k-a", "none", &head, 2_000);
        foreign["owner_ref"] = json!("project://intruder");
        let err = core.plan_append(&log, &foreign).unwrap_err();
        assert_eq!(err.code(), "work_lifecycle_log_owner_drift");
    }

    #[test]
    fn owner_drift_in_reconstruction_fails_closed() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let mut head = commit(&core, &mut log, genesis());
        head = commit(&core, &mut log, attach("a", "k-a", "none", &head, 2_000));
        let _ = head;
        // Tamper the stored owner on a successor: reconstruction must refuse.
        log[1]["owner_ref"] = json!("project://intruder");
        let err = core.reconstruct_chain(&log).unwrap_err();
        // The tampered record no longer matches its own hash first; but if hashes
        // were also forged, owner drift catches it. Accept either fail-closed code.
        assert!(
            err.code() == "work_lifecycle_log_owner_drift"
                || err.code() == "work_lifecycle_log_invalid_stored_hash"
        );
    }

    #[test]
    fn chain_reconstructs_from_unordered_storage() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let mut head = commit(&core, &mut log, genesis());
        head = commit(&core, &mut log, attach("a", "k-a", "none", &head, 2_000));
        commit(&core, &mut log, attach("b", "k-b", "none", &head, 3_000));

        let mut shuffled = vec![log[2].clone(), log[0].clone(), log[1].clone()];
        let chain = core.reconstruct_chain(&shuffled).unwrap();
        assert_eq!(chain, log);

        shuffled.push(attach(
            "orphan",
            "k-orphan",
            "none",
            &format!("sha256:{}", "9".repeat(64)),
            4_000,
        ));
        assert_eq!(
            core.reconstruct_chain(&shuffled).unwrap_err().code(),
            "work_lifecycle_log_orphan_records"
        );
    }

    #[test]
    fn chain_reconstruction_detects_a_fork() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let head = commit(&core, &mut log, genesis());
        let planned_a = core
            .plan_append(&log, &attach("a", "k-a", "none", &head, 2_000))
            .unwrap();
        let planned_b = core
            .plan_append(&log, &attach("b", "k-b", "none", &head, 2_000))
            .unwrap();
        let forked = vec![log[0].clone(), planned_a.record, planned_b.record];
        assert_eq!(
            core.reconstruct_chain(&forked).unwrap_err().code(),
            "work_lifecycle_log_fork_detected"
        );
    }

    #[test]
    fn active_children_project_from_attach_and_detach() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let mut head = commit(&core, &mut log, genesis());
        head = commit(&core, &mut log, attach("a", "k-a", "none", &head, 2_000));
        head = commit(&core, &mut log, attach("b", "k-b", "none", &head, 3_000));

        let mut detach = attach("a", "k-a-detach", "none", &head, 4_000);
        detach["child_reference"]["operation"] = json!("detach");
        commit(&core, &mut log, detach);

        let active = core.project_active_children(&log).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].child_ref, "harness_invocation://b");
    }

    #[test]
    fn projection_matches_the_registered_schema() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let mut head = commit(&core, &mut log, genesis());
        head = commit(
            &core,
            &mut log,
            attach("a", "k-a", "reversible", &head, 2_000),
        );
        commit(
            &core,
            &mut log,
            phase("p1", "k-run", "running", &head, 3_000),
        );

        let projection = core.project(&log).unwrap();
        assert_eq!(projection["active_phase"], json!("running"));
        assert_eq!(projection["record_count"], json!(3));
        assert_eq!(projection["owner_ref"], json!(OWNER));
        assert_eq!(projection["head"], log[2]["resulting_head"]);
        let harness = &projection["active_children"]["harness_invocation"];
        assert_eq!(harness[0]["child_ref"], json!("harness_invocation://a"));
    }

    #[test]
    fn authority_gate_refuses_and_admits() {
        struct DenyRunning;
        impl LegalEdgeGate for DenyRunning {
            fn authorize(&self, _prior: Option<&Value>, candidate: &Value) -> Result<(), String> {
                let to = candidate["phase_transition"]["to_phase"]
                    .as_str()
                    .unwrap_or("");
                if to == "running" {
                    Err("running not permitted by this authority".into())
                } else {
                    Ok(())
                }
            }
        }

        let core = WorkLifecycleLogCore;
        let gate = DenyRunning;
        let mut log = Vec::new();
        // Genesis to `pending` is permitted by the gate.
        let planned = core.plan_append_gated(&log, &genesis(), &gate).unwrap();
        let head = planned.resulting_head.clone();
        log.push(planned.record);

        // The illegal edge to `running` is refused at the single bounding site.
        let err = core
            .plan_append_gated(&log, &phase("p1", "k-run", "running", &head, 2_000), &gate)
            .unwrap_err();
        assert_eq!(err.code(), "work_lifecycle_log_authority_refused");

        // A permitted edge still commits.
        let ok = core
            .plan_append_gated(
                &log,
                &phase("p2", "k-wait", "waiting_for_input", &head, 2_000),
                &gate,
            )
            .unwrap();
        assert_eq!(ok.outcome, AppendOutcome::Appended);
    }

    #[test]
    fn resume_plus_tail_equals_full_replay() {
        let core = WorkLifecycleLogCore;
        let mut full = Vec::new();
        let mut head = commit(&core, &mut full, genesis());
        head = commit(
            &core,
            &mut full,
            attach("a", "k-a", "reversible", &head, 2_000),
        );
        head = commit(
            &core,
            &mut full,
            phase("p1", "k-run", "running", &head, 3_000),
        );
        head = commit(&core, &mut full, attach("b", "k-b", "none", &head, 4_000));
        let _ = head;

        let full_projection = core.project(&full).unwrap();

        // Compact the first two records into an archive + snapshot.
        let prefix = full[..2].to_vec();
        let prefix_head = prefix[1]["resulting_head"].as_str().unwrap().to_string();
        let segment = core
            .plan_archive_segment(
                "work-lifecycle-archive://run-1/seg-1",
                &prefix,
                &prefix_head,
                10,
            )
            .unwrap();
        let snapshot = core
            .plan_snapshot("work-lifecycle-snapshot://run-1/snap-1", &segment, 11)
            .unwrap();

        // Resume from the snapshot and apply the remaining tail.
        let tail = full[2..].to_vec();
        let resumed = core.resume_and_project(&snapshot, &tail).unwrap();

        assert_eq!(resumed.projection, full_projection);

        // Idempotency decisions survive the compaction boundary.
        let full_state = core
            .fold_state(&core.reconstruct_chain(&full).unwrap())
            .unwrap();
        assert_eq!(resumed.idempotency_record_hashes, full_state.idempotency);
        assert!(resumed.idempotency_record_hashes.contains_key("genesis-1"));
        assert!(resumed.idempotency_record_hashes.contains_key("k-a"));
    }

    #[test]
    fn archive_root_binds_records_and_snapshot_binds_root() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let mut head = commit(&core, &mut log, genesis());
        head = commit(&core, &mut log, attach("a", "k-a", "none", &head, 2_000));

        let segment = core
            .plan_archive_segment("work-lifecycle-archive://run-1/seg-1", &log, &head, 10)
            .unwrap();
        assert!(segment["archive_root"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));

        let snapshot = core
            .plan_snapshot("work-lifecycle-snapshot://run-1/snap-1", &segment, 11)
            .unwrap();
        assert_eq!(snapshot["archive_root"], segment["archive_root"]);
        assert_eq!(snapshot["through_head"], json!(head));

        // A tampered archive root is refused by the snapshot binding.
        let mut tampered = segment.clone();
        tampered["archive_root"] = json!(format!("sha256:{}", "a".repeat(64)));
        let err = core
            .plan_snapshot("work-lifecycle-snapshot://run-1/snap-2", &tampered, 12)
            .unwrap_err();
        assert_eq!(err.code(), "work_lifecycle_snapshot_archive_root_mismatch");
    }

    #[test]
    fn resume_refuses_a_tail_that_does_not_chain() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let head = commit(&core, &mut log, genesis());
        let segment = core
            .plan_archive_segment("work-lifecycle-archive://run-1/seg-1", &log, &head, 10)
            .unwrap();
        let snapshot = core
            .plan_snapshot("work-lifecycle-snapshot://run-1/snap-1", &segment, 11)
            .unwrap();

        let orphan_head = format!("sha256:{}", "7".repeat(64));
        let tail = vec![attach("x", "k-x", "none", &orphan_head, 5_000)];
        let err = core.resume_and_project(&snapshot, &tail).unwrap_err();
        assert_eq!(err.code(), "work_lifecycle_resume_tail_gap");
    }

    #[test]
    fn fanout_refuses_compensatable_child_without_policy() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let head = commit(&core, &mut log, genesis());
        let head = commit(
            &core,
            &mut log,
            attach("a", "k-a", "compensatable", &head, 2_000),
        );

        let intent = CancellationIntent {
            requested_by_ref: "actor://owner".into(),
            reason: "stop".into(),
            ..Default::default()
        };
        let err = core
            .plan_cancellation_fanout(OBJECT, &head, &log, &intent)
            .unwrap_err();
        assert_eq!(
            err.code(),
            "work_lifecycle_cancellation_compensation_policy_required"
        );
    }

    #[test]
    fn fanout_refuses_ambiguous_child_without_reconciliation_policy() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let head = commit(&core, &mut log, genesis());
        let head = commit(
            &core,
            &mut log,
            attach("a", "k-a", "ambiguous", &head, 2_000),
        );

        let intent = CancellationIntent {
            requested_by_ref: "actor://owner".into(),
            reason: "stop".into(),
            ..Default::default()
        };
        let err = core
            .plan_cancellation_fanout(OBJECT, &head, &log, &intent)
            .unwrap_err();
        assert_eq!(
            err.code(),
            "work_lifecycle_cancellation_reconciliation_policy_required"
        );
    }

    #[test]
    fn fanout_emits_a_schema_valid_plan_and_never_claims_completion() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let head = commit(&core, &mut log, genesis());
        let head = commit(
            &core,
            &mut log,
            attach("a", "k-a", "irreversible", &head, 2_000),
        );

        let intent = CancellationIntent {
            requested_by_ref: "actor://owner".into(),
            reason: "stop".into(),
            effect_reconciliation_policy_ref: Some("policy://reconcile".into()),
            ..Default::default()
        };
        let plan = core
            .plan_cancellation_fanout(OBJECT, &head, &log, &intent)
            .unwrap();

        assert_eq!(plan["requires_completion_receipt"], json!(true));
        let target = &plan["targets"][0];
        let actions: Vec<&str> = target["actions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        assert!(actions.contains(&"fence"));
        assert!(actions.contains(&"reconcile_irreversible_effect"));
        assert!(actions.contains(&"preserve_receipt_lineage"));
        assert!(!plan.to_string().contains("succeeded"));
        assert!(!plan.to_string().contains("completed"));
    }
}
