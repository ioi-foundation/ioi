//! Shared WorkLifecycle append-only log mechanics.
//!
//! Implements `WorkLifecycleRecordEnvelope` and `CancellationFanoutPlanEnvelope`
//! exactly as specified in
//! `docs/architecture/foundations/objects/work-results-and-lifecycle.md`:
//! content commitment, exact-head compare-and-swap, object-scoped idempotency,
//! append-only child references, active-child projection, and deterministic
//! cancellation planning.
//!
//! This layer owns mechanics only. It does not own GoalRun, GoalGroundingLoop,
//! WorkRun, AutomationRun, HarnessInvocation, ContextCell, or external-handle
//! state, and it does not flatten their phases into a universal lifecycle
//! (INV-35). Kind-specific legal-edge tables stay with their owners.
//!
//! Records are round-tripped through the generated projection
//! `WorkLifecycleRecordV1`, whose `Deserialize` validates against the registered
//! schema. A non-conforming record therefore cannot leave this module.

use std::collections::BTreeMap;

use ioi_types::app::generated::architecture_contracts::{
    CancellationFanoutPlanV1, WorkLifecycleRecordV1,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const WORK_LIFECYCLE_RECORD_SCHEMA_VERSION: &str = "ioi.work-lifecycle-record.v1";
pub const CANCELLATION_FANOUT_PLAN_SCHEMA_VERSION: &str = "ioi.cancellation-fanout-plan.v1";

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
        let canonical = canonical_json(&Value::Object(committed));
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        Ok(format!("sha256:{:x}", hasher.finalize()))
    }

    /// Append one record under exact-head compare-and-swap and object-scoped
    /// idempotency.
    ///
    /// `log` is the existing record sequence for one object, in append order.
    /// Fails closed on duplicate genesis, fork, gap, orphan, invalid hash,
    /// regressed timestamp, or a changed-bytes idempotency collision.
    pub fn plan_append(
        &self,
        log: &[Value],
        candidate: &Value,
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
    /// genesis, a fork (two records claiming the same predecessor), or an
    /// orphan/gap (records that no chain walk reaches).
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

        let mut chain = vec![genesis.clone()];
        let mut head = self.stored_head(genesis)?;
        while let Some(next) = by_predecessor.remove(&head) {
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
        Ok(active.into_values().collect())
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

    fn genesis() -> Value {
        json!({
            "schema_version": WORK_LIFECYCLE_RECORD_SCHEMA_VERSION,
            "record_id": "work-lifecycle://run-1/0",
            "record_hash": "",
            "record_type": "phase_transition",
            "object_kind": "work_run",
            "object_ref": OBJECT,
            "expected_head": Value::Null,
            "resulting_head": "",
            "idempotency_key": "genesis-1",
            "authority_class": "daemon",
            "authority_ref": "actor://daemon",
            "evidence_refs": [],
            "receipt_refs": [],
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
            "expected_head": head,
            "resulting_head": "",
            "idempotency_key": key,
            "authority_class": "daemon",
            "authority_ref": "actor://daemon",
            "evidence_refs": [],
            "receipt_refs": [],
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
        // Second writer still believes the genesis head is current.
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
        // Tamper with a committed field; the head no longer matches.
        log[0]["occurred_at_ms"] = json!(9_999);
        let err = core
            .plan_append(&log, &attach("a", "k-a", "none", &head, 2_000))
            .unwrap_err();
        assert_eq!(err.code(), "work_lifecycle_log_invalid_stored_hash");
    }

    #[test]
    fn chain_reconstructs_from_unordered_storage() {
        let core = WorkLifecycleLogCore;
        let mut log = Vec::new();
        let mut head = commit(&core, &mut log, genesis());
        head = commit(&core, &mut log, attach("a", "k-a", "none", &head, 2_000));
        commit(&core, &mut log, attach("b", "k-b", "none", &head, 3_000));

        // Storage order is not append order.
        let mut shuffled = vec![log[2].clone(), log[0].clone(), log[1].clone()];
        let chain = core.reconstruct_chain(&shuffled).unwrap();
        assert_eq!(chain, log);

        // An orphan that no walk reaches fails closed rather than being dropped.
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
        // Two records claiming the same predecessor: a fork in storage.
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
        // The plan carries no completion or success claim for any child.
        assert!(!plan.to_string().contains("succeeded"));
        assert!(!plan.to_string().contains("completed"));
    }
}
