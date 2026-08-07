//! WorkLifecycle record store and routes.
//!
//! I/O only. Every mechanic — content commitment, exact-head compare-and-swap,
//! object-scoped idempotency, chain reconstruction, active-child projection,
//! and cancellation planning — belongs to
//! `runtime_work_lifecycle_log::WorkLifecycleLogCore` in the kernel. This module
//! loads an object's records, hands them to the core, and persists what the
//! core admits. It makes no admission decision of its own (ADR 0034
//! sub-ruling 1).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use ioi_services::agentic::runtime::kernel::runtime_work_lifecycle_admission::{
    WorkLifecycleAdmissionCore, WorkLifecycleAdmissionRequest, WorkOwningNodeState,
    RUNTIME_WORK_LIFECYCLE_ADMISSION_REQUEST_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::runtime_work_lifecycle_log::{
    AppendOutcome, CancellationIntent, WorkLifecycleLogCore,
};
use serde_json::{json, Value};

use super::{persist_record, read_record_dir, AppError, DaemonState};

/// Record family. Hyphenated to match the existing family convention.
pub(crate) const WORK_LIFECYCLE_FAMILY: &str = "work-lifecycle";

fn bad_request(message: impl Into<String>) -> AppError {
    AppError(StatusCode::BAD_REQUEST, message.into())
}

/// Load one object's records in append order, reconstructed from storage.
///
/// Storage order is not trusted; the kernel walks the head chain and fails
/// closed on fork, gap, orphan, duplicate genesis, or a tampered hash.
pub(crate) fn load_chain(data_dir: &str, object_ref: &str) -> Result<Vec<Value>, AppError> {
    let stored: Vec<Value> = read_record_dir(data_dir, WORK_LIFECYCLE_FAMILY)
        .into_iter()
        .filter(|record| record.get("object_ref").and_then(Value::as_str) == Some(object_ref))
        .collect();

    WorkLifecycleLogCore
        .reconstruct_chain(&stored)
        .map_err(|error| {
            AppError(
                StatusCode::CONFLICT,
                format!("{}: {}", error.code(), error.message()),
            )
        })
}

/// Append one record under the kernel's admission, then persist it.
///
/// The write happens only after the core admits. A refusal never writes.
pub(crate) fn append_record(data_dir: &str, candidate: &Value) -> Result<Value, AppError> {
    let object_ref = candidate
        .get("object_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| bad_request("record requires object_ref"))?;

    let chain = load_chain(data_dir, object_ref)?;

    let planned = WorkLifecycleLogCore
        .plan_append(&chain, candidate)
        .map_err(|error| {
            let status = match error.code() {
                "work_lifecycle_log_head_mismatch"
                | "work_lifecycle_log_duplicate_genesis"
                | "work_lifecycle_log_idempotency_conflict"
                | "work_lifecycle_log_invalid_stored_hash" => StatusCode::CONFLICT,
                _ => StatusCode::BAD_REQUEST,
            };
            AppError(status, format!("{}: {}", error.code(), error.message()))
        })?;

    // A replay is already durable; re-persisting would rewrite identical bytes
    // under the same key for no gain.
    if planned.outcome == AppendOutcome::Appended {
        let record_id = planned
            .record
            .get("record_id")
            .and_then(Value::as_str)
            .ok_or_else(|| bad_request("record requires record_id"))?;
        let storage_key = storage_key_for(record_id);
        persist_record(
            data_dir,
            WORK_LIFECYCLE_FAMILY,
            &storage_key,
            &planned.record,
        )
        .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    }

    Ok(planned.record)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or_default()
}

/// Ensure an object has a genesis record, returning its current head.
///
/// A caller re-homing onto the graph does not need history backfilled: the
/// first delegation admits the parent as a root at its initial phase.
pub(crate) fn ensure_genesis(
    data_dir: &str,
    object_ref: &str,
    object_kind: &str,
    initial_phase: &str,
) -> Result<String, AppError> {
    let chain = load_chain(data_dir, object_ref)?;
    if let Some(head) = chain
        .last()
        .and_then(|record| record.get("resulting_head"))
        .and_then(Value::as_str)
    {
        return Ok(head.to_string());
    }

    let genesis = json!({
        "schema_version": "ioi.work-lifecycle-record.v1",
        "record_id": format!("work-lifecycle://{}/genesis", storage_key_for(object_ref)),
        "record_hash": "",
        "record_type": "phase_transition",
        "object_kind": object_kind,
        "object_ref": object_ref,
        "expected_head": Value::Null,
        "resulting_head": "",
        "idempotency_key": "genesis",
        "authority_class": "daemon",
        "authority_ref": "actor://daemon",
        "evidence_refs": [],
        "receipt_refs": [],
        "phase_transition": {
            "from_phase": Value::Null,
            "to_phase": initial_phase,
            "delegation_bounds": bounds_payload(
                0,
                ROOT_MAX_DEPTH,
                ROOT_MAX_CONCURRENT_CHILDREN,
                ROOT_DESCENDANT_BUDGET,
            ),
        },
        "child_reference": Value::Null,
        "occurred_at_ms": now_ms(),
    });

    let record = append_record(data_dir, &genesis)?;
    record
        .get("resulting_head")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| bad_request("genesis produced no head"))
}

/// Root delegation ceilings applied when an object is admitted as a root.
///
/// These are the substrate's default bounds. A child never widens them; it
/// inherits them narrowed (INV-35).
const ROOT_MAX_DEPTH: u8 = 3;
const ROOT_MAX_CONCURRENT_CHILDREN: u32 = 8;
const ROOT_DESCENDANT_BUDGET: u32 = 32;

/// Delegation bounds are carried in the genesis `phase_transition` payload,
/// which canon leaves as an open object.
fn bounds_payload(
    depth: u8,
    max_depth: u8,
    max_concurrent_children: u32,
    remaining_descendant_budget: u32,
) -> Value {
    json!({
        "depth": depth,
        "max_depth": max_depth,
        "max_concurrent_children": max_concurrent_children,
        "remaining_descendant_budget": remaining_descendant_budget,
    })
}

/// Materialize the admission-core node state for one object from its chain.
fn node_state_from_chain(
    object_ref: &str,
    chain: &[Value],
) -> Result<WorkOwningNodeState, AppError> {
    let head = chain
        .last()
        .and_then(|record| record.get("resulting_head"))
        .and_then(Value::as_str)
        .ok_or_else(|| bad_request("object has no admitted head"))?
        .to_string();

    let bounds = chain
        .first()
        .and_then(|record| record.get("phase_transition"))
        .and_then(|phase| phase.get("delegation_bounds"))
        .cloned()
        .unwrap_or_else(|| {
            bounds_payload(
                0,
                ROOT_MAX_DEPTH,
                ROOT_MAX_CONCURRENT_CHILDREN,
                ROOT_DESCENDANT_BUDGET,
            )
        });

    let read_u64 =
        |key: &str, fallback: u64| bounds.get(key).and_then(Value::as_u64).unwrap_or(fallback);

    let active = WorkLifecycleLogCore
        .project_active_children(chain)
        .map_err(|error| bad_request(format!("{}: {}", error.code(), error.message())))?;
    let active_children = active.len() as u32;

    Ok(WorkOwningNodeState {
        node_id: object_ref.to_string(),
        root_id: object_ref.to_string(),
        parent_id: None,
        state_head: head,
        depth: read_u64("depth", 0) as u8,
        max_depth: read_u64("max_depth", u64::from(ROOT_MAX_DEPTH)) as u8,
        can_delegate: true,
        remaining_descendant_budget: Some(
            read_u64(
                "remaining_descendant_budget",
                u64::from(ROOT_DESCENDANT_BUDGET),
            )
            .saturating_sub(u64::from(active_children)) as u32,
        ),
        children_admitted: active_children,
        active_children,
        max_concurrent_children: Some(read_u64(
            "max_concurrent_children",
            u64::from(ROOT_MAX_CONCURRENT_CHILDREN),
        ) as u32),
        deadline_unix_s: None,
        authority_scope_refs: BTreeSet::new(),
        context_visibility_refs: BTreeSet::new(),
        capacity: BTreeMap::new(),
        reserved: BTreeMap::new(),
        protected: BTreeMap::new(),
        terminal: false,
        fenced: false,
    })
}

/// Admit one work-owning delegation edge from `parent_object_ref` to
/// `child_ref`, appending a `child_reference` attach under kernel admission.
///
/// Two kernels run, in order: the admission core validates every applicable
/// ancestor limit (depth, fanout, descendant budget, monotonic narrowing) and
/// the log core enforces exact-head CAS and idempotency. A refusal from either
/// writes nothing.
///
/// Callers invoke this **before** creating the child object, so a refused
/// delegation leaves no domain records behind (ADR 0034 sub-ruling 5).
#[allow(clippy::too_many_arguments)]
pub(crate) fn admit_delegation_edge(
    data_dir: &str,
    parent_object_ref: &str,
    parent_object_kind: &str,
    parent_initial_phase: &str,
    relation_kind: &str,
    child_ref: &str,
    effect_recovery_class: &str,
) -> Result<Value, AppError> {
    let head = ensure_genesis(
        data_dir,
        parent_object_ref,
        parent_object_kind,
        parent_initial_phase,
    )?;

    let parent_chain = load_chain(data_dir, parent_object_ref)?;

    // An already-attached child is a semantic no-op. Returning early keeps a
    // retry from consuming a second unit of fanout or descendant budget, and
    // avoids a byte-level idempotency conflict from the differing timestamp
    // that a re-issued attach would carry.
    let already_active = WorkLifecycleLogCore
        .project_active_children(&parent_chain)
        .map_err(|error| bad_request(format!("{}: {}", error.code(), error.message())))?
        .into_iter()
        .any(|child| child.child_ref == child_ref);
    if already_active {
        return Ok(json!({
            "object_ref": parent_object_ref,
            "child_ref": child_ref,
            "outcome": "already_attached",
        }));
    }

    // Bound the delegation before anything is written.
    let parent_state = node_state_from_chain(parent_object_ref, &parent_chain)?;
    let admission_request: WorkLifecycleAdmissionRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_WORK_LIFECYCLE_ADMISSION_REQUEST_SCHEMA_VERSION,
        "operation_kind": "work.admit_child",
        "parent_node_id": parent_object_ref,
        "expected_parent_head": head,
        "child_node_id": child_ref,
    }))
    .map_err(|error| bad_request(error.to_string()))?;

    let admitted = WorkLifecycleAdmissionCore
        .admit_child(&parent_state, &[], &admission_request)
        .map_err(|error| {
            AppError(
                StatusCode::CONFLICT,
                format!("{}: {}", error.code(), error.message()),
            )
        })?;

    let attach = json!({
        "schema_version": "ioi.work-lifecycle-record.v1",
        "record_id": format!(
            "work-lifecycle://{}/attach-{}",
            storage_key_for(parent_object_ref),
            storage_key_for(child_ref)
        ),
        "record_hash": "",
        "record_type": "child_reference",
        "object_kind": parent_object_kind,
        "object_ref": parent_object_ref,
        "expected_head": head,
        "resulting_head": "",
        "idempotency_key": format!("attach:{child_ref}"),
        "authority_class": "daemon",
        "authority_ref": "actor://daemon",
        "evidence_refs": [],
        "receipt_refs": [],
        "phase_transition": Value::Null,
        "child_reference": {
            "operation": "attach",
            "relation_kind": relation_kind,
            "child_ref": child_ref,
            "effect_recovery_class": effect_recovery_class,
        },
        "occurred_at_ms": now_ms(),
    });

    let attached = append_record(data_dir, &attach)?;

    // The child is admitted as its own root carrying NARROWED bounds, so depth
    // accumulates across generations and a grandchild is bounded by its
    // grandparent's ceiling rather than starting fresh.
    let child_genesis = json!({
        "schema_version": "ioi.work-lifecycle-record.v1",
        "record_id": format!("work-lifecycle://{}/genesis", storage_key_for(child_ref)),
        "record_hash": "",
        "record_type": "phase_transition",
        "object_kind": parent_object_kind,
        "object_ref": child_ref,
        "expected_head": Value::Null,
        "resulting_head": "",
        "idempotency_key": "genesis",
        "authority_class": "daemon",
        "authority_ref": "actor://daemon",
        "evidence_refs": [],
        "receipt_refs": [],
        "phase_transition": {
            "from_phase": Value::Null,
            "to_phase": parent_initial_phase,
            "delegation_bounds": bounds_payload(
                admitted.child.depth,
                admitted.child.max_depth,
                admitted.child.max_concurrent_children.unwrap_or(0),
                admitted.child.remaining_descendant_budget.unwrap_or(0),
            ),
        },
        "child_reference": Value::Null,
        "occurred_at_ms": now_ms(),
    });
    append_record(data_dir, &child_genesis)?;

    Ok(attached)
}

/// Active typed children of one object, read from the graph rather than by
/// scanning child records for a parent field.
pub(crate) fn active_children_of(
    data_dir: &str,
    object_ref: &str,
) -> Result<Vec<(String, String)>, AppError> {
    let chain = load_chain(data_dir, object_ref)?;
    let active = WorkLifecycleLogCore
        .project_active_children(&chain)
        .map_err(|error| bad_request(format!("{}: {}", error.code(), error.message())))?;
    Ok(active
        .into_iter()
        .map(|child| (child.relation_kind, child.child_ref))
        .collect())
}

/// `work-lifecycle://object/1` is not a filesystem-safe key; the durable writer
/// refuses ids that would normalize. Flatten to a single safe component.
fn storage_key_for(record_id: &str) -> String {
    record_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// `POST /v1/work-lifecycle/records`
pub(crate) async fn handle_record_append(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let record = append_record(st.data_dir.as_str(), &body)?;
    Ok((StatusCode::CREATED, Json(record)))
}

/// `GET /v1/work-lifecycle/objects/:object_ref`
///
/// Current head plus the projected active typed children. Read-only.
pub(crate) async fn handle_object_projection(
    State(st): State<Arc<DaemonState>>,
    AxumPath(object_ref): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let chain = load_chain(st.data_dir.as_str(), &object_ref)?;
    let head = chain
        .last()
        .and_then(|record| record.get("resulting_head"))
        .cloned()
        .unwrap_or(Value::Null);

    let active = WorkLifecycleLogCore
        .project_active_children(&chain)
        .map_err(|error| bad_request(format!("{}: {}", error.code(), error.message())))?;

    Ok(Json(json!({
        "object_ref": object_ref,
        "head": head,
        "record_count": chain.len(),
        "active_children": active
            .into_iter()
            .map(|child| json!({
                "relation_kind": child.relation_kind,
                "child_ref": child.child_ref,
                "effect_recovery_class": child.effect_recovery_class,
            }))
            .collect::<Vec<Value>>(),
    })))
}

/// `POST /v1/work-lifecycle/cancellation-plans`
///
/// Derives the plan. It does not execute it, and it never claims child
/// completion; each child owner executes and receipts its own cancellation.
pub(crate) async fn handle_cancellation_plan(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let object_ref = body
        .get("object_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| bad_request("cancellation plan requires object_ref"))?;

    let chain = load_chain(st.data_dir.as_str(), object_ref)?;
    let source_head = chain
        .last()
        .and_then(|record| record.get("resulting_head"))
        .and_then(Value::as_str)
        .ok_or_else(|| bad_request("object has no admitted head"))?
        .to_string();

    let intent = CancellationIntent {
        requested_by_ref: body
            .get("requested_by_ref")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        reason: body
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        compensation_policy_ref: body
            .get("compensation_policy_ref")
            .and_then(Value::as_str)
            .map(str::to_string),
        effect_reconciliation_policy_ref: body
            .get("effect_reconciliation_policy_ref")
            .and_then(Value::as_str)
            .map(str::to_string),
        timeout_at_ms: body.get("timeout_at_ms").and_then(Value::as_i64),
    };

    let plan = WorkLifecycleLogCore
        .plan_cancellation_fanout(object_ref, &source_head, &chain, &intent)
        .map_err(|error| bad_request(format!("{}: {}", error.code(), error.message())))?;

    Ok(Json(plan))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis(object_ref: &str) -> Value {
        json!({
            "schema_version": "ioi.work-lifecycle-record.v1",
            "record_id": "work-lifecycle://run-1/0",
            "record_hash": "",
            "record_type": "phase_transition",
            "object_kind": "work_run",
            "object_ref": object_ref,
            "expected_head": Value::Null,
            "resulting_head": "",
            "idempotency_key": "genesis",
            "authority_class": "daemon",
            "authority_ref": "actor://daemon",
            "evidence_refs": [],
            "receipt_refs": [],
            "phase_transition": { "from_phase": Value::Null, "to_phase": "pending" },
            "child_reference": Value::Null,
            "occurred_at_ms": 1_000,
        })
    }

    #[test]
    fn storage_key_is_filesystem_safe() {
        assert_eq!(
            storage_key_for("work-lifecycle://run-1/0"),
            "work-lifecycle___run-1_0"
        );
        assert!(!storage_key_for("work-lifecycle://a/../b").contains('/'));
        assert!(!storage_key_for("work-lifecycle://a/../b").contains('.'));
    }

    /// `AppError` has no `Debug`, so surface its message for assertions.
    fn flatten<T>(result: Result<T, AppError>) -> Result<T, String> {
        result.map_err(|AppError(status, message)| format!("{status}: {message}"))
    }

    fn temp_dir(tag: &str) -> (std::path::PathBuf, String) {
        let dir = std::env::temp_dir().join(format!("wl-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp data dir");
        let data_dir = dir.to_string_lossy().to_string();
        (dir, data_dir)
    }

    fn admit(data_dir: &str, parent: &str, child: &str) -> Result<Value, String> {
        flatten(admit_delegation_edge(
            data_dir,
            parent,
            "work_run",
            "running",
            "work_run",
            child,
            "compensatable",
        ))
    }

    #[test]
    fn fanout_ceiling_refuses_structurally() {
        let (dir, data_dir) = temp_dir("fanout");
        let parent = "work_run://parent";

        // The root ceiling is ROOT_MAX_CONCURRENT_CHILDREN.
        for index in 0..ROOT_MAX_CONCURRENT_CHILDREN {
            admit(&data_dir, parent, &format!("work_run://child-{index}"))
                .unwrap_or_else(|error| panic!("child {index} should be admitted: {error}"));
        }

        let refused = admit(&data_dir, parent, "work_run://one-too-many");
        let message = refused.expect_err("the ceiling must refuse");
        assert!(
            message.contains("concurrency_exceeded"),
            "expected a concurrency refusal, got: {message}"
        );

        // The refusal is structural: no edge was recorded for the refused child.
        let children = flatten(active_children_of(&data_dir, parent)).expect("children");
        assert_eq!(children.len() as u32, ROOT_MAX_CONCURRENT_CHILDREN);
        assert!(children
            .iter()
            .all(|(_, child_ref)| child_ref != "work_run://one-too-many"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn depth_accumulates_across_generations_and_bottoms_out() {
        let (dir, data_dir) = temp_dir("depth");

        // Each generation narrows from its parent, so depth is bounded across
        // the chain rather than resetting at every hop.
        let mut current = "work_run://gen-0".to_string();
        for generation in 1..=ROOT_MAX_DEPTH {
            let next = format!("work_run://gen-{generation}");
            admit(&data_dir, &current, &next)
                .unwrap_or_else(|error| panic!("generation {generation}: {error}"));
            current = next;
        }

        // One generation past the ceiling is refused.
        let refused = admit(
            &data_dir,
            &current,
            &format!("work_run://gen-{}", ROOT_MAX_DEPTH + 1),
        );
        let message = refused.expect_err("depth ceiling must refuse");
        assert!(
            message.contains("depth_exceeded") || message.contains("max_depth"),
            "expected a depth refusal, got: {message}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn readmitting_the_same_child_is_idempotent_not_a_second_edge() {
        let (dir, data_dir) = temp_dir("idempotent");
        let parent = "work_run://parent";

        admit(&data_dir, parent, "work_run://child").expect("first admission");
        admit(&data_dir, parent, "work_run://child").expect("replay admits idempotently");

        let children = flatten(active_children_of(&data_dir, parent)).expect("children");
        assert_eq!(children.len(), 1, "a replay must not create a second edge");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_persists_then_reloads_as_a_chain() {
        let dir = std::env::temp_dir().join(format!(
            "wl-{}-{}",
            std::process::id(),
            "append-reload-chain"
        ));
        let data_dir = dir.to_string_lossy().to_string();
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp data dir");

        let object_ref = "work_run://run-1";
        let record = flatten(append_record(&data_dir, &genesis(object_ref))).expect("genesis");
        let head = record["resulting_head"].as_str().expect("head").to_string();
        assert!(head.starts_with("sha256:"));

        let chain = flatten(load_chain(&data_dir, object_ref)).expect("chain");
        assert_eq!(chain.len(), 1);
        // The persisted record is the admitted one, head included.
        assert_eq!(chain[0]["resulting_head"].as_str(), Some(head.as_str()));

        // A second genesis on the same object fails closed and writes nothing.
        let mut second = genesis(object_ref);
        second["idempotency_key"] = json!("genesis-2");
        second["record_id"] = json!("work-lifecycle://run-1/0b");
        let refused = flatten(append_record(&data_dir, &second));
        assert!(refused.is_err(), "second genesis must be refused");
        assert_eq!(
            flatten(load_chain(&data_dir, object_ref))
                .expect("chain after refusal")
                .len(),
            1,
            "a refused append must not write"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
