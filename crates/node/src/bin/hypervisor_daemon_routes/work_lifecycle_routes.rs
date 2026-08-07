//! WorkLifecycle record store and routes.
//!
//! I/O only. Every mechanic — content commitment, exact-head compare-and-swap,
//! object-scoped idempotency, chain reconstruction, active-child projection,
//! and cancellation planning — belongs to
//! `runtime_work_lifecycle_log::WorkLifecycleLogCore` in the kernel. This module
//! loads an object's records, hands them to the core, and persists what the
//! core admits. It makes no admission decision of its own (ADR 0034
//! sub-ruling 1).

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
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
