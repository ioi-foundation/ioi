//! TransformationRun + receipts — the THIRD ODK authority-crossing rung, and the first that says
//! "a run may exist". In v1 a run is an AUDITABLE PLAN / DRY-RUN ONLY: it validates the declared
//! source shape, the mapped ontology properties, the policy envelope, the requested operation, the
//! output intent, and the receipt obligations — and emits receipts for every act. It does NOT say
//! "the system can pull from Postgres/S3/API and mint semantic objects": there is no live source
//! contact, no extraction, no object instances, no explorer rows, no connector credentials. Live
//! reads are a FUTURE connector-adapter cut, after credentials get an authority-crossing story.
//!
//! A run references one READY ConnectorMapping (#13) and one READY PolicyBoundDataView (#14) that
//! binds the SAME mapping and allows `transform`. Requested fields must sit inside the policy scope;
//! the purpose must match the policy purpose; a high-risk output intent (export/train/evaluate
//! bundles) is admitted only when the view authorizes that downstream operation with named receipt
//! obligations. Authorization is CHECKED against the gate — never invented here.
//!
//! Lifecycle (explicit): `planned` → `dry_run_ready` | `blocked` | `cancelled`.
//! `executed` / `materialized` are RESERVED for the future connector-adapter cut and never set here.
//! Every create, dry-run, block, cancel, patch — and every FAILED validation — emits a receipt.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const RUN_SCHEMA: &str = "ioi.hypervisor.odk.transformation-run.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.odk.transformation-run-receipt.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.odk.transformation-runs-overview.v1";
pub(crate) const RECORD_DIR: &str = "odk-transformation-runs";
const RECEIPT_DIR: &str = "odk-transformation-run-receipts";

/// v1 lifecycle. `executed`/`materialized` are reserved for a future connector-adapter cut.
const LIFECYCLE_STATES: &[&str] = &["planned", "dry_run_ready", "blocked", "cancelled"];
const RESERVED_STATES: &[&str] = &["executed", "materialized"];
/// Declared output intents a plan may target. Nothing is produced here — intent only.
const OUTPUT_INTENTS: &[&str] = &[
    "ontology_objects",
    "projection",
    "evaluation_dataset",
    "training_material",
    "export_bundle",
];
/// The downstream policy operation a high-risk intent requires the view to authorize.
fn intent_downstream_op(intent: &str) -> Option<&'static str> {
    match intent {
        "evaluation_dataset" => Some("evaluate"),
        "training_material" => Some("train"),
        "export_bundle" => Some("export"),
        _ => None,
    }
}
/// The still-missing contract downstream of this rung.
const MISSING_CONTRACTS: &[&str] = &["OntologyProjection"];
/// Body keys that would be a plaintext secret — rejected outright.
const PLAINTEXT_SECRET_KEYS: &[&str] = &[
    "secret",
    "password",
    "api_key",
    "apikey",
    "token",
    "credential",
];
/// Body keys that would smuggle a raw source query into a plan — rejected outright.
const RAW_QUERY_KEYS: &[&str] = &["query", "sql", "raw_query", "statement", "command"];

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn s(v: &Value, k: &str, d: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string()
}
fn opt_s(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
}
fn str_list(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
type VErr = (String, String);
fn verr(code: &str, msg: String) -> VErr {
    (code.to_string(), msg)
}

fn load_mapping(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, crate::connector_mapping_routes::RECORD_DIR)
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
}
fn load_view(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, crate::policy_bound_data_view_routes::RECORD_DIR)
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
}
fn load_run(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, RECORD_DIR)
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
}
fn health_status(rec: &Value) -> String {
    rec.pointer("/health/status")
        .and_then(|v| v.as_str())
        .unwrap_or("incomplete")
        .to_string()
}
fn view_scope(view: &Value) -> Vec<String> {
    view.get("property_scope")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
/// Find the mapping binding (source_field, source_type) for a property id, across key/title/fields.
fn mapping_binding(mapping: &Value, property_id: &str) -> Option<(String, String)> {
    let pick = |m: &Value| -> Option<(String, String)> {
        if m.get("property_id").and_then(|v| v.as_str()) == Some(property_id) {
            Some((s(m, "source_field", ""), s(m, "source_type", "string")))
        } else {
            None
        }
    };
    for k in ["key_mapping", "title_mapping"] {
        if let Some(found) = mapping.get(k).and_then(|m| pick(m)) {
            return Some(found);
        }
    }
    mapping
        .get("field_mappings")?
        .as_array()?
        .iter()
        .find_map(pick)
}

/// The validated inputs a run needs, resolved from the current daemon state.
struct RunInputs {
    mapping: Value,
    view: Value,
    requested_fields: Vec<String>,
    purpose: String,
    output_intent: String,
}

/// Validate a run body fail-closed against CURRENT mapping/view state. Used at create, patch, and
/// dry-run — the same gate every time, never a cached approval. NO source contact anywhere.
fn validate_inputs(data_dir: &str, body: &Value) -> Result<RunInputs, VErr> {
    if let Some(obj) = body.as_object() {
        if PLAINTEXT_SECRET_KEYS
            .iter()
            .any(|k| obj.contains_key(*k) && !obj[*k].is_null())
        {
            return Err(verr("transformation_run_plaintext_secret_rejected", "A run plan never carries credentials — credential crossing is a future connector-adapter cut.".into()));
        }
        if RAW_QUERY_KEYS
            .iter()
            .any(|k| obj.contains_key(*k) && !obj[*k].is_null())
        {
            return Err(verr("transformation_run_raw_query_rejected", "A run plan never carries a raw source query — extraction semantics live behind the declared mapping, not ad-hoc query bodies.".into()));
        }
    }
    if opt_s(body, "name").is_none() {
        return Err(verr(
            "transformation_run_name_required",
            "A transformation run requires a name.".into(),
        ));
    }
    // Ready mapping.
    let mapping_id = opt_s(body, "connector_mapping_id").unwrap_or_default();
    let mapping = load_mapping(data_dir, &mapping_id).ok_or_else(|| {
        verr(
            "transformation_run_mapping_unknown",
            format!("connector_mapping_id '{mapping_id}' does not resolve to a declared mapping"),
        )
    })?;
    if health_status(&mapping) != "ready" {
        return Err(verr(
            "transformation_run_mapping_not_ready",
            format!("mapping '{mapping_id}' is not ready — a run plans only over validated shape"),
        ));
    }
    // Ready view, binding the SAME mapping, allowing transform.
    let view_id = opt_s(body, "policy_view_id").unwrap_or_default();
    let view = load_view(data_dir, &view_id).ok_or_else(|| {
        verr(
            "transformation_run_policy_view_unknown",
            format!(
                "policy_view_id '{view_id}' does not resolve to a declared policy-bound data view"
            ),
        )
    })?;
    if health_status(&view) != "ready" {
        return Err(verr("transformation_run_policy_view_not_ready", format!("policy view '{view_id}' is not ready — a run is gated on a ready capability envelope")));
    }
    if view.get("connector_mapping_id").and_then(|v| v.as_str()) != Some(mapping_id.as_str()) {
        return Err(verr(
            "transformation_run_policy_view_mapping_mismatch",
            "the policy view does not bind the referenced mapping — a run cannot mix gates".into(),
        ));
    }
    let ops: Vec<String> = str_list(&view, "allowed_operations");
    // v1 supports only `transform` — and the view must authorize it.
    let operation = opt_s(body, "operation").unwrap_or_else(|| "transform".into());
    if operation != "transform" {
        return Err(verr("transformation_run_operation_unsupported", format!("operation '{operation}' is not supported in v1 — only 'transform' plans exist (execution kinds are a future cut)")));
    }
    if !ops.iter().any(|o| o == "transform") {
        return Err(verr(
            "transformation_run_operation_not_authorized",
            "the policy view does not authorize 'transform' over this mapping".into(),
        ));
    }
    // Requested fields ⊆ policy scope (which is itself ⊆ mapped properties). Empty → the full scope.
    let scope = view_scope(&view);
    let mut requested_fields = str_list(body, "requested_fields");
    if requested_fields.is_empty() {
        requested_fields = scope.clone();
    }
    for f in &requested_fields {
        if !scope.iter().any(|x| x == f) {
            return Err(verr("transformation_run_field_unscoped", format!("requested field '{f}' is outside the policy view's property scope — a run cannot widen its gate")));
        }
    }
    // Purpose: inherited when absent; must MATCH the policy purpose when provided.
    let view_purpose = s(&view, "purpose", "");
    let purpose = opt_s(body, "purpose").unwrap_or_else(|| view_purpose.clone());
    if purpose != view_purpose {
        return Err(verr(
            "transformation_run_purpose_mismatch",
            format!(
                "run purpose '{purpose}' does not match the policy view's purpose '{view_purpose}'"
            ),
        ));
    }
    // Output intent: enum only; a high-risk intent needs the view to authorize its downstream op
    // WITH a named receipt obligation (checked against the gate — belt and braces).
    let output_intent = opt_s(body, "output_intent").unwrap_or_else(|| "ontology_objects".into());
    if !OUTPUT_INTENTS.contains(&output_intent.as_str()) {
        return Err(verr(
            "transformation_run_output_intent_invalid",
            format!("output_intent '{output_intent}' must be one of {OUTPUT_INTENTS:?}"),
        ));
    }
    if let Some(op) = intent_downstream_op(&output_intent) {
        if !ops.iter().any(|o| o == op) {
            return Err(verr("transformation_run_intent_not_authorized", format!("output intent '{output_intent}' implies downstream '{op}' which the policy view does not authorize")));
        }
        let obligations = str_list(&view, "receipt_obligations");
        if !obligations.iter().any(|o| o.to_lowercase().contains(op)) {
            return Err(verr("transformation_run_receipt_obligation_required", format!("output intent '{output_intent}' is high-risk and the policy view carries no receipt obligation naming '{op}'")));
        }
    }
    Ok(RunInputs {
        mapping,
        view,
        requested_fields,
        purpose,
        output_intent,
    })
}

fn run_receipt(data_dir: &str, run_ref: &str, op: &str, outcome: &str, summary: &str) -> Value {
    let id = format!("trr_{:x}", nanos());
    let receipt_ref = format!("agentgres://transformation-run-receipt/{id}");
    let rec = json!({
        "schema_version": RECEIPT_SCHEMA, "receipt_id": id, "receipt_ref": receipt_ref,
        "transformation_run_ref": run_ref, "op": op, "outcome": outcome, "summary": summary, "at": iso_now()
    });
    let _ = persist_record(data_dir, RECEIPT_DIR, &id, &rec);
    rec
}
/// Append a history entry + receipt ref to a run record (bounded history).
fn push_history(record: &mut Value, op: &str, summary: &str, receipt_ref: Value) {
    let rev = record.get("revision").and_then(|v| v.as_u64()).unwrap_or(1);
    let mut hist = record
        .get("history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    hist.push(json!({ "revision": rev, "op": op, "at": iso_now(), "summary": summary, "receipt_ref": receipt_ref.clone() }));
    let len = hist.len();
    if len > 20 {
        hist = hist[len - 20..].to_vec();
    }
    record["history"] = json!(hist);
    let mut refs = record
        .get("receipt_refs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    refs.push(receipt_ref);
    record["receipt_refs"] = json!(refs);
}
fn bad(data_dir: &str, op: &str, err: VErr) -> (StatusCode, Json<Value>) {
    // Failed validation is itself receipted (the audit trail records what was refused and why).
    let _ = run_receipt(
        data_dir,
        "transformation-run://unadmitted",
        op,
        &err.0,
        &err.1,
    );
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": err.0, "message": err.1 } })),
    )
}

/// GET /v1/hypervisor/odk/transformation-runs — declared run plans (newest first).
pub(crate) async fn handle_runs_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, RECORD_DIR);
    items.sort_by(|a, b| s(b, "updated_at", "").cmp(&s(a, "updated_at", "")));
    Json(
        json!({ "ok": true, "schema_version": RUN_SCHEMA, "transformation_runs": items, "runtimeTruthSource": "daemon-runtime" }),
    )
}

/// GET /v1/hypervisor/odk/transformation-runs/overview — lifecycle vocab + counts + honest gaps.
pub(crate) async fn handle_runs_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let items = read_record_dir(&st.data_dir, RECORD_DIR);
    let by = |status: &str| {
        items
            .iter()
            .filter(|r| s(r, "status", "") == status)
            .count()
    };
    Json(json!({
        "ok": true,
        "schema_version": OVERVIEW_SCHEMA,
        "transformation_runs": items.len(),
        "lifecycle": { "planned": by("planned"), "dry_run_ready": by("dry_run_ready"), "blocked": by("blocked"), "cancelled": by("cancelled") },
        "lifecycle_states": LIFECYCLE_STATES,
        "reserved_states": { "states": RESERVED_STATES, "note": "reserved for a future connector-adapter cut — never set by this plane" },
        "output_intents": OUTPUT_INTENTS,
        "missing_contracts": MISSING_CONTRACTS,
        "governance_gaps": [
            "PLAN / DRY-RUN only — a run validates shape, gate, and intent and emits receipts; it never contacts a source or moves data",
            "live source reads are a NAMED GAP: they arrive with a future connector-adapter cut, after credentials get an authority-crossing story",
            "no object plane is produced — object_instances stays 0 until an OntologyProjection exists",
            "every create, dry-run, block, cancel, and FAILED validation is receipted"
        ],
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// GET /v1/hypervisor/odk/transformation-runs/:id.
pub(crate) async fn handle_run_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_run(&st.data_dir, &id) {
        Some(r) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "transformation_run": r })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "transformation run not found" })),
        ),
    }
}

/// GET /v1/hypervisor/odk/transformation-runs/:id/history — embedded history + persisted receipts.
pub(crate) async fn handle_run_history(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(r) = load_run(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "transformation run not found" })),
        );
    };
    let rref = r
        .get("ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut receipts = read_record_dir(&st.data_dir, RECEIPT_DIR);
    receipts.retain(|x| {
        x.get("transformation_run_ref").and_then(|v| v.as_str()) == Some(rref.as_str())
    });
    receipts.sort_by(|a, b| s(b, "at", "").cmp(&s(a, "at", "")));
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "transformation_run_ref": rref, "revision": r.get("revision"), "status": r.get("status"), "history": r.get("history").cloned().unwrap_or(json!([])), "receipts": receipts }),
        ),
    )
}

/// POST /v1/hypervisor/odk/transformation-runs — admit a run PLAN (fail-closed, receipted, inert).
pub(crate) async fn handle_run_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let inputs = match validate_inputs(&st.data_dir, &body) {
        Ok(i) => i,
        Err(e) => return bad(&st.data_dir, "create_rejected", e),
    };
    let id = format!("trun_{:x}", nanos());
    let now = iso_now();
    let rref = format!("transformation-run://{id}");
    let receipt = run_receipt(
        &st.data_dir,
        &rref,
        "created",
        "ok",
        "TransformationRun plan admitted",
    );
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    let record = json!({
        "schema_version": RUN_SCHEMA,
        "object": "ioi.hypervisor.odk.transformation_run",
        "id": id,
        "ref": rref,
        "name": s(&body, "name", "transformation-run"),
        "description": s(&body, "description", ""),
        "status": "planned",
        "operation": "transform",
        "connector_mapping_id": inputs.mapping.get("id").cloned().unwrap_or(Value::Null),
        "connector_mapping_ref": inputs.mapping.get("ref").cloned().unwrap_or(Value::Null),
        "policy_view_id": inputs.view.get("id").cloned().unwrap_or(Value::Null),
        "policy_view_ref": inputs.view.get("ref").cloned().unwrap_or(Value::Null),
        "ontology_ref": inputs.mapping.get("ontology_ref").cloned().unwrap_or(Value::Null),
        "object_type_id": inputs.mapping.get("object_type_id").cloned().unwrap_or(Value::Null),
        "requested_fields": inputs.requested_fields,
        "purpose": inputs.purpose,
        "output_intent": inputs.output_intent,
        "plan": Value::Null,
        "execution": { "source_contacted": false, "data_moved": false, "object_instances": 0, "note": "plan/dry-run only — live reads are a future connector-adapter cut" },
        "missing_contracts": MISSING_CONTRACTS,
        "revision": 1,
        "receipt_refs": [receipt_ref.clone()],
        "history": [ { "revision": 1, "op": "created", "at": now.clone(), "summary": "TransformationRun plan admitted", "receipt_ref": receipt_ref } ],
        "created_at": now.clone(),
        "updated_at": now
    });
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "transformation_run": record })),
    )
}

/// POST /v1/hypervisor/odk/transformation-runs/:id/dry-run — recompute the gate against CURRENT
/// state and produce the auditable plan. Receipt is written BEFORE the plan is registered. If the
/// referenced truth drifted (mapping/view gone or degraded), the run is BLOCKED with named reasons.
pub(crate) async fn handle_run_dry_run(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut record) = load_run(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "transformation run not found" })),
        );
    };
    if s(&record, "status", "") == "cancelled" {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "ok": false, "error": { "code": "transformation_run_cancelled_immutable", "message": "a cancelled run is immutable" } }),
            ),
        );
    }
    let rref = s(&record, "ref", "");
    // Re-validate against the CURRENT mapping/view — the gate is checked every time, never cached.
    let revalidation_body = json!({
        "name": record.get("name").cloned().unwrap_or(Value::Null),
        "connector_mapping_id": record.get("connector_mapping_id").cloned().unwrap_or(Value::Null),
        "policy_view_id": record.get("policy_view_id").cloned().unwrap_or(Value::Null),
        "requested_fields": record.get("requested_fields").cloned().unwrap_or(json!([])),
        "purpose": record.get("purpose").cloned().unwrap_or(Value::Null),
        "output_intent": record.get("output_intent").cloned().unwrap_or(Value::Null),
    });
    match validate_inputs(&st.data_dir, &revalidation_body) {
        Err((code, msg)) => {
            let receipt = run_receipt(&st.data_dir, &rref, "dry_run_blocked", &code, &msg);
            let summary = format!("blocked: {code}");
            record["status"] = json!("blocked");
            record["blocked_reasons"] = json!([{ "code": code, "message": msg }]);
            record["updated_at"] = json!(iso_now());
            push_history(
                &mut record,
                "dry_run_blocked",
                &summary,
                receipt.get("receipt_ref").cloned().unwrap_or(Value::Null),
            );
            let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "transformation_run": record })),
            )
        }
        Ok(inputs) => {
            // Build the auditable plan from DECLARED truth only (no source contact anywhere).
            let fields: Vec<Value> = inputs
                .requested_fields
                .iter()
                .filter_map(|pid| {
                    mapping_binding(&inputs.mapping, pid).map(|(sf, st_)| json!({ "property_id": pid, "source_field": sf, "source_type": st_ }))
                })
                .collect();
            let plan = json!({
                "source": {
                    "data_source_ref": inputs.mapping.get("data_source_ref").cloned().unwrap_or(Value::Null),
                    "declared_endpoint_only": true
                },
                "object_type_id": inputs.mapping.get("object_type_id").cloned().unwrap_or(Value::Null),
                "fields": fields,
                "policy_gate": {
                    "policy_view_ref": inputs.view.get("ref").cloned().unwrap_or(Value::Null),
                    "purpose": inputs.purpose,
                    "receipt_obligations": inputs.view.get("receipt_obligations").cloned().unwrap_or(json!([]))
                },
                "output_intent": inputs.output_intent,
                "would_contact_source": false,
                "object_instances": 0,
                "receipts_before_output": true
            });
            // Receipt FIRST, then the plan lands on the record — output is never registered unreceipted.
            let receipt = run_receipt(
                &st.data_dir,
                &rref,
                "dry_run",
                "ok",
                "dry-run plan validated against the current gate",
            );
            record["status"] = json!("dry_run_ready");
            record["plan"] = plan;
            record["blocked_reasons"] = json!([]);
            record["updated_at"] = json!(iso_now());
            push_history(
                &mut record,
                "dry_run",
                "dry-run plan validated against the current gate",
                receipt.get("receipt_ref").cloned().unwrap_or(Value::Null),
            );
            let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "transformation_run": record })),
            )
        }
    }
}

/// POST /v1/hypervisor/odk/transformation-runs/:id/cancel — terminal, receipted.
pub(crate) async fn handle_run_cancel(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut record) = load_run(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "transformation run not found" })),
        );
    };
    if s(&record, "status", "") == "cancelled" {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "ok": false, "error": { "code": "transformation_run_cancelled_immutable", "message": "the run is already cancelled" } }),
            ),
        );
    }
    let rref = s(&record, "ref", "");
    let receipt = run_receipt(
        &st.data_dir,
        &rref,
        "cancelled",
        "ok",
        "TransformationRun plan cancelled",
    );
    record["status"] = json!("cancelled");
    record["updated_at"] = json!(iso_now());
    push_history(
        &mut record,
        "cancelled",
        "TransformationRun plan cancelled",
        receipt.get("receipt_ref").cloned().unwrap_or(Value::Null),
    );
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "transformation_run": record })),
    )
}

/// PATCH — plan-affecting changes re-validate against the CURRENT gate and reset the plan to
/// `planned` (a stale plan never survives an edit). Malformed patch changes nothing.
pub(crate) async fn handle_run_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(patch): Json<Value>,
) -> Json<Value> {
    let Some(existing) = load_run(&st.data_dir, &id) else {
        return Json(json!({ "ok": false, "reason": "transformation run not found" }));
    };
    if s(&existing, "status", "") == "cancelled" {
        return Json(
            json!({ "ok": false, "error": { "code": "transformation_run_cancelled_immutable", "message": "a cancelled run is immutable" } }),
        );
    }
    let plan_keys = [
        "connector_mapping_id",
        "policy_view_id",
        "requested_fields",
        "purpose",
        "output_intent",
        "operation",
    ];
    let plan_affecting = plan_keys.iter().any(|k| patch.get(*k).is_some());
    let mut merged = json!({});
    let mo = merged.as_object_mut().unwrap();
    for k in [
        "name",
        "description",
        "connector_mapping_id",
        "policy_view_id",
        "requested_fields",
        "purpose",
        "output_intent",
        "operation",
    ] {
        if let Some(v) = patch.get(k).or_else(|| existing.get(k)) {
            mo.insert(k.to_string(), v.clone());
        }
    }
    let inputs = match validate_inputs(&st.data_dir, &merged) {
        Ok(i) => i,
        Err(e) => {
            let _ = run_receipt(
                &st.data_dir,
                &s(&existing, "ref", ""),
                "patch_rejected",
                &e.0,
                &e.1,
            );
            return Json(json!({ "ok": false, "error": { "code": e.0, "message": e.1 } }));
        }
    };
    let mut record = existing;
    if let Some(v) = patch.get("name") {
        record["name"] = v.clone();
    }
    if let Some(v) = patch.get("description") {
        record["description"] = v.clone();
    }
    if plan_affecting {
        record["connector_mapping_id"] = inputs.mapping.get("id").cloned().unwrap_or(Value::Null);
        record["connector_mapping_ref"] = inputs.mapping.get("ref").cloned().unwrap_or(Value::Null);
        record["policy_view_id"] = inputs.view.get("id").cloned().unwrap_or(Value::Null);
        record["policy_view_ref"] = inputs.view.get("ref").cloned().unwrap_or(Value::Null);
        record["ontology_ref"] = inputs
            .mapping
            .get("ontology_ref")
            .cloned()
            .unwrap_or(Value::Null);
        record["object_type_id"] = inputs
            .mapping
            .get("object_type_id")
            .cloned()
            .unwrap_or(Value::Null);
        record["requested_fields"] = json!(inputs.requested_fields);
        record["purpose"] = json!(inputs.purpose);
        record["output_intent"] = json!(inputs.output_intent);
        record["status"] = json!("planned");
        record["plan"] = Value::Null;
        record["blocked_reasons"] = json!([]);
    }
    let rev = record.get("revision").and_then(|v| v.as_u64()).unwrap_or(1) + 1;
    record["revision"] = json!(rev);
    record["updated_at"] = json!(iso_now());
    let receipt = run_receipt(
        &st.data_dir,
        &s(&record, "ref", ""),
        "patched",
        "ok",
        if plan_affecting {
            "plan-affecting edit — plan reset to planned"
        } else {
            "metadata edit"
        },
    );
    push_history(
        &mut record,
        "patched",
        if plan_affecting {
            "plan-affecting edit — plan reset to planned"
        } else {
            "metadata edit"
        },
        receipt.get("receipt_ref").cloned().unwrap_or(Value::Null),
    );
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    Json(json!({ "ok": true, "transformation_run": record }))
}

/// DELETE — receipted removal of the plan record.
pub(crate) async fn handle_run_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let rref = load_run(&st.data_dir, &id)
        .and_then(|r| r.get("ref").and_then(|v| v.as_str()).map(str::to_string))
        .unwrap_or_else(|| format!("transformation-run://{id}"));
    let removed = remove_record(&st.data_dir, RECORD_DIR, &id);
    if removed {
        let _ = run_receipt(
            &st.data_dir,
            &rref,
            "deleted",
            "ok",
            "TransformationRun plan removed",
        );
    }
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

#[cfg(test)]
mod transformation_run_tests {
    use super::*;

    #[test]
    fn lifecycle_states_and_reserved_are_explicit() {
        assert_eq!(
            LIFECYCLE_STATES,
            &["planned", "dry_run_ready", "blocked", "cancelled"]
        );
        assert_eq!(RESERVED_STATES, &["executed", "materialized"]);
        assert_eq!(MISSING_CONTRACTS, &["OntologyProjection"]);
    }

    #[test]
    fn high_risk_intents_map_to_downstream_ops() {
        assert_eq!(intent_downstream_op("export_bundle"), Some("export"));
        assert_eq!(intent_downstream_op("training_material"), Some("train"));
        assert_eq!(intent_downstream_op("evaluation_dataset"), Some("evaluate"));
        assert_eq!(intent_downstream_op("ontology_objects"), None);
        assert_eq!(intent_downstream_op("projection"), None);
    }

    #[test]
    fn raw_query_and_secret_keys_are_named() {
        assert!(RAW_QUERY_KEYS.contains(&"sql"));
        assert!(RAW_QUERY_KEYS.contains(&"raw_query"));
        assert!(PLAINTEXT_SECRET_KEYS.contains(&"api_key"));
    }

    #[test]
    fn mapping_binding_resolves_across_key_title_fields() {
        let mapping = json!({
            "key_mapping": { "property_id": "loan_id", "source_field": "id", "source_type": "string" },
            "title_mapping": { "property_id": "title", "source_field": "disp", "source_type": "string" },
            "field_mappings": [{ "property_id": "amount", "source_field": "amt", "source_type": "double" }]
        });
        assert_eq!(mapping_binding(&mapping, "loan_id").unwrap().0, "id");
        assert_eq!(mapping_binding(&mapping, "amount").unwrap().0, "amt");
        assert!(mapping_binding(&mapping, "ghost").is_none());
    }
}
