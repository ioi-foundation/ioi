//! PolicyBoundDataView — the SECOND inert authority-crossing rung. Given a validated ConnectorMapping
//! (#13), a view declares the AUTHORITY ENVELOPE for the would-be ontology-shaped data: which
//! operations are allowed, for which subjects/actors, for what purpose, over which property scope,
//! under which retention/export/training/evaluation/publish postures, and with which receipt
//! obligations. It is a CAPABILITY over semantic data — not a thin ACL table — so a future
//! TransformationRun has a real gate to satisfy instead of inventing authorization at execution time.
//!
//! Declarative/inert like the mapping it binds: a view never executes a run, never reads the source,
//! never mints object rows, and never implies approval. `object_instances` stays 0;
//! `authority.crossed` stays false. Declaring a view authorizes NOTHING to run — it declares what a
//! run would have to prove.
//!
//! Fail-closed at write: known + READY mapping; operations from the enum only; non-empty subject set;
//! wildcard-all authority only on an explicit draft (and then never `ready`); property scope must be
//! a subset of what the mapping actually maps; postures from their enums, and never contradicting an
//! allowed operation; high-risk operations (export/publish/train/evaluate) require named receipt
//! obligations; no credential material.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const VIEW_SCHEMA: &str = "ioi.hypervisor.odk.policy-bound-data-view.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.odk.policy-bound-data-view-receipt.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.odk.policy-bound-data-views-overview.v1";
pub(crate) const RECORD_DIR: &str = "odk-policy-bound-data-views";
const RECEIPT_DIR: &str = "odk-policy-bound-data-view-receipts";

/// The operations an autonomous system could be authorized to perform over the mapped data.
const ALLOWED_OPERATIONS: &[&str] = &[
    "read",
    "transform",
    "distill",
    "train",
    "evaluate",
    "export",
    "publish",
    "route",
];
/// Operations whose authorization ALWAYS requires a named receipt obligation.
const HIGH_RISK_OPERATIONS: &[&str] = &["export", "publish", "train", "evaluate"];
/// Wildcard subject spellings — authority-for-everyone is only ever a draft, never ready.
const WILDCARD_SUBJECTS: &[&str] = &["*", "all", "everyone", "any"];
/// Posture enums. A posture that contradicts an allowed operation is a fail-closed conflict.
const RETENTION_POSTURES: &[&str] = &["ephemeral", "bounded", "durable"];
const EXPORT_POSTURES: &[&str] = &["no_export", "receipted_export_only"];
const TRAINING_POSTURES: &[&str] = &["no_training", "receipted_training_only"];
const EVALUATION_POSTURES: &[&str] = &["no_evaluation", "receipted_evaluation_only"];
const PUBLISH_ROUTE_POSTURES: &[&str] = &["no_publish_route", "receipted_publish_route_only"];
/// The contracts still missing downstream of this rung.
const MISSING_CONTRACTS: &[&str] = &["TransformationRun", "OntologyProjection"];
/// Body keys that would be a plaintext secret — rejected outright.
const PLAINTEXT_SECRET_KEYS: &[&str] = &[
    "secret",
    "password",
    "api_key",
    "apikey",
    "token",
    "credential",
];

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

fn is_wildcard(subject: &str) -> bool {
    WILDCARD_SUBJECTS.contains(&subject.to_lowercase().as_str())
}
/// Which posture field (and its enum + "forbidden" value) governs an operation, if any.
fn posture_for_operation(
    op: &str,
) -> Option<(&'static str, &'static [&'static str], &'static str)> {
    match op {
        "export" => Some(("export_posture", EXPORT_POSTURES, "no_export")),
        "train" => Some(("training_posture", TRAINING_POSTURES, "no_training")),
        "evaluate" => Some(("evaluation_posture", EVALUATION_POSTURES, "no_evaluation")),
        "publish" | "route" => Some((
            "publish_route_posture",
            PUBLISH_ROUTE_POSTURES,
            "no_publish_route",
        )),
        _ => None,
    }
}

fn load_mapping(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, crate::connector_mapping_routes::RECORD_DIR)
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
}
/// Every property the mapping actually maps (key + title + fields) — the widest scope a view may claim.
fn mapped_property_ids(mapping: &Value) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for k in ["key_mapping", "title_mapping"] {
        if let Some(pid) = mapping
            .get(k)
            .and_then(|m| m.get("property_id"))
            .and_then(|v| v.as_str())
        {
            ids.push(pid.to_string());
        }
    }
    if let Some(fs) = mapping.get("field_mappings").and_then(|v| v.as_array()) {
        for f in fs {
            if let Some(pid) = f.get("property_id").and_then(|v| v.as_str()) {
                ids.push(pid.to_string());
            }
        }
    }
    ids
}

/// Validate a view body fail-closed and project the declared record fields + honest health.
/// INERT: nothing is authorized to run; this only validates the declared envelope.
fn validate_and_project(data_dir: &str, body: &Value) -> Result<Value, VErr> {
    if let Some(obj) = body.as_object() {
        if PLAINTEXT_SECRET_KEYS
            .iter()
            .any(|k| obj.contains_key(*k) && !obj[*k].is_null())
        {
            return Err(verr(
                "policy_view_plaintext_secret_rejected",
                "A policy-bound data view never carries credentials.".into(),
            ));
        }
    }
    if opt_s(body, "name").is_none() {
        return Err(verr(
            "policy_view_name_required",
            "A policy-bound data view requires a name.".into(),
        ));
    }
    // Known + READY mapping — a view binds validated shape, never a half-declared one.
    let mapping_id = opt_s(body, "connector_mapping_id").unwrap_or_default();
    let mapping = load_mapping(data_dir, &mapping_id).ok_or_else(|| {
        verr(
            "policy_view_mapping_unknown",
            format!("connector_mapping_id '{mapping_id}' does not resolve to a declared mapping"),
        )
    })?;
    let mapping_health = mapping
        .pointer("/health/status")
        .and_then(|v| v.as_str())
        .unwrap_or("incomplete");
    if mapping_health != "ready" {
        return Err(verr(
            "policy_view_mapping_not_ready",
            format!("mapping '{mapping_id}' health is '{mapping_health}' — a view binds only a ready mapping"),
        ));
    }

    // Allowed operations: enum only, at least one.
    let operations = str_list(body, "allowed_operations");
    if operations.is_empty() {
        return Err(verr(
            "policy_view_operations_required",
            "At least one allowed operation is required.".into(),
        ));
    }
    for op in &operations {
        if !ALLOWED_OPERATIONS.contains(&op.as_str()) {
            return Err(verr(
                "policy_view_operation_invalid",
                format!("operation '{op}' is not a known operation"),
            ));
        }
    }

    // Authority subjects: non-empty; wildcard-all only on an explicit draft.
    let subjects = str_list(body, "authority_subjects");
    if subjects.is_empty() {
        return Err(verr(
            "policy_view_subjects_required",
            "A non-empty authority subject set is required.".into(),
        ));
    }
    let is_draft = body.get("draft").and_then(|v| v.as_bool()).unwrap_or(false);
    let has_wildcard = subjects.iter().any(|x| is_wildcard(x));
    if has_wildcard && !is_draft {
        return Err(verr(
            "policy_view_wildcard_authority_rejected",
            "Wildcard-all authority is never granted implicitly — mark the view draft:true to hold it as an incomplete draft.".into(),
        ));
    }

    // Property scope must be a subset of what the mapping actually maps.
    let mapped = mapped_property_ids(&mapping);
    let property_scope = str_list(body, "property_scope");
    for pid in &property_scope {
        if !mapped.iter().any(|m| m == pid) {
            return Err(verr(
                "policy_view_property_unscoped",
                format!("property '{pid}' is not mapped by the bound connector mapping — a view cannot authorize unmapped data"),
            ));
        }
    }

    // Postures: enum-valid, and never contradicting an allowed operation.
    let posture = |key: &str, allowed: &[&str], default: &str| -> Result<String, VErr> {
        let val = opt_s(body, key).unwrap_or_else(|| default.to_string());
        if !allowed.contains(&val.as_str()) {
            return Err(verr(
                "policy_view_posture_invalid",
                format!("{key} '{val}' must be one of {allowed:?}"),
            ));
        }
        Ok(val)
    };
    let retention_posture = opt_s(body, "retention_posture");
    if let Some(rp) = &retention_posture {
        if !RETENTION_POSTURES.contains(&rp.as_str()) {
            return Err(verr(
                "policy_view_posture_invalid",
                format!("retention_posture '{rp}' must be one of {RETENTION_POSTURES:?}"),
            ));
        }
    }
    let export_posture = posture("export_posture", EXPORT_POSTURES, "no_export")?;
    let training_posture = posture("training_posture", TRAINING_POSTURES, "no_training")?;
    let evaluation_posture = posture("evaluation_posture", EVALUATION_POSTURES, "no_evaluation")?;
    let publish_route_posture = posture(
        "publish_route_posture",
        PUBLISH_ROUTE_POSTURES,
        "no_publish_route",
    )?;
    let posture_value = |key: &str| -> &str {
        match key {
            "export_posture" => &export_posture,
            "training_posture" => &training_posture,
            "evaluation_posture" => &evaluation_posture,
            _ => &publish_route_posture,
        }
    };
    for op in &operations {
        if let Some((key, _, forbidden)) = posture_for_operation(op) {
            if posture_value(key) == forbidden {
                return Err(verr(
                    "policy_view_posture_conflict",
                    format!("operation '{op}' is allowed but {key} declares '{forbidden}' — the capability contradicts its own posture"),
                ));
            }
        }
    }

    // High-risk operations require a NAMED receipt obligation (an obligation string naming the op).
    let receipt_obligations = str_list(body, "receipt_obligations");
    for op in &operations {
        if HIGH_RISK_OPERATIONS.contains(&op.as_str())
            && !receipt_obligations
                .iter()
                .any(|o| o.to_lowercase().contains(op.as_str()))
        {
            return Err(verr(
                "policy_view_receipt_obligation_required",
                format!("operation '{op}' is high-risk and requires a named receipt obligation (e.g. \"{op}: receipt per batch\")"),
            ));
        }
    }

    // Honest readiness — ready ONLY when the envelope is complete: purpose, retention, scoped
    // properties, no wildcard. (Subjects/operations/obligations were enforced at write.)
    let purpose = s(body, "purpose", "");
    let mut gaps: Vec<String> = Vec::new();
    if purpose.trim().is_empty() {
        gaps.push("no purpose declared — a capability without a purpose is not grantable".into());
    }
    if retention_posture.is_none() {
        gaps.push("no retention posture declared".into());
    }
    if property_scope.is_empty() {
        gaps.push("no property scope declared — scope the view to mapped properties".into());
    }
    if has_wildcard {
        gaps.push(
            "wildcard-all authority — narrow the subject set before this view can be ready".into(),
        );
    }
    let status = if gaps.is_empty() {
        "ready"
    } else {
        "incomplete"
    };
    let (n_subjects, n_operations, n_scope) =
        (subjects.len(), operations.len(), property_scope.len());

    Ok(json!({
        "connector_mapping_id": mapping_id,
        "connector_mapping_ref": mapping.get("ref").cloned().unwrap_or(Value::Null),
        "ontology_ref": mapping.get("ontology_ref").cloned().unwrap_or(Value::Null),
        "object_type_id": mapping.get("object_type_id").cloned().unwrap_or(Value::Null),
        "allowed_operations": operations,
        "authority_subjects": subjects,
        "purpose": purpose,
        "property_scope": property_scope,
        "object_scope": body.get("object_scope").cloned().unwrap_or(Value::Null),
        "retention_posture": retention_posture,
        "export_posture": export_posture,
        "training_posture": training_posture,
        "evaluation_posture": evaluation_posture,
        "publish_route_posture": publish_route_posture,
        "receipt_obligations": receipt_obligations,
        "health": {
            "status": status,
            "gaps": gaps,
            "authorized_subjects": n_subjects,
            "allowed_operations": n_operations,
            "scoped_properties": n_scope,
            "object_instances": 0,
            "missing_contracts": MISSING_CONTRACTS,
            "note": "declarative gate only — nothing is authorized to RUN; a future TransformationRun must satisfy this view before any execution"
        },
        "authority": { "crossed": false, "note": "declaring a view implies no approval and executes nothing" }
    }))
}

fn view_receipt(data_dir: &str, view_ref: &str, op: &str, summary: &str) -> Value {
    let id = format!("pbdvr_{:x}", nanos());
    let receipt_ref = format!("agentgres://policy-bound-data-view-receipt/{id}");
    let rec = json!({
        "schema_version": RECEIPT_SCHEMA, "receipt_id": id, "receipt_ref": receipt_ref,
        "policy_view_ref": view_ref, "op": op, "outcome": "ok", "summary": summary, "at": iso_now()
    });
    let _ = persist_record(data_dir, RECEIPT_DIR, &id, &rec);
    rec
}
fn load_view(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, RECORD_DIR)
        .into_iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
}
fn bad(err: VErr) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": err.0, "message": err.1 } })),
    )
}

/// GET /v1/hypervisor/odk/policy-bound-data-views — declared views (newest first).
pub(crate) async fn handle_policy_views_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, RECORD_DIR);
    items.sort_by(|a, b| s(b, "updated_at", "").cmp(&s(a, "updated_at", "")));
    Json(
        json!({ "ok": true, "schema_version": VIEW_SCHEMA, "policy_bound_data_views": items, "runtimeTruthSource": "daemon-runtime" }),
    )
}

/// GET /v1/hypervisor/odk/policy-bound-data-views/overview — vocab + counts + honest gaps.
pub(crate) async fn handle_policy_views_overview(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    let items = read_record_dir(&st.data_dir, RECORD_DIR);
    let by_status = |status: &str| {
        items
            .iter()
            .filter(|r| r.pointer("/health/status").and_then(|v| v.as_str()) == Some(status))
            .count()
    };
    Json(json!({
        "ok": true,
        "schema_version": OVERVIEW_SCHEMA,
        "policy_bound_data_views": items.len(),
        "health": { "ready": by_status("ready"), "incomplete": by_status("incomplete") },
        "allowed_operations": ALLOWED_OPERATIONS,
        "high_risk_operations": HIGH_RISK_OPERATIONS,
        "postures": {
            "retention": RETENTION_POSTURES,
            "export": EXPORT_POSTURES,
            "training": TRAINING_POSTURES,
            "evaluation": EVALUATION_POSTURES,
            "publish_route": PUBLISH_ROUTE_POSTURES
        },
        "missing_contracts": MISSING_CONTRACTS,
        "governance_gaps": [
            "DECLARATIVE gate only — a view authorizes nothing to run; it declares what a run would have to prove",
            "execution is a NAMED GAP: a future TransformationRun must satisfy a ready view before anything executes",
            "no object plane exists — object_instances is 0 until an OntologyProjection is built",
            "wildcard-all authority is never granted implicitly; high-risk operations always carry named receipt obligations"
        ],
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// GET /v1/hypervisor/odk/policy-bound-data-views/:id.
pub(crate) async fn handle_policy_view_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_view(&st.data_dir, &id) {
        Some(r) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "policy_bound_data_view": r })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "policy-bound data view not found" })),
        ),
    }
}

/// GET /v1/hypervisor/odk/policy-bound-data-views/:id/health.
pub(crate) async fn handle_policy_view_health(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_view(&st.data_dir, &id) {
        Some(r) => (
            StatusCode::OK,
            Json(
                json!({ "ok": true, "policy_view_ref": r.get("ref"), "revision": r.get("revision"), "health": r.get("health") }),
            ),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "policy-bound data view not found" })),
        ),
    }
}

/// GET /v1/hypervisor/odk/policy-bound-data-views/:id/history — embedded history + receipts.
pub(crate) async fn handle_policy_view_history(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(r) = load_view(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "policy-bound data view not found" })),
        );
    };
    let vref = r
        .get("ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut receipts = read_record_dir(&st.data_dir, RECEIPT_DIR);
    receipts.retain(|x| x.get("policy_view_ref").and_then(|v| v.as_str()) == Some(vref.as_str()));
    receipts.sort_by(|a, b| s(b, "at", "").cmp(&s(a, "at", "")));
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "policy_view_ref": vref, "revision": r.get("revision"), "history": r.get("history").cloned().unwrap_or(json!([])), "receipts": receipts }),
        ),
    )
}

/// POST /v1/hypervisor/odk/policy-bound-data-views — declare a view (fail-closed, receipted, INERT).
pub(crate) async fn handle_policy_view_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let projected = match validate_and_project(&st.data_dir, &body) {
        Ok(p) => p,
        Err(e) => return bad(e),
    };
    let id = format!("pbdv_{:x}", nanos());
    let now = iso_now();
    let vref = format!("policy-bound-data-view://{id}");
    let receipt = view_receipt(
        &st.data_dir,
        &vref,
        "created",
        "PolicyBoundDataView declared",
    );
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    let is_draft = body.get("draft").and_then(|v| v.as_bool()).unwrap_or(false);
    let mut record = json!({
        "schema_version": VIEW_SCHEMA,
        "object": "ioi.hypervisor.odk.policy_bound_data_view",
        "id": id,
        "ref": vref,
        "name": s(&body, "name", "policy-bound-data-view"),
        "description": s(&body, "description", ""),
        "status": if is_draft { "draft" } else { "declared" },
        "revision": 1,
        "receipt_refs": [receipt_ref.clone()],
        "history": [ { "revision": 1, "op": "created", "at": now.clone(), "summary": "PolicyBoundDataView declared", "receipt_ref": receipt_ref } ],
        "created_at": now.clone(),
        "updated_at": now
    });
    if let (Some(obj), Some(proj)) = (record.as_object_mut(), projected.as_object()) {
        for (k, v) in proj {
            obj.insert(k.clone(), v.clone());
        }
    }
    let _ = persist_record(
        &st.data_dir,
        RECORD_DIR,
        record
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        &record,
    );
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "policy_bound_data_view": record })),
    )
}

/// PATCH — re-validate the merged view; a malformed patch changes nothing (no revision bump).
pub(crate) async fn handle_policy_view_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(patch): Json<Value>,
) -> Json<Value> {
    let Some(existing) = load_view(&st.data_dir, &id) else {
        return Json(json!({ "ok": false, "reason": "policy-bound data view not found" }));
    };
    let mut merged = json!({});
    let mo = merged.as_object_mut().unwrap();
    for k in [
        "name",
        "description",
        "connector_mapping_id",
        "allowed_operations",
        "authority_subjects",
        "purpose",
        "property_scope",
        "object_scope",
        "retention_posture",
        "export_posture",
        "training_posture",
        "evaluation_posture",
        "publish_route_posture",
        "receipt_obligations",
        "draft",
    ] {
        if let Some(v) = patch.get(k).or_else(|| existing.get(k)) {
            mo.insert(k.to_string(), v.clone());
        }
    }
    // `draft` is not persisted verbatim on the record — reconstruct it from status when not patched.
    if patch.get("draft").is_none()
        && existing.get("status").and_then(|v| v.as_str()) == Some("draft")
    {
        mo.insert("draft".into(), json!(true));
    }
    let projected = match validate_and_project(&st.data_dir, &merged) {
        Ok(p) => p,
        Err(e) => return Json(json!({ "ok": false, "error": { "code": e.0, "message": e.1 } })),
    };
    let mut record = existing;
    if let Some(v) = patch.get("name") {
        record["name"] = v.clone();
    }
    if let Some(v) = patch.get("description") {
        record["description"] = v.clone();
    }
    if let Some(v) = patch.get("draft").and_then(|v| v.as_bool()) {
        record["status"] = json!(if v { "draft" } else { "declared" });
    }
    if let (Some(obj), Some(proj)) = (record.as_object_mut(), projected.as_object()) {
        for (k, v) in proj {
            obj.insert(k.clone(), v.clone());
        }
    }
    let rev = record.get("revision").and_then(|v| v.as_u64()).unwrap_or(1) + 1;
    record["revision"] = json!(rev);
    let now = iso_now();
    record["updated_at"] = json!(now.clone());
    let vref = record
        .get("ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let receipt = view_receipt(
        &st.data_dir,
        &vref,
        "patched",
        "PolicyBoundDataView re-declared",
    );
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    let mut hist = record
        .get("history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    hist.push(json!({ "revision": rev, "op": "patched", "at": now, "summary": "PolicyBoundDataView re-declared", "receipt_ref": receipt_ref.clone() }));
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
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    Json(json!({ "ok": true, "policy_bound_data_view": record }))
}

/// DELETE — receipted removal (revoking a declared capability is itself an auditable act).
pub(crate) async fn handle_policy_view_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let vref = load_view(&st.data_dir, &id)
        .and_then(|r| r.get("ref").and_then(|v| v.as_str()).map(str::to_string))
        .unwrap_or_else(|| format!("policy-bound-data-view://{id}"));
    let removed = remove_record(&st.data_dir, RECORD_DIR, &id);
    if removed {
        let _ = view_receipt(
            &st.data_dir,
            &vref,
            "deleted",
            "PolicyBoundDataView removed (declared capability revoked)",
        );
    }
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

#[cfg(test)]
mod policy_bound_data_view_tests {
    use super::*;

    #[test]
    fn operation_enum_and_high_risk_are_named() {
        assert!(ALLOWED_OPERATIONS.contains(&"distill"));
        assert!(ALLOWED_OPERATIONS.contains(&"route"));
        assert!(!ALLOWED_OPERATIONS.contains(&"delete"));
        assert_eq!(
            HIGH_RISK_OPERATIONS,
            &["export", "publish", "train", "evaluate"]
        );
        assert_eq!(
            MISSING_CONTRACTS,
            &["TransformationRun", "OntologyProjection"]
        );
    }

    #[test]
    fn wildcard_subjects_are_detected_case_insensitively() {
        assert!(is_wildcard("*"));
        assert!(is_wildcard("ALL"));
        assert!(is_wildcard("Everyone"));
        assert!(!is_wildcard("agent://planner"));
    }

    #[test]
    fn posture_governs_the_right_operations() {
        assert_eq!(posture_for_operation("export").unwrap().0, "export_posture");
        assert_eq!(
            posture_for_operation("train").unwrap().0,
            "training_posture"
        );
        assert_eq!(
            posture_for_operation("publish").unwrap().0,
            "publish_route_posture"
        );
        assert_eq!(
            posture_for_operation("route").unwrap().0,
            "publish_route_posture"
        );
        assert!(posture_for_operation("read").is_none());
        assert!(posture_for_operation("transform").is_none());
    }

    #[test]
    fn mapped_property_ids_cover_key_title_and_fields() {
        let mapping = json!({
            "key_mapping": { "property_id": "loan_id" },
            "title_mapping": { "property_id": "title" },
            "field_mappings": [{ "property_id": "amount" }]
        });
        assert_eq!(
            mapped_property_ids(&mapping),
            vec!["loan_id", "title", "amount"]
        );
    }
}
