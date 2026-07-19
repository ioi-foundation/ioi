//! CapabilityLease PLAN — the credential-authority PLANNING contract for ODK materialization.
//! The first credential-crossing contract a future materializing run would have to cite: it declares
//! the EXACT CapabilityLease scope such a run would be allowed to ask for — and mints NOTHING.
//!
//! Doctrine: wallet authority becomes explicit BEFORE execution, but nothing operational crosses.
//! A plan binds the COMPLETE landed ODK ladder — DataSource → ConnectorMapping → PolicyBoundDataView
//! → TransformationRun (dry_run_ready) → OntologyProjection (ready) — and declares subject, purpose,
//! permitted operations, property scope, retention/export posture, receipt obligations, bounded TTL,
//! and credential posture. The ONLY authority gateway is the EXISTING CapabilityLease primitive
//! (`ioi.hypervisor.capability-lease.v1` at /v1/hypervisor/capability-leases); this plane never
//! becomes a second lease system.
//!
//! Inert invariants (always): lease.minted=false · credential_material=false · source_contacted=false
//! · data_moved=false · object_instances=0. No plaintext secret, no raw query, no env-credential
//! fallback, no source contact. Every create/patch/revoke — and every refusal — is receipted.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const PLAN_SCHEMA: &str = "ioi.hypervisor.odk.capability-lease-plan.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.odk.capability-lease-plan-receipt.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.odk.capability-lease-plans-overview.v1";
pub(crate) const RECORD_DIR: &str = "odk-capability-lease-plans";
const RECEIPT_DIR: &str = "odk-capability-lease-plan-receipts";

/// The ONLY authority gateway a materializing run may cross. Cited, never duplicated.
const LEASE_GATEWAY_PRIMITIVE: &str = "ioi.hypervisor.capability-lease.v1";
const LEASE_GATEWAY_ROUTE: &str = "/v1/hypervisor/capability-leases";
/// Data-source credential postures this plan can request a wallet lease against.
const LEASEABLE_POSTURES: &[&str] = &["wallet_credential_lease"];
/// A lease TTL must be bounded — a materializing run's credential is short-lived by construction.
const MAX_TTL_SECONDS: u64 = 3600;
/// Operations whose lease authorization requires named receipt obligations on the policy view.
const HIGH_RISK_OPERATIONS: &[&str] = &["export", "publish", "train", "evaluate"];
/// What still does not exist after this plan: the run that would cite it.
const MISSING_AUTHORITY: &str = "MaterializingRun — the live connector adapter that would cite this plan; a deliberate future cut";
const PLAINTEXT_SECRET_KEYS: &[&str] = &[
    "secret",
    "password",
    "api_key",
    "apikey",
    "token",
    "credential",
];
const RAW_QUERY_KEYS: &[&str] = &["query", "sql", "raw_query", "statement", "command"];
/// Env-credential fallback is an authority bypass — rejected outright.
const ENV_FALLBACK_KEYS: &[&str] = &[
    "env",
    "env_var",
    "env_credential",
    "credential_env",
    "from_env",
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
fn find_by_key(data_dir: &str, dir: &str, key: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, dir)
        .into_iter()
        .find(|r| r.get(key).and_then(|v| v.as_str()) == Some(id))
}
fn health_status(rec: &Value) -> String {
    rec.pointer("/health/status")
        .and_then(|v| v.as_str())
        .unwrap_or("incomplete")
        .to_string()
}
fn subset_of(sub: &[String], sup: &[String]) -> Option<String> {
    sub.iter().find(|x| !sup.iter().any(|y| y == *x)).cloned()
}

/// The fully-resolved, agreed ladder a plan binds.
struct PlanInputs {
    source: Value,
    mapping: Value,
    view: Value,
    run: Value,
    projection: Value,
    subject: String,
    purpose: String,
    operations: Vec<String>,
    properties: Vec<String>,
    ttl_seconds: u64,
}

/// Validate a plan body fail-closed against the CURRENT landed ladder. No source contact, no
/// minting, no secret material — this only proves the lease shape a run would be allowed to request.
fn validate_inputs(data_dir: &str, body: &Value) -> Result<PlanInputs, VErr> {
    if let Some(obj) = body.as_object() {
        if PLAINTEXT_SECRET_KEYS
            .iter()
            .any(|k| obj.contains_key(*k) && !obj[*k].is_null())
        {
            return Err(verr(
                "lease_plan_plaintext_secret_rejected",
                "A lease plan never carries credential material.".into(),
            ));
        }
        if RAW_QUERY_KEYS
            .iter()
            .any(|k| obj.contains_key(*k) && !obj[*k].is_null())
        {
            return Err(verr(
                "lease_plan_raw_query_rejected",
                "A lease plan never carries a raw source query.".into(),
            ));
        }
        if ENV_FALLBACK_KEYS
            .iter()
            .any(|k| obj.contains_key(*k) && !obj[*k].is_null())
        {
            return Err(verr("lease_plan_env_fallback_rejected", "Environment-credential fallback is an authority bypass — the ONLY gateway is the CapabilityLease primitive.".into()));
        }
    }
    if opt_s(body, "name").is_none() {
        return Err(verr(
            "lease_plan_name_required",
            "A capability-lease plan requires a name.".into(),
        ));
    }
    // Data source: known, and its declared posture must be wallet-leaseable.
    let data_source_id = opt_s(body, "data_source_id").unwrap_or_default();
    let source = find_by_key(
        data_dir,
        crate::data_source_routes::RECORD_DIR,
        "source_id",
        &data_source_id,
    )
    .ok_or_else(|| {
        verr(
            "lease_plan_data_source_unknown",
            format!("data_source_id '{data_source_id}' does not resolve to a declared data source"),
        )
    })?;
    let posture = s(&source, "credential_posture", "");
    if !LEASEABLE_POSTURES.contains(&posture.as_str()) {
        return Err(verr(
            "lease_plan_posture_not_leaseable",
            format!("data source posture '{posture}' is not wallet-leaseable — this plan requests a wallet credential lease and the source must declare one"),
        ));
    }
    // The complete ladder, each rung at its required readiness.
    let mapping_id = opt_s(body, "connector_mapping_id").unwrap_or_default();
    let mapping = find_by_key(
        data_dir,
        crate::connector_mapping_routes::RECORD_DIR,
        "id",
        &mapping_id,
    )
    .ok_or_else(|| {
        verr(
            "lease_plan_mapping_unknown",
            format!("connector_mapping_id '{mapping_id}' does not resolve"),
        )
    })?;
    if health_status(&mapping) != "ready" {
        return Err(verr(
            "lease_plan_mapping_not_ready",
            format!("mapping '{mapping_id}' is not ready"),
        ));
    }
    let view_id = opt_s(body, "policy_view_id").unwrap_or_default();
    let view = find_by_key(
        data_dir,
        crate::policy_bound_data_view_routes::RECORD_DIR,
        "id",
        &view_id,
    )
    .ok_or_else(|| {
        verr(
            "lease_plan_policy_view_unknown",
            format!("policy_view_id '{view_id}' does not resolve"),
        )
    })?;
    if health_status(&view) != "ready" {
        return Err(verr(
            "lease_plan_policy_view_not_ready",
            format!("policy view '{view_id}' is not ready"),
        ));
    }
    let run_id = opt_s(body, "transformation_run_id").unwrap_or_default();
    let run = find_by_key(
        data_dir,
        crate::transformation_run_routes::RECORD_DIR,
        "id",
        &run_id,
    )
    .ok_or_else(|| {
        verr(
            "lease_plan_run_unknown",
            format!("transformation_run_id '{run_id}' does not resolve"),
        )
    })?;
    if s(&run, "status", "") != "dry_run_ready" {
        return Err(verr("lease_plan_run_not_ready", format!("transformation run '{run_id}' is not dry_run_ready — a lease is planned only against a validated plan")));
    }
    let projection_id = opt_s(body, "ontology_projection_id").unwrap_or_default();
    let projection = find_by_key(
        data_dir,
        crate::ontology_projection_routes::RECORD_DIR,
        "id",
        &projection_id,
    )
    .ok_or_else(|| {
        verr(
            "lease_plan_projection_unknown",
            format!("ontology_projection_id '{projection_id}' does not resolve"),
        )
    })?;
    if s(&projection, "status", "") != "ready" {
        return Err(verr(
            "lease_plan_projection_not_ready",
            format!("projection '{projection_id}' is not ready"),
        ));
    }
    // ALL bindings must agree — a lease plan cannot mix gates or ladders.
    let agrees = mapping.get("data_source_id").and_then(|v| v.as_str())
        == Some(data_source_id.as_str())
        && view.get("connector_mapping_id").and_then(|v| v.as_str()) == Some(mapping_id.as_str())
        && run.get("connector_mapping_id").and_then(|v| v.as_str()) == Some(mapping_id.as_str())
        && run.get("policy_view_id").and_then(|v| v.as_str()) == Some(view_id.as_str())
        && projection
            .get("connector_mapping_id")
            .and_then(|v| v.as_str())
            == Some(mapping_id.as_str())
        && projection.get("policy_view_id").and_then(|v| v.as_str()) == Some(view_id.as_str());
    if !agrees {
        return Err(verr("lease_plan_binding_mismatch", "the cited ladder does not agree on source/mapping/policy bindings — a lease plan cannot mix ladders".into()));
    }
    // Subject: explicitly one of the view's authorized subjects (wildcards were never `ready`).
    let subject = opt_s(body, "subject").unwrap_or_default();
    let subjects = str_list(&view, "authority_subjects");
    if subject.is_empty() || !subjects.iter().any(|x| x == &subject) {
        return Err(verr(
            "lease_plan_subject_not_authorized",
            format!("subject '{subject}' is not explicitly authorized by the policy view"),
        ));
    }
    // Purpose must match the gate's purpose (inherited when absent).
    let view_purpose = s(&view, "purpose", "");
    let purpose = opt_s(body, "purpose").unwrap_or_else(|| view_purpose.clone());
    if purpose != view_purpose {
        return Err(verr("lease_plan_purpose_mismatch", format!("plan purpose '{purpose}' does not match the policy view's purpose '{view_purpose}'")));
    }
    // Permitted operations ⊆ the view's; a materializing run is a transform, so transform must be in.
    let view_ops = str_list(&view, "allowed_operations");
    let mut operations = str_list(body, "requested_operations");
    if operations.is_empty() {
        operations = vec!["read".into(), "transform".into()];
    }
    if let Some(bad) = subset_of(&operations, &view_ops) {
        return Err(verr(
            "lease_plan_operation_not_authorized",
            format!("requested operation '{bad}' is not authorized by the policy view"),
        ));
    }
    if !operations.iter().any(|o| o == "transform") {
        return Err(verr(
            "lease_plan_operation_not_authorized",
            "a materializing-run lease must request 'transform'".into(),
        ));
    }
    // High-risk requested operations require named receipt obligations on the view.
    let obligations = str_list(&view, "receipt_obligations");
    for op in &operations {
        if HIGH_RISK_OPERATIONS.contains(&op.as_str())
            && !obligations
                .iter()
                .any(|o| o.to_lowercase().contains(op.as_str()))
        {
            return Err(verr("lease_plan_receipt_obligation_required", format!("requested operation '{op}' is high-risk and the policy view carries no receipt obligation naming it")));
        }
    }
    // Property scope ⊆ policy scope AND ⊆ projection visible — a lease can never widen the ladder.
    let policy_scope = str_list(&view, "property_scope");
    let projection_visible = str_list(&projection, "visible_properties");
    let mut properties = str_list(body, "requested_properties");
    if properties.is_empty() {
        properties = projection_visible.clone();
    }
    if let Some(bad) = subset_of(&properties, &policy_scope) {
        return Err(verr("lease_plan_scope_widening_rejected", format!("requested property '{bad}' is outside the policy scope — a lease plan cannot widen its gate")));
    }
    if let Some(bad) = subset_of(&properties, &projection_visible) {
        return Err(verr("lease_plan_scope_widening_rejected", format!("requested property '{bad}' is outside the projection's visible scope — a lease plan cannot widen the declared read shape")));
    }
    // Postures: echo the view's; a provided value that differs is a conflict (never relaxable here).
    for (key, view_key) in [
        ("retention_posture", "retention_posture"),
        ("export_posture", "export_posture"),
    ] {
        if let Some(provided) = opt_s(body, key) {
            let gate = s(&view, view_key, "");
            if provided != gate {
                return Err(verr("lease_plan_posture_conflict", format!("{key} '{provided}' differs from the policy view's '{gate}' — a lease plan echoes the gate, it never relaxes it")));
            }
        }
    }
    // TTL: bounded, always.
    let ttl_seconds = body
        .get("ttl_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if ttl_seconds == 0 || ttl_seconds > MAX_TTL_SECONDS {
        return Err(verr("lease_plan_ttl_unbounded", format!("ttl_seconds must be 1..={MAX_TTL_SECONDS} — a materializing-run credential is short-lived by construction")));
    }
    Ok(PlanInputs {
        source,
        mapping,
        view,
        run,
        projection,
        subject,
        purpose,
        operations,
        properties,
        ttl_seconds,
    })
}

fn plan_receipt(data_dir: &str, plan_ref: &str, op: &str, outcome: &str, summary: &str) -> Value {
    let id = format!("clpr_{:x}", nanos());
    let receipt_ref = format!("agentgres://capability-lease-plan-receipt/{id}");
    let rec = json!({
        "schema_version": RECEIPT_SCHEMA, "receipt_id": id, "receipt_ref": receipt_ref,
        "capability_lease_plan_ref": plan_ref, "op": op, "outcome": outcome, "summary": summary, "at": iso_now()
    });
    let _ = persist_record(data_dir, RECEIPT_DIR, &id, &rec);
    rec
}
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
/// Merge the validated lease shape onto the record — including the INERT invariants, every time.
fn apply_inputs(record: &mut Value, i: &PlanInputs) {
    record["data_source_id"] = i.source.get("source_id").cloned().unwrap_or(Value::Null);
    record["data_source_ref"] = i.source.get("source_ref").cloned().unwrap_or(Value::Null);
    record["credential_posture"] = i
        .source
        .get("credential_posture")
        .cloned()
        .unwrap_or(Value::Null);
    record["connector_mapping_id"] = i.mapping.get("id").cloned().unwrap_or(Value::Null);
    record["connector_mapping_ref"] = i.mapping.get("ref").cloned().unwrap_or(Value::Null);
    record["policy_view_id"] = i.view.get("id").cloned().unwrap_or(Value::Null);
    record["policy_view_ref"] = i.view.get("ref").cloned().unwrap_or(Value::Null);
    record["transformation_run_id"] = i.run.get("id").cloned().unwrap_or(Value::Null);
    record["transformation_run_ref"] = i.run.get("ref").cloned().unwrap_or(Value::Null);
    record["ontology_projection_id"] = i.projection.get("id").cloned().unwrap_or(Value::Null);
    record["ontology_projection_ref"] = i.projection.get("ref").cloned().unwrap_or(Value::Null);
    record["ontology_ref"] = i
        .mapping
        .get("ontology_ref")
        .cloned()
        .unwrap_or(Value::Null);
    record["object_type_id"] = i
        .mapping
        .get("object_type_id")
        .cloned()
        .unwrap_or(Value::Null);
    record["subject"] = json!(i.subject);
    record["purpose"] = json!(i.purpose);
    record["requested_operations"] = json!(i.operations);
    record["requested_properties"] = json!(i.properties);
    record["retention_posture"] = i
        .view
        .get("retention_posture")
        .cloned()
        .unwrap_or(Value::Null);
    record["export_posture"] = i.view.get("export_posture").cloned().unwrap_or(Value::Null);
    record["receipt_obligations"] = i
        .view
        .get("receipt_obligations")
        .cloned()
        .unwrap_or(json!([]));
    record["ttl_seconds"] = json!(i.ttl_seconds);
    record["gateway"] = json!({
        "primitive": LEASE_GATEWAY_PRIMITIVE,
        "route": LEASE_GATEWAY_ROUTE,
        "note": "the ONLY authority gateway — a future materializing run must obtain its lease HERE, citing this plan; this plane never mints"
    });
    record["lease"] = json!({ "minted": false, "credential_material": false, "note": "plan only — no usable credential exists or is produced here" });
    record["execution"] =
        json!({ "source_contacted": false, "data_moved": false, "object_instances": 0 });
    record["missing_authority"] = json!(MISSING_AUTHORITY);
}
fn bad(data_dir: &str, op: &str, err: VErr) -> (StatusCode, Json<Value>) {
    let _ = plan_receipt(
        data_dir,
        "capability-lease-plan://unadmitted",
        op,
        &err.0,
        &err.1,
    );
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": err.0, "message": err.1 } })),
    )
}
fn load_plan(data_dir: &str, id: &str) -> Option<Value> {
    find_by_key(data_dir, RECORD_DIR, "id", id)
}

/// GET /v1/hypervisor/odk/capability-lease-plans.
pub(crate) async fn handle_plans_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, RECORD_DIR);
    items.sort_by(|a, b| s(b, "updated_at", "").cmp(&s(a, "updated_at", "")));
    Json(
        json!({ "ok": true, "schema_version": PLAN_SCHEMA, "capability_lease_plans": items, "runtimeTruthSource": "daemon-runtime" }),
    )
}

/// GET /v1/hypervisor/odk/capability-lease-plans/overview.
pub(crate) async fn handle_plans_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
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
        "capability_lease_plans": items.len(),
        "lifecycle": { "declared": by("declared"), "revoked": by("revoked") },
        "gateway": { "primitive": LEASE_GATEWAY_PRIMITIVE, "route": LEASE_GATEWAY_ROUTE },
        "leaseable_postures": LEASEABLE_POSTURES,
        "max_ttl_seconds": MAX_TTL_SECONDS,
        "missing_authority": MISSING_AUTHORITY,
        "governance_gaps": [
            "PLAN only — no lease is minted, no credential material exists or is produced here",
            "the ONLY authority gateway is the existing CapabilityLease primitive; this plane never becomes a second lease system",
            "a MaterializingRun (live connector adapter) does not exist — it is the deliberate future cut that would cite a plan like this",
            "object_instances stays 0 everywhere; every refusal is receipted"
        ],
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// GET /v1/hypervisor/odk/capability-lease-plans/:id.
pub(crate) async fn handle_plan_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_plan(&st.data_dir, &id) {
        Some(r) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "capability_lease_plan": r })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "capability-lease plan not found" })),
        ),
    }
}

/// GET /v1/hypervisor/odk/capability-lease-plans/:id/history.
pub(crate) async fn handle_plan_history(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(r) = load_plan(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "capability-lease plan not found" })),
        );
    };
    let pref = s(&r, "ref", "");
    let mut receipts = read_record_dir(&st.data_dir, RECEIPT_DIR);
    receipts.retain(|x| {
        x.get("capability_lease_plan_ref").and_then(|v| v.as_str()) == Some(pref.as_str())
    });
    receipts.sort_by(|a, b| s(b, "at", "").cmp(&s(a, "at", "")));
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "capability_lease_plan_ref": pref, "revision": r.get("revision"), "status": r.get("status"), "history": r.get("history").cloned().unwrap_or(json!([])), "receipts": receipts }),
        ),
    )
}

/// POST /v1/hypervisor/odk/capability-lease-plans — declare a lease plan (fail-closed, receipted).
pub(crate) async fn handle_plan_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let inputs = match validate_inputs(&st.data_dir, &body) {
        Ok(i) => i,
        Err(e) => return bad(&st.data_dir, "create_rejected", e),
    };
    let id = format!("clp_{:x}", nanos());
    let now = iso_now();
    let pref = format!("capability-lease-plan://{id}");
    let receipt = plan_receipt(
        &st.data_dir,
        &pref,
        "created",
        "ok",
        "CapabilityLease plan declared (nothing minted)",
    );
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    let mut record = json!({
        "schema_version": PLAN_SCHEMA,
        "object": "ioi.hypervisor.odk.capability_lease_plan",
        "id": id,
        "ref": pref,
        "name": s(&body, "name", "capability-lease-plan"),
        "description": s(&body, "description", ""),
        "status": "declared",
        "revision": 1,
        "receipt_refs": [receipt_ref.clone()],
        "history": [ { "revision": 1, "op": "created", "at": now.clone(), "summary": "CapabilityLease plan declared (nothing minted)", "receipt_ref": receipt_ref } ],
        "created_at": now.clone(),
        "updated_at": now
    });
    apply_inputs(&mut record, &inputs);
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "capability_lease_plan": record })),
    )
}

/// PATCH — re-validate the merged plan against the CURRENT ladder; a malformed patch is a receipted
/// refusal with no state change. A revoked plan is immutable.
pub(crate) async fn handle_plan_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(patch): Json<Value>,
) -> Json<Value> {
    let Some(existing) = load_plan(&st.data_dir, &id) else {
        return Json(json!({ "ok": false, "reason": "capability-lease plan not found" }));
    };
    if s(&existing, "status", "") == "revoked" {
        return Json(
            json!({ "ok": false, "error": { "code": "lease_plan_revoked_immutable", "message": "a revoked plan is immutable" } }),
        );
    }
    let mut merged = json!({});
    let mo = merged.as_object_mut().unwrap();
    for k in [
        "name",
        "description",
        "data_source_id",
        "connector_mapping_id",
        "policy_view_id",
        "transformation_run_id",
        "ontology_projection_id",
        "subject",
        "purpose",
        "requested_operations",
        "requested_properties",
        "retention_posture",
        "export_posture",
        "ttl_seconds",
    ] {
        if let Some(v) = patch.get(k).or_else(|| existing.get(k)) {
            mo.insert(k.to_string(), v.clone());
        }
    }
    let inputs = match validate_inputs(&st.data_dir, &merged) {
        Ok(i) => i,
        Err(e) => {
            let _ = plan_receipt(
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
    apply_inputs(&mut record, &inputs);
    let rev = record.get("revision").and_then(|v| v.as_u64()).unwrap_or(1) + 1;
    record["revision"] = json!(rev);
    record["updated_at"] = json!(iso_now());
    let receipt = plan_receipt(
        &st.data_dir,
        &s(&record, "ref", ""),
        "patched",
        "ok",
        "CapabilityLease plan re-declared",
    );
    push_history(
        &mut record,
        "patched",
        "CapabilityLease plan re-declared",
        receipt.get("receipt_ref").cloned().unwrap_or(Value::Null),
    );
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    Json(json!({ "ok": true, "capability_lease_plan": record }))
}

/// POST /:id/revoke — terminal, receipted (withdrawing a declared lease request is auditable).
pub(crate) async fn handle_plan_revoke(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut record) = load_plan(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "reason": "capability-lease plan not found" })),
        );
    };
    if s(&record, "status", "") == "revoked" {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "ok": false, "error": { "code": "lease_plan_revoked_immutable", "message": "the plan is already revoked" } }),
            ),
        );
    }
    let receipt = plan_receipt(
        &st.data_dir,
        &s(&record, "ref", ""),
        "revoked",
        "ok",
        "CapabilityLease plan revoked",
    );
    record["status"] = json!("revoked");
    record["updated_at"] = json!(iso_now());
    push_history(
        &mut record,
        "revoked",
        "CapabilityLease plan revoked",
        receipt.get("receipt_ref").cloned().unwrap_or(Value::Null),
    );
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "capability_lease_plan": record })),
    )
}

/// DELETE — receipted removal.
pub(crate) async fn handle_plan_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let pref = load_plan(&st.data_dir, &id)
        .and_then(|r| r.get("ref").and_then(|v| v.as_str()).map(str::to_string))
        .unwrap_or_else(|| format!("capability-lease-plan://{id}"));
    let removed = remove_record(&st.data_dir, RECORD_DIR, &id);
    if removed {
        let _ = plan_receipt(
            &st.data_dir,
            &pref,
            "deleted",
            "ok",
            "CapabilityLease plan removed",
        );
    }
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

#[cfg(test)]
mod capability_lease_plan_tests {
    use super::*;

    #[test]
    fn gateway_is_the_existing_primitive_and_ttl_is_bounded() {
        assert_eq!(
            LEASE_GATEWAY_PRIMITIVE,
            "ioi.hypervisor.capability-lease.v1"
        );
        assert_eq!(LEASE_GATEWAY_ROUTE, "/v1/hypervisor/capability-leases");
        assert_eq!(MAX_TTL_SECONDS, 3600);
        assert_eq!(LEASEABLE_POSTURES, &["wallet_credential_lease"]);
    }

    #[test]
    fn bypass_keys_are_named() {
        assert!(ENV_FALLBACK_KEYS.contains(&"from_env"));
        assert!(RAW_QUERY_KEYS.contains(&"sql"));
        assert!(PLAINTEXT_SECRET_KEYS.contains(&"api_key"));
    }

    #[test]
    fn subset_of_finds_the_widening_element() {
        let sup = vec!["a".to_string(), "b".to_string()];
        assert_eq!(subset_of(&["a".to_string()], &sup), None);
        assert_eq!(
            subset_of(&["a".to_string(), "c".to_string()], &sup),
            Some("c".to_string())
        );
    }

    #[test]
    fn high_risk_ops_match_the_view_contract() {
        assert_eq!(
            HIGH_RISK_OPERATIONS,
            &["export", "publish", "train", "evaluate"]
        );
        assert!(MISSING_AUTHORITY.contains("MaterializingRun"));
    }
}
