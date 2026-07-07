//! MaterializingRun (lease acquisition) — the FIRST LIVE AUTHORITY CROSSING, kept deliberately
//! small: a run cites one ready CapabilityLease PLAN (#17) and may request and obtain a REAL
//! CapabilityLease from the EXISTING gateway (`authorize_capability_lease` — wallet-grant-verified,
//! persisted in the capability-leases audit trail). It must NOT contact the source, resolve or
//! unwrap credential material, extract rows, move data, or create object instances yet. Connector
//! execution and materialization are the NEXT cut (#19); this one proves only that wallet authority
//! can cross for exactly the declared shape.
//!
//! The crossing is authority-only by construction: `credential_connector_id: None` +
//! `credential_required: false` — the gateway verifies the bound wallet grant and mints the
//! no-secret lease descriptor WITHOUT resolving any backing credential. The returned bearer token
//! (if any) is DROPPED, never stored, never logged, never returned.
//!
//! Fail-closed: the cited plan must be `declared` and must still match CURRENT ladder truth
//! (re-checked at create AND at acquire — never cached); run-level overrides may only NARROW the
//! plan (operations ⊆ plan's and include transform; properties ⊆ plan's; ttl ≤ plan's; subject and
//! purpose unchanged); no plaintext secret, no env fallback, no raw query. After the lease is
//! obtained the scope is FROZEN (scope-affecting patches refused). Receipts record the request, the
//! gateway decision, the lease id/ref, bounded TTL, scope, refusal reasons, and release/cancel —
//! never credential material.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};
use crate::lifecycle_routes::{authorize_capability_lease, CapabilityLeaseRequest};

const RUN_SCHEMA: &str = "ioi.hypervisor.odk.materializing-run.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.odk.materializing-run-receipt.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.odk.materializing-runs-overview.v1";
pub(crate) const RECORD_DIR: &str = "odk-materializing-runs";
const RECEIPT_DIR: &str = "odk-materializing-run-receipts";

/// Lifecycle: a run exists, may obtain its lease, and may release it — nothing executes.
const LIFECYCLE_STATES: &[&str] = &["planned", "lease_obtained", "lease_released", "cancelled"];
/// What still does not exist after this rung — the two remaining cuts, named.
const MISSING_AUTHORITY: &[&str] = &["ConnectorExecution", "MaterializedRows"];
const PLAINTEXT_SECRET_KEYS: &[&str] = &["secret", "password", "api_key", "apikey", "token", "credential"];
const RAW_QUERY_KEYS: &[&str] = &["query", "sql", "raw_query", "statement", "command"];
const ENV_FALLBACK_KEYS: &[&str] = &["env", "env_var", "env_credential", "credential_env", "from_env"];

fn nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}
fn s(v: &Value, k: &str, d: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string()
}
fn opt_s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(str::trim).filter(|x| !x.is_empty()).map(str::to_string)
}
fn str_list(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect())
        .unwrap_or_default()
}
type VErr = (String, String);
fn verr(code: &str, msg: String) -> VErr {
    (code.to_string(), msg)
}
fn find_by_key(data_dir: &str, dir: &str, key: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, dir).into_iter().find(|r| r.get(key).and_then(|v| v.as_str()) == Some(id))
}
fn health_status(rec: &Value) -> String {
    rec.pointer("/health/status").and_then(|v| v.as_str()).unwrap_or("incomplete").to_string()
}
fn subset_of(sub: &[String], sup: &[String]) -> Option<String> {
    sub.iter().find(|x| !sup.iter().any(|y| y == *x)).cloned()
}

/// The run's validated shape: the cited plan (fresh from disk) + the (possibly narrowed) ask.
struct RunInputs {
    plan: Value,
    subject: String,
    purpose: String,
    operations: Vec<String>,
    properties: Vec<String>,
    ttl_seconds: u64,
}

/// Re-verify the cited plan against CURRENT ladder truth — the same drift discipline as every rung:
/// the gate is checked at each act, never cached. Returns the drifted thing's name on failure.
pub(crate) fn check_plan_against_truth(data_dir: &str, plan: &Value) -> Result<(), String> {
    let source_id = s(plan, "data_source_id", "");
    let source = find_by_key(data_dir, crate::data_source_routes::RECORD_DIR, "source_id", &source_id)
        .ok_or_else(|| format!("data source '{source_id}' no longer resolves"))?;
    if s(&source, "credential_posture", "") != "wallet_credential_lease" {
        return Err(format!("data source '{source_id}' posture is no longer wallet-leaseable"));
    }
    let mapping_id = s(plan, "connector_mapping_id", "");
    let mapping = find_by_key(data_dir, crate::connector_mapping_routes::RECORD_DIR, "id", &mapping_id)
        .ok_or_else(|| format!("mapping '{mapping_id}' no longer resolves"))?;
    if health_status(&mapping) != "ready" {
        return Err(format!("mapping '{mapping_id}' is no longer ready"));
    }
    let view_id = s(plan, "policy_view_id", "");
    let view = find_by_key(data_dir, crate::policy_bound_data_view_routes::RECORD_DIR, "id", &view_id)
        .ok_or_else(|| format!("policy view '{view_id}' no longer resolves"))?;
    if health_status(&view) != "ready" {
        return Err(format!("policy view '{view_id}' is no longer ready"));
    }
    let run_id = s(plan, "transformation_run_id", "");
    let trun = find_by_key(data_dir, crate::transformation_run_routes::RECORD_DIR, "id", &run_id)
        .ok_or_else(|| format!("transformation run '{run_id}' no longer resolves"))?;
    if s(&trun, "status", "") != "dry_run_ready" {
        return Err(format!("transformation run '{run_id}' is no longer dry_run_ready"));
    }
    let proj_id = s(plan, "ontology_projection_id", "");
    let proj = find_by_key(data_dir, crate::ontology_projection_routes::RECORD_DIR, "id", &proj_id)
        .ok_or_else(|| format!("projection '{proj_id}' no longer resolves"))?;
    if s(&proj, "status", "") != "ready" {
        return Err(format!("projection '{proj_id}' is no longer ready"));
    }
    // The gate must still authorize what the plan declared.
    let subjects = str_list(&view, "authority_subjects");
    if !subjects.iter().any(|x| x == &s(plan, "subject", "")) {
        return Err("the plan's subject is no longer authorized by the policy view".into());
    }
    if s(&view, "purpose", "") != s(plan, "purpose", "") {
        return Err("the plan's purpose no longer matches the policy view".into());
    }
    let view_ops = str_list(&view, "allowed_operations");
    if let Some(bad) = subset_of(&str_list(plan, "requested_operations"), &view_ops) {
        return Err(format!("the plan's operation '{bad}' is no longer authorized by the policy view"));
    }
    let scope = str_list(&view, "property_scope");
    let visible = str_list(&proj, "visible_properties");
    for p in str_list(plan, "requested_properties") {
        if !scope.iter().any(|x| x == &p) || !visible.iter().any(|x| x == &p) {
            return Err(format!("the plan's property '{p}' is no longer within policy scope + projection visibility"));
        }
    }
    Ok(())
}

/// Validate a run body fail-closed: bypass guards, a declared + truth-matching plan, and overrides
/// that only ever NARROW the plan.
fn validate_inputs(data_dir: &str, body: &Value) -> Result<RunInputs, VErr> {
    if let Some(obj) = body.as_object() {
        if PLAINTEXT_SECRET_KEYS.iter().any(|k| obj.contains_key(*k) && !obj[*k].is_null()) {
            return Err(verr("materializing_run_plaintext_secret_rejected", "A materializing run never carries credential material.".into()));
        }
        if RAW_QUERY_KEYS.iter().any(|k| obj.contains_key(*k) && !obj[*k].is_null()) {
            return Err(verr("materializing_run_raw_query_rejected", "A materializing run never carries a raw source query.".into()));
        }
        if ENV_FALLBACK_KEYS.iter().any(|k| obj.contains_key(*k) && !obj[*k].is_null()) {
            return Err(verr("materializing_run_env_fallback_rejected", "Environment-credential fallback is an authority bypass — the only gateway is the CapabilityLease primitive.".into()));
        }
    }
    if opt_s(body, "name").is_none() {
        return Err(verr("materializing_run_name_required", "A materializing run requires a name.".into()));
    }
    let plan_id = opt_s(body, "capability_lease_plan_id").unwrap_or_default();
    let plan = find_by_key(data_dir, crate::capability_lease_plan_routes::RECORD_DIR, "id", &plan_id)
        .ok_or_else(|| verr("materializing_run_plan_unknown", format!("capability_lease_plan_id '{plan_id}' does not resolve to a declared plan")))?;
    if s(&plan, "status", "") != "declared" {
        return Err(verr("materializing_run_plan_not_declared", format!("plan '{plan_id}' is '{}' — a run cites only a declared plan", s(&plan, "status", ""))));
    }
    if let Err(drift) = check_plan_against_truth(data_dir, &plan) {
        return Err(verr("materializing_run_plan_drift", format!("the cited plan no longer matches current truth: {drift}")));
    }
    // Subject + purpose: UNCHANGED (inherited when absent).
    let plan_subject = s(&plan, "subject", "");
    let subject = opt_s(body, "subject").unwrap_or_else(|| plan_subject.clone());
    if subject != plan_subject {
        return Err(verr("materializing_run_subject_mismatch", format!("run subject '{subject}' differs from the plan's '{plan_subject}' — a run cannot re-assign authority")));
    }
    let plan_purpose = s(&plan, "purpose", "");
    let purpose = opt_s(body, "purpose").unwrap_or_else(|| plan_purpose.clone());
    if purpose != plan_purpose {
        return Err(verr("materializing_run_purpose_mismatch", format!("run purpose '{purpose}' differs from the plan's '{plan_purpose}'")));
    }
    // Operations / properties / TTL: unchanged or NARROWED, never widened.
    let plan_ops = str_list(&plan, "requested_operations");
    let mut operations = str_list(body, "requested_operations");
    if operations.is_empty() {
        operations = plan_ops.clone();
    }
    if let Some(bad) = subset_of(&operations, &plan_ops) {
        return Err(verr("materializing_run_operation_widening_rejected", format!("operation '{bad}' is not in the cited plan — a run can only narrow, never widen")));
    }
    if !operations.iter().any(|o| o == "transform") {
        return Err(verr("materializing_run_operation_widening_rejected", "a materializing run must retain 'transform'".into()));
    }
    let plan_props = str_list(&plan, "requested_properties");
    let mut properties = str_list(body, "requested_properties");
    if properties.is_empty() {
        properties = plan_props.clone();
    }
    if let Some(bad) = subset_of(&properties, &plan_props) {
        return Err(verr("materializing_run_scope_widening_rejected", format!("property '{bad}' is not in the cited plan — a run can only narrow, never widen")));
    }
    let plan_ttl = plan.get("ttl_seconds").and_then(|v| v.as_u64()).unwrap_or(0);
    let ttl_seconds = body.get("ttl_seconds").and_then(|v| v.as_u64()).unwrap_or(plan_ttl);
    if ttl_seconds == 0 || ttl_seconds > plan_ttl {
        return Err(verr("materializing_run_ttl_widening_rejected", format!("ttl_seconds must be 1..={plan_ttl} (the plan's bound) — a run can only narrow, never widen")));
    }
    Ok(RunInputs { plan, subject, purpose, operations, properties, ttl_seconds })
}

fn run_receipt(data_dir: &str, run_ref: &str, op: &str, outcome: &str, summary: &str) -> Value {
    let id = format!("mrr_{:x}", nanos());
    let receipt_ref = format!("agentgres://materializing-run-receipt/{id}");
    let rec = json!({
        "schema_version": RECEIPT_SCHEMA, "receipt_id": id, "receipt_ref": receipt_ref,
        "materializing_run_ref": run_ref, "op": op, "outcome": outcome, "summary": summary, "at": iso_now()
    });
    let _ = persist_record(data_dir, RECEIPT_DIR, &id, &rec);
    rec
}
fn push_history(record: &mut Value, op: &str, summary: &str, receipt_ref: Value) {
    let rev = record.get("revision").and_then(|v| v.as_u64()).unwrap_or(1);
    let mut hist = record.get("history").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    hist.push(json!({ "revision": rev, "op": op, "at": iso_now(), "summary": summary, "receipt_ref": receipt_ref.clone() }));
    let len = hist.len();
    if len > 20 {
        hist = hist[len - 20..].to_vec();
    }
    record["history"] = json!(hist);
    let mut refs = record.get("receipt_refs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    refs.push(receipt_ref);
    record["receipt_refs"] = json!(refs);
}
fn apply_inputs(record: &mut Value, i: &RunInputs) {
    record["capability_lease_plan_id"] = i.plan.get("id").cloned().unwrap_or(Value::Null);
    record["capability_lease_plan_ref"] = i.plan.get("ref").cloned().unwrap_or(Value::Null);
    record["data_source_id"] = i.plan.get("data_source_id").cloned().unwrap_or(Value::Null);
    record["ontology_ref"] = i.plan.get("ontology_ref").cloned().unwrap_or(Value::Null);
    record["object_type_id"] = i.plan.get("object_type_id").cloned().unwrap_or(Value::Null);
    record["subject"] = json!(i.subject);
    record["purpose"] = json!(i.purpose);
    record["requested_operations"] = json!(i.operations);
    record["requested_properties"] = json!(i.properties);
    record["ttl_seconds"] = json!(i.ttl_seconds);
    record["execution"] = json!({ "source_contacted": false, "data_moved": false, "rows_extracted": 0, "object_instances": 0, "note": "lease acquisition only — connector execution and materialization are the next cut" });
    record["missing_authority"] = json!(MISSING_AUTHORITY);
}
fn bad(data_dir: &str, op: &str, err: VErr) -> (StatusCode, Json<Value>) {
    let _ = run_receipt(data_dir, "materializing-run://unadmitted", op, &err.0, &err.1);
    (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": err.0, "message": err.1 } })))
}
fn load_run(data_dir: &str, id: &str) -> Option<Value> {
    find_by_key(data_dir, RECORD_DIR, "id", id)
}

/// GET /v1/hypervisor/odk/materializing-runs.
pub(crate) async fn handle_mruns_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, RECORD_DIR);
    items.sort_by(|a, b| s(b, "updated_at", "").cmp(&s(a, "updated_at", "")));
    Json(json!({ "ok": true, "schema_version": RUN_SCHEMA, "materializing_runs": items, "runtimeTruthSource": "daemon-runtime" }))
}

/// GET /v1/hypervisor/odk/materializing-runs/overview.
pub(crate) async fn handle_mruns_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let items = read_record_dir(&st.data_dir, RECORD_DIR);
    let by = |status: &str| items.iter().filter(|r| s(r, "status", "") == status).count();
    Json(json!({
        "ok": true,
        "schema_version": OVERVIEW_SCHEMA,
        "materializing_runs": items.len(),
        "lifecycle": { "planned": by("planned"), "lease_obtained": by("lease_obtained"), "lease_released": by("lease_released"), "cancelled": by("cancelled") },
        "lifecycle_states": LIFECYCLE_STATES,
        "missing_authority": MISSING_AUTHORITY,
        "governance_gaps": [
            "LEASE ACQUISITION ONLY — a run may obtain a real wallet-gated CapabilityLease from the existing gateway; it never contacts the source, resolves credentials, extracts rows, or creates object instances",
            "the crossing is authority-only by construction: no backing credential is resolved; any bearer token is dropped, never stored, never logged, never returned",
            "connector execution and materialized rows are the NEXT cut — object_instances stays 0",
            "receipts record request, gateway decision, lease id/ref, TTL, scope, refusals, release/cancel — never credential material"
        ],
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// GET /v1/hypervisor/odk/materializing-runs/:id.
pub(crate) async fn handle_mrun_get(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> (StatusCode, Json<Value>) {
    match load_run(&st.data_dir, &id) {
        Some(r) => (StatusCode::OK, Json(json!({ "ok": true, "materializing_run": r }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "materializing run not found" }))),
    }
}

/// GET /v1/hypervisor/odk/materializing-runs/:id/history.
pub(crate) async fn handle_mrun_history(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> (StatusCode, Json<Value>) {
    let Some(r) = load_run(&st.data_dir, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "materializing run not found" })));
    };
    let rref = s(&r, "ref", "");
    let mut receipts = read_record_dir(&st.data_dir, RECEIPT_DIR);
    receipts.retain(|x| x.get("materializing_run_ref").and_then(|v| v.as_str()) == Some(rref.as_str()));
    receipts.sort_by(|a, b| s(b, "at", "").cmp(&s(a, "at", "")));
    (StatusCode::OK, Json(json!({ "ok": true, "materializing_run_ref": rref, "revision": r.get("revision"), "status": r.get("status"), "history": r.get("history").cloned().unwrap_or(json!([])), "receipts": receipts })))
}

/// POST /v1/hypervisor/odk/materializing-runs — admit a run (planned; no lease yet).
pub(crate) async fn handle_mrun_create(State(st): State<Arc<DaemonState>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let inputs = match validate_inputs(&st.data_dir, &body) {
        Ok(i) => i,
        Err(e) => return bad(&st.data_dir, "create_rejected", e),
    };
    let id = format!("mrun_{:x}", nanos());
    let now = iso_now();
    let rref = format!("materializing-run://{id}");
    let receipt = run_receipt(&st.data_dir, &rref, "created", "ok", "MaterializingRun admitted (no lease yet)");
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    let mut record = json!({
        "schema_version": RUN_SCHEMA,
        "object": "ioi.hypervisor.odk.materializing_run",
        "id": id,
        "ref": rref,
        "name": s(&body, "name", "materializing-run"),
        "description": s(&body, "description", ""),
        "status": "planned",
        "lease": { "obtained": false, "credential_material": false },
        "revision": 1,
        "receipt_refs": [receipt_ref.clone()],
        "history": [ { "revision": 1, "op": "created", "at": now.clone(), "summary": "MaterializingRun admitted (no lease yet)", "receipt_ref": receipt_ref } ],
        "created_at": now.clone(),
        "updated_at": now
    });
    apply_inputs(&mut record, &inputs);
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "materializing_run": record })))
}

/// POST /:id/acquire-lease — THE live crossing. Re-checks the plan against current truth, then asks
/// the EXISTING gateway for a real lease under the run's (narrowed) shape. Without a bound wallet
/// grant the gateway's 403 challenge is returned verbatim (and the refusal receipted). On success
/// the lease descriptor's SAFE fields land on the record; any bearer token is dropped.
pub(crate) async fn handle_mrun_acquire_lease(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let Some(mut record) = load_run(&st.data_dir, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "materializing run not found" })));
    };
    let status = s(&record, "status", "");
    if status == "lease_obtained" {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": "materializing_run_lease_already_obtained", "message": "the run already holds its lease" } })));
    }
    if status == "cancelled" || status == "lease_released" {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": "materializing_run_terminal_immutable", "message": format!("a {status} run is immutable") } })));
    }
    let rref = s(&record, "ref", "");
    // Re-validate the cited plan against CURRENT truth — the gate is never cached.
    let plan_id = s(&record, "capability_lease_plan_id", "");
    let Some(plan) = find_by_key(&st.data_dir, crate::capability_lease_plan_routes::RECORD_DIR, "id", &plan_id) else {
        let e = verr("materializing_run_plan_drift", format!("the cited plan '{plan_id}' no longer resolves"));
        let _ = run_receipt(&st.data_dir, &rref, "lease_refused", &e.0, &e.1);
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": e.0, "message": e.1 } })));
    };
    if s(&plan, "status", "") != "declared" {
        let e = verr("materializing_run_plan_not_declared", "the cited plan is no longer declared".into());
        let _ = run_receipt(&st.data_dir, &rref, "lease_refused", &e.0, &e.1);
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": e.0, "message": e.1 } })));
    }
    if let Err(drift) = check_plan_against_truth(&st.data_dir, &plan) {
        let e = verr("materializing_run_plan_drift", format!("the cited plan no longer matches current truth: {drift}"));
        let _ = run_receipt(&st.data_dir, &rref, "lease_refused", &e.0, &e.1);
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": e.0, "message": e.1 } })));
    }
    // Build the gateway request — authority-only: no credential resolution in this cut.
    let operations = str_list(&record, "requested_operations");
    let properties = str_list(&record, "requested_properties");
    let ttl = record.get("ttl_seconds").and_then(|v| v.as_u64()).unwrap_or(0);
    let lease_req = CapabilityLeaseRequest {
        authority_provider_ref: "wallet.network".to_string(),
        backing_provider: "none".to_string(),
        allowed_tools: operations.iter().map(|o| format!("odk.materialize.{o}")).collect(),
        resource_refs: vec![
            s(&plan, "ref", ""),
            s(&plan, "connector_mapping_ref", ""),
            s(&plan, "policy_view_ref", ""),
            s(&plan, "transformation_run_ref", ""),
            s(&plan, "ontology_projection_ref", ""),
            s(&plan, "data_source_ref", ""),
        ],
        scopes: operations.clone(),
        policy_domain: "hypervisor.odk.materialize.policy.v1".to_string(),
        request_domain: "hypervisor.odk.materialize.request.v1".to_string(),
        request_facets: json!({
            "materializing_run_id": s(&record, "id", ""),
            "capability_lease_plan_ref": s(&plan, "ref", ""),
            "subject": s(&record, "subject", ""),
            "purpose": s(&record, "purpose", ""),
            "properties": properties,
            "ttl_seconds": ttl
        }),
        credential_connector_id: None,
        credential_store: "connector-credentials".to_string(),
        credential_required: false,
        github_host_fallback: false,
        receipt_required: true,
        revocation_ref: format!("odk-materializing-runs/{id}/lease"),
        authority_reason: "odk_materialize_lease_authority_required".to_string(),
        grant_value: body.get("wallet_approval_grant").cloned().unwrap_or(Value::Null),
    };
    let _ = run_receipt(&st.data_dir, &rref, "lease_requested", "ok", &format!("lease requested at the gateway: {} ops · {} properties · ttl {ttl}s", operations.len(), properties.len()));
    match authorize_capability_lease(&st, &lease_req).await {
        Err((code, challenge)) => {
            // The gateway refused (403 authority challenge / other). Receipt the decision; return verbatim.
            let reason = challenge.get("reason").and_then(|v| v.as_str()).unwrap_or("refused").to_string();
            let _ = run_receipt(&st.data_dir, &rref, "lease_refused", &reason, "gateway refused the crossing (challenge returned verbatim; no lease minted)");
            (code, Json(challenge))
        }
        Ok(lease) => {
            // SAFE fields only — the descriptor carries no secret; the bearer token is DROPPED here.
            drop(lease.token);
            let d = &lease.descriptor;
            let lease_id = s(d, "lease_id", "");
            record["status"] = json!("lease_obtained");
            record["lease"] = json!({
                "obtained": true,
                "credential_material": false,
                "lease_id": lease_id,
                "lease_ref": format!("capability-lease://{lease_id}"),
                "grant_ref": lease.grant_ref,
                "policy_hash": d.get("policy_hash").cloned().unwrap_or(Value::Null),
                "request_hash": d.get("request_hash").cloned().unwrap_or(Value::Null),
                "allowed_tools": d.get("allowed_tools").cloned().unwrap_or(json!([])),
                "expires_at": d.get("expires_at").cloned().unwrap_or(Value::Null),
                "ttl_seconds": ttl,
                "note": "real gateway lease — authority-only (no credential resolved); execution is the next cut"
            });
            record["updated_at"] = json!(iso_now());
            let receipt = run_receipt(&st.data_dir, &rref, "lease_obtained", "ok", &format!("gateway minted lease {lease_id} (ttl {ttl}s, {} properties) — no credential material", properties.len()));
            push_history(&mut record, "lease_obtained", &format!("lease {lease_id} obtained from the gateway"), receipt.get("receipt_ref").cloned().unwrap_or(Value::Null));
            let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
            (StatusCode::OK, Json(json!({ "ok": true, "materializing_run": record })))
        }
    }
}

/// POST /:id/release-lease — receipted release of the held lease (terminal for this run).
pub(crate) async fn handle_mrun_release_lease(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> (StatusCode, Json<Value>) {
    let Some(mut record) = load_run(&st.data_dir, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "materializing run not found" })));
    };
    if s(&record, "status", "") != "lease_obtained" {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": "materializing_run_no_lease_to_release", "message": "the run holds no lease" } })));
    }
    let lease_id = record.pointer("/lease/lease_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let receipt = run_receipt(&st.data_dir, &s(&record, "ref", ""), "lease_released", "ok", &format!("lease {lease_id} released (never used — no execution exists)"));
    record["status"] = json!("lease_released");
    record["lease"]["obtained"] = json!(false);
    record["lease"]["released_at"] = json!(iso_now());
    record["updated_at"] = json!(iso_now());
    push_history(&mut record, "lease_released", &format!("lease {lease_id} released"), receipt.get("receipt_ref").cloned().unwrap_or(Value::Null));
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    (StatusCode::OK, Json(json!({ "ok": true, "materializing_run": record })))
}

/// POST /:id/cancel — terminal from `planned`, receipted.
pub(crate) async fn handle_mrun_cancel(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> (StatusCode, Json<Value>) {
    let Some(mut record) = load_run(&st.data_dir, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "materializing run not found" })));
    };
    if s(&record, "status", "") != "planned" {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": "materializing_run_terminal_immutable", "message": "only a planned run can be cancelled (release the lease instead)" } })));
    }
    let receipt = run_receipt(&st.data_dir, &s(&record, "ref", ""), "cancelled", "ok", "MaterializingRun cancelled before any crossing");
    record["status"] = json!("cancelled");
    record["updated_at"] = json!(iso_now());
    push_history(&mut record, "cancelled", "MaterializingRun cancelled before any crossing", receipt.get("receipt_ref").cloned().unwrap_or(Value::Null));
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    (StatusCode::OK, Json(json!({ "ok": true, "materializing_run": record })))
}

/// PATCH — name/description freely; scope keys re-validate narrow-only while `planned`; once the
/// lease is obtained the scope is FROZEN. Malformed patch is a receipted refusal, no state change.
pub(crate) async fn handle_mrun_patch(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>, Json(patch): Json<Value>) -> Json<Value> {
    let Some(existing) = load_run(&st.data_dir, &id) else {
        return Json(json!({ "ok": false, "reason": "materializing run not found" }));
    };
    let status = s(&existing, "status", "");
    if status == "cancelled" || status == "lease_released" {
        return Json(json!({ "ok": false, "error": { "code": "materializing_run_terminal_immutable", "message": format!("a {status} run is immutable") } }));
    }
    let scope_keys = ["capability_lease_plan_id", "subject", "purpose", "requested_operations", "requested_properties", "ttl_seconds"];
    let scope_affecting = scope_keys.iter().any(|k| patch.get(*k).is_some());
    if scope_affecting && status == "lease_obtained" {
        let _ = run_receipt(&st.data_dir, &s(&existing, "ref", ""), "patch_rejected", "materializing_run_scope_frozen", "scope-affecting patch refused — the obtained lease's scope is frozen");
        return Json(json!({ "ok": false, "error": { "code": "materializing_run_scope_frozen", "message": "the lease is obtained — its scope is frozen; release it to re-plan" } }));
    }
    let mut record = existing;
    if scope_affecting {
        let mut merged = json!({});
        let mo = merged.as_object_mut().unwrap();
        for k in ["name", "capability_lease_plan_id", "subject", "purpose", "requested_operations", "requested_properties", "ttl_seconds"] {
            if let Some(v) = patch.get(k).or_else(|| record.get(k)) {
                mo.insert(k.to_string(), v.clone());
            }
        }
        let inputs = match validate_inputs(&st.data_dir, &merged) {
            Ok(i) => i,
            Err(e) => {
                let _ = run_receipt(&st.data_dir, &s(&record, "ref", ""), "patch_rejected", &e.0, &e.1);
                return Json(json!({ "ok": false, "error": { "code": e.0, "message": e.1 } }));
            }
        };
        apply_inputs(&mut record, &inputs);
    }
    if let Some(v) = patch.get("name") { record["name"] = v.clone(); }
    if let Some(v) = patch.get("description") { record["description"] = v.clone(); }
    let rev = record.get("revision").and_then(|v| v.as_u64()).unwrap_or(1) + 1;
    record["revision"] = json!(rev);
    record["updated_at"] = json!(iso_now());
    let receipt = run_receipt(&st.data_dir, &s(&record, "ref", ""), "patched", "ok", if scope_affecting { "run re-narrowed against the plan" } else { "metadata edit" });
    push_history(&mut record, "patched", if scope_affecting { "run re-narrowed against the plan" } else { "metadata edit" }, receipt.get("receipt_ref").cloned().unwrap_or(Value::Null));
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    Json(json!({ "ok": true, "materializing_run": record }))
}

/// DELETE — receipted removal.
pub(crate) async fn handle_mrun_delete(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    let rref = load_run(&st.data_dir, &id)
        .and_then(|r| r.get("ref").and_then(|v| v.as_str()).map(str::to_string))
        .unwrap_or_else(|| format!("materializing-run://{id}"));
    let removed = remove_record(&st.data_dir, RECORD_DIR, &id);
    if removed {
        let _ = run_receipt(&st.data_dir, &rref, "deleted", "ok", "MaterializingRun removed");
    }
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

#[cfg(test)]
mod materializing_run_tests {
    use super::*;

    #[test]
    fn lifecycle_and_missing_authority_are_explicit() {
        assert_eq!(LIFECYCLE_STATES, &["planned", "lease_obtained", "lease_released", "cancelled"]);
        assert_eq!(MISSING_AUTHORITY, &["ConnectorExecution", "MaterializedRows"]);
    }

    #[test]
    fn bypass_keys_are_named() {
        assert!(PLAINTEXT_SECRET_KEYS.contains(&"token"));
        assert!(RAW_QUERY_KEYS.contains(&"sql"));
        assert!(ENV_FALLBACK_KEYS.contains(&"from_env"));
    }

    #[test]
    fn subset_of_finds_the_widening_element() {
        let sup = vec!["read".to_string(), "transform".to_string()];
        assert_eq!(subset_of(&["transform".to_string()], &sup), None);
        assert_eq!(subset_of(&["transform".to_string(), "export".to_string()], &sup), Some("export".to_string()));
    }
}
