//! Connector execution + materialized rows — the FINAL rung of the ODK ratchet: the first cut where
//! a projection's `object_instances` may become NONZERO. One narrow read-only adapter path, not a
//! generic ingestion engine:
//!
//!   * a MaterializingRun that HOLDS its lease (#18) and has an OPENED sealed session (#19) may
//!     execute ONE bounded read-only batch against an ALLOWLISTED connector kind (v1: `rest_api`);
//!   * the adapter reads the DECLARED source shape only — a single GET of the data source's declared
//!     endpoint; never caller SQL, never caller-shaped URLs;
//!   * the sealed credential is resolved IN-MEMORY at read time, used for the Authorization header,
//!     and dropped — never stored, logged, returned, or receipted;
//!   * every fetched row transforms through the landed ladder (ConnectorMapping fields → typed
//!     properties, scoped by the run's lease scope) and validates fully: valid key + title on every
//!     row, every typed value validates — ONE malformed row rejects the WHOLE batch (all-or-nothing,
//!     no partial truth);
//!   * the PRE-OUTPUT receipt must persist BEFORE any materialized output record exists — a receipt
//!     write failure aborts the registration;
//!   * the materialized set stores ontology-bound object records + source hashes + provenance, and
//!     updates ONLY the tied projection's materialized state;
//!   * no actions, writeback, export, train, evaluate, publish, or route — read → validate → register.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};
use crate::lifecycle_routes::resolve_sealed_credential;

const SET_SCHEMA: &str = "ioi.hypervisor.odk.materialized-object-set.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.odk.materialized-object-sets-overview.v1";
pub(crate) const SET_DIR: &str = "odk-materialized-object-sets";
/// Receipts land on the RUN's stream — execution is an act of the run.
const RUN_RECEIPT_SCHEMA: &str = "ioi.hypervisor.odk.materializing-run-receipt.v1";
const RUN_RECEIPT_DIR: &str = "odk-materializing-run-receipts";

/// v1 allowlist: exactly one read-only adapter path.
const SUPPORTED_EXECUTION_KINDS: &[&str] = &["rest_api"];
const MAX_BATCH_LIMIT: u64 = 500;
const PLAINTEXT_SECRET_KEYS: &[&str] = &["secret", "password", "api_key", "apikey", "token", "credential"];
const RAW_QUERY_KEYS: &[&str] = &["query", "sql", "raw_query", "statement", "command"];
const ENV_FALLBACK_KEYS: &[&str] = &["env", "env_var", "env_credential", "credential_env", "from_env"];

fn nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}
fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
fn s(v: &Value, k: &str, d: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string()
}
fn str_list(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).map(str::to_string).collect())
        .unwrap_or_default()
}
fn find_by_key(data_dir: &str, dir: &str, key: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, dir).into_iter().find(|r| r.get(key).and_then(|v| v.as_str()) == Some(id))
}
fn expired(expires_at: &Value, now_millis: i64) -> bool {
    expires_at.as_i64().map(|e| e < now_millis).unwrap_or(false)
}
/// Endpoint form for receipts/provenance/records: userinfo and query are stripped — declared truth
/// and audit trails carry host + path only (the GET itself uses the declared endpoint verbatim).
fn redacted_endpoint(endpoint: &str) -> String {
    let (scheme, rest) = match endpoint.split_once("://") {
        Some((sc, r)) => (sc, r),
        None => return endpoint.split(['?', '#']).next().unwrap_or(endpoint).to_string(),
    };
    let had_query = rest.contains('?');
    let no_q = rest.split(['?', '#']).next().unwrap_or(rest);
    let no_user = match no_q.rsplit_once('@') {
        Some((_, host)) => host,
        None => no_q,
    };
    format!("{scheme}://{no_user}{}", if had_query { "?…redacted" } else { "" })
}
fn sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    format!("sha256:{:x}", h.finalize())
}
/// A fetched source value must match the mapping's DECLARED source_type (conservative, no coercion).
fn value_matches_source_type(v: &Value, source_type: &str) -> bool {
    match source_type {
        "string" | "timestamp" | "date" => v.is_string(),
        "integer" => v.as_i64().is_some(),
        "double" => v.is_number(),
        "boolean" => v.is_boolean(),
        "json" => !v.is_null(),
        _ => false,
    }
}
/// The mapping bindings relevant to this run: (property_id, source_field, source_type, role).
fn run_bindings(mapping: &Value, requested: &[String]) -> Vec<(String, String, String, &'static str)> {
    let mut out: Vec<(String, String, String, &'static str)> = Vec::new();
    let mut push = |m: &Value, role: &'static str| {
        let pid = s(m, "property_id", "");
        if !pid.is_empty() {
            out.push((pid, s(m, "source_field", ""), s(m, "source_type", "string"), role));
        }
    };
    if let Some(m) = mapping.get("key_mapping") {
        push(m, "key");
    }
    if let Some(m) = mapping.get("title_mapping") {
        push(m, "title");
    }
    if let Some(fs) = mapping.get("field_mappings").and_then(|v| v.as_array()) {
        for f in fs {
            push(f, "field");
        }
    }
    // Key + title always participate (identity is never optional); other fields only when requested.
    out.retain(|(pid, _, _, role)| *role != "field" || requested.iter().any(|r| r == pid));
    out
}

/// Receipt on the RUN's stream. Returns Err when the receipt itself cannot persist — callers that
/// are about to register OUTPUT must abort on that (receipts land BEFORE output, or nothing does).
fn run_receipt_checked(data_dir: &str, run_ref: &str, op: &str, outcome: &str, summary: &str) -> Result<Value, String> {
    let id = format!("mrr_{:x}", nanos());
    let receipt_ref = format!("agentgres://materializing-run-receipt/{id}");
    let rec = json!({
        "schema_version": RUN_RECEIPT_SCHEMA, "receipt_id": id, "receipt_ref": receipt_ref,
        "materializing_run_ref": run_ref, "op": op, "outcome": outcome, "summary": summary, "at": iso_now()
    });
    persist_record(data_dir, RUN_RECEIPT_DIR, &id, &rec).map_err(|e| e.to_string())?;
    Ok(rec)
}
fn run_receipt(data_dir: &str, run_ref: &str, op: &str, outcome: &str, summary: &str) -> Value {
    run_receipt_checked(data_dir, run_ref, op, outcome, summary).unwrap_or(Value::Null)
}
fn push_history(record: &mut Value, op: &str, summary: &str, receipt: &Value) {
    let rev = record.get("revision").and_then(|v| v.as_u64()).unwrap_or(1);
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
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
fn refuse(data_dir: &str, run_ref: &str, status: StatusCode, code: &str, msg: &str) -> (StatusCode, Json<Value>) {
    let _ = run_receipt(data_dir, run_ref, "execution_refused", code, msg);
    (status, Json(json!({ "ok": false, "error": { "code": code, "message": msg } })))
}

/// POST /v1/hypervisor/odk/materializing-runs/:id/execute — THE materialization. One bounded
/// read-only batch through the landed ladder, receipted before output, all-or-nothing.
pub(crate) async fn handle_run_execute(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let data_dir = st.data_dir.clone();
    let Some(mut run) = find_by_key(&data_dir, crate::materializing_run_routes::RECORD_DIR, "id", &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "materializing run not found" })));
    };
    let run_ref = s(&run, "ref", "");
    // Bypass guards — an execution request carries NO query shape and NO credential material.
    if let Some(obj) = body.as_object() {
        if PLAINTEXT_SECRET_KEYS.iter().any(|k| obj.contains_key(*k) && !obj[*k].is_null()) {
            return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_plaintext_secret_rejected", "an execution request never carries credential material");
        }
        if RAW_QUERY_KEYS.iter().any(|k| obj.contains_key(*k) && !obj[*k].is_null()) {
            return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_raw_query_rejected", "the adapter reads the DECLARED source shape only — caller queries never exist");
        }
        if ENV_FALLBACK_KEYS.iter().any(|k| obj.contains_key(*k) && !obj[*k].is_null()) {
            return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_env_fallback_rejected", "environment-credential fallback is an authority bypass");
        }
    }
    // Lifecycle: exactly one bounded batch per run (idempotency is explicit).
    let status = s(&run, "status", "");
    if status == "executed" {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": "execution_already_registered", "message": "this run already registered its batch — one bounded batch per run (v1); plan a new run for another batch" } })));
    }
    if status != "lease_obtained" {
        return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_lease_not_obtained", &format!("run is '{status}' — execution requires a HELD lease"));
    }
    if expired(run.pointer("/lease/expires_at").unwrap_or(&Value::Null), now_ms()) {
        return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_lease_expired", "the run's lease has expired");
    }
    // Bounded batch.
    let limit = body.get("limit").and_then(|v| v.as_u64()).unwrap_or(100);
    if limit == 0 || limit > MAX_BATCH_LIMIT {
        return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_limit_unbounded", &format!("limit must be 1..={MAX_BATCH_LIMIT}"));
    }
    // Ladder re-check at the moment of execution — never cached.
    let plan_id = s(&run, "capability_lease_plan_id", "");
    let Some(plan) = find_by_key(&data_dir, crate::capability_lease_plan_routes::RECORD_DIR, "id", &plan_id) else {
        return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_ladder_drift", "the run's plan no longer resolves");
    };
    if let Err(drift) = crate::materializing_run_routes::check_plan_against_truth(&data_dir, &plan) {
        return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_ladder_drift", &format!("the ladder no longer matches: {drift}"));
    }
    // Allowlisted connector kind — checked from the DECLARED source, before any session lookup.
    let source_id = s(&plan, "data_source_id", "");
    let Some(source) = find_by_key(&data_dir, crate::data_source_routes::RECORD_DIR, "source_id", &source_id) else {
        return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_ladder_drift", "the data source no longer resolves");
    };
    let kind = s(&source, "kind", "");
    if !SUPPORTED_EXECUTION_KINDS.contains(&kind.as_str()) {
        return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_connector_kind_unsupported", &format!("source kind '{kind}' has no allowlisted adapter in v1 (supported: {SUPPORTED_EXECUTION_KINDS:?})"));
    }
    // The sealed session: opened, unexpired, and tied to THIS run.
    let session_id = s(&body, "connector_session_id", "");
    let Some(session) = find_by_key(&data_dir, crate::connector_session_routes::RECORD_DIR, "id", &session_id) else {
        return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_session_unknown", "connector_session_id does not resolve");
    };
    if session.get("materializing_run_id").and_then(|v| v.as_str()) != Some(id.as_str()) {
        return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_session_mismatch", "the session is not tied to this run");
    }
    if s(&session, "status", "") != "session_obtained" {
        return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_session_not_open", &format!("session is '{}' — execution requires an OPEN sealed session", s(&session, "status", "")));
    }
    if expired(session.pointer("/session/expires_at").unwrap_or(&Value::Null), now_ms()) {
        return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_session_expired", "the sealed session has expired");
    }
    // The tied projection (the ONLY thing whose materialized state may change).
    let projection_id = s(&plan, "ontology_projection_id", "");
    let Some(mut projection) = find_by_key(&data_dir, crate::ontology_projection_routes::RECORD_DIR, "id", &projection_id) else {
        return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_ladder_drift", "the tied projection no longer resolves");
    };
    let mapping_id = s(&plan, "connector_mapping_id", "");
    let Some(mapping) = find_by_key(&data_dir, crate::connector_mapping_routes::RECORD_DIR, "id", &mapping_id) else {
        return refuse(&data_dir, &run_ref, StatusCode::BAD_REQUEST, "execution_ladder_drift", "the mapping no longer resolves");
    };

    let receipt = run_receipt(&data_dir, &run_ref, "execution_requested", "ok", &format!("read-only execution requested: kind {kind} · limit {limit} · session {}", s(&session, "id", "")));
    push_history(&mut run, "execution_requested", "read-only execution requested", &receipt);

    // Resolve the sealed credential IN-MEMORY for the read — used for the header, then dropped.
    let connector_id = s(&session, "connector_id", "");
    let bearer: Option<String> = match find_by_key(&data_dir, "connector-credentials", "connector_id", &connector_id) {
        Some(cred_rec) => resolve_sealed_credential(&cred_rec).await.0,
        None => None,
    };
    let Some(bearer) = bearer else {
        let receipt = run_receipt(&data_dir, &run_ref, "execution_refused", "execution_credential_unresolved", "the sealed credential no longer resolves — the session's authority is stale");
        push_history(&mut run, "execution_refused", "sealed credential unresolved", &receipt);
        let _ = persist_record(&data_dir, crate::materializing_run_routes::RECORD_DIR, &id, &run);
        return (StatusCode::PRECONDITION_REQUIRED, Json(json!({ "ok": false, "error": { "code": "execution_credential_unresolved", "message": "the sealed credential no longer resolves" } })));
    };

    // THE READ — one GET of the DECLARED endpoint, verbatim. Read-only by construction.
    let endpoint = s(&source, "endpoint", "");
    let display_endpoint = redacted_endpoint(&endpoint);
    let receipt = run_receipt(&data_dir, &run_ref, "source_contact_started", "ok", &format!("GET {display_endpoint} (declared endpoint, verbatim; bearer attached, never recorded)"));
    push_history(&mut run, "source_contact_started", &format!("GET {display_endpoint}"), &receipt);
    let started = now_ms();
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "error": { "code": "execution_adapter_unavailable", "message": format!("adapter client could not initialize: {e}") } })));
        }
    };
    let resp = client
        .get(&endpoint)
        .header("Authorization", format!("Bearer {bearer}"))
        .header("User-Agent", "ioi-hypervisor-odk-adapter")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;
    drop(bearer);
    let (http_status, body_text) = match resp {
        Ok(r) => {
            let st_ = r.status().as_u16();
            (st_, r.text().await.unwrap_or_default())
        }
        Err(e) => {
            let receipt = run_receipt(&data_dir, &run_ref, "source_contact_failed", "execution_source_unreachable", &format!("GET {display_endpoint} failed: {e}"));
            push_history(&mut run, "source_contact_failed", "source unreachable", &receipt);
            let _ = persist_record(&data_dir, crate::materializing_run_routes::RECORD_DIR, &id, &run);
            return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "error": { "code": "execution_source_unreachable", "message": format!("the declared endpoint did not answer: {e}") } })));
        }
    };
    let elapsed_ms = now_ms() - started;
    if (300..400).contains(&(http_status as i32)) {
        let receipt = run_receipt(&data_dir, &run_ref, "source_contact_failed", "execution_source_redirect_rejected", &format!("GET {display_endpoint} → http {http_status} redirect REFUSED — the adapter reads the DECLARED endpoint verbatim and never follows a redirect to an undeclared URL"));
        push_history(&mut run, "source_contact_failed", &format!("redirect refused (http {http_status})"), &receipt);
        let _ = persist_record(&data_dir, crate::materializing_run_routes::RECORD_DIR, &id, &run);
        return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "error": { "code": "execution_source_redirect_rejected", "message": "the declared endpoint answered with a redirect — refused; the adapter never follows redirects to undeclared URLs" } })));
    }
    if !(200..300).contains(&(http_status as i32)) {
        let receipt = run_receipt(&data_dir, &run_ref, "source_contact_failed", "execution_source_error", &format!("GET {display_endpoint} → http {http_status}"));
        push_history(&mut run, "source_contact_failed", &format!("http {http_status}"), &receipt);
        let _ = persist_record(&data_dir, crate::materializing_run_routes::RECORD_DIR, &id, &run);
        return (StatusCode::BAD_GATEWAY, Json(json!({ "ok": false, "error": { "code": "execution_source_error", "message": format!("the declared endpoint answered http {http_status}") } })));
    }
    let rows: Vec<Value> = match serde_json::from_str::<Value>(&body_text) {
        Ok(Value::Array(a)) => a,
        _ => {
            let receipt = run_receipt(&data_dir, &run_ref, "validation_result", "execution_source_shape_invalid", "the declared endpoint did not return a JSON array of rows");
            push_history(&mut run, "validation_result", "source shape invalid", &receipt);
            let _ = persist_record(&data_dir, crate::materializing_run_routes::RECORD_DIR, &id, &run);
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "ok": false, "error": { "code": "execution_source_shape_invalid", "message": "expected a JSON array of row objects" } })));
        }
    };
    let fetched = rows.len();
    let truncated = fetched as u64 > limit;
    let rows: Vec<Value> = rows.into_iter().take(limit as usize).collect();
    let receipt = run_receipt(&data_dir, &run_ref, "source_contact_completed", "ok", &format!("GET {display_endpoint} → http {http_status} · {fetched} rows fetched · {} accepted (limit {limit}) · {elapsed_ms}ms", rows.len()));
    push_history(&mut run, "source_contact_completed", &format!("{fetched} rows fetched"), &receipt);

    // TRANSFORM + VALIDATE through the landed ladder — all-or-nothing, no partial truth.
    let requested = str_list(&run, "requested_properties");
    let bindings = run_bindings(&mapping, &requested);
    let mut objects: Vec<Value> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut seen_keys: Vec<String> = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let mut properties = serde_json::Map::new();
        let mut provenance = serde_json::Map::new();
        let mut object_key = String::new();
        let mut title = String::new();
        for (pid, sf, st_, role) in &bindings {
            let v = row.get(sf.as_str()).cloned().unwrap_or(Value::Null);
            if v.is_null() {
                errors.push(format!("row {i}: source field '{sf}' (→ {pid}) is missing"));
                continue;
            }
            if !value_matches_source_type(&v, st_) {
                errors.push(format!("row {i}: source field '{sf}' (→ {pid}) does not match declared type '{st_}'"));
                continue;
            }
            if *role == "key" {
                object_key = v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string());
            }
            if *role == "title" {
                title = v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string());
            }
            properties.insert(pid.clone(), v);
            provenance.insert(pid.clone(), json!(sf));
        }
        if object_key.trim().is_empty() {
            errors.push(format!("row {i}: empty object key"));
        } else if seen_keys.iter().any(|k| k == &object_key) {
            errors.push(format!("row {i}: duplicate object key '{object_key}' — semantic identity must be unique within a batch"));
        } else {
            seen_keys.push(object_key.clone());
        }
        if title.trim().is_empty() {
            errors.push(format!("row {i}: empty title"));
        }
        objects.push(json!({
            "object_key": object_key,
            "title": title,
            "object_type_id": s(&mapping, "object_type_id", ""),
            "properties": properties,
            "source_hash": sha256_hex(&row.to_string()),
            "provenance": { "mapped_from": provenance, "connector_id": connector_id, "endpoint": display_endpoint, "session_ref": session.pointer("/session/session_ref").cloned().unwrap_or(Value::Null) }
        }));
    }
    if !errors.is_empty() {
        errors.truncate(8);
        let receipt = run_receipt(&data_dir, &run_ref, "validation_result", "execution_batch_invalid", &format!("batch REJECTED all-or-nothing: {} error(s), zero objects registered — {}", errors.len(), errors.join("; ")));
        push_history(&mut run, "validation_result", "batch rejected — no partial truth", &receipt);
        let _ = persist_record(&data_dir, crate::materializing_run_routes::RECORD_DIR, &id, &run);
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "ok": false, "error": { "code": "execution_batch_invalid", "message": "one or more rows failed validation — the whole batch is rejected (no partial truth)", "errors": errors } })));
    }
    let receipt = run_receipt(&data_dir, &run_ref, "validation_result", "ok", &format!("all {} rows validated against the typed ladder", objects.len()));
    push_history(&mut run, "validation_result", "batch validated", &receipt);

    // PRE-OUTPUT RECEIPT — must land BEFORE any output record. Persist failure ABORTS registration.
    let set_id = format!("mset_{:x}", nanos());
    let set_ref = format!("materialized-object-set://{set_id}");
    let pre = match run_receipt_checked(&data_dir, &run_ref, "pre_output_receipt", "ok", &format!("about to register {} objects as {set_ref} for projection {projection_id} — receipt lands before output, or nothing does", objects.len())) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "error": { "code": "execution_receipt_failed", "message": format!("the pre-output receipt could not persist — registration ABORTED before any output: {e}") } })));
        }
    };
    push_history(&mut run, "pre_output_receipt", "pre-output receipt landed", &pre);

    // REGISTER — all-or-nothing, one bounded set; then flip ONLY the tied projection.
    let count = objects.len();
    let set = json!({
        "schema_version": SET_SCHEMA,
        "object": "ioi.hypervisor.odk.materialized_object_set",
        "id": set_id,
        "ref": set_ref,
        "materializing_run_ref": run_ref,
        "connector_session_ref": session.get("ref").cloned().unwrap_or(Value::Null),
        "capability_lease_plan_ref": plan.get("ref").cloned().unwrap_or(Value::Null),
        "ontology_projection_id": projection_id,
        "ontology_ref": run.get("ontology_ref").cloned().unwrap_or(Value::Null),
        "object_type_id": run.get("object_type_id").cloned().unwrap_or(Value::Null),
        "objects": objects,
        "count": count,
        "rows_fetched": fetched,
        "truncated_to_limit": truncated,
        "source_contact": { "endpoint": display_endpoint, "http_status": http_status, "elapsed_ms": elapsed_ms, "at": iso_now() },
        "pre_output_receipt_ref": pre.get("receipt_ref").cloned().unwrap_or(Value::Null),
        "registered_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime"
    });
    if let Err(e) = persist_record(&data_dir, SET_DIR, &set_id, &set) {
        let receipt = run_receipt(&data_dir, &run_ref, "execution_refused", "execution_output_persist_failed", &format!("output persist failed after the pre-output receipt: {e}"));
        push_history(&mut run, "execution_refused", "output persist failed", &receipt);
        let _ = persist_record(&data_dir, crate::materializing_run_routes::RECORD_DIR, &id, &run);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "error": { "code": "execution_output_persist_failed", "message": "output could not persist" } })));
    }
    // FINALIZATION IS ATOMIC-OR-ROLLED-BACK: every write after the set is CHECKED; any failure
    // removes the set (and restores the projection) so no partial truth ever remains — a set never
    // exists without its projection flip, and a run never stays executable beside a live set.
    let rollback_set = |why: &str| {
        let _ = remove_record(&data_dir, SET_DIR, &set_id);
        let _ = run_receipt(&data_dir, &run_ref, "execution_refused", "execution_finalize_failed", &format!("finalization failed ({why}) — the set was ROLLED BACK; no partial truth remains"));
    };
    let prior_projection = projection.clone();
    projection["health"]["object_instances"] = json!(count);
    projection["health"]["materialized"] = json!(true);
    projection["health"]["note"] = json!("materialized — a bounded, receipted object set is registered for this projection");
    projection["materialized"] = json!({ "set_ref": set_ref, "count": count, "at": iso_now(), "materializing_run_ref": run_ref });
    projection["updated_at"] = json!(iso_now());
    if let Err(e) = persist_record(&data_dir, crate::ontology_projection_routes::RECORD_DIR, &projection_id, &projection) {
        rollback_set(&format!("projection persist: {e}"));
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "error": { "code": "execution_finalize_failed", "message": "the projection flip could not persist — the set was rolled back; no partial truth remains" } })));
    }
    run["status"] = json!("executed");
    run["execution"] = json!({
        "source_contacted": true, "data_moved": true, "rows_extracted": count, "object_instances": count,
        "endpoint": display_endpoint, "materialized_set_ref": set_ref, "completed_at": iso_now(),
        "note": "one bounded read-only batch, registered all-or-nothing under the held lease + sealed session"
    });
    run["updated_at"] = json!(iso_now());
    let receipt = match run_receipt_checked(&data_dir, &run_ref, "materialized_output_registered", "ok", &format!("{count} ontology-bound objects registered as {set_ref}; projection {projection_id} object_instances 0 → {count}")) {
        Ok(r) => r,
        Err(e) => {
            let _ = persist_record(&data_dir, crate::ontology_projection_routes::RECORD_DIR, &projection_id, &prior_projection);
            rollback_set(&format!("registration receipt: {e}"));
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "error": { "code": "execution_finalize_failed", "message": "the registration receipt could not persist — projection restored, set rolled back" } })));
        }
    };
    push_history(&mut run, "materialized_output_registered", &format!("{count} objects registered"), &receipt);
    if let Err(e) = persist_record(&data_dir, crate::materializing_run_routes::RECORD_DIR, &id, &run) {
        let _ = persist_record(&data_dir, crate::ontology_projection_routes::RECORD_DIR, &projection_id, &prior_projection);
        rollback_set(&format!("run persist: {e}"));
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "ok": false, "error": { "code": "execution_finalize_failed", "message": "the run state could not persist — projection restored, set rolled back (the run stays re-executable with no live set beside it)" } })));
    }
    (StatusCode::OK, Json(json!({ "ok": true, "materializing_run": run, "materialized_object_set": set })))
}

/// GET /v1/hypervisor/odk/materialized-object-sets.
pub(crate) async fn handle_sets_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, SET_DIR);
    items.sort_by(|a, b| s(b, "registered_at", "").cmp(&s(a, "registered_at", "")));
    Json(json!({ "ok": true, "schema_version": SET_SCHEMA, "materialized_object_sets": items, "runtimeTruthSource": "daemon-runtime" }))
}

/// GET /v1/hypervisor/odk/materialized-object-sets/overview.
pub(crate) async fn handle_sets_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let items = read_record_dir(&st.data_dir, SET_DIR);
    let objects: u64 = items.iter().map(|r| r.get("count").and_then(|v| v.as_u64()).unwrap_or(0)).sum();
    Json(json!({
        "ok": true,
        "schema_version": OVERVIEW_SCHEMA,
        "materialized_object_sets": items.len(),
        "object_instances": objects,
        "supported_execution_kinds": SUPPORTED_EXECUTION_KINDS,
        "max_batch_limit": MAX_BATCH_LIMIT,
        "governance_gaps": [
            "one narrow read-only adapter path (rest_api GET of the declared endpoint) — not a generic ingestion engine",
            "every set was registered all-or-nothing behind a pre-output receipt under a held lease + opened sealed session",
            "object records carry source hashes + provenance — never credential or raw source secrets",
            "no actions, writeback, export, train, evaluate, publish, or route exist on this path"
        ],
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// GET /v1/hypervisor/odk/materialized-object-sets/:id.
pub(crate) async fn handle_set_get(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> (StatusCode, Json<Value>) {
    match find_by_key(&st.data_dir, SET_DIR, "id", &id) {
        Some(r) => (StatusCode::OK, Json(json!({ "ok": true, "materialized_object_set": r }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "materialized object set not found" }))),
    }
}

/// DELETE — receipted removal that RESETS the tied projection's materialized state (no dangling counts).
pub(crate) async fn handle_set_delete(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    let Some(set) = find_by_key(&st.data_dir, SET_DIR, "id", &id) else {
        return Json(json!({ "ok": false, "removed": false, "id": id }));
    };
    let projection_id = s(&set, "ontology_projection_id", "");
    if let Some(mut projection) = find_by_key(&st.data_dir, crate::ontology_projection_routes::RECORD_DIR, "id", &projection_id) {
        projection["health"]["object_instances"] = json!(0);
        projection["health"]["materialized"] = json!(false);
        projection["materialized"] = Value::Null;
        projection["updated_at"] = json!(iso_now());
        let _ = persist_record(&st.data_dir, crate::ontology_projection_routes::RECORD_DIR, &projection_id, &projection);
    }
    let removed = remove_record(&st.data_dir, SET_DIR, &id);
    if removed {
        let _ = run_receipt(&st.data_dir, &s(&set, "materializing_run_ref", ""), "materialized_output_removed", "ok", &format!("materialized set {} removed; projection {projection_id} reset to 0", s(&set, "ref", "")));
    }
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

#[cfg(test)]
mod connector_execution_tests {
    use super::*;

    #[test]
    fn allowlist_and_bounds_are_narrow() {
        assert_eq!(SUPPORTED_EXECUTION_KINDS, &["rest_api"]);
        assert_eq!(MAX_BATCH_LIMIT, 500);
    }

    #[test]
    fn source_type_validation_is_conservative() {
        assert!(value_matches_source_type(&json!("x"), "string"));
        assert!(value_matches_source_type(&json!(3), "integer"));
        assert!(value_matches_source_type(&json!(3.5), "double"));
        assert!(value_matches_source_type(&json!(3), "double"));
        assert!(!value_matches_source_type(&json!("3"), "double"));
        assert!(!value_matches_source_type(&json!(3.5), "integer"));
        assert!(!value_matches_source_type(&json!(null), "json"));
    }

    #[test]
    fn run_bindings_always_include_key_and_title() {
        let mapping = json!({
            "key_mapping": { "property_id": "loan_id", "source_field": "id", "source_type": "string" },
            "title_mapping": { "property_id": "title", "source_field": "disp", "source_type": "string" },
            "field_mappings": [
                { "property_id": "amount", "source_field": "amt", "source_type": "double" },
                { "property_id": "extra", "source_field": "x", "source_type": "string" }
            ]
        });
        let b = run_bindings(&mapping, &vec!["loan_id".into(), "title".into(), "amount".into()]);
        let pids: Vec<&str> = b.iter().map(|(p, _, _, _)| p.as_str()).collect();
        assert!(pids.contains(&"loan_id") && pids.contains(&"title") && pids.contains(&"amount"));
        assert!(!pids.contains(&"extra")); // unrequested field excluded
    }

    #[test]
    fn endpoint_redaction_strips_userinfo_and_query() {
        assert_eq!(redacted_endpoint("https://host/rows"), "https://host/rows");
        assert_eq!(redacted_endpoint("https://host/rows?api_key=X"), "https://host/rows?…redacted");
        assert_eq!(redacted_endpoint("https://u:p@host/rows"), "https://host/rows");
        assert_eq!(redacted_endpoint("https://u:p@host/rows?t=1"), "https://host/rows?…redacted");
    }

    #[test]
    fn source_hash_is_stable_and_prefixed() {
        let h = sha256_hex("row");
        assert!(h.starts_with("sha256:"));
        assert_eq!(h, sha256_hex("row"));
    }
}
