//! Sealed connector session — the CREDENTIAL-HANDLING crossing, split from execution. A
//! MaterializingRun that HOLDS its CapabilityLease (#18) may request a sealed connector session:
//! a SECOND crossing through the SAME gateway, this time with `credential_required: true` — the
//! gateway resolves the SEALED backing credential server-side (fail-closed 428 if unresolved),
//! verifies a fresh bound wallet grant, and mints the session's lease descriptor. The session
//! PROVES credential resolution is authorized for the exact lease scope — and nothing more:
//! it does not expose credential material and does not contact the source.
//!
//! Boundaries held hard:
//!   * the resolved bearer token is DROPPED — never stored, logged, returned, or receipted;
//!     only non-secret LABELS land on the record (credential_source, credential_key_source);
//!   * no source rows are extracted, no data transformed, no output registered, no object
//!     instances created, no explorer rows — connector execution is the NEXT cut (#20);
//!   * the session binds the run's lease scope VERBATIM — restating or widening scope is refused;
//!     the session TTL may only narrow the run's;
//!   * receipts record session_requested, the gateway decision, the session/descriptor refs, the
//!     lease id, bounded TTL, scope, refusal reasons, release/cancel.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};
use crate::lifecycle_routes::{authorize_capability_lease, CapabilityLeaseRequest};

const SESSION_SCHEMA: &str = "ioi.hypervisor.odk.connector-session.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.odk.connector-session-receipt.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.odk.connector-sessions-overview.v1";
pub(crate) const RECORD_DIR: &str = "odk-connector-sessions";
const RECEIPT_DIR: &str = "odk-connector-session-receipts";

/// Lifecycle: a session request exists, may be opened (the crossing), and released — nothing reads.
const LIFECYCLE_STATES: &[&str] = &["requested", "session_obtained", "session_released", "cancelled"];
/// What still does not exist after this rung.
const MISSING_AUTHORITY: &[&str] = &["ConnectorExecution", "MaterializedRows"];
const PLAINTEXT_SECRET_KEYS: &[&str] = &["secret", "password", "api_key", "apikey", "token", "credential"];
const RAW_QUERY_KEYS: &[&str] = &["query", "sql", "raw_query", "statement", "command"];
const ENV_FALLBACK_KEYS: &[&str] = &["env", "env_var", "env_credential", "credential_env", "from_env"];
/// A session may not restate the lease scope at all — the lease scope binds verbatim.
const SCOPE_KEYS: &[&str] = &["requested_properties", "requested_operations", "subject", "purpose", "property_scope"];

fn nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}
fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
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
/// A lease is expired only when it DECLARES an expiry in the past.
fn lease_expired(expires_at: &Value, now_millis: i64) -> bool {
    expires_at.as_i64().map(|e| e < now_millis).unwrap_or(false)
}
/// The #10 source kinds that need a network session (local kinds have nothing to open).
fn source_kind_networked(kind: &str) -> bool {
    !matches!(kind, "file_drop" | "local_folder")
}

/// Split a URL into (scheme, authority, path) — authority lowercased; path defaults to "/".
fn url_parts(u: &str) -> Option<(String, String, String)> {
    let (scheme, rest) = u.split_once("://")?;
    if scheme.is_empty() || rest.is_empty() {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let authority = authority.split(['?', '#']).next().unwrap_or(authority);
    if authority.is_empty() {
        return None;
    }
    let path = path.split(['?', '#']).next().unwrap_or(path);
    Some((scheme.to_ascii_lowercase(), authority.to_ascii_lowercase(), path.to_string()))
}
/// Does the connector's `base_url` cover the data-source endpoint? A sealed credential may only be
/// sent to the endpoint its connector is the ORIGIN AUTHORITY for: same scheme + host:port, and the
/// endpoint path AT OR UNDER the base_url path. This binds the credential to the exact source it
/// authorizes — connector A's bearer can never reach data-source B's endpoint. Fail-closed on any
/// unparseable URL.
pub(crate) fn connector_covers_endpoint(base_url: &str, endpoint: &str) -> bool {
    let (Some((bs, ba, bp)), Some((es, ea, ep))) = (url_parts(base_url), url_parts(endpoint)) else {
        return false;
    };
    if bs != es || ba != ea {
        return false;
    }
    let base_path = bp.trim_end_matches('/'); // "" (root) covers all paths
    base_path.is_empty() || ep == base_path || ep.starts_with(&format!("{base_path}/"))
}

/// Everything a session needs, resolved fresh: the run (holding its lease), its plan, the connector.
struct SessionInputs {
    run: Value,
    connector_id: String,
    ttl_seconds: u64,
}

/// Validate fail-closed against CURRENT truth: bypass guards, a lease-holding run whose ladder still
/// matches, a networked source, a registered connector, and a TTL that only narrows the run's.
fn validate_inputs(data_dir: &str, body: &Value) -> Result<SessionInputs, VErr> {
    if let Some(obj) = body.as_object() {
        if PLAINTEXT_SECRET_KEYS.iter().any(|k| obj.contains_key(*k) && !obj[*k].is_null()) {
            return Err(verr("session_plaintext_secret_rejected", "A connector session never carries credential material — the gateway resolves the sealed credential server-side.".into()));
        }
        if RAW_QUERY_KEYS.iter().any(|k| obj.contains_key(*k) && !obj[*k].is_null()) {
            return Err(verr("session_raw_query_rejected", "A connector session never carries a raw source query.".into()));
        }
        if ENV_FALLBACK_KEYS.iter().any(|k| obj.contains_key(*k) && !obj[*k].is_null()) {
            return Err(verr("session_env_fallback_rejected", "Environment-credential fallback is an authority bypass.".into()));
        }
        if SCOPE_KEYS.iter().any(|k| obj.contains_key(*k) && !obj[*k].is_null()) {
            return Err(verr("session_scope_widening_rejected", "A session binds the run's lease scope VERBATIM — scope is not restated here, narrower or wider.".into()));
        }
    }
    if opt_s(body, "name").is_none() {
        return Err(verr("session_name_required", "A connector session requires a name.".into()));
    }
    // The run: must exist and HOLD its lease.
    let run_id = opt_s(body, "materializing_run_id").unwrap_or_default();
    let run = find_by_key(data_dir, crate::materializing_run_routes::RECORD_DIR, "id", &run_id)
        .ok_or_else(|| verr("session_run_unknown", format!("materializing_run_id '{run_id}' does not resolve")))?;
    if s(&run, "status", "") != "lease_obtained" {
        return Err(verr("session_lease_not_obtained", format!("run '{run_id}' is '{}' — a session requires a run that HOLDS its lease", s(&run, "status", ""))));
    }
    if lease_expired(run.pointer("/lease/expires_at").unwrap_or(&Value::Null), now_ms()) {
        return Err(verr("session_lease_expired", "the run's lease has expired — re-acquire before opening a session".into()));
    }
    // The ladder beneath the lease must STILL match (drift discipline — same check as #18, reused).
    let plan_id = s(&run, "capability_lease_plan_id", "");
    let plan = find_by_key(data_dir, crate::capability_lease_plan_routes::RECORD_DIR, "id", &plan_id)
        .ok_or_else(|| verr("session_ladder_drift", format!("the run's plan '{plan_id}' no longer resolves")))?;
    if let Err(drift) = crate::materializing_run_routes::check_plan_against_truth(data_dir, &plan) {
        return Err(verr("session_ladder_drift", format!("the ladder no longer matches the lease scope: {drift}")));
    }
    // The source must be a networked kind (a local kind has no session to open) — its posture was
    // already proven wallet-leaseable by the drift check.
    let source_id = s(&plan, "data_source_id", "");
    let source = find_by_key(data_dir, crate::data_source_routes::RECORD_DIR, "source_id", &source_id)
        .ok_or_else(|| verr("session_ladder_drift", format!("data source '{source_id}' no longer resolves")))?;
    let kind = s(&source, "kind", "");
    if !source_kind_networked(&kind) {
        return Err(verr("session_source_kind_unsupported", format!("source kind '{kind}' has no connector session to open (local kinds are read in-place by a future execution cut)")));
    }
    // The connector that HOLDS the sealed credential must be registered in the connector estate AND
    // be the ORIGIN AUTHORITY for the declared source endpoint — the credential is bound to the
    // exact source it may reach, never a different endpoint.
    let connector_id = opt_s(body, "connector_id").unwrap_or_default();
    let connector = find_by_key(data_dir, "connectors", "connector_id", &connector_id)
        .ok_or_else(|| verr("session_connector_unknown", format!("connector_id '{connector_id}' is not registered in the connector estate")))?;
    let source_endpoint = s(&source, "endpoint", "");
    if !connector_covers_endpoint(&s(&connector, "base_url", ""), &source_endpoint) {
        return Err(verr(
            "session_connector_source_mismatch",
            format!("connector '{connector_id}' (base_url '{}') is not the origin authority for the source endpoint '{}' — a session cannot bind a credential to an endpoint it does not authorize", s(&connector, "base_url", ""), s(&source, "endpoint", "")),
        ));
    }
    // TTL: bounded by the run's (which was bounded by the plan's).
    let run_ttl = run.get("ttl_seconds").and_then(|v| v.as_u64()).unwrap_or(0);
    let ttl_seconds = body.get("ttl_seconds").and_then(|v| v.as_u64()).unwrap_or(run_ttl);
    if ttl_seconds == 0 || ttl_seconds > run_ttl {
        return Err(verr("session_ttl_widening_rejected", format!("ttl_seconds must be 1..={run_ttl} (the run's lease bound) — a session can only narrow")));
    }
    Ok(SessionInputs { run, connector_id, ttl_seconds })
}

fn session_receipt(data_dir: &str, session_ref: &str, op: &str, outcome: &str, summary: &str) -> Value {
    let id = format!("csr_{:x}", nanos());
    let receipt_ref = format!("agentgres://connector-session-receipt/{id}");
    let rec = json!({
        "schema_version": RECEIPT_SCHEMA, "receipt_id": id, "receipt_ref": receipt_ref,
        "connector_session_ref": session_ref, "op": op, "outcome": outcome, "summary": summary, "at": iso_now()
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
fn bad(data_dir: &str, op: &str, err: VErr) -> (StatusCode, Json<Value>) {
    let _ = session_receipt(data_dir, "connector-session://unadmitted", op, &err.0, &err.1);
    (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": err.0, "message": err.1 } })))
}
fn load_session(data_dir: &str, id: &str) -> Option<Value> {
    find_by_key(data_dir, RECORD_DIR, "id", id)
}

/// GET /v1/hypervisor/odk/connector-sessions.
pub(crate) async fn handle_sessions_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, RECORD_DIR);
    items.sort_by(|a, b| s(b, "updated_at", "").cmp(&s(a, "updated_at", "")));
    Json(json!({ "ok": true, "schema_version": SESSION_SCHEMA, "connector_sessions": items, "runtimeTruthSource": "daemon-runtime" }))
}

/// GET /v1/hypervisor/odk/connector-sessions/overview.
pub(crate) async fn handle_sessions_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let items = read_record_dir(&st.data_dir, RECORD_DIR);
    let by = |status: &str| items.iter().filter(|r| s(r, "status", "") == status).count();
    Json(json!({
        "ok": true,
        "schema_version": OVERVIEW_SCHEMA,
        "connector_sessions": items.len(),
        "lifecycle": { "requested": by("requested"), "session_obtained": by("session_obtained"), "session_released": by("session_released"), "cancelled": by("cancelled") },
        "lifecycle_states": LIFECYCLE_STATES,
        "missing_authority": MISSING_AUTHORITY,
        "governance_gaps": [
            "CREDENTIAL-HANDLING crossing only — the gateway resolves the SEALED credential server-side and mints the session; the session proves resolution is authorized for the exact lease scope",
            "credential material is never stored, logged, returned, or receipted — only non-secret labels (credential_source, credential_key_source) land on the record",
            "the source is never contacted; no rows are extracted, no output registered — connector execution and materialized rows are the NEXT cut",
            "the session binds the run's lease scope VERBATIM; restating scope is refused; TTL may only narrow"
        ],
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// GET /v1/hypervisor/odk/connector-sessions/:id.
pub(crate) async fn handle_session_get(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> (StatusCode, Json<Value>) {
    match load_session(&st.data_dir, &id) {
        Some(r) => (StatusCode::OK, Json(json!({ "ok": true, "connector_session": r }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "connector session not found" }))),
    }
}

/// GET /v1/hypervisor/odk/connector-sessions/:id/history.
pub(crate) async fn handle_session_history(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> (StatusCode, Json<Value>) {
    let Some(r) = load_session(&st.data_dir, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "connector session not found" })));
    };
    let sref = s(&r, "ref", "");
    let mut receipts = read_record_dir(&st.data_dir, RECEIPT_DIR);
    receipts.retain(|x| x.get("connector_session_ref").and_then(|v| v.as_str()) == Some(sref.as_str()));
    receipts.sort_by(|a, b| s(b, "at", "").cmp(&s(a, "at", "")));
    (StatusCode::OK, Json(json!({ "ok": true, "connector_session_ref": sref, "revision": r.get("revision"), "status": r.get("status"), "history": r.get("history").cloned().unwrap_or(json!([])), "receipts": receipts })))
}

/// POST /v1/hypervisor/odk/connector-sessions — admit a session request (no crossing yet).
pub(crate) async fn handle_session_create(State(st): State<Arc<DaemonState>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let inputs = match validate_inputs(&st.data_dir, &body) {
        Ok(i) => i,
        Err(e) => return bad(&st.data_dir, "create_rejected", e),
    };
    let id = format!("csn_{:x}", nanos());
    let now = iso_now();
    let sref = format!("connector-session://{id}");
    let receipt = session_receipt(&st.data_dir, &sref, "created", "ok", "connector session requested (no crossing yet)");
    let receipt_ref = receipt.get("receipt_ref").cloned().unwrap_or(Value::Null);
    let run = &inputs.run;
    let record = json!({
        "schema_version": SESSION_SCHEMA,
        "object": "ioi.hypervisor.odk.connector_session",
        "id": id,
        "ref": sref,
        "name": s(&body, "name", "connector-session"),
        "description": s(&body, "description", ""),
        "status": "requested",
        "materializing_run_id": run.get("id").cloned().unwrap_or(Value::Null),
        "materializing_run_ref": run.get("ref").cloned().unwrap_or(Value::Null),
        "lease_id": run.pointer("/lease/lease_id").cloned().unwrap_or(Value::Null),
        "ontology_ref": run.get("ontology_ref").cloned().unwrap_or(Value::Null),
        "object_type_id": run.get("object_type_id").cloned().unwrap_or(Value::Null),
        "connector_id": inputs.connector_id,
        // The lease scope binds VERBATIM — snapshotted for the record, never restated by the caller.
        "subject": run.get("subject").cloned().unwrap_or(Value::Null),
        "purpose": run.get("purpose").cloned().unwrap_or(Value::Null),
        "operations": run.get("requested_operations").cloned().unwrap_or(json!([])),
        "properties": run.get("requested_properties").cloned().unwrap_or(json!([])),
        "ttl_seconds": inputs.ttl_seconds,
        "session": { "obtained": false, "credential_material": false },
        "execution": { "source_contacted": false, "data_moved": false, "rows_extracted": 0, "object_instances": 0, "note": "credential-handling crossing only — execution is the next cut" },
        "missing_authority": MISSING_AUTHORITY,
        "revision": 1,
        "receipt_refs": [receipt_ref.clone()],
        "history": [ { "revision": 1, "op": "created", "at": now.clone(), "summary": "connector session requested (no crossing yet)", "receipt_ref": receipt_ref } ],
        "created_at": now.clone(),
        "updated_at": now
    });
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "connector_session": record })))
}

/// POST /:id/open — THE credential-handling crossing. Re-validates everything, then crosses the
/// SAME gateway with credential_required:true: the sealed credential resolves server-side (428 if
/// unresolved), a fresh bound wallet grant is verified (403 challenge otherwise), and the session's
/// lease descriptor mints. The resolved bearer is DROPPED; only non-secret labels land.
pub(crate) async fn handle_session_open(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let Some(mut record) = load_session(&st.data_dir, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "connector session not found" })));
    };
    let status = s(&record, "status", "");
    if status == "session_obtained" {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": "session_already_obtained", "message": "the session is already open" } })));
    }
    if status == "cancelled" || status == "session_released" {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": "session_terminal_immutable", "message": format!("a {status} session is immutable") } })));
    }
    let sref = s(&record, "ref", "");
    // Re-validate the whole chain at the moment of crossing — never cached.
    let revalidation = json!({
        "name": record.get("name").cloned().unwrap_or(Value::Null),
        "materializing_run_id": record.get("materializing_run_id").cloned().unwrap_or(Value::Null),
        "connector_id": record.get("connector_id").cloned().unwrap_or(Value::Null),
        "ttl_seconds": record.get("ttl_seconds").cloned().unwrap_or(Value::Null),
    });
    if let Err(e) = validate_inputs(&st.data_dir, &revalidation) {
        let _ = session_receipt(&st.data_dir, &sref, "session_refused", &e.0, &e.1);
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": e.0, "message": e.1 } })));
    }
    let connector_id = s(&record, "connector_id", "");
    let operations = str_list(&record, "operations");
    let properties = str_list(&record, "properties");
    let ttl = record.get("ttl_seconds").and_then(|v| v.as_u64()).unwrap_or(0);
    let lease_req = CapabilityLeaseRequest {
        authority_provider_ref: "wallet.network".to_string(),
        backing_provider: format!("connector:{connector_id}"),
        allowed_tools: operations.iter().map(|o| format!("odk.session.{o}")).collect(),
        resource_refs: vec![
            s(&record, "materializing_run_ref", ""),
            format!("capability-lease://{}", s(&record, "lease_id", "")),
            connector_id.clone(),
        ],
        scopes: operations.clone(),
        policy_domain: "hypervisor.odk.connector-session.policy.v1".to_string(),
        request_domain: "hypervisor.odk.connector-session.request.v1".to_string(),
        request_facets: json!({
            "connector_session_id": s(&record, "id", ""),
            "materializing_run_ref": s(&record, "materializing_run_ref", ""),
            "lease_id": s(&record, "lease_id", ""),
            "connector_id": connector_id,
            "properties": properties,
            "ttl_seconds": ttl
        }),
        credential_connector_id: Some(connector_id.clone()),
        credential_store: "connector-credentials".to_string(),
        credential_required: true,
        github_host_fallback: false,
        receipt_required: true,
        revocation_ref: format!("connectors/{connector_id}/credential"),
        authority_reason: "odk_connector_session_authority_required".to_string(),
        grant_value: body.get("wallet_approval_grant").cloned().unwrap_or(Value::Null),
    };
    let _ = session_receipt(&st.data_dir, &sref, "session_requested", "ok", &format!("sealed session requested at the gateway: connector {connector_id} · ttl {ttl}s · {} properties", properties.len()));
    match authorize_capability_lease(&st, &lease_req).await {
        Err((code, challenge)) => {
            // 428 (sealed credential unresolved) or 403 (authority challenge) — verbatim, receipted.
            let reason = challenge.get("reason").and_then(|v| v.as_str()).unwrap_or("refused").to_string();
            let _ = session_receipt(&st.data_dir, &sref, "session_refused", &reason, "gateway refused the crossing (challenge returned verbatim; no session opened)");
            (code, Json(challenge))
        }
        Ok(lease) => {
            // Non-secret labels ONLY; the resolved bearer is dropped here and nowhere else exists.
            let credential_source = lease.credential_source.clone();
            let credential_key_source = lease.credential_key_source.clone();
            drop(lease.token);
            let d = &lease.descriptor;
            let session_lease_id = s(d, "lease_id", "");
            record["status"] = json!("session_obtained");
            record["session"] = json!({
                "obtained": true,
                "credential_material": false,
                "session_ref": format!("sealed-session://{session_lease_id}"),
                "gateway_lease_id": session_lease_id,
                "credential_descriptor": {
                    "credential_source": credential_source,
                    "credential_key_source": credential_key_source,
                    "note": "labels only — the sealed credential resolved server-side and was dropped"
                },
                "grant_ref": lease.grant_ref,
                "policy_hash": d.get("policy_hash").cloned().unwrap_or(Value::Null),
                "request_hash": d.get("request_hash").cloned().unwrap_or(Value::Null),
                "expires_at": d.get("expires_at").cloned().unwrap_or(Value::Null),
                "ttl_seconds": ttl
            });
            record["updated_at"] = json!(iso_now());
            let receipt = session_receipt(&st.data_dir, &sref, "session_obtained", "ok", &format!("gateway opened sealed session {session_lease_id} (connector {}, ttl {ttl}s) — credential resolved server-side, labels only", s(&record, "connector_id", "")));
            push_history(&mut record, "session_obtained", &format!("sealed session {session_lease_id} obtained"), receipt.get("receipt_ref").cloned().unwrap_or(Value::Null));
            let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
            (StatusCode::OK, Json(json!({ "ok": true, "connector_session": record })))
        }
    }
}

/// POST /:id/release — receipted release (terminal for this session).
pub(crate) async fn handle_session_release(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> (StatusCode, Json<Value>) {
    let Some(mut record) = load_session(&st.data_dir, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "connector session not found" })));
    };
    if s(&record, "status", "") != "session_obtained" {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": "session_nothing_to_release", "message": "the session is not open" } })));
    }
    let slid = record.pointer("/session/gateway_lease_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let receipt = session_receipt(&st.data_dir, &s(&record, "ref", ""), "session_released", "ok", &format!("sealed session {slid} released (never used — no execution exists)"));
    record["status"] = json!("session_released");
    record["session"]["obtained"] = json!(false);
    record["session"]["released_at"] = json!(iso_now());
    record["updated_at"] = json!(iso_now());
    push_history(&mut record, "session_released", &format!("sealed session {slid} released"), receipt.get("receipt_ref").cloned().unwrap_or(Value::Null));
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    (StatusCode::OK, Json(json!({ "ok": true, "connector_session": record })))
}

/// POST /:id/cancel — terminal from `requested`, receipted.
pub(crate) async fn handle_session_cancel(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> (StatusCode, Json<Value>) {
    let Some(mut record) = load_session(&st.data_dir, &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "connector session not found" })));
    };
    if s(&record, "status", "") != "requested" {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": { "code": "session_terminal_immutable", "message": "only a requested session can be cancelled (release an open one)" } })));
    }
    let receipt = session_receipt(&st.data_dir, &s(&record, "ref", ""), "cancelled", "ok", "connector session cancelled before any crossing");
    record["status"] = json!("cancelled");
    record["updated_at"] = json!(iso_now());
    push_history(&mut record, "cancelled", "connector session cancelled before any crossing", receipt.get("receipt_ref").cloned().unwrap_or(Value::Null));
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    (StatusCode::OK, Json(json!({ "ok": true, "connector_session": record })))
}

/// PATCH — name/description ONLY; a session's scope is the lease's scope, frozen from birth.
pub(crate) async fn handle_session_patch(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>, Json(patch): Json<Value>) -> Json<Value> {
    let Some(mut record) = load_session(&st.data_dir, &id) else {
        return Json(json!({ "ok": false, "reason": "connector session not found" }));
    };
    let status = s(&record, "status", "");
    if status == "cancelled" || status == "session_released" {
        return Json(json!({ "ok": false, "error": { "code": "session_terminal_immutable", "message": format!("a {status} session is immutable") } }));
    }
    let frozen = ["materializing_run_id", "connector_id", "ttl_seconds"];
    if frozen.iter().chain(SCOPE_KEYS.iter()).any(|k| patch.get(*k).is_some()) {
        let _ = session_receipt(&st.data_dir, &s(&record, "ref", ""), "patch_rejected", "session_scope_frozen", "scope-affecting patch refused — a session's scope is the lease's scope, frozen from birth");
        return Json(json!({ "ok": false, "error": { "code": "session_scope_frozen", "message": "a session's scope binds the lease verbatim and is frozen — cancel and request a new one" } }));
    }
    if let Some(v) = patch.get("name") { record["name"] = v.clone(); }
    if let Some(v) = patch.get("description") { record["description"] = v.clone(); }
    let rev = record.get("revision").and_then(|v| v.as_u64()).unwrap_or(1) + 1;
    record["revision"] = json!(rev);
    record["updated_at"] = json!(iso_now());
    let receipt = session_receipt(&st.data_dir, &s(&record, "ref", ""), "patched", "ok", "metadata edit");
    push_history(&mut record, "patched", "metadata edit", receipt.get("receipt_ref").cloned().unwrap_or(Value::Null));
    let _ = persist_record(&st.data_dir, RECORD_DIR, &id, &record);
    Json(json!({ "ok": true, "connector_session": record }))
}

/// DELETE — receipted removal.
pub(crate) async fn handle_session_delete(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    let sref = load_session(&st.data_dir, &id)
        .and_then(|r| r.get("ref").and_then(|v| v.as_str()).map(str::to_string))
        .unwrap_or_else(|| format!("connector-session://{id}"));
    let removed = remove_record(&st.data_dir, RECORD_DIR, &id);
    if removed {
        let _ = session_receipt(&st.data_dir, &sref, "deleted", "ok", "connector session removed");
    }
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

#[cfg(test)]
mod connector_session_tests {
    use super::*;

    #[test]
    fn lifecycle_and_missing_authority_are_explicit() {
        assert_eq!(LIFECYCLE_STATES, &["requested", "session_obtained", "session_released", "cancelled"]);
        assert_eq!(MISSING_AUTHORITY, &["ConnectorExecution", "MaterializedRows"]);
    }

    #[test]
    fn lease_expiry_only_when_declared_and_past() {
        assert!(lease_expired(&json!(1000), 2000));
        assert!(!lease_expired(&json!(3000), 2000));
        assert!(!lease_expired(&Value::Null, 2000));
    }

    #[test]
    fn connector_authority_binds_credential_to_endpoint() {
        // same origin, endpoint under (or at) the base_url path → covered
        assert!(connector_covers_endpoint("http://127.0.0.1:18099", "http://127.0.0.1:18099/rows"));
        assert!(connector_covers_endpoint("https://db.invalid", "https://db.invalid/rows?limit=5"));
        assert!(connector_covers_endpoint("https://host/api", "https://host/api/loans"));
        // different host:port → the confused-deputy case → refused
        assert!(!connector_covers_endpoint("http://127.0.0.1:18099", "http://127.0.0.1:9/rows"));
        assert!(!connector_covers_endpoint("https://a.host", "https://b.host/rows"));
        // scheme mismatch, path sibling (not under), and unparseable → refused
        assert!(!connector_covers_endpoint("http://host", "https://host/rows"));
        assert!(!connector_covers_endpoint("https://host/api", "https://host/apiv2/x"));
        assert!(!connector_covers_endpoint("not-a-url", "https://host/rows"));
    }

    #[test]
    fn local_source_kinds_have_no_session() {
        assert!(source_kind_networked("postgres"));
        assert!(source_kind_networked("rest_api"));
        assert!(!source_kind_networked("local_folder"));
        assert!(!source_kind_networked("file_drop"));
    }

    #[test]
    fn scope_keys_cover_every_restatement_path() {
        for k in ["requested_properties", "requested_operations", "subject", "purpose", "property_scope"] {
            assert!(SCOPE_KEYS.contains(&k));
        }
        assert!(ENV_FALLBACK_KEYS.contains(&"from_env"));
    }
}
