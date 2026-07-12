//! WorkResult + OutcomeDelta plane — the FIRST contract-first cut of the collaborative-pursuit
//! leg (canon-to-code-delta build step 1). Admits the GENERIC bounded result seam of
//! `WorkResultEnvelope` (canonical owner: docs/architecture/foundations/
//! common-objects-and-envelopes.md) — a result may come from research, ontology mutation,
//! incident resolution, service delivery, physical missions, review, or evaluation, not only
//! software; `ImplementationResultPayload` (the `implementation_result` GoalRun payload) remains
//! the SOFTWARE profile reached through `result_profile: software_implementation` +
//! `result_payload_ref`, and is NOT the general model.
//!
//! Doctrine enforced here (the estate's standing admission discipline):
//! - FAIL-CLOSED, TYPED, BOUNDED intake: unknown vocabulary members, present-but-wrong-type
//!   fields, and oversized values refuse with typed codes — never silently defaulted or
//!   truncated. Plaintext-secret body keys are rejected outright (results carry REFS, never
//!   secret values).
//! - ATOMIC persistence (#62/#69 discipline): receipts are built PURELY; the record persists
//!   FIRST, the receipt SECOND; a receipt failure removes the record with a CHECKED rollback;
//!   each failure lane returns a distinct typed 5xx; the receipt is returned explicitly beside
//!   the record. No orphan record, no orphan receipt.
//! - THE DELTA-BINDS-RESULT INVARIANT: an `OutcomeDelta` must bind an EXISTING admitted
//!   WorkResult at write (`proposed_by_ref` = a resolvable work-result:// ref). Proposers from
//!   the attempt/finding/participant-lease planes are named-gap REFUSED until those planes are
//!   admitted (build step 3) — fail-closed, never a dangling binding.
//! - PLANE-OWNED fields: `status` (deltas admit as `proposed`) and `admission_receipt_ref` are
//!   minted by this plane; caller-supplied values refuse typed. Evaluation/admission/rollback
//!   TRANSITIONS are a named gap (they need the room/acceptance authority of build steps 2-3).
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const RESULT_SCHEMA: &str = "ioi.hypervisor.work-result.v1";
const RESULT_RECEIPT_SCHEMA: &str = "ioi.hypervisor.work-result-receipt.v1";
const DELTA_SCHEMA: &str = "ioi.hypervisor.outcome-delta.v1";
const DELTA_RECEIPT_SCHEMA: &str = "ioi.hypervisor.outcome-delta-receipt.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.work-results-overview.v1";
pub(crate) const RESULT_DIR: &str = "work-result-registry";
const RESULT_RECEIPT_DIR: &str = "work-result-registry-receipts";
pub(crate) const DELTA_DIR: &str = "outcome-delta-registry";
const DELTA_RECEIPT_DIR: &str = "outcome-delta-registry-receipts";

/// The canonical envelope vocabularies (common-objects-and-envelopes.md, verbatim).
const RESULT_PROFILES: &[&str] = &[
    "software_implementation", "research", "ontology_mutation", "incident_resolution",
    "service_delivery", "physical_mission", "review", "evaluation", "custom",
];
const OUTCOME_CLASSES: &[&str] =
    &["positive", "negative", "inconclusive", "invalid", "exploit_found", "superseded"];
const RESULT_STATUSES: &[&str] =
    &["completed", "failed", "blocked", "partial", "challenged", "superseded"];
const NEXT_ACTIONS: &[&str] = &[
    "none", "repair", "review", "verify", "replicate", "synthesize",
    "ask_user", "escalate", "update_frontier",
];
const REPRODUCTION_STATES: &[&str] =
    &["unreviewed", "reproducible", "not_reproduced", "contradicted", "invalidated"];
const DELTA_KINDS: &[&str] = &[
    "create", "update", "supersede", "reject", "merge", "promote",
    "rollback", "course_correct", "close",
];
/// OutcomeDelta target schemes (the canonical target_ref vocabulary).
const DELTA_TARGET_SCHEMES: &[&str] = &[
    "frontier", "finding", "ontology", "state", "capability", "policy", "routing-prior", "service",
];
/// Proposer planes the canon names that are NOT yet admitted (build step 3) — refused typed.
const UNAVAILABLE_PROPOSER_SCHEMES: &[&str] = &["attempt", "finding", "participant-lease"];
/// Body keys that would be a plaintext secret — rejected outright (results carry refs, never values).
const PLAINTEXT_SECRET_KEYS: &[&str] =
    &["secret", "password", "api_key", "apikey", "token", "credential"];

const REF_MAX: usize = 300;
const LIST_MAX: usize = 64;
const GOAL_REF_MAX: usize = 300;
const UNCERTAINTY_MAX: usize = 2000;

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn s(v: &Value, k: &str, d: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string()
}

type VErr = (String, String);
fn verr(code: &str, msg: impl Into<String>) -> VErr {
    (code.into(), msg.into())
}

/// Typed, bounded optional-string reader (#63/#69 discipline): omitted/null → None; a present
/// non-string refuses typed; oversized refuses typed — never defaulted, never truncated.
fn str_opt_bounded(body: &Value, key: &str, max: usize) -> Result<Option<String>, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) => {
            if raw.chars().count() > max {
                return Err(verr("work_result_field_too_long", format!("`{key}` exceeds the bounded length ({max} chars)")));
            }
            let trimmed = raw.trim();
            if trimmed.is_empty() { return Ok(None); }
            Ok(Some(trimmed.to_string()))
        }
        Some(_) => Err(verr("work_result_field_type_invalid", format!("`{key}` must be a string when present — a non-string value is never defaulted"))),
    }
}

/// Typed, bounded ref-list reader: omitted/null → [] (consistent empties); a present non-array or
/// non-string member refuses typed; oversized list/member refuses typed.
fn ref_list_bounded(body: &Value, key: &str) -> Result<Vec<String>, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => {
            if items.len() > LIST_MAX {
                return Err(verr("work_result_field_too_long", format!("`{key}` exceeds the bounded list length ({LIST_MAX})")));
            }
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                match it {
                    Value::String(raw) if raw.chars().count() <= REF_MAX && !raw.trim().is_empty() => out.push(raw.trim().to_string()),
                    Value::String(raw) if raw.trim().is_empty() => {}
                    Value::String(_) => return Err(verr("work_result_field_too_long", format!("a `{key}` member exceeds the bounded length ({REF_MAX} chars)"))),
                    _ => return Err(verr("work_result_field_type_invalid", format!("`{key}` members must be strings"))),
                }
            }
            Ok(out)
        }
        Some(_) => Err(verr("work_result_field_type_invalid", format!("`{key}` must be an array of refs when present"))),
    }
}

/// A required vocabulary member: present string ∈ vocab, else typed refusal naming the vocabulary.
fn vocab_required(body: &Value, key: &str, vocab: &[&str], code: &str) -> Result<String, VErr> {
    match str_opt_bounded(body, key, 80)? {
        Some(v) if vocab.contains(&v.as_str()) => Ok(v),
        Some(v) => Err(verr(code, format!("`{key}` value '{v}' is not a member of the canonical vocabulary [{}]", vocab.join("|")))),
        None => Err(verr(code, format!("`{key}` is required and must be a member of [{}]", vocab.join("|")))),
    }
}

fn reject_plaintext_secrets(body: &Value) -> Result<(), VErr> {
    if let Some(obj) = body.as_object() {
        if PLAINTEXT_SECRET_KEYS.iter().any(|k| obj.contains_key(*k) && !obj[*k].is_null()) {
            return Err(verr("work_result_plaintext_secret_rejected", "Plaintext credentials are never accepted — results and deltas carry REFS; secrets stay in the daemon credential planes."));
        }
    }
    Ok(())
}

/// Build a plane receipt (PURE — nothing persists here).
fn build_plane_receipt(schema: &str, prefix: &str, subject_ref: &str, op: &str, now: &str) -> (String, Value) {
    let id = format!("{prefix}_{:x}", nanos());
    let receipt_ref = format!("agentgres://{}/{id}", if prefix == "wrr" { "work-result-receipt" } else { "outcome-delta-receipt" });
    let rec = json!({
        "schema_version": schema, "receipt_id": id, "receipt_ref": receipt_ref,
        "subject_ref": subject_ref, "op": op, "outcome": "ok", "at": now
    });
    (id, rec)
}

/// Atomic-with-rollback finalization (the standing #62/#69 discipline): record FIRST, receipt
/// SECOND, receipt failure removes the record with a CHECKED rollback; distinct typed lanes.
fn finalize_plane_persist(
    data_dir: &str,
    record_dir: &str,
    receipt_dir: &str,
    record_id: &str,
    record: &Value,
    receipt_id: &str,
    receipt: &Value,
) -> Result<(), VErr> {
    if let Err(e) = persist_record(data_dir, record_dir, record_id, record) {
        return Err(verr("work_result_record_persist_failed", format!("record persist failed ({e}) — nothing changed")));
    }
    match persist_record(data_dir, receipt_dir, receipt_id, receipt) {
        Ok(()) => Ok(()),
        Err(e) => {
            if remove_record(data_dir, record_dir, record_id) {
                Err(verr("work_result_receipt_persist_failed", format!("receipt persist failed ({e}); the created record was rolled back — nothing changed")))
            } else {
                Err(verr("work_result_rollback_failed", format!("receipt persist failed ({e}) AND the created record rollback failed — manual repair required for '{record_id}'")))
            }
        }
    }
}

/// Validate a WorkResult admission body into its durable record (PURE — no I/O, no ids/times).
fn validate_work_result(body: &Value) -> Result<Value, VErr> {
    reject_plaintext_secrets(body)?;
    let goal_ref = match str_opt_bounded(body, "goal_ref", GOAL_REF_MAX)? {
        Some(g) => g,
        None => return Err(verr("work_result_goal_ref_required", "A WorkResult requires `goal_ref` — every result is goal-shaped work.")),
    };
    let result_profile = vocab_required(body, "result_profile", RESULT_PROFILES, "work_result_profile_invalid")?;
    let outcome_class = vocab_required(body, "outcome_class", OUTCOME_CLASSES, "work_result_outcome_class_invalid")?;
    let status = vocab_required(body, "status", RESULT_STATUSES, "work_result_status_invalid")?;
    let next_action = match str_opt_bounded(body, "next_action", 80)? {
        None => "none".to_string(), // canonical default: a result with no follow-up declares none
        Some(v) if NEXT_ACTIONS.contains(&v.as_str()) => v,
        Some(v) => return Err(verr("work_result_next_action_invalid", format!("`next_action` value '{v}' is not a member of [{}]", NEXT_ACTIONS.join("|")))),
    };
    let reproduction_state = match str_opt_bounded(body, "reproduction_state", 80)? {
        None => Value::Null, // canon allows null — an unclaimed reproduction posture stays null
        Some(v) if REPRODUCTION_STATES.contains(&v.as_str()) => Value::String(v),
        Some(v) => return Err(verr("work_result_reproduction_state_invalid", format!("`reproduction_state` value '{v}' is not a member of [{}]", REPRODUCTION_STATES.join("|")))),
    };
    // `uncertainty` is number | string | object | null per canon — bounded by serialized size.
    let uncertainty = match body.get("uncertainty") {
        None | Some(Value::Null) => Value::Null,
        Some(v @ (Value::Number(_) | Value::String(_) | Value::Object(_))) => {
            if v.to_string().chars().count() > UNCERTAINTY_MAX {
                return Err(verr("work_result_field_too_long", format!("`uncertainty` exceeds the bounded serialized length ({UNCERTAINTY_MAX})")));
            }
            v.clone()
        }
        Some(_) => return Err(verr("work_result_field_type_invalid", "`uncertainty` must be a number, string, or object when present")),
    };
    let opt = |k: &str| str_opt_bounded(body, k, REF_MAX);
    let record = json!({
        "schema_version": RESULT_SCHEMA,
        "goal_ref": goal_ref,
        "goal_run_ref": opt("goal_run_ref")?,
        "outcome_room_ref": opt("outcome_room_ref")?,
        "work_claim_ref": opt("work_claim_ref")?,
        "attempt_ref": opt("attempt_ref")?,
        "invocation_or_run_ref": opt("invocation_or_run_ref")?,
        "result_profile": result_profile,
        "result_profile_ref": opt("result_profile_ref")?,
        "result_payload_ref": opt("result_payload_ref")?,
        "worker_harness_model_runtime_version_refs": ref_list_bounded(body, "worker_harness_model_runtime_version_refs")?,
        "declared_method_and_lineage_refs": ref_list_bounded(body, "declared_method_and_lineage_refs")?,
        "outcome_class": outcome_class,
        "status": status,
        "outcome_delta_refs": ref_list_bounded(body, "outcome_delta_refs")?,
        "finding_refs": ref_list_bounded(body, "finding_refs")?,
        "claim_refs": ref_list_bounded(body, "claim_refs")?,
        "uncertainty": uncertainty,
        "supporting_evidence_refs": ref_list_bounded(body, "supporting_evidence_refs")?,
        "contradicting_evidence_refs": ref_list_bounded(body, "contradicting_evidence_refs")?,
        "artifact_receipt_and_trace_refs": ref_list_bounded(body, "artifact_receipt_and_trace_refs")?,
        "resource_and_cost_refs": ref_list_bounded(body, "resource_and_cost_refs")?,
        "authority_and_policy_refs": ref_list_bounded(body, "authority_and_policy_refs")?,
        "blocker_and_decision_request_refs": ref_list_bounded(body, "blocker_and_decision_request_refs")?,
        "verifier_refs": ref_list_bounded(body, "verifier_refs")?,
        "license_disclosure_retention_and_export_refs": ref_list_bounded(body, "license_disclosure_retention_and_export_refs")?,
        "reproduction_state": reproduction_state,
        "reproduction_refs": ref_list_bounded(body, "reproduction_refs")?,
        "acceptance_ref": opt("acceptance_ref")?,
        "challenge_refs": ref_list_bounded(body, "challenge_refs")?,
        "supersedes_work_result_ref": opt("supersedes_work_result_ref")?,
        "superseded_by_ref": opt("superseded_by_ref")?,
        "summary_ref": opt("summary_ref")?,
        "next_action": next_action,
        "runtimeTruthSource": "daemon-runtime"
    });
    Ok(record)
}

fn load_by(data_dir: &str, dir: &str, id_key: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, dir)
        .into_iter()
        .find(|r| r.get(id_key).and_then(|v| v.as_str()) == Some(id))
}

/// Validate an OutcomeDelta admission body (PURE except the result-resolution closure): the
/// delta-binds-result invariant is enforced HERE, before anything could persist.
fn validate_outcome_delta(
    body: &Value,
    resolve_result: &dyn Fn(&str) -> bool,
) -> Result<Value, VErr> {
    reject_plaintext_secrets(body)?;
    // Plane-owned fields refuse typed — a caller can never self-admit or self-receipt a delta.
    if body.get("status").map(|v| !v.is_null()).unwrap_or(false) {
        return Err(verr("outcome_delta_status_plane_owned", "`status` is plane-owned: a delta admits as `proposed`; evaluation/admission transitions are a named gap (build steps 2-3 authority)."));
    }
    if body.get("admission_receipt_ref").map(|v| !v.is_null()).unwrap_or(false) {
        return Err(verr("outcome_delta_receipt_plane_owned", "`admission_receipt_ref` is minted by this plane — it is never accepted from the caller."));
    }
    let goal_ref = match str_opt_bounded(body, "goal_ref", GOAL_REF_MAX)? {
        Some(g) => g,
        None => return Err(verr("outcome_delta_goal_ref_required", "An OutcomeDelta requires `goal_ref`.")),
    };
    let delta_kind = vocab_required(body, "delta_kind", DELTA_KINDS, "outcome_delta_kind_invalid")?;
    // THE INVARIANT: the delta binds an EXISTING admitted WorkResult at write.
    let proposed_by = match str_opt_bounded(body, "proposed_by_ref", REF_MAX)? {
        Some(p) => p,
        None => return Err(verr("outcome_delta_unbound_result", "`proposed_by_ref` is required: an OutcomeDelta binds an admitted work-result:// at write.")),
    };
    if let Some(scheme) = proposed_by.split("://").next() {
        if UNAVAILABLE_PROPOSER_SCHEMES.contains(&scheme) {
            return Err(verr("outcome_delta_proposer_kind_unavailable", format!("`proposed_by_ref` scheme '{scheme}://' names a plane that is not admitted yet (build step 3) — today a delta binds an admitted work-result://.")));
        }
    }
    let Some(result_id) = proposed_by.strip_prefix("work-result://") else {
        return Err(verr("outcome_delta_unbound_result", "`proposed_by_ref` must be a work-result:// ref — the delta-binds-result invariant is fail-closed."));
    };
    if result_id.is_empty() || !resolve_result(result_id) {
        return Err(verr("outcome_delta_unbound_result", format!("`proposed_by_ref` does not resolve to an admitted WorkResult ('{result_id}') — nothing was created.")));
    }
    let target_ref = match str_opt_bounded(body, "target_ref", REF_MAX)? {
        Some(t) => t,
        None => return Err(verr("outcome_delta_target_required", format!("`target_ref` is required and must use a canonical scheme [{}]", DELTA_TARGET_SCHEMES.join("|")))),
    };
    match target_ref.split("://").next() {
        Some(scheme) if DELTA_TARGET_SCHEMES.contains(&scheme) => {}
        _ => return Err(verr("outcome_delta_target_scheme_invalid", format!("`target_ref` scheme must be one of [{}]", DELTA_TARGET_SCHEMES.join("|")))),
    }
    let opt = |k: &str| str_opt_bounded(body, k, REF_MAX);
    let record = json!({
        "schema_version": DELTA_SCHEMA,
        "goal_ref": goal_ref,
        "outcome_room_ref": opt("outcome_room_ref")?,
        "proposed_by_ref": proposed_by,
        "target_ref": target_ref,
        "delta_kind": delta_kind,
        "payload_ref": opt("payload_ref")?,
        "precondition_and_invariant_refs": ref_list_bounded(body, "precondition_and_invariant_refs")?,
        "expected_effect_ref": opt("expected_effect_ref")?,
        "verifier_and_acceptance_refs": ref_list_bounded(body, "verifier_and_acceptance_refs")?,
        "status": "proposed",
        "runtimeTruthSource": "daemon-runtime"
    });
    Ok(record)
}

fn sorted_newest(data_dir: &str, dir: &str) -> Vec<Value> {
    let mut items = read_record_dir(data_dir, dir);
    items.sort_by(|a, b| s(b, "created_at", "").cmp(&s(a, "created_at", "")));
    items
}

// ================================ HANDLERS =======================================================

pub(crate) async fn handle_work_results_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "schema_version": RESULT_SCHEMA, "work_results": sorted_newest(&st.data_dir, RESULT_DIR), "runtimeTruthSource": "daemon-runtime" }))
}

pub(crate) async fn handle_work_result_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_by(&st.data_dir, RESULT_DIR, "work_result_id", &format!("work-result://{id}")) {
        Some(r) => (StatusCode::OK, Json(json!({ "work_result": r }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": { "code": "not_found", "work_result": id } }))),
    }
}

/// GET /v1/hypervisor/work-results/overview — the DECLARATION VOCABULARY projection (a consuming
/// surface derives its pickers from THIS, never a hardcoded copy) + honest governance gaps.
pub(crate) async fn handle_work_results_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let results = read_record_dir(&st.data_dir, RESULT_DIR);
    let deltas = read_record_dir(&st.data_dir, DELTA_DIR);
    Json(json!({
        "schema_version": OVERVIEW_SCHEMA,
        "work_results": results.len(),
        "outcome_deltas": deltas.len(),
        "result_profiles": RESULT_PROFILES,
        "outcome_classes": OUTCOME_CLASSES,
        "statuses": RESULT_STATUSES,
        "next_actions": NEXT_ACTIONS,
        "reproduction_states": REPRODUCTION_STATES,
        "delta_kinds": DELTA_KINDS,
        "delta_target_schemes": DELTA_TARGET_SCHEMES,
        "governance_gaps": [
            "results and deltas are ADMITTED DECLARATIONS with durable receipts — acceptance, verification, adjudication, and settlement are the assurance-ladder rungs above admission and are NOT implied (a receipt is not proof of correctness)",
            "outcome-delta evaluation/admission/rollback TRANSITIONS are not wired: status is plane-owned at `proposed` until the room/acceptance authority of build steps 2-3 exists",
            "attempt://, finding://, and participant-lease:// proposers are named gaps (build step 3) — today a delta binds an admitted work-result://",
            "outcome_room_ref is a declared ref: the hosted OutcomeRoom aggregate is build step 2 and nothing here creates or validates a room"
        ],
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// POST /v1/hypervisor/work-results — admit a generic WorkResult (fail-closed, atomic, receipted).
pub(crate) async fn handle_work_result_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let err400 = |(code, msg): VErr| (StatusCode::BAD_REQUEST, Json(json!({ "error": { "code": code, "message": msg } })));
    let mut record = match validate_work_result(&body) {
        Ok(r) => r,
        Err(e) => return err400(e),
    };
    let id_tail = format!("wr_{:x}", nanos());
    let work_result_id = format!("work-result://{id_tail}");
    let now = iso_now();
    let (receipt_id, receipt) = build_plane_receipt(RESULT_RECEIPT_SCHEMA, "wrr", &work_result_id, "admitted", &now);
    let obj = record.as_object_mut().expect("record is an object");
    obj.insert("work_result_id".into(), json!(work_result_id));
    obj.insert("admission_receipt_ref".into(), receipt["receipt_ref"].clone());
    obj.insert("created_at".into(), json!(now));
    obj.insert("updated_at".into(), json!(now));
    if let Err((code, msg)) = finalize_plane_persist(&st.data_dir, RESULT_DIR, RESULT_RECEIPT_DIR, &id_tail, &record, &receipt_id, &receipt) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": { "code": code, "message": msg } })));
    }
    (StatusCode::CREATED, Json(json!({ "work_result": record, "work_result_receipt": receipt })))
}

pub(crate) async fn handle_outcome_deltas_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "schema_version": DELTA_SCHEMA, "outcome_deltas": sorted_newest(&st.data_dir, DELTA_DIR), "runtimeTruthSource": "daemon-runtime" }))
}

pub(crate) async fn handle_outcome_delta_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_by(&st.data_dir, DELTA_DIR, "outcome_delta_id", &format!("outcome-delta://{id}")) {
        Some(r) => (StatusCode::OK, Json(json!({ "outcome_delta": r }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": { "code": "not_found", "outcome_delta": id } }))),
    }
}

/// POST /v1/hypervisor/outcome-deltas — admit a delta bound to an EXISTING WorkResult.
pub(crate) async fn handle_outcome_delta_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let err400 = |(code, msg): VErr| (StatusCode::BAD_REQUEST, Json(json!({ "error": { "code": code, "message": msg } })));
    let data_dir = st.data_dir.clone();
    let resolve = |rid: &str| load_by(&data_dir, RESULT_DIR, "work_result_id", &format!("work-result://{rid}")).is_some();
    let mut record = match validate_outcome_delta(&body, &resolve) {
        Ok(r) => r,
        Err(e) => return err400(e),
    };
    let id_tail = format!("od_{:x}", nanos());
    let outcome_delta_id = format!("outcome-delta://{id_tail}");
    let now = iso_now();
    let (receipt_id, receipt) = build_plane_receipt(DELTA_RECEIPT_SCHEMA, "odr", &outcome_delta_id, "proposed", &now);
    let obj = record.as_object_mut().expect("record is an object");
    obj.insert("outcome_delta_id".into(), json!(outcome_delta_id));
    obj.insert("admission_receipt_ref".into(), receipt["receipt_ref"].clone());
    obj.insert("created_at".into(), json!(now));
    obj.insert("updated_at".into(), json!(now));
    if let Err((code, msg)) = finalize_plane_persist(&st.data_dir, DELTA_DIR, DELTA_RECEIPT_DIR, &id_tail, &record, &receipt_id, &receipt) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": { "code": code, "message": msg } })));
    }
    (StatusCode::CREATED, Json(json!({ "outcome_delta": record, "outcome_delta_receipt": receipt })))
}

#[cfg(test)]
mod work_result_tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ioi-wr-{tag}-{:x}", nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
    fn valid_result_body() -> Value {
        json!({
            "goal_ref": "goal://g-research-1",
            "result_profile": "research",
            "outcome_class": "positive",
            "status": "completed",
            "supporting_evidence_refs": ["artifact://a1", "receipt://r1"]
        })
    }

    #[test]
    fn generic_profiles_admit_beyond_software() {
        // The GENERAL model: research (and every canonical profile) validates without any
        // software file/diff/test fields; software_implementation is ONE profile.
        for p in RESULT_PROFILES {
            let mut b = valid_result_body();
            b["result_profile"] = json!(p);
            let rec = validate_work_result(&b).unwrap();
            assert_eq!(rec["result_profile"], json!(*p));
            assert_eq!(rec["next_action"], json!("none")); // canonical default
            assert_eq!(rec["reproduction_state"], Value::Null); // honest unclaimed posture
        }
    }

    #[test]
    fn vocabularies_fail_closed_and_fields_are_typed_bounded() {
        let cases: Vec<(Value, &str)> = vec![
            (json!({ "result_profile": "research", "outcome_class": "positive", "status": "completed" }), "work_result_goal_ref_required"),
            ({ let mut b = valid_result_body(); b["result_profile"] = json!("prose"); b }, "work_result_profile_invalid"),
            ({ let mut b = valid_result_body(); b["outcome_class"] = json!("great"); b }, "work_result_outcome_class_invalid"),
            ({ let mut b = valid_result_body(); b["status"] = json!("done"); b }, "work_result_status_invalid"),
            ({ let mut b = valid_result_body(); b["next_action"] = json!("panic"); b }, "work_result_next_action_invalid"),
            ({ let mut b = valid_result_body(); b["reproduction_state"] = json!("sure"); b }, "work_result_reproduction_state_invalid"),
            ({ let mut b = valid_result_body(); b["goal_run_ref"] = json!(7); b }, "work_result_field_type_invalid"),
            ({ let mut b = valid_result_body(); b["finding_refs"] = json!("finding://f1"); b }, "work_result_field_type_invalid"),
            ({ let mut b = valid_result_body(); b["finding_refs"] = json!([7]); b }, "work_result_field_type_invalid"),
            ({ let mut b = valid_result_body(); b["goal_ref"] = json!("g".repeat(GOAL_REF_MAX + 1)); b }, "work_result_field_too_long"),
            ({ let mut b = valid_result_body(); b["uncertainty"] = json!(true); b }, "work_result_field_type_invalid"),
            ({ let mut b = valid_result_body(); b["password"] = json!("hunter2"); b }, "work_result_plaintext_secret_rejected"),
        ];
        for (body, code) in cases {
            assert_eq!(validate_work_result(&body).unwrap_err().0, code, "body: {body}");
        }
        // Consistent empties: omitted lists are [], omitted optionals are null.
        let rec = validate_work_result(&valid_result_body()).unwrap();
        assert_eq!(rec["finding_refs"], json!([]));
        assert_eq!(rec["acceptance_ref"], Value::Null);
        assert_eq!(rec["uncertainty"], Value::Null);
    }

    #[test]
    fn delta_binds_result_invariant_is_fail_closed() {
        let exists = |rid: &str| rid == "wr_real";
        let base = json!({ "goal_ref": "goal://g1", "delta_kind": "update", "target_ref": "frontier://f1" });
        // Missing proposer → unbound.
        assert_eq!(validate_outcome_delta(&base, &exists).unwrap_err().0, "outcome_delta_unbound_result");
        // Non-work-result scheme → unbound (fail-closed, never dangling).
        let mut b = base.clone(); b["proposed_by_ref"] = json!("mystery://x");
        assert_eq!(validate_outcome_delta(&b, &exists).unwrap_err().0, "outcome_delta_unbound_result");
        // Canon-named but not-yet-admitted proposer planes → their OWN typed named gap.
        for scheme in UNAVAILABLE_PROPOSER_SCHEMES {
            let mut b = base.clone(); b["proposed_by_ref"] = json!(format!("{scheme}://x1"));
            assert_eq!(validate_outcome_delta(&b, &exists).unwrap_err().0, "outcome_delta_proposer_kind_unavailable");
        }
        // Unresolvable work-result → unbound; NOTHING validated through.
        let mut b = base.clone(); b["proposed_by_ref"] = json!("work-result://wr_ghost");
        assert_eq!(validate_outcome_delta(&b, &exists).unwrap_err().0, "outcome_delta_unbound_result");
        // Resolvable → admitted as proposed, binding recorded.
        let mut b = base.clone(); b["proposed_by_ref"] = json!("work-result://wr_real");
        let rec = validate_outcome_delta(&b, &exists).unwrap();
        assert_eq!(rec["status"], json!("proposed"));
        assert_eq!(rec["proposed_by_ref"], json!("work-result://wr_real"));
        // Target scheme is canonical-only.
        let mut b2 = b.clone(); b2["target_ref"] = json!("wat://x");
        assert_eq!(validate_outcome_delta(&b2, &exists).unwrap_err().0, "outcome_delta_target_scheme_invalid");
        // Plane-owned fields refuse typed.
        let mut b3 = b.clone(); b3["status"] = json!("admitted");
        assert_eq!(validate_outcome_delta(&b3, &exists).unwrap_err().0, "outcome_delta_status_plane_owned");
        let mut b4 = b.clone(); b4["admission_receipt_ref"] = json!("receipt://forged");
        assert_eq!(validate_outcome_delta(&b4, &exists).unwrap_err().0, "outcome_delta_receipt_plane_owned");
    }

    #[test]
    fn finalize_atomicity_no_orphan_record_no_orphan_receipt() {
        let dir = temp_dir("atomic");
        let data_dir = dir.to_str().unwrap();
        let now = "2026-01-01T00:00:00Z";
        let (rid, receipt) = build_plane_receipt(RESULT_RECEIPT_SCHEMA, "wrr", "work-result://wr_x", "admitted", now);
        let record = json!({ "work_result_id": "work-result://wr_x" });
        // Receipt dir blocked → record rolled back (no orphan record).
        std::fs::write(dir.join(RESULT_RECEIPT_DIR), b"blocker").unwrap();
        let (code, msg) = finalize_plane_persist(data_dir, RESULT_DIR, RESULT_RECEIPT_DIR, "wr_x", &record, &rid, &receipt).unwrap_err();
        assert_eq!(code, "work_result_receipt_persist_failed");
        assert!(msg.contains("rolled back"), "{msg}");
        assert!(read_record_dir(data_dir, RESULT_DIR).is_empty(), "no unproven admission survives");
        std::fs::remove_file(dir.join(RESULT_RECEIPT_DIR)).unwrap();
        // Record dir blocked → typed record lane, no orphan receipt. (The rollback above removed
        // the record FILE but persist_record's create_dir_all left the DIRECTORY — clear it so a
        // plain blocker file can occupy the path.)
        std::fs::remove_dir_all(dir.join(RESULT_DIR)).unwrap();
        std::fs::write(dir.join(RESULT_DIR), b"blocker").unwrap();
        let (code2, _) = finalize_plane_persist(data_dir, RESULT_DIR, RESULT_RECEIPT_DIR, "wr_x", &record, &rid, &receipt).unwrap_err();
        assert_eq!(code2, "work_result_record_persist_failed");
        assert!(read_record_dir(data_dir, RESULT_RECEIPT_DIR).is_empty(), "no receipt without its record");
        std::fs::remove_file(dir.join(RESULT_DIR)).unwrap();
        // Happy path: both persist.
        finalize_plane_persist(data_dir, RESULT_DIR, RESULT_RECEIPT_DIR, "wr_x", &record, &rid, &receipt).unwrap();
        assert_eq!(read_record_dir(data_dir, RESULT_DIR).len(), 1);
        assert_eq!(read_record_dir(data_dir, RESULT_RECEIPT_DIR).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn finalize_reports_rollback_failure_as_its_own_typed_lane() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("rbfail");
        let data_dir = dir.to_str().unwrap();
        let now = "2026-01-01T00:00:00Z";
        let (rid, receipt) = build_plane_receipt(DELTA_RECEIPT_SCHEMA, "odr", "outcome-delta://od_z", "proposed", now);
        let record = json!({ "outcome_delta_id": "outcome-delta://od_z" });
        persist_record(data_dir, DELTA_DIR, "od_z", &record).unwrap();
        std::fs::write(dir.join(DELTA_RECEIPT_DIR), b"blocker").unwrap();
        let record_dir = dir.join(DELTA_DIR);
        std::fs::set_permissions(&record_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let out = finalize_plane_persist(data_dir, DELTA_DIR, DELTA_RECEIPT_DIR, "od_z", &record, &rid, &receipt);
        std::fs::set_permissions(&record_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (code, msg) = out.unwrap_err();
        if code == "work_result_rollback_failed" {
            assert!(msg.contains("manual repair required"), "{msg}");
        } else {
            assert_eq!(code, "work_result_receipt_persist_failed"); // root bypasses dir perms in some CI
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
