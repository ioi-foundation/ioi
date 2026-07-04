//! IOI Agent launch plane — the user-facing product mode over the execution substrate.
//!
//! Product decision: users start work with **IOI Agent**; how the work is realized (a direct
//! single-harness session or an internal multi-harness GoalRun compare/reconcile) is a strategy
//! decision made by the pure kernel planner, not a product concept the user must learn. GoalRun
//! stays the internal orchestration/proof object — its refs appear only in advanced/proof detail.
//!
//! Two routes, no parallel truth (everything composes the existing planes by self-call):
//!
//!   POST /v1/hypervisor/ioi-agent/launch-preview
//!     Pure planning over LIVE registry facts: strategy → planned_execution_kind
//!     (direct | goal_run), eligible/excluded harnesses with reason codes, route/privacy/
//!     budget posture, expected receipt classes, and the admission the launch would compose.
//!     No resource is created.
//!
//!   POST /v1/hypervisor/ioi-agent/launch
//!     Two-phase, mirroring every other wallet crossing:
//!       Phase A (no wallet_approval_grant): plan + provision — create the target session (for
//!         direct: WITH the admitted harness binding; for goal_run: plus the GoalRun record) —
//!         then relay the underlying lane's 403 execution_authority challenge, augmented with
//!         launch_id + the created refs. Nothing executes.
//!       Phase B (grant + launch_id): run it — direct: session execute through the admitted
//!         binding; goal_run: start (parallel implementer invocations) + reconcile. Returns the
//!         user-facing IOI Agent result with the proof/advanced refs.
//!     Launches are durable records ("ioi-agent-launches"), never transient state.

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use axum::http::HeaderMap;
use ioi_services::agentic::runtime::kernel::RuntimeKernelService;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::goalrun_routes::{fact_from_profile, live_profiles, profile_by_harness, route_fact};
use super::lifecycle_routes::{deployment_auth_posture, load_session_record, resolve_principal};
use super::{iso_now, persist_record, read_record_dir, sha256_hex_str, DaemonState};

const LAUNCH_KIND: &str = "ioi-agent-launches";
const POLICY_KIND: &str = "ioi-agent-launch-policies";
const POLICY_SCHEMA_VERSION: &str = "ioi.hypervisor.ioi-agent-launch-policy.v1";
const LAUNCH_SCHEMA_VERSION: &str = "ioi.hypervisor.ioi-agent-launch.v1";

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn bad(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
}

fn kernel_err(
    error: ioi_services::agentic::runtime::kernel::runtime_goal_run_admission::RuntimeGoalRunAdmissionError,
) -> (StatusCode, Json<Value>) {
    (
        StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
        Json(json!({
            "ok": false,
            "error": { "code": error.code, "message": error.message, "details": error.details },
        })),
    )
}

async fn self_call(url: &str, method: &str, body: Option<&Value>) -> (u16, Value) {
    let client = reqwest::Client::new();
    let builder = match method {
        "GET" => client.get(url),
        _ => client.post(url),
    };
    let builder = match body {
        Some(payload) => builder.json(payload),
        None => builder,
    };
    // Budget ladder: shim 600s < spawn lane 660s < THIS self-call < composite suite 30m. A compare
    // goal-run start wraps up to two 660s-reaped invocations plus a bounded full-run retry and
    // verify/reconcile, so the wrapper must sit at the suite ceiling — 600s here deterministically
    // broke compare launches (self_call_failed) whenever one implementer ran to its shim budget.
    match builder.timeout(Duration::from_millis(1_800_000)).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            (status, resp.json::<Value>().await.unwrap_or(Value::Null))
        }
        Err(err) => (0, json!({ "error": { "code": "self_call_failed", "message": err.to_string() } })),
    }
}

/// A model route counts as local when its provider binding stays on this host.
fn route_is_local(endpoint: &str) -> bool {
    endpoint.contains("127.0.0.1") || endpoint.contains("localhost") || endpoint.is_empty()
}

// ---------------------------------------------------------------------------
// Durable launch policies — routing/admission preference envelopes (never a harness).
// Seeding model (the simpler honest one): the default set is PROTECTED — field edits and
// deletes are rejected with a clone hint; enable/disable IS allowed so operators can hide a
// default. Clones are ordinary editable records. receipt_required can never be disabled.
// ---------------------------------------------------------------------------

const POLICY_STRATEGIES: &[&str] = &["auto", "direct", "compare", "private_local"];
const POLICY_FAILURE: &[&str] =
    &["stop_on_first_failure", "partial_ok", "require_all", "retry_once"];
const POLICY_SCOPES: &[&str] = &["personal", "project", "org"];

fn load_policy(st: &DaemonState, id: &str) -> Option<Value> {
    read_record_dir(&st.data_dir, POLICY_KIND)
        .into_iter()
        .find(|record| text(record, "policy_id") == id || text(record, "policy_ref") == id)
}

fn seed_policy(id: &str, name: &str, description: &str, body: Value) -> Value {
    let mut record = json!({
        "schema_version": POLICY_SCHEMA_VERSION,
        "policy_id": id,
        "policy_ref": format!("ioi-agent-policy://{id}"),
        "status": "active",
        "scope": "org",
        "origin": "seeded",
        "protected": true,
        "display_name": name,
        "description": description,
        "receipt_required": true,
        "concurrency_limit": 2,
        "created_at": iso_now(),
        "updated_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    if let (Some(target), Some(extra)) = (record.as_object_mut(), body.as_object()) {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
    record
}

fn ensure_policy_seed(st: &DaemonState) {
    if !read_record_dir(&st.data_dir, POLICY_KIND).is_empty() {
        return;
    }
    let seeds = vec![
        seed_policy("pol_auto_default", "Auto default", "IOI Agent decides — direct for simple work, compare for ambiguous/large work.", json!({
            "strategy_preference": "auto",
            "harness_preferences": { "preferred_harness_refs": [], "excluded_harness_refs": [], "allow_fallback": true },
            "model_route_preferences": { "preferred_model_route_refs": [], "private_only": false },
            "assurance": { "require_compare": false, "require_verifier": true, "min_successful_invocations": 1, "require_reconciliation_before_write": true },
            "privacy": { "local_only": false, "forbid_remote_trust": false, "forbid_provider_credentials": false },
            "failure_policy": "partial_ok",
        })),
        seed_policy("pol_fast_local", "Fast local", "Direct execution through the fastest eligible local harness.", json!({
            "strategy_preference": "direct",
            "harness_preferences": { "preferred_harness_refs": ["harness-profile:hp_opencode"], "excluded_harness_refs": [], "allow_fallback": true },
            "model_route_preferences": { "preferred_model_route_refs": [], "private_only": true },
            "assurance": { "require_compare": false, "require_verifier": true, "min_successful_invocations": 1, "require_reconciliation_before_write": false },
            "privacy": { "local_only": true, "forbid_remote_trust": true, "forbid_provider_credentials": true },
            "failure_policy": "retry_once",
        })),
        seed_policy("pol_private_local", "Private local", "Local/private-native routes and local harnesses only; remote and provider-gated slots disabled.", json!({
            "strategy_preference": "private_local",
            "harness_preferences": { "preferred_harness_refs": [], "excluded_harness_refs": [], "allow_fallback": false },
            "model_route_preferences": { "preferred_model_route_refs": [], "private_only": true },
            "assurance": { "require_compare": false, "require_verifier": true, "min_successful_invocations": 1, "require_reconciliation_before_write": true },
            "privacy": { "local_only": true, "forbid_remote_trust": true, "forbid_provider_credentials": true },
            "failure_policy": "partial_ok",
        })),
        seed_policy("pol_compare_before_write", "Compare before write", "Two implementers compare; the workspace changes only through an admitted reconciliation.", json!({
            "strategy_preference": "compare",
            "harness_preferences": { "preferred_harness_refs": [], "excluded_harness_refs": [], "allow_fallback": false },
            "model_route_preferences": { "preferred_model_route_refs": [], "private_only": false },
            "assurance": { "require_compare": true, "require_verifier": true, "min_successful_invocations": 1, "require_reconciliation_before_write": true },
            "privacy": { "local_only": false, "forbid_remote_trust": false, "forbid_provider_credentials": false },
            "failure_policy": "partial_ok",
        })),
        seed_policy("pol_high_assurance", "High assurance", "Compare required, both implementers must verify, reconciliation gates every write.", json!({
            "strategy_preference": "compare",
            "harness_preferences": { "preferred_harness_refs": [], "excluded_harness_refs": [], "allow_fallback": false },
            "model_route_preferences": { "preferred_model_route_refs": [], "private_only": false },
            "assurance": { "require_compare": true, "require_verifier": true, "min_successful_invocations": 2, "require_reconciliation_before_write": true },
            "privacy": { "local_only": false, "forbid_remote_trust": false, "forbid_provider_credentials": false },
            "failure_policy": "require_all",
        })),
    ];
    for record in seeds {
        let id = text(&record, "policy_id").to_string();
        let _ = persist_record(&st.data_dir, POLICY_KIND, &id, &record);
    }
}

/// Validate + normalize a policy payload (create/patch). receipt_required is MANDATORY true.
fn policy_payload(body: &Value, existing: Option<&Value>) -> Result<Value, (StatusCode, Json<Value>)> {
    let mut record = existing.cloned().unwrap_or(json!({}));
    if body.get("receipt_required").and_then(Value::as_bool) == Some(false) {
        return Err(bad(
            StatusCode::FORBIDDEN,
            "ioi_agent_policy_receipts_mandatory",
            "No launch policy may disable receipts.",
        ));
    }
    for (key, allowed) in [
        ("strategy_preference", POLICY_STRATEGIES),
        ("failure_policy", POLICY_FAILURE),
        ("scope", POLICY_SCOPES),
    ] {
        if let Some(value) = body.get(key).and_then(Value::as_str) {
            if !allowed.contains(&value) {
                return Err(bad(
                    StatusCode::BAD_REQUEST,
                    "ioi_agent_policy_field_invalid",
                    &format!("{key} must be one of {allowed:?}"),
                ));
            }
            record[key] = json!(value);
        }
    }
    for key in ["display_name", "description"] {
        if let Some(value) = body.get(key).and_then(Value::as_str) {
            record[key] = json!(value.trim());
        }
    }
    for key in ["harness_preferences", "model_route_preferences", "assurance", "privacy", "memory_posture"] {
        if let Some(value) = body.get(key) {
            if !value.is_object() {
                return Err(bad(
                    StatusCode::BAD_REQUEST,
                    "ioi_agent_policy_field_invalid",
                    &format!("{key} must be an object"),
                ));
            }
            record[key] = value.clone();
        }
    }
    let harness_refs: Vec<String> = ["preferred_harness_refs", "excluded_harness_refs"]
        .iter()
        .flat_map(|key| {
            record
                .pointer(&format!("/harness_preferences/{key}"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    for reference in &harness_refs {
        if !reference.starts_with("harness-profile:") {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "ioi_agent_policy_ref_prefix_invalid",
                "harness preference refs must be harness-profile: refs",
            ));
        }
    }
    if let Some(limit) = body.get("concurrency_limit").and_then(Value::as_u64) {
        if limit == 0 || limit > 2 {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "ioi_agent_policy_concurrency_invalid",
                "concurrency_limit must be 1..=2",
            ));
        }
        record["concurrency_limit"] = json!(limit);
    }
    record["receipt_required"] = json!(true);
    record["updated_at"] = json!(iso_now());
    Ok(record)
}

pub(crate) async fn handle_policies_list(
    State(st): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    ensure_policy_seed(&st);
    let mut policies = read_record_dir(&st.data_dir, POLICY_KIND);
    if let Some(status) = query.get("status") {
        policies.retain(|policy| text(policy, "status") == status);
    }
    policies.sort_by(|a, b| text(a, "display_name").cmp(text(b, "display_name")));
    (StatusCode::OK, Json(json!({ "ok": true, "policies": policies })))
}

pub(crate) async fn handle_policies_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    ensure_policy_seed(&st);
    if text(&body, "display_name").trim().is_empty() {
        return bad(StatusCode::UNPROCESSABLE_ENTITY, "ioi_agent_policy_name_required", "A policy needs a display_name.");
    }
    let id = format!("pol_{:x}", nanos());
    let base = json!({
        "schema_version": POLICY_SCHEMA_VERSION,
        "policy_id": id,
        "policy_ref": format!("ioi-agent-policy://{id}"),
        "status": "active",
        "scope": "personal",
        "origin": "authored",
        "protected": false,
        "strategy_preference": "auto",
        "harness_preferences": { "preferred_harness_refs": [], "excluded_harness_refs": [], "allow_fallback": true },
        "model_route_preferences": { "preferred_model_route_refs": [], "private_only": false },
        "assurance": { "require_compare": false, "require_verifier": true, "min_successful_invocations": 1, "require_reconciliation_before_write": true },
        "privacy": { "local_only": false, "forbid_remote_trust": false, "forbid_provider_credentials": false },
        "failure_policy": "partial_ok",
        "concurrency_limit": 2,
        "receipt_required": true,
        "created_at": iso_now(),
    });
    match policy_payload(&body, Some(&base)) {
        Ok(record) => {
            let _ = persist_record(&st.data_dir, POLICY_KIND, &id, &record);
            (StatusCode::CREATED, Json(json!({ "ok": true, "policy": record })))
        }
        Err(rejection) => rejection,
    }
}

pub(crate) async fn handle_policies_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    ensure_policy_seed(&st);
    match load_policy(&st, &id) {
        Some(policy) => (StatusCode::OK, Json(json!({ "ok": true, "policy": policy }))),
        None => bad(StatusCode::NOT_FOUND, "ioi_agent_policy_not_found", "Unknown launch policy."),
    }
}

pub(crate) async fn handle_policies_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(existing) = load_policy(&st, &id) else {
        return bad(StatusCode::NOT_FOUND, "ioi_agent_policy_not_found", "Unknown launch policy.");
    };
    let protected = existing.get("protected").and_then(Value::as_bool) == Some(true);
    let only_status = body.as_object().map(|o| o.keys().all(|k| k == "status")).unwrap_or(false);
    if protected && !only_status {
        return bad(
            StatusCode::CONFLICT,
            "ioi_agent_policy_seeded_protected",
            "Seeded default policies are protected — clone it to customize (enable/disable is allowed).",
        );
    }
    let mut record = match policy_payload(&body, Some(&existing)) {
        Ok(record) => record,
        Err(rejection) => return rejection,
    };
    if let Some(status) = body.get("status").and_then(Value::as_str) {
        if !["active", "disabled"].contains(&status) {
            return bad(StatusCode::BAD_REQUEST, "ioi_agent_policy_field_invalid", "status must be active|disabled");
        }
        record["status"] = json!(status);
    }
    let pid = text(&record, "policy_id").to_string();
    let _ = persist_record(&st.data_dir, POLICY_KIND, &pid, &record);
    (StatusCode::OK, Json(json!({ "ok": true, "policy": record })))
}

pub(crate) async fn handle_policies_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(existing) = load_policy(&st, &id) else {
        return bad(StatusCode::NOT_FOUND, "ioi_agent_policy_not_found", "Unknown launch policy.");
    };
    if existing.get("protected").and_then(Value::as_bool) == Some(true) {
        return bad(
            StatusCode::CONFLICT,
            "ioi_agent_policy_seeded_protected",
            "Seeded default policies cannot be deleted — disable them instead.",
        );
    }
    let pid = text(&existing, "policy_id").to_string();
    let _ = super::remove_record(&st.data_dir, POLICY_KIND, &pid);
    (StatusCode::OK, Json(json!({ "ok": true, "deleted": pid })))
}

pub(crate) async fn handle_policies_clone(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(source) = load_policy(&st, &id) else {
        return bad(StatusCode::NOT_FOUND, "ioi_agent_policy_not_found", "Unknown launch policy.");
    };
    let new_id = format!("pol_{:x}", nanos());
    let mut clone = source.clone();
    if let Some(obj) = clone.as_object_mut() {
        obj.insert("policy_id".into(), json!(new_id));
        obj.insert("policy_ref".into(), json!(format!("ioi-agent-policy://{new_id}")));
        obj.insert("origin".into(), json!("cloned"));
        obj.insert("protected".into(), json!(false));
        obj.insert("scope".into(), json!("personal"));
        obj.insert("status".into(), json!("active"));
        obj.insert("cloned_from".into(), json!(text(&source, "policy_ref"))) ;
        let name = body.get("display_name").and_then(Value::as_str).map(str::trim).filter(|n| !n.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("{} (copy)", text(&source, "display_name")));
        obj.insert("display_name".into(), json!(name));
        obj.insert("created_at".into(), json!(iso_now()));
        obj.insert("updated_at".into(), json!(iso_now()));
    }
    let _ = persist_record(&st.data_dir, POLICY_KIND, &new_id, &clone);
    (StatusCode::CREATED, Json(json!({ "ok": true, "policy": clone })))
}

// ---------------------------------------------------------------------------
// Learned-policy rollouts — a canary/cohort ReleaseControl bounds WHO sees a learned policy
// variant. The base policy is never mutated: an eligible context is silently upgraded to the
// variant at plan time (recorded + explained), everyone else keeps base behavior. The
// ReleaseControl stays the LIVE gate: a closed gate switches every context back to base.

const GOV_RELEASE_KIND: &str = "governance-release-controls";

/// Deterministic canary bucketing: sha256(context_seed:release_id) → 0..99.
fn canary_bucket(seed: &str, release_id: &str) -> u64 {
    let digest = sha256_hex_str(&format!("{seed}:{release_id}"));
    u64::from_str_radix(digest.get(..8).unwrap_or("0"), 16).unwrap_or(0) % 100
}

/// The rollout identity of THIS request, derived from daemon-known truth — never trusted from
/// arbitrary caller text. Priority: authenticated principal > daemon-known project >
/// explicit test/dev override (kept, but LABELED) > deterministic local-operator posture.
pub(crate) struct RolloutContext {
    /// (canonical ref, source) pairs, priority-ordered.
    refs: Vec<(String, &'static str)>,
    source: &'static str,
    seed: String,
    posture_note: String,
    /// local_development | exposed_untrusted | authenticated_managed — high-trust rollout
    /// eligibility (outside local_development) accepts ONLY authenticated/daemon-known sources.
    posture: &'static str,
}

/// Sources a high-trust posture accepts for learned-rollout eligibility.
fn trusted_source(source: &str) -> bool {
    source == "authenticated_principal" || source == "project" || source == "org"
}

/// The posture-specific block reason for an untrusted context source.
fn untrusted_block_reason(source: &str) -> &'static str {
    if source == "explicit_override" {
        "rollout_explicit_override_disallowed"
    } else {
        "rollout_requires_authenticated_context"
    }
}

fn derive_rollout_context(st: &DaemonState, headers: &HeaderMap, body: &Value) -> RolloutContext {
    let mut refs: Vec<(String, &'static str)> = Vec::new();
    let authenticated = resolve_principal(&st.data_dir, headers);
    if let Some(principal) = &authenticated {
        let pid = text(principal, "principal_id");
        if !pid.is_empty() {
            refs.push((format!("principal://{pid}"), "authenticated_principal"));
        }
    }
    // A project counts as DERIVED context only when it resolves to a daemon project record.
    if let Some(requested) = body.get("project_ref").and_then(Value::as_str).map(str::trim).filter(|r| !r.is_empty()) {
        let candidate = requested.strip_prefix("project://").unwrap_or(requested);
        if let Some(project) = read_record_dir(&st.data_dir, "projects")
            .into_iter()
            .find(|record| text(record, "project_id") == candidate)
        {
            refs.push((format!("project://{}", text(&project, "project_id")), "project"));
        }
    }
    if let Some(explicit) = body.get("rollout_context_ref").and_then(Value::as_str).map(str::trim).filter(|r| !r.is_empty()) {
        refs.push((explicit.to_string(), "explicit_override"));
    }
    let posture = deployment_auth_posture(&st.data_dir, headers);
    let posture_note = match posture {
        "local_development" if authenticated.is_none() => {
            "identity enforcement inactive — deterministic local wallet-holder posture (local development only)".to_string()
        }
        "exposed_untrusted" => {
            "EXPOSED without enforced authentication — learned rollouts require an authenticated principal or daemon-known project; enable authentication".to_string()
        }
        _ => String::new(),
    };
    if refs.is_empty() {
        refs.push(("principal://local-operator".to_string(), "anonymous"));
    }
    let (seed, source) = (refs[0].0.clone(), refs[0].1);
    RolloutContext { refs, source, seed, posture_note, posture }
}

fn rollout_context_fact(ctx: &RolloutContext) -> Value {
    json!({
        "source": ctx.source,
        "refs": ctx.refs.iter().map(|(r, src)| json!({ "ref": r, "source": src })).collect::<Vec<Value>>(),
        "seed": ctx.seed,
        "deployment_posture": ctx.posture,
        "explicit_override_allowed": ctx.posture == "local_development",
        "posture_note": if ctx.posture_note.is_empty() { Value::Null } else { json!(ctx.posture_note) },
    })
}

/// Resolve the rollout variant (if any) that should replace `base` for THIS derived context.
/// Returns (Some((variant, explanation)) when applied, per-variant skip explanations otherwise).
fn resolve_policy_rollout(st: &DaemonState, base: &Value, ctx: &RolloutContext) -> (Option<(Value, Value)>, Vec<Value>) {
    let mut skipped: Vec<Value> = Vec::new();
    if base.is_null() {
        return (None, skipped);
    }
    let base_ref = text(base, "policy_ref").to_string();
    let now = iso_now();
    let mut variants: Vec<Value> = read_record_dir(&st.data_dir, POLICY_KIND)
        .into_iter()
        .filter(|record| {
            text(record, "status") == "active"
                && record.pointer("/rollout/base_policy_ref").and_then(Value::as_str) == Some(base_ref.as_str())
                && ["active", "promoted"]
                    .contains(&record.pointer("/rollout/state").and_then(Value::as_str).unwrap_or(""))
        })
        .collect();
    variants.sort_by(|a, b| text(b, "created_at").cmp(text(a, "created_at")));
    for variant in variants {
        let variant_ref = text(&variant, "policy_ref").to_string();
        let mut skip = |reason: String| {
            skipped.push(json!({
                "variant_policy_ref": variant_ref,
                "base_policy_ref": base_ref,
                "reason_code": reason,
            }));
        };
        let control_ref = variant
            .pointer("/rollout/release_control_ref")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let control_id = control_ref.trim_start_matches("release-control://").to_string();
        let Some(control) = read_record_dir(&st.data_dir, GOV_RELEASE_KIND)
            .into_iter()
            .find(|r| text(r, "id") == control_id)
        else {
            skip("release_control_unresolved".to_string());
            continue;
        };
        if text(&control, "state") != "open" {
            skip("release_control_not_open".to_string()); // gate closed → base behavior
            continue;
        }
        let starts = text(&control, "starts_at").to_string();
        let ends = text(&control, "ends_at").to_string();
        if (!starts.is_empty() && now < starts) || (!ends.is_empty() && now > ends) {
            skip("rollout_window_inactive".to_string());
            continue;
        }
        let promoted = variant.pointer("/rollout/state").and_then(Value::as_str) == Some("promoted");
        let mode = {
            let m = text(&control, "rollout_mode");
            if m.is_empty() { "full".to_string() } else { m.to_string() }
        };
        // (eligible?, reason, matched ref/source, matched cohort object)
        let mut matched: Option<(String, &'static str, Option<Value>, String)> = None;
        let mut miss_reason = String::new();
        let seed_trusted = ctx.posture == "local_development" || trusted_source(ctx.source);
        if (promoted || mode == "full" || mode == "canary") && !seed_trusted {
            // Anonymous/override contexts never activate learned overlays outside local dev.
            skip(untrusted_block_reason(ctx.source).to_string());
            continue;
        }
        if promoted {
            matched = Some((ctx.seed.clone(), ctx.source, None, "rollout_promoted_full".to_string()));
        } else if mode == "full" {
            matched = Some((ctx.seed.clone(), ctx.source, None, "rollout_full".to_string()));
        } else if mode == "cohort" {
            let high_trust = ctx.posture != "local_development";
            let entries: Vec<String> = control
                .get("cohort_refs")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                .unwrap_or_default();
            let mut any_active_cohort = false;
            let mut any_disabled_cohort = false;
            let mut untrusted_hit: Option<&'static str> = None;
            for entry in &entries {
                let members_match = |members: &[String]| -> (Option<(String, &'static str)>, Option<&'static str>) {
                    // Trusted sources only outside local_development; remember what an
                    // UNTRUSTED ref would have matched so the block is named, not silent.
                    let trusted = ctx.refs.iter().find(|(r, src)| members.contains(r) && (!high_trust || trusted_source(src)));
                    if let Some((r, src)) = trusted {
                        return (Some((r.clone(), src)), None);
                    }
                    let untrusted = ctx.refs.iter().find(|(r, _)| members.contains(r));
                    (None, untrusted.map(|(_, src)| untrusted_block_reason(src)))
                };
                if let Some(cohort_id) = entry.strip_prefix("cohort://") {
                    let Some(cohort) = read_record_dir(&st.data_dir, "governance-cohorts")
                        .into_iter()
                        .find(|c| text(c, "id") == cohort_id)
                    else {
                        continue;
                    };
                    if text(&cohort, "status") != "active" {
                        any_disabled_cohort = true;
                        continue; // disabled cohorts never match
                    }
                    any_active_cohort = true;
                    let members: Vec<String> = cohort
                        .get("member_refs")
                        .and_then(Value::as_array)
                        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                        .unwrap_or_default();
                    let (hit, blocked) = members_match(&members);
                    if let Some(reason) = blocked {
                        untrusted_hit = Some(reason);
                    }
                    if let Some((context_ref, source)) = hit {
                        matched = Some((context_ref, source, Some(cohort.clone()), format!("rollout_cohort_match:{entry}")));
                        break;
                    }
                } else {
                    // DEPRECATED raw member ref (pre-cohort-object controls) — still honored, marked.
                    let (hit, blocked) = members_match(std::slice::from_ref(entry));
                    if let Some(reason) = blocked {
                        untrusted_hit = Some(reason);
                    }
                    if let Some((context_ref, source)) = hit {
                        matched = Some((context_ref, source, None, format!("rollout_cohort_match_deprecated_raw:{entry}")));
                        break;
                    }
                }
            }
            if matched.is_none() {
                miss_reason = if let Some(blocked) = untrusted_hit {
                    blocked.to_string()
                } else if any_disabled_cohort && !any_active_cohort {
                    "rollout_cohort_disabled".to_string()
                } else {
                    "rollout_cohort_no_match".to_string()
                };
            }
        } else {
            // canary: bucket the DERIVED stable seed, never arbitrary request text.
            let percent = control.get("canary_percent").and_then(Value::as_u64).unwrap_or(0).min(100);
            let bucket = canary_bucket(&ctx.seed, &control_id);
            if bucket < percent {
                matched = Some((ctx.seed.clone(), ctx.source, None, format!("rollout_canary_bucket:{bucket}/{percent}")));
            } else {
                miss_reason = format!("rollout_canary_bucket_miss:{bucket}/{percent}");
            }
        }
        match matched {
            Some((matched_ref, matched_source, cohort, reason)) => {
                let note = json!({
                    "variant_policy_ref": variant_ref,
                    "base_policy_ref": base_ref,
                    "release_control_ref": control_ref,
                    "rollout_mode": mode,
                    "rollout_state": variant.pointer("/rollout/state").cloned().unwrap_or(Value::Null),
                    "reason_code": reason,
                    "matched_ref": matched_ref,
                    "rollout_context_source": matched_source,
                    "override": matched_source == "explicit_override",
                    "cohort_ref": cohort.as_ref().map(|c| text(c, "ref").to_string()),
                    "cohort_display_name": cohort.as_ref().map(|c| text(c, "display_name").to_string()),
                    "proposal_ref": variant.pointer("/rollout/proposal_ref").cloned().unwrap_or(Value::Null),
                });
                return (Some((variant, note)), skipped);
            }
            None => skip(miss_reason),
        }
    }
    (None, skipped)
}

/// Bind rollout provenance onto a (just-cloned) learned policy variant. Called by the
/// improvement apply lane — the variant carries WHY it exists and what gates it.
pub(crate) fn bind_policy_rollout(st: &DaemonState, policy_id: &str, rollout: Value) -> Option<Value> {
    let mut policy = load_policy(st, policy_id)?;
    policy["rollout"] = rollout;
    policy["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, POLICY_KIND, policy_id, &policy);
    Some(policy)
}

fn rollout_receipt(st: &DaemonState, action: &str, policy: &Value) -> String {
    let policy_id = text(policy, "policy_id");
    let receipt_ref = format!("receipt://hypervisor/policy-rollout/{policy_id}-{action}");
    let rollout = policy.get("rollout").cloned().unwrap_or(json!({}));
    let control = rollout
        .get("release_control_ref")
        .and_then(Value::as_str)
        .map(|r| r.trim_start_matches("release-control://").to_string())
        .and_then(|id| read_record_dir(&st.data_dir, GOV_RELEASE_KIND).into_iter().find(|r| text(r, "id") == id));
    let receipt = json!({
        "id": receipt_ref,
        "kind": "hypervisor.policy-rollout",
        "action": action,
        "policy_ref": text(policy, "policy_ref"),
        "base_policy_ref": rollout.get("base_policy_ref").cloned().unwrap_or(Value::Null),
        "release_control_ref": rollout.get("release_control_ref").cloned().unwrap_or(Value::Null),
        "proposal_ref": rollout.get("proposal_ref").cloned().unwrap_or(Value::Null),
        "simulation_ref": rollout.get("simulation_ref").cloned().unwrap_or(Value::Null),
        "approval_request_ref": rollout.get("approval_request_ref").cloned().unwrap_or(Value::Null),
        "cohort_refs": control.as_ref().and_then(|c| c.get("cohort_refs")).cloned().unwrap_or(json!([])),
        "rollout_mode": control.as_ref().and_then(|c| c.get("rollout_mode")).cloned().unwrap_or(Value::Null),
        "at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_ref, &receipt);
    receipt_ref
}

fn patch_release_control(st: &DaemonState, control_ref: &str, fields: Value) {
    let id = control_ref.trim_start_matches("release-control://").to_string();
    if let Some(mut control) = read_record_dir(&st.data_dir, GOV_RELEASE_KIND)
        .into_iter()
        .find(|r| text(r, "id") == id)
    {
        if let (Some(target), Some(extra)) = (control.as_object_mut(), fields.as_object()) {
            for (key, value) in extra {
                target.insert(key.clone(), value.clone());
            }
        }
        control["updated_at"] = json!(iso_now());
        let _ = persist_record(&st.data_dir, GOV_RELEASE_KIND, &id, &control);
    }
}

/// Promote: the learned variant becomes normal behavior for EVERY context that uses the base
/// policy (still overlay-selected; the base record — often a protected seed — is never mutated).
pub(crate) async fn handle_policy_rollout_promote(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut policy) = load_policy(&st, &id) else {
        return bad(StatusCode::NOT_FOUND, "ioi_agent_policy_unresolved", "Unknown policy.");
    };
    if policy.pointer("/rollout/state").and_then(Value::as_str) != Some("active") {
        return bad(StatusCode::CONFLICT, "policy_rollout_state_invalid", "Promote requires an ACTIVE rollout-bound learned policy.");
    }
    policy["rollout"]["state"] = json!("promoted");
    policy["rollout"]["promoted_at"] = json!(iso_now());
    policy["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, POLICY_KIND, &id, &policy);
    let control_ref = policy.pointer("/rollout/release_control_ref").and_then(Value::as_str).unwrap_or("").to_string();
    patch_release_control(&st, &control_ref, json!({ "rollout_mode": "full", "promoted_at": iso_now() }));
    let receipt_ref = rollout_receipt(&st, "promote", &policy);
    (StatusCode::OK, Json(json!({ "ok": true, "policy": policy, "receipt_refs": [receipt_ref] })))
}

/// Rollback: the overlay stops selecting the variant ANYWHERE; base behavior resumes. The
/// variant record and every proposal/simulation/approval/release evidence record is retained.
pub(crate) async fn handle_policy_rollout_rollback(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut policy) = load_policy(&st, &id) else {
        return bad(StatusCode::NOT_FOUND, "ioi_agent_policy_unresolved", "Unknown policy.");
    };
    if !["active", "promoted"].contains(&policy.pointer("/rollout/state").and_then(Value::as_str).unwrap_or("")) {
        return bad(StatusCode::CONFLICT, "policy_rollout_state_invalid", "Rollback requires an ACTIVE or PROMOTED rollout-bound learned policy.");
    }
    policy["rollout"]["state"] = json!("rolled_back");
    policy["rollout"]["rolled_back_at"] = json!(iso_now());
    policy["status"] = json!("disabled"); // fail-closed: explicit selection of a rolled-back variant refuses
    policy["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, POLICY_KIND, &id, &policy);
    let control_ref = policy.pointer("/rollout/release_control_ref").and_then(Value::as_str).unwrap_or("").to_string();
    patch_release_control(&st, &control_ref, json!({ "rollback_state": "rolled_back", "rollback_requested": true, "rolled_back_at": iso_now() }));
    let receipt_ref = rollout_receipt(&st, "rollback", &policy);
    (StatusCode::OK, Json(json!({ "ok": true, "policy": policy, "receipt_refs": [receipt_ref] })))
}

/// Gather LIVE facts and run the pure strategy planner. Shared by preview + launch.
async fn plan(st: &DaemonState, headers: &HeaderMap, body: &Value) -> Result<(Value, Value), (StatusCode, Json<Value>)> {
    let goal = text(body, "goal").trim().to_string();
    // Durable policy resolution (fail-closed): an unknown or disabled policy never launches.
    ensure_policy_seed(st);
    let policy = match body.get("policy_ref").and_then(Value::as_str).filter(|r| !r.is_empty()) {
        Some(reference) => {
            let Some(record) = load_policy(st, reference) else {
                return Err(bad(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "ioi_agent_policy_unresolved",
                    "The named launch policy does not exist.",
                ));
            };
            if text(&record, "status") != "active" {
                return Err(bad(
                    StatusCode::CONFLICT,
                    "ioi_agent_policy_disabled",
                    "The named launch policy is disabled.",
                ));
            }
            record
        }
        None => Value::Null,
    };
    // Learned-policy rollout overlay: eligibility derives from daemon-known identity/project,
    // never from arbitrary caller text (explicit overrides stay possible but LABELED).
    let rollout_ctx = derive_rollout_context(st, headers, body);
    let (applied_rollout, rollout_skipped) = resolve_policy_rollout(st, &policy, &rollout_ctx);
    let (policy, rollout_note) = match applied_rollout {
        Some((variant, note)) => (variant, note),
        None => (policy, Value::Null),
    };
    // Strategy: an explicit user choice wins; otherwise the policy's preference; otherwise auto.
    let strategy = {
        let requested = text(body, "strategy").trim().to_lowercase();
        if !requested.is_empty() {
            requested
        } else if !policy.is_null() {
            text(&policy, "strategy_preference").to_string()
        } else {
            "auto".to_string()
        }
    };
    let strategy = if strategy.is_empty() { "auto".to_string() } else { strategy };
    let profiles = live_profiles(st).await;
    let (route_ref, route_state, _model, endpoint) =
        route_fact(st, body.get("model_route_ref").and_then(Value::as_str));
    let route_local = route_is_local(&endpoint);
    let conductor = profile_by_harness(&profiles, "hypervisor_worker")
        .map(|p| fact_from_profile(p, &route_ref, &route_state))
        .unwrap_or(Value::Null);
    let implementer_candidates: Vec<Value> = ["opencode", "deepseek_tui", "codex", "claude_code"]
        .iter()
        .filter_map(|harness| profile_by_harness(&profiles, harness))
        .map(|p| {
            let mut fact = fact_from_profile(p, &route_ref, &route_state);
            fact["model_route_local"] = json!(route_local);
            fact
        })
        .collect();
    let selection = RuntimeKernelService::new()
        .select_ioi_agent_execution(&json!({
            "strategy": strategy,
            "normalized_goal": goal,
            "conductor_ref": text(&conductor, "profile_ref"),
            "implementer_candidates": implementer_candidates,
            "preferred_harness_refs": body.get("preferred_harness_refs").cloned().unwrap_or(json!([])),
            "policy": if policy.is_null() { Value::Null } else { json!({
                "policy_ref": text(&policy, "policy_ref"),
                "harness_preferences": policy.get("harness_preferences").cloned().unwrap_or(json!({})),
                "assurance": policy.get("assurance").cloned().unwrap_or(json!({})),
                "privacy": policy.get("privacy").cloned().unwrap_or(json!({})),
            }) },
        }))
        .map_err(kernel_err)?;
    let facts = json!({
        "goal": goal,
        "route_ref": route_ref,
        "route_state": route_state,
        "route_local": route_local,
        "policy": policy,
        "policy_rollout": rollout_note,
        "policy_rollout_skipped": rollout_skipped,
        "rollout_context": rollout_context_fact(&rollout_ctx),
    });
    Ok((selection, facts))
}

pub(crate) async fn handle_ioi_agent_launch_preview(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if text(&body, "goal").trim().len() < 4 {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "ioi_agent_goal_required",
            "Tell IOI Agent what to do (a few words at least).",
        );
    }
    let (selection, facts) = match plan(&st, &headers, &body).await {
        Ok(planned) => planned,
        Err(rejection) => return rejection,
    };
    let kind = text(&selection, "planned_execution_kind").to_string();
    let policy = facts.get("policy").cloned().unwrap_or(Value::Null);
    let failure_policy = {
        let requested = text(&body, "failure_policy");
        if !requested.is_empty() {
            requested.to_string()
        } else if !policy.is_null() {
            text(&policy, "failure_policy").to_string()
        } else {
            "continue_partial".to_string()
        }
    };
    let expected_receipts = if kind == "goal_run" {
        json!([
            "receipt://hypervisor/session-provision/*",
            "receipt://goal-run/*/create",
            "receipt://hypervisor/goal-run-invocation/*",
            "receipt://hypervisor/goal-run-reconciliation/*",
        ])
    } else {
        json!([
            "receipt://hypervisor/session-provision/*",
            "agentgres://harness-profile-receipt/*",
            "receipt://hypervisor/session-execute/*",
        ])
    };
    let admission_preview = if kind == "goal_run" {
        json!({
            "kinds": ["goal_run_admit", "harness_invocation_admit (per role)", "reconciliation_admit"],
            "authority": "wallet execution grant at start (403 challenge → grant)",
        })
    } else {
        json!({
            "kinds": ["bind_session_profile under scope:harness.profile.mutate"],
            "authority": "wallet execution grant at execute (403 challenge → grant)",
        })
    };
    // Intelligence posture — what a projection WOULD include for the planned harness(es).
    let allow_sensitive = policy
        .pointer("/privacy/allow_private_projection")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (i_entries, i_skills, i_affinities) =
        super::ioi_intelligence_routes::gather_projection_inputs(&st).await;
    let projection_ctx = super::ioi_intelligence_routes::build_projection_context(
        &st,
        &json!({
            "goal": text(&facts, "goal"),
            "harness_profile_ref": selection.get("selected_harness_ref").and_then(Value::as_str)
                .unwrap_or_else(|| selection.get("eligible_harness_refs").and_then(|e| e.get(0)).and_then(Value::as_str).unwrap_or("")),
            "model_route_ref": text(&facts, "route_ref"),
            "privacy_posture": text(&selection, "privacy_posture"),
            "allow_sensitive": allow_sensitive,
            "memory_posture": policy.get("memory_posture").cloned().unwrap_or(Value::Null),
        }),
    )
    .await;
    let intelligence = super::ioi_intelligence_routes::plan_projection(
        &i_entries, &i_skills, &i_affinities, &projection_ctx,
    );
    let space = super::ioi_intelligence_routes::ensure_default_space(&st);
    // The chosen placement venue (durable policy) travels on every preview so New Session states
    // WHERE the work runs, what fee basis applies (declared copy — never a fee object), and which
    // receipts the venue mints — named before launch.
    let placement_block = {
        let policy = super::orchestration_routes::load_venue_policy(&st.data_dir);
        let venue = policy["venue"].as_str().unwrap_or("run_local").to_string();
        json!({
            "venue": venue,
            "effective_venue": policy.get("effective_venue").cloned().unwrap_or(json!(venue.clone())),
            "provider_account_ref": policy.get("provider_account_ref").cloned().unwrap_or(Value::Null),
            "advisory": policy.get("advisory").cloned().unwrap_or(json!(false)),
            "advisory_note": policy.get("advisory_note").cloned().unwrap_or(Value::Null),
            "fee": super::orchestration_routes::venue_fee(&venue),
            "receipts_expected": super::orchestration_routes::venue_receipts_expected(&venue, &st.data_dir),
        })
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "agent": "ioi-agent",
            "coordination": "IOI Agent will coordinate this work",
            "memory_space_refs": [space.get("space_ref").cloned().unwrap_or(Value::Null)],
            "intelligence_projection_preview": {
                "counts": intelligence["counts"],
                "candidate_skill_refs": intelligence["included_skill_refs"],
                "automation_affinity_match": intelligence["automation_affinity_match"],
                "connector_context_refs": intelligence["connector_context_refs"],
                "redacted": intelligence["redacted_entry_refs"],
                "excluded": intelligence["excluded_refs_with_reasons"],
            },
            "strategy": text(&selection, "strategy"),
            "planned_execution_kind": kind,
            "reason_codes": selection.get("reason_codes").cloned().unwrap_or(json!([])),
            "eligible_harnesses": selection.get("eligible_harness_refs").cloned().unwrap_or(json!([])),
            "excluded_harnesses": selection.get("excluded_harnesses").cloned().unwrap_or(json!([])),
            "selected_harness_ref": selection.get("selected_harness_ref").cloned().unwrap_or(Value::Null),
            "model_route_ref": facts.get("route_ref").cloned().unwrap_or(Value::Null),
            "model_route_state": facts.get("route_state").cloned().unwrap_or(Value::Null),
            "privacy_posture": text(&selection, "privacy_posture"),
            "remote_slots_disabled": selection.get("remote_slots_disabled").cloned().unwrap_or(json!(false)),
            "policy_ref": selection.get("policy_ref").cloned().unwrap_or(Value::Null),
            "policy_rollout": facts.get("policy_rollout").cloned().unwrap_or(Value::Null),
            "policy_rollout_skipped": facts.get("policy_rollout_skipped").cloned().unwrap_or(json!([])),
            "rollout_context_source": facts.pointer("/rollout_context/source").cloned().unwrap_or(Value::Null),
            "rollout_context": facts.get("rollout_context").cloned().unwrap_or(Value::Null),
            "deployment_auth_posture": facts.pointer("/rollout_context/deployment_posture").cloned().unwrap_or(Value::Null),
            "policy_effective_summary": if policy.is_null() { Value::Null } else { json!(format!(
                "{} · strategy {} · {} · fallback {}",
                text(&policy, "display_name"),
                text(&selection, "strategy"),
                if text(&selection, "privacy_posture") == "private_local" { "private local" } else { "standard privacy" },
                if policy.pointer("/harness_preferences/allow_fallback").and_then(Value::as_bool).unwrap_or(false) { "allowed" } else { "off" },
            )) },
            "policy_constraints_applied": selection.get("policy_constraints_applied").cloned().unwrap_or(json!([])),
            "policy_constraints_relaxed_or_blocked": selection.get("policy_constraints_relaxed").cloned().unwrap_or(json!([])),
            "budget": {
                "max_parallel_invocations": selection.get("max_parallel_invocations").cloned().unwrap_or(json!(2)),
                "failure_policy": failure_policy,
            },
            "expected_isolation": if kind == "goal_run" {
                "each implementer writes an isolated candidate workspace; the session workspace changes only through an admitted reconciliation"
            } else {
                "one daemon-provisioned session workspace; bwrap-confined adapter execution"
            },
            "expected_receipt_refs": expected_receipts,
            "admission_preview": admission_preview,
            "placement": placement_block,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

/// The venue policy in force, snapshotted onto launch/environment records (provenance).
fn placement_venue_snapshot(st: &DaemonState) -> Value {
    let policy = super::orchestration_routes::load_venue_policy(&st.data_dir);
    json!({
        "venue": policy["venue"],
        "effective_venue": policy.get("effective_venue").cloned().unwrap_or_else(|| policy["venue"].clone()),
        "provider_account_ref": policy.get("provider_account_ref").cloned().unwrap_or(Value::Null),
        "advisory": policy.get("advisory").cloned().unwrap_or(json!(false)),
    })
}

fn load_launch(st: &DaemonState, launch_id: &str) -> Option<Value> {
    read_record_dir(&st.data_dir, LAUNCH_KIND)
        .into_iter()
        .find(|record| text(record, "launch_id") == launch_id)
}

pub(crate) async fn handle_ioi_agent_launch(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let grant = body.get("wallet_approval_grant").cloned().unwrap_or(Value::Null);
    let launch_id_in = text(&body, "launch_id").to_string();

    // ── Phase B: an existing prepared launch + a grant → run it.
    if !launch_id_in.is_empty() && !grant.is_null() {
        let Some(mut launch) = load_launch(&st, &launch_id_in) else {
            return bad(StatusCode::NOT_FOUND, "ioi_agent_launch_not_found", "Unknown launch_id.");
        };
        if text(&launch, "state") == "executed" {
            return bad(
                StatusCode::CONFLICT,
                "ioi_agent_launch_already_executed",
                "This launch has already run; start a new one.",
            );
        }
        let kind = text(&launch, "execution_kind").to_string();
        let session_ref = text(&launch, "session_ref").to_string();
        let goal = text(&launch, "goal").to_string();
        // Projections were created at PHASE A (so the wallet grant binds to the exact
        // composed intent that executes). Direct reads the stored delivered intent here.
        let delivered_intent = {
            let stored = text(&launch, "delivered_intent");
            if stored.is_empty() { goal.clone() } else { stored.to_string() }
        };
        let outcome: Value;
        if kind == "goal_run" {
            let grid = text(&launch, "goal_run_id").to_string();
            let (status, started) = self_call(
                &format!("{}/v1/hypervisor/goal-runs/{grid}/start", st.base_url),
                "POST",
                Some(&json!({ "wallet_approval_grant": grant })),
            )
            .await;
            if status != 200 {
                return (
                    StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
                    Json(started),
                );
            }
            // Assurance gate (policy min_successful_invocations): the target workspace is
            // written ONLY through reconciliation, so an unmet minimum blocks reconcile —
            // candidates stay isolated and the result names the reason. Never silent.
            let min_required = launch
                .get("min_successful_invocations")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let completed_count = started
                .get("invocations")
                .and_then(Value::as_array)
                .map(|list| list.iter().filter(|i| text(i, "status") == "completed").count() as u64)
                .unwrap_or(0);
            if min_required > 0 && completed_count < min_required {
                let outcome = json!({
                    "goal_run": started.get("goal_run").cloned().unwrap_or(Value::Null),
                    "invocations": started.get("invocations").cloned().unwrap_or(json!([])),
                    "partial_result": true,
                    "blockers": [{
                        "reason_code": "policy_assurance_unmet",
                        "message": format!("policy requires {min_required} successful invocations; {completed_count} completed — reconciliation withheld, candidates stay isolated"),
                    }],
                    "reconciliation": Value::Null,
                });
                if let Some(object) = launch.as_object_mut() {
                    object.insert("state".into(), json!("executed"));
                    object.insert("outcome".into(), outcome.clone());
                    object.insert("executed_at".into(), json!(iso_now()));
                }
                let _ = persist_record(&st.data_dir, LAUNCH_KIND, &launch_id_in, &launch);
                return (
                    StatusCode::OK,
                    Json(json!({
                        "ok": true,
                        "agent": "ioi-agent",
                        "headline": "IOI Agent withheld the write — assurance policy unmet",
                        "launch_id": launch_id_in,
                        "execution_kind": "goal_run",
                        "strategy": text(&launch, "strategy"),
                        "session_ref": session_ref,
                        "final_changed_files": [],
                        "partial_result": true,
                        "blockers": outcome.get("blockers").cloned().unwrap_or(json!([])),
                        "links": {
                            "workbench_url": "/__ioi/workbench",
                            "run_timeline_url": format!("/__ioi/run-timeline/goal-run/{grid}"),
                            "work_ledger_url": "/__ioi/work-ledger",
                        },
                        "advanced": {
                            "goal_run_ref": format!("goal://{grid}"),
                            "policy_ref": launch.get("policy_ref").cloned().unwrap_or(Value::Null),
                            "outcome": outcome,
                        },
                        "runtimeTruthSource": "daemon-runtime",
                    })),
                );
            }
            let (_, reconciled) = self_call(
                &format!("{}/v1/hypervisor/goal-runs/{grid}/reconcile", st.base_url),
                "POST",
                Some(&json!({})),
            )
            .await;
            let reconciliation = reconciled.get("reconciliation").cloned().unwrap_or(Value::Null);
            outcome = json!({
                "goal_run": reconciled.get("goal_run").cloned().unwrap_or(started.get("goal_run").cloned().unwrap_or(Value::Null)),
                "invocations": started.get("invocations").cloned().unwrap_or(json!([])),
                "partial_result": started.get("partial_result").cloned().unwrap_or(json!(false)),
                "blockers": started.get("blockers").cloned().unwrap_or(json!([])),
                "reconciliation": reconciliation,
            });
        } else {
            let (status, executed) = self_call(
                &format!(
                    "{}/v1/hypervisor/sessions/{}/execute",
                    st.base_url,
                    urlencoding_encode(&session_ref)
                ),
                "POST",
                Some(&json!({ "intent": delivered_intent, "wallet_approval_grant": grant })),
            )
            .await;
            if status != 200 {
                return (
                    StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
                    Json(executed),
                );
            }
            outcome = json!({
                "decision": executed.get("decision").cloned().unwrap_or(Value::Null),
                "harness": executed.get("harness").cloned().unwrap_or(Value::Null),
                "files_written": executed.get("files_written").cloned().unwrap_or(json!([])),
                "implementation_result": executed.get("implementation_result").cloned().unwrap_or(Value::Null),
                "receipt_refs": executed.get("receipt_refs").cloned().unwrap_or(json!([])),
                "adapter_transcript_run_id": executed.get("adapter_transcript_run_id").cloned().unwrap_or(Value::Null),
            });
        }
        let finished = iso_now();
        if let Some(object) = launch.as_object_mut() {
            object.insert("state".into(), json!("executed"));
            object.insert("outcome".into(), outcome.clone());
            object.insert("executed_at".into(), json!(finished));
        }
        let _ = persist_record(&st.data_dir, LAUNCH_KIND, &launch_id_in, &launch);

        let grid = text(&launch, "goal_run_id");
        let final_files = if kind == "goal_run" {
            outcome.pointer("/reconciliation/final_changed_files").cloned().unwrap_or(json!([]))
        } else {
            outcome.get("files_written").cloned().unwrap_or(json!([]))
        };
        return (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "agent": "ioi-agent",
                "headline": "IOI Agent coordinated this work",
                "launch_id": launch_id_in,
                "execution_kind": kind,
                "strategy": text(&launch, "strategy"),
                "session_ref": session_ref,
                "environment_ref": launch.get("environment_ref").cloned().unwrap_or(Value::Null),
                "final_changed_files": final_files,
                "partial_result": outcome.get("partial_result").cloned().unwrap_or(json!(false)),
                "blockers": outcome.get("blockers").cloned().unwrap_or(json!([])),
                "links": {
                    "workbench_url": "/__ioi/workbench",
                    "run_timeline_url": if kind == "goal_run" {
                        format!("/__ioi/run-timeline/goal-run/{grid}")
                    } else {
                        let transcript = outcome
                            .get("adapter_transcript_run_id")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let env = text(&launch, "environment_id");
                        if !transcript.is_empty() {
                            format!("/__ioi/run-timeline/{transcript}")
                        } else if !env.is_empty() {
                            format!("/__ioi/run-timeline/env/{env}")
                        } else {
                            "/__ioi/work-ledger".to_string()
                        }
                    },
                    "work_ledger_url": "/__ioi/work-ledger",
                },
                "advanced": {
                    "goal_run_ref": if grid.is_empty() { Value::Null } else { json!(format!("goal://{grid}")) },
                    "policy_ref": launch.get("policy_ref").cloned().unwrap_or(Value::Null),
                    "memory_projection_refs": launch.get("memory_projection_refs").cloned().unwrap_or(json!([])),
                    "policy_constraints_applied": launch.get("policy_constraints_applied").cloned().unwrap_or(json!([])),
                    "harness_binding_ref": launch.get("harness_binding_ref").cloned().unwrap_or(Value::Null),
                    "harness_profile_ref": launch.get("harness_profile_ref").cloned().unwrap_or(Value::Null),
                    "model_route_ref": launch.get("model_route_ref").cloned().unwrap_or(Value::Null),
                    "outcome": outcome,
                },
                "runtimeTruthSource": "daemon-runtime",
            })),
        );
    }

    // ── Phase A: plan + provision + relay the authority challenge. Nothing executes.
    if text(&body, "goal").trim().len() < 4 {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "ioi_agent_goal_required",
            "Tell IOI Agent what to do (a few words at least).",
        );
    }
    let (selection, facts) = match plan(&st, &headers, &body).await {
        Ok(planned) => planned,
        Err(rejection) => return rejection,
    };
    let kind = text(&selection, "planned_execution_kind").to_string();
    let goal = text(&facts, "goal").to_string();
    let route_ref = text(&facts, "route_ref").to_string();
    let launch_id = format!("ial_{:x}", nanos());
    let session_ref = format!("session:ioi-agent-{launch_id}");

    // Target session. Direct: created WITH the admitted harness binding (fail-closed there).
    let mut session_body = json!({ "session_ref": session_ref });
    for key in ["project_ref", "context_url", "environment_id", "editor_target_ref"] {
        if let Some(value) = body.get(key) {
            session_body[key] = value.clone();
        }
    }
    if kind == "direct" {
        let selected = text(&selection, "selected_harness_ref");
        // The conductor/native worker is the standard no-binding session; an adapter harness
        // gets the admitted binding at create.
        if selected != "harness-profile:hp_hypervisor_worker" && !selected.is_empty() {
            session_body["harness_profile_ref"] = json!(selected);
            session_body["model_route_ref"] = json!(route_ref);
        }
    }
    let (created_status, created) = self_call(
        &format!("{}/v1/hypervisor/sessions", st.base_url),
        "POST",
        Some(&session_body),
    )
    .await;
    if !(200..300).contains(&(created_status as usize)) {
        return (
            StatusCode::from_u16(created_status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(created),
        );
    }
    let session_record = load_session_record(&st, &session_ref).unwrap_or(Value::Null);
    let environment_ref = created
        .get("environment_ref")
        .cloned()
        .or_else(|| session_record.get("environment_ref").cloned())
        .unwrap_or(Value::Null);

    // For goal_run: create the internal GoalRun (advanced/proof object; not the product mode).
    let mut goal_run_id = String::new();
    if kind == "goal_run" {
        let (gr_status, gr) = self_call(
            &format!("{}/v1/hypervisor/goal-runs", st.base_url),
            "POST",
            Some(&json!({
                "goal": goal,
                "session_ref": session_ref,
                "model_route_ref": route_ref,
                "policy_ref": selection.get("policy_ref").cloned().unwrap_or(Value::Null),
            })),
        )
        .await;
        if gr_status != 201 {
            return (
                StatusCode::from_u16(gr_status).unwrap_or(StatusCode::BAD_GATEWAY),
                Json(gr),
            );
        }
        goal_run_id = gr
            .pointer("/goal_run/goal_run_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
    }

    // Portable intelligence: create the scoped, receipted MemoryProjection(s) NOW — before the
    // authority challenge — so the wallet grant binds to the exact intent that will execute
    // (direct composes goal + rendered summary; goal_run projections attach per invocation).
    let mut projection_refs: Vec<String> = Vec::new();
    let projection_base = json!({
        "goal": goal,
        "launch_ref": format!("ioi-agent-launch://{launch_id}"),
        "session_ref": session_ref,
        "model_route_ref": route_ref,
        "policy_ref": selection.get("policy_ref").cloned().unwrap_or(Value::Null),
        "privacy_posture": text(&selection, "privacy_posture"),
        "allow_sensitive": facts
            .pointer("/policy/privacy/allow_private_projection")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "memory_posture": facts.pointer("/policy/memory_posture").cloned().unwrap_or(Value::Null),
    });
    let mut delivered_intent = goal.clone();
    if kind == "goal_run" {
        if let Some(goal_run) = super::goalrun_routes::load_goal_run(&st, &goal_run_id) {
            for cell in goal_run
                .get("context_cells")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter(|c| text(c, "role") == "implementer")
            {
                let mut body = projection_base.clone();
                body["goal_run_ref"] = json!(format!("goal://{goal_run_id}"));
                body["harness_profile_ref"] = json!(text(cell, "harness_ref"));
                let projection = super::ioi_intelligence_routes::create_projection(&st, &body).await;
                projection_refs.push(text(&projection, "projection_ref").to_string());
            }
        }
    } else {
        let mut body = projection_base.clone();
        body["harness_profile_ref"] = selection
            .get("selected_harness_ref")
            .cloned()
            .unwrap_or(json!("harness-profile:hp_hypervisor_worker"));
        let projection = super::ioi_intelligence_routes::create_projection(&st, &body).await;
        let summary = text(&projection, "projection_summary").to_string();
        if !summary.is_empty() {
            delivered_intent =
                format!("{goal}\n\n[Workspace intelligence — scoped projection]\n{summary}");
        }
        projection_refs.push(text(&projection, "projection_ref").to_string());
    }

    // Relay the underlying lane's authority challenge (grant-less probe; nothing executes).
    let challenge_url = if kind == "goal_run" {
        format!("{}/v1/hypervisor/goal-runs/{goal_run_id}/start", st.base_url)
    } else {
        format!(
            "{}/v1/hypervisor/sessions/{}/execute",
            st.base_url,
            urlencoding_encode(&session_ref)
        )
    };
    let challenge_body = if kind == "goal_run" {
        json!({})
    } else {
        json!({ "intent": delivered_intent })
    };
    let (challenge_status, mut challenge) = self_call(&challenge_url, "POST", Some(&challenge_body)).await;
    if challenge_status != 403 {
        return bad(
            StatusCode::BAD_GATEWAY,
            "ioi_agent_challenge_unexpected",
            "The execution lane did not present the expected authority challenge.",
        );
    }

    let record = json!({
        "schema_version": LAUNCH_SCHEMA_VERSION,
        "launch_id": launch_id,
        "agent": "ioi-agent",
        "goal": goal,
        "strategy": text(&selection, "strategy"),
        "execution_kind": kind,
        "reason_codes": selection.get("reason_codes").cloned().unwrap_or(json!([])),
        "privacy_posture": text(&selection, "privacy_posture"),
        "session_ref": session_ref,
        "environment_ref": environment_ref,
        "environment_id": created.get("environment_id").cloned().unwrap_or(json!("")),
        "goal_run_id": goal_run_id,
        "harness_profile_ref": if kind == "direct" { selection.get("selected_harness_ref").cloned().unwrap_or(Value::Null) } else { Value::Null },
        "harness_binding_ref": created.pointer("/harness_binding/binding_id").cloned().unwrap_or(Value::Null),
        "model_route_ref": route_ref,
        "policy_ref": selection.get("policy_ref").cloned().unwrap_or(Value::Null),
        "policy_rollout": facts.get("policy_rollout").cloned().unwrap_or(Value::Null),
        "rollout_context": facts.get("rollout_context").cloned().unwrap_or(Value::Null),
        "memory_projection_refs": projection_refs,
        "delivered_intent": delivered_intent,
        "privacy_posture": text(&selection, "privacy_posture"),
        "allow_sensitive_projection": facts
            .pointer("/policy/privacy/allow_private_projection")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "policy_constraints_applied": selection.get("policy_constraints_applied").cloned().unwrap_or(json!([])),
        "policy_constraints_relaxed": selection.get("policy_constraints_relaxed").cloned().unwrap_or(json!([])),
        "min_successful_invocations": selection.get("min_successful_invocations").cloned().unwrap_or(json!(0)),
        // Placement venue snapshot at phase A — the launch record carries which venue policy was
        // in force when the composed intent was grant-bound (provenance, not behavior: execution
        // stays on the effective venue's lane; remote session relocation is a later cut).
        "placement_venue": placement_venue_snapshot(&st),
        "state": "prepared",
        "created_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, LAUNCH_KIND, &launch_id, &record);

    // A rollout blocked by DEPLOYMENT POSTURE (not mere non-membership) is a security decision —
    // receipt it so the Work Ledger shows what was refused and why.
    let posture_blocked: Vec<Value> = facts
        .get("policy_rollout_skipped")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter(|x| {
                    matches!(
                        x.get("reason_code").and_then(Value::as_str).unwrap_or(""),
                        "rollout_explicit_override_disallowed" | "rollout_requires_authenticated_context"
                    )
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if !posture_blocked.is_empty() {
        let receipt_ref = format!("receipt://hypervisor/rollout-enforcement/{launch_id}");
        let receipt = json!({
            "id": receipt_ref,
            "kind": "hypervisor.rollout-enforcement",
            "launch_ref": format!("ioi-agent-launch://{launch_id}"),
            "deployment_posture": facts.pointer("/rollout_context/deployment_posture").cloned().unwrap_or(Value::Null),
            "rollout_context_source": facts.pointer("/rollout_context/source").cloned().unwrap_or(Value::Null),
            "blocked": posture_blocked,
            "at": iso_now(),
            "runtimeTruthSource": "daemon-runtime",
        });
        let _ = persist_record(&st.data_dir, "receipts", &receipt_ref, &receipt);
    }

    // The 403 challenge, augmented with the launch identity + refs (the client mints the wallet
    // grant against approval.policy_hash/request_hash and calls launch again with launch_id).
    if let Some(object) = challenge.as_object_mut() {
        object.insert("launch_id".into(), json!(launch_id));
        object.insert("agent".into(), json!("ioi-agent"));
        object.insert("execution_kind".into(), json!(kind));
        object.insert("session_ref".into(), json!(session_ref));
        object.insert(
            "goal_run_ref".into(),
            if goal_run_id.is_empty() { Value::Null } else { json!(format!("goal://{goal_run_id}")) },
        );
    }
    (StatusCode::FORBIDDEN, Json(challenge))
}

pub(crate) async fn handle_ioi_agent_launches_list(
    State(st): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let mut launches = read_record_dir(&st.data_dir, LAUNCH_KIND);
    if let Some(session) = query.get("session") {
        launches.retain(|launch| text(launch, "session_ref") == session);
    }
    launches.sort_by(|a, b| text(b, "created_at").cmp(text(a, "created_at")));
    (StatusCode::OK, Json(json!({ "ok": true, "launches": launches })))
}

pub(crate) async fn handle_ioi_agent_launch_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load_launch(&st, &id) {
        Some(launch) => (StatusCode::OK, Json(json!({ "ok": true, "launch": launch }))),
        None => bad(StatusCode::NOT_FOUND, "ioi_agent_launch_not_found", "Unknown launch."),
    }
}

fn urlencoding_encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}
