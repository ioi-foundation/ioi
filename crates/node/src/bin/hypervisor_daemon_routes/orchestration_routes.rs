//! Cut E — orchestration / scale (daemon-native).
//!
//! K. AutomationWorkflow engine: a workflow is steps (agent / command / proposal) under a trigger;
//!    starting it CREATES a fresh environment and runs the steps over it, recording structured
//!    outputs + execution status. The steps COMPOSE the real routes (env create/start, the AgentOps
//!    conversation, the scoped exec) over loopback — honest composition, not a re-implementation —
//!    so a prompt→command→proposal loop runs in a fresh env and reports real outputs (the proposal
//!    is a real git diff of what the run changed, recorded `review_state: proposed`).
//!
//! L. Runner placement + metrics + warm pools: placement scores the real provider catalog against
//!    a request (class / trust / residency / prebuild+warm availability) and records the decision +
//!    REJECTED candidates with honest reasons (no silent drop); metrics aggregate cold-start /
//!    prebuild-hit / warm-claim / cache from real env truth; a warm pool pre-starts envs claimable
//!    by project+class.
use std::path::Path;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use super::{
    iso_now, persist_record, read_record_dir, remove_record, sha256_hex_str, AppError, DaemonState,
};

fn safe(seg: &str) -> String {
    seg.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
}
fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn load(data_dir: &str, kind: &str, id: &str) -> Option<Value> {
    serde_json::from_slice(
        &std::fs::read(
            Path::new(data_dir)
                .join(kind)
                .join(format!("{}.json", safe(id))),
        )
        .ok()?,
    )
    .ok()
}

/// Self-call the daemon's own loopback API — composes the REAL routes (no duplicated lifecycle).
/// Posture- and principal-bearing headers; same set as the MCP gateway.
///
/// Forwarding is OPPORTUNISTIC: the automation webhook path is intentionally
/// session-less (auth_gate exempts `*/webhook`; it authenticates by its own
/// per-automation trigger token), so on that path there is nothing to forward and
/// nothing changes. Directly mounted, auth-gated handlers DO have a caller, and
/// their loopback effects must be evaluated under that caller's posture.
const FORWARDED_AUTH_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "x-forwarded-host",
    "x-forwarded-for",
    "x-ioi-forwarded",
    // The per-boot internal dispatch token (scheduler tick / accepted-webhook fire). Loopback
    // self-calls only; a caller-supplied value forwards inert — it can never match the per-boot
    // secret, which is never emitted in any response.
    "x-ioi-internal-dispatch",
];

async fn call(
    base: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
    inbound: &axum::http::HeaderMap,
) -> Result<Value, String> {
    let client = reqwest::Client::new();
    let url = format!("{base}{path}");
    let mut req = match method {
        "POST" => client.post(&url),
        "GET" => client.get(&url),
        other => return Err(format!("bad method {other}")),
    };
    for name in FORWARDED_AUTH_HEADERS {
        if let Some(value) = inbound.get(*name).and_then(|v| v.to_str().ok()) {
            req = req.header(*name, value);
        }
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    let r = req.send().await.map_err(|e| e.to_string())?;
    let t = r.text().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&t).map_err(|e| format!("{e}: {t}"))
}

fn git(ws: &str, args: &[&str]) -> String {
    std::process::Command::new("git")
        .arg("-C")
        .arg(ws)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}
fn env_workspace(data_dir: &str, env_id: &str) -> Option<String> {
    let v: Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(data_dir)
                .join("environments")
                .join(format!("{}.json", safe(env_id))),
        )
        .ok()?,
    )
    .ok()?;
    v["status"]["workspace_root"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

// ============================ K. AUTOMATION WORKFLOW ENGINE ======================================

/// Keep the project the durable container of its automations: add/remove an automation_id on the
/// referenced project's `automation_refs`. Best-effort + idempotent (no-op if the project isn't a
/// persisted record, e.g. a legacy free-form project_id). The project create planner seeds
/// `automation_refs: []`, so the agent-automations plane writes back here.
fn link_project_automation(data_dir: &str, project_id: &str, automation_id: &str, add: bool) {
    if project_id.is_empty() {
        return;
    }
    let Some(mut project) = load(data_dir, "projects", project_id) else {
        return;
    };
    let mut refs: Vec<Value> = project
        .get("automation_refs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    refs.retain(|r| r.as_str() != Some(automation_id)); // dedupe / removal
    if add {
        refs.push(json!(automation_id));
    }
    project["automation_refs"] = json!(refs);
    project["updated_at"] = json!(iso_now());
    // CLASSIFIED — derived projection: project.automation_refs is a denormalized index over the
    // automations' own project_id; list truth filters automations directly, so a dropped write self-heals.
    let _ = persist_record(data_dir, "projects", project_id, &project);
}

/// Typed identity/scope refusal for the automations family (the ODK ontology precedent, #236):
/// the status is derived from the refusal kind, the body carries the machine-readable code.
fn automation_scope_refusal(
    error: super::substrate_store::RequestScopeRefusal,
) -> (StatusCode, Json<Value>) {
    use super::substrate_store::RequestScopeRefusal;
    let status = match error {
        RequestScopeRefusal::AuthenticationRequired
        | RequestScopeRefusal::PrincipalIdentityInvalid => StatusCode::UNAUTHORIZED,
        RequestScopeRefusal::TenantAuthorityRequired
        | RequestScopeRefusal::ResourceScopeRequired
        | RequestScopeRefusal::ResourceOwnerMismatch => StatusCode::FORBIDDEN,
        RequestScopeRefusal::SubstrateUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    (
        status,
        Json(json!({ "ok": false, "code": error.code(), "message": error.message() })),
    )
}

/// True when the request carries THIS boot's internal dispatch token — the daemon's own
/// scheduler tick and the accepted-webhook fire, which cross the manual-run route over loopback.
/// The token is minted per boot, lives only in process memory, and is never emitted in any
/// response, so a valid presentation can only originate from this daemon process. Internal
/// dispatch is NOT a session: the run executes as the spec's stored `executor_identity`
/// (the delegated durable authority), never as an ambient operator.
/// `pub(crate)` since the #246 session-write gate: the Session write lane admits the daemon's
/// own orchestration dispatches (ioi-agent launch, goal-run candidate sessions) through this
/// same per-boot token instead of a session — one token, one predicate, no second lane.
pub(crate) fn internal_dispatch_authorized(st: &DaemonState, headers: &HeaderMap) -> bool {
    headers
        .get("x-ioi-internal-dispatch")
        .and_then(|v| v.to_str().ok())
        .map(|presented| {
            // Constant-time-ish compare: same-length XOR fold (the token is per-boot random).
            let expected = st.internal_dispatch_token.as_bytes();
            let presented = presented.as_bytes();
            presented.len() == expected.len()
                && presented
                    .iter()
                    .zip(expected)
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0
        })
        .unwrap_or(false)
}

/// POST /v1/hypervisor/automations — create a project-scoped AutomationWorkflow spec.
/// `project_ref` (alias `project_id`) is REQUIRED: an automation is durable work that must hang off
/// a project. Returns 400 if absent. On success the project's `automation_refs` is updated.
pub(crate) async fn handle_automation_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // #237 finding closed — identity FIRST (rule E): an anonymous caller is owed the typed 401
    // before any field validation runs (project_ref included), so no field-shape probe exists
    // for unauthenticated callers. An automation spec is authored durable work, not an
    // anonymous append.
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return automation_scope_refusal(error),
    };
    let project_id = body
        .get("project_ref")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("project_id").and_then(|v| v.as_str()))
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(project_id) = project_id else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": {
                "code": "automation_project_ref_required",
                "message": "An automation must declare a project_ref (the project is its durable container)."
            } })),
        );
    };
    let id = format!("auto_{:x}", nanos());
    let now = iso_now();
    let trigger = body
        .get("trigger")
        .cloned()
        .unwrap_or_else(|| json!({ "kind": "manual" }));
    let trigger_kind = body
        .get("trigger_kind")
        .and_then(|v| v.as_str())
        .or_else(|| trigger.get("kind").and_then(|v| v.as_str()))
        .unwrap_or("manual")
        .to_string();
    // Validate the schedule (cron expression / timezone) up front with a useful error.
    if let Err(e) = super::validate_schedule_spec(body.get("schedule_spec").unwrap_or(&Value::Null))
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "ok": false, "error": { "code": "schedule_spec_invalid", "message": e } }),
            ),
        );
    }
    let mut record = json!({
        "schema_version": "ioi.hypervisor.automation-workflow.v1",
        "automation_id": id,
        // Project linkage (durable container) — project_id kept for back-compat with the executor.
        "project_id": project_id,
        "project_ref": project_id,
        "name": body.get("name").and_then(|v| v.as_str()).unwrap_or("automation"),
        "description": body.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "trigger": trigger,
        "trigger_kind": trigger_kind,
        "enabled": body.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
        "steps": body.get("steps").cloned().unwrap_or_else(|| json!([])),
        "workflow_graph_ref": body.get("workflow_graph_ref").cloned().unwrap_or(Value::Null),
        "limits": body.get("limits").cloned().unwrap_or_else(|| json!({ "max_total": 100, "per_exec_seconds": 600, "budget": Value::Null })),
        // INV-37: the execution identity defaults to the RESOLVED creating principal, never an
        // ambient "operator" literal. A caller-supplied executor_identity (delegated execution
        // config) still wins — it is spec surface, not attribution.
        "executor_identity": body.get("executor_identity").cloned().unwrap_or_else(|| json!({ "kind": "user", "ref": identity.principal_ref })),
        // Who performed this mutation (refreshed on PATCH) — resolved server-side, never client-set.
        "acting_principal_ref": identity.principal_ref,
        "environment_class_id": body.get("environment_class_id").and_then(|v| v.as_str()).unwrap_or("local-workspace-v0"),
        "recipe_ref": body.get("recipe_ref").cloned().unwrap_or(Value::Null),
        // Agent/runtime config (the HypervisorAutomationSpec surface).
        "agent_ref": body.get("agent_ref").cloned().unwrap_or(Value::Null),
        "harness_profile_ref": body.get("harness_profile_ref").cloned().unwrap_or(Value::Null),
        "model": body.get("model").cloned().unwrap_or(Value::Null),
        "reasoning": body.get("reasoning").cloned().unwrap_or(Value::Null),
        "connector_refs": body.get("connector_refs").cloned().unwrap_or_else(|| json!([])),
        "memory_profile_ref": body.get("memory_profile_ref").cloned().unwrap_or(Value::Null),
        "default_runtime_policy_ref": body.get("default_runtime_policy_ref").cloned().unwrap_or(Value::Null),
        "authority_policy_ref": body.get("authority_policy_ref").cloned().unwrap_or(Value::Null),
        // Scheduling (background execution): schedule_spec drives the daemon scheduler when enabled.
        // next_run_at is computed by the scheduler (null → it initializes to now+interval, so create
        // never fires immediately). last_run_at is stamped after each scheduled fire.
        "schedule_spec": body.get("schedule_spec").cloned().unwrap_or(Value::Null),
        "next_run_at": Value::Null,
        "last_run_at": Value::Null,
        "catch_up_policy": body.get("catch_up_policy").and_then(|v| v.as_str()).unwrap_or("skip"),
        "misfire_policy": body.get("misfire_policy").and_then(|v| v.as_str()).unwrap_or("skip"),
        "max_concurrency": body.get("max_concurrency").and_then(|v| v.as_i64()).filter(|n| *n > 0).unwrap_or(1),
        "failure_policy": body.get("failure_policy").and_then(|v| v.as_str()).unwrap_or("continue"),
        "webhook_token_hash": Value::Null,
        "webhook_url": Value::Null,
        "created_at": now,
        "updated_at": now
    });
    // Webhook trigger: mint an opaque trigger token (hashed at rest; plaintext returned ONCE).
    let mut fresh_token: Option<String> = None;
    if trigger_kind == "webhook" {
        let tok = new_webhook_token();
        record["webhook_token_hash"] = json!(sha256_hex_str(&tok));
        record["webhook_url"] = json!(format!("/v1/hypervisor/automations/{id}/webhook"));
        fresh_token = Some(tok);
    }
    // W1.2 / MEF-GAP-008 — check the spec committed BEFORE returning the once-shown webhook token:
    // a token issued for an automation that did not persist can never be used.
    if persist_record(&st.data_dir, "automations", &id, &record).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "automation_persistence_failed",
            "message": "the automation did not commit — no spec was created and no webhook token was issued" }),
            ),
        );
    }
    link_project_automation(&st.data_dir, project_id, &id, true);
    let mut resp = json!({ "ok": true, "automation": record });
    if let Some(tok) = fresh_token {
        resp["webhook_token"] = json!(tok); // shown once — never persisted in plaintext
    }
    (StatusCode::CREATED, Json(resp))
}

/// GET /v1/hypervisor/automations[?project_ref=…] — list specs, optionally scoped to one project.
pub(crate) async fn handle_automation_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, "automations");
    if let Some(pid) = q
        .get("project_ref")
        .or_else(|| q.get("project_id"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        items.retain(|a| {
            a.get("project_id").and_then(|v| v.as_str()) == Some(pid)
                || a.get("project_ref").and_then(|v| v.as_str()) == Some(pid)
        });
    }
    Json(json!({ "ok": true, "automations": items }))
}
pub(crate) async fn handle_automation_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load(&st.data_dir, "automations", &id) {
        Some(a) => Json(json!({ "ok": true, "automation": a })),
        None => Json(json!({ "ok": false, "reason": "automation not found" })),
    }
}
pub(crate) async fn handle_automation_execution_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load(&st.data_dir, "automation-executions", &id) {
        Some(e) => Json(json!({ "ok": true, "execution": e })),
        None => Json(json!({ "ok": false, "reason": "execution not found" })),
    }
}

/// PATCH /v1/hypervisor/automations/:id — update mutable spec fields (config-immutable:
/// automation_id / project_id / environment_class_id are NOT reassigned here).
pub(crate) async fn handle_automation_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // #237 finding closed — identity FIRST (rule E): the typed 401 is owed BEFORE the record
    // load, so an unauthenticated caller can never use the not-found reply as an existence
    // oracle (or probe field shapes through the schedule validator).
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return automation_scope_refusal(error),
    };
    let Some(mut a) = load(&st.data_dir, "automations", &id) else {
        return (
            StatusCode::OK,
            Json(json!({ "ok": false, "reason": "automation not found" })),
        );
    };
    if let Some(spec) = body.get("schedule_spec") {
        if let Err(e) = super::validate_schedule_spec(spec) {
            return (
                StatusCode::OK,
                Json(
                    json!({ "ok": false, "error": { "code": "schedule_spec_invalid", "message": e } }),
                ),
            );
        }
    }
    for key in [
        "name",
        "description",
        "trigger",
        "trigger_kind",
        "enabled",
        "steps",
        "workflow_graph_ref",
        "limits",
        "executor_identity",
        "recipe_ref",
        "agent_ref",
        "harness_profile_ref",
        "model",
        "reasoning",
        "connector_refs",
        "memory_profile_ref",
        "default_runtime_policy_ref",
        "authority_policy_ref",
        "schedule_spec",
        "catch_up_policy",
        "misfire_policy",
        "max_concurrency",
        "failure_policy",
    ] {
        if let Some(v) = body.get(key) {
            a[key] = v.clone();
        }
    }
    // Rescheduling or (re)enabling resets the next fire so the scheduler recomputes it cleanly
    // (pause = enabled:false → scheduler skips; resume = enabled:true → fresh next_run_at).
    if body.get("schedule_spec").is_some() || body.get("enabled").is_some() {
        a["next_run_at"] = Value::Null;
    }
    a["updated_at"] = json!(iso_now());
    // INV-37: the spec records who performed the last mutation (resolved, never client-set —
    // `acting_principal_ref` is deliberately absent from the patchable key list above).
    a["acting_principal_ref"] = json!(identity.principal_ref);
    // W1.2 / MEF-GAP-008 — CRITICAL: a discarded `enabled:false` patch returns 200 "paused" while the
    // scheduler keeps firing the spec. Fail closed so pause is honest.
    if persist_record(&st.data_dir, "automations", &id, &a).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "automation_persistence_failed",
            "message": "the automation edit did not commit — no change was applied (a reported pause would be false)" }),
            ),
        );
    }
    (StatusCode::OK, Json(json!({ "ok": true, "automation": a })))
}

/// DELETE /v1/hypervisor/automations/:id — remove the spec + unlink it from the project's
/// automation_refs. Returns {ok, removed} so a no-op delete is honest.
pub(crate) async fn handle_automation_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    // #237 finding closed — identity FIRST (rule E): the typed 401 is owed BEFORE the record
    // load, so an anonymous caller gets no existence oracle. All authenticated outcomes keep
    // their 200 body shapes exactly (the ODK delete precedent, #236).
    if let Err(error) = super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        return automation_scope_refusal(error);
    }
    let project_id = load(&st.data_dir, "automations", &id).and_then(|a| {
        a.get("project_id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    });
    let removed = remove_record(&st.data_dir, "automations", &id);
    if let Some(pid) = project_id {
        link_project_automation(&st.data_dir, &pid, &id, false);
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": removed, "removed": removed, "automation_id": id })),
    )
}

/// GET /v1/hypervisor/automations/:id/runs — the spec's run history (automation-execution records),
/// newest first. Pairs with POST /:id/runs (manual run).
pub(crate) async fn handle_automation_runs_list(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let mut runs: Vec<Value> = read_record_dir(&st.data_dir, "automation-executions")
        .into_iter()
        .filter(|e| e.get("automation_id").and_then(|v| v.as_str()) == Some(id.as_str()))
        .collect();
    runs.sort_by(|a, b| {
        b.get("started_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("started_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Json(json!({ "ok": true, "runs": runs }))
}

/// GET /v1/hypervisor/cron-preview?cron=…&tz=…&n=3 — preview the next N cron fires (UTC). Pure
/// helper (no data access) used by the create form; exempt from the auth gate.
pub(crate) async fn handle_cron_preview(Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    let cron = q.get("cron").map(String::as_str).unwrap_or("");
    let tz = q.get("tz").map(String::as_str).unwrap_or("UTC");
    let n: usize = q.get("n").and_then(|s| s.parse().ok()).unwrap_or(3).min(10);
    let mut runs: Vec<String> = Vec::new();
    let mut from = iso_now();
    for _ in 0..n {
        match super::cron_next_run(cron, tz, &from) {
            Ok(next) => {
                runs.push(next.clone());
                from = next;
            }
            Err(e) => return Json(json!({ "ok": false, "error": e })),
        }
    }
    Json(json!({ "ok": true, "runs": runs }))
}

/// GET /v1/hypervisor/scheduler/status — scheduler LIVENESS only (W0.6). Projects the
/// loop-derived tick heartbeat the background `automation_scheduler` persists each tick, plus the
/// loop's fixed catch-up/misfire posture. Liveness is heartbeat-derived truth: `live` when the
/// last tick is within 2x the tick interval (+ boot slack), `stale` when a heartbeat exists but
/// has aged out, and an honest `no_heartbeat_recorded` when none was ever persisted. This route
/// does NOT duplicate the records-derived schedule posture (per-automation enabled/trigger/
/// next_run_at/last_run_at) that `/v1/hypervisor/operations` already projects — it points there.
pub(crate) async fn handle_scheduler_status(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let heartbeat = read_record_dir(&st.data_dir, super::SCHEDULER_HEARTBEAT_FAMILY)
        .into_iter()
        .find(|record| {
            record.get("loop").and_then(Value::as_str) == Some("automation_scheduler")
                || record.get("id").and_then(Value::as_str) == Some(super::SCHEDULER_HEARTBEAT_ID)
        });
    let tick_interval_secs = super::SCHEDULER_TICK_SECS;
    let posture = json!({
        "tick_interval_secs": tick_interval_secs,
        "fires_on_create": false,
        "catch_up": "none — a due schedule fires once per due check; the next occurrence is computed from now, missed occurrences are not backfilled",
        "misfire_at_concurrency_cap": "skip_occurrence — next_run_at still advances so the slot is not retried",
        "dispatch_path": "fires through the manual-run path (POST /v1/hypervisor/automations/:id/runs), same run history/state_root/transcript as a manual run"
    });
    let Some(heartbeat) = heartbeat else {
        return Json(json!({
            "ok": true,
            "schema_version": "ioi.hypervisor.scheduler-status.v1",
            "liveness": "no_heartbeat_recorded",
            "detail": "no scheduler heartbeat has ever been persisted in this data dir — the loop has not completed a tick yet (first tick lands ~5s + one interval after daemon start), or this data dir predates the heartbeat",
            "heartbeat": Value::Null,
            "posture": posture,
            "schedule_posture_route": "/v1/hypervisor/operations",
            "runtimeTruthSource": "daemon-runtime"
        }));
    };
    let now = iso_now();
    let last_tick_at = heartbeat
        .get("last_tick_at")
        .and_then(Value::as_str)
        .unwrap_or("");
    let age_seconds = match (super::epoch_of(&now), super::epoch_of(last_tick_at)) {
        (Some(now_ts), Some(tick_ts)) => Some(now_ts - tick_ts),
        _ => None,
    };
    let liveness = match age_seconds {
        Some(age) if age <= (2 * tick_interval_secs as i64) + 5 => "live",
        Some(_) => "stale",
        None => "unknown_heartbeat_timestamp",
    };
    Json(json!({
        "ok": true,
        "schema_version": "ioi.hypervisor.scheduler-status.v1",
        "liveness": liveness,
        "age_seconds": age_seconds,
        "heartbeat": heartbeat,
        "posture": posture,
        "schedule_posture_route": "/v1/hypervisor/operations",
        "note": "liveness is heartbeat-derived: it proves the last completed tick, never that the loop will tick again",
        "runtimeTruthSource": "daemon-runtime"
    }))
}

/// GET /v1/hypervisor/operations — the execution-health projection over the automation substrate:
/// what is scheduled, what fired, what failed, what needs attention. Real records only (honest-empty).
pub(crate) async fn handle_operations(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let g = |v: &Value, k: &str| v.get(k).cloned().unwrap_or(Value::Null);
    let automations = read_record_dir(&st.data_dir, "automations");
    let mut amap: HashMap<String, Value> = HashMap::new();
    for a in &automations {
        if let Some(id) = a.get("automation_id").and_then(|v| v.as_str()) {
            amap.insert(id.to_string(), a.clone());
        }
    }
    let mut by_run: HashMap<String, Value> = HashMap::new();
    for t in read_record_dir(&st.data_dir, "agent-run-transcripts") {
        if let Some(rid) = t.get("run_id").and_then(|v| v.as_str()) {
            by_run.insert(rid.to_string(), t);
        }
    }
    // Scheduler: automations carrying a schedule_spec (enabled/paused, trigger, next/last, policy).
    let mut scheduled: Vec<Value> = Vec::new();
    for a in &automations {
        if !a
            .get("schedule_spec")
            .map(|s| s.is_object())
            .unwrap_or(false)
        {
            continue;
        }
        scheduled.push(json!({
            "automation_id": g(a, "automation_id"), "name": g(a, "name"), "project_id": g(a, "project_id"),
            "enabled": a.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
            "trigger_kind": g(a, "trigger_kind"), "schedule_spec": g(a, "schedule_spec"),
            "next_run_at": g(a, "next_run_at"), "last_run_at": g(a, "last_run_at"),
            "max_concurrency": g(a, "max_concurrency"), "failure_policy": g(a, "failure_policy"),
        }));
    }
    // Run health.
    let execs = read_record_dir(&st.data_dir, "automation-executions");
    let (mut done, mut failed, mut running) = (0i64, 0i64, 0i64);
    let mut runs: Vec<Value> = Vec::new();
    for e in &execs {
        match e.get("status").and_then(|v| v.as_str()) {
            Some("done") => done += 1,
            Some("failed") => failed += 1,
            Some("running") => running += 1,
            _ => {}
        }
        let exec_id = e.get("execution_id").and_then(|v| v.as_str()).unwrap_or("");
        let aid = e
            .get("automation_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let t = by_run.get(exec_id);
        let name = t
            .and_then(|t| t.get("automation_name"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                amap.get(aid)
                    .and_then(|a| a.get("name"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("automation");
        let project = t
            .and_then(|t| t.get("project_id"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                amap.get(aid)
                    .and_then(|a| a.get("project_id"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("");
        runs.push(json!({
            "execution_id": exec_id, "automation_id": aid, "name": name, "project_id": project,
            "status": g(e, "status"), "started_at": g(e, "started_at"), "finished_at": g(e, "finished_at"),
            "timeline_ref": format!("/__ioi/run-timeline/{exec_id}"),
        }));
    }
    runs.sort_by(|a, b| {
        b.get("started_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("started_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
    let failures: Vec<Value> = runs
        .iter()
        .filter(|r| r.get("status").and_then(|v| v.as_str()) == Some("failed"))
        .take(10)
        .cloned()
        .collect();
    let recent: Vec<Value> = runs.iter().take(10).cloned().collect();
    // Webhook health.
    let mut events = read_record_dir(&st.data_dir, "webhook-trigger-events");
    let (mut accepted, mut rejected) = (0i64, 0i64);
    let mut reasons: HashMap<String, i64> = HashMap::new();
    for ev in &events {
        if ev.get("accepted").and_then(|v| v.as_bool()) == Some(true) {
            accepted += 1;
        } else {
            rejected += 1;
            *reasons
                .entry(
                    ev.get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("rejected")
                        .to_string(),
                )
                .or_insert(0) += 1;
        }
    }
    events.sort_by(|a, b| {
        b.get("received_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("received_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
    let recent_ev: Vec<Value> = events.into_iter().take(10).map(|ev| json!({
        "receipt_id": g(&ev, "receipt_id"), "automation_id": g(&ev, "automation_id"),
        "accepted": g(&ev, "accepted"), "reason": g(&ev, "reason"),
        "payload_hash": g(&ev, "payload_hash"), "received_at": g(&ev, "received_at"), "run_ref": g(&ev, "run_ref"),
    })).collect();
    let reasons_v = serde_json::to_value(&reasons).unwrap_or_else(|_| json!({}));
    Json(json!({
        "ok": true,
        "scheduler": { "count": scheduled.len(), "automations": scheduled },
        "runs": { "total": execs.len(), "done": done, "failed": failed, "running": running, "recent": recent, "failures": failures },
        "webhooks": { "accepted": accepted, "rejected": rejected, "rejections_by_reason": reasons_v, "recent": recent_ev },
    }))
}

/// GET /v1/hypervisor/work-ledger[?project=…] — a unified, newest-first PROOF STREAM across all
/// projects/automations: automation runs (enriched with the tamper-evident state_root captured in
/// their transcript) + webhook trigger receipts. Real records only — no fabricated rows.
pub(crate) async fn handle_work_ledger(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    // This legacy aggregate joins several durable families that do not yet share principal
    // ownership coordinates. The generic auth gate proves who called, not which rows they own;
    // therefore managed/exposed reads must fail before any family is enumerated.
    match super::lifecycle_routes::deployment_auth_posture(&st.data_dir, &headers) {
        "local_development" => {}
        "exposed_untrusted" => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "ok": false,
                    "error": {
                        "code": "work_ledger_exposed_untrusted_refused",
                        "message": "Work Ledger truth is unavailable on an exposed deployment without enforceable principal ownership."
                    }
                })),
            );
        }
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "ok": false,
                    "error": {
                        "code": "work_ledger_principal_scope_unavailable",
                        "message": "The retained Work Ledger families do not share principal ownership coordinates and cannot be read on a managed deployment."
                    }
                })),
            );
        }
    }
    let g = |v: &Value, k: &str| v.get(k).cloned().unwrap_or(Value::Null);
    // run_id -> transcript (state_root + durable name/project captured at run time).
    let mut by_run: HashMap<String, Value> = HashMap::new();
    for t in read_record_dir(&st.data_dir, "agent-run-transcripts") {
        if let Some(rid) = t.get("run_id").and_then(|v| v.as_str()) {
            by_run.insert(rid.to_string(), t);
        }
    }
    let mut amap: HashMap<String, Value> = HashMap::new();
    for a in read_record_dir(&st.data_dir, "automations") {
        if let Some(aid) = a.get("automation_id").and_then(|v| v.as_str()) {
            amap.insert(aid.to_string(), a);
        }
    }
    let mut entries: Vec<Value> = Vec::new();
    // Runs (the canonical execution records).
    for e in read_record_dir(&st.data_dir, "automation-executions") {
        let exec_id = e
            .get("execution_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let aid = e
            .get("automation_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let t = by_run.get(&exec_id);
        let a = amap.get(aid);
        let name = t
            .and_then(|t| t.get("automation_name"))
            .and_then(|v| v.as_str())
            .or_else(|| a.and_then(|a| a.get("name")).and_then(|v| v.as_str()))
            .unwrap_or("automation");
        let project = t
            .and_then(|t| t.get("project_id"))
            .and_then(|v| v.as_str())
            .or_else(|| a.and_then(|a| a.get("project_id")).and_then(|v| v.as_str()))
            .unwrap_or("");
        let trigger = a
            .and_then(|a| a.get("trigger_kind"))
            .and_then(|v| v.as_str())
            .unwrap_or("manual");
        let state_root = t
            .and_then(|t| t.get("state_root"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        entries.push(json!({
            "id": exec_id, "kind": "run", "timestamp": g(&e, "started_at"),
            "automation_id": aid, "automation_name": name, "project_id": project,
            "status": g(&e, "status"), "trigger_kind": trigger,
            "state_root": state_root, "run_ref": exec_id,
            "timeline_ref": format!("/__ioi/run-timeline/{exec_id}"),
            "authority": g(&e, "executor_identity"), "counts": g(&e, "counts"),
            "environment_id": g(&e, "environment_id"), "finished_at": g(&e, "finished_at"),
            "step_results": g(&e, "step_results"),
        }));
    }
    // Provider crossings — every BYO provider lifecycle op minted a provider receipt (success
    // AND failure); surface them so provider work is reachable from the one proof stream.
    // Cross-reference spend exposures so each crossing backlinks its reconciliation row.
    let mut receipt_to_exposure: HashMap<String, Value> = HashMap::new();
    for e in read_record_dir(&st.data_dir, "provider-spend-exposures") {
        if let Some(refs) = e.get("receipt_refs").and_then(Value::as_array) {
            for r in refs {
                if let Some(rr) = r.as_str() {
                    receipt_to_exposure.insert(rr.to_string(), e["exposure_ref"].clone());
                }
            }
        }
    }
    for r in read_record_dir(&st.data_dir, "provider-receipts") {
        entries.push(json!({
            "id": g(&r, "receipt_id"), "kind": "provider_crossing", "timestamp": g(&r, "at"),
            "status": g(&r, "outcome"), "op": g(&r, "op"), "provider": g(&r, "provider"),
            "account_ref": g(&r, "account_ref"), "environment_ref": g(&r, "environment_ref"),
            "receipt_ref": g(&r, "receipt_ref"), "grant_ref": g(&r, "grant_ref"),
            "cost_estimate": g(&r, "cost_estimate"),
            "candidate_ref": g(&r, "candidate_ref"), "quote_ref": g(&r, "quote_ref"),
            "execution_mode": g(&r, "execution_mode"), "teardown_state": g(&r, "teardown_state"),
            "state_root_evidence": g(&r, "state_root"),
            "exposure_ref": r.get("receipt_ref").and_then(Value::as_str).and_then(|rr| receipt_to_exposure.get(rr).cloned()).unwrap_or(Value::Null),
            "provider_health_ref": "/__ioi/operations#ops-provider-health",
            "spend_reconciliation_ref": "/__ioi/operations#ops-spend-recon",
        }));
    }
    // Storage custody crossings — every archive export/verify/restore/repair minted a storage
    // receipt (success AND failure); incidents and repairs are reachable from the proof stream.
    for r in read_record_dir(&st.data_dir, "storage-receipts") {
        entries.push(json!({
            "id": g(&r, "receipt_id"), "kind": "storage_custody", "timestamp": g(&r, "at"),
            "status": g(&r, "outcome"), "op": g(&r, "op"), "backend": g(&r, "backend"),
            "backend_ref": g(&r, "backend_ref"), "archive_ref": g(&r, "archive_ref"),
            "material_ref": g(&r, "material_ref"), "environment_ref": g(&r, "environment_ref"),
            "receipt_ref": g(&r, "receipt_ref"), "grant_ref": g(&r, "grant_ref"),
            "state_root": g(&r, "state_root"), "commitment": g(&r, "commitment"),
            "incident_ref": g(&r, "incident_ref"), "repair_ref": g(&r, "repair_ref"),
            "custody_rule": "storage availability is not restore truth — daemon-admitted state roots are",
            "storage_health_ref": "/__ioi/operations#ops-storage-backends",
        }));
    }
    // Placement decisions — challengeable optimized-placement evidence
    // (selected + alternatives + rejected with reason codes; never a fee).
    for r in read_record_dir(&st.data_dir, "placement-decisions") {
        entries.push(json!({
            "id": g(&r, "decision_id"), "kind": "placement_decision", "timestamp": g(&r, "decided_at"),
            "status": g(&r, "decision_mode"), "decision_ref": g(&r, "decision_ref"),
            "intent_ref": g(&r, "intent_ref"), "selected_candidate_ref": g(&r, "selected_candidate_ref"),
            "alternatives_considered": r.get("alternatives_considered").and_then(|a| a.as_array()).map(|a| a.len()).unwrap_or(0),
            "rejected_candidates": r.get("rejected_candidates").and_then(|a| a.as_array()).map(|a| a.len()).unwrap_or(0),
            "receipt_ref": g(&r, "receipt_ref"), "receipt_root": g(&r, "receipt_root"),
            "failover_run_ref": g(&r, "failover_run_ref"),
            "fee_note": "fee_object_minted: false — decision is evidence, not a charge",
            "placement_ref": "/__ioi/environments#env-placement-decisions",
        }));
    }
    // Failover runs — the cross-provider proof chain (decision + material +
    // replacement create + state_root-validated restore + old teardown).
    for r in read_record_dir(&st.data_dir, "failover-runs") {
        entries.push(json!({
            "id": g(&r, "run_id"), "kind": "failover", "timestamp": g(&r, "started_at"),
            "status": g(&r, "status"), "run_ref": g(&r, "run_ref"),
            "environment_ref": g(&r, "environment_ref"),
            "replacement_environment_ref": g(&r, "replacement_environment_ref"),
            "failure_condition": g(&r, "failure_condition"),
            "decision_ref": g(&r, "decision_ref"),
            "restore_material_ref": g(&r, "restore_material_ref"),
            "state_root": g(&r, "state_root"),
            "old_provider": r.get("old_provider").cloned().unwrap_or(serde_json::Value::Null),
            "replacement": r.get("replacement").cloned().unwrap_or(serde_json::Value::Null),
            "receipt_refs": r.get("receipt_refs").cloned().unwrap_or(serde_json::json!([])),
            "triggered_by": r.get("triggered_by").cloned().unwrap_or(serde_json::Value::Null),
            "failover_ref": "/__ioi/operations#ops-failover",
        }));
    }
    // Webhook trigger receipts (accepted/rejected proofs).
    for ev in read_record_dir(&st.data_dir, "webhook-trigger-events") {
        let aid = ev
            .get("automation_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let a = amap.get(aid);
        let name = a
            .and_then(|a| a.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("automation");
        let project = a
            .and_then(|a| a.get("project_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let accepted = ev.get("accepted").and_then(|v| v.as_bool()) == Some(true);
        let run_ref = ev
            .get("run_ref")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        let run_ref_v = match run_ref {
            Some(s) => json!(s),
            None => Value::Null,
        };
        let timeline_v = match run_ref {
            Some(r) => json!(format!("/__ioi/run-timeline/{r}")),
            None => Value::Null,
        };
        entries.push(json!({
            "id": g(&ev, "receipt_id"), "kind": "trigger", "timestamp": g(&ev, "received_at"),
            "automation_id": aid, "automation_name": name, "project_id": project,
            "status": if accepted { "accepted" } else { "rejected" }, "trigger_kind": "webhook",
            "reason": g(&ev, "reason"), "state_root": g(&ev, "payload_hash"),
            "payload_hash": g(&ev, "payload_hash"), "headers_hash": g(&ev, "headers_hash"),
            "request_id": g(&ev, "request_id"), "run_ref": run_ref_v, "timeline_ref": timeline_v,
        }));
    }
    // Harness execution runs — the adapter drivers (opencode / deepseek_tui) posted an
    // agent-run-transcript per run with a tamper-evident state_root; surface each as a
    // first-class proof so a real harness execution is reachable from the ledger, with its
    // session, files changed, and receipt.
    for t in by_run.values() {
        if t.get("op").and_then(|v| v.as_str()) != Some("adapter_execute") {
            continue;
        }
        let out = t
            .get("step_results")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|s| s.get("output"))
            .cloned()
            .unwrap_or(Value::Null);
        let run_id = t.get("run_id").and_then(|v| v.as_str()).unwrap_or("");
        entries.push(json!({
            "id": run_id, "kind": "harness_execution", "timestamp": g(t, "recorded_at"),
            "status": g(&out, "exit_status"), "harness": g(&out, "harness"),
            "session_ref": g(&out, "session_ref"), "profile_ref": g(t, "profile_ref"),
            "files_written": g(&out, "files_written"),
            "state_root": g(t, "state_root"), "run_ref": run_id,
            "timeline_ref": format!("/__ioi/run-timeline/{run_id}"),
            "receipt_ref": g(&out, "receipt_ref"),
            "implementation_result": g(&out, "implementation_result"),
        }));
    }
    // GoalRun proofs — multi-harness orchestration. Each role invocation and the reconciliation
    // posted an agent-run-transcript (tamper-evident state_root); the run record itself carries
    // the topology + continuation state. All three become first-class ledger entries so the
    // whole orchestration (invocations → verifier evidence → reconciliation → final files) is
    // reachable from one proof stream.
    for t in by_run.values() {
        let op = t.get("op").and_then(|v| v.as_str()).unwrap_or("");
        if op != "goal_run_execute" && op != "goal_run_reconciliation" {
            continue;
        }
        let out = t
            .get("step_results")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|s| s.get("output"))
            .cloned()
            .unwrap_or(Value::Null);
        let run_id = t.get("run_id").and_then(|v| v.as_str()).unwrap_or("");
        if op == "goal_run_execute" {
            entries.push(json!({
                "id": run_id, "kind": "goal_run_invocation", "timestamp": g(t, "recorded_at"),
                "status": g(&out, "exit_status"), "harness": g(&out, "harness"),
                "role_key": g(&out, "role_key"), "goal_run_ref": g(&out, "goal_run_ref"),
                "session_ref": g(&out, "session_ref"), "profile_ref": g(t, "profile_ref"),
                "files_written": g(&out, "files_written"),
                "state_root": g(t, "state_root"), "run_ref": run_id,
                "timeline_ref": format!("/__ioi/run-timeline/{run_id}"),
                "receipt_ref": g(&out, "receipt_ref"),
                "implementation_result": g(&out, "implementation_result"),
            }));
        } else {
            entries.push(json!({
                "id": run_id, "kind": "goal_run_reconciliation", "timestamp": g(t, "recorded_at"),
                "status": g(&out, "merge_strategy"), "goal_run_ref": g(&out, "goal_run_ref"),
                "merge_strategy": g(&out, "merge_strategy"), "reason_code": g(&out, "reason_code"),
                "selected_candidate_refs": g(&out, "selected_candidate_refs"),
                "final_changed_files": g(&out, "final_changed_files"),
                "verifier_evidence_refs": g(&out, "verifier_evidence_refs"),
                "state_root": g(t, "state_root"), "run_ref": run_id,
                "timeline_ref": format!("/__ioi/run-timeline/{run_id}"),
                "receipt_ref": g(&out, "receipt_ref"),
            }));
        }
    }
    // Intelligence projections — the scoped memory a harness invocation actually received
    // (refs + counts only; private bodies never enter the ledger).
    for r in read_record_dir(&st.data_dir, "memory-projections") {
        entries.push(json!({
            "id": g(&r, "projection_id"), "kind": "memory_projection", "timestamp": g(&r, "created_at"),
            "status": "projected", "projection_ref": g(&r, "projection_ref"),
            "memory_space_ref": g(&r, "memory_space_ref"),
            "session_ref": g(&r, "session_ref"), "goal_run_ref": g(&r, "goal_run_ref"),
            "harness_profile_ref": g(&r, "harness_profile_ref"),
            "policy_ref": g(&r, "policy_ref"),
            "counts": g(&r, "counts"),
            "receipt_ref": r.pointer("/receipt_refs/0").cloned().unwrap_or(Value::Null),
        }));
    }
    // Memory lifecycle transitions — receipted quality-state changes (promote/dispute/stale/
    // supersede); the durable-truth audit trail for the intelligence plane.
    for r in read_record_dir(&st.data_dir, "receipts") {
        if g(&r, "kind") == json!("hypervisor.simulation-report") {
            entries.push(json!({
                "id": g(&r, "id"), "kind": "simulation_report", "timestamp": g(&r, "at"),
                "status": if r.get("high_impact") == Some(&json!(true)) { "high_impact" } else { "simulated" },
                "simulation_ref": g(&r, "simulation_ref"), "proposal_ref": g(&r, "proposal_ref"),
                "report_hash": g(&r, "report_hash"), "summary": g(&r, "summary"),
                "receipt_ref": g(&r, "id"),
            }));
            continue;
        }
        if g(&r, "kind") == json!("hypervisor.rollout-enforcement") {
            entries.push(json!({
                "id": g(&r, "id"), "kind": "rollout_enforcement", "timestamp": g(&r, "at"),
                "status": "blocked", "deployment_posture": g(&r, "deployment_posture"),
                "rollout_context_source": g(&r, "rollout_context_source"),
                "launch_ref": g(&r, "launch_ref"), "blocked": g(&r, "blocked"),
                "receipt_ref": g(&r, "id"),
            }));
            continue;
        }
        if g(&r, "kind") == json!("hypervisor.policy-rollout") {
            entries.push(json!({
                "id": g(&r, "id"), "kind": "policy_rollout", "timestamp": g(&r, "at"),
                "status": g(&r, "action"), "policy_ref": g(&r, "policy_ref"),
                "base_policy_ref": g(&r, "base_policy_ref"),
                "proposal_ref": g(&r, "proposal_ref"), "simulation_ref": g(&r, "simulation_ref"),
                "approval_request_ref": g(&r, "approval_request_ref"),
                "release_control_ref": g(&r, "release_control_ref"), "receipt_ref": g(&r, "id"),
                "cohort_refs": g(&r, "cohort_refs"), "rollout_mode": g(&r, "rollout_mode"),
            }));
            continue;
        }
        if g(&r, "kind") == json!("hypervisor.improvement-applied") {
            entries.push(json!({
                "id": g(&r, "id"), "kind": "improvement_applied", "timestamp": g(&r, "at"),
                "status": g(&r, "proposal_kind"), "signal": g(&r, "signal"),
                "proposal_ref": g(&r, "proposal_ref"), "applied_ref": g(&r, "applied_ref"),
                "evidence_refs": g(&r, "evidence_refs"), "receipt_ref": g(&r, "id"),
                "simulation_ref": g(&r, "simulation_ref"), "report_hash": g(&r, "report_hash"),
                "approval_request_ref": g(&r, "approval_request_ref"),
                "release_control_ref": g(&r, "release_control_ref"),
            }));
            continue;
        }
        if g(&r, "kind") != json!("hypervisor.memory-lifecycle") {
            continue;
        }
        entries.push(json!({
            "id": g(&r, "id"), "kind": "memory_lifecycle", "timestamp": g(&r, "at"),
            "status": g(&r, "transition"), "record_ref": g(&r, "record_ref"),
            "from_quality_state": g(&r, "from_quality_state"), "to_quality_state": g(&r, "to_quality_state"),
            "reason": g(&r, "reason"), "superseded_by_ref": g(&r, "superseded_by_ref"),
            "receipt_ref": g(&r, "id"),
        }));
    }
    for r in read_record_dir(&st.data_dir, "goal-runs") {
        entries.push(json!({
            "id": g(&r, "goal_run_id"), "kind": "goal_run", "timestamp": g(&r, "updated_at"),
            "status": g(&r, "status"), "goal_run_ref": g(&r, "goal_ref"),
            "normalized_goal": g(&r, "normalized_goal"),
            "orchestration_policy": g(&r, "orchestration_policy"),
            "continuation_state": g(&r, "continuation_state"),
            "partial_result": g(&r, "partial_result"),
            "session_ref": g(&r, "target_session_ref"),
            "invocation_refs": g(&r, "invocation_refs"),
            "reconciliation_ref": g(&r, "reconciliation_ref"),
            "policy_ref": g(&r, "policy_ref"),
            "final_changed_files": g(&r, "final_changed_files"),
            "receipt_ref": r.pointer("/admission/receipt_refs/0").cloned().unwrap_or(Value::Null),
        }));
    }
    // Governed-lifecycle proofs — domain-app mount/serve/unmount/kill, marketplace publish, and
    // KillSwitch enforcement receipts. These are real state-root proofs; surface them in the ledger so
    // the whole governed lifecycle is reachable from one proof stream (not just automation runs).
    for r in read_record_dir(&st.data_dir, "domain-app-mount-receipts") {
        entries.push(json!({
            "id": g(&r, "id"), "kind": "domain_app_runtime", "timestamp": g(&r, "at"),
            "status": g(&r, "action"), "action": g(&r, "action"), "state_root": g(&r, "state_root"),
            "domain_app_ref": g(&r, "domain_app_ref"), "approval_request_ref": g(&r, "approval_request_ref"),
            "release_control_ref": g(&r, "release_control_ref"), "receipt_ref": g(&r, "ref"),
        }));
    }
    for r in read_record_dir(&st.data_dir, "marketplace-publish-receipts") {
        entries.push(json!({
            "id": g(&r, "id"), "kind": "marketplace_publish", "timestamp": g(&r, "at"),
            "status": "published", "state_root": g(&r, "state_root"),
            "candidate_ref": g(&r, "candidate_ref"), "listing_id": g(&r, "listing_id"),
            "published_runtime_ref": g(&r, "published_runtime_ref"), "admission_review_ref": g(&r, "admission_review_ref"),
            "release_control_ref": g(&r, "release_control_ref"), "receipt_ref": g(&r, "ref"),
        }));
    }
    for r in read_record_dir(&st.data_dir, "governance-kill-enforcement-receipts") {
        entries.push(json!({
            "id": g(&r, "id"), "kind": "kill_enforcement", "timestamp": g(&r, "at"),
            "status": g(&r, "enforcement_state"), "state_root": g(&r, "state_root"),
            "kill_switch_ref": g(&r, "kill_switch_ref"), "subject_ref": g(&r, "subject_ref"),
            "affected_runtime_refs": g(&r, "affected_runtime_refs"), "receipt_ref": g(&r, "ref"),
        }));
    }
    // ODK materialization crossings — each materialized object set is a governed act: a materializing
    // run read a declared source under a held CapabilityLease + sealed connector session and
    // registered a bounded, all-or-nothing object set BEHIND a pre-output receipt. Project each set
    // into the one proof stream BY REFERENCE. The pre-output + registration receipts already exist on
    // the ODK materializing-run receipt family; this projection MINTS NOTHING (it is a read-time view)
    // — receipt authority is not duplicated, only surfaced. This turns the lineage surface's
    // "0 Provenance proof-stream edges" into real cross-plane edges.
    for r in read_record_dir(&st.data_dir, "odk-materialized-object-sets") {
        entries.push(json!({
            "id": g(&r, "id"), "kind": "odk_materialization", "timestamp": g(&r, "registered_at"),
            "status": "registered", "object_count": g(&r, "count"),
            "ontology_ref": g(&r, "ontology_ref"), "object_type_id": g(&r, "object_type_id"),
            "materialized_set_ref": g(&r, "ref"),
            "materializing_run_ref": g(&r, "materializing_run_ref"),
            "connector_session_ref": g(&r, "connector_session_ref"),
            "capability_lease_plan_ref": g(&r, "capability_lease_plan_ref"),
            "ontology_projection_id": g(&r, "ontology_projection_id"),
            // The proof pointer IS the existing pre-output receipt — referenced, never re-minted.
            "receipt_ref": g(&r, "pre_output_receipt_ref"),
            "pre_output_receipt_ref": g(&r, "pre_output_receipt_ref"),
            "source_contact": g(&r, "source_contact"),
            "lineage_ref": "/__ioi/lineage",
            "authority_rule": "projected by reference from the existing ODK materialization receipts; the Provenance proof stream mints no receipt here",
        }));
    }
    entries.sort_by(|a, b| {
        b.get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("timestamp").and_then(|v| v.as_str()).unwrap_or(""))
    });
    if let Some(pid) = q.get("project").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        entries.retain(|e| e.get("project_id").and_then(|v| v.as_str()) == Some(pid));
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "entries": entries })),
    )
}

fn new_webhook_token() -> String {
    format!(
        "whk_{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// The rotation write, extracted from the Axum adapter so its failure path is directly testable.
/// `automation` is the record the adapter just loaded; `token` is INJECTED so tests fix the secret
/// instead of asserting over a freshly minted random one.
///
/// One record, one write, no receipt and no second effect: nothing happens before the write except
/// generating the candidate token in memory, so a failed write needs no compensation — it only must
/// not be acknowledged. Acknowledgement is the whole point here. The plaintext is shown EXACTLY
/// ONCE and never persisted, so returning `ok:true` over a discarded write handed the operator a
/// secret that authenticates nowhere while the superseded token stayed valid:
/// `handle_automation_webhook` authorises inbound triggers by comparing `sha256(presented)` against
/// the stored `webhook_token_hash`, so the durable hash — not the response — decides what opens the
/// trigger. A rotation reported as done while the old credential still works is a false
/// security-control acknowledgement, which is worse than a rotation that visibly failed.
///
/// The write goes through `durable_fs::persist_record_durable` rather than the legacy
/// `persist_record` because a credential rotation needs the two failure modes told apart, and only
/// the temp-sibling → fsync → rename → directory-fsync writer can tell them apart:
///   * `NotCommitted` — THIS candidate did not commit. On its own that proves nothing about what
///     is current: a concurrent writer may have rotated between the adapter's load and this
///     failure, so "the old token still works" would be a guess. The prior hash is captured before
///     mutation and re-read after the refusal, and only when the durable state still matches what
///     this request read does the HTTP 500 claim continuity. Otherwise the state is ambiguous and
///     gets the 503 lane below.
///   * `RenamedDurabilityUnconfirmed` — the rename ALREADY replaced the old record in the live
///     view and only the directory fsync failed. HTTP 503, and the honest report is
///     unknown-but-possibly-applied: no plaintext is issued (there is none the caller can trust),
///     and the response must NOT claim the old token still works, because it very likely does not.
///
/// Every non-OK lane issues NO plaintext and tells the caller to rotate again, because rotating
/// again is the only operation that converges the automation on a token the caller knows.
///
/// A NOTE ON IDS: `persist_record_durable` REFUSES a record id that is not filesystem-safe instead
/// of normalizing it, because normalizing would let two distinct ids collide on one file. The
/// legacy `persist_record` normalized silently. `load` normalizes with the same character set, so
/// for every id that passes the guard the two agree on exactly one file; an id outside it now
/// refuses the rotation rather than rotating into a shared file. That is a refusal, never a false
/// success.
fn record_rotated_webhook_token(
    data_dir: &str,
    id: &str,
    mut automation: Value,
    token: &str,
) -> (StatusCode, Value) {
    use super::durable_fs::PersistFailure;
    let token_hash = sha256_hex_str(token);
    // Captured BEFORE mutation: the trigger-token state this request actually read. `None` is a
    // real state (a spec that has never had a token), distinct from "the record is unreadable".
    let prior_hash = automation
        .get("webhook_token_hash")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    automation["webhook_token_hash"] = json!(token_hash);
    automation["webhook_url"] = json!(format!("/v1/hypervisor/automations/{id}/webhook"));
    if automation.get("trigger_kind").and_then(|v| v.as_str()) != Some("time") {
        automation["trigger_kind"] = json!("webhook"); // don't clobber an existing schedule
    }
    automation["updated_at"] = json!(iso_now());
    match super::durable_fs::persist_record_durable(data_dir, "automations", id, &automation) {
        Ok(()) => {}
        Err(PersistFailure::NotCommitted(_)) => {
            // The candidate did not commit. Whether the PRIOR token is still current is a separate
            // question this failure does not answer, so re-read and compare against what this
            // request loaded. A vanished/unreadable record is NOT "unchanged" — it is unknown.
            let unchanged = load(data_dir, "automations", id).is_some_and(|r| {
                r.get("webhook_token_hash")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    == prior_hash
            });
            if !unchanged {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({ "ok": false, "error": {
                        "code": "automation_webhook_rotation_state_ambiguous",
                        "message": "the rotated webhook trigger token was not committed, and this automation's durable trigger-token state no longer matches the state this request read — a concurrent rotation or an unreadable record. No token was issued, and NEITHER the old nor the new token may be assumed current. Rotate again to converge."
                    }}),
                );
            }
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "ok": false, "error": {
                    "code": "automation_webhook_rotation_persistence_failed",
                    "message": "the rotated webhook trigger token could not be durably recorded — no rotation occurred, no new token was issued, and this automation's trigger token is unchanged from the one this request read. Rotate again to retry."
                }}),
            );
        }
        Err(PersistFailure::RenamedDurabilityUnconfirmed(_)) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({ "ok": false, "error": {
                    "code": "automation_webhook_rotation_durability_unconfirmed",
                    "message": "the rotated webhook trigger token is visible but its durability is UNCONFIRMED — the rotation may or may not have applied, no usable token was issued, and the previously issued token must NOT be assumed still valid. Rotate again to converge on a known token."
                }}),
            );
        }
    }
    // Acknowledge from the RELOADED durable record, never from the in-memory candidate — the same
    // read shape `handle_automation_webhook` authenticates against. A committed write that does not
    // read back as current is ambiguous in exactly the same way, and gets the same treatment: no
    // plaintext, and no claim about which token now opens the trigger.
    let reloaded = load(data_dir, "automations", id);
    if reloaded
        .as_ref()
        .and_then(|r| r.get("webhook_token_hash"))
        .and_then(|v| v.as_str())
        != Some(token_hash.as_str())
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "ok": false, "error": {
                "code": "automation_webhook_rotation_unconfirmed",
                "message": "the write reported committed but the rotated webhook trigger token did not read back as this automation's current token — the rotation is not acknowledged, no token was issued, and neither token may be assumed current. Rotate again to converge."
            }}),
        );
    }
    let webhook_url = reloaded
        .as_ref()
        .and_then(|r| r.get("webhook_url"))
        .cloned()
        .unwrap_or(Value::Null);
    (
        StatusCode::OK,
        json!({ "ok": true, "webhook_token": token, "webhook_url": webhook_url }),
    )
}

/// POST /v1/hypervisor/automations/:id/webhook-rotate — (re)mint the opaque trigger token (also
/// enables webhook triggering on an existing automation). Hash stored at rest; plaintext returned
/// ONCE, and only once the new hash is durably recorded and reads back as current.
pub(crate) async fn handle_automation_webhook_rotate(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    // #237 finding closed — identity FIRST (rule E): minting/rotating the trigger secret is a
    // write of trigger AUTHORITY; the typed 401 is owed BEFORE the record load. The inbound
    // /webhook trigger itself stays on its own token lane (gate-exempt), untouched here.
    if let Err(error) = super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        return automation_scope_refusal(error);
    }
    let Some(a) = load(&st.data_dir, "automations", &id) else {
        // PRESERVED VERBATIM. This packet changes the durability contract, not the not-found
        // contract; the return type had to name a status, and naming OK keeps the existing wire
        // response byte-for-byte rather than silently broadening it to 404.
        return (
            StatusCode::OK,
            Json(json!({ "ok": false, "reason": "automation not found" })),
        );
    };
    let (status, payload) =
        record_rotated_webhook_token(&st.data_dir, &id, a, &new_webhook_token());
    (status, Json(payload))
}

/// GET /v1/hypervisor/automations/:id/webhook-events — recent inbound trigger events (audit trail)
/// + accepted/rejected counts.
pub(crate) async fn handle_automation_webhook_events(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let mut events: Vec<Value> = read_record_dir(&st.data_dir, "webhook-trigger-events")
        .into_iter()
        .filter(|e| e.get("automation_id").and_then(|v| v.as_str()) == Some(id.as_str()))
        .collect();
    events.sort_by(|a, b| {
        b.get("received_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("received_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
    let accepted = events
        .iter()
        .filter(|e| e.get("accepted").and_then(|v| v.as_bool()) == Some(true))
        .count();
    let rejected = events.len() - accepted;
    Json(
        json!({ "ok": true, "events": events, "accepted_count": accepted, "rejected_count": rejected }),
    )
}

/// POST /v1/hypervisor/automations/:id/webhook — authenticated inbound trigger. Verifies the opaque
/// trigger token, runs policy checks, records a WebhookTriggerReceipt (accepted OR rejected w/ reason),
/// and on accept fires the SAME manual-run path (async) so the run shares the run history / state_root
/// / transcript / timeline. Auth is the trigger token (NOT a session) → the auth gate exempts it.
pub(crate) async fn handle_automation_webhook(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    const MAX_PAYLOAD: usize = 1_048_576; // 1 MiB
    let received_at = iso_now();
    let request_id = format!("whreq_{}", uuid::Uuid::new_v4().simple());
    // Audit hashes — never store raw headers/payload.
    let payload_hash = sha256_hex_str(&String::from_utf8_lossy(&body));
    let mut header_pairs: Vec<String> = headers
        .iter()
        .map(|(k, v)| format!("{}:{}", k.as_str(), v.to_str().unwrap_or("")))
        .collect();
    header_pairs.sort();
    let headers_hash = sha256_hex_str(&header_pairs.join("\n"));
    let token = headers
        .get("x-ioi-trigger-token")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    // Record a trigger receipt (audit). Returns the receipt_id.
    let record_event = |accepted: bool, reason: &str, run_ref: Value| -> std::io::Result<String> {
        let rid = format!("whk_evt_{}", uuid::Uuid::new_v4().simple());
        let ev = json!({
            "schema_version": "ioi.hypervisor.webhook-trigger-receipt.v1",
            "receipt_id": rid, "automation_id": id, "request_id": request_id,
            "received_at": received_at, "headers_hash": headers_hash, "payload_hash": payload_hash,
            "payload_bytes": body.len(), "accepted": accepted, "reason": reason, "run_ref": run_ref,
        });
        // W1.2 / MEF-GAP-008 — the trigger receipt IS the security audit trail; a discarded write
        // must fail the caller, never drop the audit record silently.
        persist_record(&st.data_dir, "webhook-trigger-events", &rid, &ev)?;
        Ok(rid)
    };
    let reject = |status: StatusCode, reason: &str| {
        // A rejection receipt is the security audit trail — if it cannot be written, fail closed
        // (500) rather than rejecting off the record.
        if record_event(false, reason, Value::Null).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "ok": false, "code": "automation_webhook_receipt_persistence_failed",
                "message": "the webhook rejection could not be receipted — refusing without an audit record is not allowed", "request_id": request_id }),
                ),
            );
        }
        (
            status,
            Json(json!({ "ok": false, "reason": reason, "request_id": request_id })),
        )
    };

    let Some(a) = load(&st.data_dir, "automations", &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                json!({ "ok": false, "reason": "automation_not_found", "request_id": request_id }),
            ),
        );
    };
    // Token: compare hashes (reject if no token configured or mismatch).
    let want = a
        .get("webhook_token_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if want.is_empty() || token.is_empty() || sha256_hex_str(&token) != want {
        return reject(StatusCode::UNAUTHORIZED, "invalid_token");
    }
    // Policy checks: kill switch, project exists, payload size, concurrency.
    if a.get("enabled").and_then(|v| v.as_bool()) != Some(true) {
        return reject(StatusCode::FORBIDDEN, "automation_disabled");
    }
    let project_id = a.get("project_id").and_then(|v| v.as_str()).unwrap_or("");
    if project_id.is_empty() || load(&st.data_dir, "projects", project_id).is_none() {
        return reject(StatusCode::UNPROCESSABLE_ENTITY, "project_missing");
    }
    if body.len() > MAX_PAYLOAD {
        return reject(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
    }
    let max_conc = a
        .get("max_concurrency")
        .and_then(|v| v.as_i64())
        .filter(|n| *n > 0)
        .unwrap_or(1);
    let running = read_record_dir(&st.data_dir, "automation-executions")
        .iter()
        .filter(|e| {
            e.get("automation_id").and_then(|v| v.as_str()) == Some(id.as_str())
                && e.get("status").and_then(|v| v.as_str()) == Some("running")
        })
        .count() as i64;
    if running >= max_conc {
        return reject(StatusCode::TOO_MANY_REQUESTS, "max_concurrency");
    }
    // Accept: record the receipt, then fire the manual-run path async; backfill run_ref when it starts.
    // W1.2 / MEF-GAP-008 — receipt precedes effect: if the acceptance cannot be receipted, return 500
    // and do NOT spawn the run.
    let receipt_id = match record_event(true, "accepted", Value::Null) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "ok": false, "code": "automation_webhook_receipt_persistence_failed",
                "message": "the webhook acceptance could not be receipted — the run is not started (receipt precedes effect)", "request_id": request_id }),
                ),
            )
        }
    };
    let base = st.base_url.clone();
    let data_dir = st.data_dir.clone();
    let id2 = id.clone();
    let receipt = receipt_id.clone();
    // Opportunistic: on the webhook path there is no session to forward, so this
    // is a no-op there. It matters when the same executor runs for an
    // authenticated caller. The accepted fire additionally carries the per-boot
    // internal dispatch token — the trigger token already authenticated this
    // crossing (receipt above), and the identity-gated manual-run lane admits the
    // daemon's own dispatch through that token, executing as the spec's stored
    // executor_identity.
    let mut inbound = headers.clone();
    if let Ok(value) = axum::http::HeaderValue::from_str(&st.internal_dispatch_token) {
        inbound.insert("x-ioi-internal-dispatch", value);
    }
    tokio::spawn(async move {
        if let Ok(r) = call(
            &base,
            "POST",
            &format!("/v1/hypervisor/automations/{id2}/runs"),
            Some(json!({ "trigger": "webhook" })),
            &inbound,
        )
        .await
        {
            if let Some(exec_id) = r
                .get("execution")
                .and_then(|e| e.get("execution_id"))
                .and_then(|v| v.as_str())
            {
                if let Some(mut rec) = load(&data_dir, "webhook-trigger-events", &receipt) {
                    rec["run_ref"] = json!(exec_id);
                    // CLASSIFIED — best-effort telemetry: no response left to gate; the execution
                    // record is the durable truth, this only backfills run_ref onto the receipt.
                    let _ = persist_record(&data_dir, "webhook-trigger-events", &receipt, &rec);
                }
            }
        }
    });
    (
        StatusCode::ACCEPTED,
        Json(
            json!({ "ok": true, "accepted": true, "request_id": request_id, "receipt_id": receipt_id }),
        ),
    )
}

/// POST /v1/hypervisor/automations/:id/start (and /:id/runs) — run the workflow: fresh env → steps
/// → outputs, then record a tamper-evident run transcript for the Run Timeline / Work Ledger.
pub(crate) async fn handle_automation_start(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    mut inbound: axum::http::HeaderMap,
) -> Result<(StatusCode, Json<Value>), AppError> {
    // #237 finding closed — identity FIRST (rule E): a manual run is a write crossing; the typed
    // 401 is owed BEFORE the record load. The daemon's OWN dispatches (scheduler tick, accepted
    // webhook fire) cross with the per-boot internal dispatch token instead of a session — they
    // are the daemon acting on the stored spec, and the run's acting identity is then the spec's
    // own `executor_identity` (the delegated durable authority), never an ambient operator.
    let internal_dispatch = internal_dispatch_authorized(&st, &inbound);
    let acting_principal_ref =
        match super::substrate_store::resolve_request_identity(&st.data_dir, &inbound) {
            Ok(identity) => Some(identity.principal_ref),
            Err(error) => {
                if !internal_dispatch_authorized(&st, &inbound) {
                    return Ok(automation_scope_refusal(error));
                }
                None // internal dispatch — resolved from the spec below, after the load
            }
        };
    let Some(automation) = load(&st.data_dir, "automations", &id) else {
        return Ok((
            StatusCode::OK,
            Json(json!({ "ok": false, "reason": "automation not found" })),
        ));
    };
    let acting_principal_ref = acting_principal_ref.unwrap_or_else(|| {
        automation["executor_identity"]["ref"]
            .as_str()
            .unwrap_or("")
            .to_string()
    });
    if internal_dispatch {
        let tenant_refs = super::lifecycle_routes::resolve_principal_tenant_refs(
            &st.data_dir,
            &acting_principal_ref,
        )
        .map_err(|error| AppError(StatusCode::SERVICE_UNAVAILABLE, error))?;
        let mut organizations = tenant_refs
            .iter()
            .filter(|tenant_ref| tenant_ref.starts_with("org://"));
        let (Some(owner_ref), None) = (organizations.next(), organizations.next()) else {
            return Err(AppError(
                StatusCode::FORBIDDEN,
                "internal environment dispatch requires exactly one active organization tenant"
                    .into(),
            ));
        };
        inbound.insert(
            "x-ioi-internal-principal-ref",
            axum::http::HeaderValue::from_str(&acting_principal_ref)
                .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?,
        );
        inbound.insert(
            "x-ioi-internal-owner-ref",
            axum::http::HeaderValue::from_str(owner_ref)
                .map_err(|error| AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?,
        );
    }
    let base = st.base_url.clone();
    let exec_id = format!("aex_{:x}", nanos());
    let steps = automation["steps"].as_array().cloned().unwrap_or_default();
    let mut counts =
        json!({ "pending": steps.len(), "running": 0, "done": 0, "failed": 0, "stopped": 0 });
    let mut exec = json!({
        "schema_version": "ioi.hypervisor.automation-execution.v1",
        "execution_id": exec_id, "automation_id": id, "status": "running",
        "executor_identity": automation["executor_identity"], "environment_id": Value::Null,
        // INV-37: who triggered this run — the resolved session principal on a manual run, the
        // spec's delegated executor ref on an internal (scheduler/webhook) dispatch.
        "acting_principal_ref": acting_principal_ref,
        "step_results": [], "counts": counts, "started_at": iso_now(), "finished_at": Value::Null
    });
    // W1.2 / MEF-GAP-008 — this running exec is the concurrency-gate input; a discarded write means
    // unbounded concurrency. Fail closed via the existing AppError 500 lane.
    if persist_record(&st.data_dir, "automation-executions", &exec_id, &exec).is_err() {
        return Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "automation_execution_persistence_failed: the initial running execution did not commit — the run was not started".to_string(),
        ));
    }

    // 1) fresh environment (real env create + start over loopback).
    let spec = json!({ "spec": { "environment_class_id": automation["environment_class_id"], "recipe_ref": automation["recipe_ref"], "project_id": automation["project_id"] } });
    let created = call(
        &base,
        "POST",
        "/v1/hypervisor/environments",
        Some(spec),
        &inbound,
    )
    .await
    .map_err(|e| {
        AppError(
            axum::http::StatusCode::BAD_GATEWAY,
            format!("env create: {e}"),
        )
    })?;
    let env_id = created["environment"]["id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if env_id.is_empty() {
        exec["status"] = json!("failed");
        exec["finished_at"] = json!(iso_now());
        // W1.2 / MEF-GAP-008 — the terminal `failed` state must be durable; a discarded write leaves
        // the exec "running" forever (holding a concurrency slot). Fail closed.
        if persist_record(&st.data_dir, "automation-executions", &exec_id, &exec).is_err() {
            return Err(AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "automation_execution_persistence_failed: the failed-execution record did not commit".to_string(),
            ));
        }
        return Ok((
            StatusCode::OK,
            Json(json!({ "ok": false, "reason": "env create failed", "execution": exec })),
        ));
    }
    let _ = call(
        &base,
        "POST",
        &format!("/v1/hypervisor/environments/{env_id}/start"),
        None,
        &inbound,
    )
    .await;
    exec["environment_id"] = json!(env_id);
    let ws = env_workspace(&st.data_dir, &env_id).unwrap_or_default();
    let base_ref = {
        let h = git(&ws, &["rev-parse", "HEAD"]).trim().to_string();
        if h.is_empty() {
            "EMPTY".to_string()
        } else {
            h
        }
    };

    let mut results: Vec<Value> = Vec::new();
    let mut failed = false;
    for (idx, step) in steps.iter().enumerate() {
        if failed {
            results.push(json!({ "step": idx, "kind": step["kind"], "status": "skipped" }));
            continue;
        }
        let kind = step["kind"].as_str().unwrap_or("");
        let (status, output) = match kind {
            "agent" => {
                let conv = call(
                    &base,
                    "POST",
                    "/v1/hypervisor/agentops/conversations",
                    Some(json!({ "environment_id": env_id, "title": automation["name"] })),
                    &inbound,
                )
                .await;
                let cid = conv
                    .as_ref()
                    .ok()
                    .and_then(|c| {
                        c["conversation"]["conversation_id"]
                            .as_str()
                            .map(str::to_string)
                    })
                    .unwrap_or_default();
                let prompt = step["prompt"].as_str().unwrap_or("Make a concrete change.");
                let sent = call(
                    &base,
                    "POST",
                    &format!("/v1/hypervisor/agentops/conversations/{cid}/send"),
                    Some(json!({ "text": prompt })),
                    &inbound,
                )
                .await;
                match sent {
                    Ok(s) => {
                        let blocks = s["blocks"].as_array().cloned().unwrap_or_default();
                        let asst = blocks
                            .iter()
                            .find(|b| b["kind"] == "assistant_message")
                            .and_then(|b| b["text"].as_str())
                            .unwrap_or("")
                            .to_string();
                        let file = blocks
                            .iter()
                            .find(|b| b["kind"] == "file_modification")
                            .and_then(|b| b["path"].as_str())
                            .unwrap_or("")
                            .to_string();
                        (
                            "done",
                            json!({ "conversation_id": cid, "assistant_excerpt": asst.chars().take(200).collect::<String>(), "file": file }),
                        )
                    }
                    Err(e) => ("failed", json!({ "error": e })),
                }
            }
            "command" => {
                let cmd = step["command"].as_str().unwrap_or("true");
                match call(
                    &base,
                    "POST",
                    "/v1/hypervisor/exec",
                    Some(json!({ "environment_id": env_id, "command": cmd })),
                    &inbound,
                )
                .await
                {
                    Ok(r) => {
                        let out = r
                            .get("stdout")
                            .or_else(|| r.get("output"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let code = r.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(0);
                        (
                            if code == 0 { "done" } else { "failed" },
                            json!({ "command": cmd, "exit_code": code, "stdout_excerpt": out.chars().take(400).collect::<String>() }),
                        )
                    }
                    Err(e) => ("failed", json!({ "command": cmd, "error": e })),
                }
            }
            "proposal" => {
                // a REAL proposal: the diff of everything this run changed on the env branch.
                let range = if base_ref == "EMPTY" {
                    "HEAD".to_string()
                } else {
                    format!("{base_ref}..HEAD")
                };
                let stat = git(&ws, &["diff", "--stat", &range]);
                let diff = git(&ws, &["diff", &range]);
                let files: Vec<String> = git(&ws, &["diff", "--name-only", &range])
                    .lines()
                    .map(str::to_string)
                    .filter(|s| !s.is_empty())
                    .collect();
                let pid = format!("prop_{:x}", nanos());
                let proposal = json!({
                    "schema_version": "ioi.hypervisor.automation-proposal.v1",
                    "proposal_id": pid, "execution_id": exec_id, "environment_id": env_id,
                    "title": step["title"].as_str().unwrap_or("Automation proposal"),
                    "review_state": "proposed", "base_ref": base_ref, "head_ref": git(&ws, &["rev-parse", "HEAD"]).trim(),
                    "changed_files": files, "diffstat": stat.trim(), "diff": diff, "host_mutation": false, "at": iso_now()
                });
                // W1.2 / MEF-GAP-008 — fail the STEP (not the whole run) if the proposal work product
                // does not commit: a returned proposal_ref must resolve to a persisted proposal.
                if persist_record(&st.data_dir, "automation-proposals", &pid, &proposal).is_err() {
                    (
                        "failed",
                        json!({ "code": "automation_proposal_persistence_failed", "message": "the proposal did not commit — the step is failed rather than reporting a proposal no reader can find", "proposal_ref": format!("agentgres://automation-proposal/{pid}") }),
                    )
                } else {
                    (
                        "done",
                        json!({ "proposal_ref": format!("agentgres://automation-proposal/{pid}"), "proposal_id": pid, "changed_files": proposal["changed_files"], "diffstat": stat.trim() }),
                    )
                }
            }
            other => (
                "failed",
                json!({ "error": format!("unknown step kind '{other}'") }),
            ),
        };
        if status == "failed" {
            failed = true;
        }
        results.push(json!({ "step": idx, "kind": kind, "status": status, "output": output }));
    }

    let done = results.iter().filter(|r| r["status"] == "done").count();
    let failed_n = results.iter().filter(|r| r["status"] == "failed").count();
    let stopped_n = results.iter().filter(|r| r["status"] == "skipped").count();
    counts = json!({ "pending": 0, "running": 0, "done": done, "failed": failed_n, "stopped": stopped_n });
    exec["counts"] = counts;
    exec["step_results"] = json!(results);
    exec["status"] = json!(if failed { "failed" } else { "done" });
    exec["finished_at"] = json!(iso_now());
    // W1.2 / MEF-GAP-008 — a discarded final write leaves the exec "running" forever; do NOT POST the
    // transcript if it fails. Fail closed via the AppError 500 lane.
    if persist_record(&st.data_dir, "automation-executions", &exec_id, &exec).is_err() {
        return Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "automation_execution_persistence_failed: the final execution record did not commit — the run transcript was not posted".to_string(),
        ));
    }

    // Record a durable, tamper-evident run transcript (the agent-run-transcript plane computes a
    // state_root over it) so the manual run shows in the Run Timeline / Work Ledger with proof.
    let transcript = json!({
        "schema_version": "ioi.hypervisor.agent-run-transcript.v1",
        "run_id": exec_id,
        "kind": "automation-run",
        "automation_id": id,
        "automation_name": automation["name"],
        "project_id": automation["project_id"],
        "environment_id": exec["environment_id"],
        "status": exec["status"],
        "step_count": results.len(),
        "counts": exec["counts"],
        "step_results": exec["step_results"],
        "started_at": exec["started_at"],
        "finished_at": exec["finished_at"],
    });
    let _ = call(
        &base,
        "POST",
        &format!("/v1/hypervisor/agent-run-transcripts/{exec_id}"),
        Some(transcript),
        &inbound,
    )
    .await;
    Ok((
        StatusCode::OK,
        Json(json!({ "ok": !failed, "execution": exec })),
    ))
}

/// POST /v1/hypervisor/automation-executions/:id/cancel — stop a running execution.
pub(crate) async fn handle_automation_cancel(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    // #237 finding closed — identity FIRST (rule E): stopping a running execution is a write;
    // the typed 401 is owed BEFORE the record load (no existence oracle for anonymous callers).
    if let Err(error) = super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        return automation_scope_refusal(error);
    }
    let Some(mut exec) = load(&st.data_dir, "automation-executions", &id) else {
        return (
            StatusCode::OK,
            Json(json!({ "ok": false, "reason": "execution not found" })),
        );
    };
    if exec["status"] == "running" {
        exec["status"] = json!("stopped");
        exec["finished_at"] = json!(iso_now());
    }
    // W1.2 / MEF-GAP-008 — a 200 "stopped" over a discarded write leaves a durably-running exec and a
    // leaked concurrency slot. Fail closed.
    if persist_record(&st.data_dir, "automation-executions", &id, &exec).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "automation_execution_persistence_failed",
            "message": "the cancel did not commit — the execution stays running rather than being falsely reported stopped" }),
            ),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "status": exec["status"] })),
    )
}

// ============================ L. RUNNER PLACEMENT + METRICS + WARM POOLS ==========================

/// POST /v1/hypervisor/placement/resolve — score the real provider catalog against the request and
/// record the decision + REJECTED candidates with honest reasons (no silent drop).
pub(crate) async fn handle_placement_resolve(
    State(st): State<Arc<DaemonState>>,
    inbound: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let base = st.base_url.clone();
    let trust = body
        .get("trust")
        .and_then(|v| v.as_str())
        .unwrap_or("trusted"); // trusted | cross_tenant
    let residency = body
        .get("residency")
        .and_then(|v| v.as_str())
        .unwrap_or("any"); // any | local
    let class = body
        .get("class")
        .and_then(|v| v.as_str())
        .unwrap_or("local-workspace-v0");
    let project = body
        .get("project_id")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let recipe_ref = body
        .get("recipe_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let providers = call(&base, "GET", "/v1/hypervisor/providers", None, &inbound)
        .await
        .map_err(|e| {
            AppError(
                axum::http::StatusCode::BAD_GATEWAY,
                format!("providers: {e}"),
            )
        })?;
    let list = providers["providers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let recipe_cached = !recipe_ref.is_empty()
        && Path::new(&st.data_dir)
            .join("recipe-cache")
            .join(safe(recipe_ref))
            .exists();
    let warm = warm_pool_for(&st.data_dir, project, class).is_some();

    let mut eligible: Vec<Value> = Vec::new();
    let mut rejected: Vec<Value> = Vec::new();
    for p in &list {
        let pref = p["provider_ref"].as_str().unwrap_or("");
        let caps = &p["capabilities"];
        let status = p["status"].as_str().unwrap_or("");
        if status != "available" {
            rejected.push(json!({ "provider_ref": pref, "reason": format!("provider {status}") }));
            continue;
        }
        if trust == "cross_tenant" && caps["isolation"].as_str() != Some("vm_kernel") {
            rejected.push(json!({ "provider_ref": pref, "reason": "cross-tenant trust requires vm_kernel isolation; this runner is not a cross-tenant boundary" }));
            continue;
        }
        if residency == "local" && caps["locality"].as_str() == Some("cloud") {
            rejected.push(json!({ "provider_ref": pref, "reason": "violates local data residency (cloud locality)" }));
            continue;
        }
        // honest scoring: isolation strength + prebuild/warm availability.
        let mut score = 50i64;
        if caps["isolation"].as_str() == Some("vm_kernel") {
            score += 20;
        }
        if caps["restore"].as_bool() == Some(true) {
            score += 5;
        }
        if recipe_cached {
            score += 15;
        }
        if warm {
            score += 25;
        }
        if caps["locality"].as_str() == Some("local") {
            score += 10;
        }
        eligible.push(json!({ "provider_ref": pref, "score": score, "capabilities": caps }));
    }
    eligible.sort_by(|a, b| {
        b["score"]
            .as_i64()
            .unwrap_or(0)
            .cmp(&a["score"].as_i64().unwrap_or(0))
    });
    let chosen = eligible.first().cloned();
    let did = format!("plc_{:x}", nanos());
    let decision = json!({
        "schema_version": "ioi.hypervisor.placement-decision.v1",
        "decision_id": did, "request": { "trust": trust, "residency": residency, "class": class, "project_id": project, "recipe_ref": recipe_ref },
        "chosen": chosen, "eligible": eligible, "rejected": rejected,
        "prebuild_available": recipe_cached, "warm_pool_available": warm,
        "claim_kind": if warm { "warm_claim" } else if recipe_cached { "prebuild_hit" } else { "cold_start" },
        "at": iso_now()
    });
    // W1.2 / MEF-GAP-008 — placement metrics read placement-decisions back; a discarded write returns
    // a decision no reader will find. Fail closed via the AppError 500 lane.
    if persist_record(&st.data_dir, "placement-decisions", &did, &decision).is_err() {
        return Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "runner_placement_decision_persistence_failed: the placement decision did not commit"
                .to_string(),
        ));
    }
    if chosen.is_none() {
        return Ok(Json(
            json!({ "ok": false, "reason": "no eligible runner for the request (all candidates rejected with honest reasons)", "decision": decision }),
        ));
    }
    Ok(Json(json!({ "ok": true, "decision": decision })))
}

/// GET /v1/hypervisor/placement/metrics — cold-start / prebuild-hit / warm-claim / cache from real
/// env + placement truth (aggregated, not invented).
pub(crate) async fn handle_placement_metrics(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    // ENVIRONMENT_OWNER_CENSUS: aggregate_only — reads cache-hit booleans and emits counts; no
    // environment identifier, record, workspace coordinate, or workspace byte crosses the route.
    let envs = read_record_dir(&st.data_dir, "environments");
    let (mut cache_hit, mut cold_start) = (0u64, 0u64);
    for e in &envs {
        match e["status"]["cache_hit"].as_bool() {
            Some(true) => cache_hit += 1,
            Some(false) => cold_start += 1,
            None => {}
        }
    }
    let decisions = read_record_dir(&st.data_dir, "placement-decisions");
    let warm_claim = read_record_dir(&st.data_dir, "warm-claims").len() as u64;
    let prebuild_hit = decisions
        .iter()
        .filter(|d| d["claim_kind"] == "prebuild_hit")
        .count() as u64;
    Json(json!({
        "schema_version": "ioi.hypervisor.placement-metrics.v1",
        "placements": decisions.len(),
        "cold_start": cold_start, "prebuild_hit": prebuild_hit, "warm_claim": warm_claim, "cache_hit": cache_hit,
        "at": iso_now()
    }))
}

// ============================ M. PLACEMENT VENUES + FEE/RECEIPT PREVIEW ==========================
//
// The placement EXPERIENCE over the BYO provider plane: four venues — run_local ·
// use_my_infrastructure · pick_provider · hypervisor_choose — composed LIVE from ProviderAccount
// records, environment-class provider eligibility, and preflight posture. Fee bases are DECLARED
// COPY, never fee objects: this plane mints no fee, no quote, and no RoutingDecisionReceipt
// (economic canon: fees attach to orchestration and governance — never hidden provider markup;
// a routing fee becomes legitimate only when IOI itself places runs for payment). "Let Hypervisor
// choose" stays a PLANNED placeholder with an advisory-empty candidate list until the
// decentralized.cloud candidate plane exists — venue selection is never hidden behind auto.

const VENUE_POLICY_KIND: &str = "placement-venue-policy";
const VENUE_IDS: &[&str] = &[
    "run_local",
    "use_my_infrastructure",
    "pick_provider",
    "hypervisor_choose",
];
const CLOUD_KINDS: &[&str] = &[
    "aws",
    "gcp",
    "azure",
    "k8s",
    "vast",
    "runpod",
    "lambda_cloud",
    "akash",
];

/// Kind-level capability hints (GPU / storage / IP / snapshot) — labeled hints, never probed
/// claims. Per-provider semantics preserved; nothing flattened into a fake generic cloud.
fn venue_capability_hints(kind: &str) -> Value {
    let (gpu, storage, ip, snapshot) = match kind {
        "local" => (
            "host-dependent",
            "host disk",
            "loopback / local",
            "daemon snapshots + sha256 state roots (real)",
        ),
        "baremetal_ssh" => (
            "host-dependent (your node's hardware)",
            "node disk",
            "node endpoint (you own it)",
            "daemon-custody tar + admitted sha256 (real)",
        ),
        "aws" => (
            "EC2 instances — enterprise customer-cloud (guarded adapter)",
            "EBS root volumes (native ids evidence-only)",
            "VPC/security-group posture; public or Elastic IPs (evidence)",
            "daemon custody via the ssh lane; EBS snapshots evidence-only",
        ),
        "gcp" => (
            "Compute Engine machine types — enterprise customer-cloud (guarded adapter)",
            "Persistent Disk boot volumes (native ids evidence-only)",
            "VPC network/firewall posture; external or static IPs (evidence)",
            "daemon custody via the ssh lane; PD snapshots evidence-only",
        ),
        "azure" => (
            "Azure VM sizes — enterprise customer-cloud (guarded adapter)",
            "managed OS disks (native ids evidence-only)",
            "VNet/NSG posture; public or static IPs (evidence)",
            "daemon custody via the ssh lane; managed-disk snapshots evidence-only",
        ),
        "k8s" => (
            "GPU device-plugin scheduling per namespace quota (guarded adapter)",
            "PVCs per storage class — cluster posture, never restore truth",
            "ClusterIP/LoadBalancer/ingress per cluster posture (evidence)",
            "daemon custody from the workload fs; VolumeSnapshots evidence-only",
        ),
        "vast" => (
            "marketplace GPUs (adapter pending)",
            "container-scoped storage",
            "host-dependent, often shared",
            "daemon custody when the adapter lands",
        ),
        "runpod" => (
            "GPU runtime pods — secure (on-demand) + community (interruptible)",
            "container disk + network volumes",
            "proxy ssh / public ip when exposed",
            "daemon custody via the ssh lane",
        ),
        "lambda_cloud" => (
            "GPU VMs — ordinary Linux + ssh (Lambda-class)",
            "instance-lifetime persistent local NVMe",
            "public ip + ssh (user ubuntu)",
            "daemon custody via the ssh lane; native snapshots evidence-only",
        ),
        "akash" => (
            "DePIN deployment-lease GPUs — SDL → bids → lease (guarded adapter)",
            "deployment-scoped persistent storage (SDL posture — never restore truth)",
            "lease-assigned IP/ports (evidence, not authority)",
            "daemon custody via the SDL-declared ssh service; archive via the storage plane",
        ),
        _ => ("unknown", "unknown", "unknown", "unknown"),
    };
    json!({ "gpu": gpu, "persistent_storage": storage, "ip": ip, "snapshot": snapshot,
            "basis": "kind-level hints — not probed claims" })
}

/// The declared fee taxonomy. COPY ONLY — no fee objects exist on this plane.
fn fee_bases_taxonomy() -> Value {
    json!({
        "none": "No fee. Nothing is charged on this path.",
        "subscription_control_plane": "The control plane (governance, receipts, authority, estate surfaces) is covered by the subscription — not metered per run.",
        "adapter_orchestration_fee": "A visible flat fee attached to adapter orchestration operations — never a percentage of customer provider spend.",
        "routing_fee": "A visible fee for one-click routed placement, legitimate only with a challengeable RoutingDecisionReceipt (Routing Fee Covenant). Not charged today — no routing exists.",
        "managed_margin": "Margin on Hypervisor-managed execution where Hypervisor bears the provider bill. Not offered today.",
    })
}

/// Per-venue fee posture: {fee_basis, fee_explanation, fee_object_minted:false, cost_owner}.
pub(crate) fn venue_fee(venue: &str) -> Value {
    let (basis, explanation) = match venue {
        "run_local" => ("none", "No fee. Local execution is the conformance reference; the control plane is covered by your subscription (subscription_control_plane), not metered per run."),
        "use_my_infrastructure" => ("none", "No provider-spend percentage. Your nodes, your spend — Hypervisor records, governs, and receipts the work; it does not hide markup inside provider cost. When Hypervisor performs the provider lifecycle for you (provisioning, snapshot custody, restore, receipts), a visible adapter orchestration fee may apply in a future cut — never a percentage of your spend. Nothing is charged today."),
        "pick_provider" => ("adapter_orchestration_fee", "Provider spend stays customer-borne at cost on your own account. When a cloud adapter lands, a visible flat orchestration fee attaches to adapter operations — never a percentage of your provider spend. Nothing is charged today: cloud kinds are credential + preflight only."),
        "hypervisor_choose" => ("routing_fee", "When Hypervisor places runs for payment (decentralized.cloud), a visible routing fee applies with a challengeable RoutingDecisionReceipt; managed execution would carry a declared managed_margin. Neither exists today — this venue is a planned placeholder, and choosing it never hides the decision."),
        _ => ("none", "unknown venue"),
    };
    json!({ "fee_basis": basis, "fee_explanation": explanation, "fee_object_minted": false, "cost_owner": "customer" })
}

fn provider_card(account: &Value, venue: &str, classes: &[Value]) -> Value {
    let s = |k: &str| account.get(k).and_then(Value::as_str).unwrap_or("");
    let kind = s("kind");
    let preflight = account.get("preflight").cloned().unwrap_or(Value::Null);
    let reason = match s("status") {
        "verified" => "verified — preflight admitted".to_string(),
        "revoked" => "credential revoked — rebind to use this account".to_string(),
        _ if preflight.is_null() => "unverified — bind a credential and run preflight".to_string(),
        _ => format!(
            "unverified — preflight refused: {}",
            preflight
                .pointer("/evidence/reason")
                .and_then(Value::as_str)
                .unwrap_or("see preflight evidence")
        ),
    };
    let eligible_classes: Vec<&str> = classes
        .iter()
        .filter(|c| {
            c.pointer("/provider_eligibility/provider_kinds")
                .and_then(Value::as_array)
                .map(|ks| ks.iter().any(|k| k.as_str() == Some(kind)))
                .unwrap_or(false)
        })
        .filter_map(|c| c.get("id").and_then(Value::as_str))
        .collect();
    json!({
        "account_ref": s("account_ref"),
        "display_name": s("display_name"),
        "kind": kind,
        "connected": true,
        "status": s("status"),
        "reason": reason,
        "preflight_at": preflight.get("at").cloned().unwrap_or(Value::Null),
        "environment_classes": if eligible_classes.is_empty() { json!({ "supported": [], "note": "no runtime classes yet — classes land with this kind's adapter" }) } else { json!({ "supported": eligible_classes }) },
        "capability_hints": venue_capability_hints(kind),
        "cost_owner": "customer",
        "provider_spend_borne_by": "customer",
        "fee_basis": venue_fee(venue)["fee_basis"],
        "lifecycle": if kind == "baremetal_ssh" { "full (provider-ops lane)" } else { "credential_preflight_only — lifecycle ops fail closed with named reasons until the adapter cut" },
    })
}

/// Compose the four venue cards from live daemon truth (accounts + environment classes).
fn compose_venues(data_dir: &str, classes: &[Value]) -> Vec<Value> {
    let accounts = read_record_dir(data_dir, "provider-accounts");
    let ssh_accounts: Vec<&Value> = accounts
        .iter()
        .filter(|a| a["kind"].as_str() == Some("baremetal_ssh"))
        .collect();
    let cloud_accounts: Vec<&Value> = accounts
        .iter()
        .filter(|a| CLOUD_KINDS.contains(&a["kind"].as_str().unwrap_or("")))
        .collect();
    let class_ids_for = |kind: &str| -> Vec<String> {
        classes
            .iter()
            .filter(|c| {
                c.pointer("/provider_eligibility/provider_kinds")
                    .and_then(Value::as_array)
                    .map(|ks| ks.iter().any(|k| k.as_str() == Some(kind)))
                    .unwrap_or(false)
            })
            .filter_map(|c| c.get("id").and_then(Value::as_str).map(str::to_string))
            .collect()
    };
    let verified_ssh = ssh_accounts
        .iter()
        .any(|a| a["status"].as_str() == Some("verified"));

    let local = json!({
        "venue": "run_local", "display_name": "Run local",
        "summary": "This machine — the conformance reference. Sessions, microVMs, snapshots, and receipts all run under the local daemon.",
        "available": true, "selectable": true,
        "environment_classes": { "supported": class_ids_for("local") },
        "capability_hints": venue_capability_hints("local"),
        "fee": venue_fee("run_local"),
        "providers": [],
    });
    let byo = json!({
        "venue": "use_my_infrastructure", "display_name": "Use my infrastructure",
        "summary": "Your own bare-metal / homelab nodes over the baremetal_ssh provider adapter — full lifecycle with daemon-custody snapshots.",
        "available": verified_ssh, "selectable": true,
        "availability_note": if verified_ssh { Value::Null } else { json!("no verified baremetal_ssh account yet — create one, bind an ssh key, and preflight it") },
        "environment_classes": { "supported": class_ids_for("baremetal_ssh") },
        "capability_hints": venue_capability_hints("baremetal_ssh"),
        "fee": venue_fee("use_my_infrastructure"),
        "providers": ssh_accounts.iter().map(|a| provider_card(a, "use_my_infrastructure", classes)).collect::<Vec<_>>(),
    });
    // Pick a cloud: connected accounts as cards + a not-connected stub per remaining kind, so
    // the choice is visible even before any account exists (never hidden).
    let mut cloud_cards: Vec<Value> = cloud_accounts
        .iter()
        .map(|a| provider_card(a, "pick_provider", classes))
        .collect();
    for kind in CLOUD_KINDS {
        if !cloud_accounts
            .iter()
            .any(|a| a["kind"].as_str() == Some(*kind))
        {
            cloud_cards.push(json!({
                "kind": kind, "connected": false, "status": "not_connected",
                "reason": "no ProviderAccount for this kind yet",
                "connect_hint": "POST /v1/hypervisor/provider-accounts { kind, display_name, … } then bind a credential and preflight",
                "capability_hints": venue_capability_hints(kind),
                "cost_owner": "customer", "fee_basis": "adapter_orchestration_fee",
                "lifecycle": "credential_preflight_only — lifecycle ops fail closed with named reasons until the adapter cut",
            }));
        }
    }
    let cloud = json!({
        "venue": "pick_provider", "display_name": "Pick a cloud",
        "summary": "A specific provider account you own (AWS · GCP · K8s · Vast · Akash). Credential + preflight are real today; lifecycle lands per-adapter.",
        "available": !cloud_accounts.is_empty(), "selectable": true,
        "availability_note": if cloud_accounts.is_empty() { json!("no cloud provider account connected yet") } else { Value::Null },
        "quote": Value::Null,
        "quote_policy": "no invented quotes — provider quotes land with each adapter, as provider evidence",
        "environment_classes": { "supported": Vec::<String>::new(), "note": "cloud runtime classes land with each adapter" },
        "fee": venue_fee("pick_provider"),
        "providers": cloud_cards,
    });
    let choose = json!({
        "venue": "hypervisor_choose", "display_name": "Let Hypervisor choose",
        "summary": "Hypervisor recommends among your REAL venues from live, evidence-bound candidates (local facts only this cut). Advisory — a candidate is never authority, and routed-for-payment placement still does not exist.",
        "available": false, "selectable": true, "status": "advisory",
        "advisory_note": "candidates derive from the verified provider catalog, environment-class eligibility, preflight posture, and receipt history; external sources without adapters are candidate_source_unavailable — never fake prices. No routing fee, no RoutingDecisionReceipt.",
        "candidates": Vec::<Value>::new(),
        "fee": venue_fee("hypervisor_choose"),
        "providers": [],
    });
    vec![local, byo, cloud, choose]
}

/// Fold the live advisory into the hypervisor_choose venue card (candidates + availability).
pub(crate) fn attach_choose_advisory(venues: &mut [Value], advisory: &Value) {
    if let Some(card) = venues
        .iter_mut()
        .find(|v| v["venue"] == "hypervisor_choose")
    {
        let eligible = advisory
            .get("eligible")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        card["available"] = json!(eligible > 0);
        card["advisory_ref"] = advisory.get("advisory_ref").cloned().unwrap_or(Value::Null);
        card["candidates"] = advisory.get("candidates").cloned().unwrap_or(json!([]));
        card["recommendation"] = advisory
            .get("recommendation")
            .cloned()
            .unwrap_or(Value::Null);
        card["no_eligible_candidate"] = advisory
            .get("no_eligible_candidate")
            .cloned()
            .unwrap_or(Value::Null);
        card["routing_fee_basis"] = advisory
            .get("routing_fee_basis")
            .cloned()
            .unwrap_or(Value::Null);
        card["fee_object_minted"] = json!(false);
    }
}

pub(crate) async fn live_environment_classes(
    base: &str,
    inbound: &axum::http::HeaderMap,
) -> Vec<Value> {
    call(
        base,
        "GET",
        "/v1/hypervisor/environment-classes",
        None,
        inbound,
    )
    .await
    .ok()
    .and_then(|v| {
        v.get("environmentClasses")
            .and_then(Value::as_array)
            .cloned()
    })
    .unwrap_or_default()
}

/// GET /v1/hypervisor/placement/venues — the four venue cards, live-composed.
pub(crate) async fn handle_placement_venues(
    State(st): State<Arc<DaemonState>>,
    inbound: axum::http::HeaderMap,
) -> (StatusCode, Json<Value>) {
    let classes = live_environment_classes(&st.base_url, &inbound).await;
    let mut venues = compose_venues(&st.data_dir, &classes);
    let intent = super::decentralized_cloud_routes::ensure_default_intent(&st.data_dir);
    // W1.2 / MEF-GAP-008 — advisory_for refreshes candidates durably; surface a write failure rather
    // than composing venues over a silently-failed refresh.
    let advisory = match super::decentralized_cloud_routes::advisory_for(
        &st, &intent, false, &inbound,
    )
    .await
    {
        Ok(a) => a,
        Err((code, message)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "code": code, "message": message })),
            )
        }
    };
    attach_choose_advisory(&mut venues, &advisory);
    (
        StatusCode::OK,
        Json(json!({
            "schema_version": "ioi.hypervisor.placement-venues.v1",
            "venues": venues,
            "fee_bases": fee_bases_taxonomy(),
            "spend_rule": "BYO provider spend is customer-borne; the hypervisor records, governs, estimates, and reconciles — it does not hide markup inside provider cost",
            "no_fee_objects": "this plane mints no fee object, no quote, and no RoutingDecisionReceipt",
            "at": iso_now(),
        })),
    )
}

pub(crate) fn load_venue_policy(data_dir: &str) -> Value {
    read_record_dir(data_dir, VENUE_POLICY_KIND)
        .into_iter()
        .find(|r| r["policy_id"].as_str() == Some("current"))
        .unwrap_or_else(|| {
            json!({
                "schema_version": "ioi.hypervisor.placement-venue-policy.v1",
                "policy_id": "current", "venue": "run_local", "default": true,
                "note": "no venue chosen yet — local is the conformance default, not a hidden auto",
            })
        })
}

/// GET /v1/hypervisor/placement/venue-policy — the durable chosen venue.
pub(crate) async fn handle_venue_policy_get(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let policy = load_venue_policy(&st.data_dir);
    let fee = venue_fee(policy["venue"].as_str().unwrap_or("run_local"));
    Json(json!({ "ok": true, "policy": policy, "fee": fee, "at": iso_now() }))
}

/// PUT /v1/hypervisor/placement/venue-policy — choose a venue (durable, explicit, never hidden).
/// Venues needing a provider require a resolvable ProviderAccount of the right family;
/// hypervisor_choose is accepted as an ADVISORY placeholder (effective venue stays run_local).
pub(crate) async fn handle_venue_policy_put(
    State(st): State<Arc<DaemonState>>,
    inbound: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let venue = body.get("venue").and_then(Value::as_str).unwrap_or("");
    if !VENUE_IDS.contains(&venue) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                json!({ "ok": false, "error": { "code": "placement_venue_invalid", "message": format!("venue must be one of {VENUE_IDS:?}") } }),
            ),
        );
    }
    let account_ref = body
        .get("provider_account_ref")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut provider_snapshot = Value::Null;
    if venue == "use_my_infrastructure" || venue == "pick_provider" {
        let accounts = read_record_dir(&st.data_dir, "provider-accounts");
        let Some(account) = accounts.iter().find(|a| {
            a["account_ref"].as_str() == Some(account_ref)
                || a["account_id"].as_str() == Some(account_ref)
        }) else {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(
                    json!({ "ok": false, "error": { "code": "placement_provider_account_required", "message": "this venue pins a ProviderAccount — pass provider_account_ref for an existing account" } }),
                ),
            );
        };
        let kind = account["kind"].as_str().unwrap_or("");
        let family_ok = if venue == "use_my_infrastructure" {
            kind == "baremetal_ssh"
        } else {
            CLOUD_KINDS.contains(&kind)
        };
        if !family_ok {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(
                    json!({ "ok": false, "error": { "code": "placement_provider_kind_mismatch", "message": format!("'{kind}' accounts do not belong to venue '{venue}'") } }),
                ),
            );
        }
        // Snapshot posture at choice time — the preview re-reads LIVE state, this is provenance.
        provider_snapshot = json!({
            "account_ref": account["account_ref"], "display_name": account["display_name"],
            "kind": kind, "status_at_choice": account["status"],
        });
    }
    let advisory = venue == "hypervisor_choose";
    let mut advisory_block = Value::Null;
    if advisory {
        let intent = super::decentralized_cloud_routes::ensure_default_intent(&st.data_dir);
        advisory_block =
            match super::decentralized_cloud_routes::advisory_for(&st, &intent, true, &inbound)
                .await
            {
                Ok(a) => a,
                Err((code, message)) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "ok": false, "code": code, "message": message })),
                    )
                }
            };
    }
    let prior = load_venue_policy(&st.data_dir);
    let mut history = prior
        .get("history")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if prior.get("default").and_then(Value::as_bool) != Some(true) {
        history.push(json!({ "venue": prior["venue"], "provider_account_ref": prior["provider_account_ref"], "chosen_at": prior["chosen_at"] }));
    }
    let record = json!({
        "schema_version": "ioi.hypervisor.placement-venue-policy.v1",
        "policy_id": "current",
        "venue": venue,
        "provider_account_ref": if account_ref.is_empty() { Value::Null } else { json!(account_ref) },
        "provider_snapshot": provider_snapshot,
        "advisory": advisory,
        "effective_venue": if advisory {
            advisory_block.get("effective_venue").cloned().unwrap_or(json!("run_local"))
        } else { json!(venue) },
        "advisory_ref": if advisory { advisory_block.get("advisory_ref").cloned().unwrap_or(Value::Null) } else { Value::Null },
        "advisory_recommendation": if advisory { advisory_block.get("recommendation").cloned().unwrap_or(Value::Null) } else { Value::Null },
        "advisory_candidate_refs": if advisory { advisory_block.get("candidate_refs").cloned().unwrap_or(json!([])) } else { json!([]) },
        "no_eligible_candidate": if advisory { advisory_block.get("no_eligible_candidate").cloned().unwrap_or(Value::Null) } else { Value::Null },
        "advisory_note": if advisory { json!("advisory recommendation from live, evidence-bound candidates (never a hidden auto); a candidate is not authority and cannot provision — execution keeps requiring wallet grants") } else { Value::Null },
        "chosen_at": iso_now(),
        "history": history,
    });
    // W1.2 / MEF-GAP-008 — CRITICAL governing-policy honesty: the venue policy is read back as the
    // durable chosen venue; a discarded write leaves the prior policy in force while reporting the new one.
    if persist_record(&st.data_dir, VENUE_POLICY_KIND, "current", &record).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "placement_venue_policy_persistence_failed",
            "message": "the venue policy did not commit — the prior policy stays in force rather than being falsely reported changed" }),
            ),
        );
    }
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "policy": record, "fee": venue_fee(venue), "advisory": advisory_block }),
        ),
    )
}

/// The receipt kinds a launch/lifecycle at this venue will mint — NAMED BEFORE LAUNCH.
pub(crate) fn venue_receipts_expected(venue: &str, data_dir: &str) -> Value {
    let base = vec![
        json!("receipt://hypervisor/session-provision/* — session create"),
        json!("agentgres://harness-profile-receipt/* — harness binding admission"),
        json!("work-ledger entries with tamper-evident state roots"),
    ];
    let provider_set = vec![
        json!("agentgres://provider-receipt/prc_* — one per provider lifecycle op, success AND failure"),
        json!("ioi.hypervisor.provider-operation.v1 (pop_*) — the admitted-operation record"),
        json!("capability-lease descriptor persisted (never carries a secret) + wallet grant_ref"),
        json!("ioi.hypervisor.placement-decision.v1 (plc_*) when placement resolve is consulted"),
    ];
    match venue {
        "use_my_infrastructure" => {
            let mut r = base;
            r.extend(provider_set);
            r.push(json!(
                "budget discovery note (local_free — customer-borne, no metered spend)"
            ));
            json!(r)
        }
        "pick_provider" => {
            let mut r = base;
            r.extend(provider_set);
            let has_budget = read_record_dir(data_dir, "resource-budgets")
                .iter()
                .any(|b| b["scope"].as_str() == Some("external_spend"));
            r.push(json!("external_spend budget discovery BEFORE any mutation (409 budget_blocked without headroom)"));
            if !has_budget {
                r.push(json!("⚠ no external_spend budget exists yet — metered mutations will be budget_blocked until one is created"));
            }
            r.push(json!("honesty: cloud lifecycle ops fail closed with PROVIDER_KIND_LIFECYCLE_NOT_IMPLEMENTED until this kind's adapter cut"));
            json!(r)
        }
        "hypervisor_choose" => {
            let mut r = base;
            r.push(json!("placement-advisory://adv_* — the advisory that recommended this placement (persisted evidence)"));
            r.push(json!("cloud-resource-candidate://crc_* — the evidence-bound candidates considered (expiring; never authority)"));
            r.push(json!("a RoutingDecisionReceipt exists only when routed-for-payment placement exists (none today; fee_object_minted stays false)"));
            json!(r)
        }
        _ => json!(base),
    }
}

/// GET /v1/hypervisor/placement/preview[?venue=&provider_account_ref=] — the pre-launch
/// placement preview: venue card, pinned provider posture, fee copy, and the receipts a run
/// will mint — NAMED BEFORE LAUNCH. Uses the stored policy unless overridden by query params.
pub(crate) async fn handle_placement_preview(
    State(st): State<Arc<DaemonState>>,
    inbound: axum::http::HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let policy = load_venue_policy(&st.data_dir);
    let venue = q
        .get("venue")
        .map(String::as_str)
        .filter(|v| VENUE_IDS.contains(v))
        .unwrap_or_else(|| policy["venue"].as_str().unwrap_or("run_local"))
        .to_string();
    let account_ref = q
        .get("provider_account_ref")
        .cloned()
        .or_else(|| {
            policy
                .get("provider_account_ref")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    let classes = live_environment_classes(&st.base_url, &inbound).await;
    let venues = compose_venues(&st.data_dir, &classes);
    let venue_card = venues
        .iter()
        .find(|v| v["venue"].as_str() == Some(venue.as_str()))
        .cloned()
        .unwrap_or(Value::Null);
    let provider_card = venue_card
        .get("providers")
        .and_then(Value::as_array)
        .and_then(|ps| {
            ps.iter()
                .find(|p| p["account_ref"].as_str() == Some(account_ref.as_str()))
                .cloned()
        });
    // W1.2 / MEF-GAP-008 — advisory_for refreshes candidates durably; surface a write failure rather
    // than previewing over a silently-failed refresh.
    let advisory = if venue == "hypervisor_choose" {
        let intent = super::decentralized_cloud_routes::ensure_default_intent(&st.data_dir);
        match super::decentralized_cloud_routes::advisory_for(&st, &intent, false, &inbound).await {
            Ok(a) => a,
            Err((code, message)) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "ok": false, "code": code, "message": message })),
                )
            }
        }
    } else {
        Value::Null
    };
    (
        StatusCode::OK,
        Json(json!({
            "schema_version": "ioi.hypervisor.placement-preview.v1",
            "policy": policy,
            "venue": venue,
            "venue_card": venue_card,
            "provider_card": provider_card,
            "advisory": advisory,
            "fee": venue_fee(&venue),
            "receipts_expected": venue_receipts_expected(&venue, &st.data_dir),
            "quote": Value::Null,
            "quote_policy": "no invented quotes — provider quotes land with each adapter, as provider evidence",
            "at": iso_now(),
        })),
    )
}

fn warm_pool_for(data_dir: &str, project: &str, class: &str) -> Option<Value> {
    read_record_dir(data_dir, "warm-pools")
        .into_iter()
        .find(|p| {
            p["project_id"].as_str() == Some(project)
                && p["class"].as_str() == Some(class)
                && p["ready"]
                    .as_array()
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
        })
}

/// POST /v1/hypervisor/warm-pools — declare a warm pool and PRE-START `size` envs (real).
pub(crate) async fn handle_warm_pool_create(
    State(st): State<Arc<DaemonState>>,
    inbound: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let base = st.base_url.clone();
    let project = body
        .get("project_id")
        .and_then(|v| v.as_str())
        .unwrap_or("default")
        .to_string();
    let class = body
        .get("class")
        .and_then(|v| v.as_str())
        .unwrap_or("local-workspace-v0")
        .to_string();
    let size = body
        .get("size")
        .and_then(|v| v.as_u64())
        .unwrap_or(2)
        .min(5);
    let id = format!("wp_{:x}", nanos());
    let mut ready: Vec<String> = Vec::new();
    for _ in 0..size {
        let spec = json!({ "spec": { "environment_class_id": class, "project_id": project } });
        if let Ok(c) = call(
            &base,
            "POST",
            "/v1/hypervisor/environments",
            Some(spec),
            &inbound,
        )
        .await
        {
            if let Some(eid) = c["environment"]["id"].as_str() {
                let _ = call(
                    &base,
                    "POST",
                    &format!("/v1/hypervisor/environments/{eid}/start"),
                    None,
                    &inbound,
                )
                .await;
                ready.push(eid.to_string());
            }
        }
    }
    let pool = json!({
        "schema_version": "ioi.hypervisor.warm-pool.v1",
        "warm_pool_id": id, "project_id": project, "class": class, "size": size,
        "ready": ready, "claimed": [], "created_at": iso_now()
    });
    // W1.2 / MEF-GAP-008 — the envs at `ready` are already created + started; a discarded pool write
    // orphans them. Fail closed and list the started env ids so they are not lost silently.
    if persist_record(&st.data_dir, "warm-pools", &id, &pool).is_err() {
        return Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("warm_pool_persistence_failed: the warm pool did not commit — these already-started environments are orphaned and need teardown: {}", json!(ready)),
        ));
    }
    Ok(Json(json!({ "ok": true, "warm_pool": pool })))
}

pub(crate) async fn handle_warm_pool_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "ok": true, "warm_pools": read_record_dir(&st.data_dir, "warm-pools") }))
}

/// POST /v1/hypervisor/warm-pools/:id/claim — claim a pre-started env (warm-claim metric).
pub(crate) async fn handle_warm_pool_claim(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(mut pool) = load(&st.data_dir, "warm-pools", &id) else {
        return (
            StatusCode::OK,
            Json(json!({ "ok": false, "reason": "warm pool not found" })),
        );
    };
    let mut ready = pool["ready"].as_array().cloned().unwrap_or_default();
    if ready.is_empty() {
        return (
            StatusCode::OK,
            Json(
                json!({ "ok": false, "reason": "warm pool exhausted (no pre-started env to claim)", "fail_closed": true }),
            ),
        );
    }
    let claimed_env = ready.remove(0);
    pool["ready"] = json!(ready);
    if let Some(c) = pool["claimed"].as_array_mut() {
        c.push(claimed_env.clone());
    }
    // W1.2 / MEF-GAP-008 — CRITICAL: persist the pool transition BEFORE minting the claim; a discarded
    // pool write would let a second caller double-claim the same env. On failure do NOT return the
    // environment_id.
    if persist_record(&st.data_dir, "warm-pools", &id, &pool).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "code": "warm_pool_persistence_failed",
            "message": "the pool claim transition did not commit — no environment was claimed (avoids a double-claim of the same env)" })),
        );
    }
    let cid = format!("wc_{:x}", nanos());
    // CLASSIFIED — best-effort telemetry: only the metrics counter reads warm-claims; the pool write
    // above is the authoritative transition.
    let _ = persist_record(
        &st.data_dir,
        "warm-claims",
        &cid,
        &json!({ "claim_id": cid, "warm_pool_id": id, "environment_id": claimed_env, "at": iso_now() }),
    );
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "environment_id": claimed_env, "claim_kind": "warm_claim", "remaining": pool["ready"].as_array().map(|a| a.len()).unwrap_or(0) }),
        ),
    )
}

#[cfg(test)]
mod webhook_rotation_durability_tests {
    use super::*;

    // Every fault below is DETERMINISTIC, UID-INDEPENDENT and PROCESS-LOCAL. No chmod: root
    // bypasses mode-bit denial, so a permission fault would pass vacuously when the suite runs as
    // root. No env var and no cwd change, so nothing here can race the rest of the suite.
    // `persist_record_durable`'s RenamedDurabilityUnconfirmed lane is deliberately NOT exercised
    // here — its only injection point is a process-global env var owned by durable_fs, whose own
    // tests already cover it. This module covers the two NotCommitted outcomes and the success lane.
    //
    // "automations" is in neither PROMOTED_DOMAINS nor REQUIRED_ADMISSION_DOMAINS, so the write
    // takes the daemon-file path: it can refuse at the id guard, at create_dir_all, at the temp
    // sibling, or at the rename. A promoted family would admit through the substrate engine and
    // its failure points would differ.

    const ID: &str = "aut_rotation";
    /// Loadable but NOT durably writable: `load` normalizes `@` to `_` and reads
    /// `aut_rotation.json`, while `persist_record_durable` REFUSES the id outright — before it
    /// opens anything — because normalizing it would let two distinct ids collide on one file.
    /// That gives a persist failure whose prior record is provably, byte-for-byte untouched, which
    /// no path shadow can do here: any shadow that breaks the write also breaks the read of the
    /// same filename-keyed record.
    const UNWRITABLE_ID: &str = "aut@rotation";
    const OLD_TOKEN: &str = "whk_the_previously_issued_token";
    const NEW_TOKEN: &str = "whk_the_candidate_token_under_test";

    fn prior_automation() -> Value {
        json!({
            "id": ID, "project_id": "prj_1", "name": "nightly",
            "trigger_kind": "webhook", "enabled": true,
            "webhook_token_hash": sha256_hex_str(OLD_TOKEN),
            "webhook_url": format!("/v1/hypervisor/automations/{ID}/webhook"),
        })
    }

    fn seed(data_dir: &str, id: &str, record: &Value) {
        super::super::durable_fs::persist_record_durable(data_dir, "automations", id, record)
            .unwrap();
    }

    /// Does `presented` open the trigger, judged the way `handle_automation_webhook` judges it —
    /// `sha256(presented)` against the DURABLE `webhook_token_hash`, never against the response.
    fn token_opens_trigger(data_dir: &str, id: &str, presented: &str) -> bool {
        load(data_dir, "automations", id)
            .and_then(|a| {
                a.get("webhook_token_hash")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .is_some_and(|want| !want.is_empty() && sha256_hex_str(presented) == want)
    }

    /// Is the candidate token durable ANYWHERE in the family? The defect being closed is a
    /// plaintext token that authenticates nowhere, so "no record carries its hash" is the fact.
    fn candidate_hash_is_durable_anywhere(data_dir: &str) -> bool {
        let candidate = sha256_hex_str(NEW_TOKEN);
        read_record_dir(data_dir, "automations").iter().any(|r| {
            r.get("webhook_token_hash").and_then(|v| v.as_str()) == Some(candidate.as_str())
        })
    }

    /// THE 500 LANE — the refusal that may truthfully claim continuity, because the prior record
    /// is verified still present and still carrying the hash this request read.
    #[test]
    fn a_refused_rotation_that_left_the_record_intact_keeps_the_prior_token_current() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        seed(data_dir, ID, &prior_automation());
        // Readable at the point the adapter loads it, under the id the adapter was called with.
        let loaded = load(data_dir, "automations", UNWRITABLE_ID).expect("readable");
        assert_eq!(
            loaded["webhook_token_hash"],
            json!(sha256_hex_str(OLD_TOKEN))
        );

        let (status, body) =
            record_rotated_webhook_token(data_dir, UNWRITABLE_ID, loaded, NEW_TOKEN);

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["ok"], json!(false));
        assert_eq!(
            body["error"]["code"],
            json!("automation_webhook_rotation_persistence_failed")
        );
        // The whole defect in one assertion: no plaintext leaves a refused rotation.
        assert!(
            body.get("webhook_token").is_none(),
            "a refused rotation must not return a token, got {body}"
        );
        // The continuity claim the 500 message makes is TRUE and verified, not assumed:
        assert!(token_opens_trigger(data_dir, UNWRITABLE_ID, OLD_TOKEN));
        // ...and the candidate opens nothing, anywhere.
        assert!(!token_opens_trigger(data_dir, UNWRITABLE_ID, NEW_TOKEN));
        assert!(!candidate_hash_is_durable_anywhere(data_dir));
    }

    /// THE 503 LANE — the same `NotCommitted` failure, but the durable state can no longer be
    /// confirmed to match what the request read, so continuity is NOT claimed. Here the rename
    /// target is shadowed by a directory: the temp sibling is written and fsynced, the rename
    /// fails, and the record is then unreadable — which is exactly the "unknown, not unchanged"
    /// case a concurrent rotation would also produce.
    #[test]
    fn a_refused_rotation_over_an_unreadable_record_refuses_to_claim_either_token() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        let family = directory.path().join("automations");
        std::fs::create_dir_all(&family).unwrap();
        // A SIBLING automation the refusal must not touch.
        seed(
            data_dir,
            "aut_sibling",
            &json!({ "id": "aut_sibling", "webhook_token_hash": sha256_hex_str("whk_sibling") }),
        );
        seed(data_dir, ID, &prior_automation());
        let loaded = load(data_dir, "automations", ID).expect("readable");
        std::fs::remove_file(family.join(format!("{ID}.json"))).unwrap();
        std::fs::create_dir_all(family.join(format!("{ID}.json"))).unwrap();

        let (status, body) = record_rotated_webhook_token(data_dir, ID, loaded, NEW_TOKEN);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["ok"], json!(false));
        assert_eq!(
            body["error"]["code"],
            json!("automation_webhook_rotation_state_ambiguous")
        );
        assert!(body.get("webhook_token").is_none());
        // No token was issued and none became durable — the ambiguity is about WHICH token is
        // current, never about the candidate having leaked into the durable record.
        assert!(!candidate_hash_is_durable_anywhere(data_dir));
        // The refusal is confined to the record it targeted.
        assert!(token_opens_trigger(data_dir, "aut_sibling", "whk_sibling"));
    }

    /// A second, distinct syscall reaching the same honest refusal: a regular FILE where the family
    /// directory belongs fails `create_dir_all`, so no temp sibling is ever created. Nothing is
    /// readable afterwards, so this is the ambiguous lane too — the handler cannot confirm
    /// continuity it cannot read.
    #[test]
    fn a_family_directory_shadowed_by_a_file_refuses_and_records_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        std::fs::write(directory.path().join("automations"), b"not a directory").unwrap();

        let (status, body) =
            record_rotated_webhook_token(data_dir, ID, prior_automation(), NEW_TOKEN);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body["error"]["code"],
            json!("automation_webhook_rotation_state_ambiguous")
        );
        assert!(body.get("webhook_token").is_none());
        assert!(load(data_dir, "automations", ID).is_none());
        assert!(!token_opens_trigger(data_dir, ID, NEW_TOKEN));
    }

    /// THE SUCCESS LANE — plaintext exactly once, and only after the new hash reads back as current.
    #[test]
    fn a_durable_rotation_is_acknowledged_from_the_reloaded_record() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        seed(data_dir, ID, &prior_automation());
        assert!(token_opens_trigger(data_dir, ID, OLD_TOKEN));

        let (status, body) = record_rotated_webhook_token(
            data_dir,
            ID,
            load(data_dir, "automations", ID).unwrap(),
            NEW_TOKEN,
        );

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], json!(true));
        assert_eq!(body["webhook_token"], json!(NEW_TOKEN));
        // Projected from the RELOADED record, never from the in-memory candidate.
        assert_eq!(
            body["webhook_url"],
            json!(format!("/v1/hypervisor/automations/{ID}/webhook"))
        );
        // The returned token opens the trigger, judged exactly as the webhook route judges it.
        assert!(token_opens_trigger(data_dir, ID, NEW_TOKEN));
        // Rotation means REPLACEMENT: the superseded token stops opening the trigger.
        assert!(!token_opens_trigger(data_dir, ID, OLD_TOKEN));
    }

    #[test]
    fn rotation_does_not_clobber_an_existing_time_trigger() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        let mut scheduled = prior_automation();
        scheduled["trigger_kind"] = json!("time");

        let (status, _) = record_rotated_webhook_token(data_dir, ID, scheduled, NEW_TOKEN);

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            load(data_dir, "automations", ID).unwrap()["trigger_kind"],
            json!("time")
        );
        assert!(token_opens_trigger(data_dir, ID, NEW_TOKEN));
    }
}
