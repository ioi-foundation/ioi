//! GoalRun plane — daemon-owned multi-harness orchestration (first cut).
//!
//! Moves the estate from "interchangeable harnesses can each execute" to "the daemon can
//! orchestrate multiple harnesses in ONE governed GoalRun" under the canonical ladder:
//! GoalRun → GoalGroundingLoop → RoleTopology → ContextCell → ContextLease →
//! ContextHandoff/TaskBriefPayload → HarnessInvocation → HarnessAdapterEvent →
//! ImplementationResultPayload → VerifierPath → reconciliation.
//!
//! First orchestration policy: `parallel_implement_reconcile` — conductor (native worker,
//! deterministic), two implementer cells (OpenCode + DeepSeek TUI adapter drivers) running the
//! SAME typed TaskBriefPayload in ISOLATED candidate session workspaces, then a conductor-run
//! deterministic VerifierPath and an admitted reconciliation that alone may copy candidate
//! artifacts into the target session workspace.
//!
//! Boundaries this plane enforces (never relaxed here):
//!   - the kernel planner (`runtime_goal_run_admission`) admits creation, role topology, every
//!     invocation, and the reconciliation — pure fail-closed checks over live registry facts;
//!   - `start` is wallet-gated exactly like session execute (403 challenge → grant), and the
//!     capability lease ref is recorded on every invocation receipt;
//!   - implementers NEVER write the target workspace — each writes its own candidate session
//!     workspace; only an admitted reconciliation copies selected files across;
//!   - raw prompts are not durable orchestration truth: the durable contract is the typed task
//!     brief; the rendered harness input is adapter-private;
//!   - a failed/ineligible implementer becomes an EXPLICIT partial result with a blocker record,
//!     never a silent skip;
//!   - every invocation and the reconciliation post agent-run transcripts (tamper-evident
//!     state_root) and mint receipts, so Run Timeline / Work Ledger carry the proof.

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use ioi_services::agentic::runtime::kernel::RuntimeKernelService;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::lifecycle_routes::{
    execute_authority_gate, load_session_record, resolve_adapter_driver, run_host_spawn_lane,
};
use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};
use std::sync::Mutex;

const GOAL_RUN_KIND: &str = "goal-runs";

/// GoalRun record mutation lock (#72 review round 2). LOCK ORDERING (fixed, documented):
/// ROOM_MUTATION_LOCK — when held — is always acquired BEFORE this lock; no .await ever executes
/// under it (update_goal_run_guarded's predicate and closure are synchronous).
pub(crate) static GOAL_RUN_MUTATION_LOCK: Mutex<()> = Mutex::new(());

/// ATOMIC file replacement for the mutable goal-run record: tmp sibling (no .json extension —
/// invisible to read_record_dir) + rename; both failure paths clean the temp file.
fn persist_goal_run_atomic(data_dir: &str, goal_run_id: &str, record: &Value) -> std::io::Result<()> {
    // Parity with persist_record (#72 review round 3): a promoted family has exactly one write
    // path (the substrate engine), and a not-yet-promoted family still feeds the opt-in
    // dual-write soak — atomic replacement must not silently drop either cross-cutting hook.
    if super::substrate_store::is_promoted(GOAL_RUN_KIND) {
        return super::substrate_store::persist_promoted(data_dir, GOAL_RUN_KIND, goal_run_id, record);
    }
    let dir = std::path::Path::new(data_dir).join(GOAL_RUN_KIND);
    std::fs::create_dir_all(&dir)?;
    let safe: String = goal_run_id.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_");
    let tmp = dir.join(format!(".{safe}.tmp-{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)));
    if let Err(e) = std::fs::write(&tmp, serde_json::to_vec_pretty(record).unwrap_or_default()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, dir.join(format!("{safe}.json"))) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    super::substrate_store::dual_write(data_dir, GOAL_RUN_KIND, goal_run_id, record);
    Ok(())
}

/// A typed seam refusal: (code, message). Codes are wire-facing.
pub(crate) type SeamErr = (String, String);

/// THE SHARED GoalRun MUTATION/CAS SEAM (#72 review rounds 2 + 3): every GoalRun-record writer —
/// lifecycle `start`/`reconcile` here, the room plane's reciprocal membership stamp — re-reads
/// the LATEST record under GOAL_RUN_MUTATION_LOCK, evaluates the caller's `expect` predicate
/// against that FRESH record (this is the CAS: state prechecks and operation-token comparisons
/// happen atomically with the write, never against a stale snapshot), then merges ONLY the
/// fields the caller owns and persists via atomic replacement. Outcomes are TYPED and distinct —
/// `goal_run_not_found`, the predicate's own refusal, `goal_run_persist_failed` — because a
/// caller that reports success without an `Ok` from this seam is fail-open (round 3 finding 1).
pub(crate) fn update_goal_run_guarded(
    data_dir: &str,
    goal_run_id: &str,
    expect: impl FnOnce(&Value) -> Result<(), SeamErr>,
    mutate: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> Result<Value, SeamErr> {
    let _guard = GOAL_RUN_MUTATION_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let Some(mut fresh) = read_record_dir(data_dir, GOAL_RUN_KIND)
        .into_iter()
        .find(|r| r.get("goal_run_id").and_then(Value::as_str) == Some(goal_run_id))
    else {
        return Err((
            "goal_run_not_found".to_string(),
            format!("no durable GoalRun record '{goal_run_id}'"),
        ));
    };
    expect(&fresh)?;
    if let Some(obj) = fresh.as_object_mut() {
        mutate(obj);
    }
    if let Err(e) = persist_goal_run_atomic(data_dir, goal_run_id, &fresh) {
        return Err((
            "goal_run_persist_failed".to_string(),
            format!("the GoalRun record write did not commit ({e}) — the durable record is unchanged"),
        ));
    }
    Ok(fresh)
}

/// Release a lifecycle operation reservation (token-guarded): restore `status`, drop
/// `lifecycle_op`. Every post-reservation refusal/rollback path releases through here so a
/// refused request leaves the run exactly re-runnable. A token mismatch means this request no
/// longer owns the run — it must not touch it.
pub(crate) fn release_lifecycle_reservation(
    data_dir: &str,
    goal_run_id: &str,
    token: &str,
    restore_status: &str,
) -> Result<(), SeamErr> {
    update_goal_run_guarded(
        data_dir,
        goal_run_id,
        |fresh| {
            if fresh.pointer("/lifecycle_op/token").and_then(Value::as_str) != Some(token) {
                return Err((
                    "goal_run_operation_conflict".to_string(),
                    "lifecycle reservation token mismatch — another operation owns this run".to_string(),
                ));
            }
            Ok(())
        },
        |obj| {
            obj.insert("status".into(), json!(restore_status));
            obj.remove("lifecycle_op");
        },
    )
    .map(|_| ())
}

/// HTTP status for a seam/lifecycle refusal code — persistence and rollback lanes are 5xx
/// (infrastructure truth), a missing run is 404, every state/token refusal is a 409 conflict.
fn seam_status(code: &str) -> StatusCode {
    match code {
        "goal_run_not_found" => StatusCode::NOT_FOUND,
        "goal_run_persist_failed" | "goal_run_finalize_failed" | "goal_run_rollback_failed"
        | "goal_run_release_failed" => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::CONFLICT,
    }
}

/// PRE-EFFECT reconcile rollback lane (#72 rounds 3 + 4): valid ONLY while the target workspace
/// is untouched (before the output-commit step) — remove the listed partial records (checked),
/// release the reservation back to `active`, and refuse typed. On success the durable state is
/// EXACTLY as before this request — target workspace included — so the reconcile is retryable.
/// Once output MAY have reached the target, `reconcile_preserve_abort` applies instead: nothing
/// is deleted there. Any incomplete step escalates to `goal_run_rollback_failed` with the
/// surviving pieces named for manual repair.
fn reconcile_abort(
    data_dir: &str,
    goal_run_id: &str,
    token: &str,
    code: &str,
    detail: &str,
    cleanup: &[(&str, &str)],
) -> (StatusCode, Json<Value>) {
    let mut failures: Vec<String> = Vec::new();
    for (family, record_id) in cleanup {
        if !remove_record(data_dir, family, record_id) {
            failures.push(format!("{family}/{record_id}"));
        }
    }
    if let Err((rcode, rmsg)) = release_lifecycle_reservation(data_dir, goal_run_id, token, "active") {
        failures.push(format!("reservation release ({rcode}: {rmsg})"));
    }
    if failures.is_empty() {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            code,
            &format!("{detail}; every partial record was rolled back and the reservation released — the run remains `active` and reconcile may be retried (nothing partial persists)"),
        )
    } else {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_rollback_failed",
            &format!("{detail} AND rollback was incomplete ({}) — manual repair required", failures.join(", ")),
        )
    }
}

/// POST-EFFECT reconcile abort (#72 round 4 finding 1): once the pre-output receipt exists and
/// the output commit MAY have begun, NOTHING is deleted — deleting the receipt would orphan the
/// output and every artifact (transcript, journal) that references it. Instead the operation
/// record is UPDATED (checked) to a recovery status carrying the commit journal, the
/// reservation is released so the idempotent reconcile can be retried, and the refusal names
/// the preserved evidence. Incomplete bookkeeping escalates to manual repair — still deleting
/// nothing.
fn reconcile_preserve_abort(
    data_dir: &str,
    goal_run_id: &str,
    token: &str,
    reconciliation_id: &str,
    preserved_record: &Value,
    code: &str,
    detail: &str,
) -> (StatusCode, Json<Value>) {
    let mut failures: Vec<String> = Vec::new();
    let mut preserved = preserved_record.clone();
    if let Some(obj) = preserved.as_object_mut() {
        obj.insert(
            "recovery".into(),
            json!({ "code": code, "detail": detail, "at": iso_now() }),
        );
    }
    if let Err(e) = persist_record(data_dir, RECONCILIATION_KIND, reconciliation_id, &preserved) {
        failures.push(format!("operation-record update ({RECONCILIATION_KIND}/{reconciliation_id}: {e})"));
    }
    if let Err((rcode, rmsg)) = release_lifecycle_reservation(data_dir, goal_run_id, token, "active") {
        failures.push(format!("reservation release ({rcode}: {rmsg})"));
    }
    let status = preserved_record.get("status").and_then(Value::as_str).unwrap_or("recovery_required");
    if failures.is_empty() {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            code,
            &format!("{detail}; the pre-output receipt and the operation record (status `{status}`, commit journal included) are PRESERVED as evidence — nothing was deleted; the reservation was released and the idempotent reconcile may be retried"),
        )
    } else {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_rollback_failed",
            &format!("{detail} AND the recovery bookkeeping was incomplete ({}) — the receipt and any persisted evidence are preserved; manual repair required", failures.join(", ")),
        )
    }
}
const INVOCATION_KIND: &str = "goal-run-invocations";
const VERIFICATION_KIND: &str = "goal-run-verifications";
const RECONCILIATION_KIND: &str = "goal-run-reconciliations";
/// Plane-owned staging area for reconcile output commits (#72 round 4): candidate outputs are
/// staged here BEFORE the pre-output receipt, so every refusal up to the commit step leaves the
/// target workspace untouched — literally, not rhetorically.
const STAGING_KIND: &str = "goal-run-reconcile-staging";

const GOAL_RUN_SCHEMA_VERSION: &str = "ioi.hypervisor.goal-run.v1";
const INVOCATION_SCHEMA_VERSION: &str = "ioi.hypervisor.goal-run-invocation.v1";
const RECONCILIATION_SCHEMA_VERSION: &str = "ioi.hypervisor.goal-run-reconciliation.v1";

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn safe(seg: &str) -> String {
    seg.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
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

pub(crate) fn load_goal_run(st: &DaemonState, goal_run_id: &str) -> Option<Value> {
    load(st, GOAL_RUN_KIND, goal_run_id)
}

fn load(st: &DaemonState, kind: &str, goal_run_id: &str) -> Option<Value> {
    read_record_dir(&st.data_dir, kind)
        .into_iter()
        .find(|record| record.get("goal_run_id").and_then(Value::as_str) == Some(goal_run_id))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

async fn self_get(url: &str) -> Option<Value> {
    reqwest::Client::new()
        .get(url)
        .timeout(Duration::from_millis(8000))
        .send()
        .await
        .ok()?
        .json::<Value>()
        .await
        .ok()
}

async fn self_post(url: &str, body: &Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(url)
        .json(body)
        .timeout(Duration::from_millis(20000))
        .send()
        .await;
    match response {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let value = resp.json::<Value>().await.unwrap_or(Value::Null);
            (status, value)
        }
        Err(err) => (0, json!({ "error": err.to_string() })),
    }
}

/// Live harness fact for the kernel planner — from the registry's own live probe projection.
pub(crate) fn fact_from_profile(profile: &Value, route_ref: &str, route_state: &str) -> Value {
    json!({
        "profile_ref": text(profile, "profile_ref"),
        "harness": text(profile, "harness"),
        "lifecycle_status": profile.pointer("/lifecycle/status").and_then(Value::as_str).unwrap_or(""),
        "execution_wiring": profile.pointer("/adapter/execution_wiring").and_then(Value::as_str).unwrap_or(""),
        "runnability_state": profile.pointer("/runnability/state").and_then(Value::as_str).unwrap_or("not_probed"),
        "provider_trust": profile.pointer("/adapter/provider_trust").and_then(Value::as_str).unwrap_or(""),
        "model_route_ref": route_ref,
        "model_route_state": route_state,
    })
}

/// The selected model route's (ref, availability state, model_id, endpoint) — the explicit ref
/// or the registry default. Read from the persisted registry (availability is probe truth).
pub(crate) fn route_fact(st: &DaemonState, explicit_ref: Option<&str>) -> (String, String, String, String) {
    let routes = read_record_dir(&st.data_dir, "model-route-registry");
    let route = routes.iter().find(|route| match explicit_ref {
        Some(wanted) => text(route, "route_ref") == wanted,
        None => route.get("default_route").and_then(Value::as_bool) == Some(true),
    });
    match route {
        Some(route) => (
            text(route, "route_ref").to_string(),
            route
                .pointer("/availability/state")
                .and_then(Value::as_str)
                .unwrap_or("declared")
                .to_string(),
            route
                .pointer("/model/model_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            route
                .pointer("/provider_binding/base_url")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        ),
        None => (String::new(), "unresolved".into(), String::new(), String::new()),
    }
}

pub(crate) async fn live_profiles(st: &DaemonState) -> Vec<Value> {
    self_get(&format!("{}/v1/hypervisor/harness-profiles?live=1", st.base_url))
        .await
        .and_then(|body| body.get("profiles").and_then(Value::as_array).cloned())
        .unwrap_or_default()
}

pub(crate) fn profile_by_harness<'a>(profiles: &'a [Value], harness: &str) -> Option<&'a Value> {
    profiles
        .iter()
        .find(|profile| text(profile, "harness") == harness)
}

// ---------------------------------------------------------------------------
// create / list / get
// ---------------------------------------------------------------------------

pub(crate) async fn handle_goal_runs_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let goal = text(&body, "goal").trim().to_string();
    let session_ref = text(&body, "session_ref").to_string();
    let Some(target_session) = load_session_record(&st, &session_ref) else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_target_session_unresolved",
            "A GoalRun binds to an existing session (its workspace is the reconciliation target).",
        );
    };
    let target_workspace = text(&target_session, "workspace_root").to_string();
    if target_workspace.is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_run_target_workspace_missing",
            "The target session has no provisioned workspace.",
        );
    }
    let project_ref = {
        let recorded = text(&target_session, "project_ref");
        if recorded.starts_with("project:") {
            recorded.to_string()
        } else {
            "project:hypervisor".to_string()
        }
    };

    // Live registry facts for the three roles (probe truth, never fabricated).
    let profiles = live_profiles(&st).await;
    let (route_ref, route_state, _, _) =
        route_fact(&st, body.get("model_route_ref").and_then(Value::as_str));
    let conductor = profile_by_harness(&profiles, "hypervisor_worker")
        .map(|p| fact_from_profile(p, &route_ref, &route_state))
        .unwrap_or(Value::Null);
    let implementer_candidates: Vec<Value> = ["opencode", "deepseek_tui"]
        .iter()
        .filter_map(|harness| profile_by_harness(&profiles, harness))
        .map(|p| fact_from_profile(p, &route_ref, &route_state))
        .collect();

    let goal_run_id = format!("gr_{:x}", nanos());
    let goal_ref = format!("goal://{goal_run_id}");
    let kernel = RuntimeKernelService::new();

    let topology = match kernel.select_goal_run_role_topology(&json!({
        "goal_ref": goal_ref,
        "conductor": conductor,
        "implementer_candidates": implementer_candidates,
    })) {
        Ok(selected) => selected,
        Err(error) => return kernel_err(error),
    };
    let admission = match kernel.admit_goal_run(
        &json!({
            "goal_ref": goal_ref,
            "normalized_goal": goal,
            "target_session_ref": session_ref,
            "project_ref": project_ref,
            "orchestration_policy": "parallel_implement_reconcile",
            "max_parallel_invocations": 2,
            "receipt_required": true,
            "authority_scope_refs": ["scope:goal.run.orchestrate"],
            "state_root_ref": format!("agentgres://state-root/goal-run/{goal_run_id}"),
        }),
        &iso_now(),
    ) {
        Ok(admitted) => admitted,
        Err(error) => return kernel_err(error),
    };

    // The typed ladder — durable coordination objects. The goal text lives ONCE as the
    // normalized goal; the task brief is the durable implementer contract (no raw prompts).
    let implementer_refs: Vec<String> = topology
        .get("implementer_refs")
        .and_then(Value::as_array)
        .map(|refs| {
            refs.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let harness_of = |profile_ref: &str| -> String {
        profiles
            .iter()
            .find(|p| text(p, "profile_ref") == profile_ref)
            .map(|p| text(p, "harness").to_string())
            .unwrap_or_default()
    };
    let role_keys = ["implementer_a", "implementer_b"];
    let mut context_cells = vec![json!({
        "context_cell_id": format!("context_cell://cc_{goal_run_id}_conductor"),
        "goal_ref": goal_ref,
        "role": "conductor",
        "harness_ref": text(&topology, "conductor_ref"),
        "model_route_ref": route_ref,
        "status": "open",
    })];
    let mut context_leases: Vec<Value> = Vec::new();
    let mut task_briefs: Vec<Value> = Vec::new();
    let mut handoffs: Vec<Value> = Vec::new();
    for (index, profile_ref) in implementer_refs.iter().enumerate() {
        let role_key = role_keys.get(index).copied().unwrap_or("implementer_x");
        let cell_ref = format!("context_cell://cc_{goal_run_id}_{role_key}");
        let lease_ref = format!("context_lease://cl_{goal_run_id}_{role_key}");
        let brief_ref = format!("task_brief://tb_{goal_run_id}_{role_key}");
        context_cells.push(json!({
            "context_cell_id": cell_ref,
            "goal_ref": goal_ref,
            "role": "implementer",
            "role_key": role_key,
            "harness_ref": profile_ref,
            "harness": harness_of(profile_ref),
            "model_route_ref": route_ref,
            "context_lease_refs": [lease_ref],
            "status": "open",
        }));
        context_leases.push(json!({
            "context_lease_id": lease_ref,
            "goal_ref": goal_ref,
            "context_cell_ref": cell_ref,
            "issued_to": profile_ref,
            "lease_kind": "worktree",
            // The implementer's writable surface is ITS candidate session workspace only.
            "allowed_ref_patterns": [format!("workspace://goal-run/{goal_run_id}/{role_key}")],
            "denied_ref_patterns": ["secret://", "unsafe_plaintext://", format!("workspace://session/{}", safe(&session_ref))],
            "budget_ref": format!("budget://goal-run/{goal_run_id}/invocation"),
            "ttl_seconds": 3600,
            "receipt_required": true,
            "status": "active",
        }));
        task_briefs.push(json!({
            "task_brief_id": brief_ref,
            "goal_ref": goal_ref,
            "handoff_ref": format!("handoff://ho_{goal_run_id}_{role_key}"),
            "objective": goal,
            "objective_class": "implement",
            "scope_refs": [format!("workspace://goal-run/{goal_run_id}/{role_key}")],
            "constraints": ["write only inside the leased candidate workspace"],
            "do_not_touch_refs": [format!("workspace://session/{}", safe(&session_ref))],
            "context_lease_refs": [lease_ref],
            "output_contract": {
                "changed_files_required": true,
                "diff_summary_required": false,
                "tests_required": false,
                "blocker_report_required": true,
                "receipt_refs_required": true,
            },
            "status": "ready",
        }));
        handoffs.push(json!({
            "handoff_id": format!("handoff://ho_{goal_run_id}_{role_key}"),
            "goal_ref": goal_ref,
            "from_context_cell_ref": format!("context_cell://cc_{goal_run_id}_conductor"),
            "to_context_cell_ref": cell_ref,
            "handoff_kind": "task_brief",
            "payload_ref": brief_ref,
            "context_lease_refs": [lease_ref],
            "status": "sent",
        }));
    }
    context_cells.push(json!({
        "context_cell_id": format!("context_cell://cc_{goal_run_id}_verifier"),
        "goal_ref": goal_ref,
        "role": "verifier",
        "harness_ref": text(&topology, "verifier_ref"),
        "model_route_ref": route_ref,
        "status": "open",
    }));

    let now = iso_now();
    let record = json!({
        "schema_version": GOAL_RUN_SCHEMA_VERSION,
        "goal_run_id": goal_run_id,
        "goal_ref": goal_ref,
        "origin_surface": "api",
        "normalized_goal": goal,
        "target_session_ref": session_ref,
        "target_workspace_root": target_workspace,
        "project_ref": project_ref,
        "orchestration_policy": "parallel_implement_reconcile",
        "max_parallel_invocations": 2,
        "role_topology": topology,
        "role_topology_ref": format!("role_topology://rt_{goal_run_id}"),
        "grounding_loop": {
            "goal_loop_id": format!("goal_loop://gl_{goal_run_id}"),
            "goal_ref": goal_ref,
            "conductor_context_cell_ref": format!("context_cell://cc_{goal_run_id}_conductor"),
            "loop_iteration": 0,
            "phase": "receive_intent",
            "escalation_state": "none",
        },
        "context_cells": context_cells,
        "context_leases": context_leases,
        "task_briefs": task_briefs,
        "handoffs": handoffs,
        "verifier_path": {
            "verifier_path_id": format!("verifier_path://vp_{goal_run_id}"),
            "owner_ref": text(&topology, "verifier_ref"),
            "verification_kind": "deterministic",
            "required_evidence": [
                "reported files exist with content in the candidate workspace",
                "driver exit_code == 0",
                "report equals disk truth",
            ],
            "independence_requirement": "none",
            "replay_required": false,
            "status": "active",
        },
        "admission": { "admission_id": text(&admission, "admission_id"), "receipt_refs": admission.get("receipt_refs").cloned().unwrap_or(json!([])) },
        // Optional launch-policy provenance (IOI Agent lane) — advanced/proof metadata only.
        "policy_ref": body.get("policy_ref").cloned().unwrap_or(Value::Null),
        "invocation_refs": [],
        "verification_refs": [],
        "reconciliation_ref": Value::Null,
        "blockers": [],
        "active_loop_phase": "receive_intent",
        "continuation_state": "open",
        "status": "draft",
        "created_at": now,
        "updated_at": now,
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, GOAL_RUN_KIND, &goal_run_id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "goal_run": record })))
}

pub(crate) async fn handle_goal_runs_list(
    State(st): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let mut runs = read_record_dir(&st.data_dir, GOAL_RUN_KIND);
    if let Some(session) = query.get("session") {
        runs.retain(|run| text(run, "target_session_ref") == session);
    }
    runs.sort_by(|a, b| text(b, "updated_at").cmp(text(a, "updated_at")));
    (StatusCode::OK, Json(json!({ "ok": true, "goal_runs": runs })))
}

pub(crate) async fn handle_goal_run_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    match load(&st, GOAL_RUN_KIND, &id) {
        Some(run) => (StatusCode::OK, Json(json!({ "ok": true, "goal_run": run }))),
        None => bad(StatusCode::NOT_FOUND, "goal_run_not_found", "Unknown GoalRun."),
    }
}

// ---------------------------------------------------------------------------
// start — wallet-gated, then the two implementer invocations run CONCURRENTLY
// ---------------------------------------------------------------------------

/// Start side-record persist failure (#72 round 4 finding 2): the wallet crossing and the
/// harness invocations already EXECUTED, so this can become neither a 200 with dangling refs
/// nor a silent release (a restored `draft` would re-open a duplicate wallet-gated crossing).
/// The run KEEPS its reservation, now marked `recovery_required` with the failure and the
/// executed-invocation evidence embedded durably on the run record itself — the side-record
/// family that refused the write is exactly the family that cannot hold the attempt evidence.
/// Recovery is the token-addressed, receipted lifecycle-recovery transition.
fn start_evidence_abort(
    data_dir: &str,
    goal_run_id: &str,
    token: &str,
    family: &str,
    record_id: &str,
    error: &str,
    executed: &[Value],
) -> (StatusCode, Json<Value>) {
    let evidence: Vec<Value> = executed
        .iter()
        .map(|i| {
            json!({
                "harness_invocation_id": text(i, "harness_invocation_id"),
                "role_key": text(i, "role_key"),
                "status": text(i, "status"),
            })
        })
        .collect();
    let marked = update_goal_run_guarded(
        data_dir,
        goal_run_id,
        |fresh| {
            if fresh.pointer("/lifecycle_op/token").and_then(Value::as_str) != Some(token) {
                return Err((
                    "goal_run_operation_conflict".to_string(),
                    "the reservation token changed while marking the start for recovery".to_string(),
                ));
            }
            Ok(())
        },
        |obj| {
            let mut op = obj.get("lifecycle_op").cloned().unwrap_or_else(|| json!({}));
            if let Some(o) = op.as_object_mut() {
                o.insert("phase".into(), json!("recovery_required"));
                o.insert(
                    "failure".into(),
                    json!({ "code": "goal_run_side_record_persist_failed", "family": family, "record_id": record_id, "error": error, "at": iso_now() }),
                );
                o.insert("executed_invocations".into(), json!(evidence));
            }
            obj.insert("lifecycle_op".into(), op);
        },
    );
    match marked {
        Ok(_) => bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_side_record_persist_failed",
            &format!("the {family} record '{record_id}' did not persist ({error}); NO ref was bound to the run, which keeps its `starting` reservation marked recovery_required with the executed-invocation evidence embedded durably — no duplicate wallet crossing is possible; recover via the token-addressed lifecycle-recovery transition"),
        ),
        Err((rcode, rmsg)) => bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_run_rollback_failed",
            &format!("the {family} record '{record_id}' did not persist ({error}) AND the recovery marking did not commit ({rcode}: {rmsg}) — manual repair required"),
        ),
    }
}

struct InvocationPlan {
    role_key: String,
    profile_ref: String,
    harness: String,
    cell_ref: String,
    brief_ref: String,
    invocation_ref: String,
    objective: String,
    /// Scoped intelligence projection for THIS harness (portable memory → rendered summary;
    /// the raw MemoryEntry records never reach the driver).
    memory_projection_ref: String,
    projection_summary: String,
}

/// One admitted implementer invocation, end to end: isolated candidate session → adapter driver
/// spawn → events/receipt/transcript → typed ImplementationResultPayload. Returns the durable
/// invocation record (completed or failed; failure is explicit, never silent).
async fn run_invocation(
    st: Arc<DaemonState>,
    goal_run_id: String,
    goal_ref: String,
    plan: InvocationPlan,
    route_ref: String,
    capability_lease_ref: String,
) -> Value {
    let started_at = iso_now();
    let candidate_session_ref = format!("session:goalrun-{}-{}", goal_run_id, plan.role_key);
    let fail = |failure_kind: &str, message: String, session_ref: &str, workspace: &str| -> Value {
        json!({
            "schema_version": INVOCATION_SCHEMA_VERSION,
            "goal_run_id": goal_run_id,
            "goal_ref": goal_ref,
            "harness_invocation_id": plan.invocation_ref,
            "role_key": plan.role_key,
            "context_cell_ref": plan.cell_ref,
            "task_brief_ref": plan.brief_ref,
            "harness_ref": plan.profile_ref,
            "harness": plan.harness,
            "model_route_ref": route_ref,
            "session_ref": session_ref,
            "candidate_workspace_root": workspace,
            "status": "failed",
            "implementation_result": {
                "implementation_result_id": format!("implementation_result://ir_{}_{}", goal_run_id, plan.role_key),
                "goal_ref": goal_ref,
                "harness_invocation_ref": plan.invocation_ref,
                "harness_profile_ref": plan.profile_ref,
                "model_route_ref": route_ref,
                "status": "failed",
                "failure_kind": failure_kind,
                "summary": message,
                "changed_files": [],
                "candidate_artifact_refs": [],
                "receipt_refs": [],
            },
            "blocker": { "reason_code": failure_kind, "message": message },
            "started_at": started_at,
            "finished_at": iso_now(),
        })
    };

    // Isolated candidate session (its workspace IS the candidate namespace).
    let (status, created) = self_post(
        &format!("{}/v1/hypervisor/sessions", st.base_url),
        &json!({
            "session_ref": candidate_session_ref,
            "harness_profile_ref": plan.profile_ref,
            "model_route_ref": route_ref,
        }),
    )
    .await;
    if !(200..300).contains(&(status as usize)) {
        return fail(
            "candidate_session_create_failed",
            format!(
                "candidate session create returned {status}: {}",
                created.pointer("/error/code").and_then(Value::as_str).unwrap_or("unknown")
            ),
            &candidate_session_ref,
            "",
        );
    }
    let Some(session_record) = load_session_record(&st, &candidate_session_ref) else {
        return fail(
            "candidate_session_record_missing",
            "candidate session record not persisted".into(),
            &candidate_session_ref,
            "",
        );
    };
    let workspace = text(&session_record, "workspace_root").to_string();

    // Model + endpoint from the session's admitted route binding (bound at create above).
    let binding =
        super::model_routes::resolve_session_route_binding(&st.data_dir, &candidate_session_ref);
    let (model, endpoint) = match &binding {
        Some((model_id, endpoint, _, _)) => (model_id.clone(), Some(endpoint.clone())),
        None => (
            std::env::var("IOI_HYPERVISOR_MODEL").unwrap_or_else(|_| "qwen2.5:7b".into()),
            std::env::var("IOI_HYPERVISOR_MODEL_UPSTREAM").ok().filter(|v| !v.is_empty()),
        ),
    };

    let driver = match resolve_adapter_driver(&session_record, &model, &workspace, endpoint.as_deref()) {
        Ok(Some(driver)) => driver,
        Ok(None) => {
            return fail(
                "adapter_driver_unresolved",
                "implementer session has no wired adapter driver".into(),
                &candidate_session_ref,
                &workspace,
            )
        }
        Err((reason, message)) => {
            return fail(reason, message, &candidate_session_ref, &workspace)
        }
    };

    // REAL adapter execution: the harness drives the model and edits ONLY its candidate
    // workspace (bwrap-confined by the driver lane). The rendered input is adapter-private;
    // the durable contract stays the task brief.
    let (_, argv) = driver;
    let delivered_objective = if plan.projection_summary.is_empty() {
        plan.objective.clone()
    } else {
        format!(
            "{}\n\n[Workspace intelligence — scoped projection]\n{}",
            plan.objective, plan.projection_summary
        )
    };
    let outcome = run_host_spawn_lane(&argv, &workspace, &delivered_objective, endpoint.as_deref()).await;

    // Persist normalized adapter events with the goal-run linkage.
    let run_tag = format!("{}_{}_{:x}", safe(&goal_run_id), plan.role_key, nanos());
    let mut adapter_event_refs: Vec<String> = Vec::new();
    for (index, event) in outcome.adapter_events.iter().enumerate() {
        let event_id = event
            .get("event_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("hae_{run_tag}_{index}"));
        let mut stored = event.clone();
        stored["goal_run_ref"] = json!(goal_ref);
        stored["harness_invocation_ref"] = json!(plan.invocation_ref);
        stored["session_ref"] = json!(candidate_session_ref);
        stored["sequence"] = json!(index + 1);
        let _ = persist_record(&st.data_dir, "harness-adapter-events", &event_id, &stored);
        adapter_event_refs.push(format!("agentgres://harness-adapter-event/{event_id}"));
    }

    let exit_status = if outcome.ok { "success" } else { "failure" };
    let candidate_artifact_refs: Vec<String> = outcome
        .files_written
        .iter()
        .map(|file| format!("artifact://goal-run/{}/{}/{}", goal_run_id, plan.role_key, file))
        .collect();

    // Invocation receipt (admitted authority named).
    let receipt_ref = format!(
        "receipt://hypervisor/goal-run-invocation/{}_{}",
        safe(&goal_run_id),
        plan.role_key
    );
    let receipt = json!({
        "id": receipt_ref,
        "kind": "hypervisor.goal-run.invoke",
        "goal_run_ref": goal_ref,
        "harness_invocation_ref": plan.invocation_ref,
        "role_key": plan.role_key,
        "harness": plan.harness,
        "harness_profile_ref": plan.profile_ref,
        "model_route_ref": route_ref,
        "session_ref": candidate_session_ref,
        "exit_status": exit_status,
        "exit_code": outcome.exit_code,
        "files_written": outcome.files_written,
        "adapter_event_refs": adapter_event_refs,
        "capability_lease_ref": capability_lease_ref,
        "started_at": started_at,
        "finished_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_ref, &receipt);

    // Tamper-evident transcript (state_root computed by the transcript plane).
    let transcript_run = super::harness_routes::post_op_transcript(
        &st.base_url,
        "goal_run_execute",
        &plan.profile_ref,
        &json!({
            "goal_run_ref": goal_ref,
            "role_key": plan.role_key,
            "session_ref": candidate_session_ref,
            "harness": plan.harness,
            "exit_status": exit_status,
            "files_written": outcome.files_written,
            "adapter_event_count": outcome.adapter_events.len(),
            "implementation_result": outcome.implementation_result,
            "receipt_ref": receipt_ref,
        }),
    )
    .await;
    let state_root = match &transcript_run {
        Some(run_id) => self_get(&format!(
            "{}/v1/hypervisor/agent-run-transcripts/{run_id}",
            st.base_url
        ))
        .await
        .and_then(|body| {
            body.pointer("/run/state_root")
                .or_else(|| body.get("state_root"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default(),
        None => String::new(),
    };

    let failure_kind = if outcome.ok {
        Value::Null
    } else if outcome.timed_out {
        json!("timeout")
    } else if outcome.spawn_error.is_some() {
        json!("spawn_error")
    } else {
        json!("exit_nonzero")
    };
    let shim = argv
        .iter()
        .find(|arg| arg.ends_with("-driver.mjs"))
        .cloned()
        .unwrap_or_default();
    json!({
        "schema_version": INVOCATION_SCHEMA_VERSION,
        "goal_run_id": goal_run_id,
        "goal_ref": goal_ref,
        "harness_invocation_id": plan.invocation_ref,
        "role_key": plan.role_key,
        "context_cell_ref": plan.cell_ref,
        "task_brief_ref": plan.brief_ref,
        "harness_ref": plan.profile_ref,
        "harness": plan.harness,
        "model_route_ref": route_ref,
        "session_ref": candidate_session_ref,
        "candidate_workspace_root": workspace,
        "status": if outcome.ok { "completed" } else { "failed" },
        "adapter_event_refs": adapter_event_refs,
        "adapter_event_count": outcome.adapter_events.len(),
        "memory_projection_ref": plan.memory_projection_ref,
        "implementation_result": {
            "implementation_result_id": format!("implementation_result://ir_{}_{}", goal_run_id, plan.role_key),
            "goal_ref": goal_ref,
            "harness_invocation_ref": plan.invocation_ref,
            "harness_profile_ref": plan.profile_ref,
            "model_route_ref": route_ref,
            "memory_projection_ref": plan.memory_projection_ref,
            "command_contract_ref": format!("command-contract://harness-shim/{}", safe(&shim)),
            "workspace_ref": format!("workspace://goal-run/{}/{}", goal_run_id, plan.role_key),
            "workspace_root": workspace,
            "candidate_artifact_refs": candidate_artifact_refs,
            "changed_files": outcome.files_written,
            "summary": outcome.summary,
            "status": if outcome.ok { "completed" } else { "failed" },
            "failure_kind": failure_kind,
            "receipt_refs": [receipt_ref],
            "transcript_run_ref": transcript_run,
            "state_root": state_root,
            "driver_result": outcome.implementation_result,
        },
        "started_at": started_at,
        "finished_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    })
}

pub(crate) async fn handle_goal_run_start(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // OPERATION RESERVATION (#72 round 3 finding 2): `start` is one-shot and wallet-gated — the
    // draft precheck and the transition to `starting` are ONE atomic CAS under the seam, before
    // any await and before the wallet crossing. Exactly one concurrent start wins the
    // reservation; the loser refuses typed, so a duplicate wallet-gated start is impossible.
    let op_token = format!("lop_{:x}", nanos());
    let reserved_at = iso_now();
    let run = match update_goal_run_guarded(
        &st.data_dir,
        &id,
        |fresh| {
            if text(fresh, "status") != "draft" {
                return Err((
                    "goal_run_already_started".to_string(),
                    "This GoalRun has already been started.".to_string(),
                ));
            }
            Ok(())
        },
        |obj| {
            obj.insert("status".into(), json!("starting"));
            obj.insert(
                "lifecycle_op".into(),
                json!({ "op": "start", "token": op_token.clone(), "reserved_at": reserved_at, "from_status": "draft" }),
            );
        },
    ) {
        Ok(run) => run,
        Err((code, msg)) => return bad(seam_status(&code), &code, &msg),
    };
    let goal_ref = text(&run, "goal_ref").to_string();
    let goal = text(&run, "normalized_goal").to_string();
    let target_workspace = text(&run, "target_workspace_root").to_string();

    // Wallet authority gate — one admitted crossing covers the run's bounded invocations; the
    // lease ref is named on every invocation receipt. 403 challenge shape identical to execute.
    // A refusal here happened before any side effect: release the reservation so the draft is
    // exactly re-runnable; a failed release is itself a typed 5xx, never a silent wedge.
    let capability_lease_ref =
        match execute_authority_gate(&body, &goal_ref, &target_workspace, &goal) {
            Ok(lease) => lease,
            Err(challenge) => {
                if let Err((rcode, rmsg)) =
                    release_lifecycle_reservation(&st.data_dir, &id, &op_token, "draft")
                {
                    return bad(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "goal_run_release_failed",
                        &format!("the start authority gate refused AND the reservation release did not commit ({rcode}: {rmsg}) — manual inspection required"),
                    );
                }
                return (StatusCode::FORBIDDEN, Json(challenge));
            }
        };

    // Refresh live facts and admit each implementer invocation (fail-closed per role; a
    // rejected role becomes an explicit failed invocation + blocker, the run continues).
    let profiles = live_profiles(&st).await;
    let (route_ref, route_state, _, _) = route_fact(
        &st,
        run.pointer("/role_topology/model_route_ref").and_then(Value::as_str),
    );
    let kernel = RuntimeKernelService::new();
    let empty = Vec::new();
    let cells = run
        .get("context_cells")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
        .clone();
    let goal_run_id = text(&run, "goal_run_id").to_string();

    let mut admitted_plans: Vec<InvocationPlan> = Vec::new();
    let mut invocations: Vec<Value> = Vec::new();
    for cell in cells.iter().filter(|c| text(c, "role") == "implementer") {
        let role_key = text(cell, "role_key").to_string();
        let profile_ref = text(cell, "harness_ref").to_string();
        let harness = text(cell, "harness").to_string();
        let invocation_ref = format!("harness_invocation://hi_{goal_run_id}_{role_key}");
        let brief_ref = format!("task_brief://tb_{goal_run_id}_{role_key}");
        let fact = profiles
            .iter()
            .find(|p| text(p, "profile_ref") == profile_ref)
            .map(|p| fact_from_profile(p, &route_ref, &route_state))
            .unwrap_or(Value::Null);
        let mut request = fact.clone();
        if let Some(object) = request.as_object_mut() {
            object.insert("goal_ref".into(), json!(goal_ref));
            object.insert("role".into(), json!("implementer"));
            object.insert("task_brief_ref".into(), json!(brief_ref));
            object.insert("context_cell_ref".into(), json!(text(cell, "context_cell_id")));
            object.insert(
                "session_ref".into(),
                json!(format!("session:goalrun-{goal_run_id}-{role_key}")),
            );
            object.insert("invocation_ref".into(), json!(invocation_ref));
        }
        // Attach the harness-scoped MemoryProjection when the IOI Agent lane created one
        // (matched by goal_run_ref + harness ref; absent = no projection, honest empty).
        let projection = read_record_dir(&st.data_dir, "memory-projections")
            .into_iter()
            .find(|p| {
                text(p, "goal_run_ref") == goal_ref && text(p, "harness_profile_ref") == profile_ref
            });
        match kernel.admit_goal_run_harness_invocation(&request, &iso_now()) {
            Ok(_admitted) => admitted_plans.push(InvocationPlan {
                role_key,
                profile_ref,
                harness,
                cell_ref: text(cell, "context_cell_id").to_string(),
                brief_ref,
                invocation_ref,
                objective: goal.clone(),
                memory_projection_ref: projection
                    .as_ref()
                    .map(|p| text(p, "projection_ref").to_string())
                    .unwrap_or_default(),
                projection_summary: projection
                    .as_ref()
                    .map(|p| text(p, "projection_summary").to_string())
                    .unwrap_or_default(),
            }),
            Err(error) => {
                // Explicit partial: the role is recorded as a failed invocation with the
                // planner's reason — never silently dropped.
                invocations.push(json!({
                    "schema_version": INVOCATION_SCHEMA_VERSION,
                    "goal_run_id": goal_run_id,
                    "goal_ref": goal_ref,
                    "harness_invocation_id": invocation_ref,
                    "role_key": role_key,
                    "harness_ref": profile_ref,
                    "harness": harness,
                    "status": "failed",
                    "implementation_result": {
                        "implementation_result_id": format!("implementation_result://ir_{goal_run_id}_{role_key}"),
                        "status": "failed",
                        "failure_kind": error.code,
                        "summary": error.message,
                        "changed_files": [],
                        "candidate_artifact_refs": [],
                    },
                    "blocker": { "reason_code": error.code, "message": error.message, "details": error.details },
                    "started_at": iso_now(),
                    "finished_at": iso_now(),
                }));
            }
        }
    }
    if admitted_plans.is_empty() && invocations.is_empty() {
        // Refused with no durable side effect — release the reservation (draft is re-runnable).
        if let Err((rcode, rmsg)) =
            release_lifecycle_reservation(&st.data_dir, &id, &op_token, "draft")
        {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "goal_run_release_failed",
                &format!("the start refused (no implementer cells) AND the reservation release did not commit ({rcode}: {rmsg}) — manual inspection required"),
            );
        }
        return bad(
            StatusCode::CONFLICT,
            "goal_run_no_implementer_cells",
            "This GoalRun has no implementer context cells.",
        );
    }

    // Bounded parallel execution (budget ≤ 2, planner-enforced at create).
    let mut executed: Vec<Value> = match admitted_plans.len() {
        0 => Vec::new(),
        1 => {
            let plan = admitted_plans.remove(0);
            vec![
                run_invocation(
                    st.clone(),
                    goal_run_id.clone(),
                    goal_ref.clone(),
                    plan,
                    route_ref.clone(),
                    capability_lease_ref.clone(),
                )
                .await,
            ]
        }
        _ => {
            let plan_b = admitted_plans.remove(1);
            let plan_a = admitted_plans.remove(0);
            let (a, b) = tokio::join!(
                run_invocation(
                    st.clone(),
                    goal_run_id.clone(),
                    goal_ref.clone(),
                    plan_a,
                    route_ref.clone(),
                    capability_lease_ref.clone(),
                ),
                run_invocation(
                    st.clone(),
                    goal_run_id.clone(),
                    goal_ref.clone(),
                    plan_b,
                    route_ref.clone(),
                    capability_lease_ref.clone(),
                )
            );
            vec![a, b]
        }
    };
    invocations.append(&mut executed);
    invocations.sort_by(|a, b| text(a, "role_key").cmp(text(b, "role_key")));

    // Conductor-run deterministic VerifierPath over each candidate (report ⇔ disk truth).
    let mut verification_refs: Vec<String> = Vec::new();
    for invocation in &invocations {
        let role_key = text(invocation, "role_key");
        let verification_id = format!("gv_{}_{}", safe(&goal_run_id), role_key);
        let workspace = text(invocation, "candidate_workspace_root");
        let changed: Vec<&str> = invocation
            .pointer("/implementation_result/changed_files")
            .and_then(Value::as_array)
            .map(|files| files.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let completed = text(invocation, "status") == "completed";
        let mut checks: Vec<Value> = vec![json!({
            "check": "invocation_completed_exit_zero",
            "pass": completed,
        })];
        let mut files_real = completed && !changed.is_empty();
        if completed {
            for file in &changed {
                let path = std::path::Path::new(workspace).join(file);
                let real = path.exists()
                    && std::fs::metadata(&path).map(|m| m.len() > 0).unwrap_or(false);
                checks.push(json!({ "check": "reported_file_exists_with_content", "file": file, "pass": real }));
                files_real &= real;
            }
            checks.push(json!({ "check": "workspace_mutation_reported", "pass": !changed.is_empty() }));
        }
        let verdict = completed && files_real;
        let verification = json!({
            "verification_id": verification_id,
            "verification_ref": format!("agentgres://goal-run-verification/{verification_id}"),
            "goal_run_id": goal_run_id,
            "goal_ref": goal_ref,
            "harness_invocation_ref": text(invocation, "harness_invocation_id"),
            "implementation_result_ref": invocation
                .pointer("/implementation_result/implementation_result_id")
                .cloned()
                .unwrap_or(Value::Null),
            "verifier_path_ref": format!("verifier_path://vp_{goal_run_id}"),
            "verification_kind": "deterministic",
            "verdict": if verdict { "pass" } else { "fail" },
            "checks": checks,
            "verified_at": iso_now(),
            "runtimeTruthSource": "daemon-runtime",
        });
        // CHECKED persist (#72 round 4 finding 2): a ref is bound ONLY after its record is
        // durable — a failed side-record write refuses typed with recovery state, never a 200
        // over nonexistent records.
        if let Err(e) = persist_record(&st.data_dir, VERIFICATION_KIND, &verification_id, &verification) {
            return start_evidence_abort(&st.data_dir, &goal_run_id, &op_token, VERIFICATION_KIND, &verification_id, &format!("{e}"), &invocations);
        }
        verification_refs.push(format!("agentgres://goal-run-verification/{verification_id}"));
    }

    // Persist invocation records + update the run (checked, same discipline).
    let mut invocation_refs: Vec<String> = Vec::new();
    for invocation in &invocations {
        let record_id = format!(
            "{}_{}",
            safe(&goal_run_id),
            text(invocation, "role_key")
        );
        if let Err(e) = persist_record(&st.data_dir, INVOCATION_KIND, &record_id, invocation) {
            return start_evidence_abort(&st.data_dir, &goal_run_id, &op_token, INVOCATION_KIND, &record_id, &format!("{e}"), &invocations);
        }
        invocation_refs.push(text(invocation, "harness_invocation_id").to_string());
    }
    let blockers: Vec<Value> = invocations
        .iter()
        .filter(|invocation| text(invocation, "status") != "completed")
        .filter_map(|invocation| invocation.get("blocker").cloned().or_else(|| {
            Some(json!({
                "reason_code": invocation.pointer("/implementation_result/failure_kind").cloned().unwrap_or(json!("failed")),
                "message": invocation.pointer("/implementation_result/summary").cloned().unwrap_or(json!("")),
                "role_key": text(invocation, "role_key"),
            }))
        }))
        .collect();
    let any_verified = read_record_dir(&st.data_dir, VERIFICATION_KIND)
        .iter()
        .any(|v| text(v, "goal_ref") == goal_ref && text(v, "verdict") == "pass");
    let partial = !blockers.is_empty();
    // FINALIZATION (#72 rounds 2 + 3): the lifecycle fields this handler OWNS merge onto the
    // LATEST record through the shared CAS seam (a stale-snapshot persist would erase the room
    // plane's reciprocal stamp), and the commit is TOKEN-GUARDED — it lands only while this
    // request still holds its reservation. A seam failure is a typed 5xx, never a 200: the
    // reservation (status `starting` + token) is preserved DELIBERATELY, because releasing to
    // `draft` after the wallet crossing would re-open the run to a duplicate wallet-gated start.
    let run = match update_goal_run_guarded(
        &st.data_dir,
        &goal_run_id,
        |fresh| {
            if fresh.pointer("/lifecycle_op/token").and_then(Value::as_str)
                != Some(op_token.as_str())
            {
                return Err((
                    "goal_run_operation_conflict".to_string(),
                    "start finalization no longer holds the reservation token — refusing to commit".to_string(),
                ));
            }
            Ok(())
        },
        |object| {
            object.insert("status".into(), json!("active"));
            object.insert("active_loop_phase".into(), json!("verify"));
            object.insert(
                "continuation_state".into(),
                json!(if any_verified { "verifying" } else { "blocked" }),
            );
            object.insert("invocation_refs".into(), json!(invocation_refs));
            object.insert("verification_refs".into(), json!(verification_refs));
            object.insert("blockers".into(), json!(blockers));
            object.insert("partial_result".into(), json!(partial));
            object.insert("capability_lease_ref".into(), json!(capability_lease_ref));
            object.insert("updated_at".into(), json!(iso_now()));
            object.remove("lifecycle_op");
        },
    ) {
        Ok(run) => run,
        Err((code, msg)) => {
            return bad(
                seam_status(&code),
                "goal_run_finalize_failed",
                &format!("start executed but its finalization did not commit ({code}: {msg}); invocation and verification records are durable and the run remains reserved (`starting`) — no duplicate start is possible; recover via the token-addressed lifecycle-recovery transition"),
            );
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "goal_run": run,
            "invocations": invocations,
            "partial_result": partial,
            "blockers": run.get("blockers").cloned().unwrap_or(json!([])),
        })),
    )
}

// ---------------------------------------------------------------------------
// reconcile — the ONLY lane into the target workspace
// ---------------------------------------------------------------------------

pub(crate) async fn handle_goal_run_reconcile(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(_body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // OPERATION RESERVATION (#72 round 3 finding 2): reconcile is one-shot — `active ->
    // reconciling` is reserved atomically with a fresh operation token BEFORE any await, so of
    // two simultaneous reconciles exactly one wins; the loser sees `reconciling` in the SAME
    // CAS predicate and refuses typed. Finalization commits only while it still holds this
    // token, and every refusal/rollback path releases the reservation back to `active`.
    let op_token = format!("lop_{:x}", nanos());
    let reserved_at = iso_now();
    let run = match update_goal_run_guarded(
        &st.data_dir,
        &id,
        |fresh| {
            if text(fresh, "status") != "active" {
                return Err((
                    "goal_run_not_reconcilable".to_string(),
                    "Reconciliation applies to a started (active) GoalRun exactly once.".to_string(),
                ));
            }
            Ok(())
        },
        |obj| {
            obj.insert("status".into(), json!("reconciling"));
            obj.insert(
                "lifecycle_op".into(),
                json!({ "op": "reconcile", "token": op_token.clone(), "reserved_at": reserved_at, "from_status": "active" }),
            );
        },
    ) {
        Ok(run) => run,
        Err((code, msg)) => return bad(seam_status(&code), &code, &msg),
    };
    let goal_ref = text(&run, "goal_ref").to_string();
    let goal_run_id = text(&run, "goal_run_id").to_string();
    let target_workspace = text(&run, "target_workspace_root").to_string();

    let invocations: Vec<Value> = read_record_dir(&st.data_dir, INVOCATION_KIND)
        .into_iter()
        .filter(|invocation| text(invocation, "goal_ref") == goal_ref)
        .collect();
    let verifications: Vec<Value> = read_record_dir(&st.data_dir, VERIFICATION_KIND)
        .into_iter()
        .filter(|verification| text(verification, "goal_ref") == goal_ref)
        .collect();
    let verdict_of = |invocation: &Value| -> bool {
        verifications.iter().any(|verification| {
            verification
                .get("harness_invocation_ref")
                .and_then(Value::as_str)
                == invocation.get("harness_invocation_id").and_then(Value::as_str)
                && text(verification, "verdict") == "pass"
        })
    };
    let mut passed: Vec<&Value> = invocations.iter().filter(|i| verdict_of(i)).collect();
    passed.sort_by(|a, b| text(a, "role_key").cmp(text(b, "role_key")));
    let result_ref = |invocation: &Value| -> String {
        invocation
            .pointer("/implementation_result/implementation_result_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let changed_of = |invocation: &Value| -> Vec<String> {
        invocation
            .pointer("/implementation_result/changed_files")
            .and_then(Value::as_array)
            .map(|files| files.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default()
    };

    // Deterministic strategy selection.
    let (merge_strategy, selected, reason_code): (&str, Vec<&Value>, String) = if passed.is_empty()
    {
        ("none_blocked", Vec::new(), "no_verified_candidate".to_string())
    } else if passed.len() >= 2 {
        let files_a = changed_of(passed[0]);
        let files_b = changed_of(passed[1]);
        let disjoint = files_a.iter().all(|f| !files_b.contains(f));
        if disjoint {
            (
                "merge_disjoint",
                vec![passed[0], passed[1]],
                "all_candidates_verified_disjoint".to_string(),
            )
        } else {
            (
                "select_single_best",
                vec![passed[0]],
                "overlapping_candidates_first_verified_selected".to_string(),
            )
        }
    } else {
        (
            "select_single_best",
            vec![passed[0]],
            "single_verified_candidate".to_string(),
        )
    };
    let selected_refs: Vec<String> = selected.iter().map(|i| result_ref(i)).collect();
    let rejected_refs: Vec<String> = invocations
        .iter()
        .filter(|i| !selected_refs.contains(&result_ref(i)))
        .map(|i| result_ref(i))
        .filter(|r| !r.is_empty())
        .collect();
    let verifier_evidence_refs: Vec<String> = verifications
        .iter()
        .map(|v| text(v, "verification_ref").to_string())
        .collect();

    let kernel = RuntimeKernelService::new();
    let admission = match kernel.admit_goal_run_reconciliation(
        &json!({
            "goal_ref": goal_ref,
            "merge_strategy": merge_strategy,
            "selected_candidate_refs": selected_refs,
            "rejected_candidate_refs": rejected_refs,
            "verifier_evidence_refs": verifier_evidence_refs,
            "reason_code": reason_code,
            "receipt_required": true,
        }),
        &iso_now(),
    ) {
        Ok(admitted) => admitted,
        Err(error) => {
            // Admission refused with nothing persisted — release the reservation so the run
            // stays exactly retryable; a failed release is a typed 5xx, never a silent wedge.
            if let Err((rcode, rmsg)) =
                release_lifecycle_reservation(&st.data_dir, &goal_run_id, &op_token, "active")
            {
                return bad(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "goal_run_release_failed",
                    &format!("reconciliation admission refused AND the reservation release did not commit ({rcode}: {rmsg}) — manual inspection required"),
                );
            }
            return kernel_err(error);
        }
    };

    // DECLARE-BEFORE-DO OUTPUT COMMIT (#72 round 4 finding 1). Order: STAGE the selected
    // candidate outputs into a plane-owned staging area (no target-workspace effect), persist
    // the PRE-OUTPUT receipt, persist the operation record (`status: committing`), and only
    // then commit staged outputs into the target under a checked per-file journal. Failures
    // BEFORE the commit clean up completely — "nothing changed" is literally true, target
    // included. From the moment output MAY have reached the target, NOTHING is deleted:
    // failures update the operation record to a recovery status and preserve the receipt.
    let reconciliation_id = format!("rc_{}", safe(&goal_run_id));
    let staging_root = std::path::Path::new(&st.data_dir)
        .join(STAGING_KIND)
        .join(format!("{}_{}", safe(&goal_run_id), op_token));
    let mut planned_files: Vec<(String, std::path::PathBuf, std::path::PathBuf)> = Vec::new();
    let mut staging_errors: Vec<String> = Vec::new();
    for invocation in &selected {
        let candidate_workspace = text(invocation, "candidate_workspace_root");
        for file in changed_of(invocation) {
            let src = std::path::Path::new(candidate_workspace).join(&file);
            let staged = staging_root.join(&file);
            if let Some(parent) = staged.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    staging_errors.push(format!("{file}: {e}"));
                    continue;
                }
            }
            match std::fs::copy(&src, &staged) {
                Ok(_) => planned_files.push((
                    file.clone(),
                    staged,
                    std::path::Path::new(&target_workspace).join(&file),
                )),
                Err(e) => staging_errors.push(format!("{file}: {e}")),
            }
        }
    }
    if !staging_errors.is_empty() {
        let _ = std::fs::remove_dir_all(&staging_root);
        return reconcile_abort(
            &st.data_dir,
            &goal_run_id,
            &op_token,
            "goal_run_output_staging_failed",
            &format!("candidate output staging failed ({}); no receipt was written and the target workspace was NOT touched", staging_errors.join("; ")),
            &[],
        );
    }
    let planned_list: Vec<String> = planned_files.iter().map(|(f, _, _)| f.clone()).collect();

    let receipt_ref = format!("receipt://hypervisor/goal-run-reconciliation/{}", safe(&goal_run_id));
    let receipt = json!({
        "id": receipt_ref,
        "kind": "hypervisor.goal-run.reconcile",
        "receipt_type": "orchestration_decision",
        "goal_run_ref": goal_ref,
        "orchestration_policy": "parallel_implement_reconcile",
        "merge_strategy": merge_strategy,
        "selected_materialization": "multi_harness_attempt",
        "selected_candidate_refs": selected_refs,
        "rejected_candidate_refs": rejected_refs,
        "selected_harness_refs": selected.iter().map(|i| text(i, "harness_ref")).collect::<Vec<_>>(),
        "selected_model_route_refs": selected.iter().map(|i| text(i, "model_route_ref")).collect::<Vec<_>>(),
        "verifier_evidence_refs": verifier_evidence_refs,
        "final_changed_files": planned_list,
        "output_commit_policy": "staged_pre_receipt: this receipt precedes ANY target-workspace effect; the reconciliation operation record journals the per-file commit",
        "reason_codes": [reason_code],
        "admission_id": text(&admission, "admission_id"),
        "capability_lease_ref": run.get("capability_lease_ref").cloned().unwrap_or(Value::Null),
        "target_session_ref": text(&run, "target_session_ref"),
        "at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    // CHECKED pre-output persist: the target is still untouched, so cleanup + release keeps
    // "nothing changed" literally true.
    if let Err(e) = persist_record(&st.data_dir, "receipts", &receipt_ref, &receipt) {
        let _ = std::fs::remove_dir_all(&staging_root);
        return reconcile_abort(
            &st.data_dir,
            &goal_run_id,
            &op_token,
            "goal_run_reconcile_receipt_persist_failed",
            &format!("the reconciliation receipt write did not commit ({e}); the target workspace was NOT touched"),
            &[],
        );
    }

    // Operation record, BEFORE any target effect: `committing` + the planned commit.
    let blocked = merge_strategy == "none_blocked";
    let base_record = |status: &str, final_files: &[String], journal: &[Value], copy_errors: &[String], transcript: &Option<String>, state_root: &str| {
        json!({
            "schema_version": RECONCILIATION_SCHEMA_VERSION,
            "reconciliation_result_id": format!("reconciliation_result://{reconciliation_id}"),
            "goal_run_id": goal_run_id,
            "goal_ref": goal_ref,
            "merge_strategy": merge_strategy,
            "selected_candidate_refs": selected_refs,
            "rejected_candidate_refs": rejected_refs,
            "verifier_evidence_refs": verifier_evidence_refs,
            "planned_changed_files": planned_list,
            "final_changed_files": final_files,
            "commit_journal": journal,
            "copy_errors": copy_errors,
            "final_receipt_refs": [receipt_ref],
            "transcript_run_ref": transcript,
            "state_root": state_root,
            "reason_code": reason_code,
            "admission_id": text(&admission, "admission_id"),
            "status": status,
            "reconciled_at": iso_now(),
            "runtimeTruthSource": "daemon-runtime",
        })
    };
    let committing = base_record("committing", &[], &[], &[], &None, "");
    if let Err(e) = persist_record(&st.data_dir, RECONCILIATION_KIND, &reconciliation_id, &committing) {
        let _ = std::fs::remove_dir_all(&staging_root);
        return reconcile_abort(
            &st.data_dir,
            &goal_run_id,
            &op_token,
            "goal_run_reconciliation_persist_failed",
            &format!("the reconciliation operation record did not commit ({e}); the target workspace was NOT touched"),
            &[("receipts", receipt_ref.as_str())],
        );
    }

    // COMMIT staged outputs → target workspace, per-file checked journal. From here on the
    // receipt and the operation record are NEVER deleted — they are the evidence for whatever
    // actually reached the target.
    let mut commit_journal: Vec<Value> = Vec::new();
    let mut final_changed_files: Vec<String> = Vec::new();
    let mut copy_errors: Vec<String> = Vec::new();
    for (file, staged, dst) in &planned_files {
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::copy(staged, dst) {
            Ok(bytes) => {
                final_changed_files.push(file.clone());
                commit_journal.push(json!({ "file": file, "applied": true, "bytes": bytes }));
            }
            Err(e) => {
                copy_errors.push(format!("{file}: {e}"));
                commit_journal.push(json!({ "file": file, "applied": false, "error": format!("{e}") }));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&staging_root);
    if !copy_errors.is_empty() {
        let preserved = base_record("failed_partial_commit", &final_changed_files, &commit_journal, &copy_errors, &None, "");
        return reconcile_preserve_abort(
            &st.data_dir,
            &goal_run_id,
            &op_token,
            &reconciliation_id,
            &preserved,
            "goal_run_output_commit_failed",
            &format!("the output commit failed partway ({}); the journal records exactly what reached the target", copy_errors.join("; ")),
        );
    }

    let conductor_ref = run
        .pointer("/role_topology/conductor_ref")
        .and_then(Value::as_str)
        .unwrap_or("harness-profile:hp_hypervisor_worker")
        .to_string();
    let transcript_run = super::harness_routes::post_op_transcript(
        &st.base_url,
        "goal_run_reconciliation",
        &conductor_ref,
        &json!({
            "goal_run_ref": goal_ref,
            "merge_strategy": merge_strategy,
            "selected_candidate_refs": selected_refs,
            "rejected_candidate_refs": rejected_refs,
            "final_changed_files": final_changed_files,
            "reason_code": reason_code,
            "receipt_ref": receipt_ref,
            "verifier_evidence_refs": verifier_evidence_refs,
        }),
    )
    .await;
    let state_root = match &transcript_run {
        Some(run_id) => self_get(&format!(
            "{}/v1/hypervisor/agent-run-transcripts/{run_id}",
            st.base_url
        ))
        .await
        .and_then(|body| {
            body.pointer("/run/state_root")
                .or_else(|| body.get("state_root"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default(),
        None => String::new(),
    };

    // Final operation-record update: the commit journal, transcript evidence, and terminal
    // status land on the SAME record id. Post-effect failure preserves everything (#72 round 4).
    let reconciliation = base_record(
        if blocked { "blocked" } else { "complete" },
        &final_changed_files,
        &commit_journal,
        &[],
        &transcript_run,
        &state_root,
    );
    if let Err(e) = persist_record(&st.data_dir, RECONCILIATION_KIND, &reconciliation_id, &reconciliation) {
        let preserved = base_record("recovery_required", &final_changed_files, &commit_journal, &[], &transcript_run, &state_root);
        return reconcile_preserve_abort(
            &st.data_dir,
            &goal_run_id,
            &op_token,
            &reconciliation_id,
            &preserved,
            "goal_run_reconciliation_finalize_failed",
            &format!("the committed outputs are in the target but the operation record's final update did not commit ({e})"),
        );
    }

    // FINALIZATION (#72 rounds 2-4): merge ONLY the reconciliation-owned fields onto the
    // LATEST record via the shared CAS seam — a concurrent reciprocal room stamp survives — and
    // commit TOKEN-GUARDED: only while this request still holds its reservation. A failure here
    // is POST-EFFECT: the receipt, the operation record (updated to a recovery status with its
    // journal), and the transcript are all PRESERVED; only the reservation is released so the
    // idempotent reconcile can be retried. Nothing is deleted.
    let run = match update_goal_run_guarded(
        &st.data_dir,
        &goal_run_id,
        |fresh| {
            if fresh.pointer("/lifecycle_op/token").and_then(Value::as_str)
                != Some(op_token.as_str())
            {
                return Err((
                    "goal_run_operation_conflict".to_string(),
                    "reconcile finalization no longer holds the reservation token — refusing to commit".to_string(),
                ));
            }
            Ok(())
        },
        |object| {
            object.insert("status".into(), json!(if blocked { "blocked" } else { "complete" }));
            object.insert(
                "continuation_state".into(),
                json!(if blocked { "blocked" } else { "complete" }),
            );
            object.insert("active_loop_phase".into(), json!("continue_or_close"));
            object.insert(
                "reconciliation_ref".into(),
                json!(format!("reconciliation_result://{reconciliation_id}")),
            );
            object.insert("final_changed_files".into(), json!(reconciliation["final_changed_files"]));
            object.insert("updated_at".into(), json!(iso_now()));
            object.remove("lifecycle_op");
        },
    ) {
        Ok(run) => run,
        Err((code, msg)) => {
            let preserved = base_record("recovery_required", &final_changed_files, &commit_journal, &[], &transcript_run, &state_root);
            return reconcile_preserve_abort(
                &st.data_dir,
                &goal_run_id,
                &op_token,
                &reconciliation_id,
                &preserved,
                "goal_run_finalize_failed",
                &format!("the outputs and their evidence are durable but the GoalRun finalization did not commit ({code}: {msg})"),
            );
        }
    };

    (
        StatusCode::OK,
        Json(json!({ "ok": true, "goal_run": run, "reconciliation": reconciliation })),
    )
}

// ---------------------------------------------------------------------------
// lifecycle-recovery — the token-addressed, receipted reservation recovery
// ---------------------------------------------------------------------------

/// POST /v1/hypervisor/goal-runs/:id/lifecycle-recovery (#72 round 4 finding 3): the recovery
/// contract for a durable lifecycle reservation — a crash after `draft -> starting` /
/// `active -> reconciling`, or a deliberately retained failed-start reservation, is resolved by
/// an EXPLICIT governed transition, never by a blind expiry. The caller must present the
/// reservation's own token (readable on the durable run record — proof they saw the current
/// state). `resolution: "release"` restores the reservation's recorded `from_status`, drops
/// `lifecycle_op` (its failure evidence moves into the receipt), and persists a
/// GoalRunLifecycleRecoveryReceipt; the receipt records that releasing after a consequential
/// execution (a completed wallet crossing) is a deliberate decision whose re-run performs a NEW
/// crossing. A receipt persist failure restores the reservation EXACTLY — nothing changed.
pub(crate) async fn handle_goal_run_lifecycle_recovery(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(token) = body.get("op_token").and_then(Value::as_str).map(str::to_string) else {
        return bad(
            StatusCode::BAD_REQUEST,
            "goal_run_recovery_token_required",
            "`op_token` is required — recovery is token-addressed to the durable reservation (read the run record first)",
        );
    };
    let resolution = body.get("resolution").and_then(Value::as_str).unwrap_or("");
    if resolution != "release" {
        return bad(
            StatusCode::BAD_REQUEST,
            "goal_run_recovery_resolution_invalid",
            "`resolution` must be \"release\" (restore the reservation's from_status and consume the token); richer resolutions are named gaps, not silent defaults",
        );
    }
    let mut prior_op: Option<Value> = None;
    let mut prior_status = String::new();
    let released = update_goal_run_guarded(
        &st.data_dir,
        &id,
        |fresh| {
            if fresh.pointer("/lifecycle_op/token").and_then(Value::as_str) != Some(token.as_str()) {
                return Err((
                    "goal_run_operation_conflict".to_string(),
                    "no durable reservation carries this token — recovery is addressed to the CURRENT reservation".to_string(),
                ));
            }
            Ok(())
        },
        |obj| {
            prior_op = obj.get("lifecycle_op").cloned();
            prior_status = obj.get("status").and_then(Value::as_str).unwrap_or("").to_string();
            let from = prior_op
                .as_ref()
                .and_then(|o| o.get("from_status"))
                .and_then(Value::as_str)
                .unwrap_or("draft")
                .to_string();
            obj.insert("status".into(), json!(from));
            obj.insert("updated_at".into(), json!(iso_now()));
            obj.remove("lifecycle_op");
        },
    );
    let run = match released {
        Ok(run) => run,
        Err((code, msg)) => return bad(seam_status(&code), &code, &msg),
    };
    let op = prior_op.unwrap_or(Value::Null);
    let restored_status = op
        .get("from_status")
        .and_then(Value::as_str)
        .unwrap_or("draft")
        .to_string();
    let receipt_id = format!(
        "receipt://hypervisor/goal-run-lifecycle-recovery/{}_{}",
        safe(&id),
        safe(&token)
    );
    let receipt = json!({
        "id": receipt_id,
        "kind": "hypervisor.goal-run.lifecycle-recovery",
        "receipt_type": "GoalRunLifecycleRecoveryReceipt",
        "goal_run_id": id,
        "op": op.get("op").cloned().unwrap_or(Value::Null),
        "op_token": token,
        "reservation": op,
        "reserved_status": prior_status,
        "restored_status": restored_status,
        "resolution": "release",
        "consequential_execution_note": "releasing after a consequential execution (e.g. a completed wallet crossing) is an explicit governed decision recorded by this receipt — re-running the operation performs a NEW crossing",
        "at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    if let Err(e) = persist_record(&st.data_dir, "receipts", &receipt_id, &receipt) {
        // Receipted transition or no transition: restore the reservation EXACTLY.
        let restore_status = prior_status.clone();
        let restore_op = receipt["reservation"].clone();
        let restored = update_goal_run_guarded(
            &st.data_dir,
            &id,
            |_| Ok(()),
            |obj| {
                obj.insert("status".into(), json!(restore_status));
                obj.insert("lifecycle_op".into(), restore_op);
            },
        );
        return match restored {
            Ok(_) => bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "goal_run_recovery_receipt_persist_failed",
                &format!("the recovery receipt did not persist ({e}); the reservation was restored EXACTLY — nothing changed"),
            ),
            Err((rcode, rmsg)) => bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "goal_run_rollback_failed",
                &format!("the recovery receipt did not persist ({e}) AND the reservation restore failed ({rcode}: {rmsg}) — manual repair required"),
            ),
        };
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "goal_run": run, "recovery_receipt": receipt })),
    )
}

// ---------------------------------------------------------------------------
// events — the run's normalized HarnessAdapterEvent stream + invocation records
// ---------------------------------------------------------------------------

pub(crate) async fn handle_goal_run_events(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(run) = load(&st, GOAL_RUN_KIND, &id) else {
        return bad(StatusCode::NOT_FOUND, "goal_run_not_found", "Unknown GoalRun.");
    };
    let goal_ref = text(&run, "goal_ref");
    let mut events: Vec<Value> = read_record_dir(&st.data_dir, "harness-adapter-events")
        .into_iter()
        .filter(|event| text(event, "goal_run_ref") == goal_ref)
        .collect();
    events.sort_by_key(|event| {
        (
            text(event, "harness_invocation_ref").to_string(),
            event.get("sequence").and_then(Value::as_u64).unwrap_or(0),
        )
    });
    let invocations: Vec<Value> = read_record_dir(&st.data_dir, INVOCATION_KIND)
        .into_iter()
        .filter(|invocation| text(invocation, "goal_ref") == goal_ref)
        .collect();
    let verifications: Vec<Value> = read_record_dir(&st.data_dir, VERIFICATION_KIND)
        .into_iter()
        .filter(|verification| text(verification, "goal_ref") == goal_ref)
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "goal_ref": goal_ref,
            "events": events,
            "invocations": invocations,
            "verifications": verifications,
        })),
    )
}

#[cfg(test)]
mod goal_run_seam_tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ioi-goalrun-{tag}-{:x}", nanos()));
        std::fs::create_dir_all(dir.join(GOAL_RUN_KIND)).unwrap();
        dir
    }

    fn plant(dir: &std::path::Path, file: &str, record: &Value) {
        std::fs::write(
            dir.join(GOAL_RUN_KIND).join(file),
            serde_json::to_vec_pretty(record).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn guarded_seam_distinguishes_not_found_refusal_and_persist_failure() {
        // #72 round 3 finding 1: the seam's outcomes are TYPED and distinct — a caller can no
        // longer collapse "record missing" and "write failed" into one silent lane.
        let dir = temp_dir("lanes");
        let data_dir = dir.to_str().unwrap();
        let seed = json!({ "goal_run_id": "gr_a", "status": "active", "normalized_goal": "x" });
        // The record lives in seed.json; the seam's atomic write targets gr_a.json — the two
        // names differ deliberately so a destination blocker can fail ONLY the persist step.
        plant(&dir, "seed.json", &seed);

        // Lane 1: unknown run — typed not-found, nothing else.
        let (code, _) = update_goal_run_guarded(data_dir, "gr_missing", |_| Ok(()), |_| {}).unwrap_err();
        assert_eq!(code, "goal_run_not_found");

        // Lane 2: predicate refusal — propagated verbatim, the mutation NEVER runs.
        let mut mutated = false;
        let (code, msg) = update_goal_run_guarded(
            data_dir,
            "gr_a",
            |_| Err(("goal_run_not_reconcilable".to_string(), "state precheck refused".to_string())),
            |_| mutated = true,
        )
        .unwrap_err();
        assert_eq!(code, "goal_run_not_reconcilable");
        assert_eq!(msg, "state precheck refused");
        assert!(!mutated, "the CAS predicate gates the mutation");

        // Lane 3: persist failure — a non-empty directory blocks the atomic rename destination.
        let blocker = dir.join(GOAL_RUN_KIND).join("gr_a.json");
        std::fs::create_dir_all(blocker.join("occupied")).unwrap();
        let before = std::fs::read(dir.join(GOAL_RUN_KIND).join("seed.json")).unwrap();
        let (code, _) = update_goal_run_guarded(data_dir, "gr_a", |_| Ok(()), |obj| {
            obj.insert("status".into(), json!("complete"));
        })
        .unwrap_err();
        assert_eq!(code, "goal_run_persist_failed", "a write failure is its OWN typed lane");
        assert_eq!(
            std::fs::read(dir.join(GOAL_RUN_KIND).join("seed.json")).unwrap(),
            before,
            "the durable record is byte-for-byte unchanged after a failed persist"
        );
        let leaks: Vec<String> = std::fs::read_dir(dir.join(GOAL_RUN_KIND))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(leaks.is_empty(), "no temporary artifact survives: {leaks:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn preserve_abort_updates_the_operation_record_and_never_deletes_evidence() {
        // #72 round 4 finding 1: once output MAY have reached the target, the abort lane
        // UPDATES the operation record to a recovery status (journal preserved), releases the
        // reservation, and deletes NOTHING — receipt included.
        let dir = temp_dir("preserve");
        let data_dir = dir.to_str().unwrap();
        plant(&dir, "gr_p.json", &json!({ "goal_run_id": "gr_p", "status": "reconciling", "lifecycle_op": { "op": "reconcile", "token": "tp", "from_status": "active" } }));
        std::fs::create_dir_all(dir.join(RECONCILIATION_KIND)).unwrap();
        std::fs::write(dir.join("receipts_marker"), b"x").unwrap();
        let preserved = json!({ "reconciliation_result_id": "reconciliation_result://rc_gr_p", "status": "failed_partial_commit", "commit_journal": [{ "file": "a.txt", "applied": true }], "final_receipt_refs": ["receipt://hypervisor/goal-run-reconciliation/gr_p"] });
        let (status, body) = reconcile_preserve_abort(data_dir, "gr_p", "tp", "rc_gr_p", &preserved, "goal_run_output_commit_failed", "half the files landed");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.0["error"]["code"], json!("goal_run_output_commit_failed"));
        let record = read_record_dir(data_dir, RECONCILIATION_KIND).pop().expect("the operation record is PRESERVED");
        assert_eq!(record["status"], json!("failed_partial_commit"));
        assert_eq!(record["commit_journal"][0]["applied"], json!(true), "the journal survives as evidence");
        assert_eq!(record["recovery"]["code"], json!("goal_run_output_commit_failed"), "the recovery lane is recorded ON the evidence");
        let run = read_record_dir(data_dir, GOAL_RUN_KIND).pop().unwrap();
        assert_eq!(run["status"], json!("active"), "the reservation was released for an idempotent retry");
        assert!(run.get("lifecycle_op").is_none());
        // Bookkeeping failure lane: a blocked record family escalates to rollback_failed while
        // STILL deleting nothing.
        plant(&dir, "gr_q.json", &json!({ "goal_run_id": "gr_q", "status": "reconciling", "lifecycle_op": { "op": "reconcile", "token": "tq", "from_status": "active" } }));
        let blocker = dir.join(RECONCILIATION_KIND).join("rc_gr_q.json");
        std::fs::create_dir_all(blocker.join("occupied")).unwrap();
        let (status, body) = reconcile_preserve_abort(data_dir, "gr_q", "tq", "rc_gr_q", &preserved, "goal_run_output_commit_failed", "half the files landed");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.0["error"]["code"], json!("goal_run_rollback_failed"));
        assert!(std::fs::read(dir.join("receipts_marker")).is_ok(), "nothing was deleted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn start_evidence_abort_marks_the_reservation_recovery_required_with_executed_evidence() {
        // #72 round 4 finding 2: a side-record persist failure after the wallet crossing keeps
        // the reservation (no duplicate crossing), embeds the failure + executed-invocation
        // evidence durably on the run record, and binds NO refs.
        let dir = temp_dir("evidence");
        let data_dir = dir.to_str().unwrap();
        plant(&dir, "gr_e.json", &json!({ "goal_run_id": "gr_e", "status": "starting", "lifecycle_op": { "op": "start", "token": "te", "from_status": "draft" } }));
        let executed = vec![json!({ "harness_invocation_id": "harness_invocation://hi_gr_e_a", "role_key": "a", "status": "failed" })];
        let (status, body) = start_evidence_abort(data_dir, "gr_e", "te", VERIFICATION_KIND, "gv_gr_e_a", "read-only dir", &executed);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.0["error"]["code"], json!("goal_run_side_record_persist_failed"));
        let run = read_record_dir(data_dir, GOAL_RUN_KIND).pop().unwrap();
        assert_eq!(run["status"], json!("starting"), "the reservation is KEPT — releasing would re-open a duplicate wallet crossing");
        assert_eq!(run["lifecycle_op"]["phase"], json!("recovery_required"));
        assert_eq!(run["lifecycle_op"]["token"], json!("te"), "the token survives for the recovery transition");
        assert_eq!(run["lifecycle_op"]["failure"]["family"], json!(VERIFICATION_KIND));
        assert_eq!(run["lifecycle_op"]["executed_invocations"][0]["harness_invocation_id"], json!("harness_invocation://hi_gr_e_a"), "the executed work is durable attempt evidence");
        assert!(run.get("invocation_refs").is_none() && run.get("verification_refs").is_none(), "no dangling refs were bound");
        // Wrong-token marking refuses without touching the record.
        let (_, body) = start_evidence_abort(data_dir, "gr_e", "wrong", VERIFICATION_KIND, "gv", "x", &executed);
        assert_eq!(body.0["error"]["code"], json!("goal_run_rollback_failed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn operation_reservation_admits_exactly_one_winner_and_finalizes_by_token() {
        // #72 round 3 finding 2: `active -> reconciling` is an atomic CAS reservation — of two
        // concurrent reconciles exactly one wins; finalization commits only under the winner's
        // token; release restores the exact pre-reservation lifecycle state.
        let dir = temp_dir("reserve");
        let data_dir = dir.to_str().unwrap();
        plant(&dir, "gr_b.json", &json!({ "goal_run_id": "gr_b", "status": "active" }));
        let reserve = |token: &str| {
            let token = token.to_string();
            update_goal_run_guarded(
                data_dir,
                "gr_b",
                |fresh| {
                    if fresh.get("status").and_then(Value::as_str) != Some("active") {
                        return Err((
                            "goal_run_not_reconcilable".to_string(),
                            "not active".to_string(),
                        ));
                    }
                    Ok(())
                },
                move |obj| {
                    obj.insert("status".into(), json!("reconciling"));
                    obj.insert("lifecycle_op".into(), json!({ "op": "reconcile", "token": token }));
                },
            )
        };
        assert!(reserve("t1").is_ok(), "the first reservation wins");
        let (code, _) = reserve("t2").unwrap_err();
        assert_eq!(code, "goal_run_not_reconcilable", "the second request loses the SAME CAS it would have raced");

        // Finalization compares the token INSIDE the seam: a foreign token refuses.
        let finalize = |token: &str| {
            let token = token.to_string();
            update_goal_run_guarded(
                data_dir,
                "gr_b",
                move |fresh| {
                    if fresh.pointer("/lifecycle_op/token").and_then(Value::as_str) != Some(token.as_str()) {
                        return Err(("goal_run_operation_conflict".to_string(), "token mismatch".to_string()));
                    }
                    Ok(())
                },
                |obj| {
                    obj.insert("status".into(), json!("complete"));
                    obj.remove("lifecycle_op");
                },
            )
        };
        let (code, _) = finalize("t2").unwrap_err();
        assert_eq!(code, "goal_run_operation_conflict");
        let committed = finalize("t1").unwrap();
        assert_eq!(committed["status"], json!("complete"));
        assert!(committed.get("lifecycle_op").is_none(), "the reservation is consumed by the commit");

        // Release restores the reserved status exactly and consumes the token.
        plant(&dir, "gr_c.json", &json!({ "goal_run_id": "gr_c", "status": "active" }));
        let hold = update_goal_run_guarded(data_dir, "gr_c", |_| Ok(()), |obj| {
            obj.insert("status".into(), json!("reconciling"));
            obj.insert("lifecycle_op".into(), json!({ "op": "reconcile", "token": "t3" }));
        });
        assert!(hold.is_ok());
        release_lifecycle_reservation(data_dir, "gr_c", "t3", "active").unwrap();
        let restored = read_record_dir(data_dir, GOAL_RUN_KIND)
            .into_iter()
            .find(|r| r.get("goal_run_id").and_then(Value::as_str) == Some("gr_c"))
            .unwrap();
        assert_eq!(restored["status"], json!("active"), "release restores the pre-reservation status");
        assert!(restored.get("lifecycle_op").is_none(), "release consumes the reservation");
        let (code, _) = release_lifecycle_reservation(data_dir, "gr_c", "t3", "active").unwrap_err();
        assert_eq!(code, "goal_run_operation_conflict", "a consumed token releases nothing twice");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
