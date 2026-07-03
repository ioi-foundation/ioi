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
use super::{iso_now, persist_record, read_record_dir, DaemonState};

const GOAL_RUN_KIND: &str = "goal-runs";
const INVOCATION_KIND: &str = "goal-run-invocations";
const VERIFICATION_KIND: &str = "goal-run-verifications";
const RECONCILIATION_KIND: &str = "goal-run-reconciliations";

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
    let Some(mut run) = load(&st, GOAL_RUN_KIND, &id) else {
        return bad(StatusCode::NOT_FOUND, "goal_run_not_found", "Unknown GoalRun.");
    };
    if text(&run, "status") != "draft" {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_already_started",
            "This GoalRun has already been started.",
        );
    }
    let goal_ref = text(&run, "goal_ref").to_string();
    let goal = text(&run, "normalized_goal").to_string();
    let target_workspace = text(&run, "target_workspace_root").to_string();

    // Wallet authority gate — one admitted crossing covers the run's bounded invocations; the
    // lease ref is named on every invocation receipt. 403 challenge shape identical to execute.
    let capability_lease_ref =
        match execute_authority_gate(&body, &goal_ref, &target_workspace, &goal) {
            Ok(lease) => lease,
            Err(challenge) => return (StatusCode::FORBIDDEN, Json(challenge)),
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
        let _ = persist_record(&st.data_dir, VERIFICATION_KIND, &verification_id, &verification);
        verification_refs.push(format!("agentgres://goal-run-verification/{verification_id}"));
    }

    // Persist invocation records + update the run.
    let mut invocation_refs: Vec<String> = Vec::new();
    for invocation in &invocations {
        let record_id = format!(
            "{}_{}",
            safe(&goal_run_id),
            text(invocation, "role_key")
        );
        let _ = persist_record(&st.data_dir, INVOCATION_KIND, &record_id, invocation);
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
    if let Some(object) = run.as_object_mut() {
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
    }
    let _ = persist_record(&st.data_dir, GOAL_RUN_KIND, &goal_run_id, &run);

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
    let Some(mut run) = load(&st, GOAL_RUN_KIND, &id) else {
        return bad(StatusCode::NOT_FOUND, "goal_run_not_found", "Unknown GoalRun.");
    };
    if text(&run, "status") != "active" {
        return bad(
            StatusCode::CONFLICT,
            "goal_run_not_reconcilable",
            "Reconciliation applies to a started (active) GoalRun exactly once.",
        );
    }
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
        Err(error) => return kernel_err(error),
    };

    // Admitted: copy selected candidate files into the target workspace (first time any
    // candidate output reaches it). merge_disjoint is conflict-free by construction.
    let mut final_changed_files: Vec<String> = Vec::new();
    let mut copy_errors: Vec<String> = Vec::new();
    for invocation in &selected {
        let candidate_workspace = text(invocation, "candidate_workspace_root");
        for file in changed_of(invocation) {
            let src = std::path::Path::new(candidate_workspace).join(&file);
            let dst = std::path::Path::new(&target_workspace).join(&file);
            if let Some(parent) = dst.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match std::fs::copy(&src, &dst) {
                Ok(_) => final_changed_files.push(file.clone()),
                Err(err) => copy_errors.push(format!("{file}: {err}")),
            }
        }
    }

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
        "final_changed_files": final_changed_files,
        "reason_codes": [reason_code],
        "admission_id": text(&admission, "admission_id"),
        "capability_lease_ref": run.get("capability_lease_ref").cloned().unwrap_or(Value::Null),
        "target_session_ref": text(&run, "target_session_ref"),
        "at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_ref, &receipt);

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

    let blocked = merge_strategy == "none_blocked";
    let reconciliation_id = format!("rc_{}", safe(&goal_run_id));
    let reconciliation = json!({
        "schema_version": RECONCILIATION_SCHEMA_VERSION,
        "reconciliation_result_id": format!("reconciliation_result://{reconciliation_id}"),
        "goal_run_id": goal_run_id,
        "goal_ref": goal_ref,
        "merge_strategy": merge_strategy,
        "selected_candidate_refs": selected_refs,
        "rejected_candidate_refs": rejected_refs,
        "verifier_evidence_refs": verifier_evidence_refs,
        "final_changed_files": final_changed_files,
        "copy_errors": copy_errors,
        "final_receipt_refs": [receipt_ref],
        "transcript_run_ref": transcript_run,
        "state_root": state_root,
        "reason_code": reason_code,
        "admission_id": text(&admission, "admission_id"),
        "status": if blocked { "blocked" } else { "complete" },
        "reconciled_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, RECONCILIATION_KIND, &reconciliation_id, &reconciliation);

    if let Some(object) = run.as_object_mut() {
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
    }
    let _ = persist_record(&st.data_dir, GOAL_RUN_KIND, &goal_run_id, &run);

    (
        StatusCode::OK,
        Json(json!({ "ok": true, "goal_run": run, "reconciliation": reconciliation })),
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
