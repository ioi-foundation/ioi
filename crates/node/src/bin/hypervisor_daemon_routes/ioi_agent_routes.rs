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
use ioi_services::agentic::runtime::kernel::RuntimeKernelService;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::goalrun_routes::{fact_from_profile, live_profiles, profile_by_harness, route_fact};
use super::lifecycle_routes::load_session_record;
use super::{iso_now, persist_record, read_record_dir, DaemonState};

const LAUNCH_KIND: &str = "ioi-agent-launches";
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
    match builder.timeout(Duration::from_millis(600_000)).send().await {
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

/// Gather LIVE facts and run the pure strategy planner. Shared by preview + launch.
async fn plan(st: &DaemonState, body: &Value) -> Result<(Value, Value), (StatusCode, Json<Value>)> {
    let goal = text(body, "goal").trim().to_string();
    let strategy = {
        let requested = text(body, "strategy").trim().to_lowercase();
        if requested.is_empty() { "auto".to_string() } else { requested }
    };
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
        }))
        .map_err(kernel_err)?;
    let facts = json!({
        "goal": goal,
        "route_ref": route_ref,
        "route_state": route_state,
        "route_local": route_local,
    });
    Ok((selection, facts))
}

pub(crate) async fn handle_ioi_agent_launch_preview(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if text(&body, "goal").trim().len() < 4 {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "ioi_agent_goal_required",
            "Tell IOI Agent what to do (a few words at least).",
        );
    }
    let (selection, facts) = match plan(&st, &body).await {
        Ok(planned) => planned,
        Err(rejection) => return rejection,
    };
    let kind = text(&selection, "planned_execution_kind").to_string();
    let failure_policy = {
        let requested = text(&body, "failure_policy");
        if requested.is_empty() { "continue_partial" } else { requested }
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
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "agent": "ioi-agent",
            "coordination": "IOI Agent will coordinate this work",
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
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}

fn load_launch(st: &DaemonState, launch_id: &str) -> Option<Value> {
    read_record_dir(&st.data_dir, LAUNCH_KIND)
        .into_iter()
        .find(|record| text(record, "launch_id") == launch_id)
}

pub(crate) async fn handle_ioi_agent_launch(
    State(st): State<Arc<DaemonState>>,
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
                Some(&json!({ "intent": goal, "wallet_approval_grant": grant })),
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
    let (selection, facts) = match plan(&st, &body).await {
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
            Some(&json!({ "goal": goal, "session_ref": session_ref, "model_route_ref": route_ref })),
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
        json!({ "intent": goal })
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
        "state": "prepared",
        "created_at": iso_now(),
        "runtimeTruthSource": "daemon-runtime",
    });
    let _ = persist_record(&st.data_dir, LAUNCH_KIND, &launch_id, &record);

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
