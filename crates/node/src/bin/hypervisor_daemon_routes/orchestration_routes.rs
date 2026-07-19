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
async fn call(base: &str, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
    let client = reqwest::Client::new();
    let url = format!("{base}{path}");
    let mut req = match method {
        "POST" => client.post(&url),
        "GET" => client.get(&url),
        other => return Err(format!("bad method {other}")),
    };
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
    let _ = persist_record(data_dir, "projects", project_id, &project);
}

/// POST /v1/hypervisor/automations — create a project-scoped AutomationWorkflow spec.
/// `project_ref` (alias `project_id`) is REQUIRED: an automation is durable work that must hang off
/// a project. Returns 400 if absent. On success the project's `automation_refs` is updated.
pub(crate) async fn handle_automation_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
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
        "executor_identity": body.get("executor_identity").cloned().unwrap_or_else(|| json!({ "kind": "user", "ref": "operator" })),
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
    let _ = persist_record(&st.data_dir, "automations", &id, &record);
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
    Json(body): Json<Value>,
) -> Json<Value> {
    let Some(mut a) = load(&st.data_dir, "automations", &id) else {
        return Json(json!({ "ok": false, "reason": "automation not found" }));
    };
    if let Some(spec) = body.get("schedule_spec") {
        if let Err(e) = super::validate_schedule_spec(spec) {
            return Json(
                json!({ "ok": false, "error": { "code": "schedule_spec_invalid", "message": e } }),
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
    let _ = persist_record(&st.data_dir, "automations", &id, &a);
    Json(json!({ "ok": true, "automation": a }))
}

/// DELETE /v1/hypervisor/automations/:id — remove the spec + unlink it from the project's
/// automation_refs. Returns {ok, removed} so a no-op delete is honest.
pub(crate) async fn handle_automation_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let project_id = load(&st.data_dir, "automations", &id).and_then(|a| {
        a.get("project_id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    });
    let removed = remove_record(&st.data_dir, "automations", &id);
    if let Some(pid) = project_id {
        link_project_automation(&st.data_dir, &pid, &id, false);
    }
    Json(json!({ "ok": removed, "removed": removed, "automation_id": id }))
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
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
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
    Json(json!({ "ok": true, "entries": entries }))
}

fn new_webhook_token() -> String {
    format!(
        "whk_{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// POST /v1/hypervisor/automations/:id/webhook-rotate — (re)mint the opaque trigger token (also
/// enables webhook triggering on an existing automation). Hash stored at rest; plaintext returned ONCE.
pub(crate) async fn handle_automation_webhook_rotate(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let Some(mut a) = load(&st.data_dir, "automations", &id) else {
        return Json(json!({ "ok": false, "reason": "automation not found" }));
    };
    let tok = new_webhook_token();
    a["webhook_token_hash"] = json!(sha256_hex_str(&tok));
    a["webhook_url"] = json!(format!("/v1/hypervisor/automations/{id}/webhook"));
    if a.get("trigger_kind").and_then(|v| v.as_str()) != Some("time") {
        a["trigger_kind"] = json!("webhook"); // don't clobber an existing schedule
    }
    a["updated_at"] = json!(iso_now());
    let _ = persist_record(&st.data_dir, "automations", &id, &a);
    Json(json!({ "ok": true, "webhook_token": tok, "webhook_url": a["webhook_url"] }))
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
    let record_event = |accepted: bool, reason: &str, run_ref: Value| -> String {
        let rid = format!("whk_evt_{}", uuid::Uuid::new_v4().simple());
        let ev = json!({
            "schema_version": "ioi.hypervisor.webhook-trigger-receipt.v1",
            "receipt_id": rid, "automation_id": id, "request_id": request_id,
            "received_at": received_at, "headers_hash": headers_hash, "payload_hash": payload_hash,
            "payload_bytes": body.len(), "accepted": accepted, "reason": reason, "run_ref": run_ref,
        });
        let _ = persist_record(&st.data_dir, "webhook-trigger-events", &rid, &ev);
        rid
    };
    let reject = |status: StatusCode, reason: &str| {
        record_event(false, reason, Value::Null);
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
    let receipt_id = record_event(true, "accepted", Value::Null);
    let base = st.base_url.clone();
    let data_dir = st.data_dir.clone();
    let id2 = id.clone();
    let receipt = receipt_id.clone();
    tokio::spawn(async move {
        if let Ok(r) = call(
            &base,
            "POST",
            &format!("/v1/hypervisor/automations/{id2}/runs"),
            Some(json!({ "trigger": "webhook" })),
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
) -> Result<Json<Value>, AppError> {
    let Some(automation) = load(&st.data_dir, "automations", &id) else {
        return Ok(Json(
            json!({ "ok": false, "reason": "automation not found" }),
        ));
    };
    let base = st.base_url.clone();
    let exec_id = format!("aex_{:x}", nanos());
    let steps = automation["steps"].as_array().cloned().unwrap_or_default();
    let mut counts =
        json!({ "pending": steps.len(), "running": 0, "done": 0, "failed": 0, "stopped": 0 });
    let mut exec = json!({
        "schema_version": "ioi.hypervisor.automation-execution.v1",
        "execution_id": exec_id, "automation_id": id, "status": "running",
        "executor_identity": automation["executor_identity"], "environment_id": Value::Null,
        "step_results": [], "counts": counts, "started_at": iso_now(), "finished_at": Value::Null
    });
    let _ = persist_record(&st.data_dir, "automation-executions", &exec_id, &exec);

    // 1) fresh environment (real env create + start over loopback).
    let spec = json!({ "spec": { "environment_class_id": automation["environment_class_id"], "recipe_ref": automation["recipe_ref"], "project_id": automation["project_id"] } });
    let created = call(&base, "POST", "/v1/hypervisor/environments", Some(spec))
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
        let _ = persist_record(&st.data_dir, "automation-executions", &exec_id, &exec);
        return Ok(Json(
            json!({ "ok": false, "reason": "env create failed", "execution": exec }),
        ));
    }
    let _ = call(
        &base,
        "POST",
        &format!("/v1/hypervisor/environments/{env_id}/start"),
        None,
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
                let _ = persist_record(&st.data_dir, "automation-proposals", &pid, &proposal);
                (
                    "done",
                    json!({ "proposal_ref": format!("agentgres://automation-proposal/{pid}"), "proposal_id": pid, "changed_files": proposal["changed_files"], "diffstat": stat.trim() }),
                )
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
    let _ = persist_record(&st.data_dir, "automation-executions", &exec_id, &exec);

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
    )
    .await;
    Ok(Json(json!({ "ok": !failed, "execution": exec })))
}

/// POST /v1/hypervisor/automation-executions/:id/cancel — stop a running execution.
pub(crate) async fn handle_automation_cancel(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let Some(mut exec) = load(&st.data_dir, "automation-executions", &id) else {
        return Json(json!({ "ok": false, "reason": "execution not found" }));
    };
    if exec["status"] == "running" {
        exec["status"] = json!("stopped");
        exec["finished_at"] = json!(iso_now());
    }
    let _ = persist_record(&st.data_dir, "automation-executions", &id, &exec);
    Json(json!({ "ok": true, "status": exec["status"] }))
}

// ============================ L. RUNNER PLACEMENT + METRICS + WARM POOLS ==========================

/// POST /v1/hypervisor/placement/resolve — score the real provider catalog against the request and
/// record the decision + REJECTED candidates with honest reasons (no silent drop).
pub(crate) async fn handle_placement_resolve(
    State(st): State<Arc<DaemonState>>,
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

    let providers = call(&base, "GET", "/v1/hypervisor/providers", None)
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
    let _ = persist_record(&st.data_dir, "placement-decisions", &did, &decision);
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

pub(crate) async fn live_environment_classes(base: &str) -> Vec<Value> {
    call(base, "GET", "/v1/hypervisor/environment-classes", None)
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
pub(crate) async fn handle_placement_venues(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let classes = live_environment_classes(&st.base_url).await;
    let mut venues = compose_venues(&st.data_dir, &classes);
    let intent = super::decentralized_cloud_routes::ensure_default_intent(&st.data_dir);
    let advisory = super::decentralized_cloud_routes::advisory_for(&st, &intent, false).await;
    attach_choose_advisory(&mut venues, &advisory);
    Json(json!({
        "schema_version": "ioi.hypervisor.placement-venues.v1",
        "venues": venues,
        "fee_bases": fee_bases_taxonomy(),
        "spend_rule": "BYO provider spend is customer-borne; the hypervisor records, governs, estimates, and reconciles — it does not hide markup inside provider cost",
        "no_fee_objects": "this plane mints no fee object, no quote, and no RoutingDecisionReceipt",
        "at": iso_now(),
    }))
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
        advisory_block = super::decentralized_cloud_routes::advisory_for(&st, &intent, true).await;
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
    let _ = persist_record(&st.data_dir, VENUE_POLICY_KIND, "current", &record);
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
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
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
    let classes = live_environment_classes(&st.base_url).await;
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
    let advisory = if venue == "hypervisor_choose" {
        let intent = super::decentralized_cloud_routes::ensure_default_intent(&st.data_dir);
        super::decentralized_cloud_routes::advisory_for(&st, &intent, false).await
    } else {
        Value::Null
    };
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
    }))
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
        if let Ok(c) = call(&base, "POST", "/v1/hypervisor/environments", Some(spec)).await {
            if let Some(eid) = c["environment"]["id"].as_str() {
                let _ = call(
                    &base,
                    "POST",
                    &format!("/v1/hypervisor/environments/{eid}/start"),
                    None,
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
    let _ = persist_record(&st.data_dir, "warm-pools", &id, &pool);
    Ok(Json(json!({ "ok": true, "warm_pool": pool })))
}

pub(crate) async fn handle_warm_pool_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "ok": true, "warm_pools": read_record_dir(&st.data_dir, "warm-pools") }))
}

/// POST /v1/hypervisor/warm-pools/:id/claim — claim a pre-started env (warm-claim metric).
pub(crate) async fn handle_warm_pool_claim(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let Some(mut pool) = load(&st.data_dir, "warm-pools", &id) else {
        return Json(json!({ "ok": false, "reason": "warm pool not found" }));
    };
    let mut ready = pool["ready"].as_array().cloned().unwrap_or_default();
    if ready.is_empty() {
        return Json(
            json!({ "ok": false, "reason": "warm pool exhausted (no pre-started env to claim)", "fail_closed": true }),
        );
    }
    let claimed_env = ready.remove(0);
    pool["ready"] = json!(ready);
    if let Some(c) = pool["claimed"].as_array_mut() {
        c.push(claimed_env.clone());
    }
    let _ = persist_record(&st.data_dir, "warm-pools", &id, &pool);
    let cid = format!("wc_{:x}", nanos());
    let _ = persist_record(
        &st.data_dir,
        "warm-claims",
        &cid,
        &json!({ "claim_id": cid, "warm_pool_id": id, "environment_id": claimed_env, "at": iso_now() }),
    );
    Json(
        json!({ "ok": true, "environment_id": claimed_env, "claim_kind": "warm_claim", "remaining": pool["ready"].as_array().map(|a| a.len()).unwrap_or(0) }),
    )
}
