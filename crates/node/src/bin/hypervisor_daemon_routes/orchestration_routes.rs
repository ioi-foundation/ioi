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
    if let Err(e) = super::validate_schedule_spec(body.get("schedule_spec").unwrap_or(&Value::Null)) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": { "code": "schedule_spec_invalid", "message": e } })),
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
            return Json(json!({ "ok": false, "error": { "code": "schedule_spec_invalid", "message": e } }));
        }
    }
    for key in [
        "name", "description", "trigger", "trigger_kind", "enabled", "steps", "workflow_graph_ref",
        "limits", "executor_identity", "recipe_ref", "agent_ref", "harness_profile_ref", "model",
        "reasoning", "connector_refs", "memory_profile_ref", "default_runtime_policy_ref",
        "authority_policy_ref", "schedule_spec", "catch_up_policy", "misfire_policy",
        "max_concurrency", "failure_policy",
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
    let project_id = load(&st.data_dir, "automations", &id)
        .and_then(|a| a.get("project_id").and_then(|v| v.as_str()).map(str::to_string));
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
        if !a.get("schedule_spec").map(|s| s.is_object()).unwrap_or(false) {
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
        let aid = e.get("automation_id").and_then(|v| v.as_str()).unwrap_or("");
        let t = by_run.get(exec_id);
        let name = t
            .and_then(|t| t.get("automation_name")).and_then(|v| v.as_str())
            .or_else(|| amap.get(aid).and_then(|a| a.get("name")).and_then(|v| v.as_str()))
            .unwrap_or("automation");
        let project = t
            .and_then(|t| t.get("project_id")).and_then(|v| v.as_str())
            .or_else(|| amap.get(aid).and_then(|a| a.get("project_id")).and_then(|v| v.as_str()))
            .unwrap_or("");
        runs.push(json!({
            "execution_id": exec_id, "automation_id": aid, "name": name, "project_id": project,
            "status": g(e, "status"), "started_at": g(e, "started_at"), "finished_at": g(e, "finished_at"),
            "timeline_ref": format!("/__ioi/run-timeline/{exec_id}"),
        }));
    }
    runs.sort_by(|a, b| {
        b.get("started_at").and_then(|v| v.as_str()).unwrap_or("")
            .cmp(a.get("started_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
    let failures: Vec<Value> = runs.iter().filter(|r| r.get("status").and_then(|v| v.as_str()) == Some("failed")).take(10).cloned().collect();
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
            *reasons.entry(ev.get("reason").and_then(|v| v.as_str()).unwrap_or("rejected").to_string()).or_insert(0) += 1;
        }
    }
    events.sort_by(|a, b| {
        b.get("received_at").and_then(|v| v.as_str()).unwrap_or("")
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
        let exec_id = e.get("execution_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let aid = e.get("automation_id").and_then(|v| v.as_str()).unwrap_or("");
        let t = by_run.get(&exec_id);
        let a = amap.get(aid);
        let name = t
            .and_then(|t| t.get("automation_name")).and_then(|v| v.as_str())
            .or_else(|| a.and_then(|a| a.get("name")).and_then(|v| v.as_str()))
            .unwrap_or("automation");
        let project = t
            .and_then(|t| t.get("project_id")).and_then(|v| v.as_str())
            .or_else(|| a.and_then(|a| a.get("project_id")).and_then(|v| v.as_str()))
            .unwrap_or("");
        let trigger = a.and_then(|a| a.get("trigger_kind")).and_then(|v| v.as_str()).unwrap_or("manual");
        let state_root = t.and_then(|t| t.get("state_root")).and_then(|v| v.as_str()).unwrap_or("");
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
    // Webhook trigger receipts (accepted/rejected proofs).
    for ev in read_record_dir(&st.data_dir, "webhook-trigger-events") {
        let aid = ev.get("automation_id").and_then(|v| v.as_str()).unwrap_or("");
        let a = amap.get(aid);
        let name = a.and_then(|a| a.get("name")).and_then(|v| v.as_str()).unwrap_or("automation");
        let project = a.and_then(|a| a.get("project_id")).and_then(|v| v.as_str()).unwrap_or("");
        let accepted = ev.get("accepted").and_then(|v| v.as_bool()) == Some(true);
        let run_ref = ev.get("run_ref").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
        let run_ref_v = match run_ref { Some(s) => json!(s), None => Value::Null };
        let timeline_v = match run_ref { Some(r) => json!(format!("/__ioi/run-timeline/{r}")), None => Value::Null };
        entries.push(json!({
            "id": g(&ev, "receipt_id"), "kind": "trigger", "timestamp": g(&ev, "received_at"),
            "automation_id": aid, "automation_name": name, "project_id": project,
            "status": if accepted { "accepted" } else { "rejected" }, "trigger_kind": "webhook",
            "reason": g(&ev, "reason"), "state_root": g(&ev, "payload_hash"),
            "payload_hash": g(&ev, "payload_hash"), "headers_hash": g(&ev, "headers_hash"),
            "request_id": g(&ev, "request_id"), "run_ref": run_ref_v, "timeline_ref": timeline_v,
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
    entries.sort_by(|a, b| {
        b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("")
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
    Json(json!({ "ok": true, "events": events, "accepted_count": accepted, "rejected_count": rejected }))
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
        (status, Json(json!({ "ok": false, "reason": reason, "request_id": request_id })))
    };

    let Some(a) = load(&st.data_dir, "automations", &id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "ok": false, "reason": "automation_not_found", "request_id": request_id })));
    };
    // Token: compare hashes (reject if no token configured or mismatch).
    let want = a.get("webhook_token_hash").and_then(|v| v.as_str()).unwrap_or("");
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
        Json(json!({ "ok": true, "accepted": true, "request_id": request_id, "receipt_id": receipt_id })),
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
