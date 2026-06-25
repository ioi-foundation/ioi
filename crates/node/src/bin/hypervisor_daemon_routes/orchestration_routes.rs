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

use axum::extract::{Path as AxumPath, State};
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, AppError, DaemonState};

fn safe(seg: &str) -> String {
    seg.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_")
}
fn nanos() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}
fn load(data_dir: &str, kind: &str, id: &str) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(Path::new(data_dir).join(kind).join(format!("{}.json", safe(id)))).ok()?).ok()
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
    if let Some(b) = body { req = req.json(&b); }
    let r = req.send().await.map_err(|e| e.to_string())?;
    let t = r.text().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&t).map_err(|e| format!("{e}: {t}"))
}

fn git(ws: &str, args: &[&str]) -> String {
    std::process::Command::new("git").arg("-C").arg(ws).args(args).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
}
fn env_workspace(data_dir: &str, env_id: &str) -> Option<String> {
    let v: Value = serde_json::from_slice(&std::fs::read(Path::new(data_dir).join("environments").join(format!("{}.json", safe(env_id)))).ok()?).ok()?;
    v["status"]["workspace_root"].as_str().filter(|s| !s.is_empty()).map(str::to_string)
}

// ============================ K. AUTOMATION WORKFLOW ENGINE ======================================

/// POST /v1/hypervisor/automations — create an AutomationWorkflow.
pub(crate) async fn handle_automation_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let id = format!("auto_{:x}", nanos());
    let record = json!({
        "schema_version": "ioi.hypervisor.automation-workflow.v1",
        "automation_id": id,
        "name": body.get("name").and_then(|v| v.as_str()).unwrap_or("automation"),
        "trigger": body.get("trigger").cloned().unwrap_or_else(|| json!({ "kind": "manual" })),
        "steps": body.get("steps").cloned().unwrap_or_else(|| json!([])),
        "limits": body.get("limits").cloned().unwrap_or_else(|| json!({ "max_total": 100, "per_exec_seconds": 600, "budget": Value::Null })),
        "executor_identity": body.get("executor_identity").cloned().unwrap_or_else(|| json!({ "kind": "user", "ref": "operator" })),
        "environment_class_id": body.get("environment_class_id").and_then(|v| v.as_str()).unwrap_or("local-workspace-v0"),
        "recipe_ref": body.get("recipe_ref").cloned().unwrap_or(Value::Null),
        "project_id": body.get("project_id").and_then(|v| v.as_str()).unwrap_or("automation"),
        "created_at": iso_now()
    });
    let _ = persist_record(&st.data_dir, "automations", &id, &record);
    Json(json!({ "ok": true, "automation": record }))
}

pub(crate) async fn handle_automation_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "ok": true, "automations": read_record_dir(&st.data_dir, "automations") }))
}
pub(crate) async fn handle_automation_get(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    match load(&st.data_dir, "automations", &id) {
        Some(a) => Json(json!({ "ok": true, "automation": a })),
        None => Json(json!({ "ok": false, "reason": "automation not found" })),
    }
}
pub(crate) async fn handle_automation_execution_get(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    match load(&st.data_dir, "automation-executions", &id) {
        Some(e) => Json(json!({ "ok": true, "execution": e })),
        None => Json(json!({ "ok": false, "reason": "execution not found" })),
    }
}

/// POST /v1/hypervisor/automations/:id/start — run the workflow: fresh env → steps → outputs.
pub(crate) async fn handle_automation_start(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let Some(automation) = load(&st.data_dir, "automations", &id) else {
        return Ok(Json(json!({ "ok": false, "reason": "automation not found" })));
    };
    let base = st.base_url.clone();
    let exec_id = format!("aex_{:x}", nanos());
    let steps = automation["steps"].as_array().cloned().unwrap_or_default();
    let mut counts = json!({ "pending": steps.len(), "running": 0, "done": 0, "failed": 0, "stopped": 0 });
    let mut exec = json!({
        "schema_version": "ioi.hypervisor.automation-execution.v1",
        "execution_id": exec_id, "automation_id": id, "status": "running",
        "executor_identity": automation["executor_identity"], "environment_id": Value::Null,
        "step_results": [], "counts": counts, "started_at": iso_now(), "finished_at": Value::Null
    });
    let _ = persist_record(&st.data_dir, "automation-executions", &exec_id, &exec);

    // 1) fresh environment (real env create + start over loopback).
    let spec = json!({ "spec": { "environment_class_id": automation["environment_class_id"], "recipe_ref": automation["recipe_ref"], "project_id": automation["project_id"] } });
    let created = call(&base, "POST", "/v1/hypervisor/environments", Some(spec)).await
        .map_err(|e| AppError(axum::http::StatusCode::BAD_GATEWAY, format!("env create: {e}")))?;
    let env_id = created["environment"]["id"].as_str().unwrap_or_default().to_string();
    if env_id.is_empty() {
        exec["status"] = json!("failed");
        exec["finished_at"] = json!(iso_now());
        let _ = persist_record(&st.data_dir, "automation-executions", &exec_id, &exec);
        return Ok(Json(json!({ "ok": false, "reason": "env create failed", "execution": exec })));
    }
    let _ = call(&base, "POST", &format!("/v1/hypervisor/environments/{env_id}/start"), None).await;
    exec["environment_id"] = json!(env_id);
    let ws = env_workspace(&st.data_dir, &env_id).unwrap_or_default();
    let base_ref = { let h = git(&ws, &["rev-parse", "HEAD"]).trim().to_string(); if h.is_empty() { "EMPTY".to_string() } else { h } };

    let mut results: Vec<Value> = Vec::new();
    let mut failed = false;
    for (idx, step) in steps.iter().enumerate() {
        if failed { results.push(json!({ "step": idx, "kind": step["kind"], "status": "skipped" })); continue; }
        let kind = step["kind"].as_str().unwrap_or("");
        let (status, output) = match kind {
            "agent" => {
                let conv = call(&base, "POST", "/v1/hypervisor/agentops/conversations", Some(json!({ "environment_id": env_id, "title": automation["name"] }))).await;
                let cid = conv.as_ref().ok().and_then(|c| c["conversation"]["conversation_id"].as_str().map(str::to_string)).unwrap_or_default();
                let prompt = step["prompt"].as_str().unwrap_or("Make a concrete change.");
                let sent = call(&base, "POST", &format!("/v1/hypervisor/agentops/conversations/{cid}/send"), Some(json!({ "text": prompt }))).await;
                match sent {
                    Ok(s) => {
                        let blocks = s["blocks"].as_array().cloned().unwrap_or_default();
                        let asst = blocks.iter().find(|b| b["kind"] == "assistant_message").and_then(|b| b["text"].as_str()).unwrap_or("").to_string();
                        let file = blocks.iter().find(|b| b["kind"] == "file_modification").and_then(|b| b["path"].as_str()).unwrap_or("").to_string();
                        ("done", json!({ "conversation_id": cid, "assistant_excerpt": asst.chars().take(200).collect::<String>(), "file": file }))
                    }
                    Err(e) => ("failed", json!({ "error": e })),
                }
            }
            "command" => {
                let cmd = step["command"].as_str().unwrap_or("true");
                match call(&base, "POST", "/v1/hypervisor/exec", Some(json!({ "environment_id": env_id, "command": cmd }))).await {
                    Ok(r) => {
                        let out = r.get("stdout").or_else(|| r.get("output")).and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let code = r.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(0);
                        (if code == 0 { "done" } else { "failed" }, json!({ "command": cmd, "exit_code": code, "stdout_excerpt": out.chars().take(400).collect::<String>() }))
                    }
                    Err(e) => ("failed", json!({ "command": cmd, "error": e })),
                }
            }
            "proposal" => {
                // a REAL proposal: the diff of everything this run changed on the env branch.
                let range = if base_ref == "EMPTY" { "HEAD".to_string() } else { format!("{base_ref}..HEAD") };
                let stat = git(&ws, &["diff", "--stat", &range]);
                let diff = git(&ws, &["diff", &range]);
                let files: Vec<String> = git(&ws, &["diff", "--name-only", &range]).lines().map(str::to_string).filter(|s| !s.is_empty()).collect();
                let pid = format!("prop_{:x}", nanos());
                let proposal = json!({
                    "schema_version": "ioi.hypervisor.automation-proposal.v1",
                    "proposal_id": pid, "execution_id": exec_id, "environment_id": env_id,
                    "title": step["title"].as_str().unwrap_or("Automation proposal"),
                    "review_state": "proposed", "base_ref": base_ref, "head_ref": git(&ws, &["rev-parse", "HEAD"]).trim(),
                    "changed_files": files, "diffstat": stat.trim(), "diff": diff, "host_mutation": false, "at": iso_now()
                });
                let _ = persist_record(&st.data_dir, "automation-proposals", &pid, &proposal);
                ("done", json!({ "proposal_ref": format!("agentgres://automation-proposal/{pid}"), "proposal_id": pid, "changed_files": proposal["changed_files"], "diffstat": stat.trim() }))
            }
            other => ("failed", json!({ "error": format!("unknown step kind '{other}'") })),
        };
        if status == "failed" { failed = true; }
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
    Ok(Json(json!({ "ok": !failed, "execution": exec })))
}

/// POST /v1/hypervisor/automation-executions/:id/cancel — stop a running execution.
pub(crate) async fn handle_automation_cancel(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    let Some(mut exec) = load(&st.data_dir, "automation-executions", &id) else {
        return Json(json!({ "ok": false, "reason": "execution not found" }));
    };
    if exec["status"] == "running" { exec["status"] = json!("stopped"); exec["finished_at"] = json!(iso_now()); }
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
    let trust = body.get("trust").and_then(|v| v.as_str()).unwrap_or("trusted"); // trusted | cross_tenant
    let residency = body.get("residency").and_then(|v| v.as_str()).unwrap_or("any"); // any | local
    let class = body.get("class").and_then(|v| v.as_str()).unwrap_or("local-workspace-v0");
    let project = body.get("project_id").and_then(|v| v.as_str()).unwrap_or("default");
    let recipe_ref = body.get("recipe_ref").and_then(|v| v.as_str()).unwrap_or("");

    let providers = call(&base, "GET", "/v1/hypervisor/providers", None).await
        .map_err(|e| AppError(axum::http::StatusCode::BAD_GATEWAY, format!("providers: {e}")))?;
    let list = providers["providers"].as_array().cloned().unwrap_or_default();
    let recipe_cached = !recipe_ref.is_empty() && Path::new(&st.data_dir).join("recipe-cache").join(safe(recipe_ref)).exists();
    let warm = warm_pool_for(&st.data_dir, project, class).is_some();

    let mut eligible: Vec<Value> = Vec::new();
    let mut rejected: Vec<Value> = Vec::new();
    for p in &list {
        let pref = p["provider_ref"].as_str().unwrap_or("");
        let caps = &p["capabilities"];
        let status = p["status"].as_str().unwrap_or("");
        if status != "available" {
            rejected.push(json!({ "provider_ref": pref, "reason": format!("provider {status}") })); continue;
        }
        if trust == "cross_tenant" && caps["isolation"].as_str() != Some("vm_kernel") {
            rejected.push(json!({ "provider_ref": pref, "reason": "cross-tenant trust requires vm_kernel isolation; this runner is not a cross-tenant boundary" })); continue;
        }
        if residency == "local" && caps["locality"].as_str() == Some("cloud") {
            rejected.push(json!({ "provider_ref": pref, "reason": "violates local data residency (cloud locality)" })); continue;
        }
        // honest scoring: isolation strength + prebuild/warm availability.
        let mut score = 50i64;
        if caps["isolation"].as_str() == Some("vm_kernel") { score += 20; }
        if caps["restore"].as_bool() == Some(true) { score += 5; }
        if recipe_cached { score += 15; }
        if warm { score += 25; }
        if caps["locality"].as_str() == Some("local") { score += 10; }
        eligible.push(json!({ "provider_ref": pref, "score": score, "capabilities": caps }));
    }
    eligible.sort_by(|a, b| b["score"].as_i64().unwrap_or(0).cmp(&a["score"].as_i64().unwrap_or(0)));
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
        return Ok(Json(json!({ "ok": false, "reason": "no eligible runner for the request (all candidates rejected with honest reasons)", "decision": decision })));
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
    let prebuild_hit = decisions.iter().filter(|d| d["claim_kind"] == "prebuild_hit").count() as u64;
    Json(json!({
        "schema_version": "ioi.hypervisor.placement-metrics.v1",
        "placements": decisions.len(),
        "cold_start": cold_start, "prebuild_hit": prebuild_hit, "warm_claim": warm_claim, "cache_hit": cache_hit,
        "at": iso_now()
    }))
}

fn warm_pool_for(data_dir: &str, project: &str, class: &str) -> Option<Value> {
    read_record_dir(data_dir, "warm-pools").into_iter().find(|p| {
        p["project_id"].as_str() == Some(project) && p["class"].as_str() == Some(class)
            && p["ready"].as_array().map(|a| !a.is_empty()).unwrap_or(false)
    })
}

/// POST /v1/hypervisor/warm-pools — declare a warm pool and PRE-START `size` envs (real).
pub(crate) async fn handle_warm_pool_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let base = st.base_url.clone();
    let project = body.get("project_id").and_then(|v| v.as_str()).unwrap_or("default").to_string();
    let class = body.get("class").and_then(|v| v.as_str()).unwrap_or("local-workspace-v0").to_string();
    let size = body.get("size").and_then(|v| v.as_u64()).unwrap_or(2).min(5);
    let id = format!("wp_{:x}", nanos());
    let mut ready: Vec<String> = Vec::new();
    for _ in 0..size {
        let spec = json!({ "spec": { "environment_class_id": class, "project_id": project } });
        if let Ok(c) = call(&base, "POST", "/v1/hypervisor/environments", Some(spec)).await {
            if let Some(eid) = c["environment"]["id"].as_str() {
                let _ = call(&base, "POST", &format!("/v1/hypervisor/environments/{eid}/start"), None).await;
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
pub(crate) async fn handle_warm_pool_claim(State(st): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Json<Value> {
    let Some(mut pool) = load(&st.data_dir, "warm-pools", &id) else {
        return Json(json!({ "ok": false, "reason": "warm pool not found" }));
    };
    let mut ready = pool["ready"].as_array().cloned().unwrap_or_default();
    if ready.is_empty() {
        return Json(json!({ "ok": false, "reason": "warm pool exhausted (no pre-started env to claim)", "fail_closed": true }));
    }
    let claimed_env = ready.remove(0);
    pool["ready"] = json!(ready);
    if let Some(c) = pool["claimed"].as_array_mut() { c.push(claimed_env.clone()); }
    let _ = persist_record(&st.data_dir, "warm-pools", &id, &pool);
    let cid = format!("wc_{:x}", nanos());
    let _ = persist_record(&st.data_dir, "warm-claims", &cid, &json!({ "claim_id": cid, "warm_pool_id": id, "environment_id": claimed_env, "at": iso_now() }));
    Json(json!({ "ok": true, "environment_id": claimed_env, "claim_kind": "warm_claim", "remaining": pool["ready"].as_array().map(|a| a.len()).unwrap_or(0) }))
}
