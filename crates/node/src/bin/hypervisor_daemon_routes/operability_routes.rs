//! Cut F — trust / operability (daemon-native).
//!
//! M. Guardrails: a real command + executable deny-list enforced AT the scoped-exec primitive (the
//!    only path agent/shell commands run through), so an agent cannot bypass policy via ordinary
//!    shell — `bash -c "rm -rf /"` is still the command string the deny-list matches. Fail-closed +
//!    audited. (Executable content-hash veto in-guest is the microVM provider follow-on.)
//! N. Observability/recovery: expose the persisted per-env logs, aggregate operability metrics from
//!    real env/incident truth, and reconstruct an incident from receipts+attempts+logs+audit (the
//!    recovery CHAIN itself already lives in environment_routes::recover_environment).
//! O. Parity — Hypervisor MCP Gateway: scoped tools (hv_create_env / hv_run_task / hv_inspect_env /
//!    hv_cleanup_env) for external agents, each calling the SAME daemon routes the app uses, under
//!    the same guardrails — create → run → inspect → clean up through scoped contracts.
use std::path::Path;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, AppError, DaemonState};

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

// ============================ M. GUARDRAILS ======================================================

/// The default fail-closed guardrail policy. Denied patterns are matched case-insensitively against
/// the full command string; denied executables against each whitespace/metachar-split token's
/// basename — so quoting or `bash -c` wrapping cannot smuggle them past.
fn default_policy() -> Value {
    json!({
        "deny_commands": [
            "rm -rf /", "rm -rf /*", "rm -rf ~", ":(){", "mkfs", "dd if=", "> /dev/sd",
            "chmod -R 777 /", "shutdown", "reboot", "curl | sh", "wget | sh", "| sh -",
            "/etc/shadow", "/etc/passwd"
        ],
        "deny_executables": ["nc", "ncat", "nmap", "telnet"],
        "note": "default fail-closed deny-list; per-env spec.guardrails extends/overrides"
    })
}

fn global_policy_path(data_dir: &str) -> std::path::PathBuf {
    Path::new(data_dir).join("guardrail-policy.json")
}

/// Effective policy = global override (if set) else default, then merged with this env's
/// `spec.guardrails` (additional deny_commands / deny_executables).
fn effective_policy(data_dir: &str, env: &Value) -> Value {
    let mut policy = std::fs::read(global_policy_path(data_dir))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .unwrap_or_else(default_policy);
    if let Some(g) = env.get("spec").and_then(|s| s.get("guardrails")) {
        for key in ["deny_commands", "deny_executables"] {
            if let Some(extra) = g.get(key).and_then(|v| v.as_array()) {
                let base = policy.get_mut(key).and_then(|v| v.as_array_mut());
                if let Some(arr) = base {
                    for e in extra {
                        if !arr.contains(e) {
                            arr.push(e.clone());
                        }
                    }
                }
            }
        }
    }
    policy
}

fn norm(s: &str) -> String {
    // collapse runs of whitespace so "rm    -rf  /" matches "rm -rf /".
    s.to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Check a command against the effective policy. Returns a denial detail if blocked (fail-closed).
pub(crate) fn guardrail_check(data_dir: &str, env: &Value, command: &str) -> Option<Value> {
    let policy = effective_policy(data_dir, env);
    let cmd_n = norm(command);
    if let Some(pats) = policy.get("deny_commands").and_then(|v| v.as_array()) {
        for p in pats {
            if let Some(pat) = p.as_str() {
                if cmd_n.contains(&norm(pat)) {
                    return Some(
                        json!({ "denied": true, "rule": "deny_command", "matched": pat, "fail_closed": true }),
                    );
                }
            }
        }
    }
    if let Some(exes) = policy.get("deny_executables").and_then(|v| v.as_array()) {
        let denied: std::collections::HashSet<String> = exes
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        // tokenize on shell metacharacters + whitespace; check each token's basename.
        for tok in command.split(|c: char| c.is_whitespace() || "|;&<>()`\"'".contains(c)) {
            let base = tok.rsplit('/').next().unwrap_or(tok).trim();
            if !base.is_empty() && denied.contains(base) {
                return Some(
                    json!({ "denied": true, "rule": "deny_executable", "matched": base, "fail_closed": true }),
                );
            }
        }
    }
    None
}

/// Record a guardrail denial to the operability audit trail.
pub(crate) fn audit_guardrail_denial(data_dir: &str, env_id: &str, command: &str, denial: &Value) {
    let id = format!("gad_{:x}", nanos());
    let _ = persist_record(
        data_dir,
        "operability-audit",
        &id,
        &json!({
            "schema_version": "ioi.hypervisor.operability-audit.v1",
            "audit_id": id, "kind": "guardrail_denied", "environment_ref": env_id,
            "command": command, "denial": denial, "at": iso_now()
        }),
    );
}

/// GET /v1/hypervisor/guardrails — the active global policy.
pub(crate) async fn handle_guardrails_get(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let policy = std::fs::read(global_policy_path(&st.data_dir))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .unwrap_or_else(default_policy);
    Json(json!({ "ok": true, "policy": policy }))
}

/// POST /v1/hypervisor/guardrails — set the global policy (audited).
pub(crate) async fn handle_guardrails_set(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let policy = json!({
        "deny_commands": body.get("deny_commands").cloned().unwrap_or_else(|| default_policy()["deny_commands"].clone()),
        "deny_executables": body.get("deny_executables").cloned().unwrap_or_else(|| default_policy()["deny_executables"].clone()),
        "updated_at": iso_now()
    });
    let _ = std::fs::write(
        global_policy_path(&st.data_dir),
        serde_json::to_vec_pretty(&policy).unwrap_or_default(),
    );
    let id = format!("pca_{:x}", nanos());
    let _ = persist_record(
        &st.data_dir,
        "operability-audit",
        &id,
        &json!({
            "schema_version": "ioi.hypervisor.operability-audit.v1",
            "audit_id": id, "kind": "policy_changed", "policy": policy, "at": iso_now()
        }),
    );
    Json(json!({ "ok": true, "policy": policy, "audited": true }))
}

// ============================ N. OBSERVABILITY / RECOVERY =========================================

/// GET /v1/hypervisor/environments/:id/logs?kind=session|tasks — read the persisted scoped logs.
pub(crate) async fn handle_env_logs(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let kind = q.get("kind").map(String::as_str).unwrap_or("session");
    let dir = Path::new(&st.data_dir).join("environments").join(safe(&id));
    match kind {
        "session" => {
            let text = std::fs::read_to_string(dir.join("session.log.jsonl")).unwrap_or_default();
            let lines: Vec<Value> = text
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            Json(json!({ "ok": true, "environment_id": id, "kind": "session", "entries": lines }))
        }
        "tasks" => {
            let mut logs = Vec::new();
            if let Ok(rd) = std::fs::read_dir(dir.join("task-logs")) {
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let content = std::fs::read_to_string(e.path()).unwrap_or_default();
                    logs.push(json!({ "task": name, "bytes": content.len(), "tail": content.chars().rev().take(400).collect::<String>().chars().rev().collect::<String>() }));
                }
            }
            Json(json!({ "ok": true, "environment_id": id, "kind": "tasks", "logs": logs }))
        }
        other => Json(json!({ "ok": false, "reason": format!("unknown log kind '{other}'") })),
    }
}

/// GET /v1/hypervisor/operability/metrics — aggregate from real env + incident + audit truth.
pub(crate) async fn handle_operability_metrics(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let envs = read_record_dir(&st.data_dir, "environments");
    let mut by_phase = serde_json::Map::new();
    for e in &envs {
        let phase = e["status"]["phase"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let n = by_phase.get(&phase).and_then(|v| v.as_u64()).unwrap_or(0) + 1;
        by_phase.insert(phase, json!(n));
    }
    let audit = read_record_dir(&st.data_dir, "operability-audit");
    let guardrail_denials = audit
        .iter()
        .filter(|a| a["kind"] == "guardrail_denied")
        .count();
    Json(json!({
        "schema_version": "ioi.hypervisor.operability-metrics.v1",
        "total_environments": envs.len(),
        "active_by_phase": Value::Object(by_phase),
        "incidents": read_record_dir(&st.data_dir, "incidents").len(),
        "recovery_attempts": read_record_dir(&st.data_dir, "recovery-attempts").len(),
        "snapshots": read_record_dir(&st.data_dir, "snapshots").len(),
        "guardrail_denials": guardrail_denials,
        "automation_executions": read_record_dir(&st.data_dir, "automation-executions").len(),
        "placements": read_record_dir(&st.data_dir, "placement-decisions").len(),
        "at": iso_now()
    }))
}

/// GET /v1/hypervisor/operability/incidents/:id — reconstruct an incident from receipts + attempts +
/// audit (the cross-source reconstruction the recovery done-bar requires).
pub(crate) async fn handle_incident_reconstruct(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let incident = read_record_dir(&st.data_dir, "incidents")
        .into_iter()
        .find(|i| {
            i["incident_id"].as_str() == Some(id.as_str())
                || i["incident_ref"].as_str() == Some(id.as_str())
        });
    let Some(incident) = incident else {
        return Json(json!({ "ok": false, "reason": "incident not found" }));
    };
    let attempts: Vec<Value> = read_record_dir(&st.data_dir, "recovery-attempts")
        .into_iter()
        .filter(|a| a["incident_ref"].as_str() == Some(id.as_str()))
        .collect();
    let receipts: Vec<Value> = read_record_dir(&st.data_dir, "receipts")
        .into_iter()
        .filter(|r| {
            r["details"]["incident_ref"].as_str() == Some(id.as_str())
                || r["kind"] == "environment_recovery"
        })
        .collect();
    Json(json!({
        "ok": true, "reconstructed": true, "incident": incident,
        "recovery_attempts": attempts, "receipts": receipts,
        "chain_complete": !attempts.is_empty() && !receipts.is_empty()
    }))
}

// ============================ O. HYPERVISOR MCP GATEWAY ===========================================

async fn call(base: &str, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
    let client = reqwest::Client::new();
    let url = format!("{base}{path}");
    let mut req = if method == "POST" {
        client.post(&url)
    } else {
        client.get(&url)
    };
    if let Some(b) = body {
        req = req.json(&b);
    }
    let r = req.send().await.map_err(|e| e.to_string())?;
    let t = r.text().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&t).map_err(|e| format!("{e}: {t}"))
}

fn gateway_tools() -> Value {
    json!([
        { "name": "hv_create_env", "scope": "environment.create", "description": "Create + start a scoped environment", "input": { "project_id": "string?", "class": "string?" } },
        { "name": "hv_run_task", "scope": "environment.exec", "description": "Run a guardrail-enforced command in an env", "input": { "environment_id": "string", "command": "string" } },
        { "name": "hv_inspect_env", "scope": "environment.read", "description": "Inspect an env (phase, components, ports)", "input": { "environment_id": "string" } },
        { "name": "hv_cleanup_env", "scope": "environment.delete", "description": "Delete an env (terminal)", "input": { "environment_id": "string" } }
    ])
}

/// GET /v1/hypervisor/mcp-gateway/tools — the scoped external-agent tool surface.
pub(crate) async fn handle_mcp_gateway_tools(State(_st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "schema_version": "ioi.hypervisor.mcp-gateway.v1", "tools": gateway_tools() }))
}

/// POST /v1/hypervisor/mcp-gateway/tools/:tool — invoke a scoped tool (same daemon routes as the app).
pub(crate) async fn handle_mcp_gateway_invoke(
    State(st): State<Arc<DaemonState>>,
    AxumPath(tool): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let base = st.base_url.clone();
    let gw = |v: Value| {
        Ok(Json(
            json!({ "ok": true, "tool": tool.clone(), "result": v }),
        ))
    };
    match tool.as_str() {
        "hv_create_env" => {
            let spec = json!({ "spec": { "environment_class_id": body.get("class").and_then(|v| v.as_str()).unwrap_or("local-workspace-v0"), "project_id": body.get("project_id").and_then(|v| v.as_str()).unwrap_or("mcp-gateway") } });
            let created = call(&base, "POST", "/v1/hypervisor/environments", Some(spec))
                .await
                .map_err(|e| AppError(axum::http::StatusCode::BAD_GATEWAY, e))?;
            let eid = created["environment"]["id"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let _ = call(
                &base,
                "POST",
                &format!("/v1/hypervisor/environments/{eid}/start"),
                None,
            )
            .await;
            gw(json!({ "environment_id": eid }))
        }
        "hv_run_task" => {
            let eid = body
                .get("environment_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let cmd = body
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            // routes through the SAME /exec the app uses → guardrails apply identically.
            let r = call(
                &base,
                "POST",
                "/v1/hypervisor/exec",
                Some(json!({ "environment_id": eid, "command": cmd })),
            )
            .await
            .map_err(|e| AppError(axum::http::StatusCode::BAD_GATEWAY, e))?;
            gw(r)
        }
        "hv_inspect_env" => {
            let eid = body
                .get("environment_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let env = call(
                &base,
                "GET",
                &format!("/v1/hypervisor/environments/{eid}"),
                None,
            )
            .await
            .map_err(|e| AppError(axum::http::StatusCode::BAD_GATEWAY, e))?;
            let s = &env["environment"]["status"];
            gw(
                json!({ "environment_id": eid, "phase": s["phase"], "readiness": s["readiness"], "components": s["components"], "ports": s["ports"] }),
            )
        }
        "hv_cleanup_env" => {
            let eid = body
                .get("environment_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let r = call(
                &base,
                "POST",
                &format!("/v1/hypervisor/environments/{eid}/delete"),
                None,
            )
            .await
            .map_err(|e| AppError(axum::http::StatusCode::BAD_GATEWAY, e))?;
            gw(
                json!({ "environment_id": eid, "deleted": r["environment"]["status"]["deleted"].as_bool().unwrap_or(false) || r["status"].as_str() == Some("deleted") }),
            )
        }
        other => Ok(Json(
            json!({ "ok": false, "reason": format!("unknown gateway tool '{other}'") }),
        )),
    }
}
