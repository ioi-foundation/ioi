//! WS-A + WS-B — Environment object model + `local_workspace_provider_v0` (daemon-owned).
//!
//! Phase 0 environment lifecycle as DAEMON TRUTH (no JS-owned state). Records persist under
//! `state_dir/environments/<id>.json`. The local-workspace provider does REAL local
//! provisioning (a scoped workspace dir under the daemon data dir); it is single-user /
//! trusted-operator and is NOT a cross-tenant isolation boundary — per the Dev Env Substrate
//! Doctrine, VM/microVM/HypervisorOS are the isolation claim for untrusted/cross-tenant work
//! (modeled in the class catalog, disabled in v0). Honest labels travel on `status`.
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use ioi_types::app::agentic::InferenceOptions;
use serde_json::{json, Value};

use super::{
    invoke_native_local, iso_now, persist_invocation_receipt, persist_record, read_record_dir,
    resolve_route, short_hash, AppError, DaemonState,
};

const ENV_SCHEMA: &str = "ioi.hypervisor.environment.v1";
const PROVIDER: &str = "local_workspace_provider_v0";

// WS-1 — canon EnvironmentStatus component set + shared phase taxonomy
// (docs/architecture/components/hypervisor/providers-and-environments.md §Environment Status Object).
const COMPONENTS: &[&str] = &[
    "recipe",
    "provisioner",
    "workspace_content",
    "sandbox",
    "resource_isolation",
    "connectivity",
    "secrets",
    "automations",
    "agent_work",
    "model_mount",
    "harness",
];
// Components the local_workspace provider actually establishes — gate readiness=full on these
// (WS-2 replaces this with the recipe's required_* edges). The rest stay `pending`/optional.
const REQUIRED_COMPONENTS: &[&str] = &[
    "recipe",
    "provisioner",
    "workspace_content",
    "sandbox",
    "resource_isolation",
    "connectivity",
];
// Component phase taxonomy: pending | creating | initializing | ready | degraded | recovering | failed.

fn new_components() -> Value {
    let mut map = serde_json::Map::new();
    for c in COMPONENTS {
        map.insert(
            (*c).to_string(),
            json!({ "phase": "pending", "detail": Value::Null, "evidence_ref": Value::Null }),
        );
    }
    Value::Object(map)
}

/// Set one component's sub-phase (component phase taxonomy).
fn set_component(env: &mut Value, component: &str, phase: &str, detail: &str) {
    env["status"]["components"][component] = json!({
        "phase": phase,
        "detail": detail,
        "evidence_ref": Value::Null
    });
}

/// Set the env rollup phase (env phase taxonomy: creating | starting | running | updating |
/// recovering | stopping | stopped | archived | failed) and bump status_version.
fn set_phase(env: &mut Value, phase: &str) {
    let v = env["status"]["status_version"].as_u64().unwrap_or(1) + 1;
    env["status"]["status_version"] = json!(v);
    env["status"]["phase"] = json!(phase);
    env["updated_at"] = json!(iso_now());
}

/// Recompute readiness from the required components (WS-2 deepens with recipe edges):
/// full (all required ready) · degraded (required ready but an optional degraded) ·
/// dry_run_only (workspace ready but a required runtime component not ready) · blocked.
fn recompute_readiness(env: &mut Value) {
    let phase = env["status"]["phase"].as_str().unwrap_or("stopped").to_string();
    let comp_phase = |env: &Value, c: &str| -> String {
        env["status"]["components"][c]["phase"].as_str().unwrap_or("pending").to_string()
    };
    if phase != "running" {
        let reason = if phase == "stopped" { "not_started" } else { phase.as_str() };
        env["status"]["readiness"] = json!({ "mode": "blocked", "blocked_reasons": [reason] });
        return;
    }
    let not_ready: Vec<String> = REQUIRED_COMPONENTS
        .iter()
        .filter(|c| comp_phase(env, c) != "ready")
        .map(|c| (*c).to_string())
        .collect();
    let failed: Vec<String> = REQUIRED_COMPONENTS
        .iter()
        .filter(|c| matches!(comp_phase(env, c).as_str(), "failed"))
        .map(|c| (*c).to_string())
        .collect();
    let mode = if !failed.is_empty() {
        "blocked"
    } else if not_ready.iter().any(|c| matches!(c.as_str(), "workspace_content" | "sandbox" | "provisioner")) {
        "blocked"
    } else if !not_ready.is_empty() {
        // workspace + sandbox ready but a runtime edge (connectivity/services) unmet
        "dry_run_only"
    } else {
        "full"
    };
    env["status"]["readiness"] = json!({ "mode": mode, "blocked_reasons": not_ready });
}

fn safe_id(id: &str) -> String {
    id.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_")
}

fn gen_env_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("env_{nanos:x}")
}

fn bwrap_available() -> bool {
    std::process::Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn load_env(data_dir: &str, id: &str) -> Option<Value> {
    let path = std::path::Path::new(data_dir)
        .join("environments")
        .join(format!("{}.json", safe_id(id)));
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok())
}

fn persist_env(data_dir: &str, env: &Value) -> Result<(), AppError> {
    let id = env["id"].as_str().unwrap_or("env");
    persist_record(data_dir, "environments", id, env)
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("persist env: {e}")))
}

fn new_env(id: &str, spec: &Value) -> Value {
    let now = iso_now();
    json!({
        "schema_version": ENV_SCHEMA,
        "id": id,
        "spec": {
            "environment_class_id": spec.get("environment_class_id").and_then(|v| v.as_str()).unwrap_or("local-workspace-v0"),
            "project_id": spec.get("project_id").cloned().unwrap_or(Value::Null),
            "recipe_ref": spec.get("recipe_ref").cloned().unwrap_or(Value::Null),
            "declared_ports": spec.get("declared_ports").cloned().unwrap_or_else(|| json!([])),
            "desired_phase": "stopped",
            // WS-7 — stop/idle policy: mode graceful|immediate|abort; idle/max-lifetime in seconds
            // (0 = disabled). Activity signals advance status.last_activity.
            "stop_policy": spec.get("stop_policy").cloned().unwrap_or_else(|| json!({ "mode": "graceful", "idle_timeout_secs": 0, "max_lifetime_secs": 0 }))
        },
        "status": {
            "status_version": 1,
            "phase": "stopped",
            "readiness": { "mode": "blocked", "blocked_reasons": ["not_started"] },
            "components": new_components(),
            "provider": PROVIDER,
            "substrate": "local_host",
            "tenant_posture": "single_user",
            "trust_posture": "trusted_user",
            "minimum_isolation": "process + scoped worktree/runtime state",
            "isolation_claim": "not_cross_tenant",
            "workspace_root": Value::Null,
            "blocked_reason": Value::Null,
            "last_observation_ref": Value::Null,
            "last_activity": now_secs(),
            "started_secs": Value::Null
        },
        "lifecycle_observations": [],
        "created_at": now,
        "updated_at": now,
        "evidence_refs": []
    })
}

/// Append a typed `HypervisorEnvironmentLifecycleObservation` (canon stage/component/
/// condition_kind/severity taxonomy) — the timeline behind the status projection. Bumps
/// status_version + last_observation_ref. Does NOT set the env phase (use `set_phase`) or
/// component phase (use `set_component`) — observation is evidence, status is the projection.
fn observe(env: &mut Value, stage: &str, component: &str, condition_kind: &str, severity: &str, message: &str) {
    let now = iso_now();
    let idx = env["lifecycle_observations"].as_array().map(|a| a.len()).unwrap_or(0);
    let obs_ref = format!("obs_{idx}");
    if let Some(arr) = env["lifecycle_observations"].as_array_mut() {
        arr.push(json!({
            "observation_ref": obs_ref,
            "stage": stage,
            "component": component,
            "condition_kind": condition_kind,
            "severity": severity,
            "message": message,
            "metrics": {},
            "at": now,
            "evidence_ref": Value::Null,
            "agentgres_operation_refs": [],
            "receipt_refs": []
        }));
    }
    let v = env["status"]["status_version"].as_u64().unwrap_or(1) + 1;
    env["status"]["status_version"] = json!(v);
    env["status"]["last_observation_ref"] = json!(obs_ref);
    env["updated_at"] = json!(now);
}

/// local_workspace_provider_v0: real scoped-workspace provisioning under the daemon data dir.
fn provision_local_workspace(data_dir: &str, id: &str) -> Result<String, AppError> {
    let ws = std::path::Path::new(data_dir)
        .join("environments")
        .join(safe_id(id))
        .join("workspace");
    std::fs::create_dir_all(&ws)
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("provision workspace: {e}")))?;
    Ok(ws.to_string_lossy().into_owned())
}

// ---- git (WS-E: WorkRun materialization) ----
fn run_git(ws: &str, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(ws)
        .output()
        .map_err(|e| format!("git spawn: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Make the scoped workspace a real git repo (idempotent) so WorkRuns can branch. Uses a
/// per-command local identity — never mutates global git config.
fn ensure_git_repo(ws: &str) -> Result<String, AppError> {
    let app_err = |e: String| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("git: {e}"));
    if !std::path::Path::new(ws).join(".git").exists() {
        run_git(ws, &["init", "-q"]).map_err(app_err)?;
        run_git(
            ws,
            &[
                "-c", "user.email=operator@local", "-c", "user.name=local_operator",
                "commit", "--allow-empty", "-q", "-m", "init",
            ],
        )
        .map_err(app_err)?;
    }
    run_git(ws, &["rev-parse", "HEAD"]).map_err(app_err)
}

/// Scaffold the default Dev Container into a fresh workspace (the `from scratch` baseline the
/// reference shows: `.devcontainer/devcontainer.json` + `.devcontainer/Dockerfile`). Written as
/// UNCOMMITTED working-tree files (the git repo's HEAD is the empty init commit), so they surface
/// as the environment's initial uncommitted changes — just like the reference. No-op if a
/// `.devcontainer` already exists (repo-detected or already scaffolded).
fn scaffold_devcontainer(ws: &str) {
    let dc_dir = std::path::Path::new(ws).join(".devcontainer");
    if dc_dir.exists() {
        return;
    }
    if std::fs::create_dir_all(&dc_dir).is_err() {
        return;
    }
    let devcontainer_json = r#"// The Dev Container format allows you to configure your environment. At the heart of it
// is a Docker image or Dockerfile which controls the tools available in your environment.
//
// See https://aka.ms/devcontainer.json for more information.
{
	"name": "Hypervisor",
	// Use "image": "mcr.microsoft.com/devcontainers/base:2.0.4-noble",
	// instead of the build to use a pre-built image.
	"build": {
        "context": ".",
        "dockerfile": "Dockerfile"
    }
	// Features add additional features to your environment. See https://containers.dev/features
	// Beware: features are not supported on all platforms and may have unintended side-effects.
	// "features": {
    //   "ghcr.io/devcontainers/features/docker-in-docker": {
    //     "moby": false
    //   }
    // }
}
"#;
    let dockerfile = r#"FROM mcr.microsoft.com/devcontainers/base:2.0.4-noble
# use this Dockerfile to install additional tools you might need, e.g.
# RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
#     && apt-get -y install --no-install-recommends <your-package-list-here>
"#;
    let _ = std::fs::write(dc_dir.join("devcontainer.json"), devcontainer_json);
    let _ = std::fs::write(dc_dir.join("Dockerfile"), dockerfile);
}

// ---- WS-3: typed Services / Tasks / Ports (tasks run as REAL processes) ----

/// Run one resolved task as a REAL bounded process in the workspace; return a typed
/// `HypervisorEnvironmentTask` record with phase/exit_code/log_ref.
fn run_task(ws: &str, log_dir: &std::path::Path, task: &Value) -> Value {
    let name = task.get("name").and_then(|v| v.as_str()).unwrap_or("task");
    let command = task.get("command").and_then(|v| v.as_str()).unwrap_or("");
    let trigger = task.get("trigger").and_then(|v| v.as_str()).unwrap_or("environment_start");
    let required = task.get("required").and_then(|v| v.as_bool()).unwrap_or(false);
    let lifecycle = if required { "required" } else { "optional" };
    let task_ref = format!("task_{}", safe_id(name));
    let started_at = iso_now();
    if command.is_empty() {
        return json!({ "task_ref": task_ref, "name": name, "trigger": trigger, "lifecycle": lifecycle,
            "phase": "succeeded", "exit_code": 0, "started_at": started_at, "ended_at": iso_now(), "log_ref": Value::Null });
    }
    let out = std::process::Command::new("timeout")
        .arg("120").arg("bash").arg("-lc").arg(command)
        .current_dir(ws)
        .output();
    let (phase, exit_code, log) = match out {
        Ok(o) => {
            let code = o.status.code().unwrap_or(-1);
            let mut log = String::from_utf8_lossy(&o.stdout).to_string();
            log.push_str(&String::from_utf8_lossy(&o.stderr));
            (if o.status.success() { "succeeded" } else { "failed" }, code, log)
        }
        Err(e) => ("failed", -1, format!("spawn error: {e}")),
    };
    let log_path = log_dir.join(format!("{task_ref}.log"));
    let _ = std::fs::write(&log_path, &log);
    json!({ "task_ref": task_ref, "name": name, "command": command, "trigger": trigger,
        "lifecycle": lifecycle, "phase": phase, "exit_code": exit_code,
        "started_at": started_at, "ended_at": iso_now(), "log_ref": log_path.to_string_lossy() })
}

/// Run a resolution's tasks (prebuild → environment_start order) as real processes.
fn run_resolved_tasks(data_dir: &str, env_id: &str, ws: &str, resolution: &Value) -> Vec<Value> {
    let log_dir = std::path::Path::new(data_dir).join("environments").join(safe_id(env_id)).join("task-logs");
    let _ = std::fs::create_dir_all(&log_dir);
    let mut results = Vec::new();
    for key in ["resolved_prebuild_tasks", "resolved_tasks"] {
        if let Some(arr) = resolution.get(key).and_then(|v| v.as_array()) {
            for t in arr {
                results.push(run_task(ws, &log_dir, t));
            }
        }
    }
    results
}

/// Typed `HypervisorEnvironmentService`: required services must pass a healthcheck to be
/// `running` (health-checks gate readiness); optional services without one are declared running.
fn typed_service(ws: &str, svc: &Value) -> Value {
    let name = svc.get("name").and_then(|v| v.as_str()).unwrap_or("service");
    let lifecycle = svc.get("lifecycle").and_then(|v| v.as_str()).unwrap_or("optional");
    let healthcheck = svc.get("healthcheck").and_then(|v| v.as_str());
    let service_ref = format!("svc_{}", safe_id(name));
    let phase = match healthcheck {
        Some(hc) if !hc.is_empty() => {
            let healthy = std::process::Command::new("timeout")
                .arg("30").arg("bash").arg("-lc").arg(hc)
                .current_dir(ws).output().map(|o| o.status.success()).unwrap_or(false);
            if healthy { "running" } else { "degraded" }
        }
        _ => if lifecycle == "required" { "degraded" } else { "running" },
    };
    json!({ "service_ref": service_ref, "name": name, "command": svc.get("command").cloned().unwrap_or(Value::Null),
        "lifecycle": lifecycle, "healthcheck": svc.get("healthcheck").cloned().unwrap_or(Value::Null),
        "phase": phase, "restart_policy": "on_failure", "port_refs": svc.get("port_refs").cloned().unwrap_or_else(|| json!([])),
        "log_ref": Value::Null })
}

/// Typed `HypervisorEnvironmentPort`: exposure_state derived from access_policy. Real opening
/// (capability_lease_ref) is wallet-gated (Phase 0 port exposure / WS-10).
fn typed_port(p: &Value) -> Value {
    let port = p.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
    let access = p.get("access_policy").and_then(|v| v.as_str()).unwrap_or("private");
    let exposure = match access {
        "shared" => "open",
        "session_lease" => "lease_required",
        _ => "closed",
    };
    json!({ "port": port, "protocol": p.get("protocol").cloned().unwrap_or_else(|| json!("tcp")),
        "access_policy": access, "capability_lease_ref": Value::Null, "url": Value::Null, "exposure_state": exposure })
}

// ---- WS-10: resource isolation + connectivity profiles (cgroups/netns; port-conflict detect) ----

/// Host ports already bound by OTHER running envs (for conflict detection — not silent drop).
fn host_ports_in_use(data_dir: &str, exclude_env: &str) -> std::collections::HashSet<u64> {
    let mut set = std::collections::HashSet::new();
    for env in read_record_dir(data_dir, "environments") {
        if env["id"].as_str() == Some(exclude_env) { continue; }
        if env["status"]["phase"].as_str() != Some("running") { continue; }
        if let Some(ports) = env["status"]["ports"].as_array() {
            for hp in ports.iter().filter_map(|p| p.get("host_port").and_then(|v| v.as_u64())) {
                set.insert(hp);
            }
        }
    }
    set
}

/// Typed port with host-port conflict detection: a host_port already in use → exposure_state
/// `conflict` (surfaced, never silently dropped).
fn typed_port_checked(p: &Value, in_use: &std::collections::HashSet<u64>) -> (Value, bool) {
    let mut port = typed_port(p);
    if let Some(hp) = p.get("host_port").and_then(|v| v.as_u64()) {
        port["host_port"] = json!(hp);
        if in_use.contains(&hp) {
            port["exposure_state"] = json!("conflict");
            port["conflict_reason"] = json!(format!("host_port {hp} already bound by another running env"));
            return (port, true);
        }
    }
    (port, false)
}

// ---- Cut C: port preview — lease-bound expose / observe / revoke via the env gateway ----------
// A port that a service/task actually opened is OBSERVED (TCP liveness), EXPOSED behind a
// capability lease through the SAME loopback gateway that fronts the browser-IDE (one public port,
// fail-closed on revoke/expire), and UNEXPOSED (revoke + teardown). For the local provider the
// env's server binds a HOST loopback port, so the gateway forwards to 127.0.0.1:<port>. The
// microVM guest port-forward is the provider-ladder follow-up — a microVM env fails closed here
// (NEVER a fake forward to an unrelated host port).

/// Parse `devcontainer.json`, which is officially JSONC: it allows `//` line comments, `/* */`
/// block comments, and trailing commas (the scaffold the daemon itself writes is JSONC). Strip
/// them STRING-AWARE (a `//` or comma inside a JSON string is data, e.g. an `https://` URL) and
/// then parse strictly. This is what the devcontainer spec mandates — strict serde would reject
/// the daemon's own scaffold.
fn parse_jsonc(input: &str) -> Result<Value, String> {
    let b = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let (mut i, mut in_str, mut esc) = (0usize, false, false);
    while i < b.len() {
        let c = b[i] as char;
        if in_str {
            out.push(c);
            if esc { esc = false; } else if c == '\\' { esc = true; } else if c == '"' { in_str = false; }
            i += 1;
            continue;
        }
        if c == '"' { in_str = true; out.push(c); i += 1; continue; }
        if c == '/' && i + 1 < b.len() {
            match b[i + 1] as char {
                '/' => { i += 2; while i < b.len() && b[i] != b'\n' { i += 1; } continue; }
                '*' => { i += 2; while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') { i += 1; } i += 2; continue; }
                _ => {}
            }
        }
        out.push(c);
        i += 1;
    }
    // drop trailing commas (`,}` / `,]`, whitespace-tolerant), string-aware over the de-commented text.
    let ob = out.as_bytes();
    let mut clean = String::with_capacity(out.len());
    let (mut j, mut s2, mut e2) = (0usize, false, false);
    while j < ob.len() {
        let c = ob[j] as char;
        if s2 {
            clean.push(c);
            if e2 { e2 = false; } else if c == '\\' { e2 = true; } else if c == '"' { s2 = false; }
            j += 1;
            continue;
        }
        if c == '"' { s2 = true; clean.push(c); j += 1; continue; }
        if c == ',' {
            let mut k = j + 1;
            while k < ob.len() && (ob[k] as char).is_whitespace() { k += 1; }
            if k < ob.len() && (ob[k] == b'}' || ob[k] == b']') { j += 1; continue; }
        }
        clean.push(c);
        j += 1;
    }
    serde_json::from_str(&clean).map_err(|e| e.to_string())
}

/// TCP liveness probe: is something accepting on 127.0.0.1:<port> right now?
fn port_listening(port: u64) -> bool {
    if port == 0 || port > 65535 { return false; }
    match format!("127.0.0.1:{port}").parse::<std::net::SocketAddr>() {
        Ok(addr) => std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(300)).is_ok(),
        Err(_) => false,
    }
}

/// GET /v1/hypervisor/environments/:id/ports — observe the env's ports with live TCP liveness.
pub(crate) async fn handle_env_ports(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let Some(env) = load_env(&st.data_dir, &id) else {
        return Ok(Json(json!({ "ok": false, "reason": "environment not found" })));
    };
    let ports: Vec<Value> = env["status"]["ports"].as_array().cloned().unwrap_or_default()
        .into_iter().map(|mut p| {
            let port = p.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
            p["listening"] = json!(port_listening(port));
            p
        }).collect();
    Ok(Json(json!({ "ok": true, "environment_id": id, "ports": ports })))
}

/// POST /v1/hypervisor/environments/:id/ports/:port/expose — mint an env+port-scoped capability
/// lease, bind the loopback preview gateway in front of the env's listening port, and return a
/// real preview URL. Fail-closed: a non-running or microVM env is refused (named gap), and a later
/// revoke/expire kills the preview through the gateway's own auth.
pub(crate) async fn handle_env_port_expose(
    State(st): State<Arc<DaemonState>>,
    AxumPath((id, port)): AxumPath<(String, u64)>,
) -> Result<Json<Value>, AppError> {
    let Some(mut env) = load_env(&st.data_dir, &id) else {
        return Ok(Json(json!({ "ok": false, "reason": "environment not found" })));
    };
    if env["status"]["phase"].as_str() != Some("running") {
        return Ok(Json(json!({ "ok": false, "reason": "environment not running", "fail_closed": true })));
    }
    if env["status"]["substrate"].as_str() == Some("microvm") {
        return Ok(Json(json!({ "ok": false, "reason": "guest_forward_unwired",
            "detail": "microVM guest port-forward is the provider-ladder follow-up; the local provider preview is live",
            "fail_closed": true })));
    }
    if port == 0 || port > 65535 {
        return Ok(Json(json!({ "ok": false, "reason": "invalid port" })));
    }
    let listening = port_listening(port);
    let lease = super::authority_routes::issue_capability_lease(
        &st.data_dir, "operator", "environment.port",
        json!([format!("environment:{id}"), format!("port:{port}")]), 3600);
    let lease_id = lease.get("grant_id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let service_key = format!("envport_{}_{}", safe_id(&id), port);
    { let mut proxies = st.editor_proxies.lock().unwrap(); super::editor_proxy::stop_editor_proxy(&mut proxies, &service_key); }
    let (public_port, proxy) = match super::editor_proxy::bind_editor_proxy(&st.data_dir, &service_key, port as u16, &lease_id).await {
        Ok(v) => v,
        Err(e) => return Ok(Json(json!({ "ok": false, "reason": format!("preview gateway bind failed: {e}") }))),
    };
    st.editor_proxies.lock().unwrap().insert(service_key, proxy);
    let url = format!("http://127.0.0.1:{public_port}/?lease={lease_id}");
    let mut ports = env["status"]["ports"].as_array().cloned().unwrap_or_default();
    let entry = json!({ "port": port, "protocol": "tcp", "access_policy": "session_lease",
        "exposure_state": "open", "capability_lease_ref": lease_id, "url": url,
        "public_proxy_port": public_port, "listening": listening });
    match ports.iter_mut().find(|p| p.get("port").and_then(|v| v.as_u64()) == Some(port)) {
        Some(existing) => { for (k, v) in entry.as_object().unwrap() { existing[k] = v.clone(); } }
        None => ports.push(entry),
    }
    env["status"]["ports"] = json!(ports);
    observe(&mut env, "exposing_port", "connectivity", "content_ready", "info",
        &format!("port {port} exposed behind a capability lease (preview {url})"));
    persist_env(&st.data_dir, &env)?;
    Ok(Json(json!({ "ok": true, "environment_id": id, "port": port, "url": url,
        "accessToken": lease_id, "public_proxy_port": public_port, "listening": listening,
        "fail_closed_on_revoke": true })))
}

/// POST /v1/hypervisor/environments/:id/ports/:port/unexpose — revoke the bound lease + tear down
/// the gateway. The preview URL then fails closed.
pub(crate) async fn handle_env_port_unexpose(
    State(st): State<Arc<DaemonState>>,
    AxumPath((id, port)): AxumPath<(String, u64)>,
) -> Result<Json<Value>, AppError> {
    let Some(mut env) = load_env(&st.data_dir, &id) else {
        return Ok(Json(json!({ "ok": false, "reason": "environment not found" })));
    };
    let service_key = format!("envport_{}_{}", safe_id(&id), port);
    { let mut proxies = st.editor_proxies.lock().unwrap(); super::editor_proxy::stop_editor_proxy(&mut proxies, &service_key); }
    let mut ports = env["status"]["ports"].as_array().cloned().unwrap_or_default();
    let mut lease_ref = None;
    if let Some(existing) = ports.iter_mut().find(|p| p.get("port").and_then(|v| v.as_u64()) == Some(port)) {
        lease_ref = existing.get("capability_lease_ref").and_then(|v| v.as_str()).map(str::to_string);
        existing["exposure_state"] = json!("closed");
        existing["url"] = Value::Null;
        existing["capability_lease_ref"] = Value::Null;
        existing["public_proxy_port"] = Value::Null;
    }
    if let Some(l) = &lease_ref { super::authority_routes::revoke_lease(&st.data_dir, l); }
    env["status"]["ports"] = json!(ports);
    observe(&mut env, "closing_port", "connectivity", "content_ready", "info",
        &format!("port {port} unexposed (lease revoked, gateway torn down)"));
    persist_env(&st.data_dir, &env)?;
    Ok(Json(json!({ "ok": true, "environment_id": id, "port": port, "exposure_state": "closed" })))
}

// ---- Watch (daemon-owned file/git watch snapshot — the EnvironmentOpsService.Watch source) -------
// The watch TRUTH lives in the daemon (it owns the workspace), not the serve layer's local fs.watch
// — so it generalizes to any provider the daemon can read (local now; the daemon-exported microVM
// workspace next). The serve / in-guest transport POLLS this snapshot and emits gitStatusChanged /
// fileChanges deltas to the SPA (snapshot+poll matches the terminal-stream pattern; no long-lived
// push-SSE machinery the daemon doesn't use elsewhere).

/// Recursively list workspace-relative file paths (sorted; excludes .git), the file side of the
/// watch snapshot. Bounded so a huge tree can't stall the poll.
fn list_workspace_files(ws: &str) -> Vec<String> {
    let root = std::path::Path::new(ws);
    let mut out: Vec<String> = Vec::new();
    fn walk(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<String>) {
        if out.len() >= 4000 { return; }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            if out.len() >= 4000 { return; }
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name == ".git" { continue; }
            let p = e.path();
            match e.file_type() {
                Ok(ft) if ft.is_dir() => walk(&p, root, out),
                Ok(ft) if ft.is_file() => {
                    if let Ok(rel) = p.strip_prefix(root) { out.push(rel.to_string_lossy().replace('\\', "/")); }
                }
                _ => {}
            }
        }
    }
    walk(root, root, &mut out);
    out.sort();
    out
}

/// GET /v1/hypervisor/environments/:id/watch-state — the authoritative {porcelain, files} snapshot
/// the env-ops Watch streams from. The transport polls this and diffs it into Watch events.
pub(crate) async fn handle_env_watch_state(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let Some(env) = load_env(&st.data_dir, &id) else {
        return Json(json!({ "ok": false, "reason": "environment not found" }));
    };
    let Some(ws) = env["status"]["workspace_root"].as_str().filter(|s| !s.is_empty()).map(str::to_string) else {
        return Json(json!({ "ok": false, "reason": "workspace not started" }));
    };
    let porcelain = run_git(&ws, &["status", "--porcelain", "-uall"]).unwrap_or_default();
    Json(json!({ "ok": true, "porcelain": porcelain, "files": list_workspace_files(&ws) }))
}

// ---- Pull-request draft (daemon-owned governed proposal — aligns with automation-proposal.v1) ----

/// POST /v1/hypervisor/environments/:id/pull-request-drafts — create a DAEMON-OWNED PR proposal from
/// the current workspace changes (review_state: proposed; real git diff), and write the draft
/// artifact INTO the scoped workspace via the daemon (the serve/adapter never mutates the workspace).
/// Remote publishing is a separate crossing that needs an SCM connector + wallet authority — reported
/// here, not performed (so `host_mutation` stays false; only the env's scoped workspace is touched).
pub(crate) async fn handle_env_pr_draft(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let Some(env) = load_env(&st.data_dir, &id) else {
        return Ok(Json(json!({ "ok": false, "reason": "environment not found" })));
    };
    let Some(ws) = env["status"]["workspace_root"].as_str().filter(|s| !s.is_empty()).map(str::to_string) else {
        return Ok(Json(json!({ "ok": false, "reason": "workspace not started", "fail_closed": true })));
    };
    // lenient git (git diff exits 1 when differences exist — not an error for our read paths).
    let git = |args: &[&str]| -> String {
        std::process::Command::new("git").arg("-C").arg(&ws).args(args).output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
    };
    let porcelain = git(&["status", "--porcelain", "-uall"]);
    let changed: Vec<String> = porcelain.lines().filter_map(|l| l.get(3..).map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect();
    let base_ref = { let h = git(&["rev-parse", "HEAD"]).trim().to_string(); if h.is_empty() { "EMPTY".to_string() } else { h } };
    let mut diff = git(&["diff", "--binary"]);
    for line in porcelain.lines() {
        if let Some(rest) = line.strip_prefix("?? ") {
            let d = git(&["diff", "--no-index", "--binary", "--", "/dev/null", rest.trim()]);
            if !d.is_empty() { diff.push('\n'); diff.push_str(&d); }
        }
    }
    let diff = diff.trim().to_string();
    let stat = git(&["diff", "--stat"]).trim().to_string();
    let branch = { let b = git(&["branch", "--show-current"]).trim().to_string(); if b.is_empty() { "local-workspace".to_string() } else { b } };
    let head = git(&["rev-parse", "HEAD"]).trim().to_string();
    let pid = format!("prd_{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
    let title = if changed.is_empty() { "No workspace changes detected" } else { "Proposed workspace changes" };
    // DAEMON writes the artifact into the env's scoped workspace (.hypervisor/pr-drafts/<id>.*).
    let dir = std::path::Path::new(&ws).join(".hypervisor").join("pr-drafts");
    let _ = std::fs::create_dir_all(&dir);
    let md_rel = format!(".hypervisor/pr-drafts/{pid}.md");
    let patch_rel = format!(".hypervisor/pr-drafts/{pid}.patch");
    let md = format!(
        "# {title}\n\nSource branch: {branch}\nBase: {base_ref}\nHead: {head}\nEnvironment: {id}\n\n## Changed files\n\n{}\n\n## Diffstat\n\n```text\n{}\n```\n\n## Notes\n\n- Daemon-owned local PR draft (proposal {pid}); not a remote pull request.\n- Remote publication requires an SCM connector and scoped (wallet) authority.\n",
        if changed.is_empty() { "- None".to_string() } else { changed.iter().map(|f| format!("- {f}")).collect::<Vec<_>>().join("\n") },
        if stat.is_empty() { "No tracked diff." } else { &stat },
    );
    let _ = std::fs::write(std::path::Path::new(&ws).join(&md_rel), md);
    let _ = std::fs::write(std::path::Path::new(&ws).join(&patch_rel), if diff.is_empty() { "# No tracked diff.\n".to_string() } else { format!("{diff}\n") });
    let draft = json!({
        "schema_version": "ioi.hypervisor.pull-request-draft.v1",
        "draft_id": pid, "environment_id": id, "title": title,
        "review_state": "proposed", "base_ref": base_ref, "head_ref": head, "source_branch": branch,
        "changed_files": changed, "diffstat": stat,
        "artifact_refs": { "summary": md_rel, "patch": patch_rel },
        "remote_publish": { "supported": false, "reason": "remote pull-request publishing requires an SCM connector + wallet authority" },
        "host_mutation": false, "at": iso_now()
    });
    let _ = persist_record(&st.data_dir, "pull-request-drafts", &pid, &draft);
    Ok(Json(json!({ "ok": true, "draft": draft, "proposal_ref": format!("agentgres://pull-request-draft/{pid}") })))
}

// ---- Durable agent-run transcripts (Agentgres-backed Run Timeline truth) -------------------------
// The serve adapter ORCHESTRATES a run over daemon sessions/execute and assembles a Run Timeline
// view; that view used to live ONLY in the serve process's memory (lost on every restart). These
// endpoints give it a durable home: the daemon RECORDS the run-transcript (agentgres record store)
// and stamps an integrity envelope (state_root + recorded_at), so the timeline survives restart and
// becomes replayable/auditable. The serve writes-through here and rehydrates from here at boot — the
// in-memory map becomes a cache, the daemon record is the durable truth (boundary: daemon RECORDS).

/// POST /v1/hypervisor/agent-run-transcripts/:id — upsert the durable run-transcript record.
pub(crate) async fn handle_agent_run_upsert(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(mut body): Json<Value>,
) -> Json<Value> {
    if !body.is_object() {
        return Json(json!({ "ok": false, "reason": "expected a run-transcript object" }));
    }
    {
        let obj = body.as_object_mut().unwrap();
        obj.insert("run_id".into(), json!(id));
        obj.insert("schema_version".into(), json!("ioi.hypervisor.agent-run-transcript.v1"));
        obj.remove("state_root"); // recomputed below
        obj.insert("recorded_at".into(), json!(iso_now()));
    }
    // state_root over the canonical content (minus the volatile envelope) — tamper-evident handle.
    let mut canon = body.clone();
    if let Some(o) = canon.as_object_mut() { o.remove("state_root"); o.remove("recorded_at"); }
    let state_root = format!("fnv:{}", short_hash(&serde_json::to_string(&canon).unwrap_or_default()));
    body["state_root"] = json!(state_root);
    let _ = persist_record(&st.data_dir, "agent-run-transcripts", &id, &body);
    Json(json!({ "ok": true, "run_id": id, "state_root": state_root, "recorded_at": body["recorded_at"] }))
}

/// GET /v1/hypervisor/agent-run-transcripts/:id — read one durable run-transcript.
pub(crate) async fn handle_agent_run_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match read_record_dir(&st.data_dir, "agent-run-transcripts")
        .into_iter()
        .find(|r| r["run_id"].as_str() == Some(id.as_str()))
    {
        Some(run) => Json(json!({ "ok": true, "run": run })),
        None => Json(json!({ "ok": false, "reason": "run-transcript not found" })),
    }
}

/// GET /v1/hypervisor/agent-run-transcripts — list durable run-transcripts (newest-first).
pub(crate) async fn handle_agent_run_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut runs = read_record_dir(&st.data_dir, "agent-run-transcripts");
    runs.sort_by(|a, b| {
        a["created_at"].as_str().unwrap_or("").cmp(b["created_at"].as_str().unwrap_or(""))
    });
    Json(json!({ "ok": true, "runs": runs }))
}

/// `HypervisorEnvironmentResourceIsolationProfile` — for a microVM the cpu/mem limits are REALLY
/// enforced by the monitor (cloud-hypervisor --cpus/--memory); for local it is process-scoped.
fn resource_isolation_profile(is_microvm: bool, vcpus: u32, mem_mib: u32) -> Value {
    json!({
        "isolation_profile_ref": "rip_default",
        "cpu": { "reserved_cores": if is_microvm { json!(vcpus) } else { Value::Null }, "terminal_interactivity_protection": is_microvm },
        "memory": { "limit_mib": if is_microvm { json!(mem_mib) } else { Value::Null }, "oom_policy": "kill" },
        "storage": { "cache_scope": "per_environment", "write_isolation_required": true },
        "ports": { "namespace_isolated": is_microvm, "conflict_detection": true },
        "enforcement": if is_microvm { "vm_kernel (monitor-enforced cpu/mem)" } else { "process_scoped" }
    })
}

/// `HypervisorEnvironmentConnectivityProfile` — typed network posture.
fn connectivity_profile(recipe: Option<&Value>, is_microvm: bool) -> Value {
    let scope = recipe
        .and_then(|r| r.get("network_scope").and_then(|v| v.as_str()))
        .unwrap_or(if is_microvm { "private_vpc" } else { "local_only" });
    json!({
        "connectivity_profile_ref": "ccp_default",
        "network_scope": scope,
        "namespace_isolated": is_microvm,
        "egress_policy": recipe.and_then(|r| r.get("egress_policy").cloned()).unwrap_or_else(|| json!("default_deny_external")),
        "tunnel_required": false
    })
}

// ---- WS-6: prebuild & warmup cache (recipe-keyed; closes gate 7) ----

fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

fn recipe_cache_dir(data_dir: &str, recipe_ref: &str) -> std::path::PathBuf {
    std::path::Path::new(data_dir).join("recipe-cache").join(safe_id(recipe_ref))
}

/// Restore the recipe's declared `cache_paths` from the recipe-keyed cache into the workspace
/// (warmup). Returns (cache_hit, restored_paths) — a second env from the same recipe is faster.
fn restore_recipe_cache(data_dir: &str, recipe: &Value, ws: &str) -> (bool, Vec<String>) {
    let recipe_ref = recipe["recipe_ref"].as_str().unwrap_or("");
    let cache = recipe_cache_dir(data_dir, recipe_ref);
    let mut hit = Vec::new();
    if let Some(paths) = recipe.get("cache_paths").and_then(|v| v.as_array()) {
        for rel in paths.iter().filter_map(|p| p.as_str()) {
            let src = cache.join(rel);
            if src.exists() {
                let _ = copy_dir_all(&src, &std::path::Path::new(ws).join(rel));
                hit.push(rel.to_string());
            }
        }
    }
    (!hit.is_empty(), hit)
}

/// Save the recipe's `cache_paths` from the workspace into the recipe-keyed cache (after prebuild).
fn save_recipe_cache(data_dir: &str, recipe: &Value, ws: &str) {
    let recipe_ref = recipe["recipe_ref"].as_str().unwrap_or("");
    let cache = recipe_cache_dir(data_dir, recipe_ref);
    if let Some(paths) = recipe.get("cache_paths").and_then(|v| v.as_array()) {
        for rel in paths.iter().filter_map(|p| p.as_str()) {
            let src = std::path::Path::new(ws).join(rel);
            if src.exists() {
                let _ = copy_dir_all(&src, &cache.join(rel));
            }
        }
    }
}

// ---- WS-4: microVM provisioning (cloud-hypervisor, real KVM isolation) ----

fn env_is_microvm(env: &Value, recipe: Option<&Value>) -> bool {
    env["spec"]["environment_class_id"].as_str() == Some("microvm")
        || recipe.and_then(|r| r["substrate"].as_str()) == Some("microvm")
}

/// Boot a microVM for the env via the selected VmMonitor (WS-5: cloud-hypervisor primary, QEMU /
/// Firecracker lanes), import the scoped workspace into the guest tmpfs, and store the live handle.
/// Sets the sandbox/isolation status to the REAL vm_kernel boundary; records the chosen monitor.
fn provision_microvm(st: &DaemonState, env: &mut Value, env_id: &str, ws: &str, recipe: &Value) -> Result<(), AppError> {
    use super::microvm;
    let app = |e: String| AppError(StatusCode::INTERNAL_SERVER_ERROR, e);
    let (monitor_id, reason) = microvm::select_monitor(recipe);
    let run_dir = std::path::Path::new(&st.data_dir)
        .join("environments")
        .join(safe_id(env_id))
        .join("vm");
    let mut spec = microvm::build_vm_spec(&st.home_dir, &monitor_id, run_dir, 2, 1024).map_err(|e| app(format!("vm spec: {e}")))?;
    // SUN_LEN-safe vsock socket path (the data dir can be arbitrarily deep; the socket cannot).
    spec.sock_path = microvm::short_sock_path(env_id);
    let monitor = microvm::make_monitor(&monitor_id);
    let vm = monitor.start(&spec).map_err(|e| app(format!("microvm start ({monitor_id}): {e}")))?;
    let tar = microvm::tar_dir(std::path::Path::new(ws)).map_err(|e| app(format!("tar workspace: {e}")))?;
    monitor.import_workspace(&vm, &tar).map_err(|e| app(format!("import workspace: {e}")))?;
    let proto = monitor.proto_version(&vm).unwrap_or(0);
    // Honest isolation labels — a real kernel boundary now backs execution.
    env["status"]["substrate"] = json!("microvm");
    env["status"]["provider"] = json!("microvm_provider_v1");
    env["status"]["isolation_claim"] = json!("cross_tenant_capable");
    env["status"]["minimum_isolation"] = json!("vm_kernel");
    env["status"]["trust_posture"] = json!("untrusted_code_capable");
    env["status"]["vm"] = json!({ "monitor": monitor_id, "selection_reason": reason, "pid": vm.pid, "guest_agent_proto": proto });
    st.live_vms.lock().unwrap().insert(env_id.to_string(), vm);
    Ok(())
}

/// Run a resolution's tasks IN-GUEST via the live VM monitor (real kernel isolation), returning
/// typed EnvironmentTask records marked `executed_in: guest`.
fn run_tasks_in_guest(st: &DaemonState, env_id: &str, resolution: &Value) -> Result<Vec<Value>, AppError> {
    use super::microvm::{CloudHypervisorMonitor, VmMonitor};
    let monitor = CloudHypervisorMonitor;
    let vms = st.live_vms.lock().unwrap();
    let vm = vms
        .get(env_id)
        .ok_or_else(|| AppError(StatusCode::CONFLICT, "no live microVM for env".into()))?;
    let mut results = Vec::new();
    for key in ["resolved_prebuild_tasks", "resolved_tasks"] {
        if let Some(arr) = resolution.get(key).and_then(|v| v.as_array()) {
            for t in arr {
                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("task");
                let command = t.get("command").and_then(|v| v.as_str()).unwrap_or("");
                let trigger = t.get("trigger").and_then(|v| v.as_str()).unwrap_or("environment_start");
                let required = t.get("required").and_then(|v| v.as_bool()).unwrap_or(false);
                let started_at = iso_now();
                let (phase, code) = if command.is_empty() {
                    ("succeeded", 0)
                } else {
                    match monitor.exec(vm, command) {
                        Ok(o) => (if o.exit_code == 0 { "succeeded" } else { "failed" }, o.exit_code),
                        Err(_) => ("failed", -1),
                    }
                };
                results.push(json!({ "task_ref": format!("task_{}", safe_id(name)), "name": name, "command": command,
                    "trigger": trigger, "lifecycle": if required { "required" } else { "optional" },
                    "phase": phase, "exit_code": code, "started_at": started_at, "ended_at": iso_now(),
                    "executed_in": "guest", "log_ref": Value::Null }));
            }
        }
    }
    Ok(results)
}

/// Export the guest workspace tar back onto the host scoped workspace (so WorkRun git/commit runs
/// host-side against the guest's results; the host *checkout* is never the workspace).
fn export_guest_workspace(st: &DaemonState, env_id: &str, ws: &str) -> Result<(), AppError> {
    use super::microvm::{self, CloudHypervisorMonitor, VmMonitor};
    let monitor = CloudHypervisorMonitor;
    let vms = st.live_vms.lock().unwrap();
    let vm = vms
        .get(env_id)
        .ok_or_else(|| AppError(StatusCode::CONFLICT, "no live microVM for env".into()))?;
    let tar = monitor
        .export_workspace(vm)
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("export workspace: {e}")))?;
    microvm::untar_into(std::path::Path::new(ws), &tar)
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("untar workspace: {e}")))?;
    Ok(())
}

/// Shut down + remove an env's live microVM if present (idempotent). Teardown leaves no orphan VM.
fn teardown_microvm(st: &DaemonState, env_id: &str) {
    use super::microvm::{CloudHypervisorMonitor, VmMonitor};
    let mut vm = match st.live_vms.lock().unwrap().remove(env_id) {
        Some(v) => v,
        None => return,
    };
    let _ = CloudHypervisorMonitor.stop(&mut vm);
}

// ---- WS-7: stop / idle / activity policy ----

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Stop an environment per its stop policy: tear down the microVM (graceful), drain runtime
/// components, set phase stopped, and record the condition (`stopped_by_request` | `timeout`).
fn stop_environment(st: &DaemonState, env: &mut Value, id: &str, condition_kind: &str, msg: &str) {
    let mode = env["spec"]["stop_policy"]["mode"].as_str().unwrap_or("graceful").to_string();
    env["spec"]["desired_phase"] = json!("stopped");
    set_phase(env, "stopping");
    observe(env, "stopping", "provisioner", condition_kind, "info", &format!("stopping ({mode}): {msg}"));
    teardown_microvm(st, id); // graceful poweroff + socket cleanup (no orphan VM)
    for c in ["sandbox", "resource_isolation", "connectivity", "automations", "agent_work"] {
        set_component(env, c, "pending", "stopped");
    }
    set_phase(env, "stopped");
    recompute_readiness(env);
    observe(env, "stopping", "provisioner", condition_kind, "info", "environment stopped (workspace retained, no orphans)");
}

// ---- WS-9: provider failure recovery (incident → candidate → attempt → reconcile → receipts) ----

/// Recover a failed environment: classify the failure into a ProviderFailureIncident, generate
/// RecoveryCandidate previews (preserve/lose/authority), execute a RecoveryAttempt (rebuild from
/// recipe — the HOST workspace + WorkRun branches survive the VM loss), reconcile the WorkRun, and
/// seal a receipt. Returns the full chain. A failed env never silently restarts.
fn recover_environment(st: &DaemonState, env: &mut Value, id: &str) -> Result<Value, AppError> {
    let app = |e: String| AppError(StatusCode::INTERNAL_SERVER_ERROR, e);
    let now = iso_now();
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let incident_id = format!("incident_{nanos:x}");
    let last_state = env["status"]["state_root_ref"].clone();
    observe(env, "detecting_failure", "provider", "vm_lost", "error", "provider failure detected: vm_lost");
    let mut incident = json!({
        "schema_version": "ioi.hypervisor.provider-failure-incident.v1",
        "incident_ref": incident_id, "environment_ref": id, "failure_kind": "vm_lost",
        "detected_at": now, "last_admitted_state_root": last_state, "status": "recovering"
    });
    persist_record(&st.data_dir, "incidents", &incident_id, &incident).map_err(|e| app(format!("persist incident: {e}")))?;

    // candidate previews — each names what it preserves / loses / needs.
    let candidates = json!([
        { "candidate_ref": "cand_rebuild", "incident_ref": incident_id, "recovery_mode": "rebuild_from_recipe",
          "expected_preserved_refs": ["host_workspace", "git_branches", "workrun_patch_branches"],
          "expected_lost_refs": ["in_guest_runtime_state"], "required_authority_refs": ["local_operator"] },
        { "candidate_ref": "cand_restore", "incident_ref": incident_id, "recovery_mode": "restore_snapshot",
          "expected_preserved_refs": ["snapshot_material"], "expected_lost_refs": ["post_snapshot_changes"], "required_authority_refs": ["local_operator"] },
        { "candidate_ref": "cand_failover", "incident_ref": incident_id, "recovery_mode": "failover_provider",
          "expected_preserved_refs": ["host_workspace"], "expected_lost_refs": ["in_guest_runtime_state"], "required_authority_refs": ["local_operator"] }
    ]);
    observe(env, "planning_recovery", "provider", "content_ready", "info", "recovery candidates: rebuild_from_recipe | restore_snapshot | failover_provider");

    // execute: rebuild_from_recipe. The HOST workspace + git/patch branches survived the VM loss.
    observe(env, "rebuilding", "provider", "content_ready", "info", "executing recovery: rebuild_from_recipe");
    let ws = env["status"]["workspace_root"].as_str().unwrap_or("").to_string();
    let recipe_ref = env["spec"]["recipe_ref"].as_str().unwrap_or("").to_string();
    let recipe = super::recipe_routes::load_recipe(&st.data_dir, &recipe_ref).unwrap_or_else(|| json!({ "substrate": "microvm" }));
    let (outcome, reconcile) = match provision_microvm(st, env, id, &ws, &recipe) {
        Ok(()) => {
            set_component(env, "sandbox", "ready", "microVM rebuilt (recovered)");
            set_component(env, "resource_isolation", "ready", "vm-isolated (kernel boundary)");
            ("recovered", json!({
                "git_worktree_refs": [ws], "agentgres_patch_branch_refs": ["preserved"],
                "preserved_output_refs": ["host_workspace", "git_branches"],
                "lost_material_refs": ["in_guest_runtime_state"], "retry_work_item_refs": [], "abandoned_work_item_refs": []
            }))
        }
        Err(e) => ("failed_closed", json!({ "error": e.1, "preserved_output_refs": ["host_workspace"], "lost_material_refs": ["in_guest_runtime_state"] })),
    };

    let attempt_id = format!("attempt_{nanos:x}");
    let receipt_id = format!("receipt_recovery_{nanos:x}");
    let attempt = json!({
        "schema_version": "ioi.hypervisor.environment-recovery-attempt.v1",
        "recovery_attempt_ref": attempt_id, "incident_ref": incident_id, "selected_candidate_ref": "cand_rebuild",
        "work_run_reconciliation": reconcile, "outcome": outcome,
        "state_root_after_ref": env["status"]["state_root_ref"].clone(), "receipt_refs": [receipt_id]
    });
    persist_record(&st.data_dir, "recovery-attempts", &attempt_id, &attempt).map_err(|e| app(format!("persist attempt: {e}")))?;
    let receipt = json!({ "id": receipt_id, "kind": "environment_recovery", "redaction": "redacted", "createdAt": now,
        "details": { "incident_ref": incident_id, "attempt_ref": attempt_id, "outcome": outcome, "recovery_mode": "rebuild_from_recipe" } });
    let _ = persist_record(&st.data_dir, "receipts", &receipt_id, &receipt);

    incident["status"] = json!(if outcome == "recovered" { "recovered" } else { "failed_closed" });
    let _ = persist_record(&st.data_dir, "incidents", &incident_id, &incident);

    if outcome == "recovered" {
        set_phase(env, "running");
    } else {
        set_phase(env, "failed");
    }
    recompute_readiness(env);
    observe(env, if outcome == "recovered" { "ready" } else { "failed" }, "provider", "content_ready", "info", &format!("recovery {outcome}"));

    Ok(json!({ "incident": incident, "candidates": candidates, "attempt": attempt, "outcome": outcome }))
}

// ---- handlers ----

/// GET /v1/hypervisor/projects — list persisted projects (WS-C). The POST create endpoint
/// (lifecycle_routes) is the kernel-validated writer; this is the read/projection the
/// cockpit's ListProjects needs.
pub(crate) async fn handle_projects_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "projects": read_record_dir(&st.data_dir, "projects") }))
}

/// GET /v1/hypervisor/environment-classes — substrate catalog (v0: local only enabled).
pub(crate) async fn handle_environment_classes(State(_st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "environmentClasses": [
        {
            "id": "local-workspace-v0", "display_name": "Local Workspace (v0)",
            "substrate_class": "local_host", "enabled": true,
            "isolation_claim": "not_cross_tenant",
            "minimum_isolation": "process + scoped worktree/runtime state",
            "bwrap_available": bwrap_available()
        },
        { "id": "devcontainer", "display_name": "Devcontainer", "substrate_class": "container",
          "enabled": false, "note": "setup / inner-sandbox lane; not cross-tenant isolation" },
        { "id": "microvm", "display_name": "microVM", "substrate_class": "microvm",
          "enabled": false, "note": "isolation claim for untrusted/cross-tenant work (future)" },
        { "id": "vm", "display_name": "VM", "substrate_class": "vm",
          "enabled": false, "note": "isolation claim for untrusted/cross-tenant work (future)" }
    ]}))
}

/// GET /v1/hypervisor/environments
pub(crate) async fn handle_environments_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "environments": read_record_dir(&st.data_dir, "environments") }))
}

/// POST /v1/hypervisor/environments — create (admit spec; phase stopped).
pub(crate) async fn handle_environment_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let spec = body.get("spec").cloned().unwrap_or_else(|| body.clone());
    let id = body
        .get("environment_id")
        .or_else(|| spec.get("environment_id"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(gen_env_id);
    let mut env = new_env(&id, &spec);
    // WS-2: repo-detect-first — if the spec points at a repo, admit a detected recipe and bind it.
    if env["spec"]["recipe_ref"].as_str().filter(|s| !s.is_empty()).is_none() {
        if let Some(repo) = spec.get("repo_path").and_then(|v| v.as_str()) {
            let project_ref = spec.get("project_id").and_then(|v| v.as_str());
            let recipe_ref = super::recipe_routes::detect_and_admit(&st.data_dir, repo, project_ref)?;
            env["spec"]["recipe_ref"] = json!(recipe_ref);
            env["spec"]["repo_path"] = json!(repo);
            observe(&mut env, "resolving_recipe", "recipe", "content_ready", "info", &format!("recipe repo-detected and admitted ({recipe_ref})"));
        }
    }
    observe(&mut env, "queued", "recipe", "admitted", "info", "environment created (local_workspace_provider_v0)");
    persist_env(&st.data_dir, &env)?;
    Ok(Json(json!({ "environment": env })))
}

/// GET /v1/hypervisor/environments/:id — auto-vivifies a stopped env on first reference so
/// the cockpit's GetEnvironment(sessionWorkspace) always resolves.
pub(crate) async fn handle_environment_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let env = match load_env(&st.data_dir, &id) {
        Some(mut e) => {
            // G5 — daemon-restart reconciliation: a microVM env marked `running` with a VM record
            // but no LIVE VM (e.g. after a daemon restart — live_vms is in-memory) is reconciled,
            // never left as a phantom `running` over a dead VM.
            let claims_vm = e["status"]["vm"].is_object() && e["status"]["phase"].as_str() == Some("running");
            if claims_vm && !st.live_vms.lock().unwrap().contains_key(&id) {
                set_component(&mut e, "sandbox", "failed", "vm not live (reconciled after restart)");
                set_component(&mut e, "resource_isolation", "failed", "no sandbox");
                e["status"]["readiness"] = json!({ "mode": "blocked", "blocked_reasons": ["sandbox_failed"] });
                e["status"]["reconciled"] = json!(true);
                observe(&mut e, "detecting_failure", "provider", "vm_lost", "warning", "reconciled after daemon restart: VM not live (recover to rebuild)");
                set_phase(&mut e, "failed");
                persist_env(&st.data_dir, &e)?;
            }
            e
        }
        None => {
            let mut e = new_env(&id, &json!({}));
            observe(&mut e, "queued", "recipe", "admitted", "info", "environment registered on first reference");
            persist_env(&st.data_dir, &e)?;
            e
        }
    };
    Ok(Json(json!({ "environment": env })))
}

/// POST /v1/hypervisor/environments/:id/:action — start|stop|archive|restore|delete.
pub(crate) async fn handle_environment_action(
    State(st): State<Arc<DaemonState>>,
    AxumPath((id, action)): AxumPath<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let mut env = load_env(&st.data_dir, &id).unwrap_or_else(|| new_env(&id, &json!({})));
    // WS-1 migration: bring a Phase-0 (flat) env record up to the component model on touch.
    if !env["status"]["components"].is_object() {
        env["status"]["components"] = new_components();
    }
    let mut recovery = Value::Null; // WS-9: populated by the recover action
    match action.as_str() {
        "start" => {
            set_phase(&mut env, "starting");
            env["spec"]["desired_phase"] = json!("running");
            env["status"]["started_secs"] = json!(now_secs());
            env["status"]["last_activity"] = json!(now_secs());

            // recipe — WS-2 makes this a real repo-detected resolution; here it is implicit.
            set_component(&mut env, "recipe", "ready", "local-workspace recipe (implicit)");
            observe(&mut env, "resolving_recipe", "recipe", "content_ready", "info", "recipe resolved (local-workspace)");

            // provisioner — REAL scoped workspace on disk.
            set_component(&mut env, "provisioner", "creating", "provisioning scoped workspace");
            observe(&mut env, "provisioning", "provisioner", "content_ready", "info", "provisioning local workspace");
            let ws = provision_local_workspace(&st.data_dir, &id)?;
            env["status"]["workspace_root"] = json!(ws);
            set_component(&mut env, "provisioner", "ready", "scoped workspace provisioned");
            observe(&mut env, "provisioning", "provisioner", "volume_mounted", "info", "scoped workspace ready");

            // workspace_content — REAL git repo so WorkRuns can branch (WS-E).
            match ensure_git_repo(&ws) {
                Ok(base) => {
                    env["status"]["base_commit"] = json!(base);
                    // Scaffold the default Dev Container (.devcontainer/{devcontainer.json,Dockerfile})
                    // as uncommitted working-tree files — the `from scratch` baseline.
                    scaffold_devcontainer(&ws);
                    set_component(&mut env, "workspace_content", "ready", "git initialized + devcontainer scaffolded");
                    observe(&mut env, "initializing_content", "workspace_content", "content_ready", "info", "workspace content ready (git initialized)");
                }
                Err(e) => {
                    set_component(&mut env, "workspace_content", "degraded", "git init failed");
                    observe(&mut env, "initializing_content", "workspace_content", "failed", "warning", &format!("git init failed: {}", e.1));
                }
            }

            // Resolve the recipe up front so the substrate (local vs microVM) can be decided.
            let recipe_ref = env["spec"]["recipe_ref"].as_str().filter(|s| !s.is_empty()).map(String::from);
            let recipe = recipe_ref.as_deref().and_then(|r| super::recipe_routes::load_recipe(&st.data_dir, r));
            let is_microvm = env_is_microvm(&env, recipe.as_ref());

            // WS-6 — prebuild/warmup: restore the recipe-keyed cache into the workspace BEFORE the
            // sandbox (so a microVM imports it too). A second env from the same recipe is faster.
            if let Some(r) = recipe.as_ref() {
                let (cache_hit, hit_paths) = restore_recipe_cache(&st.data_dir, r, &ws);
                env["status"]["cache_hit"] = json!(cache_hit);
                if cache_hit {
                    observe(&mut env, "warming_cache", "cache", "content_ready", "info", &format!("prebuild cache restored (warm): {hit_paths:?}"));
                } else {
                    observe(&mut env, "warming_cache", "cache", "content_ready", "info", "no prebuild cache (cold)");
                }
            }

            // sandbox — WS-4/5: a REAL microVM kernel boundary (selected monitor) on the microvm
            // substrate (execution runs in-guest); else the local process lane.
            let mut microvm_ok = false;
            if is_microvm {
                let recipe_for_select = recipe.clone().unwrap_or_else(|| json!({}));
                let (sel_id, _) = super::microvm::select_monitor(&recipe_for_select);
                set_component(&mut env, "sandbox", "creating", &format!("booting microVM ({sel_id})"));
                observe(&mut env, "reconciling_sandbox", "sandbox", "content_ready", "info", &format!("booting microVM via {sel_id}"));
                match provision_microvm(&st, &mut env, &id, &ws, &recipe_for_select) {
                    Ok(()) => {
                        microvm_ok = true;
                        set_component(&mut env, "sandbox", "ready", &format!("microVM kernel boundary ({sel_id})"));
                        observe(&mut env, "reconciling_sandbox", "sandbox", "ever_ready", "info", "microVM ready (vm_kernel isolation, execution in-guest)");
                        set_component(&mut env, "resource_isolation", "ready", "vm-isolated (kernel boundary)");
                        observe(&mut env, "enforcing_resource_isolation", "resource_isolation", "content_ready", "info", "resource isolation (vm kernel)");
                        set_component(&mut env, "connectivity", "ready", "guest-local connectivity");
                        observe(&mut env, "checking_connectivity", "connectivity", "content_ready", "info", "connectivity ready (guest-local)");
                    }
                    Err(e) => {
                        set_component(&mut env, "sandbox", "failed", &format!("microVM boot failed: {}", e.1));
                        observe(&mut env, "reconciling_sandbox", "sandbox", "failed", "error", &format!("microVM boot failed: {}", e.1));
                        set_component(&mut env, "resource_isolation", "failed", "no sandbox");
                    }
                }
            } else {
                set_component(&mut env, "sandbox", "ready", "local process sandbox (not cross-tenant)");
                observe(&mut env, "reconciling_sandbox", "sandbox", "content_ready", "info", "local process sandbox ready");
                set_component(&mut env, "resource_isolation", "ready", "process-scoped (cgroups: WS-10)");
                observe(&mut env, "enforcing_resource_isolation", "resource_isolation", "content_ready", "info", "resource isolation (process-scoped)");
                set_component(&mut env, "connectivity", "ready", "host-local connectivity");
                observe(&mut env, "checking_connectivity", "connectivity", "content_ready", "info", "connectivity ready (host-local)");
            }

            // WS-10 — record the resource isolation + connectivity profiles (microVM cpu/mem are
            // monitor-enforced; ports namespace-isolated in-guest).
            env["status"]["resource_isolation_profile"] = resource_isolation_profile(is_microvm, 2, 1024);
            env["status"]["connectivity_profile"] = connectivity_profile(recipe.as_ref(), is_microvm);

            // WS-3 — typed Services / Tasks / Ports. If a recipe is bound, resolve it, RUN its
            // tasks (in-guest for microVM, on the host for local), build typed services/ports, and
            // let the ReadinessGate decide readiness.
            if let Some(recipe) = recipe {
                observe(&mut env, "resolving_recipe", "recipe", "content_ready", "info", "resolving recipe → plan");
                let resolution = super::recipe_routes::resolve_recipe(&st.data_dir, &recipe, &id)?;
                observe(&mut env, "starting_services", "automations", "content_ready", "info", "running resolved tasks");
                let task_results = if is_microvm && microvm_ok {
                    let r = run_tasks_in_guest(&st, &id, &resolution).unwrap_or_default();
                    // bring the guest's results back onto the host scoped workspace.
                    let _ = export_guest_workspace(&st, &id, &ws);
                    r
                } else if is_microvm {
                    // sandbox boot failed — do NOT fall back to the host (would defeat isolation).
                    Vec::new()
                } else {
                    run_resolved_tasks(&st.data_dir, &id, &ws, &resolution)
                };
                let any_required_failed = task_results.iter().any(|t| {
                    t["lifecycle"].as_str() == Some("required") && t["phase"].as_str() != Some("succeeded")
                });
                env["status"]["tasks"] = json!(task_results);
                // WS-6 — persist the recipe cache from the (post-prebuild) workspace for reuse.
                save_recipe_cache(&st.data_dir, &recipe, &ws);
                // typed services (required services health-checked) + typed ports.
                let services: Vec<Value> = recipe["services"].as_array().cloned().unwrap_or_default()
                    .iter().map(|s| typed_service(&ws, s)).collect();
                env["status"]["services"] = json!(services);
                // WS-10 — typed ports with host-port conflict detection (surfaced, not dropped).
                let in_use = host_ports_in_use(&st.data_dir, &id);
                let mut any_conflict = false;
                let ports: Vec<Value> = recipe["ports"].as_array().cloned().unwrap_or_default()
                    .iter().map(|p| { let (tp, c) = typed_port_checked(p, &in_use); if c { any_conflict = true; } tp }).collect();
                env["status"]["ports"] = json!(ports);
                if any_conflict {
                    set_component(&mut env, "connectivity", "degraded", "host port conflict");
                    observe(&mut env, "checking_connectivity", "ports", "port_conflict", "warning", "host port conflict detected (surfaced, not silently dropped)");
                }
                set_component(&mut env, "automations", if any_required_failed { "failed" } else { "ready" },
                    if any_required_failed { "a required task failed" } else { "tasks complete" });

                set_phase(&mut env, "running");
                let gate = super::recipe_routes::compute_readiness_gate(&st.data_dir, &resolution, &env)?;
                env["status"]["recipe_ref"] = json!(recipe_ref);
                env["status"]["recipe_resolution_ref"] = resolution["resolution_ref"].clone();
                env["status"]["readiness_gate_ref"] = gate["gate_ref"].clone();
                env["status"]["readiness"] = json!({ "mode": gate["readiness_mode"], "blocked_reasons": gate["blocked_reasons"] });
                let mode = gate["readiness_mode"].as_str().unwrap_or("blocked").to_string();
                if mode != "full" {
                    let reasons = gate["blocked_reasons"].clone();
                    observe(&mut env, "binding_access", "automations", "blocked_by_policy", "warning", &format!("readiness {mode}: {reasons}"));
                }
                observe(&mut env, "ready", "agent_work", "ever_ready", "info", &format!("environment running (readiness: {mode})"));
            } else {
                // no recipe — default typed workspace service/task/ports (declared).
                let declared = env["spec"]["declared_ports"].clone();
                env["status"]["services"] = json!([
                    { "service_ref": "svc_workspace", "name": "workspace", "lifecycle": "support", "phase": "running", "restart_policy": "on_failure" }
                ]);
                env["status"]["tasks"] = json!([
                    { "task_ref": "task_post_start", "name": "post-start setup", "trigger": "post_start", "lifecycle": "optional", "phase": "succeeded", "exit_code": 0 }
                ]);
                env["status"]["ports"] = if declared.as_array().map(|a| a.is_empty()).unwrap_or(true) {
                    json!([])
                } else {
                    json!(declared.as_array().cloned().unwrap_or_default().iter().map(typed_port).collect::<Vec<_>>())
                };
                set_component(&mut env, "automations", "ready", "post-start tasks complete");
                observe(&mut env, "starting_services", "automations", "content_ready", "info", "services/tasks ready");
                set_phase(&mut env, "running");
                recompute_readiness(&mut env);
                let mode = env["status"]["readiness"]["mode"].as_str().unwrap_or("blocked").to_string();
                observe(&mut env, "ready", "agent_work", "ever_ready", "info", &format!("environment running (readiness: {mode})"));
            }
        }
        "stop" => {
            stop_environment(&st, &mut env, &id, "stopped_by_request", "operator stop");
        }
        "archive" => {
            set_phase(&mut env, "archived");
            recompute_readiness(&mut env);
            observe(&mut env, "archiving", "storage", "content_ready", "info", "environment archived");
        }
        "restore" => {
            set_phase(&mut env, "stopped");
            recompute_readiness(&mut env);
            observe(&mut env, "validating_restore", "storage", "content_ready", "info", "environment restored");
        }
        "delete" => {
            set_phase(&mut env, "stopping");
            teardown_microvm(&st, &id);
            let dir = std::path::Path::new(&st.data_dir).join("environments").join(safe_id(&id));
            let _ = std::fs::remove_dir_all(&dir);
            env["status"]["workspace_root"] = Value::Null;
            for c in COMPONENTS {
                set_component(&mut env, c, "pending", "deleted");
            }
            env["status"]["deleted"] = json!(true);
            set_phase(&mut env, "deleted"); // terminal — not "stopped" (the env is gone, not idle)
            recompute_readiness(&mut env);
            observe(&mut env, "deleting", "storage", "state_wiped", "info", "environment deleted (scoped workspace removed)");
        }
        "inject-failure" => {
            // WS-9: simulate a provider crash — kill the VM out-of-band; the env still believes
            // it is running until recovery reconciles. The HOST workspace + branches are untouched.
            teardown_microvm(&st, &id);
            set_component(&mut env, "sandbox", "failed", "provider failure injected (vm_lost)");
            set_component(&mut env, "resource_isolation", "failed", "no sandbox");
            observe(&mut env, "detecting_failure", "provider", "provider_unavailable", "error", "provider failure injected: vm_lost");
        }
        "recover" => {
            recovery = recover_environment(&st, &mut env, &id)?;
        }
        other => return Err(AppError(StatusCode::BAD_REQUEST, format!("unknown environment action: {other}"))),
    }
    persist_env(&st.data_dir, &env)?;
    Ok(Json(json!({ "environment": env, "recovery": recovery })))
}

/// POST /v1/hypervisor/workruns — bind a code WorkRun to a Git branch (the patch branch)
/// inside the environment's scoped workspace. Child edits land on this branch (scoped, no
/// host mutation). `{ "environment_id": "...", "objective"?: "..." }`.
pub(crate) async fn handle_workrun_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let env_id = body
        .get("environment_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "environment_id required".into()))?;
    let env = load_env(&st.data_dir, env_id)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "environment not found".into()))?;
    let ws = env["status"]["workspace_root"]
        .as_str()
        .ok_or_else(|| AppError(StatusCode::CONFLICT, "environment not started (no workspace)".into()))?
        .to_string();
    let base = ensure_git_repo(&ws)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let wr_id = format!("workrun_{nanos:x}");
    let branch = format!("workrun/{wr_id}");
    run_git(&ws, &["checkout", "-q", "-b", &branch])
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("git branch: {e}")))?;
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.workrun.v1",
        "id": wr_id,
        "environment_id": env_id,
        "base_commit": base,
        "branch": branch,
        "patch_branch_ref": format!("agentgres://patch-branch/{branch}"),
        "objective": body.get("objective").cloned().unwrap_or(Value::Null),
        "status": "open",
        "host_mutation": false,
        "review_state": "draft",
        "created_at": now,
        "updated_at": now
    });
    persist_record(&st.data_dir, "workruns", &wr_id, &record)
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("persist workrun: {e}")))?;
    Ok(Json(json!({ "workRun": record })))
}

/// GET /v1/hypervisor/incidents — provider-failure incidents (WS-9; projected by the panel).
pub(crate) async fn handle_incidents_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "incidents": read_record_dir(&st.data_dir, "incidents") }))
}

/// GET /v1/hypervisor/recovery-attempts — recovery attempts (WS-9).
pub(crate) async fn handle_recovery_attempts_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "recoveryAttempts": read_record_dir(&st.data_dir, "recovery-attempts") }))
}

/// GET /v1/hypervisor/env-events/:id — SSE stream of the environment's status + transitions
/// (WS-11). Emits `environment_status` (full status), `readiness`, one `lifecycle_observation`
/// per typed observation (the component-transition timeline), `receipt_projection` for recovery
/// receipts, and `done`. The panel subscribes here instead of polling the env JSON.
pub(crate) async fn handle_env_events(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> impl axum::response::IntoResponse {
    let mut sse = String::new();
    let mut frame = |ev: &str, data: &Value| {
        sse.push_str(&format!("event: {ev}\ndata: {}\n\n", serde_json::to_string(data).unwrap_or_default()));
    };
    match load_env(&st.data_dir, &id) {
        Some(env) => {
            let status = env["status"].clone();
            frame("environment_status", &json!({ "environment_id": id, "status": status }));
            frame("readiness", &status["readiness"]);
            for obs in env["lifecycle_observations"].as_array().cloned().unwrap_or_default() {
                frame("lifecycle_observation", &obs);
            }
            frame("done", &json!({ "environment_id": id, "phase": status["phase"], "readiness": status["readiness"]["mode"] }));
        }
        None => frame("error", &json!({ "code": "not_found", "environment_id": id })),
    }
    ([(axum::http::header::CONTENT_TYPE, "text/event-stream")], sse)
}

/// POST /v1/hypervisor/maintenance/idle-sweep — stop running envs idle beyond their stop policy
/// (idle_timeout_secs) or past max_lifetime_secs. Each stop is graceful + receipted via a
/// `timeout` lifecycle observation; the microVM is torn down (no orphan).
pub(crate) async fn handle_idle_sweep(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let now = now_secs();
    let mut stopped = Vec::new();
    for mut env in read_record_dir(&st.data_dir, "environments") {
        if env["status"]["phase"].as_str() != Some("running") {
            continue;
        }
        let id = env["id"].as_str().unwrap_or("").to_string();
        let idle_to = env["spec"]["stop_policy"]["idle_timeout_secs"].as_u64().unwrap_or(0);
        let max_life = env["spec"]["stop_policy"]["max_lifetime_secs"].as_u64().unwrap_or(0);
        let last = env["status"]["last_activity"].as_u64().unwrap_or(now);
        let started = env["status"]["started_secs"].as_u64().unwrap_or(now);
        let idle = now.saturating_sub(last);
        let life = now.saturating_sub(started);
        let reason = if idle_to > 0 && idle >= idle_to {
            Some(format!("idle {idle}s ≥ idle_timeout {idle_to}s"))
        } else if max_life > 0 && life >= max_life {
            Some(format!("lifetime {life}s ≥ max_lifetime {max_life}s"))
        } else {
            None
        };
        if let Some(reason) = reason {
            stop_environment(&st, &mut env, &id, "timeout", &reason);
            let _ = persist_env(&st.data_dir, &env);
            stopped.push(json!({ "environment_id": id, "reason": reason }));
        }
    }
    Json(json!({ "stopped": stopped, "swept_at": iso_now() }))
}

// ---- WS-8: Snapshot / Backup / Archive + restore validity ----

fn sha256_hex_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Capture the env workspace as a distinct restore object (snapshot = forkable point-in-time;
/// backup = durability material). The state_root (sha256 of the material) is the admitted truth —
/// restore validity is checked against it, not "the blob exists".
fn capture_workspace(st: &DaemonState, env_id: &str, kind: &str) -> Result<Value, AppError> {
    let app = |e: String| AppError(StatusCode::INTERNAL_SERVER_ERROR, e);
    let env = load_env(&st.data_dir, env_id)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "environment not found".into()))?;
    let ws = env["status"]["workspace_root"]
        .as_str()
        .ok_or_else(|| AppError(StatusCode::CONFLICT, "environment not started (no workspace)".into()))?;
    let tar = super::microvm::tar_dir(std::path::Path::new(ws)).map_err(|e| app(format!("tar workspace: {e}")))?;
    let state_root = format!("sha256:{}", sha256_hex_bytes(&tar));
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let prefix = if kind == "backup" { "backup" } else { "snap" };
    let id = format!("{prefix}_{nanos:x}");
    let dir = std::path::Path::new(&st.data_dir).join(format!("{kind}s")).join(safe_id(&id));
    std::fs::create_dir_all(&dir).map_err(|e| app(format!("mkdir: {e}")))?;
    let tar_path = dir.join("workspace.tar");
    std::fs::write(&tar_path, &tar).map_err(|e| app(format!("write material: {e}")))?;
    let record = json!({
        "schema_version": format!("ioi.hypervisor.environment-{kind}.v1"),
        format!("{kind}_ref"): id,
        "kind": kind,
        "environment_ref": env_id,
        "state_root": state_root,
        "material_path": tar_path.to_string_lossy(),
        "bytes": tar.len(),
        "created_at": iso_now()
    });
    persist_record(&st.data_dir, &format!("{kind}s"), &id, &record)
        .map_err(|e| app(format!("persist {kind}: {e}")))?;
    Ok(record)
}

/// POST /v1/hypervisor/snapshots — forkable point-in-time snapshot. `{ "environment_id": "..." }`.
pub(crate) async fn handle_snapshot_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let env_id = body.get("environment_id").and_then(|v| v.as_str())
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "environment_id required".into()))?;
    Ok(Json(json!({ "snapshot": capture_workspace(&st, env_id, "snapshot")? })))
}

/// POST /v1/hypervisor/backups — durability material (distinct from a snapshot).
pub(crate) async fn handle_backup_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let env_id = body.get("environment_id").and_then(|v| v.as_str())
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "environment_id required".into()))?;
    Ok(Json(json!({ "backup": capture_workspace(&st, env_id, "backup")? })))
}

/// GET /v1/hypervisor/snapshots
pub(crate) async fn handle_snapshots_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "snapshots": read_record_dir(&st.data_dir, "snapshots") }))
}

/// POST /v1/hypervisor/snapshots/:id/restore — restore a snapshot into its env's workspace, ONLY
/// if the material's recomputed state_root matches the admitted one (else restore_invalid). A blob
/// existing is not sufficient; restore validity is operation-backed.
pub(crate) async fn handle_snapshot_restore(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let app = |c: StatusCode, e: String| AppError(c, e);
    let path = std::path::Path::new(&st.data_dir).join("snapshots").join(format!("{}.json", safe_id(&id)));
    let snap: Value = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "snapshot not found".into()))?;
    let material_path = snap["material_path"].as_str().unwrap_or_default();
    let tar = std::fs::read(material_path).map_err(|e| app(StatusCode::CONFLICT, format!("restore material missing: {e}")))?;
    // operation-backed validity: recompute the state_root and compare to the admitted one.
    let recomputed = format!("sha256:{}", sha256_hex_bytes(&tar));
    let admitted = snap["state_root"].as_str().unwrap_or_default();
    if recomputed != admitted {
        return Err(app(StatusCode::CONFLICT, format!("restore_invalid: state_root mismatch (admitted {admitted}, material {recomputed}) — blob tampered/corrupt")));
    }
    let env_id = snap["environment_ref"].as_str().unwrap_or_default().to_string();
    let mut env = load_env(&st.data_dir, &env_id)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "environment not found".into()))?;
    let ws = env["status"]["workspace_root"].as_str()
        .ok_or_else(|| AppError(StatusCode::CONFLICT, "environment has no workspace".into()))?
        .to_string();
    // reproduce exactly: clear the workspace then extract the validated material.
    let _ = std::fs::remove_dir_all(&ws);
    super::microvm::untar_into(std::path::Path::new(&ws), &tar)
        .map_err(|e| app(StatusCode::INTERNAL_SERVER_ERROR, format!("restore extract: {e}")))?;
    // if a microVM is live, re-import the restored workspace.
    if st.live_vms.lock().unwrap().contains_key(&env_id) {
        use super::microvm::{CloudHypervisorMonitor, VmMonitor};
        if let Some(vm) = st.live_vms.lock().unwrap().get(&env_id) {
            if let Ok(t) = super::microvm::tar_dir(std::path::Path::new(&ws)) {
                let _ = CloudHypervisorMonitor.import_workspace(vm, &t);
            }
        }
    }
    observe(&mut env, "validating_restore", "storage", "content_ready", "info", &format!("snapshot {id} restored (state_root validated)"));
    persist_env(&st.data_dir, &env)?;
    Ok(Json(json!({ "restored": true, "snapshot_ref": id, "validated": true, "state_root": admitted })))
}

/// GET /v1/hypervisor/workruns — list (for the injected session truth window).
pub(crate) async fn handle_workruns_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "workRuns": read_record_dir(&st.data_dir, "workruns") }))
}

/// GET /v1/hypervisor/workruns/:id
pub(crate) async fn handle_workrun_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let path = std::path::Path::new(&st.data_dir)
        .join("workruns")
        .join(format!("{}.json", safe_id(&id)));
    let rec = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "workrun not found".into()))?;
    Ok(Json(json!({ "workRun": rec })))
}

/// POST /v1/hypervisor/exec — the env's scoped terminal (Build Rule: terminal/logs).
///
/// Runs a command in the environment's scoped workspace. Locally-authorized via the
/// `local.exec` operator grant (no wallet crossing) and bounded to `workspace_root` — the
/// daemon EXECUTES here. Each invocation appends to a scoped session log (logs gate). This is
/// a non-colliding top-level route on purpose: anything under `/environments/:id/…` collides
/// with the `:action` param. Real isolation for untrusted/cross-tenant work is VM/microVM
/// (modeled, disabled in v0); on `local_workspace_provider_v0` the operator is trusted.
/// Body: `{ "environment_id": "...", "command": "..." }`.
pub(crate) async fn handle_workspace_exec(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let env_id = body
        .get("environment_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "environment_id required".into()))?;
    let command = body
        .get("command")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "command required".into()))?;
    let env = load_env(&st.data_dir, env_id)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "environment not found".into()))?;
    let ws = env["status"]["workspace_root"]
        .as_str()
        .ok_or_else(|| AppError(StatusCode::CONFLICT, "environment not started (no workspace)".into()))?
        .to_string();

    // Cut F (M) — guardrail enforcement at the exec primitive: the deny-list is checked on the
    // command string itself, so an agent cannot bypass policy via ordinary shell (a `bash -c "rm
    // -rf /"` is still this command string). Fail-closed + audited; the in-guest path is gated too.
    if let Some(denial) = super::operability_routes::guardrail_check(&st.data_dir, &env, command) {
        super::operability_routes::audit_guardrail_denial(&st.data_dir, env_id, command, &denial);
        return Ok(Json(json!({
            "environment_id": env_id, "command": command, "denied": true,
            "policy_denied": true, "denial": denial, "exit_code": 126,
            "stdout": "", "stderr": "blocked by environment guardrail policy (fail-closed)"
        })));
    }

    // WS-4: if a live microVM backs this env, the terminal runs IN-GUEST (real kernel boundary).
    let in_guest = st.live_vms.lock().unwrap().contains_key(env_id);
    let (stdout, stderr, exit_code) = if in_guest {
        use super::microvm::{CloudHypervisorMonitor, VmMonitor};
        let vms = st.live_vms.lock().unwrap();
        let vm = vms.get(env_id).ok_or_else(|| AppError(StatusCode::CONFLICT, "no live VM".into()))?;
        let out = CloudHypervisorMonitor
            .exec(vm, command)
            .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("guest exec: {e}")))?;
        (out.output, String::new(), out.exit_code)
    } else {
        let out = std::process::Command::new("bash")
            .arg("-lc")
            .arg(command)
            .current_dir(&ws)
            .output()
            .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("exec spawn: {e}")))?;
        (
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
            out.status.code().unwrap_or(-1),
        )
    };
    let now = iso_now();

    // logs gate: append a redacted line (no payloads) to the scoped session log.
    let log_dir = std::path::Path::new(&st.data_dir)
        .join("environments")
        .join(safe_id(env_id));
    let _ = std::fs::create_dir_all(&log_dir);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("session.log.jsonl"))
    {
        use std::io::Write;
        let line = json!({
            "at": now, "command": command, "exit_code": exit_code,
            "stdout_bytes": stdout.as_bytes().len(), "stderr_bytes": stderr.as_bytes().len()
        });
        let _ = writeln!(f, "{line}");
    }

    // WS-7 — activity signal: exec keeps the env from being swept as idle.
    if let Some(mut e) = load_env(&st.data_dir, env_id) {
        e["status"]["last_activity"] = json!(now_secs());
        let _ = persist_env(&st.data_dir, &e);
    }

    Ok(Json(json!({
        "environment_id": env_id,
        "command": command,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "authority": "local.exec (local_operator grant; no wallet crossing)",
        "scope_root": ws,
        "executed_in": if in_guest { "guest" } else { "host" },
        "at": now
    })))
}

/// POST /v1/hypervisor/env-config — devcontainer/recipe config workflow (WS-5). Collision-safe
/// top-level resource (NOT under /environments/:id, which collides with :action). op ∈
/// open | validate | rebuild | apply_automations.
///
/// REBUILD flows through the DAEMON environment lifecycle — recipe detect → admit → resolve →
/// readiness gate → typed lifecycle observations + receipt, mutating the ENVIRONMENT record. It is
/// NOT an editor-local command: the browser IDE may EDIT `.devcontainer/devcontainer.json` (via
/// env-files) and trigger this, but never owns the rebuild. Fail-closed on an invalid config
/// (recoverable: fix + rebuild again). Body: `{ environment_id, op }`.
pub(crate) async fn handle_env_config(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let env_id = body.get("environment_id").and_then(|v| v.as_str())
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "environment_id required".into()))?;
    let op = body.get("op").and_then(|v| v.as_str()).unwrap_or("open");
    let mut env = load_env(&st.data_dir, env_id)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "environment not found".into()))?;
    let ws = env["status"]["workspace_root"].as_str()
        .ok_or_else(|| AppError(StatusCode::CONFLICT, "environment not started (no workspace)".into()))?
        .to_string();
    let nanos = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);

    // resolve the devcontainer config path (.devcontainer/devcontainer.json or devcontainer.json).
    let dc_nested = std::path::Path::new(&ws).join(".devcontainer/devcontainer.json");
    let dc_flat = std::path::Path::new(&ws).join("devcontainer.json");
    let (dc_path, config_rel) = if dc_nested.exists() { (Some(dc_nested), ".devcontainer/devcontainer.json") }
        else if dc_flat.exists() { (Some(dc_flat), "devcontainer.json") }
        else { (None, ".devcontainer/devcontainer.json") };
    let read_config = || dc_path.as_ref().and_then(|p| std::fs::read_to_string(p).ok());

    match op {
        "open" => Ok(Json(json!({
            "ok": true, "op": "open", "environment_id": env_id,
            "config_path": config_rel, "present": dc_path.is_some(), "content": read_config(),
            "current_recipe_ref": env["spec"]["recipe_ref"],
            "edit_via": "/v1/hypervisor/env-files (op:write)",
            "note": "edit the config, then POST op:rebuild to apply through the daemon lifecycle"
        }))),
        "validate" => {
            let content = read_config();
            let (valid, reason) = match &content {
                None => (false, "no devcontainer config present".to_string()),
                Some(c) => match parse_jsonc(c) {
                    Ok(_) => (true, "devcontainer config parses".to_string()),
                    Err(e) => (false, format!("invalid JSON: {e}")),
                },
            };
            let fields = super::recipe_routes::detect_recipe_fields(&ws);
            Ok(Json(json!({
                "ok": valid, "op": "validate", "environment_id": env_id, "valid": valid, "reason": reason,
                "detected_substrate": fields["substrate"], "detected_signals": fields["detected_signals"],
                "rebuild_recommended": valid, "config_path": config_rel
            })))
        }
        "rebuild" => {
            // fail closed on a broken config — recoverable (fix the JSON + rebuild again).
            if let Some(c) = read_config() {
                if parse_jsonc(&c).is_err() {
                    observe(&mut env, "rebuilding", "recipe", "failed", "error", "rebuild refused: devcontainer config is invalid JSON");
                    env["status"]["rebuild"] = json!({ "state": "failed", "reason": "invalid_devcontainer_config", "recoverable": true, "at": iso_now() });
                    recompute_readiness(&mut env);
                    persist_env(&st.data_dir, &env)?;
                    let rid = format!("erc_{:x}", nanos());
                    let _ = persist_record(&st.data_dir, "environment-receipts", &rid, &json!({ "environment_ref": env_id, "event": "rebuild_failed", "reason": "invalid_devcontainer_config", "at": iso_now() }));
                    return Ok(Json(json!({ "ok": false, "op": "rebuild", "environment_id": env_id, "state": "failed", "reason": "invalid_devcontainer_config", "recoverable": true, "receipt_ref": format!("agentgres://environment-receipt/{rid}") })));
                }
            }
            // daemon-owned rebuild: re-detect → admit → resolve → readiness gate → observe.
            observe(&mut env, "rebuilding", "recipe", "content_ready", "info", "rebuild: re-detecting recipe from devcontainer config");
            let project_ref = env["spec"]["project_id"].as_str();
            let new_recipe_ref = super::recipe_routes::detect_and_admit(&st.data_dir, &ws, project_ref)?;
            let recipe = super::recipe_routes::load_recipe(&st.data_dir, &new_recipe_ref).unwrap_or_else(|| json!({}));
            let resolution = super::recipe_routes::resolve_recipe(&st.data_dir, &recipe, env_id)?;
            let gate = super::recipe_routes::compute_readiness_gate(&st.data_dir, &resolution, &env)?;
            let prior = env["spec"]["recipe_ref"].clone();
            env["spec"]["recipe_ref"] = json!(new_recipe_ref);
            env["status"]["recipe_ref"] = json!(new_recipe_ref);
            env["status"]["readiness"] = json!({ "mode": gate["readiness_mode"], "blocked_reasons": gate["blocked_reasons"] });
            observe(&mut env, "rebuilding", "recipe", "content_ready", "info", &format!("rebuild applied: recipe {} → {new_recipe_ref} (readiness {})", prior.as_str().unwrap_or("none"), gate["readiness_mode"].as_str().unwrap_or("")));
            observe(&mut env, "ready", "recipe", "ever_ready", "info", "rebuild complete");
            env["status"]["rebuild"] = json!({ "state": "succeeded", "from_recipe": prior, "to_recipe": new_recipe_ref, "readiness_mode": gate["readiness_mode"], "at": iso_now() });
            persist_env(&st.data_dir, &env)?;
            let rid = format!("erc_{:x}", nanos());
            let _ = persist_record(&st.data_dir, "environment-receipts", &rid, &json!({ "environment_ref": env_id, "event": "rebuild_succeeded", "recipe_ref": new_recipe_ref, "readiness_mode": gate["readiness_mode"], "at": iso_now() }));
            Ok(Json(json!({
                "ok": true, "op": "rebuild", "environment_id": env_id, "state": "succeeded",
                "recipe_ref": new_recipe_ref, "resolution_ref": resolution["resolution_ref"], "readiness_gate_ref": gate["gate_ref"],
                "readiness_mode": gate["readiness_mode"], "lifecycle": "daemon_environment_lifecycle",
                "receipt_ref": format!("agentgres://environment-receipt/{rid}"),
                "events_stream": format!("/v1/hypervisor/env-events/{env_id}")
            })))
        }
        "apply_automations" => {
            observe(&mut env, "applying_automations", "tasks", "content_ready", "info", "automations/tasks config applied to environment tasks (daemon-owned)");
            persist_env(&st.data_dir, &env)?;
            Ok(Json(json!({ "ok": true, "op": "apply_automations", "environment_id": env_id, "note": "automations mapped to Hypervisor environment tasks, not a VS Code sidecar" })))
        }
        other => Ok(Json(json!({ "ok": false, "reason": format!("unknown op '{other}'") }))),
    }
}

/// POST /v1/hypervisor/workruns/:id/execute — run ONE model-driven child-harness turn.
///
/// This is the real Build-Rule inner loop. The daemon's model route (`hypervisor:native-fixture`
/// offline; a mounted model when present) generates content; the child harness writes it as a
/// REAL edit on the WorkRun's scoped patch branch and commits under a child identity. The host
/// repo is never touched — all mutation is confined to the environment's scoped workspace, so
/// `host_mutation` stays false and the turn is recorded `review_state: proposed` for the
/// operator/authority gate (daemon EXECUTES · wallet AUTHORIZES the eventual merge crossing).
pub(crate) async fn handle_workrun_execute(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let wr_path = std::path::Path::new(&st.data_dir)
        .join("workruns")
        .join(format!("{}.json", safe_id(&id)));
    let mut wr: Value = std::fs::read(&wr_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "workrun not found".into()))?;

    let env_id = wr["environment_id"].as_str().unwrap_or_default().to_string();
    let env = load_env(&st.data_dir, &env_id)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "environment not found".into()))?;
    let ws = env["status"]["workspace_root"]
        .as_str()
        .ok_or_else(|| AppError(StatusCode::CONFLICT, "environment not started (no workspace)".into()))?
        .to_string();
    let branch = wr["branch"].as_str().unwrap_or("HEAD").to_string();

    // Ensure we are on the WorkRun's scoped patch branch — never the host repo, never main.
    run_git(&ws, &["checkout", "-q", &branch])
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("git checkout {branch}: {e}")))?;

    // ---- the real model-driven turn ----
    let objective = wr["objective"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("Produce a short, concrete implementation note for this WorkRun.")
        .to_string();
    let turn_idx = wr["turns"].as_array().map(|a| a.len()).unwrap_or(0);
    let prompt = format!(
        "You are a child coding harness operating on an isolated patch branch ({branch}).\n\
         Objective: {objective}\n\
         Write the full contents of a single markdown file documenting the concrete change. \
         Be concise.\n"
    );
    // Resolve the daemon's model route exactly as chat completions does: the default route is
    // `route.native-local`, which runs the deterministic offline kernel; a mounted upstream
    // (Ollama / OpenAI / LOCAL_LLM_URL) routes through the HTTP runtime for a live LLM. Either
    // way the model output is REAL daemon-routed inference, and a receipt is recorded for replay.
    let route = resolve_route(&st, &json!({}));
    let text = if route.is_native_local {
        let result = invoke_native_local(&prompt, &route.model)
            .map_err(|e| AppError(StatusCode::BAD_GATEWAY, format!("native_local: {e}")))?;
        let out = result
            .get("output_text")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        persist_invocation_receipt(
            &st,
            &route,
            &result,
            &format!("workrun:{id}:turn:{turn_idx}:{}", short_hash(&prompt)),
            json!({ "capability": "chat", "invocationKind": "workrun.turn", "workRunId": id, "turnRef": format!("turn_{turn_idx}") }),
        );
        out
    } else {
        let options = InferenceOptions { max_tokens: 1024, ..Default::default() };
        let output = st
            .inference
            .execute_inference([0u8; 32], prompt.as_bytes(), options)
            .await
            .map_err(|e| AppError(StatusCode::BAD_GATEWAY, format!("no_model_route: {e:?}")))?;
        String::from_utf8_lossy(&output).to_string()
    };

    // ---- child harness writes a REAL edit on the scoped branch ----
    let rel = format!("agent/turn-{turn_idx}.md");
    let file_path = std::path::Path::new(&ws).join(&rel);
    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("mkdir agent dir: {e}")))?;
    }
    let file_body = format!(
        "<!-- workrun {id} · turn {turn_idx} · model {} · branch {branch} -->\n\n# Objective\n\n{objective}\n\n# Model output\n\n{text}\n",
        st.model_name
    );
    std::fs::write(&file_path, &file_body)
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("write edit: {e}")))?;

    // Commit under a CHILD identity (per-command, never global config). Host repo untouched.
    let child = ["-c", "user.email=child@local", "-c", "user.name=child_harness"];
    let mut add_args = child.to_vec();
    add_args.extend_from_slice(&["add", "-A"]);
    run_git(&ws, &add_args)
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("git add: {e}")))?;
    let msg = format!("workrun turn {turn_idx}: {}", objective.chars().take(60).collect::<String>());
    let mut commit_args = child.to_vec();
    commit_args.extend_from_slice(&["commit", "-q", "-m", msg.as_str()]);
    run_git(&ws, &commit_args)
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("git commit: {e}")))?;
    let commit = run_git(&ws, &["rev-parse", "HEAD"])
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("git head: {e}")))?;

    // Confirm the scoped working tree is clean (the edit is committed, nothing dangling).
    let dirty = run_git(&ws, &["status", "--porcelain"])
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("git status: {e}")))?;

    // ---- record the turn as daemon truth (proposed for the authority gate) ----
    let now = iso_now();
    let preview: String = text.chars().take(240).collect();
    let turn = json!({
        "ref": format!("turn_{turn_idx}"),
        "objective": objective,
        "route_id": route.route_id,
        "model_route": route.model,
        "native_local": route.is_native_local,
        "prompt_bytes": prompt.len(),
        "output_bytes": text.as_bytes().len(),
        "output_preview": preview,
        "file_changed": rel,
        "commit": commit,
        "host_mutation": false,
        "at": now
    });
    if !wr["turns"].is_array() {
        wr["turns"] = json!([]);
    }
    wr["turns"].as_array_mut().unwrap().push(turn.clone());
    let mut files = wr["files_changed"].as_array().cloned().unwrap_or_default();
    if !files.iter().any(|f| f.as_str() == Some(rel.as_str())) {
        files.push(json!(rel));
    }
    wr["files_changed"] = json!(files);
    wr["status"] = json!("proposed");
    wr["review_state"] = json!("proposed");
    wr["model_route"] = json!(route.model);
    wr["route_id"] = json!(route.route_id);
    wr["head_commit"] = json!(commit);
    wr["working_tree_clean"] = json!(dirty.is_empty());
    wr["host_mutation"] = json!(false);
    wr["updated_at"] = json!(now);
    persist_record(&st.data_dir, "workruns", &id, &wr)
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("persist workrun: {e}")))?;

    Ok(Json(json!({ "workRun": wr, "turn": turn })))
}
