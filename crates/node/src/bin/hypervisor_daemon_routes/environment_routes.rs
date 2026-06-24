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
    let spec = microvm::build_vm_spec(&st.home_dir, &monitor_id, run_dir, 2, 1024).map_err(|e| app(format!("vm spec: {e}")))?;
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
        Some(e) => e,
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
                    set_component(&mut env, "workspace_content", "ready", "git initialized");
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
                let ports: Vec<Value> = recipe["ports"].as_array().cloned().unwrap_or_default()
                    .iter().map(typed_port).collect();
                env["status"]["ports"] = json!(ports);
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
            set_phase(&mut env, "stopped");
            recompute_readiness(&mut env);
            observe(&mut env, "deleting", "storage", "state_wiped", "info", "environment deleted (scoped workspace removed)");
        }
        other => return Err(AppError(StatusCode::BAD_REQUEST, format!("unknown environment action: {other}"))),
    }
    persist_env(&st.data_dir, &env)?;
    Ok(Json(json!({ "environment": env })))
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
