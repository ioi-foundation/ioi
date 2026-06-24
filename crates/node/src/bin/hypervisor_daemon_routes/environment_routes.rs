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
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, AppError, DaemonState};

const ENV_SCHEMA: &str = "ioi.hypervisor.environment.v1";
const PROVIDER: &str = "local_workspace_provider_v0";

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
            "desired_phase": "stopped"
        },
        "status": {
            "status_version": 1,
            "phase": "stopped",
            "provider": PROVIDER,
            "substrate": "local_host",
            "tenant_posture": "single_user",
            "trust_posture": "trusted_user",
            "minimum_isolation": "process + scoped worktree/runtime state",
            "isolation_claim": "not_cross_tenant",
            "workspace_root": Value::Null,
            "blocked_reason": Value::Null,
            "last_observation_ref": Value::Null
        },
        "lifecycle_observations": [],
        "created_at": now,
        "updated_at": now,
        "evidence_refs": []
    })
}

/// Append a lifecycle observation, advance phase + status_version (daemon-owned truth).
fn observe(env: &mut Value, phase: &str, detail: &str) {
    let now = iso_now();
    let idx = env["lifecycle_observations"].as_array().map(|a| a.len()).unwrap_or(0);
    let obs_ref = format!("obs_{idx}");
    if let Some(arr) = env["lifecycle_observations"].as_array_mut() {
        arr.push(json!({ "ref": obs_ref, "phase": phase, "detail": detail, "at": now }));
    }
    let v = env["status"]["status_version"].as_u64().unwrap_or(1) + 1;
    env["status"]["status_version"] = json!(v);
    env["status"]["phase"] = json!(phase);
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
    observe(&mut env, "stopped", "environment created (local_workspace_provider_v0)");
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
            observe(&mut e, "stopped", "environment registered on first reference");
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
    match action.as_str() {
        "start" => {
            let ws = provision_local_workspace(&st.data_dir, &id)?;
            env["spec"]["desired_phase"] = json!("running");
            env["status"]["workspace_root"] = json!(ws);
            observe(&mut env, "provisioning", "provisioning local workspace");
            // Make it a real git repo so code WorkRuns can branch (WS-E).
            match ensure_git_repo(&ws) {
                Ok(base) => {
                    env["status"]["base_commit"] = json!(base);
                    observe(&mut env, "running", "local workspace ready (git initialized)");
                }
                Err(_) => observe(&mut env, "running", "local workspace ready (no git)"),
            }
        }
        "stop" => {
            env["spec"]["desired_phase"] = json!("stopped");
            observe(&mut env, "stopped", "environment stopped (workspace retained)");
        }
        "archive" => observe(&mut env, "archived", "environment archived"),
        "restore" => observe(&mut env, "stopped", "environment restored"),
        "delete" => {
            let dir = std::path::Path::new(&st.data_dir).join("environments").join(safe_id(&id));
            let _ = std::fs::remove_dir_all(&dir);
            env["status"]["workspace_root"] = Value::Null;
            observe(&mut env, "deleting", "environment deleted (scoped workspace removed)");
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
