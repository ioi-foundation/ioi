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

// ---- handlers ----

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
            observe(&mut env, "running", "local workspace ready");
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
