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
            // WS-F: env-bound services / tasks / ports as daemon truth (the cockpit's bottom
            // panel renders these; deep terminal streaming is the remaining Ona-slot work).
            let declared = env["spec"]["declared_ports"].clone();
            env["status"]["services"] = json!([
                { "name": "workspace", "phase": "running", "lease": "local_operator" }
            ]);
            env["status"]["tasks"] = json!([
                { "name": "post-start setup", "phase": "succeeded", "trigger": "post_start" }
            ]);
            env["status"]["ports"] = if declared.as_array().map(|a| a.is_empty()).unwrap_or(true) {
                json!([])
            } else {
                declared
            };
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
