//! WS-2 — DevelopmentEnvironmentRecipe → RecipeResolution → ReadinessGate (repo-detect-first).
//!
//! The canonical contract (providers-and-environments.md): *recipe declares desired env · daemon
//! resolves+admits a concrete plan · provider executes as evidence · agentgres records truth.*
//! Recipes are admitted Hypervisor objects authored explicitly OR detected from repo signals
//! (devcontainer.json / Dockerfile / language manifests). Resolution turns a recipe into a
//! concrete plan; the ReadinessGate proves the env is fit for the intended WorkRun — READY is
//! emitted only at `readiness_mode: full`, never on "container started".
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, AppError, DaemonState};

const RECIPE_SCHEMA: &str = "ioi.hypervisor.development-environment-recipe.v1";
const RESOLUTION_SCHEMA: &str = "ioi.hypervisor.environment-recipe-resolution.v1";
const GATE_SCHEMA: &str = "ioi.hypervisor.environment-readiness-gate.v1";

fn safe_id(id: &str) -> String {
    id.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_")
}

fn gen_id(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{prefix}_{nanos:x}")
}

/// Repo-detect-first: scan a repo for signals and compile recipe fields (init tasks, services,
/// ports, required edges). Honest — only what the signals actually imply.
pub(crate) fn detect_recipe_fields(repo_path: &str) -> Value {
    let p = std::path::Path::new(repo_path);
    let has = |rel: &str| p.join(rel).exists();
    let read = |rel: &str| std::fs::read_to_string(p.join(rel)).unwrap_or_default();

    let mut signals: Vec<&str> = Vec::new();
    let mut init_tasks: Vec<Value> = Vec::new();
    let mut prebuild_tasks: Vec<Value> = Vec::new();
    let mut services: Vec<Value> = Vec::new();
    let mut ports: Vec<Value> = Vec::new();
    let mut substrate = "local_host";

    if has(".devcontainer/devcontainer.json") || has("devcontainer.json") {
        signals.push("devcontainer.json");
        substrate = "devcontainer";
        let body = if has("devcontainer.json") { read("devcontainer.json") } else { read(".devcontainer/devcontainer.json") };
        // forwardPorts / postCreateCommand are common devcontainer keys (best-effort, no JSON5).
        if let Ok(dc) = serde_json::from_str::<Value>(&body) {
            if let Some(pcc) = dc.get("postCreateCommand").and_then(|v| v.as_str()) {
                init_tasks.push(json!({ "name": "postCreateCommand", "command": pcc, "trigger": "post_start", "required": true }));
            }
            if let Some(fp) = dc.get("forwardPorts").and_then(|v| v.as_array()) {
                for port in fp.iter().filter_map(|v| v.as_u64()) {
                    ports.push(json!({ "port": port, "protocol": "tcp", "access_policy": "session_lease" }));
                }
            }
        }
    }
    if has("Dockerfile") {
        signals.push("Dockerfile");
        if substrate == "local_host" { substrate = "container"; }
    }
    if has("Cargo.toml") {
        signals.push("Cargo.toml");
        prebuild_tasks.push(json!({ "name": "cargo fetch", "command": "cargo fetch", "trigger": "prebuild", "required": false }));
        init_tasks.push(json!({ "name": "cargo build", "command": "cargo build", "trigger": "environment_start", "required": false }));
    }
    if has("package.json") {
        signals.push("package.json");
        init_tasks.push(json!({ "name": "npm install", "command": "npm install", "trigger": "environment_start", "required": true }));
        let pj = read("package.json");
        if let Ok(v) = serde_json::from_str::<Value>(&pj) {
            if v.get("scripts").and_then(|s| s.get("start")).is_some() {
                services.push(json!({ "name": "app", "command": "npm start", "lifecycle": "optional", "trigger": "post_start" }));
            }
        }
    }
    if has("pyproject.toml") || has("requirements.txt") {
        signals.push("python");
        init_tasks.push(json!({ "name": "pip install", "command": "pip install -r requirements.txt", "trigger": "environment_start", "required": false }));
    }
    if has("go.mod") {
        signals.push("go.mod");
        prebuild_tasks.push(json!({ "name": "go mod download", "command": "go mod download", "trigger": "prebuild", "required": false }));
    }

    json!({
        "substrate": substrate,
        "detected_signals": signals,
        "init_tasks": init_tasks,
        "prebuild_tasks": prebuild_tasks,
        "post_start_tasks": [],
        "services": services,
        "ports": ports,
        "secret_requirement_refs": [],
        "scm_auth_requirement_refs": []
    })
}

/// Build a recipe record from explicit fields and/or detected signals.
pub(crate) fn new_recipe(id: &str, fields: &Value, source: &str, project_ref: Option<&str>) -> Value {
    let get = |k: &str, dflt: Value| fields.get(k).cloned().unwrap_or(dflt);
    json!({
        "schema_version": RECIPE_SCHEMA,
        "recipe_ref": id,
        "source": source,
        "project_ref": project_ref,
        "environment_class_ref": get("environment_class_ref", json!("local-workspace-v0")),
        "substrate": get("substrate", json!("local_host")),
        "detected_signals": get("detected_signals", json!([])),
        "prebuild_tasks": get("prebuild_tasks", json!([])),
        "init_tasks": get("init_tasks", json!([])),
        "post_start_tasks": get("post_start_tasks", json!([])),
        "services": get("services", json!([])),
        "ports": get("ports", json!([])),
        "secret_requirement_refs": get("secret_requirement_refs", json!([])),
        "scm_auth_requirement_refs": get("scm_auth_requirement_refs", json!([])),
        "created_at": iso_now()
    })
}

pub(crate) fn persist_recipe(data_dir: &str, recipe: &Value) -> Result<(), AppError> {
    let id = recipe["recipe_ref"].as_str().unwrap_or("recipe");
    persist_record(data_dir, "recipes", id, recipe)
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("persist recipe: {e}")))
}

pub(crate) fn load_recipe(data_dir: &str, recipe_ref: &str) -> Option<Value> {
    let path = std::path::Path::new(data_dir).join("recipes").join(format!("{}.json", safe_id(recipe_ref)));
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok())
}

fn task_refs(recipe: &Value, key: &str, required_only: bool) -> Vec<String> {
    recipe.get(key).and_then(|v| v.as_array()).map(|a| {
        a.iter()
            .filter(|t| !required_only || t.get("required").and_then(|r| r.as_bool()).unwrap_or(false))
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect()
    }).unwrap_or_default()
}

/// Resolve a recipe into a concrete `HypervisorEnvironmentRecipeResolution` for an environment.
pub(crate) fn resolve_recipe(data_dir: &str, recipe: &Value, env_id: &str) -> Result<Value, AppError> {
    let resolution_id = gen_id("reso");
    let gate_ref = gen_id("gate");
    let required_task_refs: Vec<String> = task_refs(recipe, "init_tasks", true)
        .into_iter()
        .chain(task_refs(recipe, "prebuild_tasks", true))
        .chain(task_refs(recipe, "post_start_tasks", true))
        .collect();
    let required_service_refs: Vec<String> = recipe.get("services").and_then(|v| v.as_array()).map(|a| {
        a.iter()
            .filter(|s| s.get("lifecycle").and_then(|l| l.as_str()) == Some("required"))
            .filter_map(|s| s.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect()
    }).unwrap_or_default();
    let required_port_refs: Vec<u64> = recipe.get("ports").and_then(|v| v.as_array()).map(|a| {
        a.iter().filter_map(|p| p.get("port").and_then(|n| n.as_u64())).collect()
    }).unwrap_or_default();
    let resolution = json!({
        "schema_version": RESOLUTION_SCHEMA,
        "recipe_ref": recipe["recipe_ref"],
        "environment_ref": env_id,
        "resolved_substrate": recipe["substrate"],
        "resolved_tasks": recipe.get("init_tasks").cloned().unwrap_or_else(|| json!([])),
        "resolved_prebuild_tasks": recipe.get("prebuild_tasks").cloned().unwrap_or_else(|| json!([])),
        "resolved_services": recipe.get("services").cloned().unwrap_or_else(|| json!([])),
        "resolved_ports": recipe.get("ports").cloned().unwrap_or_else(|| json!([])),
        "required_task_refs": required_task_refs,
        "required_service_refs": required_service_refs,
        "required_port_refs": required_port_refs,
        "required_secret_refs": recipe.get("secret_requirement_refs").cloned().unwrap_or_else(|| json!([])),
        "required_scm_auth_refs": recipe.get("scm_auth_requirement_refs").cloned().unwrap_or_else(|| json!([])),
        "readiness_gate_ref": gate_ref,
        "resolution_ref": resolution_id,
        "blocked_reason": Value::Null,
        "created_at": iso_now()
    });
    persist_record(data_dir, "recipe-resolutions", &resolution_id, &resolution)
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("persist resolution: {e}")))?;
    Ok(resolution)
}

/// Compute the `HypervisorEnvironmentReadinessGate` from a resolution + the env's runtime facts.
/// readiness_mode = full | degraded | dry_run_only | blocked, naming the blocking edges.
/// `env` carries: workspace_ready (bool), services_healthy (set of names), secret_leases (set),
/// scm_auth (set). Required edges that aren't satisfied push blocked_reasons.
pub(crate) fn compute_readiness_gate(data_dir: &str, resolution: &Value, env: &Value) -> Result<Value, AppError> {
    let arr = |v: &Value, k: &str| v.get(k).and_then(|x| x.as_array()).cloned().unwrap_or_default();
    let strs = |v: &Vec<Value>| v.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>();

    let mut blocked: Vec<String> = Vec::new();

    // required secrets: satisfied only if a lease exists (local provider has none by default).
    let leases: Vec<String> = env["status"]["secret_leases"].as_array().map(strs).unwrap_or_default();
    for s in strs(&arr(resolution, "required_secret_refs")) {
        if !leases.contains(&s) {
            blocked.push(format!("required_secret:{s}"));
        }
    }
    // required scm-auth: satisfied only if recorded.
    let scm: Vec<String> = env["status"]["scm_auth"].as_array().map(strs).unwrap_or_default();
    for s in strs(&arr(resolution, "required_scm_auth_refs")) {
        if !scm.contains(&s) {
            blocked.push(format!("required_scm_auth:{s}"));
        }
    }
    // required services: satisfied only if the env reports them healthy.
    let healthy: Vec<String> = env["status"]["services"].as_array().map(|a| {
        a.iter().filter(|s| s.get("phase").and_then(|p| p.as_str()) == Some("running"))
            .filter_map(|s| s.get("name").and_then(|n| n.as_str()).map(String::from)).collect()
    }).unwrap_or_default();
    for s in strs(&arr(resolution, "required_service_refs")) {
        if !healthy.contains(&s) {
            blocked.push(format!("required_service:{s}"));
        }
    }

    let workspace_ready = env["status"]["components"]["workspace_content"]["phase"].as_str() == Some("ready")
        && env["status"]["components"]["provisioner"]["phase"].as_str() == Some("ready");

    let readiness_mode = if !workspace_ready {
        "blocked"
    } else if !blocked.is_empty() {
        // workspace ready but a required runtime edge unmet → inspect-only, no run.
        "dry_run_only"
    } else {
        "full"
    };

    let gate_ref = resolution["readiness_gate_ref"].as_str().unwrap_or("gate").to_string();
    let gate = json!({
        "schema_version": GATE_SCHEMA,
        "gate_ref": gate_ref,
        "environment_ref": resolution["environment_ref"],
        "recipe_resolution_ref": resolution["resolution_ref"],
        "required_task_refs": resolution["required_task_refs"],
        "required_service_refs": resolution["required_service_refs"],
        "required_secret_refs": resolution["required_secret_refs"],
        "required_scm_auth_refs": resolution["required_scm_auth_refs"],
        "readiness_mode": readiness_mode,
        "blocked_reasons": blocked,
        "evidence_refs": [],
        "created_at": iso_now()
    });
    persist_record(data_dir, "readiness-gates", &gate_ref, &gate)
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("persist gate: {e}")))?;
    Ok(gate)
}

/// Repo-detect-first: detect + admit a recipe for a repo, returning its recipe_ref.
pub(crate) fn detect_and_admit(data_dir: &str, repo_path: &str, project_ref: Option<&str>) -> Result<String, AppError> {
    let id = gen_id("recipe");
    let fields = detect_recipe_fields(repo_path);
    let recipe = new_recipe(&id, &fields, "repo_detected", project_ref);
    persist_recipe(data_dir, &recipe)?;
    Ok(id)
}

/// Env-start integration: if the env carries a recipe_ref, resolve it, compute the readiness
/// gate, and set the env's readiness from the gate (overriding the component-only rollup). The
/// gate is the single authority that promotes an env to readiness `full` (canon: not "started").
pub(crate) fn apply_readiness_gate(data_dir: &str, env: &mut Value) -> Result<bool, AppError> {
    let recipe_ref = match env["spec"]["recipe_ref"].as_str() {
        Some(r) if !r.is_empty() => r.to_string(),
        _ => return Ok(false),
    };
    let recipe = match load_recipe(data_dir, &recipe_ref) {
        Some(r) => r,
        None => return Ok(false),
    };
    let env_id = env["id"].as_str().unwrap_or("env").to_string();
    let resolution = resolve_recipe(data_dir, &recipe, &env_id)?;
    let gate = compute_readiness_gate(data_dir, &resolution, env)?;
    env["status"]["recipe_ref"] = json!(recipe_ref);
    env["status"]["recipe_resolution_ref"] = resolution["resolution_ref"].clone();
    env["status"]["readiness_gate_ref"] = gate["gate_ref"].clone();
    env["status"]["readiness"] = json!({
        "mode": gate["readiness_mode"],
        "blocked_reasons": gate["blocked_reasons"]
    });
    Ok(true)
}

// ---- handlers ----

/// POST /v1/hypervisor/recipes — admit a recipe. Body either explicit recipe fields, or
/// `{ "repo_path": "...", "project_ref"?: "..." }` to repo-detect (repo-detect-first).
pub(crate) async fn handle_recipe_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let id = gen_id("recipe");
    let project_ref = body.get("project_ref").and_then(|v| v.as_str());
    let (fields, source) = if let Some(repo) = body.get("repo_path").and_then(|v| v.as_str()) {
        (detect_recipe_fields(repo), "repo_detected")
    } else {
        (body.get("recipe").cloned().unwrap_or_else(|| body.clone()), "explicit")
    };
    let recipe = new_recipe(&id, &fields, source, project_ref);
    persist_recipe(&st.data_dir, &recipe)?;
    Ok(Json(json!({ "recipe": recipe })))
}

/// GET /v1/hypervisor/recipes
pub(crate) async fn handle_recipes_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "recipes": read_record_dir(&st.data_dir, "recipes") }))
}

/// GET /v1/hypervisor/recipes/:id
pub(crate) async fn handle_recipe_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let recipe = load_recipe(&st.data_dir, &id)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "recipe not found".into()))?;
    Ok(Json(json!({ "recipe": recipe })))
}
