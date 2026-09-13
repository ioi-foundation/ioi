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
use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{iso_now, persist_record, read_record_dir, AppError, DaemonState};

const RECIPE_SCHEMA: &str = "ioi.hypervisor.development-environment-recipe.v1";
const RESOLUTION_SCHEMA: &str = "ioi.hypervisor.environment-recipe-resolution.v1";
const GATE_SCHEMA: &str = "ioi.hypervisor.environment-readiness-gate.v1";

fn safe_id(id: &str) -> String {
    id.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
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
        let body = if has("devcontainer.json") {
            read("devcontainer.json")
        } else {
            read(".devcontainer/devcontainer.json")
        };
        // forwardPorts / postCreateCommand are common devcontainer keys (best-effort, no JSON5).
        if let Ok(dc) = serde_json::from_str::<Value>(&body) {
            if let Some(pcc) = dc.get("postCreateCommand").and_then(|v| v.as_str()) {
                init_tasks.push(json!({ "name": "postCreateCommand", "command": pcc, "trigger": "post_start", "required": false }));
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
        if substrate == "local_host" {
            substrate = "container";
        }
    }
    if has("Cargo.toml") {
        signals.push("Cargo.toml");
        prebuild_tasks.push(json!({ "name": "cargo fetch", "command": "cargo fetch", "trigger": "prebuild", "required": false }));
        init_tasks.push(json!({ "name": "cargo build", "command": "cargo build", "trigger": "environment_start", "required": false }));
    }
    if has("package.json") {
        signals.push("package.json");
        init_tasks.push(json!({ "name": "npm install", "command": "npm install", "trigger": "environment_start", "required": false }));
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
pub(crate) fn new_recipe(
    id: &str,
    fields: &Value,
    source: &str,
    project_ref: Option<&str>,
) -> Value {
    let get = |k: &str, dflt: Value| fields.get(k).cloned().unwrap_or(dflt);
    json!({
        "schema_version": RECIPE_SCHEMA,
        "recipe_ref": id,
        "source": source,
        "project_ref": project_ref,
        "environment_class_ref": get("environment_class_ref", json!("local-workspace-v0")),
        "substrate": get("substrate", json!("local_host")),
        // WS-5 — monitor selection hints (carried so select_monitor sees them).
        "monitor": get("monitor", Value::Null),
        "isolation_profile": get("isolation_profile", Value::Null),
        // WS-6 — prebuild/warmup cache paths (dirs reused across envs from the same recipe).
        "cache_paths": get("cache_paths", json!([])),
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
    // M09.2: THE REGISTERED CONTRACT IS CHECKED IN PRODUCTION, not only under `#[cfg(test)]`.
    // This module had three `validate_architecture_contract` calls and every one of them was
    // inside its test module — a healthy-looking grep over code a running daemon never reaches.
    // Tests proved the shape agreed on the day they were written; nothing stopped a production
    // path from writing a record that did not.
    contract_checked(RECIPE_CONTRACT_ID, recipe)?;
    let id = recipe["recipe_ref"].as_str().unwrap_or("recipe");
    persist_record(data_dir, "recipes", id, recipe).map_err(|e| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("persist recipe: {e}"),
        )
    })
}

pub(crate) fn load_recipe(data_dir: &str, recipe_ref: &str) -> Option<Value> {
    let path = std::path::Path::new(data_dir)
        .join("recipes")
        .join(format!("{}.json", safe_id(recipe_ref)));
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

fn task_refs(recipe: &Value, key: &str, required_only: bool) -> Vec<String> {
    recipe
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter(|t| {
                    !required_only || t.get("required").and_then(|r| r.as_bool()).unwrap_or(false)
                })
                .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Resolve a recipe into a concrete `HypervisorEnvironmentRecipeResolution` for an environment.
pub(crate) fn resolve_recipe(
    data_dir: &str,
    recipe: &Value,
    env_id: &str,
) -> Result<Value, AppError> {
    let resolution_id = gen_id("reso");
    let gate_ref = gen_id("gate");
    let required_task_refs: Vec<String> = task_refs(recipe, "init_tasks", true)
        .into_iter()
        .chain(task_refs(recipe, "prebuild_tasks", true))
        .chain(task_refs(recipe, "post_start_tasks", true))
        .collect();
    let required_service_refs: Vec<String> = recipe
        .get("services")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter(|s| s.get("lifecycle").and_then(|l| l.as_str()) == Some("required"))
                .filter_map(|s| s.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let required_port_refs: Vec<u64> = recipe
        .get("ports")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| p.get("port").and_then(|n| n.as_u64()))
                .collect()
        })
        .unwrap_or_default();
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
    contract_checked(RESOLUTION_CONTRACT_ID, &resolution)?;
    persist_record(data_dir, "recipe-resolutions", &resolution_id, &resolution).map_err(|e| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("persist resolution: {e}"),
        )
    })?;
    Ok(resolution)
}

/// Compute the `HypervisorEnvironmentReadinessGate` from a resolution + the env's runtime facts.
/// readiness_mode = full | degraded | dry_run_only | blocked, naming the blocking edges.
/// `env` carries: workspace_ready (bool), services_healthy (set of names), secret_leases (set),
/// scm_auth (set). Required edges that aren't satisfied push blocked_reasons.
pub(crate) fn compute_readiness_gate(
    data_dir: &str,
    resolution: &Value,
    env: &Value,
) -> Result<Value, AppError> {
    let arr = |v: &Value, k: &str| {
        v.get(k)
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default()
    };
    let strs = |v: &Vec<Value>| {
        v.iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect::<Vec<_>>()
    };

    let mut blocked: Vec<String> = Vec::new();

    // required secrets: satisfied only if a lease exists (local provider has none by default).
    let leases: Vec<String> = env["status"]["secret_leases"]
        .as_array()
        .map(strs)
        .unwrap_or_default();
    for s in strs(&arr(resolution, "required_secret_refs")) {
        if !leases.contains(&s) {
            blocked.push(format!("required_secret:{s}"));
        }
    }
    // required scm-auth: satisfied only if recorded.
    let scm: Vec<String> = env["status"]["scm_auth"]
        .as_array()
        .map(strs)
        .unwrap_or_default();
    for s in strs(&arr(resolution, "required_scm_auth_refs")) {
        if !scm.contains(&s) {
            blocked.push(format!("required_scm_auth:{s}"));
        }
    }
    // required services: satisfied only if the env reports them healthy.
    let healthy: Vec<String> = env["status"]["services"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|s| s.get("phase").and_then(|p| p.as_str()) == Some("running"))
                .filter_map(|s| s.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    for s in strs(&arr(resolution, "required_service_refs")) {
        if !healthy.contains(&s) {
            blocked.push(format!("required_service:{s}"));
        }
    }
    // required tasks: a required task that did NOT succeed is a hard block (WS-3: tasks really ran).
    let mut required_task_failed = false;
    if let Some(tasks) = env["status"]["tasks"].as_array() {
        for t in tasks {
            let required = t.get("lifecycle").and_then(|l| l.as_str()) == Some("required");
            let succeeded = t.get("phase").and_then(|p| p.as_str()) == Some("succeeded");
            if required && !succeeded {
                let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("task");
                blocked.push(format!("required_task:{name}"));
                required_task_failed = true;
            }
        }
    }

    let workspace_ready = env["status"]["components"]["workspace_content"]["phase"].as_str()
        == Some("ready")
        && env["status"]["components"]["provisioner"]["phase"].as_str() == Some("ready");
    let sandbox_failed = env["status"]["components"]["sandbox"]["phase"].as_str() == Some("failed");
    if sandbox_failed {
        blocked.push("sandbox_failed".to_string());
    }

    let readiness_mode = if !workspace_ready || required_task_failed || sandbox_failed {
        // no workspace, a required setup task failed, or the sandbox didn't come up → not usable.
        "blocked"
    } else if !blocked.is_empty() {
        // workspace ready but a required runtime edge (secret/scm/service) unmet → inspect-only.
        "dry_run_only"
    } else {
        "full"
    };

    let gate_ref = resolution["readiness_gate_ref"]
        .as_str()
        .unwrap_or("gate")
        .to_string();
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
    persist_record(data_dir, "readiness-gates", &gate_ref, &gate).map_err(|e| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("persist gate: {e}"),
        )
    })?;
    Ok(gate)
}

/// Repo-detect-first: detect + admit a recipe for a repo, returning its recipe_ref.
pub(crate) fn detect_and_admit(
    data_dir: &str,
    repo_path: &str,
    project_ref: Option<&str>,
) -> Result<String, AppError> {
    let id = gen_id("recipe");
    let fields = detect_recipe_fields(repo_path);
    let recipe = new_recipe(&id, &fields, "repo_detected", project_ref);
    persist_recipe(data_dir, &recipe)?;
    Ok(id)
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
        (
            body.get("recipe").cloned().unwrap_or_else(|| body.clone()),
            "explicit",
        )
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

/// Refuse a record the registered contract would refuse, BEFORE it is written. A record that
/// would not survive the offline verifier is never persisted and then explained.
fn contract_checked(contract_id: &str, record: &Value) -> Result<(), AppError> {
    validate_architecture_contract(contract_id, record).map_err(|error| {
        AppError(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{contract_id} refused this record: {error}"),
        )
    })
}

// ---------------------------------------------------------------------------------
// M09.2 — HypervisorEnvironmentStartupPlan: the immutable bridge from a resolved
// recipe to ONE concrete startup attempt.
//
// ACC-11 clause 3 requires the startup plan to be inspectable before it runs and the
// lifecycle to execute THAT plan. Before this, the object did not exist anywhere in
// the estate: the only occurrence of the name outside canon was
// `environment_startup_plan_ref`, listed in `project_discovery_routes.rs` as a
// boundary field a discovery proposal may NOT carry — the plane next door correctly
// refusing to mint something that had no owner.
//
// WHY IT IS A SEPARATE RECORD FROM THE RESOLUTION. The same recipe resolves to
// DIFFERENT startup plans across local, customer-managed and IOI-managed postures.
// A resolution carrying the concrete attempt would have to be rewritten per posture
// and would stop being the reusable thing it is.
// ---------------------------------------------------------------------------------

const STARTUP_PLAN_SCHEMA: &str = "ioi.hypervisor.environment-startup-plan.v1";
/// Named rather than inlined at the call sites, so the ontology admission census can RESOLVE the
/// family this module writes instead of bucketing the call as a runtime parameter it cannot read.
/// The census's own text is the argument: naming the unresolvable bucket and pinning its size is
/// what stops it silently absorbing the calls the census exists to read — so a writer that can be
/// legible to it should be.
const STARTUP_PLAN_RECORDS: &str = "environment-startup-plans";
const STARTUP_PLAN_CONTRACT: &str =
    "schema://ioi/components/hypervisor/hypervisor-environment-startup-plan/v1";
const RECIPE_CONTRACT_ID: &str =
    "schema://ioi/components/hypervisor/hypervisor-development-environment-recipe/v1";
const RESOLUTION_CONTRACT_ID: &str =
    "schema://ioi/components/hypervisor/hypervisor-development-environment-recipe-resolution/v1";

/// The fields a caller may never assert, because asserting them is asserting the very
/// thing the plan exists to freeze. INV-37: identity, lineage and content commitments
/// are SERVER-RESOLVED, and a plan that took the caller's word for what the recipe
/// said would have frozen a claim rather than a recipe.
const SERVER_RESOLVED_PLAN_FIELDS: &[&str] = &[
    "startup_plan_ref",
    "plan_hash",
    "development_environment_recipe_ref",
    "development_environment_recipe_content_hash",
    "development_environment_recipe_resolution_ref",
    "development_environment_recipe_resolution_hash",
    "schema_version",
];

/// Canon's ten nullable fields. They are PRESENT AND NULL rather than absent, because
/// `plan_hash` covers "every exact nullable System/work-subject, temporal,
/// currentness-floor, continuity-floor, and ordering/finality field" — and a field
/// cannot be inside a hash and absent at the same time. Present-and-null is a
/// registered answer; absent is a different record that happens to hash differently.
const NULLABLE_PLAN_FIELDS: &[&str] = &[
    "session_ref",
    "system_ref",
    "work_subject_ref",
    "runtime_assignment_ref",
    "provider_account_ref",
    "provider_adapter_revision_ref",
    "lifecycle_continuity_floor_ref",
    "ordering_finality_profile_ref",
    "budget_lease_ref",
    "resource_allocation_ref",
];

/// Every required edge the RESOLUTION names, paired with the plan field that must
/// declare it. This pairing is the whole of "refuse undeclared paths, endpoints,
/// custody, egress and effects": the resolution already computed what the recipe
/// REQUIRES, so a plan that declares less would start an environment missing an edge
/// its own predecessor said was required — and nothing downstream would know, because
/// the plan is what the lifecycle executes.
const REQUIRED_EDGE_PAIRS: &[(&str, &str)] = &[
    ("required_service_refs", "service_refs"),
    ("required_secret_refs", "required_secret_refs"),
    ("required_scm_auth_refs", "required_scm_auth_refs"),
];

fn plan_refusal(code: &str, detail: String) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "code": code, "detail": detail })),
    )
}

fn jcs_sha256(value: &Value) -> Result<String, (StatusCode, Json<Value>)> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "ok": false,
                "code": "environment_startup_plan_canonicalisation_failed",
                "detail": error.to_string()
            })),
        )
    })?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

/// THE OBJECT RENAME, AT THE BOUNDARY WHERE IT BELONGS. The resolution plane stores BARE ids —
/// `recipe_ab12`, `reso_cd34`, `gate_ef56`, and an `environment_ref` that is a plain string — which
/// is the unqualified naming canon calls a defect: `DataRecipe`, `HypervisorSessionLaunchRecipe`,
/// `WorkflowTemplate` and `GoalRunProfile` would all answer to a generic `recipe_…`.
///
/// Canon's instruction is precise about what to do with them: the historical spellings are
/// READ-ONLY v1 COMPATIBILITY ALIASES — "boundary adapters may read them, but canonical state emits
/// the owner-qualified development-environment and provider-neutral authority names". So the stored
/// records keep their spellings and are not rewritten (rewriting them would break every persisted
/// resolution for a naming change), and the plan — a NEW contract with no legacy data — requires
/// the qualified form from its first byte.
///
/// This QUALIFIES; it does not rename. The bare id survives intact as the last path segment, so the
/// mapping is reversible by inspection and no identity is invented. An id that already carries a
/// scheme is left exactly as it is.
fn qualify(scheme: &str, id: &str) -> String {
    if id.contains("://") {
        return id.to_string();
    }
    format!("{scheme}://hypervisor/{id}")
}

/// Does the plan declare this required edge?
///
/// THE TWO PLANES SPEAK DIFFERENT VOCABULARIES AND BOTH ARE CORRECT IN THEIR OWN. A resolution
/// names a required service `db` and a required port `5432`, because that is what the recipe said;
/// the plan names `service://hypervisor/db` and `port://hypervisor/env-1/5432`, because a plan's
/// members are refs. Comparing them by string equality would never match, so the check would refuse
/// every plan — and the natural "fix" for that, comparing two non-empty lists for non-emptiness,
/// would accept every plan instead. Both failures look like a working check from outside.
///
/// So an edge is declared when a plan entry either IS it or ENDS WITH it as a whole final path
/// segment. The `/` in the suffix is what keeps `5432` from being satisfied by a declaration of
/// port `15432`.
fn declares(declared: &[String], edge: &str) -> bool {
    let suffix = format!("/{edge}");
    declared
        .iter()
        .any(|entry| entry == edge || entry.ends_with(&suffix))
}

fn strings_at(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| match item {
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Build and admit one startup plan from an existing resolution. The caller supplies
/// the POSTURE — operator, placement, profiles, policies — and nothing about lineage.
pub(crate) fn admit_startup_plan(
    data_dir: &str,
    body: &Value,
) -> Result<Value, (StatusCode, Json<Value>)> {
    for field in SERVER_RESOLVED_PLAN_FIELDS {
        if body.get(*field).is_some() {
            return Err(plan_refusal(
                "environment_startup_plan_server_resolved_field_asserted",
                format!(
                    "`{field}` is resolved by this daemon from the stored records. A caller that \
                     supplies it is asserting the lineage the plan exists to freeze."
                ),
            ));
        }
    }
    let resolution_ref = body
        .get("resolution_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            plan_refusal(
                "environment_startup_plan_resolution_ref_required",
                "A startup plan bridges FROM a resolved recipe. Without the resolution there is \
                 nothing to bridge from and nothing to freeze."
                    .to_string(),
            )
        })?;
    let resolution: Value = std::fs::read(
        std::path::Path::new(data_dir)
            .join("recipe-resolutions")
            .join(format!("{}.json", safe_id(resolution_ref))),
    )
    .ok()
    .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "code": "environment_startup_plan_resolution_not_found",
                "detail": "The named resolution does not exist. A plan is never minted against a \
                           resolution this daemon cannot read, because the hash it would freeze \
                           would be a hash of nothing."
            })),
        )
    })?;

    // CANON, VERBATIM: "A refused candidate remains a resolution refusal or startup-admission
    // refusal; it never becomes an admitted startup plan with an embedded `blocked_reason`."
    // The resolution contract carries `blocked_reason` and is right to; promoting a blocked one
    // into an admitted plan would produce a record asserting two contradictory things, and
    // something downstream would believe the wrong half.
    if !resolution
        .get("blocked_reason")
        .map(Value::is_null)
        .unwrap_or(true)
    {
        return Err(plan_refusal(
            "environment_startup_plan_from_a_blocked_resolution",
            format!(
                "The resolution is blocked ({}). A refused candidate stays a refusal; it does not \
                 become an admitted plan carrying its own blockage.",
                resolution["blocked_reason"]
            ),
        ));
    }

    let recipe_ref = resolution
        .get("recipe_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let recipe = load_recipe(data_dir, &recipe_ref).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "code": "environment_startup_plan_recipe_not_found",
                "detail": "The resolution's recipe is unreadable, so its content hash cannot be \
                           computed. Freezing a recipe by name alone is exactly the mutable alias \
                           this plan refuses."
            })),
        )
    })?;

    // THE CONTENT COMMITMENTS ARE COMPUTED HERE, FROM THE STORED BYTES. A ref alone is an alias
    // that can be repointed; a hash the caller supplied is an alias wearing a hash's clothes.
    let recipe_content_hash = jcs_sha256(&recipe)?;
    let resolution_hash = jcs_sha256(&resolution)?;

    // Every required edge the resolution names must be DECLARED in the plan. The plan is what the
    // lifecycle executes, so an edge missing here is an edge missing at startup.
    for (resolution_key, plan_key) in REQUIRED_EDGE_PAIRS {
        let required = strings_at(&resolution, resolution_key);
        let declared = strings_at(body, plan_key);
        let undeclared: Vec<&String> = required
            .iter()
            .filter(|edge| !declares(&declared, edge))
            .collect();
        if !undeclared.is_empty() {
            return Err(plan_refusal(
                "environment_startup_plan_undeclared_required_edge",
                format!(
                    "the resolution requires {resolution_key} {undeclared:?} which the plan's \
                     `{plan_key}` does not declare"
                ),
            ));
        }
    }
    // Ports are NUMBERS in the resolution and refs in the plan, so they go through the same
    // last-segment comparison as everything else rather than a string equality that could never
    // match — a check that cannot fail is worse than no check, because it reads as coverage.
    let required_ports: Vec<u64> = resolution
        .get("required_port_refs")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default();
    let declared_ports = strings_at(body, "port_refs");
    let undeclared_ports: Vec<u64> = required_ports
        .iter()
        .copied()
        .filter(|port| !declares(&declared_ports, &port.to_string()))
        .collect();
    if !undeclared_ports.is_empty() {
        return Err(plan_refusal(
            "environment_startup_plan_undeclared_required_edge",
            format!(
                "the resolution requires ports {undeclared_ports:?} which the plan's `port_refs` \
                 does not declare"
            ),
        ));
    }

    let environment_ref = resolution
        .get("environment_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // QUALIFIED ONCE, HERE, and compared in the qualified vocabulary everywhere below. Counting
    // revisions against the BARE id while stored plans carry the qualified one matched nothing, so
    // every plan minted as revision 1 and each successor overwrote its predecessor — the exact
    // patch-in-place canon forbids, arriving through a comparison rather than through an update.
    let qualified_environment_ref = qualify("environment", environment_ref);
    // Revision-exact by construction. A plan ref without a revision is a mutable alias, and canon
    // requires a SUCCESSOR plan for every change rather than a patch in place — which is
    // unenforceable if the ref can point at different bytes over time.
    let revision = read_record_dir(data_dir, STARTUP_PLAN_RECORDS)
        .iter()
        .filter(|row| row["environment_ref"].as_str() == Some(qualified_environment_ref.as_str()))
        .count()
        + 1;
    let startup_plan_ref = format!(
        "environment-startup-plan://hypervisor/{}/revision/{revision}",
        safe_id(environment_ref)
    );

    let caller = |key: &str| body.get(key).cloned();
    let required_ref = |key: &str| -> Result<Value, (StatusCode, Json<Value>)> {
        caller(key)
            .filter(|value| value.as_str().map(|text| !text.is_empty()).unwrap_or(false))
            .ok_or_else(|| {
                plan_refusal(
                    "environment_startup_plan_undeclared_posture_field",
                    format!(
                        "`{key}` is part of what the plan freezes and has no default. A plan \
                         minted with a substituted profile would be inspectable and wrong, which \
                         is worse than absent."
                    ),
                )
            })
    };

    let mut plan = json!({
        "schema_version": STARTUP_PLAN_SCHEMA,
        "startup_plan_ref": startup_plan_ref,
        "plan_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "environment_ref": qualified_environment_ref,
        "development_environment_recipe_ref": qualify("development-environment-recipe", &recipe_ref),
        "development_environment_recipe_content_hash": recipe_content_hash,
        "development_environment_recipe_resolution_ref": qualify(
            "environment-recipe-resolution",
            resolution["resolution_ref"].as_str().unwrap_or_default(),
        ),
        "development_environment_recipe_resolution_hash": resolution_hash,
        "placement_decision_ref": required_ref("placement_decision_ref")?,
        "runtime_operator": caller("runtime_operator").unwrap_or_else(|| json!("local")),
        "source_ref": required_ref("source_ref")?,
        "artifact_ref": required_ref("artifact_ref")?,
        "configuration_ref": required_ref("configuration_ref")?,
        "ordered_task_refs": caller("ordered_task_refs").unwrap_or_else(|| json!([])),
        "service_refs": caller("service_refs").unwrap_or_else(|| json!([])),
        "agent_service_refs": caller("agent_service_refs").unwrap_or_else(|| json!([])),
        "port_refs": caller("port_refs").unwrap_or_else(|| json!([])),
        "readiness_gate_ref": qualify(
            "readiness-gate",
            resolution["readiness_gate_ref"].as_str().unwrap_or_default(),
        ),
        "connectivity_profile_ref": required_ref("connectivity_profile_ref")?,
        "resource_isolation_profile_ref": required_ref("resource_isolation_profile_ref")?,
        "custody_and_privacy_profile_refs": caller("custody_and_privacy_profile_refs").unwrap_or_else(|| json!([])),
        "temporal_verification_profile_ref": required_ref("temporal_verification_profile_ref")?,
        "authority_currentness_floor_ref": required_ref("authority_currentness_floor_ref")?,
        "required_identity_context_ref": required_ref("required_identity_context_ref")?,
        "required_authority_scope_refs": caller("required_authority_scope_refs").unwrap_or_else(|| json!([])),
        "resolved_authority_decision_refs": caller("resolved_authority_decision_refs").unwrap_or_else(|| json!([])),
        "authority_lease_refs": caller("authority_lease_refs").unwrap_or_else(|| json!([])),
        "capability_lease_refs": caller("capability_lease_refs").unwrap_or_else(|| json!([])),
        "required_secret_refs": caller("required_secret_refs").unwrap_or_else(|| json!([])),
        "secret_capability_lease_refs": caller("secret_capability_lease_refs").unwrap_or_else(|| json!([])),
        "required_scm_auth_refs": caller("required_scm_auth_refs").unwrap_or_else(|| json!([])),
        "resource_budget_ref": required_ref("resource_budget_ref")?,
        "stop_policy_ref": required_ref("stop_policy_ref")?,
        "recovery_policy_ref": required_ref("recovery_policy_ref")?,
        "rollback_policy_ref": required_ref("rollback_policy_ref")?,
        "expected_receipt_contract_refs": caller("expected_receipt_contract_refs").unwrap_or_else(|| json!([])),
    });
    // The nullable ten are written EXPLICITLY, so "this plan serves no System" is a registered
    // answer rather than a gap in the record.
    for field in NULLABLE_PLAN_FIELDS {
        let value = caller(field).unwrap_or(Value::Null);
        plan[*field] = value;
    }

    // The hash covers the body INCLUDING the allocated ref and every nullable field, and excludes
    // only itself — so it is computed over the plan with `plan_hash` removed, never over a plan
    // carrying a placeholder that would silently become part of what was signed.
    let mut hashable = plan.clone();
    if let Some(object) = hashable.as_object_mut() {
        object.remove("plan_hash");
    }
    plan["plan_hash"] = json!(jcs_sha256(&hashable)?);

    // BEFORE the write, never after. A record that would not survive the offline verifier is not
    // written and then explained.
    validate_architecture_contract(STARTUP_PLAN_CONTRACT, &plan).map_err(|error| {
        plan_refusal(
            "environment_startup_plan_contract_refused",
            error.to_string(),
        )
    })?;
    persist_record(
        data_dir,
        STARTUP_PLAN_RECORDS,
        &safe_id(
            &plan["startup_plan_ref"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        ),
        &plan,
    )
    .map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "ok": false,
                "code": "environment_startup_plan_persist_failed",
                "detail": error.to_string()
            })),
        )
    })?;
    Ok(plan)
}

/// POST /v1/hypervisor/environment-recipes/:id/resolutions — resolve a recipe WITHOUT starting
/// anything.
///
/// ACC-11 clause 3 requires the startup plan to be inspectable BEFORE it runs. Until this lane
/// existed the only producer of a resolution was environment CREATION — `environment_routes.rs`
/// resolves the recipe, runs its tasks and starts its services in one pass — so the only way to
/// obtain a plan's predecessor was to start the environment the plan plans. A plan inspectable only
/// after the thing it plans has started is the negation of the clause, not a weaker form of it.
///
/// Resolution is a pure derivation from a recipe and an environment id, which is why it can have
/// this lane at all: it reads a recipe, computes the required edges, and writes a record. It starts
/// nothing, and this handler adds no capability that environment creation did not already exercise.
pub(crate) async fn handle_recipe_resolve(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, AppError> {
    let body: Value = if body.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&body)
            .map_err(|error| AppError(StatusCode::BAD_REQUEST, error.to_string()))?
    };
    let recipe = load_recipe(&st.data_dir, &id)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "recipe not found".into()))?;
    let environment_ref = body
        .get("environment_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError(
                StatusCode::BAD_REQUEST,
                "environment_ref is required: the same recipe resolves differently per environment,                  so a resolution with no environment would be a resolution of nothing"
                    .into(),
            )
        })?;
    let resolution = resolve_recipe(&st.data_dir, &recipe, environment_ref)?;
    Ok(Json(json!({ "resolution": resolution })))
}

/// POST /v1/hypervisor/environment-startup-plans
pub(crate) async fn handle_startup_plan_create(
    State(st): State<Arc<DaemonState>>,
    body: axum::body::Bytes,
) -> (StatusCode, Json<Value>) {
    // Identity before body, as every handler on this plane learned to do the expensive way: with
    // `Json<Value>` here axum runs the body extractor before the handler is entered, and a caller
    // with no body is refused for its content type rather than for what it actually got wrong.
    let body: Value = if body.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice(&body) {
            Ok(value) => value,
            Err(error) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "ok": false,
                        "code": "environment_startup_plan_malformed_body",
                        "detail": error.to_string()
                    })),
                )
            }
        }
    };
    match admit_startup_plan(&st.data_dir, &body) {
        Ok(plan) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "startup_plan": plan })),
        ),
        Err(response) => response,
    }
}

/// GET /v1/hypervisor/environment-startup-plans — ACC-11 clause 3's "inspectable before it runs".
pub(crate) async fn handle_startup_plans_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({
        "startup_plans": read_record_dir(&st.data_dir, STARTUP_PLAN_RECORDS),
        // The plan freezes what WILL start. It does not execute, does not grant authority, does
        // not own provider truth, and does not make readiness true by declaration — stated on the
        // wire because a reader holding a fully-populated plan could reasonably assume otherwise.
        "read_model_only": true,
        "nonclaims": [
            "execution",
            "authority_grant",
            "provider_truth",
            "readiness_by_declaration"
        ]
    }))
}

// ---------------------------------------------------------------------------------
// M2 session-chain contract proofs (route layer): the recipe -> resolution ->
// readiness-gate links are bound to the registered architecture contracts, with the
// live produced objects (never hand-written shapes) as the validated instances.
// ---------------------------------------------------------------------------------
#[cfg(test)]
mod m2_contract_tests {
    use super::*;
    use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;

    const RECIPE_CONTRACT: &str =
        "schema://ioi/components/hypervisor/hypervisor-development-environment-recipe/v1";
    const RESOLUTION_CONTRACT: &str =
        "schema://ioi/components/hypervisor/hypervisor-development-environment-recipe-resolution/v1";

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("ioi-m2-recipe-{label}-{nanos:x}"));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    /// `AppError` carries no Debug impl; unwrap route results by naming the failure site.
    fn ok<T>(result: Result<T, AppError>, at: &str) -> T {
        match result {
            Ok(value) => value,
            Err(AppError(status, message)) => panic!("{at}: {status} {message}"),
        }
    }

    /// The LIVE repo-detected recipe and its LIVE resolution validate against the registered
    /// contracts, and the resolution cites its exact recipe and environment predecessors.
    #[test]
    fn detected_recipe_and_resolution_validate_registered_contracts() {
        let repo = temp_dir("repo");
        std::fs::write(repo.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        std::fs::write(
            repo.join("package.json"),
            "{\"name\":\"demo\",\"scripts\":{\"start\":\"node index.js\"}}",
        )
        .unwrap();
        let data = temp_dir("data");
        let data_dir = data.to_str().unwrap();

        let recipe_ref = ok(
            detect_and_admit(data_dir, repo.to_str().unwrap(), Some("project:ioi")),
            "admit",
        );
        let recipe = load_recipe(data_dir, &recipe_ref).expect("persisted recipe loads");
        validate_architecture_contract(RECIPE_CONTRACT, &recipe)
            .expect("live repo-detected recipe validates against the registered contract");
        assert_eq!(recipe["source"], "repo_detected");
        assert_eq!(recipe["project_ref"], "project:ioi");
        let signals: Vec<&str> = recipe["detected_signals"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(signals.contains(&"Cargo.toml") && signals.contains(&"package.json"));

        let resolution = ok(resolve_recipe(data_dir, &recipe, "env_test01"), "resolved");
        validate_architecture_contract(RESOLUTION_CONTRACT, &resolution)
            .expect("live resolution validates against the registered contract");
        // Exact predecessor binding: the resolution cites the recipe and environment it
        // resolved, never a substitute.
        assert_eq!(resolution["recipe_ref"], recipe["recipe_ref"]);
        assert_eq!(resolution["environment_ref"], "env_test01");
        assert!(resolution["blocked_reason"].is_null());
    }

    /// Missing predecessor at the route layer: an absent recipe never resolves to a phantom
    /// record (the daemon 404s from this same None).
    #[test]
    fn absent_recipe_predecessor_loads_none() {
        let data = temp_dir("empty");
        assert!(load_recipe(data.to_str().unwrap(), "recipe_ffffffffffff").is_none());
    }

    /// Fabricated readiness at the environment layer: READY (`readiness_mode: full`) is
    /// unreachable while a required secret/service edge is unproven, and the blocking edges are
    /// named rather than erased.
    #[test]
    fn readiness_gate_cannot_fabricate_full_over_unmet_edges() {
        let data = temp_dir("gate");
        let data_dir = data.to_str().unwrap();
        let recipe = new_recipe(
            "recipe_00000000000000aa",
            &json!({
                "substrate": "local_host",
                "services": [
                    { "name": "db", "command": "docker compose up db", "lifecycle": "required", "trigger": "post_start" }
                ],
                "secret_requirement_refs": ["secret:dev-db-password"],
            }),
            "explicit",
            Some("project:ioi"),
        );
        let resolution = ok(resolve_recipe(data_dir, &recipe, "env_gate01"), "resolved");
        assert_eq!(resolution["required_service_refs"], json!(["db"]));
        assert_eq!(
            resolution["required_secret_refs"],
            json!(["secret:dev-db-password"])
        );

        // Workspace is up but the required service and secret lease are unproven.
        let unmet_env = json!({
            "status": {
                "secret_leases": [],
                "scm_auth": [],
                "services": [],
                "tasks": [],
                "components": {
                    "workspace_content": { "phase": "ready" },
                    "provisioner": { "phase": "ready" },
                    "sandbox": { "phase": "ready" },
                },
            }
        });
        let gate = ok(
            compute_readiness_gate(data_dir, &resolution, &unmet_env),
            "gate",
        );
        assert_ne!(gate["readiness_mode"], "full");
        let blocked: Vec<&str> = gate["blocked_reasons"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(blocked.contains(&"required_secret:secret:dev-db-password"));
        assert!(blocked.contains(&"required_service:db"));

        // With the exact edges proven, the same gate computation reaches full readiness.
        let met_env = json!({
            "status": {
                "secret_leases": ["secret:dev-db-password"],
                "scm_auth": [],
                "services": [{ "name": "db", "phase": "running" }],
                "tasks": [],
                "components": {
                    "workspace_content": { "phase": "ready" },
                    "provisioner": { "phase": "ready" },
                    "sandbox": { "phase": "ready" },
                },
            }
        });
        let gate = ok(
            compute_readiness_gate(data_dir, &resolution, &met_env),
            "gate",
        );
        assert_eq!(gate["readiness_mode"], "full");
        assert_eq!(gate["blocked_reasons"], json!([]));
        assert_eq!(gate["environment_ref"], "env_gate01");
        assert_eq!(gate["recipe_resolution_ref"], resolution["resolution_ref"]);
    }
}

// ---------------------------------------------------------------------------------
// M09.2 — the startup plan admission. These prove the TRANSACTION: what it refuses,
// and that what it mints is server-resolved rather than caller-asserted. The contract
// proves the shape; only these can prove the admission APPLIES it, which is the
// defect class M07.2 named — a decision function with no caller passes every unit
// test it has.
// ---------------------------------------------------------------------------------
#[cfg(test)]
mod m09_2_startup_plan_tests {
    use super::*;

    const PLAN_CONTRACT: &str =
        "schema://ioi/components/hypervisor/hypervisor-environment-startup-plan/v1";

    fn scratch(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("ioi-m092-{label}-{nanos:x}"));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    /// `AppError` carries no `Debug`, so `.expect` is unavailable on it. Unwrapping through the
    /// status and detail is better anyway: a failure here reports WHICH refusal fired rather than
    /// that one did.
    fn must<T>(result: Result<T, AppError>, label: &str) -> T {
        match result {
            Ok(value) => value,
            Err(AppError(status, detail)) => panic!("{label}: {status} {detail}"),
        }
    }

    /// One recipe with a required service, a required secret and a required port, resolved.
    fn seeded(data_dir: &str, env: &str) -> Value {
        let recipe = new_recipe(
            "recipe_0a92",
            &json!({
                "substrate": "container",
                "services": [{
                    "name": "db",
                    "command": "postgres -D /var/lib/postgresql/data",
                    "lifecycle": "required",
                    "trigger": "environment_start",
                }],
                "ports": [{ "port": 5432, "protocol": "tcp", "access_policy": "private" }],
                "secret_requirement_refs": ["secret://hypervisor/db-password"],
                "scm_auth_requirement_refs": [],
                "init_tasks": [],
                "prebuild_tasks": [],
                "post_start_tasks": [],
            }),
            "explicit",
            Some("project:m092"),
        );
        must(persist_recipe(data_dir, &recipe), "recipe persists");
        must(resolve_recipe(data_dir, &recipe, env), "resolution")
    }

    /// The posture half — everything a caller legitimately supplies.
    fn posture(resolution_ref: &str) -> Value {
        json!({
            "resolution_ref": resolution_ref,
            "placement_decision_ref": "placement-decision://hypervisor/pld-1",
            "runtime_operator": "local",
            "source_ref": "source://hypervisor/repo-1",
            "artifact_ref": "artifact://hypervisor/build-1",
            "configuration_ref": "configuration://hypervisor/cfg-1",
            "connectivity_profile_ref": "connectivity-profile://hypervisor/loopback-only",
            "resource_isolation_profile_ref": "resource-isolation-profile://hypervisor/standard",
            "temporal_verification_profile_ref": "temporal-verification-profile://hypervisor/local",
            "authority_currentness_floor_ref": "authority-currentness-floor://hypervisor/floor-1",
            "required_identity_context_ref": "identity-context://hypervisor/local-operator",
            "resource_budget_ref": "budget://hypervisor/b-1",
            "stop_policy_ref": "stop-policy://hypervisor/graceful",
            "recovery_policy_ref": "recovery-policy://hypervisor/restart-once",
            "rollback_policy_ref": "rollback-policy://hypervisor/revert",
            "service_refs": ["service://hypervisor/db"],
            "required_secret_refs": ["secret://hypervisor/db-password"],
            "port_refs": ["port://hypervisor/env-1/5432"],
        })
    }

    fn code(error: &(StatusCode, Json<Value>)) -> String {
        error.1["code"].as_str().unwrap_or_default().to_string()
    }

    #[test]
    fn a_plan_freezes_its_predecessors_by_content_and_validates_before_it_is_written() {
        let dir = scratch("mint");
        let data_dir = dir.to_str().unwrap();
        let resolution = seeded(data_dir, "env-1");
        let plan = admit_startup_plan(
            data_dir,
            &posture(resolution["resolution_ref"].as_str().unwrap()),
        )
        .expect("plan admits");

        validate_architecture_contract(PLAN_CONTRACT, &plan)
            .expect("the live minted plan validates against the registered contract");
        // Exact predecessor binding, both by name AND by content.
        // The plan speaks the OWNER-QUALIFIED vocabulary while the resolution plane keeps its
        // historical bare spellings as read-only v1 aliases, exactly as canon directs. The bare id
        // survives as the final path segment, so the binding is still exact and still reversible by
        // inspection — asserted that way rather than by string equality, which would have passed
        // only if the rename had not happened.
        assert_eq!(
            plan["development_environment_recipe_resolution_ref"]
                .as_str()
                .unwrap(),
            format!(
                "environment-recipe-resolution://hypervisor/{}",
                resolution["resolution_ref"].as_str().unwrap()
            )
        );
        assert_eq!(
            plan["development_environment_recipe_ref"].as_str().unwrap(),
            format!(
                "development-environment-recipe://hypervisor/{}",
                resolution["recipe_ref"].as_str().unwrap()
            )
        );
        assert_eq!(
            plan["environment_ref"],
            json!("environment://hypervisor/env-1")
        );
        let recipe = load_recipe(data_dir, resolution["recipe_ref"].as_str().unwrap()).unwrap();
        assert_eq!(
            plan["development_environment_recipe_content_hash"].as_str().unwrap(),
            jcs_sha256(&recipe).unwrap(),
            "the content hash is computed from the STORED recipe, not from anything the caller said"
        );
        assert_eq!(
            plan["development_environment_recipe_resolution_hash"]
                .as_str()
                .unwrap(),
            jcs_sha256(&resolution).unwrap()
        );
        // Revision-exact, because canon requires a successor for every change.
        assert!(plan["startup_plan_ref"]
            .as_str()
            .unwrap()
            .ends_with("/revision/1"));
        // A plan never carries a blockage.
        assert!(plan.get("blocked_reason").is_none());
    }

    #[test]
    fn the_plan_hash_excludes_itself_and_covers_every_nullable_field() {
        let dir = scratch("hash");
        let data_dir = dir.to_str().unwrap();
        let resolution = seeded(data_dir, "env-hash");
        let plan = admit_startup_plan(
            data_dir,
            &posture(resolution["resolution_ref"].as_str().unwrap()),
        )
        .expect("plan admits");

        let mut hashable = plan.clone();
        hashable.as_object_mut().unwrap().remove("plan_hash");
        assert_eq!(
            plan["plan_hash"].as_str().unwrap(),
            jcs_sha256(&hashable).unwrap(),
            "the hash covers the body with plan_hash removed — never a placeholder that would \
             silently become part of what was committed"
        );
        // Every nullable field is PRESENT and null. Absent and null are different records, and
        // canon puts the nullable fields inside the hash.
        for field in NULLABLE_PLAN_FIELDS {
            assert!(
                plan.get(*field).is_some(),
                "{field} must be present so the hash can cover it"
            );
            assert!(
                plan[*field].is_null(),
                "{field} defaults to a registered null"
            );
        }
        // And the nullables genuinely move the hash: a plan serving a System is different bytes.
        let mut with_system = hashable.clone();
        with_system["system_ref"] = json!("system://hypervisor/sys-1");
        assert_ne!(
            jcs_sha256(&with_system).unwrap(),
            jcs_sha256(&hashable).unwrap()
        );
    }

    #[test]
    fn a_caller_may_not_assert_the_lineage_the_plan_exists_to_freeze() {
        let dir = scratch("assert");
        let data_dir = dir.to_str().unwrap();
        let resolution = seeded(data_dir, "env-assert");
        let resolution_ref = resolution["resolution_ref"].as_str().unwrap();
        for field in SERVER_RESOLVED_PLAN_FIELDS {
            let mut body = posture(resolution_ref);
            body[*field] = json!("sha256:beef");
            let error = admit_startup_plan(data_dir, &body)
                .expect_err(&format!("{field} must be refused when asserted"));
            assert_eq!(
                code(&error),
                "environment_startup_plan_server_resolved_field_asserted",
                "{field}"
            );
        }
    }

    #[test]
    fn a_blocked_resolution_never_becomes_an_admitted_plan() {
        let dir = scratch("blocked");
        let data_dir = dir.to_str().unwrap();
        let mut resolution = seeded(data_dir, "env-blocked");
        // Canon: a refused candidate remains a resolution refusal; it never becomes an admitted
        // startup plan with an embedded blockage. Written straight to the record, because the
        // point is what the ADMISSION does with a blocked predecessor it finds on disk.
        resolution["blocked_reason"] = json!("secret_lease_missing");
        let id = resolution["resolution_ref"].as_str().unwrap().to_string();
        persist_record(data_dir, "recipe-resolutions", &id, &resolution).expect("persist");

        let error = admit_startup_plan(data_dir, &posture(&id)).expect_err("must refuse");
        assert_eq!(
            code(&error),
            "environment_startup_plan_from_a_blocked_resolution"
        );
    }

    #[test]
    fn a_plan_that_declares_less_than_its_resolution_requires_is_refused() {
        let dir = scratch("edges");
        let data_dir = dir.to_str().unwrap();
        let resolution = seeded(data_dir, "env-edges");
        let resolution_ref = resolution["resolution_ref"].as_str().unwrap();

        // Each required edge, dropped one at a time. Dropping them together would let one check
        // cover for another and would not distinguish a working pair from a working single.
        for (field, empty) in [
            ("service_refs", json!([])),
            ("required_secret_refs", json!([])),
            ("port_refs", json!([])),
        ] {
            let mut body = posture(resolution_ref);
            body[field] = empty;
            let error = admit_startup_plan(data_dir, &body)
                .expect_err(&format!("dropping {field} must be refused"));
            assert_eq!(
                code(&error),
                "environment_startup_plan_undeclared_required_edge",
                "{field}"
            );
        }
    }

    #[test]
    fn a_port_declared_under_a_different_number_does_not_satisfy_the_required_one() {
        let dir = scratch("ports");
        let data_dir = dir.to_str().unwrap();
        let resolution = seeded(data_dir, "env-ports");
        let mut body = posture(resolution["resolution_ref"].as_str().unwrap());
        // The plausible wrong implementation compares a non-empty list to a non-empty list and
        // passes. The resolution requires 5432; this declares 5433.
        body["port_refs"] = json!(["port://hypervisor/env-1/5433"]);
        let error = admit_startup_plan(data_dir, &body).expect_err("must refuse");
        assert_eq!(
            code(&error),
            "environment_startup_plan_undeclared_required_edge"
        );
        assert!(
            error.1["detail"].as_str().unwrap().contains("5432"),
            "the refusal names the port that is missing, not merely that one is"
        );
    }

    #[test]
    fn change_mints_a_successor_rather_than_patching_the_admitted_plan() {
        let dir = scratch("successor");
        let data_dir = dir.to_str().unwrap();
        let resolution = seeded(data_dir, "env-succ");
        let resolution_ref = resolution["resolution_ref"].as_str().unwrap();
        let first = admit_startup_plan(data_dir, &posture(resolution_ref)).expect("first");

        // Changed placement — canon's own first example of what requires a successor.
        let mut changed = posture(resolution_ref);
        changed["placement_decision_ref"] = json!("placement-decision://hypervisor/pld-2");
        let second = admit_startup_plan(data_dir, &changed).expect("second");

        assert!(first["startup_plan_ref"]
            .as_str()
            .unwrap()
            .ends_with("/revision/1"));
        assert!(second["startup_plan_ref"]
            .as_str()
            .unwrap()
            .ends_with("/revision/2"));
        assert_ne!(first["plan_hash"], second["plan_hash"]);
        // The first plan is untouched on disk: a successor is not an edit.
        let stored = read_record_dir(data_dir, STARTUP_PLAN_RECORDS);
        assert_eq!(stored.len(), 2);
        let reread = stored
            .iter()
            .find(|row| row["startup_plan_ref"] == first["startup_plan_ref"])
            .expect("the first plan is still there");
        assert_eq!(reread["plan_hash"], first["plan_hash"]);
        assert_eq!(
            reread["placement_decision_ref"],
            first["placement_decision_ref"]
        );
    }

    #[test]
    fn a_missing_posture_field_refuses_rather_than_substituting_a_default() {
        let dir = scratch("posture");
        let data_dir = dir.to_str().unwrap();
        let resolution = seeded(data_dir, "env-posture");
        let mut body = posture(resolution["resolution_ref"].as_str().unwrap());
        body.as_object_mut().unwrap().remove("stop_policy_ref");
        let error = admit_startup_plan(data_dir, &body).expect_err("must refuse");
        assert_eq!(
            code(&error),
            "environment_startup_plan_undeclared_posture_field"
        );
    }

    #[test]
    fn a_resolution_this_daemon_cannot_read_mints_nothing() {
        let dir = scratch("absent");
        let data_dir = dir.to_str().unwrap();
        let error =
            admit_startup_plan(data_dir, &posture("reso_does_not_exist")).expect_err("must refuse");
        assert_eq!(
            code(&error),
            "environment_startup_plan_resolution_not_found"
        );
        assert!(read_record_dir(data_dir, STARTUP_PLAN_RECORDS).is_empty());
    }

    #[test]
    fn the_same_recipe_resolves_to_different_plans_across_postures() {
        let dir = scratch("postures");
        let data_dir = dir.to_str().unwrap();
        let resolution = seeded(data_dir, "env-multi");
        let resolution_ref = resolution["resolution_ref"].as_str().unwrap();
        let local = admit_startup_plan(data_dir, &posture(resolution_ref)).expect("local");

        let mut managed = posture(resolution_ref);
        managed["runtime_operator"] = json!("ioi_managed");
        managed["provider_account_ref"] = json!("provider-account://hypervisor/acct-1");
        managed["budget_lease_ref"] = json!("budget-lease://hypervisor/bl-1");
        let hosted = admit_startup_plan(data_dir, &managed).expect("managed");

        // Canon's reason for the plan being a separate object from the resolution: one recipe,
        // one resolution, two concrete attempts that are not each other.
        assert_eq!(
            local["development_environment_recipe_content_hash"],
            hosted["development_environment_recipe_content_hash"],
            "same recipe"
        );
        assert_ne!(local["plan_hash"], hosted["plan_hash"]);
        assert_eq!(local["provider_account_ref"], Value::Null);
        assert_eq!(
            hosted["provider_account_ref"],
            json!("provider-account://hypervisor/acct-1")
        );
        validate_architecture_contract(PLAN_CONTRACT, &hosted).expect("managed plan validates");
    }

    #[test]
    fn production_writes_are_contract_checked_and_not_only_under_cfg_test() {
        let dir = scratch("prodcheck");
        let data_dir = dir.to_str().unwrap();
        // A recipe the registered contract refuses. Before M09.2 this persisted silently: the
        // module's three validation calls were all inside its test module, so the check ran where
        // a running daemon never reaches.
        let mut broken = new_recipe(
            "recipe_0b0e",
            &json!({ "substrate": "container" }),
            "explicit",
            None,
        );
        broken["substrate"] = json!("not-a-registered-substrate");
        assert!(
            broken["recipe_ref"].is_string(),
            "otherwise the refusal could be about identity"
        );
        let refused = persist_recipe(data_dir, &broken);
        assert!(
            refused.is_err(),
            "a record the contract refuses is not written"
        );
        assert!(
            !std::path::Path::new(data_dir)
                .join("recipes")
                .join("recipe_0b0e.json")
                .exists(),
            "and it is refused BEFORE the write, not written and then explained"
        );
    }
}
