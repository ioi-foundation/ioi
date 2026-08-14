//! WS-A + WS-B — Environment object model + `local_workspace_provider_v0` (daemon-owned).
//!
//! Phase 0 environment lifecycle as DAEMON TRUTH (no JS-owned state). Records persist under
//! `state_dir/environments/<id>.json`. The local-workspace provider does REAL local
//! provisioning (a scoped workspace dir under the daemon data dir); it is single-user /
//! trusted-operator and is NOT a cross-tenant isolation boundary — per the Dev Env Substrate
//! Doctrine, VM/microVM/HypervisorOS are the isolation claim for untrusted/cross-tenant work
//! (modeled in the class catalog, disabled in v0). Honest labels travel on `status`.
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use ioi_services::agentic::runtime::kernel::emergency_containment::{
    admit_cache_path, admit_cache_scope, admit_isolated_execution, close_deletion,
    truthful_isolation_label, unsafe_path_gate, DeclaredIsolation, DeletionOutcome, ExecutionLocus,
    IsolatedSubstrate, UNVERIFIED_WORKSPACE_RESTORE_GATE,
};
use ioi_services::agentic::runtime::kernel::runtime_goal_pursuit::GoalPursuitCore;
use ioi_types::app::agentic::InferenceOptions;
use serde_json::{json, Value};

use super::{
    invoke_native_local, iso_now, persist_invocation_receipt, persist_record, read_record_dir,
    remove_record, resolve_route, short_hash, AppError, DaemonState,
};

const ENV_SCHEMA: &str = "ioi.hypervisor.environment.v1";
const PROVIDER: &str = "local_workspace_provider_v0";

/// The substrate scope kinds this plane's custody lane owns.
///
/// `org://local` is the ONLY constructible organization and EVERY principal holds it, so a check of
/// the form "is the caller in the owner tenant" isolates nothing. Ownership here is per-PRINCIPAL,
/// read from the substrate's own immutable scope pin, exactly as the managed-runtime custody surface
/// resolves its backups.
const ENVIRONMENT_SCOPE_KIND: &str = "hypervisor-environment";
const CAPTURE_SCOPE_KIND: &str = "hypervisor-environment-capture";
/// The owner-scoped stream namespace for one capture's LOCAL custody lifecycle.
const CUSTODY_NAMESPACE: &str = "hypervisor-environment-custody";
const CAPTURE_LIFECYCLE_SCHEMA: &str = "ioi.hypervisor.environment-capture-lifecycle.v1";

// The retained v1 transcript records predate principal ownership coordinates. They remain a
// local-operator projection, but must never become global managed-deployment truth merely because
// an authenticated request passed the generic auth gate. Refuse before enumerating, opening, or
// mutating the family until a later contract supplies owner coordinates and migration semantics.
fn agent_run_transcript_access_refusal(
    st: &DaemonState,
    headers: &HeaderMap,
) -> Option<(StatusCode, Json<Value>)> {
    match super::lifecycle_routes::deployment_auth_posture(&st.data_dir, headers) {
        "local_development" => None,
        "exposed_untrusted" => Some((
            StatusCode::FORBIDDEN,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "agent_run_transcript_exposed_untrusted_refused",
                    "message": "Run transcript truth is unavailable on an exposed deployment without enforceable principal ownership."
                }
            })),
        )),
        _ => Some((
            StatusCode::FORBIDDEN,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "agent_run_transcript_principal_scope_unavailable",
                    "message": "The retained transcript family has no principal ownership coordinates and cannot be accessed on a managed deployment."
                }
            })),
        )),
    }
}

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
    let phase = env["status"]["phase"]
        .as_str()
        .unwrap_or("stopped")
        .to_string();
    let comp_phase = |env: &Value, c: &str| -> String {
        env["status"]["components"][c]["phase"]
            .as_str()
            .unwrap_or("pending")
            .to_string()
    };
    if phase != "running" {
        let reason = if phase == "stopped" {
            "not_started"
        } else {
            phase.as_str()
        };
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
    } else if not_ready
        .iter()
        .any(|c| matches!(c.as_str(), "workspace_content" | "sandbox" | "provisioner"))
    {
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
    id.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
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
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

fn persist_env(data_dir: &str, env: &Value) -> Result<(), AppError> {
    let id = env["id"].as_str().unwrap_or("env");
    persist_record(data_dir, "environments", id, env).map_err(|e| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("persist env: {e}"),
        )
    })
}

fn new_env(id: &str, spec: &Value) -> Result<Value, AppError> {
    let now = iso_now();
    let mut env = json!({
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
    });
    // The environment-local command-execution guardrail declaration, VALIDATED then RETAINED.
    //
    // It was silently DROPPED here, which made the local additions canon requires
    // (platform-operability.md PO-10, "environment-local declarations may only add denials")
    // unreachable from the product path: an operator could declare extra denials at create and
    // the durable record would carry none of them. Dropping is the widening direction.
    //
    // Validation uses the SAME semantic validator the enforcement point composes with, so the two
    // cannot drift: a declaration this accepts is exactly a declaration the scoped primitive can
    // compose. Refusing here — before persist — matters because the enforcement point treats a
    // malformed declaration as INDETERMINATE and denies every command in that environment, while
    // no route exists that can update `spec.guardrails` afterwards. Admitting one would durably
    // brick the environment's terminal with no in-API repair.
    //
    // A valid declaration is retained VERBATIM. The key is omitted entirely when the spec carries
    // none, so "no local declaration" stays distinguishable from "an empty one", and records
    // written before this field was retained keep composing as no-additions.
    if let Err(why) = super::operability_routes::validate_environment_guardrail_declaration(spec) {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            format!("environment-local command-execution guardrail declaration is invalid: {why}. It may carry only deny_commands and deny_executables, each an array of non-empty strings, and it may only ADD denials."),
        ));
    }
    // A JSON null is ABSENCE, exactly as the validator and the composition step read it, so the
    // key is omitted rather than retained as null. Retaining it would contradict the contract
    // stated above — "the key is omitted entirely when the spec carries none" — and mint a
    // null-shaped declaration that no caller wrote.
    if let Some(declaration) = spec.get("guardrails").filter(|value| !value.is_null()) {
        env["spec"]["guardrails"] = declaration.clone();
    }
    Ok(env)
}

/// Append a typed `HypervisorEnvironmentLifecycleObservation` (canon stage/component/
/// condition_kind/severity taxonomy) — the timeline behind the status projection. Bumps
/// status_version + last_observation_ref. Does NOT set the env phase (use `set_phase`) or
/// component phase (use `set_component`) — observation is evidence, status is the projection.
fn observe(
    env: &mut Value,
    stage: &str,
    component: &str,
    condition_kind: &str,
    severity: &str,
    message: &str,
) {
    let now = iso_now();
    let idx = env["lifecycle_observations"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
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
    std::fs::create_dir_all(&ws).map_err(|e| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("provision workspace: {e}"),
        )
    })?;
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
                "-c",
                "user.email=operator@local",
                "-c",
                "user.name=local_operator",
                "commit",
                "--allow-empty",
                "-q",
                "-m",
                "init",
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
/// Seed the default Dev Container files into the workspace working tree. Returns whether the
/// devcontainer is present after this call (already existed, or both seed files were written) so
/// the caller does not assert "devcontainer scaffolded" over a write that did not land.
fn scaffold_devcontainer(ws: &str) -> bool {
    let dc_dir = std::path::Path::new(ws).join(".devcontainer");
    if dc_dir.exists() {
        return true;
    }
    if std::fs::create_dir_all(&dc_dir).is_err() {
        return false;
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
    // CLASSIFIED — bootstrap seed: these are uncommitted working-tree seed files (the `from scratch`
    // baseline), re-seedable and never a truth claim. Measure the writes and return the result so
    // the caller conditions its "devcontainer scaffolded" component message on what actually landed.
    let wrote_json = std::fs::write(dc_dir.join("devcontainer.json"), devcontainer_json).is_ok();
    let wrote_dockerfile = std::fs::write(dc_dir.join("Dockerfile"), dockerfile).is_ok();
    wrote_json && wrote_dockerfile
}

// ---- WS-3: typed Services / Tasks / Ports (tasks run as REAL processes) ----

/// Run one resolved task as a REAL bounded process in the workspace; return a typed
/// `HypervisorEnvironmentTask` record with phase/exit_code/log_ref.
fn run_task(ws: &str, log_dir: &std::path::Path, task: &Value) -> Value {
    let name = task.get("name").and_then(|v| v.as_str()).unwrap_or("task");
    let command = task.get("command").and_then(|v| v.as_str()).unwrap_or("");
    let trigger = task
        .get("trigger")
        .and_then(|v| v.as_str())
        .unwrap_or("environment_start");
    let required = task
        .get("required")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let lifecycle = if required { "required" } else { "optional" };
    let task_ref = format!("task_{}", safe_id(name));
    let started_at = iso_now();
    if command.is_empty() {
        return json!({ "task_ref": task_ref, "name": name, "trigger": trigger, "lifecycle": lifecycle,
            "phase": "succeeded", "exit_code": 0, "started_at": started_at, "ended_at": iso_now(), "log_ref": Value::Null });
    }
    let out = std::process::Command::new("timeout")
        .arg("120")
        .arg("bash")
        .arg("-lc")
        .arg(command)
        .current_dir(ws)
        .output();
    let (phase, exit_code, log) = match out {
        Ok(o) => {
            let code = o.status.code().unwrap_or(-1);
            let mut log = String::from_utf8_lossy(&o.stdout).to_string();
            log.push_str(&String::from_utf8_lossy(&o.stderr));
            (
                if o.status.success() {
                    "succeeded"
                } else {
                    "failed"
                },
                code,
                log,
            )
        }
        Err(e) => ("failed", -1, format!("spawn error: {e}")),
    };
    let log_path = log_dir.join(format!("{task_ref}.log"));
    // CLASSIFIED — best-effort telemetry: the task ran as a REAL process and its phase/exit_code are
    // the truth; the log file is a convenience artifact. Null the returned log_ref when the write
    // failed so no reader cites a log path that does not exist.
    let log_ref = if std::fs::write(&log_path, &log).is_ok() {
        json!(log_path.to_string_lossy())
    } else {
        Value::Null
    };
    json!({ "task_ref": task_ref, "name": name, "command": command, "trigger": trigger,
        "lifecycle": lifecycle, "phase": phase, "exit_code": exit_code,
        "started_at": started_at, "ended_at": iso_now(), "log_ref": log_ref })
}

/// Run a resolution's tasks (prebuild → environment_start order) as real processes.
fn run_resolved_tasks(data_dir: &str, env_id: &str, ws: &str, resolution: &Value) -> Vec<Value> {
    let log_dir = std::path::Path::new(data_dir)
        .join("environments")
        .join(safe_id(env_id))
        .join("task-logs");
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
    let name = svc
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("service");
    let lifecycle = svc
        .get("lifecycle")
        .and_then(|v| v.as_str())
        .unwrap_or("optional");
    let healthcheck = svc.get("healthcheck").and_then(|v| v.as_str());
    let service_ref = format!("svc_{}", safe_id(name));
    let phase = match healthcheck {
        Some(hc) if !hc.is_empty() => {
            let healthy = std::process::Command::new("timeout")
                .arg("30")
                .arg("bash")
                .arg("-lc")
                .arg(hc)
                .current_dir(ws)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if healthy {
                "running"
            } else {
                "degraded"
            }
        }
        _ => {
            if lifecycle == "required" {
                "degraded"
            } else {
                "running"
            }
        }
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
    let access = p
        .get("access_policy")
        .and_then(|v| v.as_str())
        .unwrap_or("private");
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
        if env["id"].as_str() == Some(exclude_env) {
            continue;
        }
        if env["status"]["phase"].as_str() != Some("running") {
            continue;
        }
        if let Some(ports) = env["status"]["ports"].as_array() {
            for hp in ports
                .iter()
                .filter_map(|p| p.get("host_port").and_then(|v| v.as_u64()))
            {
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
            port["conflict_reason"] = json!(format!(
                "host_port {hp} already bound by another running env"
            ));
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
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '/' && i + 1 < b.len() {
            match b[i + 1] as char {
                '/' => {
                    i += 2;
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
                '*' => {
                    i += 2;
                    while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                        i += 1;
                    }
                    i += 2;
                    continue;
                }
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
            if e2 {
                e2 = false;
            } else if c == '\\' {
                e2 = true;
            } else if c == '"' {
                s2 = false;
            }
            j += 1;
            continue;
        }
        if c == '"' {
            s2 = true;
            clean.push(c);
            j += 1;
            continue;
        }
        if c == ',' {
            let mut k = j + 1;
            while k < ob.len() && (ob[k] as char).is_whitespace() {
                k += 1;
            }
            if k < ob.len() && (ob[k] == b'}' || ob[k] == b']') {
                j += 1;
                continue;
            }
        }
        clean.push(c);
        j += 1;
    }
    serde_json::from_str(&clean).map_err(|e| e.to_string())
}

/// TCP liveness probe: is something accepting on 127.0.0.1:<port> right now?
fn port_listening(port: u64) -> bool {
    if port == 0 || port > 65535 {
        return false;
    }
    match format!("127.0.0.1:{port}").parse::<std::net::SocketAddr>() {
        Ok(addr) => {
            std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(300))
                .is_ok()
        }
        Err(_) => false,
    }
}

/// GET /v1/hypervisor/environments/:id/ports — observe the env's ports with live TCP liveness.
pub(crate) async fn handle_env_ports(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let Some(env) = load_env(&st.data_dir, &id) else {
        return Ok(Json(
            json!({ "ok": false, "reason": "environment not found" }),
        ));
    };
    let ports: Vec<Value> = env["status"]["ports"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|mut p| {
            let port = p.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
            p["listening"] = json!(port_listening(port));
            p
        })
        .collect();
    Ok(Json(
        json!({ "ok": true, "environment_id": id, "ports": ports }),
    ))
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
        return Ok(Json(
            json!({ "ok": false, "reason": "environment not found" }),
        ));
    };
    if env["status"]["phase"].as_str() != Some("running") {
        return Ok(Json(
            json!({ "ok": false, "reason": "environment not running", "fail_closed": true }),
        ));
    }
    if env["status"]["substrate"].as_str() == Some("microvm") {
        return Ok(Json(
            json!({ "ok": false, "reason": "guest_forward_unwired",
            "detail": "microVM guest port-forward is the provider-ladder follow-up; the local provider preview is live",
            "fail_closed": true }),
        ));
    }
    if port == 0 || port > 65535 {
        return Ok(Json(json!({ "ok": false, "reason": "invalid port" })));
    }
    let listening = port_listening(port);
    let lease = super::authority_routes::issue_capability_lease(
        &st.data_dir,
        "operator",
        "environment.port",
        json!([format!("environment:{id}"), format!("port:{port}")]),
        3600,
    );
    let lease_id = lease
        .get("grant_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let service_key = format!("envport_{}_{}", safe_id(&id), port);
    {
        let mut proxies = st.editor_proxies.lock().unwrap();
        super::editor_proxy::stop_editor_proxy(&mut proxies, &service_key);
    }
    let (public_port, proxy) = match super::editor_proxy::bind_editor_proxy(
        &st.data_dir,
        &service_key,
        port as u16,
        &lease_id,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return Ok(Json(
                json!({ "ok": false, "reason": format!("preview gateway bind failed: {e}") }),
            ))
        }
    };
    st.editor_proxies.lock().unwrap().insert(service_key, proxy);
    let url = format!("http://127.0.0.1:{public_port}/?lease={lease_id}");
    let mut ports = env["status"]["ports"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let entry = json!({ "port": port, "protocol": "tcp", "access_policy": "session_lease",
        "exposure_state": "open", "capability_lease_ref": lease_id, "url": url,
        "public_proxy_port": public_port, "listening": listening });
    match ports
        .iter_mut()
        .find(|p| p.get("port").and_then(|v| v.as_u64()) == Some(port))
    {
        Some(existing) => {
            for (k, v) in entry.as_object().unwrap() {
                existing[k] = v.clone();
            }
        }
        None => ports.push(entry),
    }
    env["status"]["ports"] = json!(ports);
    observe(
        &mut env,
        "exposing_port",
        "connectivity",
        "content_ready",
        "info",
        &format!("port {port} exposed behind a capability lease (preview {url})"),
    );
    persist_env(&st.data_dir, &env)?;
    Ok(Json(
        json!({ "ok": true, "environment_id": id, "port": port, "url": url,
        "accessToken": lease_id, "public_proxy_port": public_port, "listening": listening,
        "fail_closed_on_revoke": true }),
    ))
}

/// POST /v1/hypervisor/environments/:id/ports/:port/unexpose — revoke the bound lease + tear down
/// the gateway. The preview URL then fails closed.
pub(crate) async fn handle_env_port_unexpose(
    State(st): State<Arc<DaemonState>>,
    AxumPath((id, port)): AxumPath<(String, u64)>,
) -> Result<Json<Value>, AppError> {
    let Some(mut env) = load_env(&st.data_dir, &id) else {
        return Ok(Json(
            json!({ "ok": false, "reason": "environment not found" }),
        ));
    };
    let service_key = format!("envport_{}_{}", safe_id(&id), port);
    {
        let mut proxies = st.editor_proxies.lock().unwrap();
        super::editor_proxy::stop_editor_proxy(&mut proxies, &service_key);
    }
    let mut ports = env["status"]["ports"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut lease_ref = None;
    if let Some(existing) = ports
        .iter_mut()
        .find(|p| p.get("port").and_then(|v| v.as_u64()) == Some(port))
    {
        lease_ref = existing
            .get("capability_lease_ref")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        existing["exposure_state"] = json!("closed");
        existing["url"] = Value::Null;
        existing["capability_lease_ref"] = Value::Null;
        existing["public_proxy_port"] = Value::Null;
    }
    if let Some(l) = &lease_ref {
        super::authority_routes::revoke_lease(&st.data_dir, l);
    }
    env["status"]["ports"] = json!(ports);
    observe(
        &mut env,
        "closing_port",
        "connectivity",
        "content_ready",
        "info",
        &format!("port {port} unexposed (lease revoked, gateway torn down)"),
    );
    persist_env(&st.data_dir, &env)?;
    Ok(Json(
        json!({ "ok": true, "environment_id": id, "port": port, "exposure_state": "closed" }),
    ))
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
        if out.len() >= 4000 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            if out.len() >= 4000 {
                return;
            }
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name == ".git" {
                continue;
            }
            let p = e.path();
            match e.file_type() {
                Ok(ft) if ft.is_dir() => walk(&p, root, out),
                Ok(ft) if ft.is_file() => {
                    if let Ok(rel) = p.strip_prefix(root) {
                        out.push(rel.to_string_lossy().replace('\\', "/"));
                    }
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
    let Some(ws) = env["status"]["workspace_root"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
    else {
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
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let identity = super::scm_publication_routes::request_identity(&st.data_dir, &headers)
        .map_err(|(status, Json(body))| {
            AppError(
                status,
                body.get("message")
                    .or_else(|| body.get("reason"))
                    .and_then(Value::as_str)
                    .unwrap_or("publication identity refused")
                    .to_owned(),
            )
        })?;
    let Some(env) = load_env(&st.data_dir, &id) else {
        return Ok(Json(
            json!({ "ok": false, "reason": "environment not found" }),
        ));
    };
    let publication_owner_ref = super::scm_publication_routes::publication_owner_for_environment(
        &identity, &env,
    )
    .map_err(|(status, Json(body))| {
        AppError(
            status,
            body.get("message")
                .or_else(|| body.get("reason"))
                .and_then(Value::as_str)
                .unwrap_or("environment publication ownership refused")
                .to_owned(),
        )
    })?;
    let Some(ws) = env["status"]["workspace_root"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
    else {
        return Ok(Json(
            json!({ "ok": false, "reason": "workspace not started", "fail_closed": true }),
        ));
    };
    // lenient git (git diff exits 1 when differences exist — not an error for our read paths).
    let git = |args: &[&str]| -> String {
        std::process::Command::new("git")
            .arg("-C")
            .arg(&ws)
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    };
    let porcelain = git(&["status", "--porcelain", "-uall"]);
    let changed: Vec<String> = porcelain
        .lines()
        .filter_map(|l| l.get(3..).map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .collect();
    let base_ref = {
        let h = git(&["rev-parse", "HEAD"]).trim().to_string();
        if h.is_empty() {
            "EMPTY".to_string()
        } else {
            h
        }
    };
    let mut diff = git(&["diff", "--binary"]);
    for line in porcelain.lines() {
        if let Some(rest) = line.strip_prefix("?? ") {
            let d = git(&[
                "diff",
                "--no-index",
                "--binary",
                "--",
                "/dev/null",
                rest.trim(),
            ]);
            if !d.is_empty() {
                diff.push('\n');
                diff.push_str(&d);
            }
        }
    }
    let diff = diff.trim().to_string();
    let stat = git(&["diff", "--stat"]).trim().to_string();
    let branch = {
        let b = git(&["branch", "--show-current"]).trim().to_string();
        if b.is_empty() {
            "local-workspace".to_string()
        } else {
            b
        }
    };
    let head = git(&["rev-parse", "HEAD"]).trim().to_string();
    let pid = format!(
        "prd_{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let title = if changed.is_empty() {
        "No workspace changes detected"
    } else {
        "Proposed workspace changes"
    };
    let canonical_base_revision = head.len() >= 40
        && head.len() <= 64
        && head
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    let publication_proposal_ref = format!("proposal://local/hypervisor/{pid}");
    let mut publication_files = Vec::new();
    if canonical_base_revision {
        for line in porcelain.lines() {
            let Some(status) = line.get(..2) else {
                continue;
            };
            let Some(raw_path) = line.get(3..) else {
                continue;
            };
            let relative_path = raw_path
                .rsplit_once(" -> ")
                .map(|(_, target)| target)
                .unwrap_or(raw_path)
                .trim();
            if relative_path.is_empty() {
                continue;
            }
            let change_kind = if status.contains('D') {
                "removed"
            } else if status == "??" || status.contains('A') {
                "added"
            } else {
                "modified"
            };
            let content_digest = if change_kind == "removed" {
                Value::Null
            } else {
                let bytes = std::fs::read(std::path::Path::new(&ws).join(relative_path)).map_err(
                    |error| {
                        AppError(
                            StatusCode::CONFLICT,
                            format!(
                                "pull-request draft cannot bind changed file '{relative_path}': {error}"
                            ),
                        )
                    },
                )?;
                json!(format!("sha256:{}", sha256_hex_bytes(&bytes)))
            };
            publication_files.push(json!({
                "path": relative_path,
                "change_kind": change_kind,
                "content_digest": content_digest,
                "proposal_ref": publication_proposal_ref,
            }));
        }
    }
    let admitted_publication_proposal = if canonical_base_revision && !publication_files.is_empty()
    {
        let candidate = json!({
            "proposal_ref": publication_proposal_ref,
            "base_revision_id": format!("scm-revision:{head}"),
            "files": publication_files,
            "work_run_ref": Value::Null,
        });
        Some(
            super::scm_publication_routes::admit_publication_proposal(
                &st.data_dir,
                &identity,
                &publication_owner_ref,
                &format!("scm-pr-draft:{pid}"),
                &candidate,
            )
            .map_err(|(status, Json(body))| {
                AppError(
                    status,
                    format!(
                        "pull-request publication proposal refused: {}",
                        body.get("message")
                            .or_else(|| body.get("reason"))
                            .and_then(Value::as_str)
                            .unwrap_or("unknown refusal")
                    ),
                )
            })?,
        )
    } else {
        None
    };
    // DAEMON writes the artifact into the env's scoped workspace (.hypervisor/pr-drafts/<id>.*).
    let dir = std::path::Path::new(&ws)
        .join(".hypervisor")
        .join("pr-drafts");
    std::fs::create_dir_all(&dir).map_err(|error| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("pull-request draft directory cannot be created: {error}"),
        )
    })?;
    let md_rel = format!(".hypervisor/pr-drafts/{pid}.md");
    let patch_rel = format!(".hypervisor/pr-drafts/{pid}.patch");
    let md = format!(
        "# {title}\n\nSource branch: {branch}\nBase: {base_ref}\nHead: {head}\nEnvironment: {id}\n\n## Changed files\n\n{}\n\n## Diffstat\n\n```text\n{}\n```\n\n## Notes\n\n- Daemon-owned local PR draft (proposal {pid}); not a remote pull request.\n- Remote publication requires an SCM connector and scoped (wallet) authority.\n",
        if changed.is_empty() { "- None".to_string() } else { changed.iter().map(|f| format!("- {f}")).collect::<Vec<_>>().join("\n") },
        if stat.is_empty() { "No tracked diff." } else { &stat },
    );
    let md_path = std::path::Path::new(&ws).join(&md_rel);
    let patch_path = std::path::Path::new(&ws).join(&patch_rel);
    std::fs::write(&md_path, md).map_err(|error| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("pull-request draft summary cannot be persisted: {error}"),
        )
    })?;
    if let Err(error) = std::fs::write(
        &patch_path,
        if diff.is_empty() {
            "# No tracked diff.\n".to_string()
        } else {
            format!("{diff}\n")
        },
    ) {
        let _ = std::fs::remove_file(&md_path);
        return Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("pull-request draft patch cannot be persisted: {error}"),
        ));
    }
    let draft = json!({
        "schema_version": "ioi.hypervisor.pull-request-draft.v1",
        "draft_id": pid, "environment_id": id, "title": title,
        "review_state": "proposed", "base_ref": base_ref, "head_ref": head, "source_branch": branch,
        "changed_files": changed, "diffstat": stat,
        "artifact_refs": { "summary": md_rel, "patch": patch_rel },
        "remote_publish": {
            "supported": admitted_publication_proposal.is_some(),
            "reason": if admitted_publication_proposal.is_some() {
                "an enumerated proposal is admitted; publication additionally requires an admitted destination binding, SCM connector, and wallet authority"
            } else if changed.is_empty() {
                "no changed files are available for an enumerated publication proposal"
            } else {
                "the workspace has no canonical base revision for an enumerated publication proposal"
            },
            "publication_proposal_ref": admitted_publication_proposal
                .as_ref()
                .and_then(|proposal| proposal.get("proposal_ref"))
                .cloned()
                .unwrap_or(Value::Null),
            "publication_proposal_hash": admitted_publication_proposal
                .as_ref()
                .and_then(|proposal| proposal.get("proposal_hash"))
                .cloned()
                .unwrap_or(Value::Null)
        },
        "host_mutation": false,
        "admission_state": "local_draft_not_agentgres_admitted",
        "at": iso_now()
    });
    if let Err(error) = persist_record(&st.data_dir, "pull-request-drafts", &pid, &draft) {
        let _ = std::fs::remove_file(&md_path);
        let _ = std::fs::remove_file(&patch_path);
        return Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("pull-request draft record cannot be persisted: {error}"),
        ));
    }
    Ok(Json(json!({
        "ok": true,
        "draft": draft,
        "proposal_ref": format!("local-pr-draft://{pid}"),
        "admission_state": "local_draft_not_agentgres_admitted"
    })))
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
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(mut body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Some(refusal) = agent_run_transcript_access_refusal(&st, &headers) {
        return refusal;
    }
    if !body.is_object() {
        return (
            StatusCode::OK,
            Json(json!({ "ok": false, "reason": "expected a run-transcript object" })),
        );
    }
    {
        let obj = body.as_object_mut().unwrap();
        obj.insert("run_id".into(), json!(id));
        obj.insert(
            "schema_version".into(),
            json!("ioi.hypervisor.agent-run-transcript.v1"),
        );
        obj.remove("state_root"); // recomputed below
        obj.insert("recorded_at".into(), json!(iso_now()));
    }
    // state_root over the canonical content (minus the volatile envelope) — tamper-evident handle.
    let mut canon = body.clone();
    if let Some(o) = canon.as_object_mut() {
        o.remove("state_root");
        o.remove("recorded_at");
    }
    let state_root = format!(
        "fnv:{}",
        short_hash(&serde_json::to_string(&canon).unwrap_or_default())
    );
    body["state_root"] = json!(state_root);
    // W1.2 / MEF-GAP-008 — the response returns a tamper-evident state_root for a record that MUST
    // be durable; a discarded write hands the caller a handle no reader (agent_run_get,
    // orchestration) will ever resolve. Refuse before returning the state_root.
    if persist_record(&st.data_dir, "agent-run-transcripts", &id, &body).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "agent_run_transcript_persistence_failed",
                "message": "the run-transcript did not commit — the returned state_root would resolve to nothing" }),
            ),
        );
    }
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "run_id": id, "state_root": state_root, "recorded_at": body["recorded_at"] }),
        ),
    )
}

/// GET /v1/hypervisor/agent-run-transcripts/:id — read one durable run-transcript.
pub(crate) async fn handle_agent_run_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    if let Some(refusal) = agent_run_transcript_access_refusal(&st, &headers) {
        return refusal;
    }
    match read_record_dir(&st.data_dir, "agent-run-transcripts")
        .into_iter()
        .find(|r| r["run_id"].as_str() == Some(id.as_str()))
    {
        Some(run) => (StatusCode::OK, Json(json!({ "ok": true, "run": run }))),
        None => (
            StatusCode::OK,
            Json(json!({ "ok": false, "reason": "run-transcript not found" })),
        ),
    }
}

/// GET /v1/hypervisor/agent-run-transcripts — list durable run-transcripts (newest-first).
pub(crate) async fn handle_agent_run_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    if let Some(refusal) = agent_run_transcript_access_refusal(&st, &headers) {
        return refusal;
    }
    let mut runs = read_record_dir(&st.data_dir, "agent-run-transcripts");
    runs.sort_by(|a, b| {
        a["created_at"]
            .as_str()
            .unwrap_or("")
            .cmp(b["created_at"].as_str().unwrap_or(""))
    });
    (StatusCode::OK, Json(json!({ "ok": true, "runs": runs })))
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
        .unwrap_or(if is_microvm {
            "private_vpc"
        } else {
            "local_only"
        });
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

/// The owning scope segment of a recipe cache.
///
/// CONTAINMENT: the cache used to be keyed on `recipe_ref` ALONE, so every System/tenant on the
/// node sharing a recipe also shared one cache directory — and the restored content is then
/// executed by the prebuild/init tasks. That is a cross-tenant cache-poisoning to code-execution
/// primitive. The owning scope is now part of the key, and a recipe with no owning scope is
/// refused rather than silently pooled into a shared cache.
fn recipe_cache_scope(recipe: &Value) -> Option<String> {
    for key in ["system_ref", "system_id", "owner_ref", "account_ref"] {
        if let Some(scope) = recipe.get(key).and_then(|v| v.as_str()) {
            if let Ok(scope) = admit_cache_scope(Some(scope)) {
                return Some(scope);
            }
        }
    }
    None
}

fn recipe_cache_dir(data_dir: &str, recipe_ref: &str, scope: &str) -> std::path::PathBuf {
    std::path::Path::new(data_dir)
        .join("recipe-cache")
        .join(safe_id(scope))
        .join(safe_id(recipe_ref))
}

/// Admit the recipe's declared `cache_paths`, dropping any that is absolute or escapes the root.
///
/// CONTAINMENT: `Path::join` does not normalize. A `cache_paths` entry of `"/root/.ssh"` made
/// `join` discard the base entirely, and `"../../environments/<other>/workspace"` walked out of
/// both the cache dir and the workspace. Entries are validated before use.
fn admitted_cache_paths(recipe: &Value) -> Vec<String> {
    recipe
        .get("cache_paths")
        .and_then(|v| v.as_array())
        .map(|paths| {
            paths
                .iter()
                .filter_map(|p| p.as_str())
                .filter(|rel| admit_cache_path(rel).is_ok())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Restore the recipe's declared `cache_paths` from the scope-keyed cache into the workspace
/// (warmup). Returns (cache_hit, restored_paths) — a second env from the same recipe is faster.
fn restore_recipe_cache(data_dir: &str, recipe: &Value, ws: &str) -> (bool, Vec<String>) {
    let recipe_ref = recipe["recipe_ref"].as_str().unwrap_or("");
    let Some(scope) = recipe_cache_scope(recipe) else {
        // Unattributed cache: refuse to read it rather than serve another tenant's bytes.
        return (false, Vec::new());
    };
    let cache = recipe_cache_dir(data_dir, recipe_ref, &scope);
    let mut hit = Vec::new();
    for rel in admitted_cache_paths(recipe) {
        let src = cache.join(&rel);
        if src.exists() {
            let _ = copy_dir_all(&src, &std::path::Path::new(ws).join(&rel));
            hit.push(rel);
        }
    }
    (!hit.is_empty(), hit)
}

/// Save the recipe's `cache_paths` from the workspace into the scope-keyed cache (after prebuild).
fn save_recipe_cache(data_dir: &str, recipe: &Value, ws: &str) {
    let recipe_ref = recipe["recipe_ref"].as_str().unwrap_or("");
    let Some(scope) = recipe_cache_scope(recipe) else {
        return;
    };
    let cache = recipe_cache_dir(data_dir, recipe_ref, &scope);
    for rel in admitted_cache_paths(recipe) {
        let src = std::path::Path::new(ws).join(&rel);
        if src.exists() {
            let _ = copy_dir_all(&src, &cache.join(&rel));
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
fn provision_microvm(
    st: &DaemonState,
    env: &mut Value,
    env_id: &str,
    ws: &str,
    recipe: &Value,
) -> Result<(), AppError> {
    use super::microvm;
    let app = |e: String| AppError(StatusCode::INTERNAL_SERVER_ERROR, e);
    let (monitor_kind, reason) = microvm::select_monitor(recipe)
        .map_err(|e| AppError(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    let monitor_id = monitor_kind.as_str();
    let run_dir = std::path::Path::new(&st.data_dir)
        .join("environments")
        .join(safe_id(env_id))
        .join("vm");
    let mut spec = microvm::build_vm_spec(&st.home_dir, monitor_id, run_dir, 2, 1024)
        .map_err(|e| app(format!("vm spec: {e}")))?;
    // SUN_LEN-safe vsock socket path (the data dir can be arbitrarily deep; the socket cannot).
    spec.sock_path =
        microvm::short_sock_path(env_id).map_err(|e| app(format!("vm socket: {e}")))?;
    let monitor = microvm::make_monitor(monitor_kind);
    let mut vm = monitor
        .start(&spec)
        .map_err(|e| app(format!("microvm start ({monitor_id}): {e}")))?;
    let tar = match microvm::tar_dir(std::path::Path::new(ws)) {
        Ok(tar) => tar,
        Err(error) => {
            let _ = monitor.stop(&mut vm);
            return Err(app(format!("tar workspace: {error}")));
        }
    };
    if let Err(error) = monitor.import_workspace(&vm, &tar) {
        let _ = monitor.stop(&mut vm);
        return Err(app(format!("import workspace: {error}")));
    }
    let proto = match monitor.proto_version(&vm) {
        Ok(version) if version > 0 => version,
        Ok(_) => {
            let _ = monitor.stop(&mut vm);
            return Err(app("guest protocol version 0 is not ready".to_string()));
        }
        Err(error) => {
            let _ = monitor.stop(&mut vm);
            return Err(app(format!("guest protocol negotiation: {error}")));
        }
    };
    // Honest isolation labels — a real kernel boundary now backs execution.
    env["status"]["substrate"] = json!("microvm");
    env["status"]["provider"] = json!("microvm_provider_v1");
    env["status"]["isolation_claim"] = json!("selected_microvm_preview");
    env["status"]["minimum_isolation"] = json!("vm_kernel");
    env["status"]["trust_posture"] = json!("selected_profile_only");
    env["status"]["vm"] = json!({ "monitor": monitor_id, "selection_reason": reason, "pid": vm.pid, "guest_agent_proto": proto });
    st.live_vms.lock().unwrap().insert(env_id.to_string(), vm);
    Ok(())
}

/// Run a resolution's tasks IN-GUEST via the live VM monitor (real kernel isolation), returning
/// typed EnvironmentTask records marked `executed_in: guest`.
fn run_tasks_in_guest(
    st: &DaemonState,
    env_id: &str,
    resolution: &Value,
) -> Result<Vec<Value>, AppError> {
    use super::microvm;
    let vms = st.live_vms.lock().unwrap();
    let vm = vms
        .get(env_id)
        .ok_or_else(|| AppError(StatusCode::CONFLICT, "no live microVM for env".into()))?;
    let monitor_kind =
        microvm::MonitorKind::parse(vm.monitor).map_err(|e| AppError(StatusCode::CONFLICT, e))?;
    let monitor = microvm::make_monitor(monitor_kind);
    let mut results = Vec::new();
    for key in ["resolved_prebuild_tasks", "resolved_tasks"] {
        if let Some(arr) = resolution.get(key).and_then(|v| v.as_array()) {
            for t in arr {
                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("task");
                let command = t.get("command").and_then(|v| v.as_str()).unwrap_or("");
                let trigger = t
                    .get("trigger")
                    .and_then(|v| v.as_str())
                    .unwrap_or("environment_start");
                let required = t.get("required").and_then(|v| v.as_bool()).unwrap_or(false);
                let started_at = iso_now();
                let (phase, code) = if command.is_empty() {
                    ("succeeded", 0)
                } else {
                    match monitor.exec(vm, command) {
                        Ok(o) => (
                            if o.exit_code == 0 {
                                "succeeded"
                            } else {
                                "failed"
                            },
                            o.exit_code,
                        ),
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
    use super::microvm;
    let vms = st.live_vms.lock().unwrap();
    let vm = vms
        .get(env_id)
        .ok_or_else(|| AppError(StatusCode::CONFLICT, "no live microVM for env".into()))?;
    let monitor_kind =
        microvm::MonitorKind::parse(vm.monitor).map_err(|e| AppError(StatusCode::CONFLICT, e))?;
    let monitor = microvm::make_monitor(monitor_kind);
    // CONTAINMENT: the guest is the UNTRUSTED party — this environment is labelled
    // `trust_posture: untrusted_code_capable`. These bytes are guest-authored, carry no digest
    // the daemon admitted beforehand, and are extracted onto the HOST filesystem with no
    // member-level traversal/symlink/permission guard. That is an unverified-provenance restore
    // across the isolation boundary, so it is gated behind an explicit opt-in that defaults OFF.
    if let Err(refusal) = unsafe_path_gate(
        UNVERIFIED_WORKSPACE_RESTORE_GATE,
        std::env::var(UNVERIFIED_WORKSPACE_RESTORE_GATE)
            .ok()
            .as_deref(),
    ) {
        return Err(AppError(
            StatusCode::CONFLICT,
            format!("{}: {}", refusal.reason, refusal.detail),
        ));
    }
    let tar = monitor.export_workspace(vm).map_err(|e| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("export workspace: {e}"),
        )
    })?;
    microvm::untar_into(std::path::Path::new(ws), &tar).map_err(|e| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("untar workspace: {e}"),
        )
    })?;
    Ok(())
}

/// Shut down + remove an env's live microVM if present (idempotent).
///
/// CARVE-OUT: deletion of an EXISTING resource always remains callable — this function never
/// refuses. What containment changes is HONESTY. It previously discarded the stop result
/// (`let _ = ...`) and the doc claimed "leaves no orphan VM", which the code never verified.
/// It now returns an exact `succeeded | failed | unknown` disposition and opens a durable
/// cleanup obligation whenever the outcome is not `succeeded`. `unknown` is first-class: the
/// monitor's `stop` cannot prove the guest process is gone, so a stop that merely returned Ok
/// is `unknown`, never `succeeded`.
fn teardown_microvm(st: &DaemonState, env_id: &str) -> Value {
    let resource_ref = format!("microvm://environment/{env_id}");
    let mut vm = match st.live_vms.lock().unwrap().remove(env_id) {
        Some(v) => v,
        // Nothing live to tear down: the resource is observably absent from this daemon.
        None => return close_deletion(&resource_ref, DeletionOutcome::Succeeded).to_json(),
    };
    // CONTAINMENT (cleanup availability): teardown used to hardcode `CloudHypervisorMonitor`
    // even for a VM booted under QEMU or Firecracker. `QemuMonitor` overrides `connect` to use
    // AF_VSOCK while the default uses a UDS, so the graceful shutdown byte was written to the
    // wrong transport and never reached those guests. Resolve the monitor that actually booted
    // this VM from the environment record so graceful stop reaches the right guest.
    let monitor = match super::microvm::MonitorKind::parse(vm.monitor) {
        Ok(kind) => super::microvm::make_monitor(kind),
        Err(_) => {
            let _ = vm.child.kill();
            let _ = vm.child.wait();
            return close_deletion(&resource_ref, DeletionOutcome::Unknown).to_json();
        }
    };
    let pid = vm.pid;
    let call_succeeded = monitor.stop(&mut vm).is_ok();
    // Re-observe: proof of absence is the process no longer existing, not the call returning.
    let proven_absent = !process_alive(pid);
    close_deletion(
        &resource_ref,
        DeletionOutcome::classify(call_succeeded, proven_absent),
    )
    .to_json()
}

/// Post-teardown observation: is the monitor process still present?
///
/// `kill(pid, 0)` reports liveness without signalling. An error other than "no such process"
/// (e.g. EPERM) means we genuinely do not know, so it reports alive and the outcome degrades to
/// `unknown` rather than a false `succeeded`.
fn process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: signal 0 performs error checking only; it never delivers a signal.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
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
    let mode = env["spec"]["stop_policy"]["mode"]
        .as_str()
        .unwrap_or("graceful")
        .to_string();
    env["spec"]["desired_phase"] = json!("stopped");
    set_phase(env, "stopping");
    observe(
        env,
        "stopping",
        "provisioner",
        condition_kind,
        "info",
        &format!("stopping ({mode}): {msg}"),
    );
    // CARVE-OUT: stop always runs. Its exact outcome is recorded rather than assumed.
    let disposition = teardown_microvm(st, id);
    record_cleanup_disposition(st, env, &disposition);
    for c in [
        "sandbox",
        "resource_isolation",
        "connectivity",
        "automations",
        "agent_work",
    ] {
        set_component(env, c, "pending", "stopped");
    }
    set_phase(env, "stopped");
    recompute_readiness(env);
    // CLAIM TRUTH: "no orphans" used to be asserted unconditionally while the stop result was
    // discarded. The message now reports the measured teardown outcome.
    let outcome = disposition["outcome"].as_str().unwrap_or("unknown");
    observe(
        env,
        "stopping",
        "provisioner",
        condition_kind,
        "info",
        &format!("environment stopped (workspace retained; microVM teardown: {outcome})"),
    );
}

/// Record one cleanup disposition on the environment record.
///
/// CARVE-OUT SUPPORT: a non-`succeeded` deletion opens a DURABLE cleanup obligation that
/// survives on the record. Obligations accumulate and are never erased by a later teardown —
/// only an explicit receipted disposition may close one.
fn record_cleanup_disposition(st: &DaemonState, env: &mut Value, disposition: &Value) {
    env["status"]["last_cleanup_disposition"] = disposition.clone();
    if disposition["cleanup_obligation_ref"].is_null() {
        return;
    }
    if !env["status"]["cleanup_obligations"].is_array() {
        env["status"]["cleanup_obligations"] = json!([]);
    }
    let obligation = json!({
        "cleanup_obligation_ref": disposition["cleanup_obligation_ref"],
        "resource_ref": disposition["resource_ref"],
        "outcome": disposition["outcome"],
        "status": "pending",
        "detail": disposition["detail"],
        "opened_at": iso_now(),
    });
    env["status"]["cleanup_obligations"]
        .as_array_mut()
        .expect("cleanup_obligations initialized as an array above")
        .push(obligation.clone());
    // Durable beyond the environment record: an obligation must survive parent deletion. That
    // standalone copy is the record's stated purpose, so W1.2 / MEF-GAP-008 refuses to assert it
    // silently — deletion CARVE-OUT never refuses, so on a lost write the loss is MEASURED onto the
    // obligation (durable_copy_persisted:false) and observed rather than pretended.
    if let Some(id) = disposition["cleanup_obligation_ref"].as_str() {
        if persist_record(
            &st.data_dir,
            "cleanup-obligations",
            &safe_id(id),
            &obligation,
        )
        .is_err()
        {
            if let Some(last) = env["status"]["cleanup_obligations"]
                .as_array_mut()
                .and_then(|a| a.last_mut())
            {
                last["durable_copy_persisted"] = json!(false);
                last["durable_copy_error"] =
                    json!("environment_cleanup_obligation_persistence_failed");
            }
            observe(
                env,
                "cleanup",
                "provisioner",
                "error",
                "error",
                &format!("cleanup obligation {id} could NOT be recorded as a standalone durable copy (environment_cleanup_obligation_persistence_failed); it survives only on this env record and a parent deletion would orphan the resource"),
            );
        }
    }
}

// ---- WS-9: provider failure recovery (incident → candidate → attempt → reconcile → receipts) ----

/// Recover a failed environment: classify the failure into a ProviderFailureIncident, generate
/// RecoveryCandidate previews (preserve/lose/authority), execute a RecoveryAttempt (rebuild from
/// recipe — the HOST workspace + WorkRun branches survive the VM loss), reconcile the WorkRun, and
/// seal a receipt. Returns the full chain. A failed env never silently restarts.
fn recover_environment(st: &DaemonState, env: &mut Value, id: &str) -> Result<Value, AppError> {
    let app = |e: String| AppError(StatusCode::INTERNAL_SERVER_ERROR, e);
    let now = iso_now();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let incident_id = format!("incident_{nanos:x}");
    let last_state = env["status"]["state_root_ref"].clone();
    observe(
        env,
        "detecting_failure",
        "provider",
        "vm_lost",
        "error",
        "provider failure detected: vm_lost",
    );
    let mut incident = json!({
        "schema_version": "ioi.hypervisor.provider-failure-incident.v1",
        "incident_ref": incident_id, "environment_ref": id, "failure_kind": "vm_lost",
        "detected_at": now, "last_admitted_state_root": last_state, "status": "recovering"
    });
    persist_record(&st.data_dir, "incidents", &incident_id, &incident)
        .map_err(|e| app(format!("persist incident: {e}")))?;

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
    observe(
        env,
        "planning_recovery",
        "provider",
        "content_ready",
        "info",
        "recovery candidates: rebuild_from_recipe | restore_snapshot | failover_provider",
    );

    // execute: rebuild_from_recipe. The HOST workspace + git/patch branches survived the VM loss.
    observe(
        env,
        "rebuilding",
        "provider",
        "content_ready",
        "info",
        "executing recovery: rebuild_from_recipe",
    );
    let ws = env["status"]["workspace_root"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let recipe_ref = env["spec"]["recipe_ref"].as_str().unwrap_or("").to_string();
    let recipe = super::recipe_routes::load_recipe(&st.data_dir, &recipe_ref)
        .unwrap_or_else(|| json!({ "substrate": "microvm" }));
    let (outcome, reconcile) = match provision_microvm(st, env, id, &ws, &recipe) {
        Ok(()) => {
            set_component(env, "sandbox", "ready", "microVM rebuilt (recovered)");
            set_component(
                env,
                "resource_isolation",
                "ready",
                "vm-isolated (kernel boundary)",
            );
            (
                "recovered",
                json!({
                    "git_worktree_refs": [ws], "agentgres_patch_branch_refs": ["preserved"],
                    "preserved_output_refs": ["host_workspace", "git_branches"],
                    "lost_material_refs": ["in_guest_runtime_state"], "retry_work_item_refs": [], "abandoned_work_item_refs": []
                }),
            )
        }
        Err(e) => (
            "failed_closed",
            json!({ "error": e.1, "preserved_output_refs": ["host_workspace"], "lost_material_refs": ["in_guest_runtime_state"] }),
        ),
    };

    let attempt_id = format!("attempt_{nanos:x}");
    let receipt_id = format!("receipt_recovery_{nanos:x}");
    let attempt = json!({
        "schema_version": "ioi.hypervisor.environment-recovery-attempt.v1",
        "recovery_attempt_ref": attempt_id, "incident_ref": incident_id, "selected_candidate_ref": "cand_rebuild",
        "work_run_reconciliation": reconcile, "outcome": outcome,
        "state_root_after_ref": env["status"]["state_root_ref"].clone(), "receipt_refs": [receipt_id]
    });
    persist_record(&st.data_dir, "recovery-attempts", &attempt_id, &attempt)
        .map_err(|e| app(format!("persist attempt: {e}")))?;
    let receipt = json!({ "id": receipt_id, "kind": "environment_recovery", "redaction": "redacted", "createdAt": now,
        "details": { "incident_ref": incident_id, "attempt_ref": attempt_id, "outcome": outcome, "recovery_mode": "rebuild_from_recipe" } });
    // W1.2 / MEF-GAP-008 — the attempt (persisted above) cites this receipt in receipt_refs and it
    // is read back (lifecycle/operability/orchestration). A lost write leaves the attempt pointing
    // at a receipt no reader resolves. Refuse.
    persist_record(&st.data_dir, "receipts", &receipt_id, &receipt)
        .map_err(|e| app(format!("persist recovery receipt {receipt_id} (cited by attempt {attempt_id}.receipt_refs): {e}")))?;

    incident["status"] = json!(if outcome == "recovered" {
        "recovered"
    } else {
        "failed_closed"
    });
    // W1.2 / MEF-GAP-008 — a lost status update leaves this incident stuck "recovering" forever
    // (read back by handle_incidents_list) while recovery reports a terminal outcome. Refuse.
    persist_record(&st.data_dir, "incidents", &incident_id, &incident)
        .map_err(|e| app(format!("persist incident {incident_id} status ({outcome}): recovery executed but the incident would read 'recovering' forever: {e}")))?;

    if outcome == "recovered" {
        set_phase(env, "running");
    } else {
        set_phase(env, "failed");
    }
    recompute_readiness(env);
    observe(
        env,
        if outcome == "recovered" {
            "ready"
        } else {
            "failed"
        },
        "provider",
        "content_ready",
        "info",
        &format!("recovery {outcome}"),
    );

    Ok(
        json!({ "incident": incident, "candidates": candidates, "attempt": attempt, "outcome": outcome }),
    )
}

// ---- handlers ----

/// GET /v1/hypervisor/projects — list persisted projects (WS-C). The POST create endpoint
/// (lifecycle_routes) is the kernel-validated writer; this is the read/projection the
/// cockpit's ListProjects needs.
pub(crate) async fn handle_projects_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "projects": read_record_dir(&st.data_dir, "projects") }))
}

/// GET /v1/hypervisor/projects/:id — fetch one persisted project (the cockpit's GetProject:
/// detail page + prebuild counts). `{ok:false}` when absent so the client can branch honestly.
pub(crate) async fn handle_project_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match read_record_dir(&st.data_dir, "projects")
        .into_iter()
        .find(|p| p.get("project_id").and_then(|v| v.as_str()) == Some(id.as_str()))
    {
        Some(project) => Json(json!({ "ok": true, "project": project })),
        None => Json(json!({ "ok": false, "reason": "project not found", "project": Value::Null })),
    }
}

/// DELETE /v1/hypervisor/projects/:id — remove a persisted project record (the cockpit's
/// DeleteProject). Returns `{ok, removed}` so a no-op delete is honest, not a fabricated success.
pub(crate) async fn handle_project_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let removed = remove_record(&st.data_dir, "projects", &id);
    Json(json!({ "ok": removed, "removed": removed, "project_id": id }))
}

/// PATCH /v1/hypervisor/projects/:id/environment-classes — the second durable step of the
/// project-creation saga (OQ-5 ruling: an explicit resumable saga, never an atomic pretense —
/// the live audit watched CreateProject 200 then this step 501 leave a stuck form). Identity
/// first (rule E: the 401 is owed before the 404 existence oracle); `expected_revision` CAS;
/// class ids validated against the ONE substrate catalog; record-first receipt-second with
/// restore-on-failure so no accepted binding lacks its proof; an identical re-bind replays the
/// stored receipt rather than minting a second truth.
pub(crate) async fn handle_project_environment_classes_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return super::lifecycle_routes::planner_scope_refusal(error),
    };
    let Some(prev) = read_record_dir(&st.data_dir, "projects")
        .into_iter()
        .find(|p| p.get("project_id").and_then(|v| v.as_str()) == Some(id.as_str()))
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "code": "project_not_found",
                "message": format!("project {id} not found — the create step of the saga has not run") })),
        );
    };
    let current_rev = prev.get("revision").and_then(|v| v.as_u64()).unwrap_or(1);
    if let Some(expected) = body.get("expected_revision") {
        let Some(expected) = expected.as_u64() else {
            return (
                StatusCode::OK,
                Json(json!({ "ok": false, "code": "project_field_type_invalid",
                    "message": "`expected_revision` must be an unsigned integer" })),
            );
        };
        if expected != current_rev {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "ok": false, "code": "project_revision_conflict",
                    "message": "the project changed since it was read — re-read and retry",
                    "current_revision": current_rev })),
            );
        }
    }
    let Some(raw) = body.get("environment_class_ids").and_then(|v| v.as_array()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "ok": false, "code": "project_environment_class_ids_required",
                "message": "`environment_class_ids` (array of catalog ids) is required" }),
            ),
        );
    };
    if raw.len() > 32 {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "ok": false, "code": "project_environment_class_ids_bounds",
                "message": "at most 32 environment classes bind to one project" }),
            ),
        );
    }
    let mut requested: Vec<String> = Vec::new();
    for v in raw {
        match v.as_str() {
            Some(s) if !s.trim().is_empty() && s.chars().count() <= 120 => {
                let s = s.trim().to_string();
                if !requested.contains(&s) {
                    requested.push(s);
                }
            }
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "ok": false, "code": "project_field_type_invalid",
                        "message": "every environment class id must be a non-empty bounded string" })),
                );
            }
        }
    }
    // Validate against the exact catalog the GET serves (same lazy seed, no second truth).
    let catalog_json = handle_environment_classes(State(st.clone())).await.0;
    let known: Vec<String> = catalog_json
        .get("environmentClasses")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|c| c.get("id").and_then(|v| v.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let unknown: Vec<&String> = requested.iter().filter(|r| !known.contains(r)).collect();
    if !unknown.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "ok": false, "code": "environment_class_unknown",
                "message": format!("not in the substrate catalog: {unknown:?}"),
                "unknown": unknown, "known": known })),
        );
    }
    // Idempotent replay: an identical set re-binds nothing and returns the stored receipt.
    let prev_ids: Vec<String> = prev
        .get("environment_class_ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if prev_ids == requested {
        if let Some(receipt) = prev.get("last_environment_classes_receipt") {
            return (
                StatusCode::OK,
                Json(json!({ "ok": true, "replayed": true, "project": prev, "receipt": receipt })),
            );
        }
    }
    let now = iso_now();
    let rev = current_rev + 1;
    let slug = id.strip_prefix("project:").unwrap_or(&id);
    let receipt_id = format!("prjrcpt_{slug}_{rev}");
    let receipt = json!({
        "schema_version": "ioi.hypervisor.project.environment-classes-receipt.v1",
        "receipt_id": receipt_id,
        "receipt_ref": format!("agentgres://project-receipts/{receipt_id}"),
        "project_id": id,
        "op": "environment_classes_bound",
        "environment_class_ids": requested,
        "revision": rev,
        "recorded_at": now,
        "acting_principal_ref": identity.principal_ref,
    });
    let mut next = prev.clone();
    next["environment_class_ids"] = json!(requested);
    next["revision"] = json!(rev);
    next["updated_at"] = json!(now.clone());
    next["saga_state"] = json!("environment_classes_bound");
    next["last_environment_classes_receipt"] = receipt.clone();
    let mut hist = next
        .get("history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    hist.push(
        json!({ "revision": rev, "op": "environment_classes_bound", "at": now,
        "receipt_ref": receipt.get("receipt_ref").cloned().unwrap_or(Value::Null) }),
    );
    let len = hist.len();
    if len > 20 {
        hist = hist[len - 20..].to_vec();
    }
    next["history"] = json!(hist);
    if persist_record(&st.data_dir, "projects", &id, &next).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "project_record_persistence_failed",
                "message": "the binding did not commit — the project is unchanged" }),
            ),
        );
    }
    if persist_record(&st.data_dir, "project-receipts", &receipt_id, &receipt).is_err() {
        // Double-fault disclosure: the restore's own result is part of the truth — a
        // discarded restore would hide a record that kept the binding without its proof.
        let restored = persist_record(&st.data_dir, "projects", &id, &prev).is_ok();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "project_receipt_persistence_failed",
                "restored": restored,
                "message": if restored {
                    "the receipt did not commit — the binding was restored to its prior state"
                } else {
                    "the receipt did not commit AND the restore failed — the record may hold the new binding without its receipt; re-read before retrying"
                } }),
            ),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "project": next, "receipt": receipt })),
    )
}

/// GET /v1/hypervisor/environment-classes — substrate catalog (v0: local only enabled).
/// Environment classes as DURABLE records with provider eligibility. `enabled` is computed
/// HONESTLY at read time: a class is enabled only when a real provider/account path backs it —
/// local host always; microVM when the monitor lane is operational (fixing the prior
/// enabled:false honesty gap — the lane IS real, see env_is_microvm); byo-ssh-node only while
/// at least one VERIFIED baremetal_ssh ProviderAccount exists.
pub(crate) async fn handle_environment_classes(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    // Seed durable records once (idempotent); dynamic truth is computed per read below.
    let seeded = super::read_record_dir(&st.data_dir, "environment-classes");
    if seeded.is_empty() {
        let seeds = [
            json!({ "id": "local-workspace-v0", "display_name": "Local Workspace (v0)", "substrate_class": "local_host",
                "isolation_claim": "not_cross_tenant", "minimum_isolation": "process + scoped worktree/runtime state",
                "provider_eligibility": { "provider_kinds": ["local"], "required_capabilities": [], "credential_kind": null, "spend_posture": "local_free" } }),
            json!({ "id": "devcontainer", "display_name": "Devcontainer", "substrate_class": "container",
                "note": "setup / inner-sandbox lane; not cross-tenant isolation",
                "provider_eligibility": { "provider_kinds": [], "required_capabilities": ["container_runtime"], "credential_kind": null, "spend_posture": "local_free" } }),
            json!({ "id": "microvm", "display_name": "microVM", "substrate_class": "microvm",
                "note": "isolation claim for untrusted/cross-tenant work (VmMonitor lane)",
                "provider_eligibility": { "provider_kinds": ["local"], "required_capabilities": ["vm_kernel"], "credential_kind": null, "spend_posture": "local_free" } }),
            json!({ "id": "vm", "display_name": "VM", "substrate_class": "vm",
                "note": "isolation claim for untrusted/cross-tenant work (future)",
                "provider_eligibility": { "provider_kinds": [], "required_capabilities": ["vm_kernel"], "credential_kind": null, "spend_posture": "external_spend" } }),
            json!({ "id": "byo-ssh-node", "display_name": "BYO SSH Node", "substrate_class": "customer_host",
                "note": "customer-owned bare-metal/homelab node over the baremetal_ssh provider adapter; spend is customer-borne",
                "provider_eligibility": { "provider_kinds": ["baremetal_ssh"], "required_capabilities": ["ssh", "tar"], "credential_kind": "ssh_key", "spend_posture": "customer_borne_byo" } }),
        ];
        for seed in seeds {
            let id = seed["id"].as_str().unwrap_or("").to_string();
            let mut record = seed;
            record["schema_version"] = json!("ioi.hypervisor.environment-class.v1");
            record["created_at"] = json!(iso_now());
            // CLASSIFIED — bootstrap seed: the projection re-reads the family in the same handler and recomputes enablement per read; a lost seed yields an empty honest list and reseeds on the next read
            let _ = super::persist_record(&st.data_dir, "environment-classes", &id, &record);
        }
    }
    let verified_ssh_accounts = super::read_record_dir(&st.data_dir, "provider-accounts")
        .into_iter()
        .filter(|a| {
            a["kind"].as_str() == Some("baremetal_ssh") && a["status"].as_str() == Some("verified")
        })
        .count();
    let classes: Vec<Value> = super::read_record_dir(&st.data_dir, "environment-classes")
        .into_iter()
        .map(|mut record| {
            let id = record["id"].as_str().unwrap_or("").to_string();
            let (enabled, backing) = match id.as_str() {
                "local-workspace-v0" => (true, json!({ "path": "local host workspace", "real": true })),
                // CONTAINMENT (claim truth): this arm was the unconditional constant
                // `(true, {"real": true})`. It probed nothing, so on a host with no monitor
                // binary and no pinned VM toolchain the daemon still advertised
                // `microvm: enabled=true, real=true` — violating this handler's own stated
                // honesty rule that "a class is enabled only when a real provider/account path
                // backs it". Enablement is now MEASURED by resolving the pinned, checksum-verified
                // toolchain that `build_vm_spec` actually requires.
                "microvm" => {
                    let toolchain = super::microvm::resolve_toolchain(&st.home_dir);
                    let operational = toolchain.is_ok();
                    (
                        operational,
                        json!({
                            "path": "VmMonitor lane (cloud-hypervisor primary; QEMU/Firecracker)",
                            "real": operational,
                            "probe": "resolve_toolchain (pinned supply-manifest + sha256 re-hash)",
                            "unavailable_reason": toolchain.err(),
                        }),
                    )
                }
                "byo-ssh-node" => (
                    verified_ssh_accounts > 0,
                    json!({ "path": "verified baremetal_ssh ProviderAccount(s)", "verified_accounts": verified_ssh_accounts, "real": verified_ssh_accounts > 0 }),
                ),
                _ => (false, json!({ "path": "no real provider/account path yet", "real": false })),
            };
            record["enabled"] = json!(enabled);
            record["enabled_backing"] = backing;
            if id == "local-workspace-v0" {
                record["bwrap_available"] = json!(bwrap_available());
            }
            record
        })
        .collect();
    Json(
        json!({ "environmentClasses": classes, "honesty_rule": "a class is enabled only when a real provider/account path backs it" }),
    )
}

/// GET /v1/hypervisor/environments
pub(crate) async fn handle_environments_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "environments": read_record_dir(&st.data_dir, "environments") }))
}

/// GET /v1/hypervisor/environments-summary — a READ PROJECTION over the env records: global counts
/// + a filtered, paged slice of SLIM records (so callers stop pulling the full env list). Does NOT
/// mutate the /environments full-record contract and adds NO durable object.
/// Params: limit, offset, phase=running|stopped|deleted|live|all, project, class, include_deleted.
pub(crate) async fn handle_environments_summary(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    Json(environments_summary(
        &read_record_dir(&st.data_dir, "environments"),
        &q,
    ))
}

/// Pure projection (unit-tested): global counts + filtered, paged slim slice over env records.
pub(crate) fn environments_summary(all: &[Value], q: &HashMap<String, String>) -> Value {
    let qs = |k: &str| {
        q.get(k)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let phase = qs("phase").unwrap_or_default();
    let include_deleted = q
        .get("include_deleted")
        .map(|s| s == "true")
        .unwrap_or(false);
    let want_project = qs("project");
    let want_class = qs("class");
    let limit: usize = q
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(60)
        .clamp(1, 500);
    let offset: usize = q.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0);

    let dphase = |e: &Value| e["status"]["phase"].as_str().unwrap_or("").to_string();
    let is_deleted =
        |e: &Value| e["status"]["deleted"].as_bool().unwrap_or(false) || dphase(e) == "deleted";
    let cnt = |v: &Value| {
        v.as_array()
            .map(|a| a.len())
            .or_else(|| v.as_object().map(|o| o.len()))
            .unwrap_or(0)
    };

    // Global inventory counts (over ALL records).
    let mut by_phase: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_class: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_substrate: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_readiness: BTreeMap<String, i64> = BTreeMap::new();
    let (mut live, mut deleted) = (0i64, 0i64);
    for e in all {
        *by_phase.entry(dphase(e)).or_insert(0) += 1;
        if is_deleted(e) {
            deleted += 1;
            continue;
        }
        live += 1;
        if let Some(c) = e["spec"]["environment_class_id"].as_str() {
            *by_class.entry(c.to_string()).or_insert(0) += 1;
        }
        if let Some(s) = e["status"]["substrate"].as_str() {
            *by_substrate.entry(s.to_string()).or_insert(0) += 1;
        }
        if let Some(r) = e["status"]["readiness"]["mode"].as_str() {
            *by_readiness.entry(r.to_string()).or_insert(0) += 1;
        }
    }

    // Active filter (default = live unless include_deleted).
    let mut matching: Vec<&Value> = all
        .iter()
        .filter(|e| {
            let del = is_deleted(e);
            let pass = match phase.as_str() {
                "" => include_deleted || !del,
                "all" => true,
                "live" => !del,
                "deleted" => del,
                other => dphase(e) == other,
            };
            if !pass {
                return false;
            }
            if let Some(p) = &want_project {
                if e["spec"]["project_id"].as_str() != Some(p.as_str()) {
                    return false;
                }
            }
            if let Some(c) = &want_class {
                if e["spec"]["environment_class_id"].as_str() != Some(c.as_str()) {
                    return false;
                }
            }
            true
        })
        .collect();
    // Live-first, then newest-first.
    matching.sort_by(|a, b| {
        is_deleted(a).cmp(&is_deleted(b)).then_with(|| {
            b["updated_at"]
                .as_str()
                .unwrap_or("")
                .cmp(a["updated_at"].as_str().unwrap_or(""))
        })
    });
    let total_matching = matching.len();
    let page: Vec<Value> = matching
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|e| {
            let stt = &e["status"];
            let sp = &e["spec"];
            json!({
                "id": e["id"], "created_at": e["created_at"], "updated_at": e["updated_at"],
                "project_id": sp["project_id"], "environment_class_id": sp["environment_class_id"],
                "phase": stt["phase"], "deleted": is_deleted(e),
                "readiness_mode": stt["readiness"]["mode"], "blocked_reason": stt["blocked_reason"],
                "provider": stt["provider"], "substrate": stt["substrate"], "workspace_root": stt["workspace_root"],
                "ports_count": cnt(&stt["ports"]), "services_count": cnt(&stt["services"]),
                "tasks_count": cnt(&stt["tasks"]), "components_count": cnt(&stt["components"]),
                "last_activity": stt["last_activity"],
            })
        })
        .collect();
    let has_more = offset + page.len() < total_matching;
    json!({
        "schema_version": "ioi.hypervisor.environments-summary.v1",
        "total_environments": all.len(),
        "total_matching": total_matching,
        "limit": limit,
        "offset": offset,
        "has_more": has_more,
        "counts": {
            "by_phase": serde_json::to_value(&by_phase).unwrap_or_else(|_| json!({})),
            "live": live,
            "deleted": deleted,
            "by_class": serde_json::to_value(&by_class).unwrap_or_else(|_| json!({})),
            "by_substrate": serde_json::to_value(&by_substrate).unwrap_or_else(|_| json!({})),
            "by_readiness": serde_json::to_value(&by_readiness).unwrap_or_else(|_| json!({})),
        },
        "environments": page,
    })
}

#[cfg(test)]
mod environments_summary_tests {
    use super::environments_summary;
    use serde_json::{json, Value};
    use std::collections::HashMap;

    fn env(
        id: &str,
        phase: &str,
        deleted: bool,
        project: &str,
        class: &str,
        updated: &str,
    ) -> Value {
        json!({
            "id": id, "updated_at": updated,
            "spec": { "project_id": project, "environment_class_id": class },
            "status": { "phase": phase, "deleted": deleted, "substrate": "local_host",
                        "readiness": { "mode": if deleted { "blocked" } else { "full" } },
                        "ports": [], "services": [], "tasks": [] },
        })
    }
    fn p(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn default_excludes_deleted_and_counts_globally() {
        let all = vec![
            env(
                "a",
                "running",
                false,
                "p1",
                "local-workspace-v0",
                "2026-06-30T03:00:00Z",
            ),
            env(
                "b",
                "stopped",
                false,
                "p1",
                "local-workspace-v0",
                "2026-06-30T02:00:00Z",
            ),
            env(
                "c",
                "deleted",
                true,
                "p2",
                "microvm",
                "2026-06-30T01:00:00Z",
            ),
        ];
        let s = environments_summary(&all, &p(&[]));
        assert_eq!(s["total_environments"], 3);
        assert_eq!(s["total_matching"], 2); // deleted excluded by default
        assert_eq!(s["counts"]["live"], 2);
        assert_eq!(s["counts"]["deleted"], 1);
        assert_eq!(s["counts"]["by_phase"]["running"], 1);
        assert_eq!(s["environments"].as_array().unwrap().len(), 2);
        // slim shape
        assert_eq!(s["environments"][0]["id"], "a");
        assert_eq!(s["environments"][0]["readiness_mode"], "full");
    }
    #[test]
    fn phase_and_filter_params() {
        let all = vec![
            env("a", "running", false, "p1", "local-workspace-v0", "z"),
            env("b", "stopped", false, "p2", "microvm", "z"),
            env("c", "deleted", true, "p1", "local-workspace-v0", "z"),
        ];
        assert_eq!(
            environments_summary(&all, &p(&[("phase", "running")]))["total_matching"],
            1
        );
        assert_eq!(
            environments_summary(&all, &p(&[("phase", "deleted")]))["total_matching"],
            1
        );
        assert_eq!(
            environments_summary(&all, &p(&[("phase", "all")]))["total_matching"],
            3
        );
        assert_eq!(
            environments_summary(&all, &p(&[("phase", "live")]))["total_matching"],
            2
        );
        assert_eq!(
            environments_summary(&all, &p(&[("project", "p1")]))["total_matching"],
            1
        ); // p1 live only
        assert_eq!(
            environments_summary(&all, &p(&[("class", "microvm")]))["total_matching"],
            1
        );
    }
    #[test]
    fn pagination_limit_offset_has_more() {
        let all: Vec<Value> = (0..5)
            .map(|i| {
                env(
                    &format!("e{i}"),
                    "running",
                    false,
                    "p",
                    "local-workspace-v0",
                    "z",
                )
            })
            .collect();
        let s = environments_summary(&all, &p(&[("limit", "2"), ("offset", "0")]));
        assert_eq!(s["total_matching"], 5);
        assert_eq!(s["environments"].as_array().unwrap().len(), 2);
        assert_eq!(s["has_more"], true);
        let s2 = environments_summary(&all, &p(&[("limit", "2"), ("offset", "4")]));
        assert_eq!(s2["environments"].as_array().unwrap().len(), 1);
        assert_eq!(s2["has_more"], false);
    }
}

/// POST /v1/hypervisor/environments — create (admit spec; phase stopped).
pub(crate) async fn handle_environment_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, CustodyReply> {
    // Rule E — identity BEFORE any record read or spec validation. This is the route that means
    // "create", so it is where an environment acquires the owner every custody act is scoped to;
    // an environment minted here without one would be an environment nobody could ever capture.
    let identity = custody_identity(&st.data_dir, &headers)?;
    let spec = body.get("spec").cloned().unwrap_or_else(|| body.clone());
    let id = body
        .get("environment_id")
        .or_else(|| spec.get("environment_id"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(gen_env_id);
    // THE AUTHORIZATION DECISION, BEFORE ANYTHING DURABLE AND BEFORE THE RECORD IS READ. The pin is
    // the authority, so the pin is what decides.
    //
    // CREATE DOES NOT MINT OWNERSHIP, and two demonstrated ship-blockers are why. Binding here made
    // ownership FIRST-TOUCH over a COORDINATE, while the thing custody protects — the workspace
    // bytes — is created later by `start`, an unauthenticated lifecycle route. So a member could
    // pre-claim `session_workspace`, let the administrator start it and write secrets into it, and
    // then capture those bytes. Refusing an existing-but-unpinned record instead made it permanent
    // in the other direction: one anonymous GET established a record that NO principal could ever
    // own, capture, back up or place under a retention duty.
    //
    // Both fall out of the same mistake. OWNERSHIP FOLLOWS THE WORKSPACE, not the record: it is
    // bound where the workspace is MATERIALIZED, by the authenticated principal whose request
    // materialized it. Create still refuses to touch an environment someone else owns — that is what
    // this check is for — but a coordinate with no workspace has nothing to own yet.
    if environment_owner_pin(&st.data_dir, &id)?.is_some() {
        authorize_environment_custody(&st.data_dir, &identity, &id)?;
    }
    // Refuses BEFORE any persist when the spec carries an invalid environment-local guardrail
    // declaration; every other field is admitted exactly as before.
    //
    // NOTHING IS PINNED HERE. Creating an environment record creates no workspace, so there are no
    // bytes to hold custody of yet; the pin is bound where `start` materializes one. Binding here
    // also left an irrevocable claim behind on every refused create, since the pin is genesis-only
    // and the substrate has no unbind.
    let mut env = new_env(&id, &spec).map_err(app_error_reply)?;
    // WS-2: repo-detect-first — if the spec points at a repo, admit a detected recipe and bind it.
    if env["spec"]["recipe_ref"]
        .as_str()
        .filter(|s| !s.is_empty())
        .is_none()
    {
        if let Some(repo) = spec.get("repo_path").and_then(|v| v.as_str()) {
            let project_ref = spec.get("project_id").and_then(|v| v.as_str());
            let recipe_ref =
                super::recipe_routes::detect_and_admit(&st.data_dir, repo, project_ref)
                    .map_err(app_error_reply)?;
            env["spec"]["recipe_ref"] = json!(recipe_ref);
            env["spec"]["repo_path"] = json!(repo);
            observe(
                &mut env,
                "resolving_recipe",
                "recipe",
                "content_ready",
                "info",
                &format!("recipe repo-detected and admitted ({recipe_ref})"),
            );
        }
    }
    observe(
        &mut env,
        "queued",
        "recipe",
        "admitted",
        "info",
        "environment created (local_workspace_provider_v0)",
    );
    // Snapshot the placement venue policy in force at create (provenance — the picker's chosen
    // venue is consumable estate truth; substrate stays local until relocation lands).
    {
        let policy = super::orchestration_routes::load_venue_policy(&st.data_dir);
        env["spec"]["placement_venue"] = json!({
            "venue": policy["venue"],
            "effective_venue": policy.get("effective_venue").cloned().unwrap_or_else(|| policy["venue"].clone()),
            "provider_account_ref": policy.get("provider_account_ref").cloned().unwrap_or(serde_json::Value::Null),
            "advisory": policy.get("advisory").cloned().unwrap_or(json!(false)),
            "advisory_ref": policy.get("advisory_ref").cloned().unwrap_or(serde_json::Value::Null),
            "advisory_candidate_refs": policy.get("advisory_candidate_refs").cloned().unwrap_or(json!([])),
        });
    }
    persist_env(&st.data_dir, &env).map_err(app_error_reply)?;
    Ok(Json(json!({ "environment": env })))
}

/// GET /v1/hypervisor/environments/:id — auto-vivifies a stopped env on first reference so
/// the cockpit's GetEnvironment(sessionWorkspace) always resolves.
pub(crate) async fn handle_environment_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let env = match load_env(&st.data_dir, &id) {
        Some(mut e) => {
            // G5 — daemon-restart reconciliation: a microVM env marked `running` with a VM record
            // but no LIVE VM (e.g. after a daemon restart — live_vms is in-memory) is reconciled,
            // never left as a phantom `running` over a dead VM.
            let claims_vm =
                e["status"]["vm"].is_object() && e["status"]["phase"].as_str() == Some("running");
            if claims_vm && !st.live_vms.lock().unwrap().contains_key(&id) {
                set_component(
                    &mut e,
                    "sandbox",
                    "failed",
                    "vm not live (reconciled after restart)",
                );
                set_component(&mut e, "resource_isolation", "failed", "no sandbox");
                e["status"]["readiness"] =
                    json!({ "mode": "blocked", "blocked_reasons": ["sandbox_failed"] });
                e["status"]["reconciled"] = json!(true);
                observe(
                    &mut e,
                    "detecting_failure",
                    "provider",
                    "vm_lost",
                    "warning",
                    "reconciled after daemon restart: VM not live (recover to rebuild)",
                );
                set_phase(&mut e, "failed");
                persist_env(&st.data_dir, &e)?;
            }
            e
        }
        None => {
            // An empty spec declares no guardrails, so this cannot refuse; `?` keeps the one
            // validation path rather than asserting that here.
            let mut e = new_env(&id, &json!({}))?;
            observe(
                &mut e,
                "queued",
                "recipe",
                "admitted",
                "info",
                "environment registered on first reference",
            );
            persist_env(&st.data_dir, &e)?;
            // NO OWNER IS RECORDED HERE. Establishing a record is not creating content, and a
            // first-touch claim over a coordinate someone else will fill is the seizure this leg
            // exists to close. Ownership is bound where the workspace is materialized.
            e
        }
    };
    Ok(Json(json!({ "environment": env })))
}

/// POST /v1/hypervisor/environments/:id/:action — start|stop|archive|restore|delete.
pub(crate) async fn handle_environment_action(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((id, action)): AxumPath<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let mut env = match load_env(&st.data_dir, &id) {
        Some(env) => env,
        // An empty spec declares no guardrails, so this cannot refuse.
        // No owner is recorded here either — see `handle_environment_get`. A REFUSED action must
        // leave no pin, and binding at this point staked a permanent claim on an unknown-action 400.
        None => new_env(&id, &json!({}))?,
    };
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
            set_component(
                &mut env,
                "recipe",
                "ready",
                "local-workspace recipe (implicit)",
            );
            observe(
                &mut env,
                "resolving_recipe",
                "recipe",
                "content_ready",
                "info",
                "recipe resolved (local-workspace)",
            );

            // provisioner — REAL scoped workspace on disk.
            set_component(
                &mut env,
                "provisioner",
                "creating",
                "provisioning scoped workspace",
            );
            observe(
                &mut env,
                "provisioning",
                "provisioner",
                "content_ready",
                "info",
                "provisioning local workspace",
            );
            let ws = provision_local_workspace(&st.data_dir, &id)?;
            // THE ONE MOMENT AN ENVIRONMENT ACQUIRES ITS CUSTODY OWNER: the workspace it protects has
            // just come into existence, and the principal whose authenticated request materialized it
            // is the only honest answer to "whose bytes are these". Binding earlier claims a
            // coordinate whose content someone else will write; binding never leaves the workspace
            // ownerless forever. It binds only when NO pin exists, so a restart or a second start
            // never transfers custody, and it never refuses: an unauthenticated start materializes an
            // UNOWNED workspace, which the custody gate reads as "no principal may capture this".
            bind_environment_owner_if_resolvable(&st.data_dir, &headers, &id);
            env["status"]["workspace_root"] = json!(ws);
            set_component(
                &mut env,
                "provisioner",
                "ready",
                "scoped workspace provisioned",
            );
            observe(
                &mut env,
                "provisioning",
                "provisioner",
                "volume_mounted",
                "info",
                "scoped workspace ready",
            );

            // workspace_content — REAL git repo so WorkRuns can branch (WS-E).
            match ensure_git_repo(&ws) {
                Ok(base) => {
                    env["status"]["base_commit"] = json!(base);
                    // Scaffold the default Dev Container (.devcontainer/{devcontainer.json,Dockerfile})
                    // as uncommitted working-tree files — the `from scratch` baseline.
                    // W1.2 / MEF-GAP-008 — condition the component message on the measured seed result.
                    let scaffolded = scaffold_devcontainer(&ws);
                    set_component(
                        &mut env,
                        "workspace_content",
                        "ready",
                        if scaffolded {
                            "git initialized + devcontainer scaffolded"
                        } else {
                            "git initialized (devcontainer scaffold incomplete)"
                        },
                    );
                    observe(
                        &mut env,
                        "initializing_content",
                        "workspace_content",
                        "content_ready",
                        "info",
                        "workspace content ready (git initialized)",
                    );
                }
                Err(e) => {
                    set_component(&mut env, "workspace_content", "degraded", "git init failed");
                    observe(
                        &mut env,
                        "initializing_content",
                        "workspace_content",
                        "failed",
                        "warning",
                        &format!("git init failed: {}", e.1),
                    );
                }
            }

            // Resolve the recipe up front so the substrate (local vs microVM) can be decided.
            let recipe_ref = env["spec"]["recipe_ref"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(String::from);
            let recipe = recipe_ref
                .as_deref()
                .and_then(|r| super::recipe_routes::load_recipe(&st.data_dir, r));
            let is_microvm = env_is_microvm(&env, recipe.as_ref());

            // A host cache is not admitted into an isolation-required guest until cache material
            // has no-follow traversal, immutable provenance, and a matching trust-domain binding.
            // Local trusted workspaces retain the scoped preview cache.
            if let Some(r) = recipe.as_ref().filter(|_| !is_microvm) {
                let (cache_hit, hit_paths) = restore_recipe_cache(&st.data_dir, r, &ws);
                env["status"]["cache_hit"] = json!(cache_hit);
                if cache_hit {
                    observe(
                        &mut env,
                        "warming_cache",
                        "cache",
                        "content_ready",
                        "info",
                        &format!("prebuild cache restored (warm): {hit_paths:?}"),
                    );
                } else {
                    observe(
                        &mut env,
                        "warming_cache",
                        "cache",
                        "content_ready",
                        "info",
                        "no prebuild cache (cold)",
                    );
                }
            }

            // sandbox — WS-4/5: a REAL microVM kernel boundary (selected monitor) on the microvm
            // substrate (execution runs in-guest); else the local process lane.
            let mut microvm_ok = false;
            if is_microvm {
                let recipe_for_select = recipe.clone().unwrap_or_else(|| json!({}));
                let selection = super::microvm::select_monitor(&recipe_for_select);
                let sel_id = selection
                    .as_ref()
                    .map(|(kind, _)| kind.as_str())
                    .unwrap_or("unsupported");
                set_component(
                    &mut env,
                    "sandbox",
                    "creating",
                    &format!("booting microVM ({sel_id})"),
                );
                observe(
                    &mut env,
                    "reconciling_sandbox",
                    "sandbox",
                    "content_ready",
                    "info",
                    &format!("booting microVM via {sel_id}"),
                );
                match selection
                    .map_err(|e| AppError(StatusCode::UNPROCESSABLE_ENTITY, e))
                    .and_then(|_| provision_microvm(&st, &mut env, &id, &ws, &recipe_for_select))
                {
                    Ok(()) => {
                        microvm_ok = true;
                        set_component(
                            &mut env,
                            "sandbox",
                            "ready",
                            &format!("microVM kernel boundary ({sel_id})"),
                        );
                        observe(
                            &mut env,
                            "reconciling_sandbox",
                            "sandbox",
                            "ever_ready",
                            "info",
                            "microVM ready (vm_kernel isolation, execution in-guest)",
                        );
                        set_component(
                            &mut env,
                            "resource_isolation",
                            "ready",
                            "vm-isolated (kernel boundary)",
                        );
                        observe(
                            &mut env,
                            "enforcing_resource_isolation",
                            "resource_isolation",
                            "content_ready",
                            "info",
                            "resource isolation (vm kernel)",
                        );
                        set_component(
                            &mut env,
                            "connectivity",
                            "ready",
                            "guest-local connectivity",
                        );
                        observe(
                            &mut env,
                            "checking_connectivity",
                            "connectivity",
                            "content_ready",
                            "info",
                            "connectivity ready (guest-local)",
                        );
                    }
                    Err(e) => {
                        set_component(
                            &mut env,
                            "sandbox",
                            "failed",
                            &format!("microVM boot failed: {}", e.1),
                        );
                        observe(
                            &mut env,
                            "reconciling_sandbox",
                            "sandbox",
                            "failed",
                            "error",
                            &format!("microVM boot failed: {}", e.1),
                        );
                        set_component(&mut env, "resource_isolation", "failed", "no sandbox");
                    }
                }
            } else {
                set_component(
                    &mut env,
                    "sandbox",
                    "ready",
                    "local process sandbox (not cross-tenant)",
                );
                observe(
                    &mut env,
                    "reconciling_sandbox",
                    "sandbox",
                    "content_ready",
                    "info",
                    "local process sandbox ready",
                );
                set_component(
                    &mut env,
                    "resource_isolation",
                    "ready",
                    "process-scoped (cgroups: WS-10)",
                );
                observe(
                    &mut env,
                    "enforcing_resource_isolation",
                    "resource_isolation",
                    "content_ready",
                    "info",
                    "resource isolation (process-scoped)",
                );
                set_component(&mut env, "connectivity", "ready", "host-local connectivity");
                observe(
                    &mut env,
                    "checking_connectivity",
                    "connectivity",
                    "content_ready",
                    "info",
                    "connectivity ready (host-local)",
                );
            }

            // WS-10 — record the resource isolation + connectivity profiles (microVM cpu/mem are
            // monitor-enforced; ports namespace-isolated in-guest).
            //
            // CONTAINMENT (claim truth): these profiles are keyed on `microvm_ok` — the MEASURED
            // boot outcome — not on `is_microvm`, the declaration. Previously a microVM whose boot
            // FAILED still published `enforcement: "vm_kernel (monitor-enforced cpu/mem)"` and
            // `namespace_isolated: true`, which no longer held. A declared-but-unbooted
            // environment now reports the weaker truth and carries a withdrawn-label marker.
            env["status"]["resource_isolation_profile"] =
                resource_isolation_profile(microvm_ok, 2, 1024);
            env["status"]["connectivity_profile"] =
                connectivity_profile(recipe.as_ref(), microvm_ok);
            env["status"]["measured_isolation"] = json!(truthful_isolation_label(
                if is_microvm {
                    DeclaredIsolation::VmKernel
                } else {
                    DeclaredIsolation::ProcessScoped
                },
                IsolatedSubstrate::observed(microvm_ok),
            ));

            // WS-3 — typed Services / Tasks / Ports. If a recipe is bound, resolve it, RUN its
            // tasks (in-guest for microVM, on the host for local), build typed services/ports, and
            // let the ReadinessGate decide readiness.
            if let Some(recipe) = recipe {
                observe(
                    &mut env,
                    "resolving_recipe",
                    "recipe",
                    "content_ready",
                    "info",
                    "resolving recipe → plan",
                );
                let resolution = super::recipe_routes::resolve_recipe(&st.data_dir, &recipe, &id)?;
                observe(
                    &mut env,
                    "starting_services",
                    "automations",
                    "content_ready",
                    "info",
                    "running resolved tasks",
                );
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
                    t["lifecycle"].as_str() == Some("required")
                        && t["phase"].as_str() != Some("succeeded")
                });
                env["status"]["tasks"] = json!(task_results);
                // Do not admit guest-authored bytes into the host cache. The current preview
                // cache remains local/trusted only until its provenance contract is implemented.
                if !is_microvm {
                    save_recipe_cache(&st.data_dir, &recipe, &ws);
                }
                // typed services (required services health-checked) + typed ports.
                let services: Vec<Value> = recipe["services"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .map(|s| typed_service(&ws, s))
                    .collect();
                env["status"]["services"] = json!(services);
                // WS-10 — typed ports with host-port conflict detection (surfaced, not dropped).
                let in_use = host_ports_in_use(&st.data_dir, &id);
                let mut any_conflict = false;
                let ports: Vec<Value> = recipe["ports"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .map(|p| {
                        let (tp, c) = typed_port_checked(p, &in_use);
                        if c {
                            any_conflict = true;
                        }
                        tp
                    })
                    .collect();
                env["status"]["ports"] = json!(ports);
                if any_conflict {
                    set_component(&mut env, "connectivity", "degraded", "host port conflict");
                    observe(
                        &mut env,
                        "checking_connectivity",
                        "ports",
                        "port_conflict",
                        "warning",
                        "host port conflict detected (surfaced, not silently dropped)",
                    );
                }
                set_component(
                    &mut env,
                    "automations",
                    if any_required_failed {
                        "failed"
                    } else {
                        "ready"
                    },
                    if any_required_failed {
                        "a required task failed"
                    } else {
                        "tasks complete"
                    },
                );

                set_phase(&mut env, "running");
                let gate =
                    super::recipe_routes::compute_readiness_gate(&st.data_dir, &resolution, &env)?;
                env["status"]["recipe_ref"] = json!(recipe_ref);
                env["status"]["recipe_resolution_ref"] = resolution["resolution_ref"].clone();
                env["status"]["readiness_gate_ref"] = gate["gate_ref"].clone();
                env["status"]["readiness"] = json!({ "mode": gate["readiness_mode"], "blocked_reasons": gate["blocked_reasons"] });
                let mode = gate["readiness_mode"]
                    .as_str()
                    .unwrap_or("blocked")
                    .to_string();
                if mode != "full" {
                    let reasons = gate["blocked_reasons"].clone();
                    observe(
                        &mut env,
                        "binding_access",
                        "automations",
                        "blocked_by_policy",
                        "warning",
                        &format!("readiness {mode}: {reasons}"),
                    );
                }
                observe(
                    &mut env,
                    "ready",
                    "agent_work",
                    "ever_ready",
                    "info",
                    &format!("environment running (readiness: {mode})"),
                );
            } else {
                // no recipe — default typed workspace service/task/ports (declared).
                let declared = env["spec"]["declared_ports"].clone();
                env["status"]["services"] = json!([
                    { "service_ref": "svc_workspace", "name": "workspace", "lifecycle": "support", "phase": "running", "restart_policy": "on_failure" }
                ]);
                env["status"]["tasks"] = json!([
                    { "task_ref": "task_post_start", "name": "post-start setup", "trigger": "post_start", "lifecycle": "optional", "phase": "succeeded", "exit_code": 0 }
                ]);
                env["status"]["ports"] =
                    if declared.as_array().map(|a| a.is_empty()).unwrap_or(true) {
                        json!([])
                    } else {
                        json!(declared
                            .as_array()
                            .cloned()
                            .unwrap_or_default()
                            .iter()
                            .map(typed_port)
                            .collect::<Vec<_>>())
                    };
                set_component(
                    &mut env,
                    "automations",
                    "ready",
                    "post-start tasks complete",
                );
                observe(
                    &mut env,
                    "starting_services",
                    "automations",
                    "content_ready",
                    "info",
                    "services/tasks ready",
                );
                set_phase(&mut env, "running");
                recompute_readiness(&mut env);
                let mode = env["status"]["readiness"]["mode"]
                    .as_str()
                    .unwrap_or("blocked")
                    .to_string();
                observe(
                    &mut env,
                    "ready",
                    "agent_work",
                    "ever_ready",
                    "info",
                    &format!("environment running (readiness: {mode})"),
                );
            }
        }
        "stop" => {
            stop_environment(&st, &mut env, &id, "stopped_by_request", "operator stop");
        }
        "archive" => {
            set_phase(&mut env, "archived");
            recompute_readiness(&mut env);
            observe(
                &mut env,
                "archiving",
                "storage",
                "content_ready",
                "info",
                "environment archived",
            );
        }
        "restore" => {
            set_phase(&mut env, "stopped");
            recompute_readiness(&mut env);
            observe(
                &mut env,
                "validating_restore",
                "storage",
                "content_ready",
                "info",
                "environment restored",
            );
        }
        "delete" => {
            // CARVE-OUT: deletion of an EXISTING environment REMAINS CALLABLE under every
            // containment in this cut. It never refuses. It returns an exact
            // `succeeded | failed | unknown` outcome and opens a durable cleanup obligation
            // whenever the outcome is not `succeeded`, so an operator is never stranded with a
            // resource they cannot delete — and never told a resource is gone when it may not be.
            set_phase(&mut env, "stopping");
            let disposition = teardown_microvm(&st, &id);
            record_cleanup_disposition(&st, &mut env, &disposition);
            env["status"]["deletion_outcome"] = disposition["outcome"].clone();
            let dir = std::path::Path::new(&st.data_dir)
                .join("environments")
                .join(safe_id(&id));
            // W1.2 / MEF-GAP-008 — MEASURE the removal (the b6c19c766 false-destruction-ack shape): a
            // failed remove_dir_all must not be acknowledged as "scoped workspace removed", and the
            // workspace_root pointer is nulled ONLY when the files are actually gone (ENOENT counts),
            // so leftover files stay findable rather than stranded behind a null pointer.
            let workspace_removed = match std::fs::remove_dir_all(&dir) {
                Ok(()) => true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                Err(_) => false,
            };
            if workspace_removed {
                env["status"]["workspace_root"] = Value::Null;
            }
            env["status"]["workspace_removed"] = json!(workspace_removed);
            for c in COMPONENTS {
                set_component(&mut env, c, "pending", "deleted");
            }
            env["status"]["deleted"] = json!(true);
            set_phase(&mut env, "deleted"); // terminal — not "stopped" (the env is gone, not idle)
            recompute_readiness(&mut env);
            let outcome = disposition["outcome"].as_str().unwrap_or("unknown");
            observe(
                &mut env,
                "deleting",
                "storage",
                "state_wiped",
                "info",
                &format!(
                    "environment deleted ({workspace}; microVM teardown: {outcome})",
                    workspace = if workspace_removed {
                        "scoped workspace removed"
                    } else {
                        "scoped workspace removal FAILED — files may remain on disk (workspace_root retained)"
                    }
                ),
            );
        }
        "inject-failure" => {
            // WS-9: simulate a provider crash — kill the VM out-of-band; the env still believes
            // it is running until recovery reconciles. The HOST workspace + branches are untouched.
            let disposition = teardown_microvm(&st, &id);
            record_cleanup_disposition(&st, &mut env, &disposition);
            set_component(
                &mut env,
                "sandbox",
                "failed",
                "provider failure injected (vm_lost)",
            );
            set_component(&mut env, "resource_isolation", "failed", "no sandbox");
            observe(
                &mut env,
                "detecting_failure",
                "provider",
                "provider_unavailable",
                "error",
                "provider failure injected: vm_lost",
            );
        }
        "recover" => {
            recovery = recover_environment(&st, &mut env, &id)?;
        }
        other => {
            return Err(AppError(
                StatusCode::BAD_REQUEST,
                format!("unknown environment action: {other}"),
            ))
        }
    }
    persist_env(&st.data_dir, &env)?;
    Ok(Json(json!({ "environment": env, "recovery": recovery })))
}

fn admit_workrun_isolation_contract(
    body: &Value,
    env_id: &str,
    wr_id: &str,
    admitted_at: &str,
) -> Result<Value, AppError> {
    let workrun_ref = format!("workrun://{wr_id}");
    let requirements = body.get("workload_isolation_requirements").ok_or_else(|| {
        AppError(
            StatusCode::BAD_REQUEST,
            "workload_isolation_requirements_required: compiled requirements are required".into(),
        )
    })?;
    if requirements
        .get("minimum_isolation")
        .and_then(Value::as_str)
        != Some("process_scoped")
    {
        return Err(AppError(
            StatusCode::CONFLICT,
            "workload_isolation_floor_unavailable: the local WorkRun route admits process_scoped requirements only"
                .into(),
        ));
    }
    let binding_inputs = body.get("workload_isolation_binding_inputs").ok_or_else(|| {
        AppError(
            StatusCode::BAD_REQUEST,
            "workload_isolation_binding_inputs_required: current runtime assignment and enforcement facts are required"
                .into(),
        )
    })?;
    let admission = GoalPursuitCore
        .admit_workrun_isolation(requirements, binding_inputs, &workrun_ref, admitted_at)
        .map_err(|error| {
            AppError(
                StatusCode::BAD_REQUEST,
                format!("{}: {}", error.code(), error.message()),
            )
        })?;
    let expected_environment_ref = format!("environment://{env_id}");
    if admission["binding"]["environment_ref"].as_str() != Some(expected_environment_ref.as_str()) {
        return Err(AppError(
            StatusCode::CONFLICT,
            "workload_isolation_environment_mismatch: binding inputs name a different environment"
                .into(),
        ));
    }
    Ok(admission)
}

/// POST /v1/hypervisor/workruns — bind a code WorkRun to its own Git worktree and patch branch.
/// Concurrent WorkRuns never checkout or mutate one another's working directory.
/// `{ "environment_id": "...", "objective"?: "..." }`.
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
    if env["status"]["substrate"].as_str() == Some("microvm")
        || env["spec"]["environment_class_id"].as_str() == Some("microvm")
    {
        return Err(AppError(
            StatusCode::NOT_IMPLEMENTED,
            "isolated_workrun_pipeline_unavailable: WorkRun creation still mutates a host Git workspace and cannot satisfy guest-proposal, quarantined-output, and governed-SCM requirements".into(),
        ));
    }
    let ws = env["status"]["workspace_root"]
        .as_str()
        .ok_or_else(|| {
            AppError(
                StatusCode::CONFLICT,
                "environment not started (no workspace)".into(),
            )
        })?
        .to_string();
    let base = ensure_git_repo(&ws)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let wr_id = format!("workrun_{nanos:x}");
    // Admit the complete immutable isolation binding before creating a Git
    // worktree or performing any other host effect. The local route can honor
    // only its honest process-scoped floor; a stronger request fails closed
    // and is never recorded as containment it did not provide.
    let workrun_ref = format!("workrun://{wr_id}");
    let isolation_admission = admit_workrun_isolation_contract(&body, env_id, &wr_id, &iso_now())?;
    let runtime_assignment_ref = isolation_admission["binding"]["runtime_assignment_ref"].clone();
    let isolation_binding_ref = isolation_admission["binding"]["binding_ref"].clone();
    let isolation_binding_hash = isolation_admission["binding"]["binding_hash"].clone();
    let branch = format!("workrun/{wr_id}");
    let workrun_root = std::path::Path::new(&st.data_dir)
        .join("workrun-workspaces")
        .join(safe_id(&wr_id));
    if let Some(parent) = workrun_root.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("workrun workspace parent: {e}"),
            )
        })?;
    }
    let workrun_root_string = workrun_root.to_string_lossy().to_string();
    run_git(
        &ws,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            &branch,
            &workrun_root_string,
            &base,
        ],
    )
    .map_err(|e| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("git worktree: {e}"),
        )
    })?;
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.workrun.v1",
        "id": wr_id,
        "workrun_ref": workrun_ref,
        "environment_id": env_id,
        "base_commit": base,
        "branch": branch,
        "workspace_root": workrun_root_string,
        "patch_branch_ref": format!("agentgres://patch-branch/{branch}"),
        "objective": body.get("objective").cloned().unwrap_or(Value::Null),
        "status": "open",
        "host_mutation": true,
        "host_mutation_scope": "workrun_scoped_workspace",
        "host_repo_mutation": false,
        "review_state": "draft",
        "workload_isolation_admission": isolation_admission,
        "runtime_assignment_ref": runtime_assignment_ref,
        "isolation_binding_ref": isolation_binding_ref,
        "isolation_binding_hash": isolation_binding_hash,
        "isolation_state": "admitted",
        "created_at": now,
        "updated_at": now
    });
    persist_record(&st.data_dir, "workruns", &wr_id, &record).map_err(|e| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("persist workrun: {e}"),
        )
    })?;
    Ok(Json(json!({ "workRun": record })))
}

/// GET /v1/hypervisor/incidents — provider-failure incidents (WS-9; projected by the panel).
pub(crate) async fn handle_incidents_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "incidents": read_record_dir(&st.data_dir, "incidents") }))
}

/// GET /v1/hypervisor/recovery-attempts — recovery attempts (WS-9).
pub(crate) async fn handle_recovery_attempts_list(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
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
        sse.push_str(&format!(
            "event: {ev}\ndata: {}\n\n",
            serde_json::to_string(data).unwrap_or_default()
        ));
    };
    match load_env(&st.data_dir, &id) {
        Some(env) => {
            let status = env["status"].clone();
            frame(
                "environment_status",
                &json!({ "environment_id": id, "status": status }),
            );
            frame("readiness", &status["readiness"]);
            for obs in env["lifecycle_observations"]
                .as_array()
                .cloned()
                .unwrap_or_default()
            {
                frame("lifecycle_observation", &obs);
            }
            frame(
                "done",
                &json!({ "environment_id": id, "phase": status["phase"], "readiness": status["readiness"]["mode"] }),
            );
        }
        None => frame(
            "error",
            &json!({ "code": "not_found", "environment_id": id }),
        ),
    }
    (
        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
        sse,
    )
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
        let idle_to = env["spec"]["stop_policy"]["idle_timeout_secs"]
            .as_u64()
            .unwrap_or(0);
        let max_life = env["spec"]["stop_policy"]["max_lifetime_secs"]
            .as_u64()
            .unwrap_or(0);
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
            // W1.2 / MEF-GAP-008 — teardown already ran (measured, honest); record the per-env
            // outcome rather than discarding the write. A lost env record would leave the sweep
            // reporting a stop no reader sees; a per-item outcome keeps one failure from failing the
            // whole sweep (teardown-first order means the record reports a measured outcome).
            if persist_env(&st.data_dir, &env).is_ok() {
                stopped
                    .push(json!({ "environment_id": id, "reason": reason, "outcome": "stopped" }));
            } else {
                stopped.push(json!({ "environment_id": id, "reason": reason, "outcome": "environment_record_persistence_failed" }));
            }
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
fn capture_workspace(
    st: &DaemonState,
    identity: &super::substrate_store::RequestIdentity,
    env_id: &str,
    kind: &str,
) -> Result<Value, CustodyReply> {
    let app = |e: String| {
        custody_bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "environment_capture_failed",
            e,
        )
    };
    // AUTHORIZATION BEFORE EXISTENCE. The scope pin is read from the coordinate the caller supplied,
    // so a principal who holds no custody of this environment learns nothing about whether it
    // exists — and, far more importantly, never reaches the tar below.
    authorize_environment_custody(&st.data_dir, identity, env_id)?;
    let env = load_env(&st.data_dir, env_id).ok_or_else(|| {
        custody_bad(
            StatusCode::NOT_FOUND,
            "environment_not_found",
            "environment not found",
        )
    })?;
    if env["status"]["substrate"].as_str() == Some("microvm")
        || env["spec"]["environment_class_id"].as_str() == Some("microvm")
    {
        return Err(custody_bad(
            StatusCode::NOT_IMPLEMENTED,
            "machine_snapshot_unsupported",
            "the current workspace archive does not quiesce or capture guest disk/memory state",
        ));
    }
    let ws = env["status"]["workspace_root"].as_str().ok_or_else(|| {
        custody_bad(
            StatusCode::CONFLICT,
            "environment_workspace_absent",
            "environment not started (no workspace)",
        )
    })?;
    let tar = super::microvm::tar_dir(std::path::Path::new(ws))
        .map_err(|e| app(format!("tar workspace: {e}")))?;
    let state_root = format!("sha256:{}", sha256_hex_bytes(&tar));
    // A RE-CAPTURE OVER A DESTRUCTION REFUSES, and it refuses BEFORE a byte is written. Re-capturing
    // a workspace whose content an owner ordered destroyed would put those exact bytes back under a
    // fresh coordinate — the resurrection deletion forbids, and the one the capture-side name gate
    // could not see. Asked against the estate-wide stream, so a destruction ordered in the
    // managed-runtime lane binds here too.
    super::managed_runtime_routes::refuse_if_material_destroyed_public(&st.data_dir, &state_root)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let prefix = if kind == "backup" { "backup" } else { "snap" };
    let id = format!("{prefix}_{nanos:x}");
    // THE CAPTURE'S OWN OWNER PIN, BEFORE ITS BYTES EXIST. A capture is separately addressable — the
    // retention plane resolves it by id and restore takes it by id — so it carries its own
    // per-principal scope rather than inheriting the environment's by inspection. Binding first means
    // a capture record can never exist on disk without an owner.
    let owner_ref = custody_owner_tenant(identity)?;
    super::substrate_store::bind_request_resource_scope(
        &st.data_dir,
        identity,
        CAPTURE_SCOPE_KIND,
        &custody_coordinate(&id),
        &owner_ref,
        &owner_ref,
        &format!("environment-capture-owner:{id}"),
    )
    .map_err(custody_scope_refusal)?;
    let dir = std::path::Path::new(&st.data_dir)
        .join(format!("{kind}s"))
        .join(safe_id(&id));
    std::fs::create_dir_all(&dir).map_err(|e| app(format!("mkdir: {e}")))?;
    let tar_path = dir.join("workspace.tar");
    std::fs::write(&tar_path, &tar).map_err(|e| app(format!("write material: {e}")))?;
    let record = json!({
        "schema_version": format!("ioi.hypervisor.environment-{kind}.v1"),
        format!("{kind}_ref"): id,
        "kind": kind,
        "environment_ref": env_id,
        "state_root": state_root,
        "material_ref": format!("local-cas://sha256/{}", state_root.trim_start_matches("sha256:")),
        "material_path": tar_path.to_string_lossy(),
        "bytes": tar.len(),
        "created_at": iso_now()
    });
    persist_record(&st.data_dir, &format!("{kind}s"), &id, &record)
        .map_err(|e| app(format!("persist {kind}: {e}")))?;
    Ok(public_capture(&record))
}

/// A capture as a caller may see it: never the absolute `material_path`, which is daemon-local
/// filesystem layout and was readable by any caller at all through the unscoped list route.
fn public_capture(record: &Value) -> Value {
    let mut public = record.clone();
    public
        .as_object_mut()
        .map(|object| object.remove("material_path"));
    public
}

// =================================================================================================
// THE LEGACY CUSTODY LANE'S OWNER MODEL.
//
// Next-legs XI closed the UNAUTHENTICATED half of this defect and filed the rest open, correctly:
// `handle_snapshot_create`, `handle_backup_create` and `handle_snapshot_restore` resolved no caller
// at all, and `POST /snapshots/:id/restore` OVERWRITES a workspace. Authentication is not
// authorization, and what remained was the larger half — every AUTHENTICATED principal could still
// archive or restore EVERY environment's workspace, because an environment had no owner to scope to.
//
// It has one now. Ownership is the substrate's own immutable per-PRINCIPAL scope pin, bound at the
// one route that means create, and every custody act on the environment or on a capture is
// authorized against it. Never a record's descriptive `owner_ref`, and never a tenant check:
// `org://local` is the only constructible organization and every principal holds it.
// =================================================================================================

type CustodyReply = (StatusCode, Json<Value>);

/// Carry one of this module's existing `AppError` refusals into the typed shape without inventing a
/// code for it. The message is preserved verbatim, so nothing a caller already reads disappears;
/// only the envelope gains `ok` and a code naming the class.
fn app_error_reply(error: AppError) -> CustodyReply {
    custody_bad(error.0, "environment_request_refused", error.1)
}

fn custody_bad(status: StatusCode, code: &str, message: impl Into<String>) -> CustodyReply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

fn custody_scope_refusal(error: super::substrate_store::RequestScopeRefusal) -> CustodyReply {
    super::mutation_event_foundation::scope_refusal_reply(error)
}

/// Identity FIRST, before any record is read — a 401 is owed before a 404 existence oracle, and
/// every handler behind this either reads workspace bytes or writes them.
fn custody_identity(
    data_dir: &str,
    headers: &HeaderMap,
) -> Result<super::substrate_store::RequestIdentity, CustodyReply> {
    super::substrate_store::resolve_request_identity(data_dir, headers)
        .map_err(custody_scope_refusal)
}

/// The one organization tenant this principal's session was admitted for.
///
/// The scope binding requires `tenant_ref == owner_ref`, so the owner coordinate has to be exactly
/// one tenant. Deriving it from the session's own resolved membership is what makes the pin the
/// caller's; a route-supplied `owner_ref` would let a caller name the scope it wants to land in.
fn custody_owner_tenant(
    identity: &super::substrate_store::RequestIdentity,
) -> Result<String, CustodyReply> {
    let mut organizations = identity
        .tenant_refs
        .iter()
        .filter(|tenant_ref| tenant_ref.starts_with("org://"));
    let (Some(owner_ref), None) = (organizations.next(), organizations.next()) else {
        return Err(custody_bad(
            StatusCode::FORBIDDEN,
            "environment_custody_owner_tenant_unresolved",
            "custody ownership binds to exactly one org:// tenant resolved from the caller's own session; zero or many cannot name an owner",
        ));
    };
    Ok(owner_ref.clone())
}

/// THE ONE COORDINATE RULE FOR THIS MODULE, and it exists because breaking it shipped a
/// demonstrated cross-principal read AND write in this leg's own first cut.
///
/// A GATE IS ONLY AS STRONG AS THE COORDINATE IT KEYS ON. The pin was bound on the RAW caller-supplied
/// `environment_id` while the record file and the workspace directory are keyed on `safe_id(id)` —
/// and `safe_id` is MANY-TO-ONE, mapping every character outside `[A-Za-z0-9_-]` to `_`. So
/// `env.18cb` and `env_18cb` were two distinct pin coordinates over ONE record and ONE workspace.
/// Every daemon-minted id is `env_{nanos:x}` and therefore always contains `_`, so a colliding raw id
/// always existed for the default create path: a merge-blocking review created the alias, took a
/// fresh pin at it, clobbered the victim's environment record, started it onto the victim's own
/// workspace directory, captured the victim's bytes, and restored over them.
///
/// Every caller-supplied id becomes a scope coordinate through here, so the pin coordinate, the
/// record coordinate and the workspace coordinate are the same string by construction.
fn custody_coordinate(resource_id: &str) -> String {
    safe_id(resource_id)
}

/// Bind this environment to the caller as its owner. Idempotent for the same principal; a DIFFERENT
/// principal binding an already-pinned environment is refused by the substrate as an owner mismatch.
///
/// Reached only through `bind_environment_owner_if_resolvable`, at workspace materialization.
fn bind_environment_owner(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    environment_id: &str,
) -> Result<super::substrate_store::RequestResourceScope, CustodyReply> {
    let owner_ref = custody_owner_tenant(identity)?;
    let coordinate = custody_coordinate(environment_id);
    super::substrate_store::bind_request_resource_scope(
        data_dir,
        identity,
        ENVIRONMENT_SCOPE_KIND,
        &coordinate,
        &owner_ref,
        &owner_ref,
        &format!("environment-owner:{coordinate}"),
    )
    .map_err(custody_scope_refusal)
}

/// Record ownership for an environment whose WORKSPACE has just been materialized.
///
/// Called from exactly one place — the `start` arm, immediately after
/// `provision_local_workspace` succeeds. That is the moment the bytes custody protects come into
/// existence, and the authenticated principal whose request created them is the only honest owner.
///
/// It never refuses, and binds only when no pin exists: an unauthenticated start materializes an
/// UNOWNED workspace exactly as before, and the custody gate reads that as "no principal may capture
/// this". A second start by anyone never transfers custody, because the pin is already there.
fn bind_environment_owner_if_resolvable(data_dir: &str, headers: &HeaderMap, environment_id: &str) {
    if let Ok(identity) = super::substrate_store::resolve_request_identity(data_dir, headers) {
        let _ = bind_environment_owner(data_dir, &identity, environment_id);
    }
}

/// The environment's owner pin, or `None` when no principal holds custody of it.
fn environment_owner_pin(
    data_dir: &str,
    environment_id: &str,
) -> Result<Option<super::substrate_store::RequestResourceScope>, CustodyReply> {
    super::substrate_store::read_request_scope(
        data_dir,
        ENVIRONMENT_SCOPE_KIND,
        &custody_coordinate(environment_id),
    )
    .map_err(custody_scope_refusal)
}

/// Authorize this caller against the environment's own scope pin, per PRINCIPAL.
///
/// The two refusals are deliberately distinguishable, because they are different facts: an
/// environment with NO pin is one no principal holds custody of, while a pin held by another
/// principal is an authorization failure.
fn authorize_environment_custody(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    environment_id: &str,
) -> Result<super::substrate_store::RequestResourceScope, CustodyReply> {
    if environment_owner_pin(data_dir, environment_id)?.is_none() {
        return Err(custody_bad(
            StatusCode::FORBIDDEN,
            "environment_custody_owner_unbound",
            "this environment carries no owner pin, so no principal holds custody of its workspace; its workspace was materialized by a caller this daemon could not identify, or it predates the owner model. Ownership is acquired by the authenticated principal whose request materializes the workspace — start it under a session to acquire one",
        ));
    }
    super::substrate_store::authorize_request_resource_scope(
        data_dir,
        identity,
        ENVIRONMENT_SCOPE_KIND,
        &custody_coordinate(environment_id),
        None,
    )
    .map_err(custody_scope_refusal)
}

/// One capture's durable record, addressed by the kind directory it lives in.
fn load_capture(data_dir: &str, kind: &str, id: &str) -> Option<Value> {
    serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(data_dir)
                .join(format!("{kind}s"))
                .join(format!("{}.json", safe_id(id))),
        )
        .ok()?,
    )
    .ok()
}

/// The material bytes one legacy capture wrote. Unlike the managed-runtime lane, this store is
/// keyed by CAPTURE ID rather than by content, so two captures of identical bytes are two files.
pub(crate) fn capture_material_path(data_dir: &str, kind: &str, id: &str) -> std::path::PathBuf {
    std::path::Path::new(data_dir)
        .join(format!("{kind}s"))
        .join(safe_id(id))
        .join("workspace.tar")
}

/// Resolve one capture through the caller's OWN authorized scope set, never through the record.
///
/// This is the shape `authorized_backup_by_id` already has on the managed lane, and the reason is
/// the same: reading the record first and then checking a field on it makes the record the
/// authority. The scope pin is the authority; the record is what the scope points at.
/// Returns the CANONICAL coordinate beside the record, because a caller's spelling must not travel
/// any further than this seam.
///
/// A review demonstrated why: normalizing only where the scope is authorized, and carrying the RAW
/// id onward, left the pin at one coordinate and the lifecycle stream, the retention subject and the
/// tombstone read at another. A retention duty declared against `snap.18cb…` was admitted (the scope
/// authorized, because it normalizes) and could then NEVER be executed (the tombstone keyed on the
/// raw spelling), while its own refusal said "retry to converge". A MIXED CONVENTION IS THE SAME
/// DEFECT IN A NEW PLACE, so the canonical coordinate is returned and every caller uses it.
pub(crate) fn authorized_capture_by_id(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    capture_id: &str,
) -> Result<
    (
        String,
        String,
        Value,
        super::substrate_store::RequestResourceScope,
    ),
    CustodyReply,
> {
    let coordinate = custody_coordinate(capture_id);
    let scope = super::substrate_store::authorize_request_resource_scope(
        data_dir,
        identity,
        CAPTURE_SCOPE_KIND,
        &coordinate,
        None,
    )
    .map_err(custody_scope_refusal)?;
    for kind in ["snapshot", "backup"] {
        if let Some(record) = load_capture(data_dir, kind, &coordinate) {
            return Ok((kind.to_string(), coordinate, record, scope));
        }
    }
    Err(custody_bad(
        StatusCode::NOT_FOUND,
        "environment_capture_not_found",
        "the caller holds a custody scope at this coordinate but no capture record resolves under it",
    ))
}

fn capture_lifecycle_tail(capture_ref: &str) -> String {
    super::mutation_event_foundation::stream_tail("environment-capture-lifecycle", capture_ref)
}

fn read_capture_lifecycle(
    data_dir: &str,
    capture_ref: &str,
) -> Result<Option<agentgres::mux::ExactProjection>, CustodyReply> {
    super::substrate_store::read_event_stream_operation(
        data_dir,
        CUSTODY_NAMESPACE,
        &capture_lifecycle_tail(capture_ref),
    )
    .map_err(|error| {
        custody_bad(
            StatusCode::SERVICE_UNAVAILABLE,
            "environment_capture_lifecycle_unavailable",
            error.to_string(),
        )
    })
}

/// Establish this capture's lifecycle genesis from the ALREADY-ADMITTED record when the stream is
/// absent, and return the head.
///
/// `expected_head: None` is GENESIS-ONLY — it sets expected-absent, so an object a deletion must
/// advance needs a head to compare-and-swap against and a tombstone that PRESERVES it. Deriving the
/// genesis wholly from durable truth is what lets one code path serve a capture written before this
/// stream existed without a migration pass over the family.
fn ensure_capture_lifecycle(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    scope: &super::substrate_store::RequestResourceScope,
    kind: &str,
    capture_ref: &str,
    record: &Value,
    idempotency_key: &str,
) -> Result<agentgres::mux::ExactProjection, CustodyReply> {
    if let Some(head) = read_capture_lifecycle(data_dir, capture_ref)? {
        return Ok(head);
    }
    let payload = json!({
        "schema_version": CAPTURE_LIFECYCLE_SCHEMA,
        "capture_ref": capture_ref,
        "capture_kind": kind,
        "environment_ref": record["environment_ref"],
        "state_root": record["state_root"],
        "status": "admitted",
        "pruned_by_disposition_ref": Value::Null,
    });
    admit_custody_stream(
        data_dir,
        true,
        identity,
        scope,
        capture_ref,
        &capture_lifecycle_tail(capture_ref),
        "event_stream.environment_capture_lifecycle_admitted",
        None,
        &payload,
        idempotency_key,
    )
    .map(|(exact, _)| exact)
}

#[allow(clippy::too_many_arguments)]
fn admit_custody_stream(
    data_dir: &str,
    genesis: bool,
    identity: &super::substrate_store::RequestIdentity,
    scope: &super::substrate_store::RequestResourceScope,
    capture_ref: &str,
    tail: &str,
    op_kind: &str,
    expected_head: Option<&str>,
    payload: &Value,
    idempotency_key: &str,
) -> Result<(agentgres::mux::ExactProjection, bool), CustodyReply> {
    super::mutation_event_foundation::admit_owner_scoped_mutation(
        data_dir,
        genesis,
        super::mutation_event_foundation::ScopedMutation {
            identity,
            scope,
            resource_kind: CAPTURE_SCOPE_KIND,
            resource_ref: capture_ref,
            owner_namespace: CUSTODY_NAMESPACE,
            stream_tail: tail,
            op_kind,
            expected_head,
            payload,
            idempotency_key,
            recorded_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0),
        },
    )
    .map(|commit| (commit.projection, commit.replayed))
    .map_err(super::mutation_event_foundation::mutation_refusal_reply)
}

/// Refuse when this capture was deleted — by NAME (its lifecycle head is a tombstone) or by CONTENT
/// (its bytes were destroyed under an executed disposition, in EITHER custody lane).
///
/// The content half deliberately reads the managed-runtime plane's estate-wide destroyed-material
/// stream rather than a second one of this lane's own. An owner who ordered content destroyed is
/// owed that destruction wherever those exact bytes would otherwise be re-established, and this leg
/// exists precisely because the two custody lanes could be treated as one when they were not. One
/// fact, one stream, both lanes.
fn refuse_if_capture_deleted(
    data_dir: &str,
    capture_ref: &str,
    state_root: &str,
) -> Result<(), CustodyReply> {
    if let Some(head) = read_capture_lifecycle(data_dir, capture_ref)? {
        if head.operation.payload["status"] == json!("pruned") {
            return Err((
                StatusCode::GONE,
                Json(json!({
                    "ok": false,
                    "error": {
                        "code": "environment_capture_tombstoned",
                        "message": "this capture was deleted under an executed retention disposition; its content is destroyed and it is not restore material",
                        "details": {
                            "pruned_by_disposition_ref": head.operation.payload["pruned_by_disposition_ref"],
                            "admitted_head": head.head,
                        }
                    }
                })),
            ));
        }
    }
    super::managed_runtime_routes::refuse_if_material_destroyed_public(data_dir, state_root)
}

/// Admit the head-preserving TOMBSTONE for one legacy capture, and record the destroyed content on
/// the estate's single destroyed-material stream.
///
/// This is NOT a second delete route. The W1.5 data-retention disposition plane owns deletion, blocks
/// on legal hold, and builds its evidence from real filesystem outcomes; this function is how that
/// one decision becomes reachable for the legacy custody store's separate bytes. The retention plane
/// calls it BEFORE it destroys a byte, so a deletion that reaches the filesystem always carries the
/// tombstone that makes it legible — and a tombstone that cannot be admitted refuses the deletion
/// outright, with nothing destroyed and a retry that converges.
pub(crate) fn tombstone_environment_capture(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    capture_id: &str,
    disposition_ref: &str,
    idempotency_key: &str,
) -> Result<Value, CustodyReply> {
    let (kind, capture_ref, record, scope) =
        authorized_capture_by_id(data_dir, identity, capture_id)?;
    let state_root = record["state_root"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let current = ensure_capture_lifecycle(
        data_dir,
        identity,
        &scope,
        &kind,
        &capture_ref,
        &record,
        &format!("{idempotency_key}.lifecycle"),
    )?;
    if current.operation.payload["status"] == json!("pruned") {
        return Ok(json!({
            "capture_ref": capture_ref,
            "capture_kind": kind,
            "admitted_head": current.head,
            "replayed": true,
        }));
    }
    let mut payload = current.operation.payload.clone();
    payload["status"] = json!("pruned");
    payload["pruned_by_disposition_ref"] = json!(disposition_ref);
    let (exact, replayed) = admit_custody_stream(
        data_dir,
        false,
        identity,
        &scope,
        &capture_ref,
        &capture_lifecycle_tail(&capture_ref),
        "event_stream.environment_capture_lifecycle_pruned",
        Some(&current.head),
        &payload,
        &format!("{idempotency_key}.pruned"),
    )?;
    // AND the fact keyed on WHAT WAS DESTROYED, on the SAME estate-wide stream the managed lane
    // writes and reads. Keying only on the capture name would leave re-capture of identical content
    // as an unblocked resurrection path, and would leave the two custody lanes with two different
    // answers to one owner's deletion.
    let destroyed_head = super::managed_runtime_routes::record_material_destroyed(
        data_dir,
        identity,
        &scope,
        CAPTURE_SCOPE_KIND,
        &capture_ref,
        &state_root,
        disposition_ref,
        idempotency_key,
    )?;
    Ok(json!({
        "capture_ref": capture_ref,
        "capture_kind": kind,
        "admitted_head": exact.head,
        "state_root": state_root,
        "destroyed_material_head": destroyed_head,
        "replayed": replayed,
    }))
}

/// The environment coordinate a capture request names, refused typed when absent.
fn requested_environment(body: &Value) -> Result<&str, CustodyReply> {
    body.get("environment_id")
        .and_then(|v| v.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            custody_bad(
                StatusCode::BAD_REQUEST,
                "environment_id_required",
                "environment_id required",
            )
        })
}

/// POST /v1/hypervisor/snapshots — forkable point-in-time snapshot. `{ "environment_id": "..." }`.
pub(crate) async fn handle_snapshot_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, CustodyReply> {
    let identity = custody_identity(&st.data_dir, &headers)?;
    let env_id = requested_environment(&body)?;
    Ok(Json(
        json!({ "snapshot": capture_workspace(&st, &identity, env_id, "snapshot")? }),
    ))
}

/// POST /v1/hypervisor/backups — durability material (distinct from a snapshot).
pub(crate) async fn handle_backup_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, CustodyReply> {
    let identity = custody_identity(&st.data_dir, &headers)?;
    let env_id = requested_environment(&body)?;
    Ok(Json(
        json!({ "backup": capture_workspace(&st, &identity, env_id, "backup")? }),
    ))
}

/// GET /v1/hypervisor/snapshots — the caller's OWN captures.
///
/// This route answered every snapshot record in the estate to an unauthenticated caller, including
/// each one's absolute `material_path` and `state_root`. Listing is now derived from the caller's own
/// authorized scope set — the same set the retention plane and restore resolve through — so the list
/// cannot report a capture the caller could not act on.
pub(crate) async fn handle_snapshots_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, CustodyReply> {
    let identity = custody_identity(&st.data_dir, &headers)?;
    let authorized = super::substrate_store::authorized_request_resource_refs(
        &st.data_dir,
        &identity,
        CAPTURE_SCOPE_KIND,
    )
    .map_err(custody_scope_refusal)?;
    let snapshots = read_record_dir(&st.data_dir, "snapshots")
        .iter()
        .filter(|record| {
            record["snapshot_ref"]
                .as_str()
                .is_some_and(|reference| authorized.contains(reference))
        })
        .map(public_capture)
        .collect::<Vec<_>>();
    Ok(Json(json!({ "snapshots": snapshots })))
}

/// POST /v1/hypervisor/snapshots/:id/restore — restore a snapshot into its env's workspace, ONLY
/// if the material's recomputed state_root matches the admitted one (else restore_invalid). A blob
/// existing is not sufficient; restore validity is operation-backed.
pub(crate) async fn handle_snapshot_restore(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, CustodyReply> {
    // Rule E: identity before any record read — a 401 is owed before a 404 existence oracle, and
    // this handler's effect is a WRITE into an environment's workspace.
    let identity = custody_identity(&st.data_dir, &headers)?;
    // AUTHORIZATION BEFORE EXISTENCE, on the coordinate the path supplies: the capture's own owner
    // pin decides whether this caller may read these bytes at all, and it is read before the record.
    let (_kind, capture_ref, snap, _scope) =
        authorized_capture_by_id(&st.data_dir, &identity, &id)?;
    let app = |c: StatusCode, code: &str, e: String| custody_bad(c, code, e);
    let admitted_root = snap["state_root"].as_str().unwrap_or_default().to_string();
    // A DELETED CAPTURE IS NOT RESTORE MATERIAL, and saying so is what keeps an executed retention
    // deletion legible: reading the missing file first would answer "material missing", the same
    // observable a lost disk produces.
    refuse_if_capture_deleted(&st.data_dir, &capture_ref, &admitted_root)?;
    let env_id = snap["environment_ref"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    // AND the DESTINATION is authorized independently of the source. Holding a capture does not
    // license writing it into an environment whose workspace this principal does not hold — the two
    // are the same act only when one principal owns both, which is exactly what this asks.
    authorize_environment_custody(&st.data_dir, &identity, &env_id)?;
    let material_path = snap["material_path"].as_str().unwrap_or_default();
    let tar = std::fs::read(material_path).map_err(|e| {
        app(
            StatusCode::CONFLICT,
            "restore_material_missing",
            format!("restore material missing: {e}"),
        )
    })?;
    // operation-backed validity: recompute the state_root and compare to the admitted one.
    let recomputed = format!("sha256:{}", sha256_hex_bytes(&tar));
    let admitted = admitted_root.as_str();
    if recomputed != admitted {
        return Err(app(StatusCode::CONFLICT, "restore_invalid", format!("restore_invalid: state_root mismatch (admitted {admitted}, material {recomputed}) — blob tampered/corrupt")));
    }
    let mut env = load_env(&st.data_dir, &env_id).ok_or_else(|| {
        custody_bad(
            StatusCode::NOT_FOUND,
            "environment_not_found",
            "environment not found",
        )
    })?;
    if env["status"]["substrate"].as_str() == Some("microvm")
        || env["spec"]["environment_class_id"].as_str() == Some("microvm")
    {
        return Err(app(
            StatusCode::NOT_IMPLEMENTED,
            "machine_restore_unsupported",
            "machine_restore_unsupported: workspace material is not a quiesced guest disk or memory snapshot".to_string(),
        ));
    }
    let ws = env["status"]["workspace_root"]
        .as_str()
        .ok_or_else(|| {
            custody_bad(
                StatusCode::CONFLICT,
                "environment_workspace_absent",
                "environment has no workspace",
            )
        })?
        .to_string();
    // Restore is prepare/apply, never delete-first. Extract and validate into a sibling staging
    // directory, retain the trusted workspace as a rollback target, then swap by rename.
    let ws_path = std::path::PathBuf::from(&ws);
    let parent = ws_path.parent().ok_or_else(|| {
        app(
            StatusCode::CONFLICT,
            "restore_workspace_parent_absent",
            "workspace has no restore parent".to_string(),
        )
    })?;
    let restore_token = safe_id(&id);
    let staging = parent.join(format!(".ioi-restore-staging-{restore_token}"));
    let rollback = parent.join(format!(".ioi-restore-rollback-{restore_token}"));
    if staging.exists() || rollback.exists() {
        return Err(app(
            StatusCode::CONFLICT,
            "restore_recovery_obligation_open",
            "restore recovery obligation already exists; reconcile it before retry".to_string(),
        ));
    }
    super::microvm::untar_into(&staging, &tar).map_err(|e| {
        let _ = std::fs::remove_dir_all(&staging);
        app(
            StatusCode::INTERNAL_SERVER_ERROR,
            "restore_staging_extract_failed",
            format!("restore staging extract: {e}"),
        )
    })?;
    std::fs::rename(&ws_path, &rollback).map_err(|e| {
        let _ = std::fs::remove_dir_all(&staging);
        app(
            StatusCode::CONFLICT,
            "restore_prepare_rename_failed",
            format!("restore prepare rename: {e}"),
        )
    })?;
    if let Err(error) = std::fs::rename(&staging, &ws_path) {
        let rollback_result = std::fs::rename(&rollback, &ws_path);
        return Err(app(
            StatusCode::INTERNAL_SERVER_ERROR,
            "restore_apply_rename_failed",
            format!("restore apply rename: {error}; rollback={rollback_result:?}"),
        ));
    }
    // if a microVM is live, re-import the restored workspace.
    if st.live_vms.lock().unwrap().contains_key(&env_id) {
        use super::microvm;
        if let Some(vm) = st.live_vms.lock().unwrap().get(&env_id) {
            let monitor_kind = microvm::MonitorKind::parse(vm.monitor)
                .map_err(|e| app(StatusCode::CONFLICT, "restore_monitor_kind_invalid", e))?;
            let monitor = microvm::make_monitor(monitor_kind);
            let t = microvm::tar_dir(std::path::Path::new(&ws)).map_err(|e| {
                app(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "restore_reimport_tar_failed",
                    format!("restore re-import tar: {e}"),
                )
            })?;
            if let Err(error) = monitor.import_workspace(vm, &t) {
                let failed = parent.join(format!(".ioi-restore-failed-{restore_token}"));
                let _ = std::fs::rename(&ws_path, &failed);
                let rollback_result = std::fs::rename(&rollback, &ws_path);
                return Err(app(
                    StatusCode::CONFLICT,
                    "restore_reimport_failed",
                    format!("restore re-import failed: {error}; host rollback={rollback_result:?}"),
                ));
            }
        }
    }
    std::fs::remove_dir_all(&rollback).map_err(|e| {
        app(
            StatusCode::INTERNAL_SERVER_ERROR,
            "restore_rollback_cleanup_unresolved",
            format!("restore applied but rollback cleanup is unresolved: {e}"),
        )
    })?;
    observe(
        &mut env,
        "validating_restore",
        "storage",
        "content_ready",
        "info",
        &format!("snapshot {id} restored (state_root validated)"),
    );
    persist_env(&st.data_dir, &env).map_err(|error| {
        custody_bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "environment_projection_failed",
            error.1,
        )
    })?;
    Ok(Json(
        json!({ "restored": true, "snapshot_ref": id, "validated": true, "state_root": admitted }),
    ))
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

/// The command-execution guardrail decision AT the scoped execution primitive, and the response
/// body when it refuses. `None` means no veto fired — which grants nothing: the caller still has
/// every other gate to pass.
///
/// Extracted from the Axum adapter so both refusal shapes are directly testable without standing
/// up a daemon. Two refusals, kept DISTINCT:
///
///   * `policy_denied` — a policy rule actually matched this command string. `denial` names the
///     rule and the matched pattern.
///   * `policy_indeterminate` — the policy could NOT be resolved (unreadable, malformed, or
///     non-regular persisted state, or a malformed environment-local declaration). Execution is
///     still refused, but the response must not claim a rule matched, because none did; the
///     previous hardcoded "blocked by environment guardrail policy" stderr asserted exactly that
///     for a state where no policy had been read at all.
///
/// The enforcement fact and the audit outcome are reported SEPARATELY. Losing the audit record is
/// an observability gap, never a reason to admit the command and never `audited: true` — so
/// `audit_durability` rides alongside the refusal instead of being discarded.
fn guardrail_refusal_response(
    data_dir: &str,
    env: &Value,
    env_id: &str,
    command: &str,
) -> Option<Value> {
    use super::operability_routes::GuardrailDecision;
    let (mut body, refusal) = match super::operability_routes::guardrail_check(
        data_dir, env, command,
    ) {
        GuardrailDecision::Allowed => return None,
        GuardrailDecision::Denied(denial) => (
            json!({
                "environment_id": env_id, "command": command, "denied": true,
                "policy_denied": true, "denial": denial.clone(), "exit_code": 126,
                "stdout": "", "stderr": "blocked by environment guardrail policy (fail-closed)"
            }),
            denial,
        ),
        GuardrailDecision::Indeterminate(indeterminacy) => (
            json!({
                "environment_id": env_id, "command": command, "denied": true,
                "policy_indeterminate": true, "refusal": indeterminacy.clone(), "exit_code": 126,
                "stdout": "", "stderr": "refused: the command-execution guardrail policy is INDETERMINATE and no policy rule was evaluated (fail-closed)"
            }),
            indeterminacy,
        ),
    };
    body["audit_durability"] =
        super::operability_routes::audit_guardrail_denial(data_dir, env_id, command, &refusal);
    Some(body)
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
        .ok_or_else(|| {
            AppError(
                StatusCode::CONFLICT,
                "environment not started (no workspace)".into(),
            )
        })?
        .to_string();

    // Cut F (M) — guardrail enforcement at the exec primitive: the deny-list is checked on the
    // command string itself, so an agent cannot bypass policy via ordinary shell (a `bash -c "rm
    // -rf /"` is still this command string). Fail-closed + audited; the in-guest path is gated too.
    if let Some(refusal) = guardrail_refusal_response(&st.data_dir, &env, env_id, command) {
        return Ok(Json(refusal));
    }

    // WS-4: if a live microVM backs this env, the terminal runs IN-GUEST (real kernel boundary).
    let in_guest = st.live_vms.lock().unwrap().contains_key(env_id);

    // CONTAINMENT: an environment that DECLARED a vm_kernel isolation floor must never silently
    // execute on the host when its guest is gone (daemon restart, VM crash, teardown). Previously
    // this fell through to `bash -lc` on the host while the durable record still advertised
    // `minimum_isolation: vm_kernel`. Refuse by name instead of falling back.
    if let Err(refusal) = admit_isolated_execution(
        DeclaredIsolation::from_env_status(&env["status"]),
        IsolatedSubstrate::observed(in_guest),
        ExecutionLocus::Guest,
    ) {
        return Ok(Json(json!({
            "ok": false,
            "refused": true,
            "reason": refusal.reason,
            "detail": refusal.detail,
            "executed": false,
            "executed_in": "none",
            "exit_code": 126,
            "stdout": "",
            "stderr": "isolation required but no isolated substrate is live (fail-closed)"
        })));
    }

    let (stdout, stderr, exit_code) = if in_guest {
        use super::microvm;
        let vms = st.live_vms.lock().unwrap();
        let vm = vms
            .get(env_id)
            .ok_or_else(|| AppError(StatusCode::CONFLICT, "no live VM".into()))?;
        let monitor_kind = microvm::MonitorKind::parse(vm.monitor)
            .map_err(|e| AppError(StatusCode::CONFLICT, e))?;
        let monitor = microvm::make_monitor(monitor_kind);
        let out = monitor.exec(vm, command).map_err(|e| {
            AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("guest exec: {e}"),
            )
        })?;
        (out.output, String::new(), out.exit_code)
    } else {
        let out = std::process::Command::new("bash")
            .arg("-lc")
            .arg(command)
            .current_dir(&ws)
            .output()
            .map_err(|e| {
                AppError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("exec spawn: {e}"),
                )
            })?;
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
    let env_id = body
        .get("environment_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError(StatusCode::BAD_REQUEST, "environment_id required".into()))?;
    let op = body.get("op").and_then(|v| v.as_str()).unwrap_or("open");
    let mut env = load_env(&st.data_dir, env_id)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "environment not found".into()))?;
    let ws = env["status"]["workspace_root"]
        .as_str()
        .ok_or_else(|| {
            AppError(
                StatusCode::CONFLICT,
                "environment not started (no workspace)".into(),
            )
        })?
        .to_string();
    let nanos = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    };

    // resolve the devcontainer config path (.devcontainer/devcontainer.json or devcontainer.json).
    let dc_nested = std::path::Path::new(&ws).join(".devcontainer/devcontainer.json");
    let dc_flat = std::path::Path::new(&ws).join("devcontainer.json");
    let (dc_path, config_rel) = if dc_nested.exists() {
        (Some(dc_nested), ".devcontainer/devcontainer.json")
    } else if dc_flat.exists() {
        (Some(dc_flat), "devcontainer.json")
    } else {
        (None, ".devcontainer/devcontainer.json")
    };
    let read_config = || {
        dc_path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
    };

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
                    observe(
                        &mut env,
                        "rebuilding",
                        "recipe",
                        "failed",
                        "error",
                        "rebuild refused: devcontainer config is invalid JSON",
                    );
                    env["status"]["rebuild"] = json!({ "state": "failed", "reason": "invalid_devcontainer_config", "recoverable": true, "at": iso_now() });
                    recompute_readiness(&mut env);
                    persist_env(&st.data_dir, &env)?;
                    let rid = format!("erc_{:x}", nanos());
                    // W1.2 / MEF-GAP-008 — null the returned receipt_ref if the receipt did not
                    // persist (provider_receipt_ext pattern); no response cites a receipt that
                    // resolves to nothing.
                    let receipt_ref = if persist_record(
                        &st.data_dir,
                        "environment-receipts",
                        &rid,
                        &json!({ "environment_ref": env_id, "event": "rebuild_failed", "reason": "invalid_devcontainer_config", "at": iso_now() }),
                    )
                    .is_ok()
                    {
                        json!(format!("agentgres://environment-receipt/{rid}"))
                    } else {
                        Value::Null
                    };
                    return Ok(Json(
                        json!({ "ok": false, "op": "rebuild", "environment_id": env_id, "state": "failed", "reason": "invalid_devcontainer_config", "recoverable": true, "receipt_ref": receipt_ref }),
                    ));
                }
            }
            // daemon-owned rebuild: re-detect → admit → resolve → readiness gate → observe.
            observe(
                &mut env,
                "rebuilding",
                "recipe",
                "content_ready",
                "info",
                "rebuild: re-detecting recipe from devcontainer config",
            );
            let project_ref = env["spec"]["project_id"].as_str();
            let new_recipe_ref =
                super::recipe_routes::detect_and_admit(&st.data_dir, &ws, project_ref)?;
            let recipe = super::recipe_routes::load_recipe(&st.data_dir, &new_recipe_ref)
                .unwrap_or_else(|| json!({}));
            let resolution = super::recipe_routes::resolve_recipe(&st.data_dir, &recipe, env_id)?;
            let gate =
                super::recipe_routes::compute_readiness_gate(&st.data_dir, &resolution, &env)?;
            let prior = env["spec"]["recipe_ref"].clone();
            env["spec"]["recipe_ref"] = json!(new_recipe_ref);
            env["status"]["recipe_ref"] = json!(new_recipe_ref);
            env["status"]["readiness"] = json!({ "mode": gate["readiness_mode"], "blocked_reasons": gate["blocked_reasons"] });
            observe(
                &mut env,
                "rebuilding",
                "recipe",
                "content_ready",
                "info",
                &format!(
                    "rebuild applied: recipe {} → {new_recipe_ref} (readiness {})",
                    prior.as_str().unwrap_or("none"),
                    gate["readiness_mode"].as_str().unwrap_or("")
                ),
            );
            observe(
                &mut env,
                "ready",
                "recipe",
                "ever_ready",
                "info",
                "rebuild complete",
            );
            env["status"]["rebuild"] = json!({ "state": "succeeded", "from_recipe": prior, "to_recipe": new_recipe_ref, "readiness_mode": gate["readiness_mode"], "at": iso_now() });
            persist_env(&st.data_dir, &env)?;
            let rid = format!("erc_{:x}", nanos());
            // W1.2 / MEF-GAP-008 — null the returned receipt_ref if the receipt did not persist
            // (provider_receipt_ext pattern); no response cites a receipt that resolves to nothing.
            let receipt_ref = if persist_record(
                &st.data_dir,
                "environment-receipts",
                &rid,
                &json!({ "environment_ref": env_id, "event": "rebuild_succeeded", "recipe_ref": new_recipe_ref, "readiness_mode": gate["readiness_mode"], "at": iso_now() }),
            )
            .is_ok()
            {
                json!(format!("agentgres://environment-receipt/{rid}"))
            } else {
                Value::Null
            };
            Ok(Json(json!({
                "ok": true, "op": "rebuild", "environment_id": env_id, "state": "succeeded",
                "recipe_ref": new_recipe_ref, "resolution_ref": resolution["resolution_ref"], "readiness_gate_ref": gate["gate_ref"],
                "readiness_mode": gate["readiness_mode"], "lifecycle": "daemon_environment_lifecycle",
                "receipt_ref": receipt_ref,
                "events_stream": format!("/v1/hypervisor/env-events/{env_id}")
            })))
        }
        "apply_automations" => {
            observe(
                &mut env,
                "applying_automations",
                "tasks",
                "content_ready",
                "info",
                "automations/tasks config applied to environment tasks (daemon-owned)",
            );
            persist_env(&st.data_dir, &env)?;
            Ok(Json(
                json!({ "ok": true, "op": "apply_automations", "environment_id": env_id, "note": "automations mapped to Hypervisor environment tasks, not a VS Code sidecar" }),
            ))
        }
        other => Ok(Json(
            json!({ "ok": false, "reason": format!("unknown op '{other}'") }),
        )),
    }
}

/// POST /v1/hypervisor/workruns/:id/execute — run ONE model-driven child-harness turn.
///
/// This is the real Build-Rule inner loop. The daemon's model route (`hypervisor:native-fixture`
/// offline; a mounted model when present) generates content; the child harness writes it as a
/// REAL edit on the WorkRun's scoped patch branch and commits under a child identity.
///
/// CLAIM TRUTH: this turn executes ON THE HOST — host `git` subprocesses and a host
/// `std::fs::write`. The IOI source repo is not touched and mutation is confined to the
/// environment's scoped workspace, but that is `host_repo_mutation: false`, NOT
/// `host_mutation: false`. The record reports both, measured rather than asserted (INV-38).
/// An environment that declared a `vm_kernel` isolation floor refuses this route outright.
/// The turn is recorded `review_state: proposed` for the operator/authority gate
/// (daemon EXECUTES · wallet AUTHORIZES the eventual merge crossing).
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

    let env_id = wr["environment_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let env = load_env(&st.data_dir, &env_id)
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "environment not found".into()))?;
    let ws = wr["workspace_root"]
        .as_str()
        .ok_or_else(|| {
            AppError(
                StatusCode::CONFLICT,
                "workrun has no isolated workspace".into(),
            )
        })?
        .to_string();
    let branch = wr["branch"].as_str().unwrap_or("HEAD").to_string();

    let workrun_ref = wr["workrun_ref"].as_str().ok_or_else(|| {
        AppError(
            StatusCode::CONFLICT,
            "workload_isolation_workrun_ref_missing: legacy unbound WorkRun cannot execute".into(),
        )
    })?;
    let isolation_admission = wr.get("workload_isolation_admission").ok_or_else(|| {
        AppError(
            StatusCode::CONFLICT,
            "workload_isolation_binding_missing: legacy unbound WorkRun cannot execute".into(),
        )
    })?;
    GoalPursuitCore
        .preserve_workrun_isolation(
            isolation_admission,
            &isolation_admission["binding"],
            workrun_ref,
            "execute",
        )
        .map_err(|error| {
            AppError(
                StatusCode::CONFLICT,
                format!("{}: {}", error.code(), error.message()),
            )
        })?;

    // CONTAINMENT: this turn executes host-side — host `git` processes and a host
    // `std::fs::write` against the scoped workspace. That cannot honour a declared vm_kernel
    // isolation floor, so an environment that declared one refuses here rather than executing
    // host-side and then recording `host_mutation: false`.
    if let Err(refusal) = admit_isolated_execution(
        DeclaredIsolation::from_env_status(&env["status"]),
        IsolatedSubstrate::observed(st.live_vms.lock().unwrap().contains_key(&env_id)),
        ExecutionLocus::Host,
    ) {
        return Err(AppError(
            StatusCode::CONFLICT,
            format!("{}: {}", refusal.reason, refusal.detail),
        ));
    }

    // The dedicated Git worktree is born on this branch. Refuse drift rather than checking out
    // inside a potentially shared directory.
    let observed_branch = run_git(&ws, &["branch", "--show-current"]).map_err(|e| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("git branch: {e}"),
        )
    })?;
    if observed_branch != branch {
        return Err(AppError(
            StatusCode::CONFLICT,
            format!("workrun branch drift: expected {branch}, observed {observed_branch}"),
        ));
    }

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
        let options = InferenceOptions {
            max_tokens: 1024,
            ..Default::default()
        };
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
        std::fs::create_dir_all(parent).map_err(|e| {
            AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("mkdir agent dir: {e}"),
            )
        })?;
    }
    let file_body = format!(
        "<!-- workrun {id} · turn {turn_idx} · model {} · branch {branch} -->\n\n# Objective\n\n{objective}\n\n# Model output\n\n{text}\n",
        st.model_name
    );
    std::fs::write(&file_path, &file_body).map_err(|e| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write edit: {e}"),
        )
    })?;

    // Commit under a CHILD identity (per-command, never global config). Host repo untouched.
    let child = [
        "-c",
        "user.email=child@local",
        "-c",
        "user.name=child_harness",
    ];
    let mut add_args = child.to_vec();
    add_args.extend_from_slice(&["add", "-A"]);
    run_git(&ws, &add_args)
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("git add: {e}")))?;
    let msg = format!(
        "workrun turn {turn_idx}: {}",
        objective.chars().take(60).collect::<String>()
    );
    let mut commit_args = child.to_vec();
    commit_args.extend_from_slice(&["commit", "-q", "-m", msg.as_str()]);
    run_git(&ws, &commit_args).map_err(|e| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("git commit: {e}"),
        )
    })?;
    let commit = run_git(&ws, &["rev-parse", "HEAD"])
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, format!("git head: {e}")))?;

    // Confirm the scoped working tree is clean (the edit is committed, nothing dangling).
    let dirty = run_git(&ws, &["status", "--porcelain"]).map_err(|e| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("git status: {e}"),
        )
    })?;

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
        // CONTAINMENT (claim truth): this turn wrote to the host filesystem and ran host `git`
        // processes. The former hardcoded `host_mutation: false` asserted a fact the code never
        // measured (INV-37). What is actually true is narrower: the IOI source repo was not
        // touched; the scoped workspace on the host WAS.
        "host_mutation": true,
        "host_mutation_scope": "environment_scoped_workspace",
        "host_repo_mutation": false,
        "executed_in": "host",
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
    // CONTAINMENT (claim truth): measured, not asserted — see the turn record above.
    wr["host_mutation"] = json!(true);
    wr["host_mutation_scope"] = json!("environment_scoped_workspace");
    wr["host_repo_mutation"] = json!(false);
    wr["executed_in"] = json!("host");
    wr["updated_at"] = json!(now);
    persist_record(&st.data_dir, "workruns", &id, &wr).map_err(|e| {
        AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("persist workrun: {e}"),
        )
    })?;

    Ok(Json(json!({ "workRun": wr, "turn": turn })))
}

#[cfg(test)]
mod containment_tests {
    use super::*;

    fn microvm_env_status() -> Value {
        json!({
            "minimum_isolation": "vm_kernel",
            "substrate": "microvm",
            "isolation_claim": "cross_tenant_capable",
            "trust_posture": "untrusted_code_capable",
        })
    }

    fn local_env_status() -> Value {
        json!({
            "minimum_isolation": "process + scoped worktree/runtime state",
            "substrate": "local_host",
            "isolation_claim": "not_cross_tenant",
        })
    }

    // ---- isolation: refuse, never fall back ----

    #[test]
    fn exec_refuses_host_fallback_when_a_declared_microvm_is_not_live() {
        // This is the exec route's decision, extracted: previously the same inputs fell through
        // to `bash -lc` on the host while the record still advertised vm_kernel isolation.
        let refusal = admit_isolated_execution(
            DeclaredIsolation::from_env_status(&microvm_env_status()),
            IsolatedSubstrate::observed(false),
            ExecutionLocus::Guest,
        )
        .expect_err("exec must refuse rather than run on the host");
        assert_eq!(refusal.reason, "isolation_required_substrate_unavailable");
    }

    #[test]
    fn exec_still_runs_in_guest_when_the_microvm_is_live() {
        assert!(admit_isolated_execution(
            DeclaredIsolation::from_env_status(&microvm_env_status()),
            IsolatedSubstrate::observed(true),
            ExecutionLocus::Guest,
        )
        .is_ok());
    }

    #[test]
    fn a_host_executed_workrun_refuses_under_a_declared_isolation_requirement() {
        // handle_workrun_execute runs host `git` + a host `std::fs::write`. Under a declared
        // vm_kernel floor that is refused even when a VM happens to be live.
        for live in [true, false] {
            let refusal = admit_isolated_execution(
                DeclaredIsolation::from_env_status(&microvm_env_status()),
                IsolatedSubstrate::observed(live),
                ExecutionLocus::Host,
            )
            .expect_err("host-executed WorkRun must refuse");
            assert_eq!(refusal.reason, "isolation_required_host_execution_refused");
        }
    }

    #[test]
    fn local_environments_are_unaffected_by_containment() {
        // Containment reduces claims; it must not break the honest process-scoped lane.
        assert!(admit_isolated_execution(
            DeclaredIsolation::from_env_status(&local_env_status()),
            IsolatedSubstrate::observed(false),
            ExecutionLocus::Host,
        )
        .is_ok());
    }

    fn workrun_isolation_body(minimum_isolation: &str) -> Value {
        let mut requirements: Value = serde_json::from_str(include_str!(
            "../../../../../docs/architecture/_meta/schemas/fixtures/hypervisor-workload-isolation-requirements-v1/positive-high-risk.json"
        ))
        .unwrap();
        requirements["minimum_isolation"] = json!(minimum_isolation);
        let mut inputs: Value = serde_json::from_str(include_str!(
            "../../../../../docs/architecture/_meta/schemas/fixtures/hypervisor-workload-isolation-binding-v1/positive-bound.json"
        ))
        .unwrap();
        let object = inputs.as_object_mut().unwrap();
        for daemon_owned in [
            "schema_version",
            "binding_ref",
            "binding_hash",
            "requirements_ref",
            "requirements_hash",
            "workrun_ref",
        ] {
            object.remove(daemon_owned);
        }
        json!({
            "workload_isolation_requirements": requirements,
            "workload_isolation_binding_inputs": inputs
        })
    }

    #[test]
    fn workrun_isolation_is_admitted_before_the_local_effect_lane() {
        let admission = match admit_workrun_isolation_contract(
            &workrun_isolation_body("process_scoped"),
            "env-1",
            "run-1",
            "2026-07-30T12:00:00Z",
        ) {
            Ok(admission) => admission,
            Err(_) => panic!("valid process-scoped isolation contract must be admitted"),
        };
        assert_eq!(admission["workrun_ref"], "workrun://run-1");
        assert_eq!(
            admission["binding"]["environment_ref"],
            "environment://env-1"
        );
        assert_eq!(
            admission["binding"]["required_terminal_disposition"],
            "destroyed_verified"
        );
    }

    #[test]
    fn workrun_isolation_refuses_missing_or_stronger_contracts_before_effects() {
        assert_eq!(
            admit_workrun_isolation_contract(&json!({}), "env-1", "run-1", "2026-07-30T12:00:00Z",)
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            admit_workrun_isolation_contract(
                &workrun_isolation_body("vm_kernel"),
                "env-1",
                "run-1",
                "2026-07-30T12:00:00Z",
            )
            .unwrap_err()
            .0,
            StatusCode::CONFLICT
        );
    }

    // ---- withdrawn labels ----

    #[test]
    fn a_failed_microvm_boot_no_longer_publishes_vm_kernel_enforcement() {
        // resource_isolation_profile is now keyed on the MEASURED boot outcome.
        let measured_fail = resource_isolation_profile(false, 2, 1024);
        assert_eq!(measured_fail["enforcement"], json!("process_scoped"));
        assert_eq!(measured_fail["ports"]["namespace_isolated"], json!(false));

        let measured_ok = resource_isolation_profile(true, 2, 1024);
        assert_eq!(
            measured_ok["enforcement"],
            json!("vm_kernel (monitor-enforced cpu/mem)")
        );
    }

    #[test]
    fn the_withdrawn_label_names_what_is_actually_unverified() {
        assert_eq!(
            truthful_isolation_label(
                DeclaredIsolation::VmKernel,
                IsolatedSubstrate::observed(false)
            ),
            "unverified_isolation_declared_vm_kernel_substrate_unavailable"
        );
    }

    // ---- feature-gated unsafe paths ----

    #[test]
    fn the_guest_to_host_workspace_restore_is_off_by_default() {
        let refusal = unsafe_path_gate(UNVERIFIED_WORKSPACE_RESTORE_GATE, None)
            .expect_err("guest->host restore must be gated OFF by default");
        assert_eq!(refusal.reason, "unsafe_path_gate_disabled");
        assert!(unsafe_path_gate(UNVERIFIED_WORKSPACE_RESTORE_GATE, Some("1")).is_ok());
    }

    // ---- cache containment ----

    #[test]
    fn recipe_cache_paths_that_escape_the_root_are_dropped() {
        let recipe = json!({
            "recipe_ref": "recipe://demo",
            "system_ref": "system://tenant-a",
            "cache_paths": ["node_modules", "../../etc", "/root/.ssh", "target"],
        });
        assert_eq!(
            admitted_cache_paths(&recipe),
            vec!["node_modules", "target"]
        );
    }

    #[test]
    fn an_unattributed_recipe_cache_is_not_shared_across_tenants() {
        // No owning scope -> no cache at all, rather than a node-global shared directory.
        let unattributed = json!({ "recipe_ref": "recipe://demo", "cache_paths": ["target"] });
        assert!(recipe_cache_scope(&unattributed).is_none());
        assert_eq!(
            restore_recipe_cache("/tmp/ioi-containment-test", &unattributed, "/tmp/ws"),
            (false, Vec::new())
        );

        // Two tenants sharing a recipe get two different cache directories.
        let a = recipe_cache_dir("/d", "recipe://demo", "system://tenant-a");
        let b = recipe_cache_dir("/d", "recipe://demo", "system://tenant-b");
        assert_ne!(a, b);
    }

    // ---- CARVE-OUT: deletion stays callable with all three outcomes ----

    #[test]
    fn environment_deletion_reports_each_of_the_three_outcomes_with_obligations() {
        for (outcome, expects_obligation) in [
            (DeletionOutcome::Succeeded, false),
            (DeletionOutcome::Failed, true),
            (DeletionOutcome::Unknown, true),
        ] {
            let disposition = close_deletion("microvm://environment/env_1", outcome);
            assert_eq!(disposition.outcome, outcome);
            assert_eq!(
                disposition.cleanup_obligation_ref.is_some(),
                expects_obligation,
                "{outcome:?} obligation expectation"
            );
        }
    }

    #[test]
    fn a_teardown_that_cannot_prove_absence_is_unknown_not_succeeded() {
        // teardown_microvm re-observes the monitor pid; a stop call that merely returned Ok is
        // never reported as a proven deletion.
        assert_eq!(
            DeletionOutcome::classify(true, false),
            DeletionOutcome::Unknown
        );
    }

    #[test]
    fn a_non_succeeded_deletion_records_a_durable_obligation_on_the_record() {
        let disposition = close_deletion("microvm://environment/env_1", DeletionOutcome::Unknown);
        let st_dir = std::env::temp_dir().join("ioi-containment-oblig-test");
        let _ = std::fs::create_dir_all(&st_dir);
        let mut env = json!({ "status": {} });
        // Exercise the record-shaping half without a DaemonState.
        env["status"]["last_cleanup_disposition"] = disposition.to_json();
        env["status"]["cleanup_obligations"] = json!([{
            "cleanup_obligation_ref": disposition.cleanup_obligation_ref,
            "outcome": disposition.outcome.as_str(),
            "status": "pending",
        }]);
        assert_eq!(
            env["status"]["cleanup_obligations"][0]["outcome"],
            json!("unknown")
        );
        assert_eq!(
            env["status"]["cleanup_obligations"][0]["status"],
            json!("pending")
        );
    }
}

#[cfg(test)]
mod scoped_exec_guardrail_tests {
    use super::*;

    // Deterministic, uid-independent, process-local: path shadows only. No chmod (root bypasses
    // mode bits), no env var, no cwd change. These drive the PRODUCTION functions the mounted
    // POST /v1/hypervisor/exec route calls — `new_env` for the retained declaration and
    // `guardrail_refusal_response` for the enforcement decision and its response body.

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// `AppError` is not `Debug`, and its defining module is not this change's to touch, so these
    /// two destructure it rather than reaching for `expect`/`expect_err`.
    fn admit(id: &str, spec: &Value) -> Value {
        match new_env(id, spec) {
            Ok(env) => env,
            Err(AppError(status, message)) => {
                panic!("new_env refused a valid spec: {status} {message}")
            }
        }
    }

    fn creation_refusal(id: &str, spec: &Value) -> (StatusCode, String) {
        match new_env(id, spec) {
            Ok(env) => panic!("new_env admitted a spec it must refuse: {env}"),
            Err(AppError(status, message)) => (status, message),
        }
    }

    fn refuse(directory: &tempfile::TempDir, env: &Value, command: &str) -> Option<Value> {
        guardrail_refusal_response(
            directory.path().to_str().unwrap(),
            env,
            env["id"].as_str().unwrap_or("env_1"),
            command,
        )
    }

    /// 4a. An environment created with a valid local addition RETAINS it, and the addition is
    /// enforced at the primitive. The declaration used to be dropped by `new_env`, which made
    /// every environment-local denial unreachable from the product path.
    #[test]
    fn environment_creation_retains_a_valid_local_addition_and_it_enforces() {
        let directory = temp();
        let env = admit(
            "env_local",
            &json!({ "guardrails": { "deny_commands": ["deploy-to-prod"] } }),
        );

        assert_eq!(
            env["spec"]["guardrails"],
            json!({ "deny_commands": ["deploy-to-prod"] }),
            "the declaration must survive into the durable record"
        );
        let refusal = refuse(&directory, &env, "deploy-to-prod --now")
            .expect("the retained local addition must be enforced");
        assert_eq!(refusal["policy_denied"], json!(true));
        assert_eq!(refusal["denial"]["rule"], json!("deny_command"));
        assert_eq!(refusal["denial"]["matched"], json!("deploy-to-prod"));
        assert_eq!(refusal["exit_code"], json!(126));
        // A command the composed policy does not deny still runs the normal path.
        assert!(refuse(&directory, &env, "cargo build").is_none());
    }

    #[test]
    fn an_environment_without_a_declaration_carries_no_guardrails_key() {
        // Absence stays legible as absence; nothing is minted for a spec that declared none.
        let env = admit("env_plain", &json!({ "project_id": "prj" }));
        assert!(env["spec"].get("guardrails").is_none());

        // An EXPLICIT null is absence too — the validator and the composition step both read it
        // that way, so retaining it would mint a null-shaped declaration no caller wrote and
        // contradict the "omitted when the spec carries none" contract.
        let explicit_null = admit("env_null", &json!({ "guardrails": Value::Null }));
        assert!(
            explicit_null["spec"].get("guardrails").is_none(),
            "an explicit null must be omitted, not retained: {}",
            explicit_null["spec"]
        );
    }

    /// 4b. A malformed local declaration is REFUSED at creation, before persist. Admitting one
    /// would durably brick that environment's terminal: the enforcement point treats a malformed
    /// declaration as indeterminate and denies every command, and no route can update
    /// `spec.guardrails` afterwards. Refusing is the only disposition with a repair path.
    #[test]
    fn environment_creation_refuses_a_malformed_local_declaration_before_persist() {
        for malformed in [
            json!({ "deny_commands": "not-an-array" }),
            json!({ "deny_commands": [42] }),
            json!({ "deny_commands": [""] }),
            json!({ "deny_commands": ["ok"], "deny_executables": [null] }),
            json!(["deny_commands"]),
            // An environment cannot author its own authority: an allow-shaped key is refused
            // rather than ignored.
            json!({ "allow_commands": ["rm -rf /"] }),
            json!({ "deny_commands": ["ok"], "note": "extra" }),
        ] {
            let (status, message) =
                creation_refusal("env_bad", &json!({ "guardrails": malformed.clone() }));
            assert_eq!(status, StatusCode::BAD_REQUEST, "for {malformed}");
            assert!(
                message.contains("guardrail declaration is invalid"),
                "for {malformed}: {message}"
            );
        }
    }

    /// The same semantic validator decides creation and composition, so a record that WAS
    /// admitted before that validation existed (or written out of band) still denies rather than
    /// being ignored — and the refusal names the only repair the API actually has.
    #[test]
    fn a_pre_existing_malformed_declaration_denies_and_names_a_real_repair() {
        let directory = temp();
        // Written out of band, exactly as a record predating create-time validation would be.
        let mut env = admit("env_broken", &json!({}));
        env["spec"]["guardrails"] = json!({ "deny_commands": "not-an-array" });

        let refusal = refuse(&directory, &env, "echo harmless").expect("must refuse");
        assert_eq!(refusal["denied"], json!(true));
        assert_eq!(refusal["policy_indeterminate"], json!(true));
        assert!(refusal.get("policy_denied").is_none());
        assert_eq!(
            refusal["refusal"]["store"],
            json!("environment_local_declaration")
        );
        // The recovery text must name an affordance that EXISTS. There is no route that updates
        // spec.guardrails, so "repair the declaration" would have been a lie.
        let recovery = refusal["refusal"]["recovery"].as_str().unwrap();
        assert!(
            recovery.contains("delete and recreate") && recovery.contains("out of band"),
            "recovery must name a real repair path, got: {recovery}"
        );
        assert!(
            recovery.contains("NO route"),
            "recovery must say no update route exists, got: {recovery}"
        );
    }

    /// 10a. An indeterminate policy refuses WITHOUT claiming a policy rule matched. The previous
    /// response hardcoded `policy_denied: true` and "blocked by environment guardrail policy" for
    /// a state in which no policy had been read at all.
    #[test]
    fn an_indeterminate_policy_refuses_without_claiming_a_matched_rule() {
        let directory = temp();
        std::fs::write(directory.path().join("guardrail-policy.json"), b"{ corrupt").unwrap();
        let env = admit("env_1", &json!({}));

        let refusal = refuse(&directory, &env, "echo harmless").expect("must refuse");

        assert_eq!(refusal["denied"], json!(true));
        assert_eq!(refusal["policy_indeterminate"], json!(true));
        assert!(
            refusal.get("policy_denied").is_none(),
            "an unresolvable policy is not a matched denial: {refusal}"
        );
        assert!(refusal["refusal"].get("rule").is_none());
        assert!(refusal["refusal"].get("matched").is_none());
        assert!(!refusal["refusal"]["recovery"].as_str().unwrap().is_empty());
        assert!(refusal["stderr"]
            .as_str()
            .unwrap()
            .contains("INDETERMINATE"));
        assert_eq!(refusal["exit_code"], json!(126));
    }

    /// 10b. A denial whose audit write fails is STILL a denial, and the evidence loss is reported
    /// separately from the enforcement fact — never as `audited: true`, never as permission.
    #[test]
    fn a_denial_whose_audit_write_fails_remains_a_denial_and_exposes_the_gap() {
        let directory = temp();
        // A regular FILE where the audit family directory belongs: the audit write cannot commit.
        std::fs::write(
            directory.path().join("operability-audit"),
            b"not a directory",
        )
        .unwrap();
        let env = admit("env_1", &json!({}));

        let refusal = refuse(&directory, &env, "rm -rf /").expect("must still refuse");

        assert_eq!(refusal["denied"], json!(true));
        assert_eq!(refusal["policy_denied"], json!(true));
        assert_eq!(refusal["denial"]["matched"], json!("rm -rf /"));
        assert_eq!(refusal["audit_durability"]["audited"], json!(false));
        assert_eq!(refusal["audit_durability"]["state"], json!("not_committed"));
        assert!(!refusal["audit_durability"]["recovery"]
            .as_str()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_durable_denial_audit_is_reported_durable_and_recorded() {
        let directory = temp();
        let env = admit("env_1", &json!({}));

        let refusal = refuse(&directory, &env, "rm -rf /").expect("must refuse");

        assert_eq!(refusal["audit_durability"]["audited"], json!(true));
        assert_eq!(refusal["audit_durability"]["state"], json!("durable"));
        let audits = read_record_dir(directory.path().to_str().unwrap(), "operability-audit");
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0]["kind"], json!("guardrail_denied"));
        assert_eq!(audits[0]["environment_ref"], json!("env_1"));
    }
}
