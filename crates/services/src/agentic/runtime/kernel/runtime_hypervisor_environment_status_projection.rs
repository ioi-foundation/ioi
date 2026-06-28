//! Hypervisor environment-status projection (pure).
//!
//! Rust port of `runtime-environment-status-projection.mjs`
//! (`buildHypervisorEnvironmentStatus` + `deriveWorkspaceInitializer` +
//! `buildEnvironmentPort`). The Hypervisor cockpit renders the canonical
//! `HypervisorEnvironmentStatus` object (see canon
//! `providers-and-environments.md` → Environment Status Object): a status with
//! per-component sub-phases (`provisioner` → `workspace_content` → `sandbox` →
//! `secrets` → `automations` → `model_mount` → `harness`), a typed
//! `HypervisorWorkspaceInitializer`, and wallet-gated `HypervisorEnvironmentPort`s.
//!
//! This is a PURE projection: the daemon gathers the real transitions (workspace
//! provisioned? model route reachable? harness binary present?) and feeds them in
//! as `componentPhases` / `readinessChecks`; this builder canonicalizes the shape.
//! The truth is Agentgres, the authority is wallet.network, the bytes are
//! encrypted-blob storage — the daemon only projects this object.
//!
//! Input objects use the SAME camelCase keys as the JS builder args so the
//! daemon constructs identical inputs and parity holds byte-for-byte.

use serde_json::{json, Map, Value};

pub const HYPERVISOR_ENVIRONMENT_STATUS_SCHEMA_VERSION: &str =
    "ioi.hypervisor.environment_status.v1";

pub const HYPERVISOR_WORKSPACE_INITIALIZER_SCHEMA_VERSION: &str =
    "ioi.hypervisor.workspace_initializer.v1";

/// Per-component sub-phase taxonomy (distinct from the top-level environment phase).
pub const ENVIRONMENT_COMPONENT_PHASES: &[&str] = &[
    "pending",
    "creating",
    "initializing",
    "ready",
    "degraded",
    "failed",
];

/// The ordered component sub-objects the status carries.
pub const ENVIRONMENT_COMPONENT_KEYS: &[&str] = &[
    "provisioner",
    "workspace_content",
    "sandbox",
    "secrets",
    "automations",
    "model_mount",
    "harness",
];

const TERMINAL_FAILED_PHASE: &str = "failed";

fn coerce_component_phase(value: Option<&Value>, fallback: &str) -> String {
    match optional_string(value) {
        Some(phase) if ENVIRONMENT_COMPONENT_PHASES.contains(&phase.as_str()) => phase,
        _ => fallback.to_string(),
    }
}

/// Derive the aggregate environment phase from the component sub-phases.
fn aggregate_environment_phase(components: &Map<String, Value>) -> &'static str {
    let phases: Vec<String> = ENVIRONMENT_COMPONENT_KEYS
        .iter()
        .map(|key| {
            components
                .get(*key)
                .and_then(|component| component.get("phase"))
                .and_then(Value::as_str)
                .unwrap_or("ready")
                .to_string()
        })
        .collect();
    if phases.iter().any(|phase| phase == TERMINAL_FAILED_PHASE) {
        return "failed";
    }
    if phases.iter().any(|phase| phase == "degraded") {
        return "updating";
    }
    if phases
        .iter()
        .any(|phase| matches!(phase.as_str(), "pending" | "creating" | "initializing"))
    {
        return "starting";
    }
    "running"
}

/// Build a typed `HypervisorWorkspaceInitializer`. `specs` is an ordered list of
/// `{context_url}` or `{git:{remote_uri,clone_target,target_mode}}` entries; an
/// empty specs list means a fresh scratch workspace. Pure: no I/O.
///
/// Input keys (camelCase, mirror JS args): `contextUrl`, `gitSpec` (object with
/// `remote_uri`/`clone_target`/`target_mode`), `workspaceMountPolicy`,
/// `authorityScopeRefs`, `initializerRef`.
pub fn derive_workspace_initializer(input: &Value) -> Value {
    let mut specs: Vec<Value> = Vec::new();
    if let Some(context) = optional_string(input.get("contextUrl")) {
        specs.push(json!({ "context_url": context }));
    }
    if let Some(git) = object_record(input.get("gitSpec")) {
        if let Some(remote_uri) = optional_string(git.get("remote_uri")) {
            specs.push(json!({
                "git": {
                    "remote_uri": remote_uri,
                    "clone_target": optional_string(git.get("clone_target")).unwrap_or_else(|| ".".to_string()),
                    "target_mode": optional_string(git.get("target_mode")).unwrap_or_else(|| "remote_branch".to_string()),
                }
            }));
        }
    }
    let custody_posture = optional_string(input.get("workspaceMountPolicy"))
        .unwrap_or_else(|| "public_trunk".to_string());
    let initializer_ref = optional_string(input.get("initializerRef")).unwrap_or_else(|| {
        format!(
            "workspace-initializer:{}-{}",
            safe_id(&custody_posture),
            specs.len()
        )
    });
    json!({
        "schema_version": HYPERVISOR_WORKSPACE_INITIALIZER_SCHEMA_VERSION,
        "initializer_ref": initializer_ref,
        "specs": specs,
        "custody_posture": custody_posture,
        "authority_scope_refs": unique_strings(input.get("authorityScopeRefs")),
    })
}

/// Build a wallet-gated `HypervisorEnvironmentPort`. `access_policy` is one of
/// private | session_lease | shared; `exposure_state` is closed | lease_required
/// | open. Port exposure is authorized by a wallet capability lease, never an
/// owner token. Pure: no I/O.
pub fn build_environment_port(input: &Value) -> Value {
    json!({
        "port": finite_number(input.get("port")),
        "protocol": optional_string(input.get("protocol")).unwrap_or_else(|| "http".to_string()),
        "access_policy": optional_string(input.get("accessPolicy")).unwrap_or_else(|| "session_lease".to_string()),
        "capability_lease_ref": optional_value(input.get("capabilityLeaseRef")),
        "url": optional_value(input.get("url")),
        "exposure_state": optional_string(input.get("exposureState")).unwrap_or_else(|| "lease_required".to_string()),
    })
}

fn component_evidence(environment_ref: &str, component: &str) -> String {
    format!(
        "agentgres://evidence/environment-status/{}/{}",
        safe_id(environment_ref),
        component
    )
}

/// Map real readiness checks (`harness_binary`, `ollama_provider`,
/// `qwen_model_available`) onto the `model_mount` / `harness` component phases.
fn phases_from_readiness_checks(readiness_checks: Option<&Value>) -> Map<String, Value> {
    let mut result = Map::new();
    let checks_owned = normalize_array(readiness_checks);
    let checks: Vec<&Map<String, Value>> = checks_owned
        .iter()
        .filter_map(|item| item.as_object())
        .collect();
    if checks.is_empty() {
        return result;
    }
    let status_for = |id: &str| -> Option<String> {
        checks
            .iter()
            .find(|entry| entry.get("id").and_then(Value::as_str) == Some(id))
            .and_then(|check| optional_string(check.get("status")))
    };
    let to_phase = |status: Option<String>| -> Option<&'static str> {
        match status.as_deref() {
            Some("pass") => Some("ready"),
            Some("fail") => Some("degraded"),
            None => None,
            Some(_) => Some("initializing"),
        }
    };
    if let Some(harness_phase) = to_phase(status_for("harness_binary")) {
        result.insert("harness".to_string(), json!(harness_phase));
    }
    let provider_phase = to_phase(status_for("qwen_model_available"))
        .or_else(|| to_phase(status_for("ollama_provider")));
    if let Some(provider_phase) = provider_phase {
        result.insert("model_mount".to_string(), json!(provider_phase));
    }
    result
}

/// Project a canonical `HypervisorEnvironmentStatus` from real transitions. The
/// `componentPhases` map (e.g. from the workspace provisioner) and
/// `readinessChecks` (from the substrate probes) drive the real sub-phases;
/// anything not supplied defaults to `ready` so the object is always renderable.
/// Pure: no I/O.
///
/// Input keys (camelCase, mirror JS args): `environmentRef`,
/// `providerPlacementRef`, `workspaceRoot`, `workspaceMountPolicy`,
/// `initializerRef`, `modelRouteRef`, `harnessSessionRef`, `stateRootRef`,
/// `workspaceArtifactRef`, `componentPhases`, `readinessChecks`, `ports`,
/// `capabilityLeaseRefs`, `failureMessage`, `warningMessage`.
pub fn build_hypervisor_environment_status(input: &Value) -> Value {
    let env_ref = optional_string(input.get("environmentRef"))
        .unwrap_or_else(|| "environment:hypervisor-session".to_string());
    let empty = Map::new();
    let overrides = object_record(input.get("componentPhases")).unwrap_or(&empty);
    let readiness_phases = phases_from_readiness_checks(input.get("readinessChecks"));

    let phase_for = |component: &str, fallback: &str| -> String {
        let override_value = overrides
            .get(component)
            .or_else(|| readiness_phases.get(component));
        coerce_component_phase(override_value, fallback)
    };

    let custody_posture = optional_string(input.get("workspaceMountPolicy"))
        .unwrap_or_else(|| "public_trunk".to_string());

    let mut components = Map::new();
    components.insert(
        "provisioner".to_string(),
        json!({
            "phase": phase_for("provisioner", "ready"),
            "evidence_ref": component_evidence(&env_ref, "provisioner"),
        }),
    );
    components.insert(
        "workspace_content".to_string(),
        json!({
            "phase": phase_for("workspace_content", "ready"),
            "initializer_ref": optional_value(input.get("initializerRef")),
            "custody_posture": custody_posture,
            "workspace_root": optional_value(input.get("workspaceRoot")),
            "evidence_ref": component_evidence(&env_ref, "workspace_content"),
        }),
    );
    components.insert(
        "sandbox".to_string(),
        json!({
            "phase": phase_for("sandbox", "ready"),
            "evidence_ref": component_evidence(&env_ref, "sandbox"),
        }),
    );
    components.insert(
        "secrets".to_string(),
        json!({
            "phase": phase_for("secrets", "ready"),
            "capability_lease_refs": unique_strings(input.get("capabilityLeaseRefs")),
            "evidence_ref": component_evidence(&env_ref, "secrets"),
        }),
    );
    components.insert(
        "automations".to_string(),
        json!({
            "phase": phase_for("automations", "ready"),
            "evidence_ref": component_evidence(&env_ref, "automations"),
        }),
    );
    components.insert(
        "model_mount".to_string(),
        json!({
            "phase": phase_for("model_mount", "ready"),
            "model_route_ref": optional_value(input.get("modelRouteRef")),
            "evidence_ref": component_evidence(&env_ref, "model_mount"),
        }),
    );
    components.insert(
        "harness".to_string(),
        json!({
            "phase": phase_for("harness", "ready"),
            "harness_session_ref": optional_value(input.get("harnessSessionRef")),
            "evidence_ref": component_evidence(&env_ref, "harness"),
        }),
    );

    let aggregate = aggregate_environment_phase(&components);

    let ports: Vec<Value> = normalize_array(input.get("ports"))
        .iter()
        .filter(|port| port.is_object())
        .map(|port| {
            build_environment_port(&json!({
                "port": port.get("port").cloned().unwrap_or(Value::Null),
                "protocol": port.get("protocol").cloned().unwrap_or(Value::Null),
                "accessPolicy": port.get("access_policy").cloned().unwrap_or(Value::Null),
                "capabilityLeaseRef": port.get("capability_lease_ref").cloned().unwrap_or(Value::Null),
                "url": port.get("url").cloned().unwrap_or(Value::Null),
                "exposureState": port.get("exposure_state").cloned().unwrap_or(Value::Null),
            }))
        })
        .collect();

    let state_root_ref = optional_string(input.get("stateRootRef")).unwrap_or_else(|| {
        format!(
            "agentgres://state-root/environment-status/{}",
            safe_id(&env_ref)
        )
    });

    json!({
        "schema_version": HYPERVISOR_ENVIRONMENT_STATUS_SCHEMA_VERSION,
        "environment_ref": env_ref,
        "provider_placement_ref": optional_value(input.get("providerPlacementRef")),
        "phase": aggregate,
        "components": Value::Object(components),
        "ports": ports,
        "failure_message": optional_value(input.get("failureMessage")),
        "warning_message": optional_value(input.get("warningMessage")),
        "state_root_ref": state_root_ref,
        "workspace_artifact_ref": optional_value(input.get("workspaceArtifactRef")),
        "runtimeTruthSource": "daemon-runtime",
    })
}

// --- helpers (faithful to runtime-value-helpers.mjs for daemon-constructed inputs) ---

/// Mirror JS `optionalString`: trimmed non-empty string, else None. Inputs are
/// daemon-constructed strings/null; non-string JSON yields None here.
fn optional_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(string)) => {
            let trimmed = string.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        _ => None,
    }
}

/// `optionalString(...) ?? null` — the trimmed string or a JSON null.
fn optional_value(value: Option<&Value>) -> Value {
    optional_string(value)
        .map(Value::String)
        .unwrap_or(Value::Null)
}

/// Mirror JS `normalizeArray`: array filtered of falsy entries, else [].
fn normalize_array(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter(|item| is_truthy(item))
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

/// Mirror JS `objectRecord`: a plain object, else None.
fn object_record(value: Option<&Value>) -> Option<&Map<String, Value>> {
    value.and_then(Value::as_object)
}

/// Mirror JS `uniqueStrings`: `[...new Set(normalizeArray(values).map(String).filter(Boolean))]`.
fn unique_strings(value: Option<&Value>) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for item in normalize_array(value) {
        let coerced = match &item {
            Value::String(string) => string.clone(),
            other => other.to_string(),
        };
        if coerced.is_empty() || seen.contains(&coerced) {
            continue;
        }
        seen.push(coerced);
    }
    seen
}

/// JS truthiness for `Array.filter(Boolean)`: null/false/0/""/empty are dropped.
fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(boolean) => *boolean,
        Value::Number(number) => number.as_f64().map(|n| n != 0.0).unwrap_or(true),
        Value::String(string) => !string.is_empty(),
        _ => true,
    }
}

/// JS `Number.isFinite(port) ? port : null`, preserving the numeric form.
fn finite_number(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Number(number)) if number.as_f64().map(f64::is_finite).unwrap_or(false) => {
            Value::Number(number.clone())
        }
        _ => Value::Null,
    }
}

/// Mirror JS `safeId`: replace each run of `[^a-zA-Z0-9_.-]` with a single `_`.
fn safe_id(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut in_run = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
            out.push(ch);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_status_aggregates_to_running() {
        let status = build_hypervisor_environment_status(&json!({
            "environmentRef": "environment:hypervisor-session",
            "workspaceRoot": "/tmp/ioi-hypervisor-sessions/session-abc",
            "workspaceMountPolicy": "public_trunk",
        }));
        assert_eq!(
            status["schema_version"],
            HYPERVISOR_ENVIRONMENT_STATUS_SCHEMA_VERSION
        );
        assert_eq!(status["phase"], "running");
        assert_eq!(status["runtimeTruthSource"], "daemon-runtime");
        // All 7 components present and ready by default.
        for key in ENVIRONMENT_COMPONENT_KEYS {
            assert_eq!(
                status["components"][key]["phase"], "ready",
                "component {key}"
            );
        }
        assert_eq!(
            status["components"]["workspace_content"]["workspace_root"],
            "/tmp/ioi-hypervisor-sessions/session-abc"
        );
        assert_eq!(
            status["components"]["workspace_content"]["custody_posture"],
            "public_trunk"
        );
        assert_eq!(
            status["components"]["provisioner"]["evidence_ref"],
            "agentgres://evidence/environment-status/environment_hypervisor-session/provisioner"
        );
        assert_eq!(
            status["state_root_ref"],
            "agentgres://state-root/environment-status/environment_hypervisor-session"
        );
    }

    #[test]
    fn initializing_component_aggregates_to_starting() {
        let status = build_hypervisor_environment_status(&json!({
            "componentPhases": { "workspace_content": "initializing" },
        }));
        assert_eq!(status["phase"], "starting");
        assert_eq!(
            status["components"]["workspace_content"]["phase"],
            "initializing"
        );
    }

    #[test]
    fn degraded_component_aggregates_to_updating() {
        // No model / no harness: honest degraded, not a fake "running".
        let status = build_hypervisor_environment_status(&json!({
            "readinessChecks": [
                { "id": "harness_binary", "status": "fail" },
                { "id": "ollama_provider", "status": "fail" },
            ],
        }));
        assert_eq!(status["phase"], "updating");
        assert_eq!(status["components"]["harness"]["phase"], "degraded");
        assert_eq!(status["components"]["model_mount"]["phase"], "degraded");
    }

    #[test]
    fn failed_component_aggregates_to_failed() {
        let status = build_hypervisor_environment_status(&json!({
            "componentPhases": { "provisioner": "failed" },
        }));
        assert_eq!(status["phase"], "failed");
    }

    #[test]
    fn readiness_pass_maps_to_ready_model_mount() {
        let status = build_hypervisor_environment_status(&json!({
            "readinessChecks": [
                { "id": "harness_binary", "status": "pass" },
                { "id": "qwen_model_available", "status": "pass" },
            ],
        }));
        assert_eq!(status["components"]["harness"]["phase"], "ready");
        assert_eq!(status["components"]["model_mount"]["phase"], "ready");
        assert_eq!(status["phase"], "running");
    }

    #[test]
    fn override_takes_precedence_over_readiness() {
        let status = build_hypervisor_environment_status(&json!({
            "componentPhases": { "model_mount": "initializing" },
            "readinessChecks": [ { "id": "ollama_provider", "status": "fail" } ],
        }));
        assert_eq!(status["components"]["model_mount"]["phase"], "initializing");
    }

    #[test]
    fn ports_normalize_through_environment_port_builder() {
        let status = build_hypervisor_environment_status(&json!({
            "ports": [
                { "port": 4321, "protocol": "http", "access_policy": "session_lease", "url": "http://127.0.0.1:4321", "exposure_state": "open" },
                "not-a-port",
            ],
        }));
        assert_eq!(status["ports"].as_array().unwrap().len(), 1);
        assert_eq!(status["ports"][0]["port"], 4321);
        assert_eq!(status["ports"][0]["exposure_state"], "open");
        assert_eq!(status["ports"][0]["capability_lease_ref"], Value::Null);
    }

    #[test]
    fn derive_initializer_empty_specs_is_scratch() {
        let initializer = derive_workspace_initializer(&json!({}));
        assert_eq!(
            initializer["schema_version"],
            HYPERVISOR_WORKSPACE_INITIALIZER_SCHEMA_VERSION
        );
        assert_eq!(initializer["specs"].as_array().unwrap().len(), 0);
        assert_eq!(initializer["custody_posture"], "public_trunk");
        assert_eq!(
            initializer["initializer_ref"],
            "workspace-initializer:public_trunk-0"
        );
    }

    #[test]
    fn derive_initializer_with_git_spec() {
        let initializer = derive_workspace_initializer(&json!({
            "gitSpec": { "remote_uri": "https://github.com/x/y" },
            "workspaceMountPolicy": "redacted_projection",
            "authorityScopeRefs": ["scope:fs.write", "scope:fs.write", "scope:net"],
        }));
        assert_eq!(
            initializer["specs"][0]["git"]["remote_uri"],
            "https://github.com/x/y"
        );
        assert_eq!(initializer["specs"][0]["git"]["clone_target"], ".");
        assert_eq!(
            initializer["specs"][0]["git"]["target_mode"],
            "remote_branch"
        );
        // uniqueStrings dedupes preserving order.
        assert_eq!(
            initializer["authority_scope_refs"],
            json!(["scope:fs.write", "scope:net"])
        );
    }

    #[test]
    fn derive_initializer_context_url_then_git_order() {
        let initializer = derive_workspace_initializer(&json!({
            "contextUrl": "https://example.com/seed.tar",
            "gitSpec": { "remote_uri": "https://github.com/x/y", "clone_target": "repo", "target_mode": "tag" },
        }));
        assert_eq!(
            initializer["specs"][0]["context_url"],
            "https://example.com/seed.tar"
        );
        assert_eq!(initializer["specs"][1]["git"]["clone_target"], "repo");
        assert_eq!(initializer["specs"][1]["git"]["target_mode"], "tag");
    }
}
