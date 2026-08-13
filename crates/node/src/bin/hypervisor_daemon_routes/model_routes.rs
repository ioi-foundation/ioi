//! Model-route REGISTRY — daemon-owned truth for which model routes exist, their availability
//! posture, and their session bindings. The resource substrate the model selector / New Session /
//! Agent Studio consume ("the model selection center" — a registry, not a runtime).
//!
//! Doctrine enforced here:
//! - A route is `available` ONLY when a REAL probe succeeded (Ollama `/api/tags` containing the
//!   model tag, or an OpenAI-compatible `/models` catalog with a resolvable credential). Postures
//!   are explicit and honest: `declared` | `available` | `unreachable` | `credentials_missing` |
//!   `model_not_present`. No code path fabricates `available`.
//! - Effectful mutations (enable/disable/select-default/bind-session) COMPOSE the existing pure
//!   kernel planners (model-route-mutation + model-weight-custody admissions) — never a parallel
//!   validation path; planner rejections propagate as the HTTP error body.
//! - Records persist under `model-route-registry` (the pre-existing `model-routes` dir belongs to
//!   the model-mount family and is NOT touched). Every mutation writes a receipt; effectful ops
//!   also post an agent-run-transcript so they carry a state_root in Run Timeline / Work Ledger.
//! - Session-binding consumption (lifecycle_routes::handle_session_execute) stays byte-identical
//!   to the env-var path when no binding exists; only an `available` + `active` ollama-transport
//!   route may bind (the shim refuses other providers — no dropdown lies in either direction).
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use ioi_services::agentic::runtime::kernel::RuntimeKernelService;

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const ROUTE_SCHEMA: &str = "ioi.hypervisor.model-route.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.model-route-receipt.v1";
const BINDING_SCHEMA: &str = "ioi.hypervisor.model-route-session-binding.v1";
const OVERVIEW_SCHEMA: &str = "ioi.hypervisor.model-routes-overview.v1";
pub(crate) const RECORD_DIR: &str = "model-route-registry";
const RECEIPT_DIR: &str = "model-route-registry-receipts";
const BINDING_DIR: &str = "model-route-session-bindings";
/// The sealed credential vault the CapabilityLease gateway resolves a model route's provider key
/// from. A SEPARATE store from `connector-credentials` on purpose: the two families are revoked by
/// different surfaces and audited under different backing providers, and one shared bag would let a
/// connector's credential answer a model route's lease.
pub(crate) const CREDENTIAL_DIR: &str = "model-route-credentials";
const SEED_ROUTE_ID: &str = "mrt_local_default";
const PROBE_TIMEOUT_MS: u64 = 1500;
/// A persisted probe older than this is surfaced with `stale: true` in list projections.
const PROBE_FRESH_SECS: u64 = 120;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundSessionModelRoute {
    pub(crate) model_id: String,
    /// Normalized provider root retained by the registry (never sourced from process env here).
    pub(crate) base_url: String,
    /// Exact OpenAI-compatible endpoint consumed by the adapter driver.
    pub(crate) execution_endpoint: String,
    pub(crate) route_ref: String,
    pub(crate) binding_id: String,
    pub(crate) receipt_ref: String,
}

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn s(v: &Value, k: &str, d: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or(d).to_string()
}
fn opt_s(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
}

/// Strip a trailing `/v1` (the OpenAI-compat suffix) so the registry stores the provider ROOT;
/// probes derive `/api/tags` or `/models` and the execute hook re-appends `/v1` for the shim.
fn normalize_base_url(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches('/');
    trimmed
        .strip_suffix("/v1")
        .unwrap_or(trimmed)
        .trim_end_matches('/')
        .to_string()
}

pub(crate) fn load_route_record(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, RECORD_DIR)
        .into_iter()
        .find(|r| r.get("route_id").and_then(|v| v.as_str()) == Some(id))
}

fn canonical_value_hash(value: &Value) -> Result<String, String> {
    let bytes = serde_jcs::to_vec(value)
        .map_err(|error| format!("record is not canonical JSON ({error})"))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn deterministic_binding_digest(session_ref: &str) -> String {
    format!("{:x}", Sha256::digest(session_ref.as_bytes()))
}

/// Complete no-follow route census for authority-bearing M4 reads. Compatibility endpoints keep
/// their historical permissive projection; activation, Session binding, and invocation do not.
fn strict_route_census(data_dir: &str) -> Result<Vec<Value>, String> {
    const MAX_ROUTES: usize = 4_096;
    const MAX_ROUTE_BYTES: usize = 1_048_576;
    const MAX_TOTAL_BYTES: usize = 32 * 1_048_576;

    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, RECORD_DIR) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("model-route registry cannot be pinned ({error})")),
    };
    let mut names = super::durable_fs::enumerate_pinned(&directory)
        .map_err(|error| format!("model-route registry cannot be enumerated ({error})"))?;
    names.sort();
    if names.len() > MAX_ROUTES {
        return Err(format!(
            "model-route registry exceeds its bounded census ({}/{MAX_ROUTES})",
            names.len()
        ));
    }

    let mut total_bytes = 0usize;
    let mut route_ids = std::collections::HashSet::new();
    let mut route_refs = std::collections::HashSet::new();
    let mut defaults = 0usize;
    let mut routes = Vec::with_capacity(names.len());
    for name in names {
        let Some(route_id) = name.strip_suffix(".json") else {
            return Err(format!(
                "model-route registry contains unexpected occupant '{name}'"
            ));
        };
        if route_id.is_empty()
            || !route_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err(format!(
                "model-route registry slot '{name}' has a non-canonical key"
            ));
        }
        let Some((_file, bytes)) = super::durable_fs::read_slot_strict(&directory, &name)
            .map_err(|error| format!("model-route slot '{name}' is unreadable ({error})"))?
        else {
            return Err(format!(
                "model-route slot '{name}' disappeared during its strict census"
            ));
        };
        if bytes.len() > MAX_ROUTE_BYTES {
            return Err(format!(
                "model-route slot '{name}' exceeds the {MAX_ROUTE_BYTES}-byte bound"
            ));
        }
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| "model-route registry byte census overflowed".to_string())?;
        if total_bytes > MAX_TOTAL_BYTES {
            return Err(format!(
                "model-route registry exceeds the {MAX_TOTAL_BYTES}-byte aggregate bound"
            ));
        }
        let route: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("model-route slot '{name}' is malformed ({error})"))?;
        let expected_ref = format!("model-route:{route_id}");
        if route.get("schema_version").and_then(Value::as_str) != Some(ROUTE_SCHEMA)
            || route.get("route_id").and_then(Value::as_str) != Some(route_id)
            || route.get("route_ref").and_then(Value::as_str) != Some(expected_ref.as_str())
            || !route
                .pointer("/model/model_id")
                .and_then(Value::as_str)
                .is_some_and(|model| !model.trim().is_empty())
            || !route
                .pointer("/provider_binding/base_url")
                .and_then(Value::as_str)
                .is_some_and(|base| !base.trim().is_empty())
            || !route
                .pointer("/provider_binding/transport")
                .and_then(Value::as_str)
                .is_some_and(|transport| !transport.trim().is_empty())
        {
            return Err(format!(
                "model-route slot '{name}' fails schema/key/ref/execution-fact binding"
            ));
        }
        let route_ref = route
            .get("route_ref")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if !route_ids.insert(route_id.to_string()) || !route_refs.insert(route_ref) {
            return Err(format!(
                "model-route identity '{route_id}' resolves more than once"
            ));
        }
        if route.get("default_route").and_then(Value::as_bool) == Some(true) {
            defaults += 1;
            if defaults > 1 {
                return Err("model-route registry contains more than one default route".to_string());
            }
        }
        routes.push(route);
    }
    Ok(routes)
}

/// Prove existing bytes before seed reconciliation, then prove the post-seed census. A registry
/// with an alternate default but no canonical seed is ambiguous and is left untouched.
pub(crate) fn strict_routes_seeded(data_dir: &str) -> Result<Vec<Value>, String> {
    let before = strict_route_census(data_dir)?;
    if !before.is_empty()
        && !before
            .iter()
            .any(|route| route.get("route_id").and_then(Value::as_str) == Some(SEED_ROUTE_ID))
        && before
            .iter()
            .any(|route| route.get("default_route").and_then(Value::as_bool) == Some(true))
    {
        return Err(
            "model-route seed is absent while another default occupies the registry; automatic seed reconciliation is refused"
                .to_string(),
        );
    }
    ensure_seed(data_dir);
    let routes = strict_route_census(data_dir)?;
    if routes
        .iter()
        .filter(|route| route.get("default_route").and_then(Value::as_bool) == Some(true))
        .count()
        != 1
    {
        return Err("model-route registry must resolve exactly one default route".to_string());
    }
    Ok(routes)
}

fn unique_route<'a>(routes: &'a [Value], explicit_ref: Option<&str>) -> Result<&'a Value, String> {
    let mut matches = routes.iter().filter(|route| match explicit_ref {
        Some(reference) => route.get("route_ref").and_then(Value::as_str) == Some(reference),
        None => route.get("default_route").and_then(Value::as_bool) == Some(true),
    });
    let route = matches.next().ok_or_else(|| match explicit_ref {
        Some(reference) => format!("model route '{reference}' does not resolve"),
        None => "default model route does not resolve".to_string(),
    })?;
    if matches.next().is_some() {
        return Err(match explicit_ref {
            Some(reference) => format!("model route '{reference}' resolves more than once"),
            None => "default model route resolves more than once".to_string(),
        });
    }
    Ok(route)
}

fn route_fact_tuple(route: &Value) -> (String, String, String, String) {
    (
        s(route, "route_ref", ""),
        route
            .pointer("/availability/state")
            .and_then(Value::as_str)
            .unwrap_or("declared")
            .to_string(),
        route
            .pointer("/model/model_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        normalize_base_url(
            route
                .pointer("/provider_binding/base_url")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
    )
}

/// Resolve one retained route without seed reconciliation. This is the pre-effect half of an
/// admission preflight; callers may invoke the mutating seeded resolver only after every
/// refusal that can be adjudicated from retained bytes has passed.
pub(crate) fn existing_route_fact_strict(
    data_dir: &str,
    explicit_ref: Option<&str>,
) -> Result<(String, String, String, String), String> {
    let routes = strict_route_census(data_dir)?;
    if routes
        .iter()
        .filter(|route| route.get("default_route").and_then(Value::as_bool) == Some(true))
        .count()
        != 1
    {
        return Err("model-route registry must resolve exactly one retained default route".into());
    }
    unique_route(&routes, explicit_ref).map(route_fact_tuple)
}

/// Strict route fact used by the M4 GoalRun planner. No empty/unresolved tuple is fabricated.
pub(crate) fn route_fact_strict(
    data_dir: &str,
    explicit_ref: Option<&str>,
) -> Result<(String, String, String, String), String> {
    let routes = strict_routes_seeded(data_dir)?;
    unique_route(&routes, explicit_ref).map(route_fact_tuple)
}

fn strict_binding_census(data_dir: &str) -> Result<Vec<Value>, String> {
    const MAX_BINDINGS: usize = 16_384;
    const MAX_BINDING_BYTES: usize = 1_048_576;
    const MAX_TOTAL_BYTES: usize = 64 * 1_048_576;

    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, BINDING_DIR) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(format!(
                "model-route Session-binding registry cannot be pinned ({error})"
            ))
        }
    };
    let mut names = super::durable_fs::enumerate_pinned(&directory).map_err(|error| {
        format!("model-route Session-binding registry cannot be enumerated ({error})")
    })?;
    names.sort();
    if names.len() > MAX_BINDINGS {
        return Err(format!(
            "model-route Session-binding registry exceeds its bounded census ({}/{MAX_BINDINGS})",
            names.len()
        ));
    }
    let mut total_bytes = 0usize;
    let mut identities = std::collections::HashSet::new();
    let mut bindings = Vec::with_capacity(names.len());
    for name in names {
        let Some(binding_id) = name.strip_suffix(".json") else {
            return Err(format!(
                "model-route Session-binding registry contains unexpected occupant '{name}'"
            ));
        };
        if binding_id.is_empty()
            || !binding_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err(format!(
                "model-route Session-binding slot '{name}' has a non-canonical key"
            ));
        }
        let Some((_file, bytes)) =
            super::durable_fs::read_slot_strict(&directory, &name).map_err(|error| {
                format!("model-route Session-binding slot '{name}' is unreadable ({error})")
            })?
        else {
            return Err(format!(
                "model-route Session-binding slot '{name}' disappeared during its strict census"
            ));
        };
        if bytes.len() > MAX_BINDING_BYTES {
            return Err(format!(
                "model-route Session-binding slot '{name}' exceeds the {MAX_BINDING_BYTES}-byte bound"
            ));
        }
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| "model-route Session-binding byte census overflowed".to_string())?;
        if total_bytes > MAX_TOTAL_BYTES {
            return Err(format!(
                "model-route Session-binding registry exceeds the {MAX_TOTAL_BYTES}-byte aggregate bound"
            ));
        }
        let binding: Value = serde_json::from_slice(&bytes).map_err(|error| {
            format!("model-route Session-binding slot '{name}' is malformed ({error})")
        })?;
        if binding.get("schema_version").and_then(Value::as_str) != Some(BINDING_SCHEMA)
            || binding.get("binding_id").and_then(Value::as_str) != Some(binding_id)
            || !binding
                .get("session_ref")
                .and_then(Value::as_str)
                .is_some_and(|reference| {
                    reference.starts_with("session:") && reference.len() <= 512
                })
            || !binding
                .get("route_ref")
                .and_then(Value::as_str)
                .is_some_and(|reference| reference.starts_with("model-route:"))
            || !binding
                .get("route_id")
                .and_then(Value::as_str)
                .is_some_and(|identity| !identity.is_empty())
            || !binding
                .get("model_id")
                .and_then(Value::as_str)
                .is_some_and(|model| !model.is_empty())
            || !binding
                .get("base_url")
                .and_then(Value::as_str)
                .is_some_and(|base| !base.is_empty())
            || !binding
                .get("transport")
                .and_then(Value::as_str)
                .is_some_and(|transport| !transport.is_empty())
        {
            return Err(format!(
                "model-route Session-binding slot '{name}' fails schema/key/execution-fact binding"
            ));
        }
        if let Some(root) = binding.get("binding_root").and_then(Value::as_str) {
            let mut material = binding.clone();
            material
                .as_object_mut()
                .map(|object| object.remove("binding_root"));
            if canonical_value_hash(&material).as_deref() != Ok(root) {
                return Err(format!(
                    "model-route Session-binding slot '{name}' fails its canonical root"
                ));
            }
        }
        if !identities.insert(binding_id.to_string()) {
            return Err(format!(
                "model-route Session-binding identity '{binding_id}' resolves more than once"
            ));
        }
        bindings.push(binding);
    }
    Ok(bindings)
}

fn binding_receipt_id(binding_id: &str) -> String {
    format!(
        "mrrb_{}",
        binding_id.strip_prefix("mrb_").unwrap_or(binding_id)
    )
}

fn validate_exact_binding_receipt(data_dir: &str, binding: &Value) -> Result<(), String> {
    let binding_id = binding
        .get("binding_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let receipt_id = binding_receipt_id(binding_id);
    let receipt = super::durable_fs::read_record_durable(data_dir, RECEIPT_DIR, &receipt_id)?
        .ok_or_else(|| {
            format!("model-route Session binding '{binding_id}' has no durable receipt")
        })?;
    if receipt.get("schema_version").and_then(Value::as_str) != Some(RECEIPT_SCHEMA)
        || receipt.get("receipt_id").and_then(Value::as_str) != Some(receipt_id.as_str())
        || receipt.get("receipt_ref") != binding.get("receipt_ref")
        || receipt.get("binding_id") != binding.get("binding_id")
        || receipt.get("session_ref") != binding.get("session_ref")
        || receipt.get("route_ref") != binding.get("route_ref")
        || receipt.get("model_id") != binding.get("model_id")
        || receipt.get("base_url") != binding.get("base_url")
        || receipt.get("execution_endpoint") != binding.get("execution_endpoint")
    {
        return Err(format!(
            "model-route Session binding '{binding_id}' receipt fails exact fact binding"
        ));
    }
    Ok(())
}

/// Resolve one exact M4 execution binding. Every registry occupant is read strictly; missing,
/// malformed, or duplicate target bindings refuse before adapter resolution or host spawn.
pub(crate) fn resolve_session_route_binding_strict(
    data_dir: &str,
    session_ref: &str,
    expected_route_ref: Option<&str>,
    expected_binding_id: Option<&str>,
) -> Result<BoundSessionModelRoute, String> {
    let normalized_session = if session_ref.starts_with("session:") {
        session_ref.to_string()
    } else {
        format!("session:{session_ref}")
    };
    let mut matches = strict_binding_census(data_dir)?
        .into_iter()
        .filter(|binding| {
            binding.get("session_ref").and_then(Value::as_str) == Some(normalized_session.as_str())
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!(
            "Session '{normalized_session}' resolves {} model-route bindings; exactly one is required",
            matches.len()
        ));
    }
    let binding = matches.remove(0);
    if expected_route_ref.is_some_and(|reference| {
        binding.get("route_ref").and_then(Value::as_str) != Some(reference)
    }) || expected_binding_id
        .is_some_and(|identity| binding.get("binding_id").and_then(Value::as_str) != Some(identity))
    {
        return Err(format!(
            "Session '{normalized_session}' model-route binding does not match its retained coordinates"
        ));
    }
    if binding
        .pointer("/availability_at_bind/state")
        .and_then(Value::as_str)
        != Some("available")
    {
        return Err(format!(
            "Session '{normalized_session}' model-route binding lacks available at-bind proof"
        ));
    }

    let routes = strict_route_census(data_dir)?;
    let route_ref = binding
        .get("route_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let route = unique_route(&routes, Some(route_ref))?;
    let route_id = route
        .get("route_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let model_id = route
        .pointer("/model/model_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let base_url = normalize_base_url(
        route
            .pointer("/provider_binding/base_url")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let transport = route
        .pointer("/provider_binding/transport")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let execution_endpoint = format!("{base_url}/v1");
    if route.pointer("/lifecycle/status").and_then(Value::as_str) != Some("active")
        || route.pointer("/availability/state").and_then(Value::as_str) != Some("available")
        || transport != "ollama"
        || binding.get("route_id").and_then(Value::as_str) != Some(route_id)
        || binding.get("model_id").and_then(Value::as_str) != Some(model_id.as_str())
        || binding.get("base_url").and_then(Value::as_str) != Some(base_url.as_str())
        || binding.get("execution_endpoint").and_then(Value::as_str)
            != Some(execution_endpoint.as_str())
        || binding.get("transport").and_then(Value::as_str) != Some(transport)
    {
        return Err(format!(
            "Session '{normalized_session}' model-route binding no longer matches one active, available executable route"
        ));
    }
    validate_exact_binding_receipt(data_dir, &binding)?;
    Ok(BoundSessionModelRoute {
        model_id,
        base_url,
        execution_endpoint,
        route_ref: route_ref.to_string(),
        binding_id: binding
            .get("binding_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        receipt_ref: binding
            .get("receipt_ref")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

/// Preflight or durably materialize a deterministic, recoverable model-route binding for a
/// Session. The binding and its receipt are written from a reserved Session-create transaction;
/// retry resolves the same full-digest slot and never mints a second binding.
pub(crate) fn bind_route_for_session_recoverable(
    data_dir: &str,
    session_ref: &str,
    route_ref: &str,
    harness_binding_ref: Option<&str>,
    created_at: &str,
    commit: bool,
) -> Result<Value, String> {
    if !session_ref.starts_with("session:") || session_ref.len() > 512 || route_ref.is_empty() {
        return Err("model-route Session binding requires canonical session and route refs".into());
    }
    let routes = strict_routes_seeded(data_dir)?;
    let route = unique_route(&routes, Some(route_ref))?;
    let route_id = route
        .get("route_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let model_id = route
        .pointer("/model/model_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let base_url = normalize_base_url(
        route
            .pointer("/provider_binding/base_url")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let transport = route
        .pointer("/provider_binding/transport")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if route.pointer("/lifecycle/status").and_then(Value::as_str) != Some("active")
        || route.pointer("/availability/state").and_then(Value::as_str) != Some("available")
        || transport != "ollama"
    {
        return Err(
            "model-route Session binding requires one active, probe-available ollama route".into(),
        );
    }
    let admission =
        compose_mutation_admission(route, "bind_session_route", Some(session_ref), None).map_err(
            |(_, body)| {
                format!(
                    "model-route Session binding admission refused ({})",
                    body.pointer("/error/code")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                )
            },
        )?;

    let existing = strict_binding_census(data_dir)?
        .into_iter()
        .filter(|binding| binding.get("session_ref").and_then(Value::as_str) == Some(session_ref))
        .collect::<Vec<_>>();
    if existing.len() > 1 {
        return Err(format!(
            "Session '{session_ref}' resolves multiple model-route bindings"
        ));
    }
    if let Some(binding) = existing.into_iter().next() {
        let resolved = resolve_session_route_binding_strict(
            data_dir,
            session_ref,
            Some(route_ref),
            binding.get("binding_id").and_then(Value::as_str),
        )?;
        if binding.get("harness_binding_ref").and_then(Value::as_str) != harness_binding_ref
            || resolved.route_ref != route_ref
        {
            return Err(format!(
                "Session '{session_ref}' existing model-route binding conflicts with the reserved create inputs"
            ));
        }
        return Ok(binding);
    }
    if !commit {
        return Ok(Value::Null);
    }

    let digest = deterministic_binding_digest(session_ref);
    let binding_id = format!("mrb_{digest}");
    let receipt_id = binding_receipt_id(&binding_id);
    let receipt_ref = format!("agentgres://model-route-receipt/{receipt_id}");
    let execution_endpoint = format!("{base_url}/v1");
    let mut binding = json!({
        "schema_version": BINDING_SCHEMA,
        "binding_id": binding_id,
        "route_ref": route_ref,
        "route_id": route_id,
        "session_ref": session_ref,
        "harness_binding_ref": harness_binding_ref,
        "admission_id": admission.get("admission_id"),
        "mutation_receipt_ref": admission.get("mutation_receipt_ref"),
        "receipt_ref": receipt_ref,
        "availability_at_bind": route.get("availability").cloned().unwrap_or(Value::Null),
        "model_id": model_id,
        "base_url": base_url,
        "execution_endpoint": execution_endpoint,
        "transport": transport,
        "route_record_hash_at_bind": canonical_value_hash(route)?,
        "created_at": created_at,
        "runtimeTruthSource": "daemon-runtime"
    });
    let binding_root = canonical_value_hash(&binding)?;
    binding["binding_root"] = json!(binding_root);
    let receipt = json!({
        "schema_version": RECEIPT_SCHEMA,
        "receipt_id": receipt_id,
        "receipt_ref": receipt_ref,
        "op": "bind_session_route",
        "outcome": "ok",
        "binding_id": binding.get("binding_id"),
        "session_ref": session_ref,
        "route_ref": route_ref,
        "model_id": model_id,
        "base_url": base_url,
        "execution_endpoint": execution_endpoint,
        "harness_binding_ref": harness_binding_ref,
        "admission_id": admission.get("admission_id"),
        "at": created_at,
        "runtimeTruthSource": "daemon-runtime"
    });
    super::durable_fs::persist_record_durable(data_dir, RECEIPT_DIR, &receipt_id, &receipt)
        .map_err(|failure| {
            format!(
                "model-route Session-binding receipt did not durably commit ({})",
                failure.detail()
            )
        })?;
    super::durable_fs::persist_record_durable(data_dir, BINDING_DIR, &binding_id, &binding)
        .map_err(|failure| {
            format!(
                "model-route Session binding did not durably commit ({})",
                failure.detail()
            )
        })?;
    let resolved = resolve_session_route_binding_strict(
        data_dir,
        session_ref,
        Some(route_ref),
        Some(&binding_id),
    )?;
    if resolved.model_id != model_id || resolved.execution_endpoint != execution_endpoint {
        return Err("model-route Session binding post-write facts changed".into());
    }
    Ok(binding)
}

fn route_receipt(
    data_dir: &str,
    route_ref: &str,
    op: &str,
    outcome: &str,
    admission_id: Option<&str>,
) -> std::io::Result<String> {
    let id = format!("mrr_{:x}", nanos());
    let receipt_ref = format!("agentgres://model-route-receipt/{id}");
    // The receipt_ref is embedded on the mutated route record and read back by GET :id; a
    // discarded write hands the record a receipt no reader can find. Effectful callers map this
    // to a typed 500; the bootstrap-seed caller keeps it best-effort (CLASSIFIED there).
    persist_record(
        data_dir,
        RECEIPT_DIR,
        &id,
        &json!({
            "schema_version": RECEIPT_SCHEMA, "receipt_id": id, "receipt_ref": receipt_ref,
            "route_ref": route_ref, "op": op, "outcome": outcome,
            "admission_id": admission_id, "at": iso_now()
        }),
    )?;
    Ok(receipt_ref)
}

/// Post an agent-run-transcript for an effectful registry op so the transcript plane computes a
/// tamper-evident state_root and the op surfaces in Run Timeline / Work Ledger. Best-effort; the
/// outcome (`transcript_recorded`) is reported honestly on the response.
async fn post_op_transcript(
    base: &str,
    op: &str,
    route_ref: &str,
    detail: &Value,
) -> Option<String> {
    let run_id = format!("mro_{:x}", nanos());
    let at = iso_now();
    let transcript = json!({
        "schema_version": "ioi.hypervisor.agent-run-transcript.v1",
        "run_id": run_id,
        "kind": "model-route-op",
        "op": op,
        "route_ref": route_ref,
        "status": "done",
        "step_results": [ { "step": 0, "kind": op, "status": "done", "output": detail } ],
        "started_at": at,
        "finished_at": at,
    });
    let url = format!("{base}/v1/hypervisor/agent-run-transcripts/{run_id}");
    let ok = reqwest::Client::new()
        .post(&url)
        .json(&transcript)
        .timeout(Duration::from_millis(3000))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    ok.then_some(run_id)
}

// ---------------------------------------------------------------------------
// live model-mount catalog (ref validation against REAL substrate — no duplicate catalogs)
// ---------------------------------------------------------------------------

async fn get_json(base: &str, path: &str) -> Value {
    let url = format!("{base}{path}");
    match reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_millis(3000))
        .send()
        .await
    {
        Ok(r) => match r.text().await {
            Ok(t) => serde_json::from_str(&t).unwrap_or(Value::Null),
            Err(_) => Value::Null,
        },
        Err(_) => Value::Null,
    }
}

fn as_list(v: &Value) -> Vec<Value> {
    if let Some(a) = v.as_array() {
        return a.clone();
    }
    if let Some(obj) = v.as_object() {
        for val in obj.values() {
            if let Some(a) = val.as_array() {
                return a.clone();
            }
        }
    }
    Vec::new()
}

fn collect_ids(list: &[Value], keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for item in list {
        for k in keys {
            if let Some(v) = item.get(*k).and_then(|v| v.as_str()) {
                if !v.is_empty() && !out.iter().any(|x| x == v) {
                    out.push(v.to_string());
                }
            }
        }
    }
    out
}

/// Validate optional provider_ref / endpoint_ref against the LIVE model-mount substrate.
/// Fail-closed with a named code when a declared ref does not resolve.
async fn validate_substrate_refs(
    base: &str,
    provider_ref: Option<&str>,
    endpoint_ref: Option<&str>,
) -> Result<(), (String, String)> {
    if provider_ref.is_none() && endpoint_ref.is_none() {
        return Ok(());
    }
    let providers = collect_ids(
        &as_list(&get_json(base, "/v1/model-mount/providers").await),
        &["id", "provider_ref"],
    );
    let endpoints = collect_ids(
        &as_list(&get_json(base, "/v1/model-mount/endpoints").await),
        &["endpoint_id", "id"],
    );
    if let Some(p) = provider_ref {
        let bare = p.strip_prefix("provider:").unwrap_or(p);
        if !providers.iter().any(|x| x == p || x == bare) {
            return Err((
                "model_route_ref_unresolved".into(),
                format!("provider ref '{p}' does not resolve to real model-mount substrate"),
            ));
        }
    }
    if let Some(e) = endpoint_ref {
        let bare = e.strip_prefix("model-endpoint:").unwrap_or(e);
        if !endpoints.iter().any(|x| x == e || x == bare) {
            return Err((
                "model_route_ref_unresolved".into(),
                format!("endpoint ref '{e}' does not resolve to real model-mount substrate"),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// honest availability probe
// ---------------------------------------------------------------------------

/// A tag `qwen2.5-coder` and its `:latest` resolution are the SAME model to Ollama (native +
/// OpenAI-compat APIs both resolve the untagged name to `:latest`), while `/api/tags` only ever
/// returns fully-qualified names. Match on either form so an untagged declared model_id (including
/// the code-default seed `qwen2.5-coder`) is not falsely reported absent.
fn tag_matches(model_id: &str, tag: &str) -> bool {
    tag == model_id
        || tag == format!("{model_id}:latest")
        || (!model_id.contains(':') && tag.strip_suffix(":latest") == Some(model_id))
}

/// Decide availability from a fetched Ollama tag catalog. Pure — unit tested.
fn ollama_availability(model_id: &str, tags: &[String]) -> (&'static str, Value) {
    if tags.iter().any(|t| tag_matches(model_id, t)) {
        (
            "available",
            json!({ "matched_model": model_id, "catalog_count": tags.len() }),
        )
    } else {
        (
            "model_not_present",
            json!({ "requested_model": model_id, "catalog_count": tags.len() }),
        )
    }
}

/// Run the REAL availability probe for one route record. Never fabricates: connect failures and
/// non-2xx responses are `unreachable`, an unresolvable credential is `credentials_missing`
/// (no network call), a live catalog without the tag is `model_not_present`.
///
/// SECURITY: the probe NEVER resolves a daemon environment secret and sends it to the route's
/// caller-supplied `base_url` — that would turn the registry into a secret-exfiltration primitive
/// (any local caller could name IOI_WALLET_SECRET_PASS as env_key_name and point base_url at a
/// listener). `openai_compatible` routes therefore stay POSTURE-ONLY: `credentials_missing` when
/// the declared env key is absent, `credentials_present` when it resolves — never `available`, and
/// never an authenticated outbound request. Real authenticated catalog probing waits for a future
/// branch that binds the endpoint to admitted/trusted substrate (see overview governance_gaps).
async fn probe_route(route: &Value) -> Value {
    let transport = route
        .pointer("/provider_binding/transport")
        .and_then(|v| v.as_str())
        .unwrap_or("ollama");
    let base_url = route
        .pointer("/provider_binding/base_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim_end_matches('/')
        .to_string();
    let model_id = route
        .pointer("/model/model_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let checked_at = iso_now();
    let client = reqwest::Client::new();

    let (state, kind, evidence) = match transport {
        "ollama" => {
            let url = format!("{base_url}/api/tags");
            match client
                .get(&url)
                .timeout(Duration::from_millis(PROBE_TIMEOUT_MS))
                .send()
                .await
            {
                Ok(resp) if !resp.status().is_success() => (
                    "unreachable",
                    "ollama_tags",
                    json!({ "error": format!("upstream returned HTTP {}", resp.status().as_u16()) }),
                ),
                Ok(resp) => match resp.json::<Value>().await {
                    Ok(body) => {
                        let tags: Vec<String> = body
                            .get("models")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|m| {
                                        m.get("name")
                                            .or_else(|| m.get("model"))
                                            .and_then(|v| v.as_str())
                                            .map(str::to_string)
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        let (state, evidence) = ollama_availability(&model_id, &tags);
                        (state, "ollama_tags", evidence)
                    }
                    Err(e) => (
                        "unreachable",
                        "ollama_tags",
                        json!({ "error": format!("tag catalog unparsable: {e}") }),
                    ),
                },
                Err(e) => (
                    "unreachable",
                    "ollama_tags",
                    json!({ "error": e.to_string() }),
                ),
            }
        }
        "openai_compatible" => {
            // POSTURE-ONLY — never send a secret to the caller-supplied base_url (see fn doc).
            let env_key = route
                .pointer("/credential_binding/env_key_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let needs_key = route
                .get("credential_posture")
                .and_then(|v| v.as_str())
                .map(|p| p != "no_credentials_required")
                .unwrap_or(true);
            let key_present = !env_key.is_empty()
                && std::env::var(env_key)
                    .ok()
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false);
            if needs_key && !key_present {
                (
                    "credentials_missing",
                    "openai_compatible_posture",
                    json!({ "env_key_name": env_key, "note": "declared credential env key absent; no network call made" }),
                )
            } else {
                (
                    "credentials_present",
                    "openai_compatible_posture",
                    json!({ "env_key_name": env_key, "note": "credential env key resolves; authenticated catalog probing is deferred (the daemon never sends a secret to a caller-supplied URL) — not bindable for execution" }),
                )
            }
        }
        other => (
            "declared",
            "none",
            json!({ "note": format!("no probe implemented for transport '{other}'; posture stays declared") }),
        ),
    };
    json!({
        "state": state,
        "probe": { "kind": kind, "checked_at": checked_at, "evidence": evidence }
    })
}

fn probe_is_stale(availability: &Value) -> bool {
    let Some(checked_at) = availability
        .pointer("/probe/checked_at")
        .and_then(|v| v.as_str())
    else {
        return true;
    };
    // iso_now() is RFC3339; a lexicographic comparison against (now - fresh window) is exact.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cutoff = now_secs.saturating_sub(PROBE_FRESH_SECS);
    let cutoff_iso = chrono_free_iso(cutoff);
    checked_at < cutoff_iso.as_str()
}

/// Format unix seconds as a UTC RFC3339 stamp without pulling in chrono (comparison-only use).
fn chrono_free_iso(unix_secs: u64) -> String {
    // Days-from-civil inverse (Howard Hinnant's algorithm) — exact for the comparison window.
    let days = unix_secs / 86_400;
    let secs = unix_secs % 86_400;
    let (h, m, sec) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{sec:02}")
}

// ---------------------------------------------------------------------------
// admission composition (pure kernel planners — never re-implemented)
// ---------------------------------------------------------------------------

/// Compose a model-weight custody admission for a route from its declared custody fields.
fn compose_custody_admission(route: &Value) -> Result<Value, (u16, Value)> {
    let route_ref = s(route, "route_ref", "");
    let model_id = route
        .pointer("/model/model_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let transport = route
        .pointer("/provider_binding/transport")
        .and_then(|v| v.as_str())
        .unwrap_or("ollama");
    let weight_class = route
        .pointer("/custody/weight_class")
        .and_then(|v| v.as_str())
        .unwrap_or(if transport == "ollama" {
            "public_open_weight"
        } else {
            "remote_api_private_weight"
        });
    let (mount_target, posture, controls, scopes): (&str, &str, Vec<&str>, Vec<&str>) =
        if transport == "ollama" {
            (
                "local_device",
                "private_native",
                vec![],
                vec!["scope:model.route.mutate"],
            )
        } else {
            (
                "provider_api",
                "remote_api_provider_trust",
                vec!["wallet_authorized_api_capability"],
                vec!["scope:model.route.mutate", "scope:model.invoke_remote"],
            )
        };
    let request = json!({
        "route_ref": route_ref,
        "model_ref": format!("model:{model_id}"),
        "provider_ref": route.pointer("/provider_binding/provider_ref").cloned()
            .filter(|v| !v.is_null())
            .unwrap_or_else(|| json!(format!("provider:{transport}"))),
        "weight_class": route.pointer("/custody/weight_class").and_then(|v| v.as_str()).unwrap_or(weight_class),
        "mount_target": route.pointer("/custody/mount_target").and_then(|v| v.as_str()).unwrap_or(mount_target),
        "execution_privacy_posture": route.pointer("/custody/execution_privacy_posture").and_then(|v| v.as_str()).unwrap_or(posture),
        "authority_scope_refs": scopes,
        "required_controls": controls,
        "agentgres_operation_refs": [format!("agentgres://operation/model-route/{}/custody", s(route, "route_id", ""))],
    });
    RuntimeKernelService::new()
        .admit_model_weight_custody(&request, &iso_now())
        .map_err(|e| {
            (
                e.status,
                json!({ "error": { "code": e.code, "message": e.message, "details": e.details } }),
            )
        })
}

/// Compose a model-route-mutation admission for one mutation kind against the route's own refs.
fn compose_mutation_admission(
    route: &Value,
    mutation_kind: &str,
    session_ref: Option<&str>,
    custody_admission_id: Option<&str>,
) -> Result<Value, (u16, Value)> {
    let route_id = s(route, "route_id", "");
    let route_ref = s(route, "route_ref", "");
    let transport = route
        .pointer("/provider_binding/transport")
        .and_then(|v| v.as_str())
        .unwrap_or("ollama");
    let provider_kind = route
        .pointer("/provider_binding/provider_kind")
        .and_then(|v| v.as_str())
        .unwrap_or("local");
    let credential_posture = route
        .get("credential_posture")
        .and_then(|v| v.as_str())
        .unwrap_or("no_credentials_required");
    let provider_ref = route
        .pointer("/provider_binding/provider_ref")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("provider:{transport}"));
    let endpoint_ref = route
        .pointer("/provider_binding/endpoint_ref")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("model-endpoint:{route_id}"));
    let custody_ref = custody_admission_id
        .map(str::to_string)
        .or_else(|| {
            route
                .pointer("/custody/custody_admission_ref")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    let mut request = json!({
        "mutation_kind": mutation_kind,
        "route_ref": route_ref,
        "project_ref": opt_s(route, "project_ref").unwrap_or_else(|| "project:hypervisor".into()),
        "provider_ref": provider_ref,
        "provider_kind": provider_kind,
        "endpoint_refs": [endpoint_ref],
        "credential_posture": credential_posture,
        "authority_scope_refs": ["scope:model.route.mutate"],
        "agentgres_operation_refs": [format!("agentgres://operation/model-route/{route_id}/{mutation_kind}")],
        "receipt_refs": [format!("receipt://model-route/{route_id}/{mutation_kind}")],
        "state_root_ref": format!("agentgres://state-root/model-route/{route_id}"),
    });
    if !custody_ref.is_empty() {
        request["model_weight_custody_admission_ref"] = json!(custody_ref);
    }
    if mutation_kind != "disable_route" {
        let posture = route
            .pointer("/custody/execution_privacy_posture")
            .and_then(|v| v.as_str())
            .unwrap_or("private_native");
        request["privacy_posture_ref"] = json!(format!("privacy-posture:{posture}"));
    }
    if let Some(sref) = session_ref {
        let normalized = if sref.starts_with("session:") {
            sref.to_string()
        } else {
            format!("session:{sref}")
        };
        request["session_ref"] = json!(normalized);
    }
    if matches!(
        credential_posture,
        "wallet_credential_lease" | "provider_vault_token"
    ) {
        request["credential_scope_refs"] = json!(["scope:secret.use"]);
        if let Some(lease) = route
            .pointer("/credential_binding/provider_credential_lease_ref")
            .and_then(|v| v.as_str())
        {
            request["provider_credential_lease_ref"] = json!(lease);
        }
    }
    RuntimeKernelService::new()
        .admit_model_route_mutation(&request, &iso_now())
        .map_err(|e| {
            (
                e.status,
                json!({ "error": { "code": e.code, "message": e.message, "details": e.details } }),
            )
        })
}

/// Record an admission's id + mutation receipt on the route record (admissions are otherwise
/// stateless planner outputs — the registry links them to the object they admitted).
fn stamp_admission(route: &mut Value, admission: &Value) {
    let admission_id = admission
        .get("admission_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let receipt_ref = admission
        .get("mutation_receipt_ref")
        .and_then(|v| v.as_str())
        .or_else(|| admission.get("receipt_ref").and_then(|v| v.as_str()))
        .unwrap_or("");
    route["admission"]["last_admission_id"] = json!(admission_id);
    if !receipt_ref.is_empty() {
        let refs = route["admission"]["mutation_receipt_refs"]
            .as_array_mut()
            .map(|a| {
                if !a.iter().any(|v| v.as_str() == Some(receipt_ref)) {
                    a.push(json!(receipt_ref));
                }
            });
        if refs.is_none() {
            route["admission"]["mutation_receipt_refs"] = json!([receipt_ref]);
        }
    }
}

// ---------------------------------------------------------------------------
// seed — represent the env-var execution reality as a real, admitted registry record
// ---------------------------------------------------------------------------

fn seed_route_record() -> Value {
    let model_id = std::env::var("IOI_HYPERVISOR_MODEL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "qwen2.5-coder".to_string());
    let base_url = normalize_base_url(
        &std::env::var("IOI_HYPERVISOR_MODEL_UPSTREAM")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "http://127.0.0.1:11434".to_string()),
    );
    json!({
        "schema_version": ROUTE_SCHEMA,
        "route_id": SEED_ROUTE_ID,
        "route_ref": format!("model-route:{SEED_ROUTE_ID}"),
        "display_name": "Local default (env)",
        "summary": "The daemon's env-configured local execution route (IOI_HYPERVISOR_MODEL / IOI_HYPERVISOR_MODEL_UPSTREAM), represented as registry truth.",
        "origin": "seeded",
        "project_ref": "project:hypervisor",
        "model": {
            "model_id": model_id,
            "family": Value::Null,
            "modalities": ["text"],
            "capabilities": {
                "tool_calling": Value::Null,
                "structured_outputs": Value::Null,
                "reasoning": { "supported": Value::Null, "effort_levels": [] }
            },
            "context_window": Value::Null,
            "max_output_tokens": Value::Null
        },
        "provider_binding": {
            "provider_kind": "local",
            "transport": "ollama",
            "base_url": base_url,
            "provider_ref": Value::Null,
            "endpoint_ref": Value::Null
        },
        "credential_posture": "no_credentials_required",
        "credential_binding": Value::Null,
        "custody": {
            "weight_class": "public_open_weight",
            "mount_target": "local_device",
            "execution_privacy_posture": "private_native",
            "custody_admission_ref": Value::Null
        },
        "lifecycle": { "status": "declared" },
        "default_route": true,
        "availability": { "state": "declared", "probe": Value::Null },
        "admission": { "last_admission_id": Value::Null, "mutation_receipt_refs": [], "gaps": [] },
        "receipt_refs": [],
        "created_at": iso_now(),
        "updated_at": iso_now()
    })
}

/// Ensure the seeded local-default route exists (and is fully admitted). Idempotent; called from
/// read handlers so the registry never presents an empty world that hides the real env route.
pub(crate) fn ensure_seed(data_dir: &str) {
    if load_route_record(data_dir, SEED_ROUTE_ID).is_some() {
        return;
    }
    let mut record = seed_route_record();
    // Compose the REAL planners for the seed: custody first, then enable. If a planner rejects
    // (should not for the local lane), the seed stays `declared` with the rejection named.
    match compose_custody_admission(&record) {
        Ok(custody) => {
            record["custody"]["custody_admission_ref"] = custody["admission_id"].clone();
            match compose_mutation_admission(
                &record,
                "enable_route",
                None,
                custody.get("admission_id").and_then(|v| v.as_str()),
            ) {
                Ok(admission) => {
                    record["lifecycle"]["status"] = json!("active");
                    stamp_admission(&mut record, &admission);
                }
                Err((_, body)) => {
                    record["admission"]["gaps"] = json!([format!(
                        "seed enable_route admission rejected: {}",
                        body.pointer("/error/code")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                    )]);
                }
            }
        }
        Err((_, body)) => {
            record["admission"]["gaps"] = json!([format!(
                "seed custody admission rejected: {}",
                body.pointer("/error/code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
            )]);
        }
    }
    // CLASSIFIED — bootstrap seed: idempotent, retried every read; strict lane re-censuses (:224-232)
    let receipt = route_receipt(
        data_dir,
        &s(&record, "route_ref", ""),
        "seeded",
        "ok",
        record
            .pointer("/admission/last_admission_id")
            .and_then(|v| v.as_str()),
    )
    .unwrap_or_default();
    record["receipt_refs"] = json!([receipt]);
    // CLASSIFIED — bootstrap seed: idempotent, retried every read; strict lane re-censuses (:224-232)
    let _ = persist_record(data_dir, RECORD_DIR, SEED_ROUTE_ID, &record);
}

fn save_route(data_dir: &str, route: &mut Value) -> std::io::Result<()> {
    route["updated_at"] = json!(iso_now());
    if let Some(id) = route.get("route_id").and_then(|v| v.as_str()) {
        let id = id.to_string();
        persist_record(data_dir, RECORD_DIR, &id, route)?;
    }
    Ok(())
}

/// Persist a fresh availability probe onto a route WITHOUT clobbering a concurrent edit: under the
/// registry lock, RE-LOAD the record, set only `availability` (plus an optional receipt ref), save,
/// and return the reloaded+updated record. The lock is held only across the synchronous
/// reload-mutate-save — never across the network probe that produced `availability`. Returns None
/// if the record vanished between probe and persist.
fn persist_availability_locked(
    st: &Arc<DaemonState>,
    id: &str,
    availability: Value,
    receipt: Option<&str>,
) -> std::io::Result<Option<Value>> {
    let _guard = st
        .model_route_lock
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let Some(mut route) = load_route_record(&st.data_dir, id) else {
        return Ok(None);
    };
    route["availability"] = availability;
    if let Some(r) = receipt {
        if let Some(refs) = route["receipt_refs"].as_array_mut() {
            refs.push(json!(r));
        }
    }
    save_route(&st.data_dir, &mut route)?;
    Ok(Some(route))
}

fn with_staleness(mut route: Value) -> Value {
    let stale = probe_is_stale(&route["availability"]);
    route["availability"]["stale"] = json!(stale);
    route
}

// ---------------------------------------------------------------------------
// route handlers
// ---------------------------------------------------------------------------

/// GET /v1/hypervisor/model-routes — the registry. `?probe=live` re-probes every route serially
/// (bounded by the per-probe timeout) before responding; otherwise persisted probe evidence is
/// returned with an explicit `stale` flag.
pub(crate) async fn handle_model_routes_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    ensure_seed(&st.data_dir);
    let live = q.get("probe").map(|v| v == "live").unwrap_or(false);
    let mut routes = read_record_dir(&st.data_dir, RECORD_DIR);
    routes.sort_by(|a, b| s(a, "route_id", "").cmp(&s(b, "route_id", "")));
    if live {
        let mut refreshed = Vec::with_capacity(routes.len());
        for r in routes {
            let id = s(&r, "route_id", "");
            let availability = probe_route(&r).await;
            // Reload-under-lock so a concurrent PATCH/mutation in the probe window is not clobbered.
            // A persist failure (or a vanished record) falls back to the last DURABLE record `r`
            // rather than surfacing an un-persisted probe as truth on this read projection.
            let updated = persist_availability_locked(&st, &id, availability, None)
                .ok()
                .flatten()
                .unwrap_or(r);
            refreshed.push(with_staleness(updated));
        }
        routes = refreshed;
    } else {
        routes = routes.into_iter().map(with_staleness).collect();
    }
    let default_route = routes
        .iter()
        .find(|r| r.get("default_route").and_then(|v| v.as_bool()) == Some(true))
        .map(|r| s(r, "route_ref", ""));
    Json(json!({
        "schema_version": ROUTE_SCHEMA,
        "routes": routes,
        "default_route_ref": default_route,
        "probe_mode": if live { "live" } else { "persisted" },
        "at": iso_now()
    }))
}

/// GET /v1/hypervisor/model-routes/overview — read projection: registry counts, the live env
/// execution posture (named plainly as `source: env`), model-mount substrate counts, honest gaps.
pub(crate) async fn handle_model_routes_overview(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    ensure_seed(&st.data_dir);
    let routes = read_record_dir(&st.data_dir, RECORD_DIR);
    let mut by_availability = serde_json::Map::new();
    let mut by_lifecycle = serde_json::Map::new();
    for r in &routes {
        let a = r
            .pointer("/availability/state")
            .and_then(|v| v.as_str())
            .unwrap_or("declared")
            .to_string();
        let l = r
            .pointer("/lifecycle/status")
            .and_then(|v| v.as_str())
            .unwrap_or("declared")
            .to_string();
        *by_availability.entry(a).or_insert(json!(0)) = json!(
            by_availability
                .get(&a)
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                + 1
        );
        let count = by_lifecycle.get(&l).and_then(|v| v.as_u64()).unwrap_or(0) + 1;
        by_lifecycle.insert(l, json!(count));
    }
    let bindings = read_record_dir(&st.data_dir, BINDING_DIR);

    // The env execution posture the session-execute path uses when NO binding exists — named
    // truthfully, source `env`, with a real reachability probe of the configured upstream.
    let env_model = std::env::var("IOI_HYPERVISOR_MODEL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "qwen2.5-coder".to_string());
    let env_upstream = std::env::var("IOI_HYPERVISOR_MODEL_UPSTREAM")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:11434".to_string());
    let env_probe = probe_route(&json!({
        "provider_binding": { "transport": "ollama", "base_url": normalize_base_url(&env_upstream) },
        "model": { "model_id": env_model }
    }))
    .await;

    // Model-mount substrate counts via the live catalog (evidence, not a second truth).
    let mount_providers = as_list(&get_json(&st.base_url, "/v1/model-mount/providers").await).len();
    let mount_routes = as_list(&get_json(&st.base_url, "/v1/model-mount/routes").await).len();

    let mut gaps: Vec<String> = Vec::new();
    if !routes
        .iter()
        .any(|r| r.pointer("/availability/state").and_then(|v| v.as_str()) == Some("available"))
    {
        gaps.push("no registry route has a successful availability probe yet (run POST /v1/hypervisor/model-routes/:id/probe)".into());
    }
    gaps.push("sealed BYOK credential bindings are not implemented; credentialed routes report env-key posture only".into());
    gaps.push("multi-transport execution is not implemented; only ollama-transport routes are bindable for session execution (shim contract)".into());

    Json(json!({
        "schema_version": OVERVIEW_SCHEMA,
        "route_count": routes.len(),
        "by_availability": by_availability,
        "by_lifecycle": by_lifecycle,
        "session_binding_count": bindings.len(),
        "env_execution": {
            "source": "env",
            "model": env_model,
            "upstream": env_upstream,
            "availability": env_probe
        },
        "model_mount_substrate": { "providers": mount_providers, "routes": mount_routes },
        "governance_gaps": gaps,
        "at": iso_now()
    }))
}

/// POST /v1/hypervisor/model-routes — register a DECLARED route. Composes the custody planner and
/// validates optional substrate refs against the live model-mount catalog; nothing persists on a
/// rejection. Credentials are never accepted as plaintext — only an env key NAME (posture).
pub(crate) async fn handle_model_route_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let model_id = s(&body, "model_id", "");
    if model_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "model_route_model_id_required", "message": "model_id is required." } }),
            ),
        );
    }
    let transport = s(&body, "transport", "ollama");
    if !matches!(transport.as_str(), "ollama" | "openai_compatible") {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "model_route_transport_invalid", "message": "transport must be 'ollama' or 'openai_compatible'.", "details": { "transport": transport } } }),
            ),
        );
    }
    let base_url_raw = s(&body, "base_url", "");
    if base_url_raw.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "model_route_base_url_required", "message": "base_url is required." } }),
            ),
        );
    }
    if body
        .get("api_key")
        .or_else(|| body.get("secret"))
        .or_else(|| body.get("token"))
        .is_some()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "model_route_plaintext_secret_rejected", "message": "Plaintext credentials are never accepted. Declare credential posture + env_key_name; the key stays in the daemon's environment." } }),
            ),
        );
    }
    let provider_ref = opt_s(&body, "provider_ref");
    let endpoint_ref = opt_s(&body, "endpoint_ref");
    if let Err((code, message)) = validate_substrate_refs(
        &st.base_url,
        provider_ref.as_deref(),
        endpoint_ref.as_deref(),
    )
    .await
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": { "code": code, "message": message } })),
        );
    }

    let id = format!("mrt_{:x}", nanos());
    let provider_kind = s(
        &body,
        "provider_kind",
        if transport == "ollama" {
            "local"
        } else {
            "hosted_api"
        },
    );
    let credential_posture = s(
        &body,
        "credential_posture",
        if transport == "ollama" {
            "no_credentials_required"
        } else {
            "provider_vault_token"
        },
    );
    let mut record = json!({
        "schema_version": ROUTE_SCHEMA,
        "route_id": id,
        "route_ref": format!("model-route:{id}"),
        "display_name": s(&body, "display_name", &model_id),
        "summary": s(&body, "summary", ""),
        "origin": "registered",
        "project_ref": opt_s(&body, "project_ref").unwrap_or_else(|| "project:hypervisor".into()),
        "model": {
            "model_id": model_id,
            "family": body.get("family").cloned().unwrap_or(Value::Null),
            "modalities": body.get("modalities").cloned().unwrap_or_else(|| json!(["text"])),
            "capabilities": body.get("capabilities").cloned().unwrap_or_else(|| json!({
                "tool_calling": Value::Null,
                "structured_outputs": Value::Null,
                "reasoning": { "supported": Value::Null, "effort_levels": [] }
            })),
            "context_window": body.get("context_window").cloned().unwrap_or(Value::Null),
            "max_output_tokens": body.get("max_output_tokens").cloned().unwrap_or(Value::Null)
        },
        "provider_binding": {
            "provider_kind": provider_kind,
            "transport": transport,
            "base_url": normalize_base_url(&base_url_raw),
            "provider_ref": provider_ref,
            "endpoint_ref": endpoint_ref
        },
        "credential_posture": credential_posture,
        "credential_binding": body.get("env_key_name").and_then(|v| v.as_str()).map(|k| json!({ "kind": "env_key_report", "env_key_name": k })).unwrap_or(Value::Null),
        "custody": {
            "weight_class": body.get("weight_class").cloned().unwrap_or(Value::Null),
            "mount_target": body.get("mount_target").cloned().unwrap_or(Value::Null),
            "execution_privacy_posture": body.get("execution_privacy_posture").cloned().unwrap_or(Value::Null),
            "custody_admission_ref": Value::Null
        },
        "lifecycle": { "status": "declared" },
        "default_route": false,
        "availability": { "state": "declared", "probe": Value::Null },
        "admission": { "last_admission_id": Value::Null, "mutation_receipt_refs": [], "gaps": [] },
        "receipt_refs": [],
        "created_at": iso_now(),
        "updated_at": iso_now()
    });
    // Custody admission at declaration time — the planner is the validator (fail-closed).
    match compose_custody_admission(&record) {
        Ok(custody) => {
            record["custody"]["custody_admission_ref"] = custody["admission_id"].clone();
        }
        Err((status, body)) => {
            return (
                StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
                Json(body),
            );
        }
    }
    // Mirror the M4 checked order: the receipt commits first (its ref is embedded on the record),
    // then the record — a 201 is returned only when both durable effects landed.
    let receipt = match route_receipt(
        &st.data_dir,
        &s(&record, "route_ref", ""),
        "registered",
        "ok",
        record
            .pointer("/custody/custody_admission_ref")
            .and_then(|v| v.as_str()),
    ) {
        Ok(receipt) => receipt,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "ok": false, "code": "model_route_receipt_persistence_failed",
                    "message": "the registration receipt did not commit — the route was not registered" }),
                ),
            );
        }
    };
    record["receipt_refs"] = json!([receipt]);
    if persist_record(
        &st.data_dir,
        RECORD_DIR,
        &s(&record, "route_id", ""),
        &record,
    )
    .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "model_route_persistence_failed",
                "message": "the model route did not commit — nothing was registered" }),
            ),
        );
    }
    (StatusCode::CREATED, Json(json!({ "route": record })))
}

/// GET /v1/hypervisor/model-routes/:id — record + persisted probe + bindings + receipts.
pub(crate) async fn handle_model_route_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    ensure_seed(&st.data_dir);
    let Some(route) = load_route_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    };
    let route_ref = s(&route, "route_ref", "");
    let bindings: Vec<Value> = read_record_dir(&st.data_dir, BINDING_DIR)
        .into_iter()
        .filter(|b| b.get("route_ref").and_then(|v| v.as_str()) == Some(route_ref.as_str()))
        .collect();
    let receipts: Vec<Value> = read_record_dir(&st.data_dir, RECEIPT_DIR)
        .into_iter()
        .filter(|r| r.get("route_ref").and_then(|v| v.as_str()) == Some(route_ref.as_str()))
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "route": with_staleness(route),
            "session_bindings": bindings,
            "receipts": receipts
        })),
    )
}

/// PATCH /v1/hypervisor/model-routes/:id — mutate declared metadata / provider binding /
/// credential posture. A credential-touching change composes `update_provider_credentials`
/// admission; a base_url change resets probe evidence to `declared` (old evidence would lie).
pub(crate) async fn handle_model_route_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if load_route_record(&st.data_dir, &id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    }
    if body
        .get("api_key")
        .or_else(|| body.get("secret"))
        .or_else(|| body.get("token"))
        .is_some()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "model_route_plaintext_secret_rejected", "message": "Plaintext credentials are never accepted." } }),
            ),
        );
    }
    // Serialize the whole read-modify-write under the registry lock (like lifecycle_flip) so a
    // concurrent flip / select-default landing in the mutate window is not clobbered. No .await
    // is taken while the guard is held.
    let _guard = st
        .model_route_lock
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let Some(mut route) = load_route_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    };
    // A route holding a SEALED credential has its destination and posture FROZEN. This closes the
    // other half of the credential-exfiltration chain an adversarial review found: even with the
    // destination now bound into the invoke crossing's grant hash, an unauthenticated caller could
    // repoint `base_url` and leave the sealed key attached, so a fresh owner approval would ship it
    // to the new host. While custody exists the destination cannot move and the posture cannot be
    // downgraded — you must REVOKE first, which is owner-scoped to whoever established custody.
    // (The broader gap — this whole registry's mutations are unauthenticated because a route
    // carries no owner — is filed as its own leg; this guard is the part that protects the key.)
    if live_credential_record(&st.data_dir, &id).is_some() {
        let touches_frozen = body.get("base_url").is_some()
            || body.get("credential_posture").is_some()
            || body.get("env_key_name").is_some();
        if touches_frozen {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": {
                    "code": "model_route_credentialed_config_frozen",
                    "message": "this route holds a sealed credential; its base_url and credential posture cannot be changed while custody exists. Revoke the credential first: DELETE /v1/hypervisor/model-routes/{id}/credential",
                    "details": { "route_id": id }
                } })),
            );
        }
    }
    let credential_change =
        body.get("credential_posture").is_some() || body.get("env_key_name").is_some();
    if credential_change {
        if let Some(p) = opt_s(&body, "credential_posture") {
            route["credential_posture"] = json!(p);
        }
        if let Some(k) = opt_s(&body, "env_key_name") {
            route["credential_binding"] = json!({ "kind": "env_key_report", "env_key_name": k });
        }
        match compose_mutation_admission(&route, "update_provider_credentials", None, None) {
            Ok(admission) => stamp_admission(&mut route, &admission),
            Err((status, body)) => {
                return (
                    StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
                    Json(body),
                );
            }
        }
    }
    if let Some(name) = opt_s(&body, "display_name") {
        route["display_name"] = json!(name);
    }
    if let Some(summary) = opt_s(&body, "summary") {
        route["summary"] = json!(summary);
    }
    if let Some(caps) = body.get("capabilities") {
        route["model"]["capabilities"] = caps.clone();
    }
    if let Some(cw) = body.get("context_window") {
        route["model"]["context_window"] = cw.clone();
    }
    if let Some(base) = opt_s(&body, "base_url") {
        let normalized = normalize_base_url(&base);
        if route
            .pointer("/provider_binding/base_url")
            .and_then(|v| v.as_str())
            != Some(normalized.as_str())
        {
            route["provider_binding"]["base_url"] = json!(normalized);
            route["availability"] = json!({ "state": "declared", "probe": Value::Null });
        }
    }
    let receipt = match route_receipt(
        &st.data_dir,
        &s(&route, "route_ref", ""),
        "patched",
        "ok",
        None,
    ) {
        Ok(receipt) => receipt,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "ok": false, "code": "model_route_receipt_persistence_failed",
                    "message": "the patch receipt did not commit — no change was recorded" }),
                ),
            );
        }
    };
    if let Some(refs) = route["receipt_refs"].as_array_mut() {
        refs.push(json!(receipt));
    }
    if save_route(&st.data_dir, &mut route).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "model_route_persistence_failed",
                "message": "the model route patch did not commit — nothing changed" }),
            ),
        );
    }
    (StatusCode::OK, Json(json!({ "route": route })))
}

/// DELETE /v1/hypervisor/model-routes/:id — registered-origin only; fail-closed 409 for the seed,
/// the current default, or a route with session bindings.
pub(crate) async fn handle_model_route_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let Some(route) = load_route_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    };
    let route_ref = s(&route, "route_ref", "");
    if s(&route, "origin", "") == "seeded" {
        return (
            StatusCode::CONFLICT,
            Json(
                json!({ "error": { "code": "model_route_seed_undeletable", "message": "The seeded env-default route represents live execution reality; it cannot be deleted." } }),
            ),
        );
    }
    if route.get("default_route").and_then(|v| v.as_bool()) == Some(true) {
        return (
            StatusCode::CONFLICT,
            Json(
                json!({ "error": { "code": "model_route_default_undeletable", "message": "Select a different default route before deleting this one." } }),
            ),
        );
    }
    let bound = read_record_dir(&st.data_dir, BINDING_DIR)
        .into_iter()
        .any(|b| b.get("route_ref").and_then(|v| v.as_str()) == Some(route_ref.as_str()));
    if bound {
        return (
            StatusCode::CONFLICT,
            Json(
                json!({ "error": { "code": "model_route_has_session_bindings", "message": "Route has session bindings; it cannot be deleted." } }),
            ),
        );
    }
    let removed = remove_record(&st.data_dir, RECORD_DIR, &id);
    if !removed {
        // The route resolved above; a false removal means the delete did not take effect. Do not
        // emit a "deleted"/ok receipt or a 200 over a record that is still present.
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "code": "model_route_delete_failed",
                "message": "the model route record was not removed — nothing was deleted" })),
        );
    }
    let receipt = match route_receipt(&st.data_dir, &route_ref, "deleted", "ok", None) {
        Ok(receipt) => receipt,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "ok": false, "code": "model_route_receipt_persistence_failed",
                    "message": "the route was removed but the deletion receipt did not commit" }),
                ),
            );
        }
    };
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "route_ref": route_ref, "receipt_ref": receipt })),
    )
}

/// POST /v1/hypervisor/model-routes/:id/probe — THE honest availability probe (effectful,
/// receipted, transcript-proofed).
pub(crate) async fn handle_model_route_probe(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    ensure_seed(&st.data_dir);
    let Some(route) = load_route_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    };
    let route_ref = s(&route, "route_ref", "");
    let availability = probe_route(&route).await;
    let state = availability
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("declared");
    let receipt = match route_receipt(&st.data_dir, &route_ref, "probed", state, None) {
        Ok(receipt) => receipt,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "ok": false, "code": "model_route_receipt_persistence_failed",
                    "message": "the probe receipt did not commit — no availability was recorded" }),
                ),
            );
        }
    };
    // Reload-under-lock so a PATCH that landed during the network probe is not clobbered. The
    // probe result is authoritative registry truth: refuse rather than return un-persisted state.
    if persist_availability_locked(&st, &id, availability.clone(), Some(&receipt)).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "ok": false, "code": "model_route_probe_persistence_failed",
                "message": "the availability probe did not commit — the route's posture is unchanged" }),
            ),
        );
    }
    let transcript_run = post_op_transcript(&st.base_url, "probe", &route_ref, &availability).await;
    (
        StatusCode::OK,
        Json(json!({
            "route_ref": route_ref,
            "availability": availability,
            "receipt_ref": receipt,
            "transcript_run_id": transcript_run,
            "transcript_recorded": transcript_run.is_some()
        })),
    )
}

async fn lifecycle_flip(
    st: &Arc<DaemonState>,
    id: &str,
    mutation_kind: &str,
    new_status: &str,
) -> (StatusCode, Json<Value>) {
    let Some(route) = load_route_record(&st.data_dir, id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    };
    match compose_mutation_admission(&route, mutation_kind, None, None) {
        Ok(admission) => {
            let route_ref = s(&route, "route_ref", "");
            let receipt = match route_receipt(
                &st.data_dir,
                &route_ref,
                mutation_kind,
                "ok",
                admission.get("admission_id").and_then(|v| v.as_str()),
            ) {
                Ok(receipt) => receipt,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(
                            json!({ "ok": false, "code": "model_route_receipt_persistence_failed",
                            "message": "the lifecycle receipt did not commit — the route was not changed" }),
                        ),
                    );
                }
            };
            // Reload-under-lock and apply the flip on fresh state so a concurrent mutation isn't lost.
            let route = {
                let _guard = st
                    .model_route_lock
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let mut fresh = load_route_record(&st.data_dir, id).unwrap_or(route);
                fresh["lifecycle"]["status"] = json!(new_status);
                stamp_admission(&mut fresh, &admission);
                if let Some(refs) = fresh["receipt_refs"].as_array_mut() {
                    refs.push(json!(receipt));
                }
                if save_route(&st.data_dir, &mut fresh).is_err() {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(
                            json!({ "ok": false, "code": "model_route_persistence_failed",
                            "message": "the lifecycle flip did not commit — the route's status is unchanged" }),
                        ),
                    );
                }
                fresh
            };
            let transcript_run = post_op_transcript(
                &st.base_url,
                mutation_kind,
                &route_ref,
                &json!({ "new_status": new_status }),
            )
            .await;
            (
                StatusCode::OK,
                Json(json!({
                    "route": route,
                    "admission_id": admission.get("admission_id"),
                    "receipt_ref": receipt,
                    "transcript_recorded": transcript_run.is_some()
                })),
            )
        }
        Err((status, body)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(body),
        ),
    }
}

// ---------------------------------------------------------------------------
// sealed provider credentials — the custody a model route never had
// ---------------------------------------------------------------------------
//
// THE ASYMMETRY THIS CLOSES. Compute `ProviderAccount`s already get real sealed per-kind BYOK
// across nine provider kinds, resolved at the CapabilityLease gateway. A model route got an
// `env_key_report`: a record of which environment variable a human was supposed to have exported.
// That is not custody — it is a note about custody. The daemon's only credentialed model call read
// its key straight out of the process environment, which means no lease, no wallet authority, no
// receipt, and no revocation surface.
//
// A route's credential lives HERE, sealed, and reaches a provider only through
// `authorize_capability_lease`. The plaintext is accepted exactly once, at bind time, and is never
// returned, logged, projected onto the route record, or embedded in a receipt.

/// The RAW record for a route's credential slot — live credential, or the revocation tombstone the
/// stream leaves behind. Callers that need "is there a usable key" want [`live_credential_record`];
/// this one is for the lifecycle machinery that has to see the tombstone (successor CAS, existence).
fn credential_record(data_dir: &str, route_id: &str) -> Option<Value> {
    read_record_dir(data_dir, CREDENTIAL_DIR)
        .into_iter()
        // `connector_id` is the CapabilityLease gateway's own lookup field, not a claim that a
        // model route is a connector. Spelling it the gateway's way is what lets one resolver serve
        // both families instead of growing a second one.
        .find(|c| c.get("connector_id").and_then(Value::as_str) == Some(route_id))
}

/// A record only when a route holds a LIVE sealed key — never a tombstone.
///
/// Revocation does not delete; it leaves a tombstone (no `sealed_token`, `state: "revoked"`) so the
/// hash-chained credential stream keeps a head a later re-bind can succeed a CAS from. A rotation
/// that could not chain onto the prior head was the reviewer's finding #3: bind was genesis-only,
/// so a route could be bound exactly once, ever. The distinction between "holds a key" and "the
/// slot has history" is exactly this function.
fn live_credential_record(data_dir: &str, route_id: &str) -> Option<Value> {
    credential_record(data_dir, route_id).filter(|record| {
        record.get("sealed_token").and_then(Value::as_str).is_some()
            && record.get("state").and_then(Value::as_str) != Some("revoked")
    })
}

/// Non-secret labels only. Every reader of a route learns THAT a credential is bound and how it is
/// revoked; none of them can learn what it is. A tombstone reads as no binding.
pub(crate) fn credential_binding_projection(data_dir: &str, route_id: &str) -> Value {
    match live_credential_record(data_dir, route_id) {
        Some(record) => json!({
            "kind": "sealed_capability_lease",
            "credential_ref": format!("model-route-credential://{route_id}"),
            "credential_kind": record.get("kind").cloned().unwrap_or(Value::Null),
            "sealed": true,
            "bound_at": record.get("bound_at").cloned().unwrap_or(Value::Null),
            "revocation_ref": format!("model-routes/{route_id}/credential"),
            // THE FIELD THE KERNEL PLANNER HAS ALWAYS ASKED FOR AND NOTHING EVER WROTE.
            //
            // `runtime_model_route_mutation_admission` refuses to enable or bind a route whose
            // credential posture is `provider_vault_token` / `wallet_credential_lease` unless a
            // `provider_credential_lease_ref` is present, and `compose_mutation_admission` reads it
            // from exactly here. No code path produced it, so a credentialed route could not be
            // enabled AT ALL: the refusal was correct and unreachable in both directions.
            //
            // The planner also pins the `lease:` prefix, which settles what the field means — a
            // LEASE, not a pointer at a vault. So the bind is itself an authority crossing that
            // mints one, and this carries that lease's id. Satisfying the prefix with a
            // custody-shaped ref would have been label-fitting, which is the defect class this
            // program keeps finding.
            "provider_credential_lease_ref": record
                .get("custody_lease_ref").cloned().unwrap_or(Value::Null),
        }),
        None => Value::Null,
    }
}

/// Undo a bind by RESTORING what was there before it, and CONFIRM the restore took.
///
/// Two findings converge here. `check:mutation-handlers` caught the first cut discarding the
/// removal's bool — "nothing was there" and "deletion failed" were indistinguishable. The
/// adversarial review then caught the deeper one (finding #4): the rollback DELETED, so a rebind
/// that overwrote an incumbent key and then failed the crossing destroyed the incumbent. Rollback
/// must return the slot to its prior contents — the incumbent record if there was one, or absence
/// if there was not — and verify the result on disk before anyone is told the bind failed cleanly.
fn restore_or_remove_credential(data_dir: &str, route_id: &str, incumbent: Option<&Value>) -> bool {
    match incumbent {
        Some(prior) => {
            persist_record(data_dir, CREDENTIAL_DIR, route_id, prior).is_ok()
                && credential_record(data_dir, route_id).as_ref() == Some(prior)
        }
        None => {
            let removed = remove_record(data_dir, CREDENTIAL_DIR, route_id);
            removed && credential_record(data_dir, route_id).is_none()
        }
    }
}

/// The refusal a stranded secret earns. The operator is told the bind failed AND that key material
/// survived it, because those are different problems and only one of them is theirs to clean up.
fn stranded_credential_reply(route_id: &str, cause: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "ok": false, "error": {
            "code": "model_route_credential_rollback_failed",
            "message": format!(
                "the bind did not complete ({cause}) and the sealed credential could NOT be removed; key material is still in custody for this route. Revoke it: DELETE /v1/hypervisor/model-routes/{route_id}/credential"
            ),
            "details": { "route_id": route_id, "cause": cause, "key_material_stranded": true }
        } })),
    )
}

/// POST /v1/hypervisor/model-routes/:id/credential — seal a provider key into route custody.
///
/// The plaintext crosses this boundary once and is sealed before anything else happens to it. A
/// route declaring `no_credentials_required` is REFUSED: a credential that no crossing will ever
/// consume is an unrevoked secret sitting in a vault for no reason.
pub(crate) async fn handle_model_route_credential_bind(
    State(st): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let caller =
        match super::mutation_event_foundation::require_write_caller(&st.data_dir, &headers, &body)
        {
            Ok(caller) => caller,
            Err(response) => return response,
        };
    // INV-37 — WHO establishes custody is resolved server-side; a body carrying an actor field
    // refuses. The custody record and its admitted event then carry the resolved principal, so the
    // audit answers "who bound this key" rather than leaving it unstated (review finding #13).
    let acting_principal_ref = match super::lifecycle_routes::resolve_acting_principal_ref(
        &st.data_dir,
        &headers,
        &body,
    ) {
        Ok(actor) => actor,
        Err((status, value)) => return (status, Json(value)),
    };
    ensure_seed(&st.data_dir);
    let Some(mut route) = load_route_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    };
    let posture = s(&route, "credential_posture", "no_credentials_required");
    if posture == "no_credentials_required" {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": {
                "code": "model_route_credential_not_required",
                "message": "this route declares no_credentials_required; binding a secret it will never present is custody with no crossing behind it",
                "details": { "credential_posture": posture }
            } })),
        );
    }

    // OWNERSHIP GATE, BEFORE THE VAULT IS TOUCHED (review finding #4).
    //
    // A model route carries no owner of its own, so the first principal to establish custody owns
    // the credential SLOT — pinned per (resource_kind, resource_ref) by the substrate. Binding the
    // scope here, before anything is written, is what stops a different tenant from reaching the
    // vault write at all: the old ordering overwrote the sealed record first and only refused at the
    // admission afterward, so an attacker presenting their own owner_ref could clobber a victim's
    // key and the destructive rollback then deleted it. A wrong owner now refuses here, having
    // written nothing. (The broad gap — every OTHER model-route mutation is unauthenticated because
    // routes are ownerless — is filed as its own leg; this closes the part that guards a secret.)
    let credential_ref = format!("model-route-credential://{id}");
    if let Err(refusal) = super::substrate_store::bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        CREDENTIAL_DIR,
        &credential_ref,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        return super::mutation_event_foundation::scope_refusal_reply(refusal);
    }

    let token = body
        .get("token")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": {
                "code": "model_route_credential_token_required",
                "message": "token is required: it is sealed on arrival and never readable again"
            } })),
        );
    }
    let Some(sealed) = super::lifecycle_routes::seal_scm_token(&token) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": {
                "code": "model_route_credential_seal_failed",
                "message": "the credential could not be sealed and is NOT bound; nothing was stored"
            } })),
        );
    };
    drop(token);
    // key_source is the STRENGTH-OF-SEALING label, and it is SERVER-DERIVED, never caller-supplied
    // (review finding #6). Every other sealed-credential family derives it from `scm_key_source()`;
    // reading it from the body let a caller stamp "wallet-secret-pass" onto a key actually sealed
    // under the well-known local-mode passphrase, falsifying a durable custody label. The daemon
    // knows which passphrase it used; the caller does not get to claim otherwise.
    let key_source = super::lifecycle_routes::scm_key_source();

    // The incumbent — a live key being rotated, or a revocation tombstone — is what a failed bind
    // must be able to RESTORE, and its admitted head is what a rebind's successor CAS chains onto.
    let incumbent = credential_record(&st.data_dir, &id);
    let expected_head = incumbent
        .as_ref()
        .and_then(|r| r["admitted_head"].as_str().map(str::to_owned));

    let mut credential = json!({
        "connector_id": id,
        "kind": "model-provider-key",
        "sealed_token": sealed,
        "key_source": key_source,
        "sealed": true,
        "state": "active",
        "route_ref": s(&route, "route_ref", ""),
        "acting_principal_ref": acting_principal_ref,
        "bound_at": iso_now(),
    });

    // SEAL, THEN CROSS. The gateway resolves the sealed credential as part of authorizing the
    // crossing (428 if it will not open), so the key must be in the vault before the crossing can be
    // asked about it. The ownership gate above already refused any wrong owner, so the only writer
    // that reaches here is the slot's owner rotating their own key — and every failure path RESTORES
    // their incumbent rather than deleting it.
    if persist_record(&st.data_dir, CREDENTIAL_DIR, &id, &credential).is_err() {
        if !restore_or_remove_credential(&st.data_dir, &id, incumbent.as_ref()) {
            return stranded_credential_reply(&id, "the sealed credential could not be written");
        }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": {
                "code": "model_route_credential_persistence_failed",
                "message": "the credential was not durably sealed and is NOT bound"
            } })),
        );
    }

    // Establishing custody is its own authority crossing, distinct from USING the credential. The
    // estate already works this way — a connector acquires a lease and then opens a session — and
    // the model-route planner's `lease:` prefix requires it: the route records the custody lease's
    // id, and each invocation mints its own short-lived use lease at the same gateway.
    let lease_request = super::lifecycle_routes::CapabilityLeaseRequest {
        authority_provider_ref: "wallet.network".to_string(),
        backing_provider: format!("model-route:{id}"),
        allowed_tools: vec!["model.credential.bind".to_string()],
        resource_refs: vec![format!("model-route:{id}"), credential_ref.clone()],
        scopes: vec!["secret.use".to_string()],
        policy_domain: "hypervisor.model-route.credential-bind.policy.v1".to_string(),
        request_domain: "hypervisor.model-route.credential-bind.request.v1".to_string(),
        // A per-bind NONCE (the caller's idempotency key) makes every bind a DISTINCT crossing.
        // Establishing custody is a fresh authority decision each time — rotating a compromised key
        // is not a reuse of the original bind's authority — so two binds must not collapse to the
        // same grant coordinates. Without this a rotation reuses the first bind's (policy, request)
        // hash, and the gateway rejects it as a replay of an already-consumed grant. A RETRY of the
        // same logical bind keeps the same idempotency key, so it still replays idempotently; only a
        // genuinely new bind gets new coordinates. (Contrast the invoke crossing, whose facets are
        // deliberately stable so one grant is a bounded authority to use a route many times.)
        request_facets: json!({
            "route_id": id,
            "credential_posture": posture,
            "credential_kind": "model-provider-key",
            "bind_nonce": caller.idempotency_key,
        }),
        credential_connector_id: Some(id.clone()),
        credential_store: CREDENTIAL_DIR.to_string(),
        credential_required: true,
        github_host_fallback: false,
        receipt_required: true,
        revocation_ref: format!("model-routes/{id}/credential"),
        authority_reason: "model_route_credential_bind_authority_required".to_string(),
        grant_value: body
            .get("wallet_approval_grant")
            .cloned()
            .unwrap_or(Value::Null),
    };
    let custody_lease =
        match super::lifecycle_routes::authorize_capability_lease(&st, &lease_request).await {
            Ok(lease) => lease,
            Err((status, challenge)) => {
                if !restore_or_remove_credential(&st.data_dir, &id, incumbent.as_ref()) {
                    return stranded_credential_reply(&id, "the authority crossing was refused");
                }
                return (status, Json(challenge));
            }
        };
    // The bind never presents the bearer to anyone; it only proves the credential resolves. Drop it
    // here so it does not outlive the one function that had a reason to hold it.
    drop(custody_lease.token);
    let custody_lease_id = s(&custody_lease.descriptor, "lease_id", "");
    credential["custody_lease_ref"] = json!(format!("lease:{custody_lease_id}"));
    credential["custody_grant_ref"] = json!(custody_lease.grant_ref);

    // The bind EVENT is admitted on the SAME stream ref as revoke, with a successor CAS from the
    // incumbent's head — so a rebind chains onto history instead of failing as a genesis conflict
    // (finding #3), and the owner pin established above governs every write on this ref.
    let admitted = json!({
        "route_id": id,
        "route_ref": s(&route, "route_ref", ""),
        "credential_kind": "model-provider-key",
        "key_source": key_source,
        "credential_posture": posture,
        "acting_principal_ref": acting_principal_ref,
        "custody_lease_ref": format!("lease:{custody_lease_id}"),
    });
    let commit = match super::mutation_event_foundation::admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        "hypervisor-model-route-credentials",
        CREDENTIAL_DIR,
        &credential_ref,
        "model_route.credential_bound",
        expected_head.as_deref(),
        &admitted,
    ) {
        Ok(commit) => commit,
        Err(response) => {
            if !restore_or_remove_credential(&st.data_dir, &id, incumbent.as_ref()) {
                return stranded_credential_reply(&id, "the bind event was not admitted");
            }
            return response;
        }
    };
    credential["admitted_head"] = json!(commit.projection.head);
    if persist_record(&st.data_dir, CREDENTIAL_DIR, &id, &credential).is_err() {
        if !restore_or_remove_credential(&st.data_dir, &id, incumbent.as_ref()) {
            return stranded_credential_reply(
                &id,
                "the custody lease did not attach to the sealed credential",
            );
        }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": {
                "code": "model_route_credential_persistence_failed",
                "message": "the custody lease did not attach to the sealed credential; nothing is bound"
            } })),
        );
    }
    route["credential_binding"] = credential_binding_projection(&st.data_dir, &id);
    route["updated_at"] = json!(iso_now());
    if persist_record(&st.data_dir, RECORD_DIR, &id, &route).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": {
                "code": "model_route_credential_binding_projection_failed",
                "message": "the credential is sealed but the route still advertises its previous binding; re-bind to converge"
            } })),
        );
    }
    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "route_id": id,
            "credential_posture": posture,
            "credential_binding": route["credential_binding"],
        })),
    )
}

/// DELETE /v1/hypervisor/model-routes/:id/credential — the revocation surface the lease descriptor
/// names. Custody you cannot revoke is not custody; a credential family without this route would
/// have shipped a secret with no way to take it back.
pub(crate) async fn handle_model_route_credential_revoke(
    State(st): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let caller =
        match super::mutation_event_foundation::require_write_caller(&st.data_dir, &headers, &body)
        {
            Ok(caller) => caller,
            Err(response) => return response,
        };
    let acting_principal_ref = match super::lifecycle_routes::resolve_acting_principal_ref(
        &st.data_dir,
        &headers,
        &body,
    ) {
        Ok(actor) => actor,
        Err((status, value)) => return (status, Json(value)),
    };

    let incumbent = credential_record(&st.data_dir, &id);
    let was_bound = incumbent
        .as_ref()
        .map(|r| {
            r.get("sealed_token").and_then(Value::as_str).is_some()
                && r.get("state").and_then(Value::as_str) != Some("revoked")
        })
        .unwrap_or(false);

    // A route whose credential slot was NEVER touched has no stream and no owner. Revoking it must
    // not admit an event or claim the slot — that would let a revoke-of-nothing seize ownership of
    // another party's future bind. It is an honest no-op.
    let Some(incumbent) = incumbent else {
        return (
            StatusCode::OK,
            Json(
                json!({ "ok": true, "route_id": id, "was_bound": false, "credential_binding": Value::Null }),
            ),
        );
    };

    // Revoke admits on the SAME resource ref the bind claimed (review finding #5). The first cut
    // admitted revocation under `model-route-credential-revocation://{id}` — a DIFFERENT ref, whose
    // ownership was unclaimed, so any authenticated principal in any tenant could revoke another
    // tenant's key. Binding revoke to the credential ref means the owner pin from the bind governs
    // it, and the successor CAS keeps the stream's head intact for a later rebind.
    let credential_ref = format!("model-route-credential://{id}");
    let expected_head = incumbent["admitted_head"].as_str().map(str::to_owned);
    let commit = match super::mutation_event_foundation::admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        "hypervisor-model-route-credentials",
        CREDENTIAL_DIR,
        &credential_ref,
        "model_route.credential_revoked",
        expected_head.as_deref(),
        &json!({ "route_id": id, "was_bound": was_bound, "acting_principal_ref": acting_principal_ref }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };

    // A TOMBSTONE, not a delete. It carries no `sealed_token`, so no key survives revocation and
    // `live_credential_record` reads it as no binding — but it keeps the stream's head so a future
    // rebind is a successor rather than a genesis conflict. Revocation that deleted the record threw
    // that head away and made the route un-rebindable (the other half of finding #3).
    let tombstone = json!({
        "connector_id": id,
        "kind": "model-provider-key",
        "state": "revoked",
        "sealed": false,
        "route_ref": incumbent.get("route_ref").cloned().unwrap_or(Value::Null),
        "revoked_by": acting_principal_ref,
        "revoked_at": iso_now(),
        "admitted_head": commit.projection.head,
    });
    if persist_record(&st.data_dir, CREDENTIAL_DIR, &id, &tombstone).is_err()
        || live_credential_record(&st.data_dir, &id).is_some()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": {
                "code": "model_route_credential_revocation_failed",
                "message": "the sealed credential is still resolvable; the route is NOT revoked"
            } })),
        );
    }
    if let Some(mut route) = load_route_record(&st.data_dir, &id) {
        route["credential_binding"] = Value::Null;
        route["updated_at"] = json!(iso_now());
        if persist_record(&st.data_dir, RECORD_DIR, &id, &route).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": {
                    "code": "model_route_credential_binding_projection_failed",
                    "message": "the credential is revoked but the route still advertises a binding; re-read to converge"
                } })),
            );
        }
    }
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "route_id": id, "was_bound": was_bound, "credential_binding": Value::Null }),
        ),
    )
}

/// POST /v1/hypervisor/model-routes/:id/enable — declared/disabled -> active (admitted). Enabling
/// does NOT assert availability: an active route can still be credentials_missing/unreachable —
/// the two postures stay independently visible.
pub(crate) async fn handle_model_route_enable(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    lifecycle_flip(&st, &id, "enable_route", "active").await
}

/// POST /v1/hypervisor/model-routes/:id/disable — active -> disabled (admitted; relaxed lane).
pub(crate) async fn handle_model_route_disable(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    lifecycle_flip(&st, &id, "disable_route", "disabled").await
}

/// POST /v1/hypervisor/model-routes/:id/select-default — exactly-one default invariant, admitted.
pub(crate) async fn handle_model_route_select_default(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    ensure_seed(&st.data_dir);
    let Some(route) = load_route_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    };
    match compose_mutation_admission(&route, "select_route", None, None) {
        Ok(admission) => {
            let route_ref = s(&route, "route_ref", "");
            let receipt = match route_receipt(
                &st.data_dir,
                &route_ref,
                "select_route",
                "ok",
                admission.get("admission_id").and_then(|v| v.as_str()),
            ) {
                Ok(receipt) => receipt,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(
                            json!({ "ok": false, "code": "model_route_receipt_persistence_failed",
                            "message": "the select-default receipt did not commit — the default was not changed" }),
                        ),
                    );
                }
            };
            // Hold the registry lock across clear-others + set-self so two concurrent
            // select-default calls cannot each observe the old default and both win (the
            // exactly-one invariant). No .await inside the guarded region.
            let route = {
                let _guard = st
                    .model_route_lock
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                // Track the defaults we clear so a set-self failure can restore them: a partial
                // failure that clears the old default but never sets the new one would leave ZERO
                // defaults and the strict lane refuses the whole registry (:225-232).
                let mut cleared: Vec<Value> = Vec::new();
                for mut other in read_record_dir(&st.data_dir, RECORD_DIR) {
                    if other.get("default_route").and_then(|v| v.as_bool()) == Some(true)
                        && s(&other, "route_id", "") != id
                    {
                        other["default_route"] = json!(false);
                        let other_ref = s(&other, "route_ref", "");
                        // CLASSIFIED — best-effort telemetry: the flag flip is proven by the save
                        // below + the exactly-one census; the cleared-receipt is an evidence trail.
                        let _ =
                            route_receipt(&st.data_dir, &other_ref, "default_cleared", "ok", None);
                        if save_route(&st.data_dir, &mut other).is_err() {
                            for prior in cleared.iter_mut() {
                                prior["default_route"] = json!(true);
                                let _ = save_route(&st.data_dir, prior);
                            }
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(
                                    json!({ "ok": false, "code": "model_route_persistence_failed",
                                    "message": "clearing a prior default route did not commit — the default was not changed" }),
                                ),
                            );
                        }
                        cleared.push(other);
                    }
                }
                let mut fresh = load_route_record(&st.data_dir, &id).unwrap_or(route);
                fresh["default_route"] = json!(true);
                stamp_admission(&mut fresh, &admission);
                if let Some(refs) = fresh["receipt_refs"].as_array_mut() {
                    refs.push(json!(receipt));
                }
                if save_route(&st.data_dir, &mut fresh).is_err() {
                    for prior in cleared.iter_mut() {
                        prior["default_route"] = json!(true);
                        let _ = save_route(&st.data_dir, prior);
                    }
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(
                            json!({ "ok": false, "code": "model_route_persistence_failed",
                            "message": "selecting the new default route did not commit — the prior default was restored" }),
                        ),
                    );
                }
                fresh
            };
            let transcript_run =
                post_op_transcript(&st.base_url, "select_default", &route_ref, &json!({})).await;
            (
                StatusCode::OK,
                Json(json!({
                    "route": route,
                    "receipt_ref": receipt,
                    "transcript_recorded": transcript_run.is_some()
                })),
            )
        }
        Err((status, body)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(body),
        ),
    }
}

/// POST /v1/hypervisor/model-routes/:id/session-bindings — bind a session to a route. FAIL-CLOSED:
/// 412 unless an inline live probe returns `available` AND lifecycle is `active`; 409 for
/// transports the execution shim cannot run (no dropdown lies). Admitted (`bind_session_route`)
/// and receipted; consumed by sessions/:id/execute.
pub(crate) async fn handle_model_route_bind_session(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    ensure_seed(&st.data_dir);
    let Some(route) = load_route_record(&st.data_dir, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "not_found", "route": id } })),
        );
    };
    let session_ref = s(&body, "session_ref", "");
    if session_ref.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": { "code": "model_route_session_ref_required", "message": "session_ref is required." } }),
            ),
        );
    }
    let transport = route
        .pointer("/provider_binding/transport")
        .and_then(|v| v.as_str())
        .unwrap_or("ollama")
        .to_string();
    if transport != "ollama" {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": {
                "code": "transport_unsupported_for_execution",
                "message": "Only ollama-transport routes are executable by the session harness today; this route stays declared/available but is not bindable for execution.",
                "details": { "transport": transport }
            } })),
        );
    }
    let lifecycle = route
        .pointer("/lifecycle/status")
        .and_then(|v| v.as_str())
        .unwrap_or("declared")
        .to_string();
    if lifecycle != "active" {
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": {
                "code": "model_route_not_active",
                "message": format!("Route lifecycle is '{lifecycle}'; enable it before binding sessions."),
            } })),
        );
    }
    // Inline REAL probe — a binding must never be minted against stale availability. Persist the
    // fresh probe under the registry lock (reload-modify-save) so a concurrent flip is not lost,
    // and refuse rather than bind against an un-persisted availability.
    let availability = probe_route(&route).await;
    let route = match persist_availability_locked(&st, &id, availability.clone(), None) {
        Ok(Some(route)) => route,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": { "code": "not_found", "route": id } })),
            );
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "ok": false, "code": "model_route_persistence_failed",
                    "message": "the bind-time availability probe did not commit — the session was not bound" }),
                ),
            );
        }
    };
    let state = availability
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("declared");
    if state != "available" {
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": {
                "code": "model_route_not_available",
                "message": format!("Live probe returned '{state}'; only an available route may bind a session."),
                "details": availability
            } })),
        );
    }
    match compose_mutation_admission(&route, "bind_session_route", Some(&session_ref), None) {
        Ok(admission) => {
            let binding_id = format!("mrb_{:x}", nanos());
            let route_ref = s(&route, "route_ref", "");
            let receipt = match route_receipt(
                &st.data_dir,
                &route_ref,
                "bind_session_route",
                "ok",
                admission.get("admission_id").and_then(|v| v.as_str()),
            ) {
                Ok(receipt) => receipt,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(
                            json!({ "ok": false, "code": "model_route_receipt_persistence_failed",
                            "message": "the bind receipt did not commit — the session was not bound" }),
                        ),
                    );
                }
            };
            let binding = json!({
                "schema_version": BINDING_SCHEMA,
                "binding_id": binding_id,
                "route_ref": route_ref,
                "route_id": s(&route, "route_id", ""),
                "session_ref": session_ref,
                "harness_binding_ref": opt_s(&body, "harness_binding_ref"),
                "admission_id": admission.get("admission_id"),
                "mutation_receipt_ref": admission.get("mutation_receipt_ref"),
                "receipt_ref": receipt,
                "availability_at_bind": availability,
                "model_id": route.pointer("/model/model_id"),
                "base_url": route.pointer("/provider_binding/base_url"),
                "transport": transport,
                "created_at": iso_now()
            });
            // The binding is consumed by sessions/:id/execute and guards route deletion; a 201 over
            // a discarded write hands the session a binding no execute path can find.
            if persist_record(&st.data_dir, BINDING_DIR, &binding_id, &binding).is_err() {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(
                        json!({ "ok": false, "code": "model_route_session_binding_persistence_failed",
                        "message": "the session binding did not commit — the session was not bound" }),
                    ),
                );
            }
            let transcript_run = post_op_transcript(
                &st.base_url,
                "bind_session_route",
                &route_ref,
                &json!({ "session_ref": binding["session_ref"], "binding_id": binding_id }),
            )
            .await;
            (
                StatusCode::CREATED,
                Json(json!({
                    "binding": binding,
                    "transcript_recorded": transcript_run.is_some()
                })),
            )
        }
        Err((status, body)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
            Json(body),
        ),
    }
}

/// GET /v1/hypervisor/model-route-session-bindings?session_ref=&route_ref= — binding projection.
pub(crate) async fn handle_model_route_bindings_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let mut bindings = read_record_dir(&st.data_dir, BINDING_DIR);
    if let Some(sref) = q.get("session_ref") {
        bindings.retain(|b| b.get("session_ref").and_then(|v| v.as_str()) == Some(sref.as_str()));
    }
    if let Some(rref) = q.get("route_ref") {
        bindings.retain(|b| b.get("route_ref").and_then(|v| v.as_str()) == Some(rref.as_str()));
    }
    bindings.sort_by(|a, b| s(b, "binding_id", "").cmp(&s(a, "binding_id", "")));
    Json(json!({
        "schema_version": BINDING_SCHEMA,
        "bindings": bindings,
        "at": iso_now()
    }))
}

/// Resolve the newest execution-consumable binding for a session: route must still be `active`.
/// Returns `(model_id, shim_endpoint, route_ref, binding_id)`; the shim endpoint re-appends the
/// OpenAI-compat `/v1` the stored provider root omits. Used by handle_session_execute — when this
/// returns None the execute path is byte-identical to the env-var default.
pub(crate) fn resolve_session_route_binding(
    data_dir: &str,
    session_id: &str,
) -> Option<(String, String, String, String)> {
    let mut bindings: Vec<Value> = read_record_dir(data_dir, BINDING_DIR)
        .into_iter()
        .filter(|b| {
            let sref = b.get("session_ref").and_then(|v| v.as_str()).unwrap_or("");
            sref == session_id || sref == format!("session:{session_id}")
        })
        .filter(|b| b.get("transport").and_then(|v| v.as_str()) == Some("ollama"))
        .collect();
    bindings.sort_by(|a, b| s(b, "binding_id", "").cmp(&s(a, "binding_id", "")));
    let binding = bindings.into_iter().next()?;
    let route_id = s(&binding, "route_id", "");
    let route = load_route_record(data_dir, &route_id)?;
    if route.pointer("/lifecycle/status").and_then(|v| v.as_str()) != Some("active") {
        return None;
    }
    let model_id = route
        .pointer("/model/model_id")
        .and_then(|v| v.as_str())?
        .to_string();
    let base_url = route
        .pointer("/provider_binding/base_url")
        .and_then(|v| v.as_str())?
        .trim_end_matches('/')
        .to_string();
    Some((
        model_id,
        format!("{base_url}/v1"),
        s(&binding, "route_ref", ""),
        s(&binding, "binding_id", ""),
    ))
}

#[cfg(test)]
mod model_route_tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let directory =
            std::env::temp_dir().join(format!("ioi-model-route-{tag}-{:x}", super::nanos()));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn explicit_available_route(data_dir: &str) -> Value {
        let mut route = seed_route_record();
        let custody = compose_custody_admission(&route).expect("custody admission");
        route["custody"]["custody_admission_ref"] = custody["admission_id"].clone();
        route["lifecycle"]["status"] = json!("active");
        route["availability"] = json!({
            "state":"available",
            "probe":{"kind":"test-explicit-route","at":"2026-07-30T00:00:00Z"}
        });
        route["model"]["model_id"] = json!("route-bound-model:not-env-default");
        route["provider_binding"]["base_url"] = json!("http://127.0.0.1:41199");
        super::super::durable_fs::persist_record_durable(
            data_dir,
            RECORD_DIR,
            SEED_ROUTE_ID,
            &route,
        )
        .unwrap();
        route
    }

    fn family_bytes(
        data_dir: &std::path::Path,
        family: &str,
    ) -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut files = std::collections::BTreeMap::new();
        if let Ok(entries) = std::fs::read_dir(data_dir.join(family)) {
            for entry in entries.flatten() {
                if entry.path().is_file() {
                    files.insert(
                        entry.file_name().to_string_lossy().into_owned(),
                        std::fs::read(entry.path()).unwrap(),
                    );
                }
            }
        }
        files
    }

    #[test]
    fn base_url_normalization_strips_openai_suffix() {
        assert_eq!(
            normalize_base_url("http://127.0.0.1:11434/v1"),
            "http://127.0.0.1:11434"
        );
        assert_eq!(
            normalize_base_url("http://127.0.0.1:11434/"),
            "http://127.0.0.1:11434"
        );
        assert_eq!(
            normalize_base_url("https://openrouter.ai/api/v1"),
            "https://openrouter.ai/api"
        );
    }

    #[test]
    fn ollama_availability_matches_tag_and_latest_forms() {
        let tags = vec![
            "qwen2.5:7b".to_string(),
            "qwen2.5-coder:latest".to_string(),
            "llama3.2:3b".to_string(),
        ];
        // Exact tagged match.
        assert_eq!(ollama_availability("qwen2.5:7b", &tags).0, "available");
        // Untagged declared id resolves to the catalog's `:latest` entry (the seed-default case).
        assert_eq!(ollama_availability("qwen2.5-coder", &tags).0, "available");
        // A genuinely absent tag stays model_not_present with an honest catalog count.
        let (state, evidence) = ollama_availability("qwen2.5:14b", &tags);
        assert_eq!(state, "model_not_present");
        assert_eq!(evidence["catalog_count"], 3);
    }

    #[test]
    fn tag_matches_handles_latest_equivalence_both_directions() {
        assert!(tag_matches("qwen2.5-coder", "qwen2.5-coder:latest"));
        assert!(tag_matches("qwen2.5-coder:latest", "qwen2.5-coder:latest"));
        assert!(tag_matches("qwen2.5:7b", "qwen2.5:7b"));
        // An untagged id must NOT match a different explicit tag.
        assert!(!tag_matches("qwen2.5", "qwen2.5:7b"));
    }

    #[test]
    fn seed_route_composes_real_planner_admissions() {
        let record = seed_route_record();
        let custody = compose_custody_admission(&record).expect("seed custody lane admits");
        assert!(custody["admission_id"]
            .as_str()
            .unwrap()
            .starts_with("model-weight-custody-admission:"));
        let admission = compose_mutation_admission(
            &record,
            "enable_route",
            None,
            custody["admission_id"].as_str(),
        )
        .expect("seed enable_route admits");
        assert_eq!(admission["admission_state"], "admitted_for_model_router");
        assert_eq!(admission["mutation_kind"], "enable_route");
    }

    #[test]
    fn bind_session_admission_normalizes_session_ref() {
        let record = seed_route_record();
        let custody = compose_custody_admission(&record).expect("custody");
        let admission = compose_mutation_admission(
            &record,
            "bind_session_route",
            Some("sess_abc123"),
            custody["admission_id"].as_str(),
        )
        .expect("bind admits");
        assert_eq!(admission["session_ref"], "session:sess_abc123");
    }

    #[test]
    fn credentialed_mutation_without_lease_is_rejected_by_planner() {
        let mut record = seed_route_record();
        record["credential_posture"] = json!("wallet_credential_lease");
        let custody = compose_custody_admission(&record).expect("custody");
        let err = compose_mutation_admission(
            &record,
            "enable_route",
            None,
            custody["admission_id"].as_str(),
        )
        .expect_err("missing lease must fail closed");
        assert_eq!(err.0, 403);
    }

    #[test]
    fn iso_formatter_matches_known_epoch() {
        assert_eq!(chrono_free_iso(0), "1970-01-01T00:00:00");
        assert_eq!(chrono_free_iso(1_782_998_400), "2026-07-02T13:20:00");
    }

    #[test]
    fn m4_binding_consumes_explicit_route_facts_not_environment_defaults() {
        let directory = temp_dir("explicit-binding");
        let data_dir = directory.to_str().unwrap();
        let route = explicit_available_route(data_dir);
        let session_ref = "session:goalrun-explicit-route-implementer-a";
        let binding = bind_route_for_session_recoverable(
            data_dir,
            session_ref,
            route["route_ref"].as_str().unwrap(),
            Some("hpb_test"),
            "2026-07-30T00:00:00Z",
            true,
        )
        .expect("binding commits");
        let resolved = resolve_session_route_binding_strict(
            data_dir,
            session_ref,
            route["route_ref"].as_str(),
            binding["binding_id"].as_str(),
        )
        .expect("strict binding resolves");
        assert_eq!(resolved.model_id, "route-bound-model:not-env-default");
        assert_eq!(resolved.base_url, "http://127.0.0.1:41199");
        assert_eq!(resolved.execution_endpoint, "http://127.0.0.1:41199/v1");
        assert_eq!(binding["model_id"], resolved.model_id);
        assert_eq!(binding["execution_endpoint"], resolved.execution_endpoint);
        assert!(!resolved.receipt_ref.is_empty());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn m4_binding_missing_malformed_and_duplicate_refuse_without_read_side_effects() {
        let directory = temp_dir("binding-refusals");
        let data_dir = directory.to_str().unwrap();
        let route = explicit_available_route(data_dir);
        let route_ref = route["route_ref"].as_str().unwrap();
        let session_ref = "session:goalrun-binding-refusals-implementer-a";

        let before_missing = family_bytes(&directory, BINDING_DIR);
        assert!(
            resolve_session_route_binding_strict(data_dir, session_ref, Some(route_ref), None,)
                .unwrap_err()
                .contains("exactly one")
        );
        assert_eq!(family_bytes(&directory, BINDING_DIR), before_missing);

        std::fs::create_dir_all(directory.join(BINDING_DIR)).unwrap();
        std::fs::write(
            directory.join(BINDING_DIR).join("malformed.json"),
            b"{bad-json",
        )
        .unwrap();
        let malformed_before = family_bytes(&directory, BINDING_DIR);
        assert!(
            resolve_session_route_binding_strict(data_dir, session_ref, Some(route_ref), None,)
                .unwrap_err()
                .contains("malformed")
        );
        assert_eq!(family_bytes(&directory, BINDING_DIR), malformed_before);
        std::fs::remove_file(directory.join(BINDING_DIR).join("malformed.json")).unwrap();

        let binding = bind_route_for_session_recoverable(
            data_dir,
            session_ref,
            route_ref,
            Some("hpb_test"),
            "2026-07-30T00:00:00Z",
            true,
        )
        .expect("first binding commits");
        let mut duplicate = binding.clone();
        duplicate["binding_id"] = json!(format!(
            "{}_duplicate",
            binding["binding_id"].as_str().unwrap()
        ));
        duplicate.as_object_mut().unwrap().remove("binding_root");
        duplicate["binding_root"] = json!(canonical_value_hash(&duplicate).unwrap());
        let duplicate_id = duplicate["binding_id"].as_str().unwrap().to_string();
        super::super::durable_fs::persist_record_durable(
            data_dir,
            BINDING_DIR,
            &duplicate_id,
            &duplicate,
        )
        .unwrap();
        let duplicate_before = family_bytes(&directory, BINDING_DIR);
        assert!(resolve_session_route_binding_strict(
            data_dir,
            session_ref,
            Some(route_ref),
            binding["binding_id"].as_str(),
        )
        .unwrap_err()
        .contains("exactly one"));
        assert_eq!(family_bytes(&directory, BINDING_DIR), duplicate_before);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn strict_route_census_refuses_malformed_seed_without_repairing_it() {
        let directory = temp_dir("malformed-route-seed");
        std::fs::create_dir_all(directory.join(RECORD_DIR)).unwrap();
        let slot = directory
            .join(RECORD_DIR)
            .join(format!("{SEED_ROUTE_ID}.json"));
        std::fs::write(&slot, b"{malformed-route").unwrap();
        let before = std::fs::read(&slot).unwrap();
        assert!(strict_routes_seeded(directory.to_str().unwrap())
            .unwrap_err()
            .contains("malformed"));
        assert_eq!(std::fs::read(&slot).unwrap(), before);
        let _ = std::fs::remove_dir_all(directory);
    }
}
