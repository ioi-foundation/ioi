//! Harness-profile mutation admission planner.
//!
//! Pure validation + canonicalization (no IO) for mutations of the daemon-owned harness-profile
//! registry (enable/disable/select-default) and for binding a profile to a session for execution.
//! The daemon passes the profile's declared adapter posture and the LATEST probed runnability
//! evidence; the planner asserts the fail-closed rules — a session may bind only a profile whose
//! execution wiring is real and whose runnability probe passed, and enabling/selecting a
//! non-local-trust adapter requires an explicit provider-trust acceptance. Runnability itself is
//! IO-truth probed by the daemon; here it is bound evidence, never fabricated.

use serde_json::{json, Value};
use std::collections::HashSet;

pub const HARNESS_PROFILE_MUTATION_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.runtime.harness_profile_mutation_admission.v1";

const MUTATION_KINDS: &[&str] = &[
    "enable_profile",
    "disable_profile",
    "select_profile",
    "bind_session_profile",
];

const ADAPTER_KINDS: &[&str] = &["native_worker", "cli_shim", "cli_binary", "terminal_shell"];

const EXECUTION_WIRINGS: &[&str] = &["lane_a_host_spawn", "terminal_pty", "adapter_slot_unwired"];

const PROVIDER_TRUST: &[&str] = &["local", "remote", "remote_attested"];

const RUNNABILITY_STATES: &[&str] = &[
    "runnable",
    "binary_missing",
    "shim_missing",
    "model_route_unreachable",
    "not_probed",
];

const RETIRED_ALIASES: &[&str] = &[
    "profileRef",
    "sessionRef",
    "modelRouteRef",
    "agentgresOperationRefs",
    "receiptRefs",
    "stateRootRef",
];

/// Structured admission rejection (HTTP status + code + message + details); the daemon renders it
/// as `{error: {code, message, details}}`.
#[derive(Debug, Clone)]
pub struct RuntimeHarnessProfileMutationAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimeHarnessProfileMutationAdmissionError {
    fn new(status: u16, code: &str, message: &str, details: Value) -> Self {
        Self {
            status,
            code: code.to_string(),
            message: message.to_string(),
            details,
        }
    }
}

type AdmitResult<T> = Result<T, RuntimeHarnessProfileMutationAdmissionError>;

#[derive(Default)]
pub struct RuntimeHarnessProfileMutationAdmissionCore;

impl RuntimeHarnessProfileMutationAdmissionCore {
    /// Validate + canonicalize a harness-profile-mutation admission request. `now_iso` stamps
    /// `admitted_at` when the request omits it.
    pub fn admit(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        assert_no_retired_aliases(request)?;

        let mutation_kind = enum_value(request, "mutation_kind", MUTATION_KINDS)?;
        let profile_ref = prefixed_string(request, "profile_ref", "harness-profile:")?;
        let project_ref = prefixed_string(request, "project_ref", "project:")?;
        let session_ref = optional_prefixed_string(request, "session_ref", "session:")?;
        let model_route_ref = optional_prefixed_string(request, "model_route_ref", "model-route:")?;
        let adapter_kind = enum_value(request, "adapter_kind", ADAPTER_KINDS)?;
        let execution_wiring = enum_value(request, "execution_wiring", EXECUTION_WIRINGS)?;
        let provider_trust = enum_value(request, "provider_trust", PROVIDER_TRUST)?;
        let runnability_state = enum_value(request, "runnability_state", RUNNABILITY_STATES)?;
        let provider_trust_acceptance_ref = optional_prefixed_string(
            request,
            "provider_trust_acceptance_ref",
            "approval://provider-trust/",
        )?;
        let authority_scope_refs = prefixed_refs(request, "authority_scope_refs", "scope:", false)?;
        let agentgres_operation_refs = prefixed_refs(
            request,
            "agentgres_operation_refs",
            "agentgres://operation/",
            false,
        )?;
        let receipt_refs = prefixed_refs(request, "receipt_refs", "receipt://", false)?;
        let state_root_ref = prefixed_string(request, "state_root_ref", "agentgres://state-root/")?;

        require_scope(
            &authority_scope_refs,
            "scope:harness.profile.mutate",
            &mutation_kind,
        )?;

        // Enabling or selecting an adapter whose provider trust leaves the local boundary requires
        // an explicit provider-trust acceptance (disable is always the relaxed lane).
        if matches!(mutation_kind.as_str(), "enable_profile" | "select_profile")
            && provider_trust != "local"
            && provider_trust_acceptance_ref.is_none()
        {
            return Err(admission_error(
                "harness_profile_mutation_provider_trust_acceptance_required",
                "Enabling or selecting a non-local-trust harness adapter requires provider-trust acceptance.",
                json!({ "mutation_kind": mutation_kind, "provider_trust": provider_trust }),
            ));
        }

        if mutation_kind == "bind_session_profile" {
            if session_ref.is_none() {
                return Err(admission_error(
                    "harness_profile_mutation_session_ref_required",
                    "Binding a harness profile to a session requires session_ref.",
                    json!({ "mutation_kind": mutation_kind }),
                ));
            }
            if model_route_ref.is_none() {
                return Err(admission_error(
                    "harness_profile_mutation_model_route_ref_required",
                    "Binding a harness profile to a session requires the model route it executes over.",
                    json!({ "mutation_kind": mutation_kind }),
                ));
            }
            if execution_wiring == "adapter_slot_unwired" {
                return Err(admission_error(
                    "harness_profile_mutation_execution_unwired",
                    "An adapter-slot profile has no wired execution lane; it cannot be bound to a session for execution.",
                    json!({ "profile_ref": profile_ref, "execution_wiring": execution_wiring }),
                ));
            }
            if runnability_state != "runnable" {
                return Err(admission_error(
                    "harness_profile_mutation_not_runnable",
                    "A harness profile binds to a session only when its latest runnability probe passed.",
                    json!({ "profile_ref": profile_ref, "runnability_state": runnability_state }),
                ));
            }
        }

        let admission_id = optional_field(request, "admission_id").unwrap_or_else(|| {
            format!(
                "harness-profile-mutation-admission:{}:{}",
                safe_id(&profile_ref),
                safe_id(&mutation_kind)
            )
        });
        let mutation_receipt_ref =
            optional_field(request, "mutation_receipt_ref").unwrap_or_else(|| {
                format!(
                    "receipt://harness-profile-mutation/{}/{}",
                    safe_id(&profile_ref),
                    safe_id(&mutation_kind)
                )
            });
        let admitted_at =
            optional_field(request, "admitted_at").unwrap_or_else(|| now_iso.to_string());

        let mut all_receipt_refs = receipt_refs.clone();
        push_unique(&mut all_receipt_refs, mutation_receipt_ref);

        Ok(json!({
            "schema_version": HARNESS_PROFILE_MUTATION_ADMISSION_SCHEMA_VERSION,
            "admission_id": admission_id,
            "decision": "admitted",
            "admission_state": "admitted_for_harness_registry",
            "mutation_kind": mutation_kind,
            "profile_ref": profile_ref,
            "project_ref": project_ref,
            "session_ref": session_ref,
            "model_route_ref": model_route_ref,
            "adapter_kind": adapter_kind,
            "execution_wiring": execution_wiring,
            "provider_trust": provider_trust,
            "runnability_state": runnability_state,
            "provider_trust_acceptance_ref": provider_trust_acceptance_ref,
            "authority_scope_refs": authority_scope_refs,
            "agentgres_operation_refs": agentgres_operation_refs,
            "receipt_refs": all_receipt_refs,
            "state_root_ref": state_root_ref,
            "admitted_at": admitted_at,
            "profile_mutation_invariant": "Harness profile mutation is daemon-admitted only after the harness authority scope, adapter posture, provider-trust acceptance (non-local trust), Agentgres operation refs, receipts, and state-root refs are bound; session binding additionally requires a wired execution lane, a passing runnability probe, and the model route it executes over.",
            "runtimeTruthSource": "daemon-runtime",
        }))
    }
}

fn assert_no_retired_aliases(request: &Value) -> AdmitResult<()> {
    let Some(object) = request.as_object() else {
        return Ok(());
    };
    let retired: Vec<String> = RETIRED_ALIASES
        .iter()
        .filter(|alias| object.contains_key(**alias))
        .map(|alias| alias.to_string())
        .collect();
    if retired.is_empty() {
        return Ok(());
    }
    Err(RuntimeHarnessProfileMutationAdmissionError::new(
        400,
        "harness_profile_mutation_request_aliases_retired",
        "Harness profile mutation admission accepts only canonical snake_case request fields.",
        json!({ "retired_aliases": retired }),
    ))
}

fn admission_error(
    code: &str,
    message: &str,
    details: Value,
) -> RuntimeHarnessProfileMutationAdmissionError {
    RuntimeHarnessProfileMutationAdmissionError::new(403, code, message, details)
}

fn enum_value(request: &Value, field: &str, allowed: &[&str]) -> AdmitResult<String> {
    let normalized = optional_field(request, field);
    match normalized {
        Some(ref value) if allowed.contains(&value.as_str()) => Ok(value.clone()),
        other => Err(RuntimeHarnessProfileMutationAdmissionError::new(
            400,
            &format!("harness_profile_mutation_{field}_invalid"),
            &format!("Harness profile mutation admission requires a valid {field}."),
            json!({ field: other, "allowed_values": allowed }),
        )),
    }
}

fn prefixed_string(request: &Value, field: &str, prefix: &str) -> AdmitResult<String> {
    let normalized = optional_field(request, field).ok_or_else(|| {
        RuntimeHarnessProfileMutationAdmissionError::new(
            400,
            &format!("harness_profile_mutation_{field}_required"),
            &format!("Harness profile mutation admission requires {field}."),
            json!({ "field": field }),
        )
    })?;
    if !normalized.starts_with(prefix) {
        return Err(RuntimeHarnessProfileMutationAdmissionError::new(
            400,
            "harness_profile_mutation_ref_prefix_invalid",
            &format!("{field} must use {prefix} refs."),
            json!({ "field": field, "ref": normalized, "expected_prefix": prefix }),
        ));
    }
    Ok(normalized)
}

fn optional_prefixed_string(
    request: &Value,
    field: &str,
    prefix: &str,
) -> AdmitResult<Option<String>> {
    let Some(normalized) = optional_field(request, field) else {
        return Ok(None);
    };
    if !normalized.starts_with(prefix) {
        return Err(RuntimeHarnessProfileMutationAdmissionError::new(
            400,
            "harness_profile_mutation_ref_prefix_invalid",
            &format!("{field} must use {prefix} refs."),
            json!({ "field": field, "ref": normalized, "expected_prefix": prefix }),
        ));
    }
    Ok(Some(normalized))
}

fn prefixed_refs(
    request: &Value,
    field: &str,
    prefix: &str,
    allow_empty: bool,
) -> AdmitResult<Vec<String>> {
    let refs = unique_strings(request.get(field));
    if !allow_empty && refs.is_empty() {
        return Err(RuntimeHarnessProfileMutationAdmissionError::new(
            400,
            "harness_profile_mutation_required_refs_missing",
            &format!("Harness profile mutation admission requires {field}."),
            json!({ "field": field }),
        ));
    }
    for reference in &refs {
        if !reference.starts_with(prefix) {
            return Err(RuntimeHarnessProfileMutationAdmissionError::new(
                400,
                "harness_profile_mutation_ref_prefix_invalid",
                &format!("{field} must use {prefix} refs."),
                json!({ "field": field, "ref": reference, "expected_prefix": prefix }),
            ));
        }
    }
    Ok(refs)
}

fn require_scope(scope_refs: &[String], scope: &str, mutation_kind: &str) -> AdmitResult<()> {
    if scope_refs.iter().any(|value| value == scope) {
        return Ok(());
    }
    Err(admission_error(
        "harness_profile_mutation_required_scope_missing",
        &format!("Harness profile mutation admission requires {scope}."),
        json!({ "mutation_kind": mutation_kind, "required_scope": scope }),
    ))
}

/// Mirror JS `optionalString`: trim a string field, returning None when absent/blank.
fn optional_field(request: &Value, field: &str) -> Option<String> {
    match request.get(field) {
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Some(Value::Number(number)) => Some(number.to_string()),
        Some(Value::Bool(value)) => Some(value.to_string()),
        _ => None,
    }
}

/// Mirror JS `uniqueStrings(normalizeArray(value))`: dedup the truthy string items of an array,
/// preserving first-seen order.
fn unique_strings(value: Option<&Value>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let Some(Value::Array(items)) = value else {
        return out;
    };
    for item in items {
        let candidate = match item {
            Value::String(value) if !value.is_empty() => value.clone(),
            Value::Number(number) if number.as_f64() != Some(0.0) => number.to_string(),
            Value::Bool(true) => "true".to_string(),
            _ => continue,
        };
        if seen.insert(candidate.clone()) {
            out.push(candidate);
        }
    }
    out
}

fn push_unique(refs: &mut Vec<String>, candidate: String) {
    if !candidate.is_empty() && !refs.iter().any(|value| value == &candidate) {
        refs.push(candidate);
    }
}

/// Mirror JS `safeId`: collapse runs of characters outside [A-Za-z0-9_.-] to a single `_`.
fn safe_id(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_was_sep = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' || ch == '-' {
            out.push(ch);
            last_was_sep = false;
        } else if !last_was_sep {
            out.push('_');
            last_was_sep = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request(mutation_kind: &str) -> Value {
        json!({
            "mutation_kind": mutation_kind,
            "profile_ref": "harness-profile:hypervisor_worker",
            "project_ref": "project:hypervisor",
            "adapter_kind": "native_worker",
            "execution_wiring": "lane_a_host_spawn",
            "provider_trust": "local",
            "runnability_state": "runnable",
            "authority_scope_refs": ["scope:harness.profile.mutate"],
            "agentgres_operation_refs": ["agentgres://operation/harness-profile/hypervisor_worker/enable"],
            "receipt_refs": ["receipt://harness-profile/hypervisor_worker/enable"],
            "state_root_ref": "agentgres://state-root/harness-profile/hypervisor_worker",
        })
    }

    #[test]
    fn admits_local_enable() {
        let admitted = RuntimeHarnessProfileMutationAdmissionCore
            .admit(&base_request("enable_profile"), "2026-07-02T00:00:00Z")
            .expect("local enable admits");
        assert_eq!(admitted["decision"], "admitted");
        assert_eq!(
            admitted["admission_id"],
            "harness-profile-mutation-admission:harness-profile_hypervisor_worker:enable_profile"
        );
        assert!(admitted["receipt_refs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r
                .as_str()
                .unwrap()
                .starts_with("receipt://harness-profile-mutation/")));
    }

    #[test]
    fn rejects_missing_mutate_scope() {
        let mut request = base_request("enable_profile");
        request["authority_scope_refs"] = json!(["scope:workspace.read"]);
        let error = RuntimeHarnessProfileMutationAdmissionCore
            .admit(&request, "2026-07-02T00:00:00Z")
            .unwrap_err();
        assert_eq!(error.status, 403);
        assert_eq!(
            error.code,
            "harness_profile_mutation_required_scope_missing"
        );
    }

    #[test]
    fn rejects_remote_enable_without_trust_acceptance() {
        let mut request = base_request("enable_profile");
        request["provider_trust"] = json!("remote_attested");
        let error = RuntimeHarnessProfileMutationAdmissionCore
            .admit(&request, "2026-07-02T00:00:00Z")
            .unwrap_err();
        assert_eq!(error.status, 403);
        assert_eq!(
            error.code,
            "harness_profile_mutation_provider_trust_acceptance_required"
        );
        request["provider_trust_acceptance_ref"] = json!("approval://provider-trust/claude_code");
        RuntimeHarnessProfileMutationAdmissionCore
            .admit(&request, "2026-07-02T00:00:00Z")
            .expect("remote enable admits with trust acceptance");
    }

    #[test]
    fn disable_is_relaxed_for_remote_trust() {
        let mut request = base_request("disable_profile");
        request["provider_trust"] = json!("remote");
        RuntimeHarnessProfileMutationAdmissionCore
            .admit(&request, "2026-07-02T00:00:00Z")
            .expect("remote disable is the relaxed lane");
    }

    #[test]
    fn bind_session_requires_wired_runnable_profile_and_route() {
        let mut request = base_request("bind_session_profile");
        let error = RuntimeHarnessProfileMutationAdmissionCore
            .admit(&request, "2026-07-02T00:00:00Z")
            .unwrap_err();
        assert_eq!(error.code, "harness_profile_mutation_session_ref_required");

        request["session_ref"] = json!("session:hyp-abc");
        let error = RuntimeHarnessProfileMutationAdmissionCore
            .admit(&request, "2026-07-02T00:00:00Z")
            .unwrap_err();
        assert_eq!(
            error.code,
            "harness_profile_mutation_model_route_ref_required"
        );

        request["model_route_ref"] = json!("model-route:mrt_local_default");
        request["execution_wiring"] = json!("adapter_slot_unwired");
        let error = RuntimeHarnessProfileMutationAdmissionCore
            .admit(&request, "2026-07-02T00:00:00Z")
            .unwrap_err();
        assert_eq!(error.code, "harness_profile_mutation_execution_unwired");

        request["execution_wiring"] = json!("lane_a_host_spawn");
        request["runnability_state"] = json!("binary_missing");
        let error = RuntimeHarnessProfileMutationAdmissionCore
            .admit(&request, "2026-07-02T00:00:00Z")
            .unwrap_err();
        assert_eq!(error.code, "harness_profile_mutation_not_runnable");

        request["runnability_state"] = json!("runnable");
        let admitted = RuntimeHarnessProfileMutationAdmissionCore
            .admit(&request, "2026-07-02T00:00:00Z")
            .expect("wired runnable bind admits");
        assert_eq!(admitted["session_ref"], "session:hyp-abc");
        assert_eq!(admitted["model_route_ref"], "model-route:mrt_local_default");
    }

    #[test]
    fn rejects_retired_camel_case_aliases() {
        let mut request = base_request("enable_profile");
        request["profileRef"] = json!("harness-profile:x");
        let error = RuntimeHarnessProfileMutationAdmissionCore
            .admit(&request, "2026-07-02T00:00:00Z")
            .unwrap_err();
        assert_eq!(error.status, 400);
        assert_eq!(
            error.code,
            "harness_profile_mutation_request_aliases_retired"
        );
    }
}
