//! Model-route-mutation admission planner.
//!
//! A faithful Rust port of the retired JS `admitModelRouteMutation`
//! (`packages/runtime-daemon/src/runtime-model-route-mutation-admission.mjs`). This is a
//! PURE validation + canonicalization function: it asserts the caller supplied the required
//! authority / credential-posture / model-weight-custody / privacy / receipt refs (the
//! actual wallet + dcrypt enforcement happens upstream where those refs are minted), then
//! returns the canonical admission record. No state reads, no IO, no crypto here.

use std::collections::HashSet;

use serde_json::{json, Value};

pub const MODEL_ROUTE_MUTATION_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.runtime.model_route_mutation_admission.v1";

const MUTATION_KINDS: &[&str] = &[
    "select_route",
    "bind_session_route",
    "enable_route",
    "disable_route",
    "update_provider_credentials",
];

const PROVIDER_KINDS: &[&str] = &["local", "customer", "hosted_api", "tee", "provider_trust"];

const CREDENTIAL_POSTURES: &[&str] = &[
    "no_credentials_required",
    "wallet_credential_lease",
    "provider_vault_token",
    "customer_boundary",
    "unsafe_plaintext_secret",
];

const RETIRED_ALIASES: &[&str] = &[
    "routeRef",
    "sessionRef",
    "providerRef",
    "walletLeaseRef",
    "credentialLeaseRef",
    "agentgresOperationRefs",
    "receiptRefs",
    "stateRootRef",
];

/// A structured admission rejection mirroring the JS `runtimeError` shape (HTTP status +
/// code + message + details). The daemon renders it as `{error: {code, message, details}}`.
#[derive(Debug, Clone)]
pub struct RuntimeModelRouteMutationAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimeModelRouteMutationAdmissionError {
    fn new(status: u16, code: &str, message: &str, details: Value) -> Self {
        Self {
            status,
            code: code.to_string(),
            message: message.to_string(),
            details,
        }
    }
}

type AdmitResult<T> = Result<T, RuntimeModelRouteMutationAdmissionError>;

#[derive(Default)]
pub struct RuntimeModelRouteMutationAdmissionCore;

impl RuntimeModelRouteMutationAdmissionCore {
    /// Validate + canonicalize a model-route-mutation admission request. `now_iso` stamps
    /// `admitted_at` when the request omits it.
    pub fn admit(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        assert_no_retired_aliases(request)?;

        let mutation_kind = enum_value(request, "mutation_kind", MUTATION_KINDS)?;
        let route_ref = prefixed_string(request, "route_ref", "model-route:", 400)?;
        let project_ref = prefixed_string(request, "project_ref", "project:", 400)?;
        let session_ref = optional_prefixed_string(request, "session_ref", "session:")?;
        let provider_ref = prefixed_string(request, "provider_ref", "provider:", 400)?;
        let provider_kind = enum_value(request, "provider_kind", PROVIDER_KINDS)?;
        let endpoint_refs = prefixed_refs(
            request,
            "endpoint_refs",
            "model-endpoint:",
            mutation_kind == "disable_route",
        )?;
        let loaded_instance_refs =
            prefixed_refs(request, "loaded_instance_refs", "model-instance:", true)?;
        let credential_posture = enum_value(request, "credential_posture", CREDENTIAL_POSTURES)?;
        let provider_root_receives_prompt_plaintext =
            boolean_field(request, "provider_root_receives_prompt_plaintext").unwrap_or(false);
        let provider_root_receives_credential_plaintext =
            boolean_field(request, "provider_root_receives_credential_plaintext").unwrap_or(false);
        let authority_scope_refs = prefixed_refs(request, "authority_scope_refs", "scope:", false)?;
        let credential_scope_refs =
            prefixed_refs(request, "credential_scope_refs", "scope:", true)?;
        let wallet_approval_ref =
            prefixed_string(request, "wallet_approval_ref", "approval://wallet/", 403)?;
        let wallet_lease_ref = prefixed_string(request, "wallet_lease_ref", "lease:", 403)?;
        let provider_credential_lease_ref =
            optional_prefixed_string(request, "provider_credential_lease_ref", "lease:")?;
        let model_weight_custody_admission_ref =
            optional_field(request, "model_weight_custody_admission_ref");
        let privacy_posture_ref = optional_field(request, "privacy_posture_ref");
        let tee_attestation_ref = optional_field(request, "tee_attestation_ref");
        let customer_boundary_ref = optional_field(request, "customer_boundary_ref");
        let provider_trust_acceptance_ref = optional_field(request, "provider_trust_acceptance_ref");
        let secret_disclosure_receipt_refs =
            prefixed_refs(request, "secret_disclosure_receipt_refs", "receipt://", true)?;
        let agentgres_operation_refs =
            prefixed_refs(request, "agentgres_operation_refs", "agentgres://operation/", false)?;
        let receipt_refs = prefixed_refs(request, "receipt_refs", "receipt://", false)?;
        let state_root_ref =
            prefixed_string(request, "state_root_ref", "agentgres://state-root/", 400)?;

        assert_route_mutation(
            &mutation_kind,
            &provider_kind,
            &credential_posture,
            &authority_scope_refs,
            &credential_scope_refs,
            provider_credential_lease_ref.as_deref(),
            model_weight_custody_admission_ref.as_deref(),
            privacy_posture_ref.as_deref(),
            tee_attestation_ref.as_deref(),
            customer_boundary_ref.as_deref(),
            provider_trust_acceptance_ref.as_deref(),
            &secret_disclosure_receipt_refs,
            provider_root_receives_prompt_plaintext,
            provider_root_receives_credential_plaintext,
        )?;

        let admission_id = optional_field(request, "admission_id").unwrap_or_else(|| {
            format!(
                "model-route-mutation-admission:{}:{}",
                safe_id(&route_ref),
                safe_id(&mutation_kind)
            )
        });
        let mutation_receipt_ref = optional_field(request, "mutation_receipt_ref").unwrap_or_else(|| {
            format!(
                "receipt://model-route-mutation/{}/{}",
                safe_id(&route_ref),
                safe_id(&mutation_kind)
            )
        });
        let admitted_at =
            optional_field(request, "admitted_at").unwrap_or_else(|| now_iso.to_string());

        let mut all_receipt_refs = receipt_refs.clone();
        push_unique(&mut all_receipt_refs, mutation_receipt_ref);

        Ok(json!({
            "schema_version": MODEL_ROUTE_MUTATION_ADMISSION_SCHEMA_VERSION,
            "admission_id": admission_id,
            "decision": "admitted",
            "admission_state": "admitted_for_model_router",
            "mutation_kind": mutation_kind,
            "route_ref": route_ref,
            "project_ref": project_ref,
            "session_ref": session_ref,
            "provider_ref": provider_ref,
            "provider_kind": provider_kind,
            "endpoint_refs": endpoint_refs,
            "loaded_instance_refs": loaded_instance_refs,
            "credential_posture": credential_posture,
            "provider_root_receives_prompt_plaintext": provider_root_receives_prompt_plaintext,
            "provider_root_receives_credential_plaintext": provider_root_receives_credential_plaintext,
            "authority_scope_refs": authority_scope_refs,
            "credential_scope_refs": credential_scope_refs,
            "wallet_approval_ref": wallet_approval_ref,
            "wallet_lease_ref": wallet_lease_ref,
            "provider_credential_lease_ref": provider_credential_lease_ref,
            "model_weight_custody_admission_ref": model_weight_custody_admission_ref,
            "privacy_posture_ref": privacy_posture_ref,
            "tee_attestation_ref": tee_attestation_ref,
            "customer_boundary_ref": customer_boundary_ref,
            "provider_trust_acceptance_ref": provider_trust_acceptance_ref,
            "secret_disclosure_receipt_refs": secret_disclosure_receipt_refs,
            "agentgres_operation_refs": agentgres_operation_refs,
            "receipt_refs": all_receipt_refs,
            "state_root_ref": state_root_ref,
            "admitted_at": admitted_at,
            "route_mutation_invariant": "Model route mutation is daemon-admitted only after wallet authority, credential lease posture, model-weight custody admission, Agentgres operation refs, receipts, and state-root refs are bound.",
            "runtimeTruthSource": "daemon-runtime",
        }))
    }
}

#[allow(clippy::too_many_arguments)]
fn assert_route_mutation(
    mutation_kind: &str,
    provider_kind: &str,
    credential_posture: &str,
    authority_scope_refs: &[String],
    credential_scope_refs: &[String],
    provider_credential_lease_ref: Option<&str>,
    model_weight_custody_admission_ref: Option<&str>,
    privacy_posture_ref: Option<&str>,
    tee_attestation_ref: Option<&str>,
    customer_boundary_ref: Option<&str>,
    provider_trust_acceptance_ref: Option<&str>,
    secret_disclosure_receipt_refs: &[String],
    provider_root_receives_prompt_plaintext: bool,
    provider_root_receives_credential_plaintext: bool,
) -> AdmitResult<()> {
    require_scope(authority_scope_refs, "scope:model.route.mutate", mutation_kind)?;

    if mutation_kind != "disable_route"
        && !model_weight_custody_admission_ref
            .map(|value| value.starts_with("model-weight-custody-admission:"))
            .unwrap_or(false)
    {
        return Err(admission_error(
            "model_route_mutation_custody_admission_required",
            "Model route mutation requires model-weight custody admission before enabling or binding routes.",
            json!({ "mutation_kind": mutation_kind }),
        ));
    }
    if mutation_kind != "disable_route" && privacy_posture_ref.is_none() {
        return Err(admission_error(
            "model_route_mutation_privacy_posture_required",
            "Model route mutation requires an execution privacy posture ref before enabling or binding routes.",
            json!({ "mutation_kind": mutation_kind }),
        ));
    }
    if credential_posture == "wallet_credential_lease" || credential_posture == "provider_vault_token"
    {
        require_scope(credential_scope_refs, "scope:secret.use", mutation_kind)?;
        if provider_credential_lease_ref.is_none() {
            return Err(admission_error(
                "model_route_mutation_provider_credential_lease_required",
                "Model route mutation requires a wallet/provider credential lease for credentialed provider routes.",
                json!({ "credential_posture": credential_posture }),
            ));
        }
    }
    if credential_posture == "customer_boundary" && customer_boundary_ref.is_none() {
        return Err(admission_error(
            "model_route_mutation_customer_boundary_required",
            "Customer-boundary model route mutation requires a customer boundary ref.",
            json!({ "credential_posture": credential_posture }),
        ));
    }
    if provider_kind == "tee" && tee_attestation_ref.is_none() {
        return Err(admission_error(
            "model_route_mutation_tee_attestation_required",
            "TEE model route mutation requires attestation.",
            json!({ "provider_kind": provider_kind }),
        ));
    }
    if provider_kind == "provider_trust" || provider_root_receives_prompt_plaintext {
        if !provider_trust_acceptance_ref
            .map(|value| value.starts_with("approval://provider-trust/"))
            .unwrap_or(false)
        {
            return Err(admission_error(
                "model_route_mutation_provider_trust_acceptance_required",
                "Provider-trust model route mutation requires provider-trust acceptance.",
                json!({ "provider_kind": provider_kind }),
            ));
        }
    }
    if credential_posture == "unsafe_plaintext_secret" {
        require_scope(credential_scope_refs, "scope:secret.export", mutation_kind)?;
        if !provider_root_receives_credential_plaintext {
            return Err(admission_error(
                "model_route_mutation_unsafe_secret_shape_invalid",
                "Unsafe plaintext secret routes must explicitly disclose provider-root credential visibility.",
                json!({ "provider_root_receives_credential_plaintext": false }),
            ));
        }
        if secret_disclosure_receipt_refs.is_empty() {
            return Err(admission_error(
                "model_route_mutation_secret_disclosure_receipt_required",
                "Unsafe plaintext secret routes require secret disclosure receipts.",
                json!({ "required": "secret_disclosure_receipt_refs" }),
            ));
        }
        if !provider_trust_acceptance_ref
            .map(|value| value.starts_with("approval://provider-trust/"))
            .unwrap_or(false)
        {
            return Err(admission_error(
                "model_route_mutation_secret_provider_trust_acceptance_required",
                "Unsafe plaintext secret routes require provider-trust acceptance.",
                json!({ "credential_posture": credential_posture }),
            ));
        }
    }
    Ok(())
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
    Err(RuntimeModelRouteMutationAdmissionError::new(
        400,
        "model_route_mutation_request_aliases_retired",
        "Model route mutation admission accepts only canonical snake_case request fields.",
        json!({ "retired_aliases": retired }),
    ))
}

fn enum_value(request: &Value, field: &str, allowed: &[&str]) -> AdmitResult<String> {
    let normalized = optional_field(request, field);
    match normalized {
        Some(ref value) if allowed.contains(&value.as_str()) => Ok(value.clone()),
        other => Err(RuntimeModelRouteMutationAdmissionError::new(
            400,
            &format!("model_route_mutation_{field}_invalid"),
            &format!("Model route mutation admission requires a valid {field}."),
            json!({ field: other, "allowed_values": allowed }),
        )),
    }
}

fn prefixed_string(request: &Value, field: &str, prefix: &str, status: u16) -> AdmitResult<String> {
    let normalized = required_string(request, field, status)?;
    if !normalized.starts_with(prefix) {
        return Err(RuntimeModelRouteMutationAdmissionError::new(
            status,
            "model_route_mutation_ref_prefix_invalid",
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
        return Err(RuntimeModelRouteMutationAdmissionError::new(
            400,
            "model_route_mutation_ref_prefix_invalid",
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
        return Err(RuntimeModelRouteMutationAdmissionError::new(
            400,
            "model_route_mutation_required_refs_missing",
            &format!("Model route mutation admission requires {field}."),
            json!({ "field": field }),
        ));
    }
    for reference in &refs {
        if !reference.starts_with(prefix) {
            return Err(RuntimeModelRouteMutationAdmissionError::new(
                400,
                "model_route_mutation_ref_prefix_invalid",
                &format!("{field} must use {prefix} refs."),
                json!({ "field": field, "ref": reference, "expected_prefix": prefix }),
            ));
        }
    }
    Ok(refs)
}

fn required_string(request: &Value, field: &str, status: u16) -> AdmitResult<String> {
    optional_field(request, field).ok_or_else(|| {
        RuntimeModelRouteMutationAdmissionError::new(
            status,
            &format!("model_route_mutation_{field}_required"),
            &format!("Model route mutation admission requires {field}."),
            json!({ "field": field }),
        )
    })
}

fn require_scope(scope_refs: &[String], scope: &str, mutation_kind: &str) -> AdmitResult<()> {
    if scope_refs.iter().any(|value| value == scope) {
        return Ok(());
    }
    Err(admission_error(
        "model_route_mutation_required_scope_missing",
        &format!("Model route mutation admission requires {scope}."),
        json!({ "mutation_kind": mutation_kind, "required_scope": scope }),
    ))
}

fn admission_error(code: &str, message: &str, details: Value) -> RuntimeModelRouteMutationAdmissionError {
    RuntimeModelRouteMutationAdmissionError::new(403, code, message, details)
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

/// Mirror JS `booleanValue`: true/false or the "true"/"false" strings, else None.
fn boolean_field(request: &Value, field: &str) -> Option<bool> {
    match request.get(field) {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::String(value)) => match value.to_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Mirror JS `uniqueStrings(normalizeArray(value))`: dedup the truthy string items of an
/// array, preserving first-seen order.
fn unique_strings(value: Option<&Value>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let Some(Value::Array(items)) = value else {
        return out;
    };
    for item in items {
        let candidate = match item {
            Value::String(value) if !value.is_empty() => value.clone(),
            Value::Number(number) => number.to_string(),
            Value::Bool(true) => "true".to_string(),
            _ => continue,
        };
        if candidate.is_empty() {
            continue;
        }
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
    let source = if value.is_empty() { "runtime" } else { value };
    let mut out = String::with_capacity(source.len());
    let mut in_run = false;
    for ch in source.chars() {
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

    fn base_request() -> Value {
        json!({
            "mutation_kind": "bind_session_route",
            "route_ref": "model-route:local/default",
            "project_ref": "project:ioi",
            "session_ref": "session:ioi",
            "provider_ref": "provider:local",
            "provider_kind": "local",
            "endpoint_refs": ["model-endpoint:local/default"],
            "loaded_instance_refs": ["model-instance:local/default"],
            "credential_posture": "no_credentials_required",
            "provider_root_receives_prompt_plaintext": false,
            "provider_root_receives_credential_plaintext": false,
            "authority_scope_refs": ["scope:model.route.mutate"],
            "credential_scope_refs": [],
            "wallet_approval_ref": "approval://wallet/model-route/local",
            "wallet_lease_ref": "lease:wallet/model-route/local",
            "model_weight_custody_admission_ref": "model-weight-custody-admission:model-route_local_default",
            "privacy_posture_ref": "privacy-posture:private-native",
            "agentgres_operation_refs": ["agentgres://operation/model-route/local/bind-session"],
            "receipt_refs": ["receipt://model-route/local/bind-session"],
            "state_root_ref": "agentgres://state-root/model-route/local",
        })
    }

    #[test]
    fn admits_local_route_binding() {
        let admission = RuntimeModelRouteMutationAdmissionCore
            .admit(&base_request(), "2026-06-18T00:00:00.000Z")
            .expect("admitted");
        assert_eq!(admission["decision"], "admitted");
        assert_eq!(admission["admission_state"], "admitted_for_model_router");
        assert_eq!(admission["mutation_kind"], "bind_session_route");
        assert_eq!(admission["admitted_at"], "2026-06-18T00:00:00.000Z");
        assert_eq!(admission["runtimeTruthSource"], "daemon-runtime");
        let receipts = admission["receipt_refs"].as_array().expect("receipt_refs");
        assert!(receipts.iter().any(|value| value
            == "receipt://model-route-mutation/model-route_local_default/bind_session_route"));
    }

    #[test]
    fn credentialed_route_requires_secret_scope_and_lease() {
        let mut request = base_request();
        request["route_ref"] = json!("model-route:hosted/default");
        request["provider_ref"] = json!("provider:hosted-api");
        request["provider_kind"] = json!("hosted_api");
        request["endpoint_refs"] = json!(["model-endpoint:hosted/default"]);
        request["credential_posture"] = json!("wallet_credential_lease");
        request["credential_scope_refs"] = json!([]);
        let error = RuntimeModelRouteMutationAdmissionCore
            .admit(&request, "now")
            .expect_err("missing secret scope");
        assert_eq!(error.status, 403);
        assert!(error.message.contains("scope:secret.use"));

        request["credential_scope_refs"] = json!(["scope:secret.use"]);
        request["provider_credential_lease_ref"] = json!("lease:wallet/provider/openai");
        let admission = RuntimeModelRouteMutationAdmissionCore
            .admit(&request, "now")
            .expect("admitted");
        assert_eq!(
            admission["provider_credential_lease_ref"],
            "lease:wallet/provider/openai"
        );
    }

    #[test]
    fn tee_route_requires_attestation() {
        let mut request = base_request();
        request["provider_ref"] = json!("provider:tee");
        request["provider_kind"] = json!("tee");
        request["endpoint_refs"] = json!(["model-endpoint:tee/default"]);
        let error = RuntimeModelRouteMutationAdmissionCore
            .admit(&request, "now")
            .expect_err("missing attestation");
        assert!(error.message.contains("attestation"));
    }

    #[test]
    fn retired_aliases_rejected() {
        let mut request = base_request();
        request["routeRef"] = json!("model-route:local/default");
        let error = RuntimeModelRouteMutationAdmissionCore
            .admit(&request, "now")
            .expect_err("retired alias");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "model_route_mutation_request_aliases_retired");
    }
}
