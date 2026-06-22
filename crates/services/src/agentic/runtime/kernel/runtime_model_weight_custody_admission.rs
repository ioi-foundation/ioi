//! Model-weight-custody admission planner.
//!
//! A faithful Rust port of the retired JS `admitModelWeightCustodyRoute`
//! (`packages/runtime-daemon/src/runtime-model-weight-custody-admission.mjs`). Pure
//! validation + canonicalization: asserts the weight-class / mount-target / execution-
//! privacy lane is admissible and the required controls + authority scopes + attestation /
//! customer-boundary / provider-trust refs are bound, then returns the admission record.
//!
//! Note vs the model-route-mutation port: this module's JS uses a LOCAL `uniqueStrings`
//! that trims each item, and `optionalString`/`String()` coerce non-scalars — so the
//! helpers here use `js_string_coerce` to replicate JS `String(value)` exactly.

use std::collections::HashSet;

use serde_json::{json, Value};

pub const MODEL_WEIGHT_CUSTODY_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.runtime.model_weight_custody_admission.v1";

const WEIGHT_CLASSES: &[&str] = &[
    "public_open_weight",
    "user_local_private_weight",
    "remote_api_private_weight",
    "provider_trust_remote_mount",
    "tee_or_customer_cloud_mount",
    "forbidden_plaintext_mount",
];

const MOUNT_TARGETS: &[&str] = &[
    "local_device",
    "user_owned_node",
    "rented_gpu",
    "customer_cloud",
    "provider_api",
    "tee_session",
    "none",
];

const EXECUTION_PRIVACY_POSTURES: &[&str] = &[
    "private_native",
    "ctee_split",
    "encrypted_storage_only",
    "confidential_compute",
    "remote_api_provider_trust",
    "unsafe_plaintext_mount",
];

const RETIRED_ALIASES: &[&str] = &["modelWeightCustodyProfile", "remoteProviderCanReadWeights"];

#[derive(Debug, Clone)]
pub struct RuntimeModelWeightCustodyAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimeModelWeightCustodyAdmissionError {
    fn new(status: u16, code: &str, message: &str, details: Value) -> Self {
        Self { status, code: code.to_string(), message: message.to_string(), details }
    }
}

type AdmitResult<T> = Result<T, RuntimeModelWeightCustodyAdmissionError>;

#[derive(Default)]
pub struct RuntimeModelWeightCustodyAdmissionCore;

impl RuntimeModelWeightCustodyAdmissionCore {
    pub fn admit(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        // Field extraction first (in JS order), then the retired-alias guard, then the lane
        // assertion — so a malformed field error wins over a retired-alias error.
        let route_ref = required_string(request, "route_ref")?;
        let model_ref = required_string(request, "model_ref")?;
        let provider_ref =
            optional_field(request, "provider_ref").unwrap_or_else(|| "provider:unspecified".to_string());
        let weight_class = enum_value(request, "weight_class", WEIGHT_CLASSES)?;
        let mount_target = enum_value(request, "mount_target", MOUNT_TARGETS)?;
        let execution_privacy_posture =
            enum_value(request, "execution_privacy_posture", EXECUTION_PRIVACY_POSTURES)?;
        let remote_provider_can_read_weights =
            boolean_field(request, "remote_provider_can_read_weights").unwrap_or(false);
        let authority_scope_refs = unique_scope_refs(request.get("authority_scope_refs"))?;
        let required_controls = unique_strings(&normalize_array(request.get("required_controls")));
        let disclosure_ref = optional_field(request, "user_disclosure_ref");
        let provider_trust_acceptance_ref = optional_field(request, "provider_trust_acceptance_ref");
        let tee_attestation_ref = optional_field(request, "tee_attestation_ref");
        let customer_boundary_ref = optional_field(request, "customer_boundary_ref");

        assert_no_retired_aliases(request)?;
        assert_weight_lane_admission(
            &weight_class,
            &mount_target,
            &execution_privacy_posture,
            remote_provider_can_read_weights,
            &authority_scope_refs,
            &required_controls,
            disclosure_ref.as_deref(),
            provider_trust_acceptance_ref.as_deref(),
            tee_attestation_ref.as_deref(),
            customer_boundary_ref.as_deref(),
        )?;

        let decision = if weight_class == "provider_trust_remote_mount" {
            "admitted_provider_trust"
        } else {
            "admitted"
        };

        let admission_id = optional_field(request, "admission_id").unwrap_or_else(|| {
            format!(
                "model-weight-custody-admission:{}:{}",
                safe_id(&route_ref),
                safe_id(&weight_class)
            )
        });
        let receipt_ref = optional_field(request, "receipt_ref").unwrap_or_else(|| {
            format!(
                "receipt://model-weight-custody/{}/{}",
                safe_id(&route_ref),
                safe_id(&weight_class)
            )
        });
        let admitted_at =
            optional_field(request, "admitted_at").unwrap_or_else(|| now_iso.to_string());

        Ok(json!({
            "schema_version": MODEL_WEIGHT_CUSTODY_ADMISSION_SCHEMA_VERSION,
            "admission_id": admission_id,
            "route_ref": route_ref,
            "model_ref": model_ref,
            "provider_ref": provider_ref,
            "decision": decision,
            "weight_class": weight_class,
            "mount_target": mount_target,
            "execution_privacy_posture": execution_privacy_posture,
            "remote_provider_can_read_weights": remote_provider_can_read_weights,
            "protects_model_weights_from_provider_root": protects_model_weights_from_provider_root(&weight_class),
            "protects_workspace_state": protects_workspace_state(&execution_privacy_posture),
            "required_controls": required_controls,
            "authority_scope_refs": authority_scope_refs,
            "user_disclosure_ref": disclosure_ref,
            "provider_trust_acceptance_ref": provider_trust_acceptance_ref,
            "tee_attestation_ref": tee_attestation_ref,
            "customer_boundary_ref": customer_boundary_ref,
            "agentgres_operation_refs": normalize_array(request.get("agentgres_operation_refs")),
            "artifact_refs": normalize_array(request.get("artifact_refs")),
            "receipt_ref": receipt_ref,
            "admitted_at": admitted_at,
            "runtimeTruthSource": "daemon-runtime",
        }))
    }
}

#[allow(clippy::too_many_arguments)]
fn assert_weight_lane_admission(
    weight_class: &str,
    mount_target: &str,
    execution_privacy_posture: &str,
    remote_provider_can_read_weights: bool,
    authority_scope_refs: &[String],
    required_controls: &[String],
    disclosure_ref: Option<&str>,
    provider_trust_acceptance_ref: Option<&str>,
    tee_attestation_ref: Option<&str>,
    customer_boundary_ref: Option<&str>,
) -> AdmitResult<()> {
    if weight_class == "forbidden_plaintext_mount" {
        return Err(admission_error(
            "model_weight_custody_forbidden_plaintext_mount_blocked",
            "Model-weight custody admission blocks forbidden plaintext mounts by default.",
            json!({ "weight_class": weight_class, "mount_target": mount_target }),
        ));
    }
    if remote_provider_can_read_weights
        && weight_class != "public_open_weight"
        && weight_class != "provider_trust_remote_mount"
    {
        return Err(admission_error(
            "model_weight_custody_plaintext_private_weight_blocked",
            "Private model weights cannot be mounted where a remote provider can read them unless the route is explicit provider trust.",
            json!({ "weight_class": weight_class, "mount_target": mount_target }),
        ));
    }
    if execution_privacy_posture == "private_native"
        && (remote_provider_can_read_weights || weight_class == "provider_trust_remote_mount")
    {
        return Err(admission_error(
            "model_weight_custody_private_native_claim_invalid",
            "Provider-readable or provider-trust model-weight routes cannot be presented as private-native.",
            json!({ "weight_class": weight_class, "execution_privacy_posture": execution_privacy_posture }),
        ));
    }
    if weight_class == "user_local_private_weight" {
        if mount_target != "local_device" && mount_target != "user_owned_node" {
            return Err(admission_error(
                "model_weight_custody_user_local_mount_target_invalid",
                "User-local private weights must stay on a local device or user-owned node.",
                json!({ "mount_target": mount_target }),
            ));
        }
        require_control(required_controls, "local_only", weight_class)?;
    }
    if weight_class == "remote_api_private_weight" {
        if mount_target != "provider_api" {
            return Err(admission_error(
                "model_weight_custody_remote_api_target_invalid",
                "Remote API private-weight routes must use a provider_api mount target.",
                json!({ "mount_target": mount_target }),
            ));
        }
        require_control(required_controls, "wallet_authorized_api_capability", weight_class)?;
        require_scope(authority_scope_refs, "scope:model.invoke_remote", weight_class)?;
    }
    if weight_class == "tee_or_customer_cloud_mount" {
        if mount_target != "tee_session"
            && mount_target != "customer_cloud"
            && mount_target != "user_owned_node"
        {
            return Err(admission_error(
                "model_weight_custody_confidential_target_invalid",
                "TEE/customer-cloud model-weight mounts require a TEE session, customer cloud, or user-owned node target.",
                json!({ "mount_target": mount_target }),
            ));
        }
        if tee_attestation_ref.is_none() && customer_boundary_ref.is_none() {
            return Err(admission_error(
                "model_weight_custody_attestation_or_customer_boundary_required",
                "TEE/customer-cloud model-weight mounts require attestation or a customer-boundary reference.",
                json!({ "required": ["tee_attestation_ref", "customer_boundary_ref"] }),
            ));
        }
        if tee_attestation_ref.is_some() {
            require_control(required_controls, "tee_attestation", weight_class)?;
        }
        if customer_boundary_ref.is_some() {
            require_control(required_controls, "customer_account_boundary", weight_class)?;
        }
    }
    if weight_class == "provider_trust_remote_mount" {
        if !remote_provider_can_read_weights {
            return Err(admission_error(
                "model_weight_custody_provider_trust_requires_provider_readable",
                "Provider-trust model-weight mounts must explicitly disclose provider-readable weights.",
                json!({ "remote_provider_can_read_weights": false }),
            ));
        }
        if provider_trust_acceptance_ref.is_none() || disclosure_ref.is_none() {
            return Err(admission_error(
                "model_weight_custody_provider_trust_acceptance_required",
                "Provider-trust model-weight mounts require explicit user disclosure and provider-trust acceptance.",
                json!({ "required": ["user_disclosure_ref", "provider_trust_acceptance_ref"] }),
            ));
        }
        require_control(required_controls, "explicit_provider_trust_acceptance", weight_class)?;
        require_scope(authority_scope_refs, "scope:provider.trust_override", weight_class)?;
    }
    Ok(())
}

fn protects_model_weights_from_provider_root(weight_class: &str) -> bool {
    matches!(
        weight_class,
        "public_open_weight"
            | "user_local_private_weight"
            | "remote_api_private_weight"
            | "tee_or_customer_cloud_mount"
    )
}

fn protects_workspace_state(posture: &str) -> bool {
    matches!(posture, "private_native" | "ctee_split" | "confidential_compute")
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
    Err(RuntimeModelWeightCustodyAdmissionError::new(
        400,
        "model_weight_custody_request_aliases_retired",
        "Model-weight custody admission accepts only canonical snake_case request fields.",
        json!({ "retired_aliases": retired }),
    ))
}

fn unique_scope_refs(value: Option<&Value>) -> AdmitResult<Vec<String>> {
    let scopes = unique_strings(&normalize_array(value));
    for scope in &scopes {
        if !scope.starts_with("scope:") {
            return Err(RuntimeModelWeightCustodyAdmissionError::new(
                400,
                "model_weight_custody_scope_invalid",
                "Model-weight custody authority scopes must use scope:* refs.",
                json!({ "scope": scope }),
            ));
        }
    }
    Ok(scopes)
}

fn enum_value(request: &Value, field: &str, allowed: &[&str]) -> AdmitResult<String> {
    let normalized = optional_field(request, field);
    match normalized {
        Some(ref value) if allowed.contains(&value.as_str()) => Ok(value.clone()),
        other => Err(RuntimeModelWeightCustodyAdmissionError::new(
            400,
            &format!("model_weight_custody_{field}_invalid"),
            &format!("Model-weight custody admission requires a valid {field}."),
            json!({ field: other, "allowed_values": allowed }),
        )),
    }
}

fn required_string(request: &Value, field: &str) -> AdmitResult<String> {
    optional_field(request, field).ok_or_else(|| {
        RuntimeModelWeightCustodyAdmissionError::new(
            400,
            &format!("model_weight_custody_{field}_required"),
            &format!("Model-weight custody admission requires {field}."),
            json!({ "field": field }),
        )
    })
}

fn require_control(required_controls: &[String], control: &str, weight_class: &str) -> AdmitResult<()> {
    if required_controls.iter().any(|value| value == control) {
        return Ok(());
    }
    Err(admission_error(
        "model_weight_custody_required_control_missing",
        "Model-weight custody admission is missing a required control.",
        json!({ "weight_class": weight_class, "required_control": control }),
    ))
}

fn require_scope(authority_scope_refs: &[String], scope: &str, weight_class: &str) -> AdmitResult<()> {
    if authority_scope_refs.iter().any(|value| value == scope) {
        return Ok(());
    }
    Err(admission_error(
        "model_weight_custody_required_scope_missing",
        "Model-weight custody admission is missing a required authority scope.",
        json!({ "weight_class": weight_class, "required_scope": scope }),
    ))
}

fn admission_error(code: &str, message: &str, details: Value) -> RuntimeModelWeightCustodyAdmissionError {
    RuntimeModelWeightCustodyAdmissionError::new(403, code, message, details)
}

/// Mirror JS `optionalString`: String(value).trim(), None when null/absent/blank. Non-scalar
/// values are coerced via js_string_coerce exactly like JS String().
fn optional_field(request: &Value, field: &str) -> Option<String> {
    match request.get(field) {
        None | Some(Value::Null) => None,
        Some(value) => {
            let coerced = js_string_coerce(value);
            let trimmed = coerced.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
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

/// Mirror JS `normalizeArray`: Array.isArray ? value.filter(Boolean) : [] — keep the truthy
/// RAW items (objects/arrays survive, as in JS).
fn normalize_array(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(items)) => items.iter().filter(|item| is_truthy(item)).cloned().collect(),
        _ => Vec::new(),
    }
}

/// Mirror this module's LOCAL `uniqueStrings`: values.map(v => String(v).trim()).filter(Boolean),
/// deduped, first-seen order. Input is an already-normalized (truthy) array of raw values.
fn unique_strings(values: &[Value]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        let trimmed = js_string_coerce(value).trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.clone()) {
            out.push(trimmed);
        }
    }
    out
}

/// JS truthiness for filter(Boolean): null/false/0/""/NaN are falsy; objects+arrays truthy.
fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(boolean) => *boolean,
        Value::Number(number) => number.as_f64().map(|float| float != 0.0).unwrap_or(false),
        Value::String(string) => !string.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// Mirror JS `String(value)` for the value shapes that can appear in a ref array / scalar
/// field: scalars exactly; arrays comma-join their (string-coerced) elements with null/
/// undefined rendered empty; objects → "[object Object]".
fn js_string_coerce(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(boolean) => boolean.to_string(),
        Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                int.to_string()
            } else if let Some(uint) = number.as_u64() {
                uint.to_string()
            } else {
                number.as_f64().map(|float| float.to_string()).unwrap_or_default()
            }
        }
        Value::String(string) => string.clone(),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Null => String::new(),
                other => js_string_coerce(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

/// Mirror JS `safeId`: collapse runs of characters outside [A-Za-z0-9_.-] to a single `_`.
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

    fn base_request() -> Value {
        json!({
            "route_ref": "model-route:local/default",
            "model_ref": "model:local/qwen",
            "weight_class": "user_local_private_weight",
            "mount_target": "local_device",
            "execution_privacy_posture": "private_native",
            "remote_provider_can_read_weights": false,
            "authority_scope_refs": ["scope:model.mount"],
            "required_controls": ["local_only"],
        })
    }

    #[test]
    fn admits_user_local_private_weight() {
        let admission = RuntimeModelWeightCustodyAdmissionCore
            .admit(&base_request(), "2026-06-18T00:00:00.000Z")
            .expect("admitted");
        assert_eq!(admission["decision"], "admitted");
        assert_eq!(admission["weight_class"], "user_local_private_weight");
        assert_eq!(admission["protects_model_weights_from_provider_root"], true);
        assert_eq!(admission["protects_workspace_state"], true);
        assert_eq!(admission["provider_ref"], "provider:unspecified");
        assert_eq!(admission["admitted_at"], "2026-06-18T00:00:00.000Z");
        assert!(admission["receipt_ref"]
            .as_str()
            .unwrap()
            .starts_with("receipt://model-weight-custody/model-route_local_default/"));
    }

    #[test]
    fn blocks_forbidden_plaintext_mount() {
        let mut request = base_request();
        request["weight_class"] = json!("forbidden_plaintext_mount");
        let error = RuntimeModelWeightCustodyAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 403);
        assert_eq!(error.code, "model_weight_custody_forbidden_plaintext_mount_blocked");
    }

    #[test]
    fn blocks_provider_readable_private_weight() {
        let mut request = base_request();
        request["weight_class"] = json!("remote_api_private_weight");
        request["mount_target"] = json!("provider_api");
        request["execution_privacy_posture"] = json!("remote_api_provider_trust");
        request["remote_provider_can_read_weights"] = json!(true);
        request["required_controls"] = json!(["wallet_authorized_api_capability"]);
        request["authority_scope_refs"] = json!(["scope:model.invoke_remote"]);
        let error = RuntimeModelWeightCustodyAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.code, "model_weight_custody_plaintext_private_weight_blocked");
    }

    #[test]
    fn user_local_requires_local_only_control() {
        let mut request = base_request();
        request["required_controls"] = json!([]);
        let error = RuntimeModelWeightCustodyAdmissionCore
            .admit(&request, "now")
            .expect_err("missing control");
        assert_eq!(error.status, 403);
        assert_eq!(error.code, "model_weight_custody_required_control_missing");
    }

    #[test]
    fn scope_refs_must_use_scope_prefix() {
        let mut request = base_request();
        request["authority_scope_refs"] = json!(["model.mount"]);
        let error = RuntimeModelWeightCustodyAdmissionCore
            .admit(&request, "now")
            .expect_err("bad scope");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "model_weight_custody_scope_invalid");
    }

    #[test]
    fn unique_strings_trims_items() {
        // The local uniqueStrings trims each item; a padded duplicate collapses.
        let values = vec![json!("  local_only  "), json!("local_only")];
        assert_eq!(unique_strings(&values), vec!["local_only".to_string()]);
    }

    #[test]
    fn retired_aliases_rejected_after_field_extraction() {
        let mut request = base_request();
        request["remoteProviderCanReadWeights"] = json!(true);
        let error = RuntimeModelWeightCustodyAdmissionCore
            .admit(&request, "now")
            .expect_err("retired alias");
        assert_eq!(error.code, "model_weight_custody_request_aliases_retired");
    }
}
