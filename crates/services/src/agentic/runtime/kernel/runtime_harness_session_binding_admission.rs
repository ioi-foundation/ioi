//! Harness-session-binding admission planner.
//!
//! A faithful Rust port of the retired JS `admitHarnessSessionBinding`
//! (`packages/runtime-daemon/src/runtime-harness-session-binding-admission.mjs`). Pure
//! validation + canonicalization: a harness-session launch is admitted only after the harness
//! selection, model route, workspace-mount policy, privacy posture, authority scopes, receipts,
//! and daemon runtime-truth boundary are bound.
//!
//! STATUS varies per branch: the field-shape helpers (required/prefix/enum/non-empty) reject
//! with HTTP 400; the policy/authority assertions (`admissionError`) reject with HTTP 403. The
//! JS field-extraction order is preserved (all extraction first, then `assertHarnessSessionBinding`)
//! so a 400 field-shape error wins over the later 403 policy errors.
//!
//! HELPER NOTE vs session-launch-recipe: this module's `prefixedRefs` is the SHARED
//! `uniqueStrings(normalizeArray(value))` — it does NOT trim items (no `optionalString` map), so
//! a padded ref keeps its whitespace and fails the prefix check. `enumValue` DOES trim (via
//! `optionalString`). `js_string_coerce`/`js_number_to_string` replicate JS `String(value)`.

use serde_json::{json, Map, Value};

pub const HARNESS_SESSION_BINDING_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.runtime.harness_session_binding_admission.v1";

const BINDING_SCHEMA_VERSION: &str = "ioi.hypervisor.harness_session_binding.v1";

const SELECTION_KINDS: &[&str] = &["harness_profile", "agent_harness_adapter"];
const TRUTH_BOUNDARIES: &[&str] = &["daemon-owned", "proposal_source_only"];
const MODEL_ROUTE_POLICIES: &[&str] = &[
    "hypervisor_model_mount",
    "adapter_builtin",
    "provider_trust",
    "forbidden",
];
const MODEL_ROUTE_STATES: &[&str] = &[
    "daemon_verified",
    "fixture_available",
    "missing",
    "unavailable",
];
const WORKSPACE_MOUNT_POLICIES: &[&str] = &[
    "public_trunk",
    "redacted_projection",
    "plain_workspace",
    "ctee_private_workspace",
];

const RETIRED_ALIASES: &[&str] = &[
    "sessionBindingRef",
    "sessionRouteRef",
    "harnessSelectionRef",
    "harnessLaunchRouteRef",
    "modelConfigurationRef",
    "modelRouteRef",
    "workspaceMountPolicy",
    "privacyPostureRef",
    "authorityScopeRefs",
    "receiptPolicyRef",
    "receiptPreviewRef",
    "expectedReceiptRefs",
    "agentgresOperationRefs",
    "receiptRefs",
    "stateRoot",
];

#[derive(Debug, Clone)]
pub struct RuntimeHarnessSessionBindingAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimeHarnessSessionBindingAdmissionError {
    fn new(status: u16, code: String, message: String, details: Value) -> Self {
        Self {
            status,
            code,
            message,
            details,
        }
    }
}

type AdmitResult<T> = Result<T, RuntimeHarnessSessionBindingAdmissionError>;

#[derive(Default)]
pub struct RuntimeHarnessSessionBindingAdmissionCore;

impl RuntimeHarnessSessionBindingAdmissionCore {
    pub fn admit(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        assert_no_retired_aliases(request)?;

        // Field extraction (JS order); the shape helpers throw 400 inline.
        let schema_version = required_string(request.get("schema_version"), "schema_version")?;
        let session_binding_ref = prefixed_string(
            request.get("session_binding_ref"),
            "session_binding_ref",
            "harness-session-binding:",
        )?;
        let session_route_ref = prefixed_string(
            request.get("session_route_ref"),
            "session_route_ref",
            "session-route:",
        )?;
        let harness_selection_ref = required_string(
            request.get("harness_selection_ref"),
            "harness_selection_ref",
        )?;
        let harness_selection_kind = enum_value(
            request.get("harness_selection_kind"),
            "harness_selection_kind",
            SELECTION_KINDS,
        )?;
        let harness_truth_boundary = enum_value(
            request.get("harness_truth_boundary"),
            "harness_truth_boundary",
            TRUTH_BOUNDARIES,
        )?;
        let harness_launch_route_ref = prefixed_string(
            request.get("harness_launch_route_ref"),
            "harness_launch_route_ref",
            "harness-route:",
        )?;
        let agent_harness_adapter_id = optional_value(request.get("agent_harness_adapter_id"));
        let harness_profile_ref = optional_value(request.get("harness_profile_ref"));
        let model_configuration_ref = prefixed_string(
            request.get("model_configuration_ref"),
            "model_configuration_ref",
            "model-config:",
        )?;
        let model_route_ref = prefixed_string(
            request.get("model_route_ref"),
            "model_route_ref",
            "model-route:",
        )?;
        let model_route_policy = enum_value(
            request.get("model_route_policy"),
            "model_route_policy",
            MODEL_ROUTE_POLICIES,
        )?;
        let model_route_availability_state = enum_value(
            request.get("model_route_availability_state"),
            "model_route_availability_state",
            MODEL_ROUTE_STATES,
        )?;
        let model_route_endpoint_refs = prefixed_refs(
            request.get("model_route_endpoint_refs"),
            "model_route_endpoint_refs",
            "model-endpoint:",
            true,
        )?;
        let model_route_loaded_instance_refs = prefixed_refs(
            request.get("model_route_loaded_instance_refs"),
            "model_route_loaded_instance_refs",
            "model-instance:",
            true,
        )?;
        let workspace_mount_policy = enum_value(
            request.get("workspace_mount_policy"),
            "workspace_mount_policy",
            WORKSPACE_MOUNT_POLICIES,
        )?;
        let privacy_posture_ref = prefixed_string(
            request.get("privacy_posture_ref"),
            "privacy_posture_ref",
            "privacy:",
        )?;
        let authority_scope_refs = prefixed_refs(
            request.get("authority_scope_refs"),
            "authority_scope_refs",
            "scope:",
            false,
        )?;
        let receipt_policy_ref = prefixed_string(
            request.get("receipt_policy_ref"),
            "receipt_policy_ref",
            "receipt-policy:",
        )?;
        let receipt_preview_ref = prefixed_string(
            request.get("receipt_preview_ref"),
            "receipt_preview_ref",
            "receipt-preview:",
        )?;
        let expected_receipt_refs = prefixed_refs(
            request.get("expected_receipt_refs"),
            "expected_receipt_refs",
            "receipt",
            false,
        )?;
        let requires_daemon_gate =
            boolean_value(request.get("requires_daemon_gate")).unwrap_or(false);
        let runtime_truth_source = optional_value(request.get("runtimeTruthSource"));
        let agentgres_operation_refs = prefixed_refs(
            request.get("agentgres_operation_refs"),
            "agentgres_operation_refs",
            "agentgres://operation/",
            true,
        )?;
        let receipt_refs = prefixed_refs(
            request.get("receipt_refs"),
            "receipt_refs",
            "receipt://",
            true,
        )?;
        let state_root = optional_value(request.get("state_root"));
        let harness_runtime_truth_claimed =
            boolean_value(request.get("harness_runtime_truth_claimed")).unwrap_or(false);

        // assertHarnessSessionBinding — policy/authority checks (mostly 403).
        if schema_version != BINDING_SCHEMA_VERSION {
            return Err(authority_error(
                "harness_session_binding_schema_invalid",
                "Harness session binding admission requires the canonical binding schema.",
                json!({ "schema_version": schema_version }),
            ));
        }
        if !requires_daemon_gate || runtime_truth_source.as_deref() != Some("daemon-runtime") {
            return Err(authority_error(
                "harness_session_binding_daemon_gate_required",
                "Harness session bindings must require daemon gates and daemon runtime truth.",
                json!({ "requires_daemon_gate": requires_daemon_gate, "runtimeTruthSource": runtime_truth_source }),
            ));
        }
        if harness_runtime_truth_claimed {
            return Err(authority_error(
                "harness_session_binding_runtime_truth_claim_blocked",
                "Harness adapters may propose actions but cannot claim runtime truth.",
                json!({ "harness_runtime_truth_claimed": harness_runtime_truth_claimed }),
            ));
        }
        require_scope(&authority_scope_refs, "scope:workspace.read")?;
        if !expected_receipt_refs.contains(&receipt_preview_ref) {
            return Err(authority_error(
                "harness_session_binding_receipt_preview_unbound",
                "Harness session binding must include the launch receipt preview in expected receipt refs.",
                json!({ "receipt_preview_ref": receipt_preview_ref }),
            ));
        }
        if !expected_receipt_refs.contains(&receipt_policy_ref) {
            return Err(authority_error(
                "harness_session_binding_receipt_policy_unbound",
                "Harness session binding must include its receipt policy in expected receipt refs.",
                json!({ "receipt_policy_ref": receipt_policy_ref }),
            ));
        }
        if !session_binding_ref.contains(&safe_binding_id(&session_route_ref)) {
            return Err(authority_error(
                "harness_session_binding_route_unbound",
                "Harness session binding ref must bind the session route.",
                json!({ "session_binding_ref": session_binding_ref, "session_route_ref": session_route_ref }),
            ));
        }

        if harness_selection_kind == "harness_profile" {
            require_prefix(
                &harness_selection_ref,
                "harness-profile:",
                "harness_selection_ref",
            )?;
            if harness_profile_ref.is_none() {
                return Err(authority_error(
                    "harness_session_binding_profile_ref_required",
                    "Harness profile bindings require harness_profile_ref.",
                    json!({ "harness_selection_kind": harness_selection_kind }),
                ));
            }
            if agent_harness_adapter_id.is_some() {
                return Err(authority_error(
                    "harness_session_binding_adapter_ref_for_profile_blocked",
                    "Harness profile bindings must not carry agent harness adapter ids.",
                    json!({ "agent_harness_adapter_id": agent_harness_adapter_id }),
                ));
            }
            if harness_truth_boundary != "daemon-owned" {
                return Err(authority_error(
                    "harness_session_binding_profile_truth_boundary_invalid",
                    "Harness profile bindings must remain daemon-owned.",
                    json!({ "harness_truth_boundary": harness_truth_boundary }),
                ));
            }
        } else {
            require_prefix(
                &harness_selection_ref,
                "agent-harness-adapter:",
                "harness_selection_ref",
            )?;
            if agent_harness_adapter_id.is_none() {
                return Err(authority_error(
                    "harness_session_binding_adapter_id_required",
                    "Agent harness adapter bindings require agent_harness_adapter_id.",
                    json!({ "harness_selection_kind": harness_selection_kind }),
                ));
            }
            if harness_profile_ref.is_some() {
                return Err(authority_error(
                    "harness_session_binding_profile_ref_for_adapter_blocked",
                    "Agent harness adapter bindings must not carry harness profile refs.",
                    json!({ "harness_profile_ref": harness_profile_ref }),
                ));
            }
            if harness_truth_boundary != "proposal_source_only" {
                return Err(authority_error(
                    "harness_session_binding_adapter_truth_boundary_invalid",
                    "Agent harness adapters are proposal sources only.",
                    json!({ "harness_truth_boundary": harness_truth_boundary }),
                ));
            }
            if workspace_mount_policy == "ctee_private_workspace"
                || privacy_posture_ref == "privacy:ctee-private-workspace"
            {
                return Err(authority_error(
                    "harness_session_binding_external_ctee_custody_blocked",
                    "External harness adapters cannot mount or claim cTEE private workspace custody.",
                    json!({ "harness_selection_ref": harness_selection_ref }),
                ));
            }
        }

        if model_route_policy == "hypervisor_model_mount" {
            if !matches!(
                model_route_availability_state.as_str(),
                "daemon_verified" | "fixture_available"
            ) {
                return Err(authority_error(
                    "harness_session_binding_model_route_unavailable",
                    "Hypervisor model mount bindings require a verified or fixture-available local model route.",
                    json!({ "model_route_availability_state": model_route_availability_state }),
                ));
            }
            require_non_empty(&model_route_endpoint_refs, "model_route_endpoint_refs")?;
            require_non_empty(
                &model_route_loaded_instance_refs,
                "model_route_loaded_instance_refs",
            )?;
            if !model_configuration_ref.starts_with("model-config:local/") {
                return Err(authority_error(
                    "harness_session_binding_local_model_config_required",
                    "Hypervisor model mount bindings require a local model configuration.",
                    json!({ "model_configuration_ref": model_configuration_ref }),
                ));
            }
        }

        if model_route_policy == "provider_trust" {
            return Err(authority_error(
                "harness_session_binding_provider_trust_requires_future_lease",
                "Provider-trust harness routes require an explicit provider-trust lease and are not admitted by the local-first session binding gate.",
                json!({ "model_route_ref": model_route_ref }),
            ));
        }

        if model_route_policy == "forbidden" && model_route_ref != "model-route:none" {
            return Err(authority_error(
                "harness_session_binding_forbidden_model_route_invalid",
                "Harnesses with forbidden model routes must bind model-route:none.",
                json!({ "model_route_ref": model_route_ref }),
            ));
        }

        let binding_safe = safe_id(&session_binding_ref);
        let admission_id = optional_value(request.get("admission_id"))
            .unwrap_or_else(|| format!("harness-session-binding-admission:{binding_safe}"));
        let admission_receipt_ref = optional_value(request.get("admission_receipt_ref"))
            .unwrap_or_else(|| {
                format!("receipt://harness-session-binding/{binding_safe}/admitted")
            });

        let mut receipt_out = receipt_refs;
        receipt_out.push(admission_receipt_ref);
        let receipt_out = dedupe_strings(receipt_out);

        let admitted_at =
            optional_value(request.get("admitted_at")).unwrap_or_else(|| now_iso.to_string());

        Ok(json!({
            "schema_version": HARNESS_SESSION_BINDING_ADMISSION_SCHEMA_VERSION,
            "admission_id": admission_id,
            "decision": "admitted",
            "admission_state": "admitted_for_harness_launch",
            "session_binding_ref": session_binding_ref,
            "session_route_ref": session_route_ref,
            "harness_selection_ref": harness_selection_ref,
            "harness_selection_kind": harness_selection_kind,
            "harness_truth_boundary": harness_truth_boundary,
            "harness_launch_route_ref": harness_launch_route_ref,
            "agent_harness_adapter_id": agent_harness_adapter_id,
            "harness_profile_ref": harness_profile_ref,
            "model_configuration_ref": model_configuration_ref,
            "model_route_ref": model_route_ref,
            "model_route_policy": model_route_policy,
            "model_route_availability_state": model_route_availability_state,
            "model_route_endpoint_refs": model_route_endpoint_refs,
            "model_route_loaded_instance_refs": model_route_loaded_instance_refs,
            "workspace_mount_policy": workspace_mount_policy,
            "privacy_posture_ref": privacy_posture_ref,
            "authority_scope_refs": authority_scope_refs,
            "receipt_policy_ref": receipt_policy_ref,
            "receipt_preview_ref": receipt_preview_ref,
            "expected_receipt_refs": expected_receipt_refs,
            "agentgres_operation_refs": agentgres_operation_refs,
            "receipt_refs": receipt_out,
            "state_root": state_root,
            "harness_runtime_truth_claimed": false,
            "requiresDaemonGate": true,
            "runtimeTruthSource": "daemon-runtime",
            "admitted_at": admitted_at,
            "binding_invariant": "Harness session launch is admitted only after harness, model route, workspace mount policy, privacy posture, authority scopes, receipts, and daemon runtime truth boundary are bound.",
        }))
    }
}

fn assert_no_retired_aliases(request: &Value) -> AdmitResult<()> {
    let empty = Map::new();
    let object = request.as_object().unwrap_or(&empty);
    let present: Vec<String> = RETIRED_ALIASES
        .iter()
        .filter(|alias| object.contains_key(**alias))
        .map(|alias| alias.to_string())
        .collect();
    if present.is_empty() {
        return Ok(());
    }
    Err(RuntimeHarnessSessionBindingAdmissionError::new(
        400,
        "harness_session_binding_request_aliases_retired".to_string(),
        "Harness session binding admission uses canonical snake_case request fields.".to_string(),
        json!({ "retired_aliases": present }),
    ))
}

/// Mirror JS `requiredString(value, field)` — optionalString then 400 `_required`.
fn required_string(value: Option<&Value>, field: &str) -> AdmitResult<String> {
    optional_value(value).ok_or_else(|| {
        RuntimeHarnessSessionBindingAdmissionError::new(
            400,
            format!("harness_session_binding_{field}_required"),
            format!("Harness session binding admission requires {field}."),
            json!({ "field": field }),
        )
    })
}

/// Mirror JS `prefixedString` — requiredString then requirePrefix.
fn prefixed_string(value: Option<&Value>, field: &str, prefix: &str) -> AdmitResult<String> {
    let normalized = required_string(value, field)?;
    require_prefix(&normalized, prefix, field)?;
    Ok(normalized)
}

/// Mirror JS `prefixedRefs` — `uniqueStrings(normalizeArray(value))` (NO trim), require_non_empty
/// unless allow_empty, then require_prefix each.
fn prefixed_refs(
    value: Option<&Value>,
    field: &str,
    prefix: &str,
    allow_empty: bool,
) -> AdmitResult<Vec<String>> {
    let refs = unique_strings_raw(value);
    if !allow_empty {
        require_non_empty(&refs, field)?;
    }
    for reference in &refs {
        require_prefix(reference, prefix, field)?;
    }
    Ok(refs)
}

/// Mirror JS `enumValue` — optionalString (trim) then membership; 400 `_invalid`; details carry
/// the dynamic `[field]` key + allowed_values.
fn enum_value(value: Option<&Value>, field: &str, allowed: &[&str]) -> AdmitResult<String> {
    let normalized = optional_value(value);
    match &normalized {
        Some(value) if allowed.contains(&value.as_str()) => Ok(value.clone()),
        _ => {
            let mut details = Map::new();
            details.insert(
                field.to_string(),
                normalized.map(Value::String).unwrap_or(Value::Null),
            );
            details.insert("allowed_values".to_string(), json!(allowed));
            Err(RuntimeHarnessSessionBindingAdmissionError::new(
                400,
                format!("harness_session_binding_{field}_invalid"),
                format!("Harness session binding admission requires a valid {field}."),
                Value::Object(details),
            ))
        }
    }
}

fn require_non_empty(refs: &[String], field: &str) -> AdmitResult<()> {
    if !refs.is_empty() {
        return Ok(());
    }
    Err(RuntimeHarnessSessionBindingAdmissionError::new(
        400,
        format!("harness_session_binding_{field}_required"),
        format!("Harness session binding admission requires {field}."),
        json!({ "field": field }),
    ))
}

fn require_prefix(value: &str, prefix: &str, field: &str) -> AdmitResult<()> {
    if value.starts_with(prefix) {
        return Ok(());
    }
    Err(RuntimeHarnessSessionBindingAdmissionError::new(
        400,
        format!("harness_session_binding_{field}_prefix_invalid"),
        format!("Harness session binding admission requires {field} to start with {prefix}."),
        json!({ "field": field, "value": value, "expected_prefix": prefix }),
    ))
}

fn require_scope(scope_refs: &[String], scope: &str) -> AdmitResult<()> {
    if scope_refs.iter().any(|value| value == scope) {
        return Ok(());
    }
    Err(authority_error(
        "harness_session_binding_required_scope_missing",
        &format!("Harness session binding admission requires {scope}."),
        json!({ "required_scope": scope }),
    ))
}

fn authority_error(
    code: &str,
    message: &str,
    details: Value,
) -> RuntimeHarnessSessionBindingAdmissionError {
    RuntimeHarnessSessionBindingAdmissionError::new(
        403,
        code.to_string(),
        message.to_string(),
        details,
    )
}

/// Mirror JS `optionalString`: String(value).trim(), None when null/absent/blank.
fn optional_value(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => None,
        Some(value) => {
            let trimmed = js_string_coerce(value).trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }
    }
}

/// Mirror JS `booleanValue`: true/false or "true"/"false" (case-insensitive), else None.
fn boolean_value(value: Option<&Value>) -> Option<bool> {
    match value {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::String(value)) => match value.to_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Mirror the SHARED `uniqueStrings(normalizeArray(value))`: truthy raw items, `String()`-coerced
/// (NO trim), drop blanks, first-seen dedup. Non-array → empty.
fn unique_strings_raw(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for item in items {
        if !is_truthy(item) {
            continue;
        }
        let coerced = js_string_coerce(item);
        if coerced.is_empty() {
            continue;
        }
        if !out.contains(&coerced) {
            out.push(coerced);
        }
    }
    out
}

/// First-seen dedup of an already-string list (the output `uniqueStrings` over non-empty refs).
fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values {
        if value.is_empty() {
            continue;
        }
        if !out.contains(&value) {
            out.push(value);
        }
    }
    out
}

/// JS truthiness for filter(Boolean): null/false/0/""/NaN falsy; objects+arrays truthy.
fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(boolean) => *boolean,
        Value::Number(number) => number.as_f64().map(|float| float != 0.0).unwrap_or(false),
        Value::String(string) => !string.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// Mirror JS `String(value)`: scalars exactly; arrays comma-join coerced elements (null→empty);
/// objects → "[object Object]". Numbers go through the ECMAScript Number→String algorithm.
fn js_string_coerce(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(boolean) => boolean.to_string(),
        Value::Number(number) => js_number_to_string(number.as_f64().unwrap_or(0.0)),
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

/// Mirror ECMAScript `Number::toString` (base 10) for a finite f64: shortest round-trip digits
/// with V8's exponential thresholds (n>21 or n<=-6 → exponential), -0 → "0".
fn js_number_to_string(value: f64) -> String {
    if value == 0.0 {
        return "0".to_string();
    }
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 {
            "Infinity".to_string()
        } else {
            "-Infinity".to_string()
        };
    }
    let negative = value < 0.0;
    let magnitude = value.abs();
    let exp_form = format!("{magnitude:e}");
    let (mantissa, exp_str) = exp_form.split_once('e').unwrap_or((exp_form.as_str(), "0"));
    let exp: i32 = exp_str.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|ch| *ch != '.').collect();
    let k = digits.len() as i32;
    let n = exp + 1;

    let body = if k <= n && n <= 21 {
        let mut out = digits;
        for _ in 0..(n - k) {
            out.push('0');
        }
        out
    } else if 0 < n && n <= 21 {
        let (head, tail) = digits.split_at(n as usize);
        format!("{head}.{tail}")
    } else if -6 < n && n <= 0 {
        let mut out = String::from("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(&digits);
        out
    } else {
        let mut chars = digits.chars();
        let first = chars.next().unwrap_or('0');
        let rest: String = chars.collect();
        let mut out = String::new();
        out.push(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(&rest);
        }
        out.push('e');
        let e = n - 1;
        if e >= 0 {
            out.push('+');
            out.push_str(&e.to_string());
        } else {
            out.push('-');
            out.push_str(&(-e).to_string());
        }
        out
    };
    if negative {
        format!("-{body}")
    } else {
        body
    }
}

/// Mirror the SHARED `safeId`: collapse runs outside [A-Za-z0-9_.-] to a single `_`.
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

/// Mirror JS `safeBindingId`: lowercase, collapse runs outside [a-z0-9_-] to `-`, trim `-`,
/// slice to 96 chars, default "binding".
fn safe_binding_id(value: &str) -> String {
    let lowered = value.to_lowercase();
    let mut collapsed = String::with_capacity(lowered.len());
    let mut in_run = false;
    for ch in lowered.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '-') {
            collapsed.push(ch);
            in_run = false;
        } else if !in_run {
            collapsed.push('-');
            in_run = true;
        }
    }
    let trimmed = collapsed.trim_matches('-');
    let sliced: String = trimmed.chars().take(96).collect();
    if sliced.is_empty() {
        "binding".to_string()
    } else {
        sliced
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_binding() -> Value {
        json!({
            "schema_version": "ioi.hypervisor.harness_session_binding.v1",
            "session_binding_ref": "harness-session-binding:session-route-sessions-mission-default-project-ioi:harness-profile-default_harness_profile:model-config-local-codex-oss-qwen",
            "session_route_ref": "session-route:sessions/mission.default/project:ioi",
            "harness_selection_ref": "harness-profile:default_harness_profile",
            "harness_selection_kind": "harness_profile",
            "harness_label": "Default Harness Profile",
            "harness_truth_boundary": "daemon-owned",
            "harness_launch_route_ref": "harness-route:default-harness-profile/local-model",
            "harness_profile_ref": "default_harness_profile",
            "model_configuration_ref": "model-config:local/codex-oss-qwen",
            "model_configuration_label": "Local Codex OSS / Qwen route",
            "model_route_ref": "model-route:hypervisor/default-local",
            "model_route_policy": "hypervisor_model_mount",
            "model_route_availability_state": "daemon_verified",
            "model_route_endpoint_refs": ["model-endpoint:hypervisor/default-local"],
            "model_route_loaded_instance_refs": ["model-instance:hypervisor/default-local"],
            "workspace_mount_policy": "ctee_private_workspace",
            "privacy_posture_ref": "privacy:ctee-private-workspace",
            "authority_scope_refs": ["scope:workspace.read", "scope:receipt.write"],
            "receipt_policy_ref": "receipt-policy:harness-profile/default",
            "receipt_preview_ref": "receipt-preview:new-session/admitted",
            "expected_receipt_refs": [
                "receipt-preview:new-session/admitted",
                "receipt-policy:harness-profile/default",
            ],
            "requires_daemon_gate": true,
            "runtimeTruthSource": "daemon-runtime",
            "agentgres_operation_refs": ["agentgres://operation/harness-session-binding/admit"],
            "receipt_refs": ["receipt://harness-session-binding/admit"],
            "state_root": "agentgres://state-root/harness-session-binding/admit",
        })
    }

    #[test]
    fn admits_default_harness_profile() {
        let admission = RuntimeHarnessSessionBindingAdmissionCore
            .admit(&base_binding(), "2026-06-18T12:00:00.000Z")
            .expect("admitted");
        assert_eq!(
            admission["schema_version"],
            HARNESS_SESSION_BINDING_ADMISSION_SCHEMA_VERSION
        );
        assert_eq!(admission["decision"], "admitted");
        assert_eq!(admission["admission_state"], "admitted_for_harness_launch");
        assert_eq!(
            admission["model_configuration_ref"],
            "model-config:local/codex-oss-qwen"
        );
        assert_eq!(admission["requiresDaemonGate"], true);
        assert_eq!(admission["harness_runtime_truth_claimed"], false);
        assert_eq!(admission["admitted_at"], "2026-06-18T12:00:00.000Z");
    }

    #[test]
    fn admits_proposal_source_adapter() {
        let mut binding = base_binding();
        binding["session_binding_ref"] = json!("harness-session-binding:session-route-sessions-mission-default-project-ioi:agent-harness-adapter-codex_cli:model-config-local-codex-oss-qwen");
        binding["harness_selection_ref"] = json!("agent-harness-adapter:codex_cli");
        binding["harness_selection_kind"] = json!("agent_harness_adapter");
        binding["harness_truth_boundary"] = json!("proposal_source_only");
        binding["harness_launch_route_ref"] = json!("harness-route:codex-cli/local-model");
        binding["agent_harness_adapter_id"] = json!("codex_cli");
        binding
            .as_object_mut()
            .unwrap()
            .remove("harness_profile_ref");
        binding["workspace_mount_policy"] = json!("redacted_projection");
        binding["privacy_posture_ref"] = json!("privacy:redacted-projection");
        binding["receipt_policy_ref"] = json!("receipt-policy:harness-adapter/default");
        binding["expected_receipt_refs"] = json!([
            "receipt-preview:new-session/admitted",
            "receipt-policy:harness-adapter/default",
        ]);
        let admission = RuntimeHarnessSessionBindingAdmissionCore
            .admit(&binding, "now")
            .expect("admitted");
        assert_eq!(
            admission["harness_selection_ref"],
            "agent-harness-adapter:codex_cli"
        );
        assert_eq!(admission["agent_harness_adapter_id"], "codex_cli");
    }

    #[test]
    fn blocks_external_ctee_custody() {
        let mut binding = base_binding();
        binding["session_binding_ref"] = json!("harness-session-binding:session-route-sessions-mission-default-project-ioi:agent-harness-adapter-codex_cli:model-config-local-codex-oss-qwen");
        binding["harness_selection_ref"] = json!("agent-harness-adapter:codex_cli");
        binding["harness_selection_kind"] = json!("agent_harness_adapter");
        binding["harness_truth_boundary"] = json!("proposal_source_only");
        binding["agent_harness_adapter_id"] = json!("codex_cli");
        binding
            .as_object_mut()
            .unwrap()
            .remove("harness_profile_ref");
        let error = RuntimeHarnessSessionBindingAdmissionCore
            .admit(&binding, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "harness_session_binding_external_ctee_custody_blocked"
        );
        assert_eq!(error.status, 403);
    }

    #[test]
    fn blocks_provider_trust() {
        let mut binding = base_binding();
        binding["model_route_policy"] = json!("provider_trust");
        binding["model_configuration_ref"] = json!("model-config:adapter-native/provider-trust");
        let error = RuntimeHarnessSessionBindingAdmissionCore
            .admit(&binding, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "harness_session_binding_provider_trust_requires_future_lease"
        );
    }

    #[test]
    fn blocks_unavailable_model_route() {
        let mut binding = base_binding();
        binding["model_route_availability_state"] = json!("missing");
        binding["model_route_endpoint_refs"] = json!([]);
        let error = RuntimeHarnessSessionBindingAdmissionCore
            .admit(&binding, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "harness_session_binding_model_route_unavailable"
        );
    }

    #[test]
    fn blocks_runtime_truth_claim() {
        let mut binding = base_binding();
        binding["harness_runtime_truth_claimed"] = json!(true);
        let error = RuntimeHarnessSessionBindingAdmissionCore
            .admit(&binding, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "harness_session_binding_runtime_truth_claim_blocked"
        );
    }

    #[test]
    fn rejects_retired_aliases() {
        let mut binding = base_binding();
        binding["sessionBindingRef"] = json!("legacy");
        let error = RuntimeHarnessSessionBindingAdmissionCore
            .admit(&binding, "now")
            .expect_err("retired alias");
        assert_eq!(error.status, 400);
        assert_eq!(
            error.code,
            "harness_session_binding_request_aliases_retired"
        );
    }

    #[test]
    fn rejects_prim_scope_masquerade() {
        let mut binding = base_binding();
        binding["authority_scope_refs"] = json!(["prim:shell.exec"]);
        let error = RuntimeHarnessSessionBindingAdmissionCore
            .admit(&binding, "now")
            .expect_err("bad scope");
        assert_eq!(
            error.code,
            "harness_session_binding_authority_scope_refs_prefix_invalid"
        );
        assert_eq!(error.status, 400);
    }
}
