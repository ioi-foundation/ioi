//! Hypervisor session-launch-recipe admission planner.
//!
//! A faithful Rust port of the retired JS `admitHypervisorSessionLaunchRecipe`
//! (`packages/runtime-daemon/src/runtime-hypervisor-session-launch-recipe-admission.mjs`).
//! Pure validation + canonicalization: asserts a New-Session launch recipe + its target
//! binding agree, bind the canonical route/model/privacy/authority/receipt/Agentgres refs,
//! require daemon gates + daemon-runtime truth, then returns the admission record.
//!
//! GOTCHA vs the other admissions: the request carries NESTED objects (`recipe`,
//! `target_binding`). The JS helpers (`requiredString`/`prefixedString`/`enumValue`) take a
//! `(value, label)` shape — they validate a VALUE, not an `(object, field)` key-lookup — so we
//! extract each nested value first, then validate it. All errors are HTTP 400 (the JS
//! `admissionError` default status). This module imports the SHARED `uniqueStrings`
//! (`runtime-value-helpers.mjs`) which does NOT trim its items (unlike model-weight-custody's
//! local variant); within ref lists items are already trimmed via `optionalString`, so the
//! `js_string_coerce` helper replicates JS `String(value)` exactly.

use serde_json::{json, Value};

pub const HYPERVISOR_SESSION_LAUNCH_RECIPE_ADMISSION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.hypervisor.session_launch_recipe_admission_request.v1";

pub const HYPERVISOR_SESSION_LAUNCH_RECIPE_SCHEMA_VERSION: &str =
    "ioi.hypervisor.session_launch_recipe.v1";

pub const HYPERVISOR_SESSION_LAUNCH_RECIPE_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.runtime.hypervisor_session_launch_recipe_admission.v1";

const TARGET_BINDING_SCHEMA_VERSION: &str = "ioi.hypervisor.new_session_target_binding.v1";

const RECIPE_KINDS: &[&str] = &[
    "mission",
    "workbench",
    "agent",
    "automation",
    "foundry_job",
    "provider_environment_job",
    "privacy_workspace",
];

const MODEL_MOUNT_POLICIES: &[&str] = &["inherit", "select", "required", "forbidden"];

const HARNESS_PROFILE_POLICIES: &[&str] = &["default", "select", "external_adapter"];

/// SURFACE_BY_KIND: each recipe kind maps to exactly one canonical surface id.
fn surface_for_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "mission" => Some("sessions"),
        "workbench" => Some("workbench"),
        "agent" => Some("agents"),
        "automation" => Some("automations"),
        "foundry_job" => Some("foundry"),
        "provider_environment_job" => Some("environments"),
        "privacy_workspace" => Some("privacy"),
        _ => None,
    }
}

const RETIRED_ALIASES: &[&str] = &[
    "recipeId",
    "recipeRef",
    "targetBindingRef",
    "targetKind",
    "surfaceId",
    "projectRef",
    "sessionRouteRef",
    "modelRouteRef",
    "privacyPostureRef",
    "authorityScopeRefs",
    "receiptPreviewRef",
    "requiresDaemonGate",
    "agentgresOperationRefs",
    "receiptRefs",
    "stateRoot",
];

#[derive(Debug, Clone)]
pub struct RuntimeHypervisorSessionLaunchRecipeAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimeHypervisorSessionLaunchRecipeAdmissionError {
    fn new(code: &str, message: String, details: Value) -> Self {
        Self { status: 400, code: code.to_string(), message, details }
    }
}

type AdmitResult<T> = Result<T, RuntimeHypervisorSessionLaunchRecipeAdmissionError>;

struct NormalizedRecipe {
    recipe_id: String,
    kind: String,
    surface_id: String,
}

struct NormalizedTargetBinding {
    target_binding_ref: String,
    project_ref: String,
    operator_intent_ref: Option<String>,
    session_route_ref: String,
    code_editor_adapter_target_ref: Option<String>,
    recipe_ref: String,
    target_kind: String,
    surface_id: String,
}

#[derive(Default)]
pub struct RuntimeHypervisorSessionLaunchRecipeAdmissionCore;

impl RuntimeHypervisorSessionLaunchRecipeAdmissionCore {
    pub fn admit(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        // 1. Retired-alias guard runs FIRST (matches JS field-extraction order).
        assert_no_retired_aliases(request)?;

        // 2. Field extraction (JS order); prefixed_string / prefixed_refs throw inline so a
        // missing/badly-prefixed top-level ref wins over the later schema/gate checks.
        let schema_version = required_string(request.get("schema_version"), "schema_version")?;
        let model_route_ref =
            prefixed_string(request.get("model_route_ref"), "model_route_ref", "model-route:")?;
        let privacy_posture_ref = prefixed_string(
            request.get("privacy_posture_ref"),
            "privacy_posture_ref",
            "privacy:",
        )?;
        let authority_scope_refs =
            prefixed_refs(request.get("authority_scope_refs"), "authority_scope_refs", "scope:", false)?;
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
        let receipt_refs =
            prefixed_refs(request.get("receipt_refs"), "receipt_refs", "receipt://", true)?;
        let state_root = optional_value(request.get("state_root"));

        // 3. Schema / daemon-gate / receipt-preview-binding checks.
        if schema_version != HYPERVISOR_SESSION_LAUNCH_RECIPE_ADMISSION_REQUEST_SCHEMA_VERSION {
            return Err(admission_error(
                "hypervisor_session_launch_recipe_request_schema_invalid",
                "Hypervisor session launch recipe admission requires the canonical request schema.".to_string(),
                json!({ "schema_version": schema_version }),
            ));
        }
        if !requires_daemon_gate || runtime_truth_source.as_deref() != Some("daemon-runtime") {
            return Err(admission_error(
                "hypervisor_session_launch_recipe_daemon_gate_required",
                "Hypervisor session launch recipe admission requires daemon gates and daemon runtime truth.".to_string(),
                json!({
                    "requires_daemon_gate": requires_daemon_gate,
                    "runtimeTruthSource": runtime_truth_source,
                }),
            ));
        }
        if !expected_receipt_refs.contains(&receipt_preview_ref) {
            return Err(admission_error(
                "hypervisor_session_launch_recipe_receipt_preview_unbound",
                "Hypervisor session launch recipe admission must bind the receipt preview in expected receipt refs.".to_string(),
                json!({ "receipt_preview_ref": receipt_preview_ref }),
            ));
        }

        // 4. Nested recipe + target-binding validation, then cross-agreement.
        let normalized_recipe = normalize_recipe(request.get("recipe"))?;
        let normalized_target_binding = normalize_target_binding(request.get("target_binding"))?;
        assert_recipe_target_binding(&normalized_recipe, &normalized_target_binding)?;

        let binding_safe = safe_id(&normalized_target_binding.target_binding_ref);
        let admission_id = optional_value(request.get("admission_id")).unwrap_or_else(|| {
            format!("hypervisor-session-launch-recipe-admission:{binding_safe}")
        });
        let admission_receipt_ref = optional_value(request.get("admission_receipt_ref"))
            .unwrap_or_else(|| {
                format!("receipt://hypervisor/session-launch-recipe/{binding_safe}/admitted")
            });
        let operation_ref = agentgres_operation_refs.first().cloned().unwrap_or_else(|| {
            format!("agentgres://operation/hypervisor/session-launch-recipe/{binding_safe}")
        });

        let mut agentgres_out = agentgres_operation_refs.clone();
        agentgres_out.push(operation_ref);
        let agentgres_out = dedupe_strings(agentgres_out);

        let mut receipt_out = receipt_refs.clone();
        receipt_out.push(admission_receipt_ref);
        let receipt_out = dedupe_strings(receipt_out);

        let state_root_out = state_root.unwrap_or_else(|| {
            format!("agentgres://state-root/hypervisor/session-launch-recipe/{binding_safe}")
        });
        let admitted_at =
            optional_value(request.get("admitted_at")).unwrap_or_else(|| now_iso.to_string());

        Ok(json!({
            "schema_version": HYPERVISOR_SESSION_LAUNCH_RECIPE_ADMISSION_SCHEMA_VERSION,
            "admission_id": admission_id,
            "decision": "admitted",
            "admission_state": "admitted_for_session_binding",
            "recipe_ref": normalized_recipe.recipe_id,
            "recipe_kind": normalized_recipe.kind,
            "surface_id": normalized_recipe.surface_id,
            "target_binding_ref": normalized_target_binding.target_binding_ref,
            "project_ref": normalized_target_binding.project_ref,
            "operator_intent_ref": normalized_target_binding.operator_intent_ref,
            "session_route_ref": normalized_target_binding.session_route_ref,
            "code_editor_adapter_target_ref": normalized_target_binding.code_editor_adapter_target_ref,
            "model_route_ref": model_route_ref,
            "privacy_posture_ref": privacy_posture_ref,
            "authority_scope_refs": authority_scope_refs,
            "receipt_preview_ref": receipt_preview_ref,
            "expected_receipt_refs": expected_receipt_refs,
            "agentgres_operation_refs": agentgres_out,
            "receipt_refs": receipt_out,
            "state_root": state_root_out,
            "requiresDaemonGate": true,
            "runtimeTruthSource": "daemon-runtime",
            "admitted_at": admitted_at,
            "recipe_invariant": "New Session recipes become launchable only after daemon admission binds recipe, target binding, project, route, model, privacy, authority scopes, receipts, and Agentgres operation refs.",
        }))
    }
}

fn normalize_recipe(value: Option<&Value>) -> AdmitResult<NormalizedRecipe> {
    let recipe = record_value(value);
    let schema_ok = recipe
        .and_then(|recipe| recipe.get("schema_version"))
        .and_then(Value::as_str)
        == Some(HYPERVISOR_SESSION_LAUNCH_RECIPE_SCHEMA_VERSION);
    let Some(recipe) = recipe.filter(|_| schema_ok) else {
        return Err(admission_error(
            "hypervisor_session_launch_recipe_schema_invalid",
            "Hypervisor session launch recipe admission requires a canonical recipe object.".to_string(),
            json!({ "expected_schema_version": HYPERVISOR_SESSION_LAUNCH_RECIPE_SCHEMA_VERSION }),
        ));
    };
    let recipe_id = required_string(recipe.get("recipe_id"), "recipe.recipe_id")?;
    let kind = enum_value(recipe.get("kind"), "recipe.kind", RECIPE_KINDS)?;
    let surface_id = required_string(recipe.get("surface_id"), "recipe.surface_id")?;
    // Validate (for side-effect throws) the remaining recipe fields; not echoed in the output.
    enum_value(recipe.get("model_mount_policy"), "recipe.model_mount_policy", MODEL_MOUNT_POLICIES)?;
    enum_value(
        recipe.get("harness_profile_policy"),
        "recipe.harness_profile_policy",
        HARNESS_PROFILE_POLICIES,
    )?;
    string_list(recipe.get("required_inputs"), "recipe.required_inputs")?;
    prefixed_refs(
        recipe.get("authority_scope_templates"),
        "recipe.authority_scope_templates",
        "scope:",
        false,
    )?;
    string_list(recipe.get("privacy_posture_templates"), "recipe.privacy_posture_templates")?;
    if surface_for_kind(&kind) != Some(surface_id.as_str()) {
        return Err(admission_error(
            "hypervisor_session_launch_recipe_surface_mismatch",
            "Hypervisor session launch recipe kind must map to its canonical surface.".to_string(),
            json!({ "kind": kind, "surface_id": surface_id }),
        ));
    }
    Ok(NormalizedRecipe { recipe_id, kind, surface_id })
}

fn normalize_target_binding(value: Option<&Value>) -> AdmitResult<NormalizedTargetBinding> {
    let binding = record_value(value);
    let schema_ok = binding
        .and_then(|binding| binding.get("schema_version"))
        .and_then(Value::as_str)
        == Some(TARGET_BINDING_SCHEMA_VERSION);
    let Some(binding) = binding.filter(|_| schema_ok) else {
        return Err(admission_error(
            "hypervisor_session_launch_recipe_target_binding_invalid",
            "Hypervisor session launch recipe admission requires the canonical target binding.".to_string(),
            json!({ "expected_schema_version": TARGET_BINDING_SCHEMA_VERSION }),
        ));
    };
    Ok(NormalizedTargetBinding {
        target_binding_ref: prefixed_string(
            binding.get("target_binding_ref"),
            "target_binding.target_binding_ref",
            "target-binding:",
        )?,
        recipe_ref: required_string(binding.get("recipe_ref"), "target_binding.recipe_ref")?,
        target_kind: enum_value(binding.get("target_kind"), "target_binding.target_kind", RECIPE_KINDS)?,
        surface_id: required_string(binding.get("surface_id"), "target_binding.surface_id")?,
        project_ref: required_string(binding.get("project_ref"), "target_binding.project_ref")?,
        operator_intent_ref: optional_value(binding.get("operator_intent_ref")),
        session_route_ref: prefixed_string(
            binding.get("session_route_ref"),
            "target_binding.session_route_ref",
            "session-route:",
        )?,
        code_editor_adapter_target_ref: optional_value(binding.get("code_editor_adapter_target_ref")),
    })
}

fn assert_recipe_target_binding(
    recipe: &NormalizedRecipe,
    binding: &NormalizedTargetBinding,
) -> AdmitResult<()> {
    if recipe.recipe_id != binding.recipe_ref
        || recipe.kind != binding.target_kind
        || recipe.surface_id != binding.surface_id
    {
        return Err(admission_error(
            "hypervisor_session_launch_recipe_target_mismatch",
            "Hypervisor session launch recipe admission requires recipe and target binding to agree.".to_string(),
            json!({
                "recipe_ref": recipe.recipe_id,
                "binding_recipe_ref": binding.recipe_ref,
                "recipe_kind": recipe.kind,
                "target_kind": binding.target_kind,
                "recipe_surface": recipe.surface_id,
                "target_surface": binding.surface_id,
            }),
        ));
    }
    let route_token = route_safe_id(&recipe.recipe_id);
    if !binding.session_route_ref.contains(&route_token) {
        return Err(admission_error(
            "hypervisor_session_launch_recipe_route_unbound",
            "Target binding session route must bind the selected recipe.".to_string(),
            json!({
                "recipe_ref": recipe.recipe_id,
                "expected_route_token": route_token,
                "session_route_ref": binding.session_route_ref,
            }),
        ));
    }
    if recipe.kind == "workbench" && binding.code_editor_adapter_target_ref.is_none() {
        return Err(admission_error(
            "hypervisor_session_launch_recipe_workbench_adapter_required",
            "Workbench launch recipes require a code editor adapter target binding.".to_string(),
            json!({ "recipe_ref": recipe.recipe_id }),
        ));
    }
    Ok(())
}

fn assert_no_retired_aliases(request: &Value) -> AdmitResult<()> {
    let Some(object) = request.as_object() else {
        return Ok(());
    };
    let present: Vec<String> = RETIRED_ALIASES
        .iter()
        .filter(|alias| object.contains_key(**alias))
        .map(|alias| alias.to_string())
        .collect();
    if present.is_empty() {
        return Ok(());
    }
    Err(admission_error(
        "hypervisor_session_launch_recipe_retired_aliases",
        "Hypervisor session launch recipe admission rejects retired camelCase aliases.".to_string(),
        json!({ "aliases": present }),
    ))
}

/// Mirror JS `recordValue`: a non-null, non-array object, else None.
fn record_value(value: Option<&Value>) -> Option<&Value> {
    match value {
        Some(value @ Value::Object(_)) => Some(value),
        _ => None,
    }
}

/// Mirror JS `requiredString(value, field)` — optionalString then throw field_required.
fn required_string(value: Option<&Value>, field: &str) -> AdmitResult<String> {
    optional_value(value).ok_or_else(|| {
        admission_error(
            "hypervisor_session_launch_recipe_field_required",
            format!("Hypervisor session launch recipe admission requires {field}."),
            json!({ "field": field }),
        )
    })
}

/// Mirror JS `prefixedString(value, field, prefix)` — required + startsWith(prefix).
fn prefixed_string(value: Option<&Value>, field: &str, prefix: &str) -> AdmitResult<String> {
    let string = required_string(value, field)?;
    if !string.starts_with(prefix) {
        return Err(admission_error(
            "hypervisor_session_launch_recipe_prefix_invalid",
            format!("{field} must start with {prefix}."),
            json!({ "field": field, "prefix": prefix, "value": string }),
        ));
    }
    Ok(string)
}

/// Mirror JS `prefixedRefs(value, field, prefix, {allowEmpty})`.
fn prefixed_refs(
    value: Option<&Value>,
    field: &str,
    prefix: &str,
    allow_empty: bool,
) -> AdmitResult<Vec<String>> {
    let refs = coerced_ref_list(value);
    if !allow_empty && refs.is_empty() {
        return Err(admission_error(
            "hypervisor_session_launch_recipe_refs_required",
            format!("Hypervisor session launch recipe admission requires {field}."),
            json!({ "field": field }),
        ));
    }
    for reference in &refs {
        if !reference.starts_with(prefix) {
            return Err(admission_error(
                "hypervisor_session_launch_recipe_ref_prefix_invalid",
                format!("{field} entries must start with {prefix}."),
                json!({ "field": field, "prefix": prefix, "value": reference }),
            ));
        }
    }
    Ok(refs)
}

/// Mirror JS `stringList(value, field)` — non-empty uniqueStrings of optionalString'd items.
fn string_list(value: Option<&Value>, field: &str) -> AdmitResult<Vec<String>> {
    let refs = coerced_ref_list(value);
    if refs.is_empty() {
        return Err(admission_error(
            "hypervisor_session_launch_recipe_list_required",
            format!("Hypervisor session launch recipe admission requires {field}."),
            json!({ "field": field }),
        ));
    }
    Ok(refs)
}

/// Mirror JS `enumValue(value, field, allowed)` — required + membership.
fn enum_value(value: Option<&Value>, field: &str, allowed: &[&str]) -> AdmitResult<String> {
    let string = required_string(value, field)?;
    if !allowed.contains(&string.as_str()) {
        return Err(admission_error(
            "hypervisor_session_launch_recipe_enum_invalid",
            format!("{field} has an unsupported value."),
            json!({ "field": field, "value": string, "allowed": allowed }),
        ));
    }
    Ok(string)
}

/// Mirror `uniqueStrings(normalizeArray(value).map(optionalString).filter(Boolean))`:
/// keep truthy raw items, coerce+trim each, drop blanks, first-seen dedup.
fn coerced_ref_list(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for item in items {
        if !is_truthy(item) {
            continue;
        }
        if let Some(coerced) = optional_value(Some(item)) {
            if !out.contains(&coerced) {
                out.push(coerced);
            }
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

/// Mirror JS `optionalString`: String(value).trim(), None when null/absent/blank.
fn optional_value(value: Option<&Value>) -> Option<String> {
    match value {
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

/// Mirror JS `booleanValue`: true/false or the "true"/"false" strings (case-insensitive),
/// else None.
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

/// Mirror JS `String(value)` for the value shapes that can appear in a ref array / scalar
/// field: scalars exactly; arrays comma-join their (string-coerced) elements with null/
/// undefined rendered empty; objects → "[object Object]". Numbers go through the ECMAScript
/// Number→String algorithm via `js_number_to_string` (JSON numbers are f64 in JS).
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

/// Mirror ECMAScript `Number::toString` (base 10) for a finite f64: the shortest round-tripping
/// decimal digits with V8's exponential thresholds (n>21 or n<=-6 → exponential), and -0 → "0".
/// Rust's `{:e}` yields the same shortest-round-trip mantissa as V8; we only reshape the layout.
fn js_number_to_string(value: f64) -> String {
    if value == 0.0 {
        return "0".to_string(); // covers +0 and -0 (JS String(-0) === "0")
    }
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity".to_string() } else { "-Infinity".to_string() };
    }
    let negative = value < 0.0;
    let magnitude = value.abs();
    // "1.23456e2" / "1e21" / "1e-7": shortest mantissa (no trailing zeros) + decimal exponent.
    let exp_form = format!("{magnitude:e}");
    let (mantissa, exp_str) = exp_form.split_once('e').unwrap_or((exp_form.as_str(), "0"));
    let exp: i32 = exp_str.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|ch| *ch != '.').collect();
    let k = digits.len() as i32; // significant-digit count
    let n = exp + 1; // value = digits * 10^(n - k)

    let body = if k <= n && n <= 21 {
        // Integer: all digits then (n-k) trailing zeros.
        let mut out = digits;
        for _ in 0..(n - k) {
            out.push('0');
        }
        out
    } else if 0 < n && n <= 21 {
        // Decimal point inside the digit string.
        let (head, tail) = digits.split_at(n as usize);
        format!("{head}.{tail}")
    } else if -6 < n && n <= 0 {
        // "0." then (-n) leading zeros then the digits.
        let mut out = String::from("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(&digits);
        out
    } else {
        // Exponential: d[.ddd]e±(n-1).
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

/// Mirror the SHARED `safeId`: collapse runs of chars outside [A-Za-z0-9_.-] to a single `_`.
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

/// Mirror JS `routeSafeId`: lowercase, collapse runs outside [a-z0-9_-] to `-`, trim `-`,
/// slice to 96 chars, default "recipe".
fn route_safe_id(value: &str) -> String {
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
        "recipe".to_string()
    } else {
        sliced
    }
}

fn admission_error(
    code: &str,
    message: String,
    details: Value,
) -> RuntimeHypervisorSessionLaunchRecipeAdmissionError {
    RuntimeHypervisorSessionLaunchRecipeAdmissionError::new(code, message, details)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipe() -> Value {
        json!({
            "schema_version": "ioi.hypervisor.session_launch_recipe.v1",
            "recipe_id": "workbench.default",
            "label": "Workbench",
            "description": "Governed code/systems session that opens the selected code editor adapter.",
            "kind": "workbench",
            "surface_id": "workbench",
            "required_inputs": ["project", "adapter_preference", "harness", "model_route", "privacy_posture"],
            "model_mount_policy": "inherit",
            "harness_profile_policy": "select",
            "authority_scope_templates": ["scope:workspace.read", "scope:workspace.patch"],
            "privacy_posture_templates": ["public_trunk", "redacted_projection"],
        })
    }

    fn target_binding() -> Value {
        json!({
            "schema_version": "ioi.hypervisor.new_session_target_binding.v1",
            "target_binding_ref": "target-binding:new-session/workbench-default/ioi",
            "recipe_ref": "workbench.default",
            "target_kind": "workbench",
            "surface_id": "workbench",
            "project_ref": "project:ioi",
            "operator_intent_ref": "target-binding:new-session/workbench.default/ioi/operator-intent",
            "session_route_ref": "session-route:workbench/workbench-default/ioi",
            "code_editor_adapter_target_ref": "code-editor-target:vscode",
            "automation_recipe_ref": null,
            "agent_template_ref": null,
            "foundry_job_ref": null,
            "provider_candidate_ref": null,
            "environment_ref": null,
            "private_workspace_ref": null,
            "runtimeTruthSource": "daemon-runtime",
        })
    }

    fn request() -> Value {
        json!({
            "schema_version": "ioi.hypervisor.session_launch_recipe_admission_request.v1",
            "recipe": recipe(),
            "target_binding": target_binding(),
            "model_route_ref": "model-route:hypervisor/default-local",
            "privacy_posture_ref": "privacy:redacted-projection",
            "authority_scope_refs": ["scope:workspace.read", "scope:workspace.patch"],
            "receipt_preview_ref": "receipt-preview:new-session/workbench",
            "expected_receipt_refs": [
                "receipt-preview:new-session/workbench",
                "receipt-policy:harness-adapter/default",
            ],
            "agentgres_operation_refs": ["agentgres://operation/hypervisor/session-launch-recipe/workbench"],
            "receipt_refs": ["receipt://hypervisor/session-launch-recipe/workbench"],
            "state_root": "agentgres://state-root/hypervisor/session-launch-recipe/workbench",
            "requires_daemon_gate": true,
            "runtimeTruthSource": "daemon-runtime",
        })
    }

    #[test]
    fn admits_session_launch_recipes_before_harness_binding() {
        let admission = RuntimeHypervisorSessionLaunchRecipeAdmissionCore
            .admit(&request(), "2026-06-19T12:00:00.000Z")
            .expect("admitted");
        assert_eq!(admission["schema_version"], HYPERVISOR_SESSION_LAUNCH_RECIPE_ADMISSION_SCHEMA_VERSION);
        assert_eq!(admission["decision"], "admitted");
        assert_eq!(admission["admission_state"], "admitted_for_session_binding");
        assert_eq!(admission["recipe_ref"], "workbench.default");
        assert_eq!(admission["target_binding_ref"], "target-binding:new-session/workbench-default/ioi");
        assert_eq!(admission["session_route_ref"], "session-route:workbench/workbench-default/ioi");
        assert_eq!(admission["model_route_ref"], "model-route:hypervisor/default-local");
        assert_eq!(
            admission["authority_scope_refs"],
            json!(["scope:workspace.read", "scope:workspace.patch"])
        );
        assert_eq!(admission["requiresDaemonGate"], true);
        assert_eq!(admission["runtimeTruthSource"], "daemon-runtime");
        assert_eq!(admission["admitted_at"], "2026-06-19T12:00:00.000Z");
    }

    #[test]
    fn blocks_target_binding_mismatch() {
        let mut request = request();
        request["target_binding"]["recipe_ref"] = json!("agent.default");
        request["target_binding"]["target_kind"] = json!("agent");
        request["target_binding"]["surface_id"] = json!("agents");
        let error = RuntimeHypervisorSessionLaunchRecipeAdmissionCore
            .admit(&request, "now")
            .expect_err("mismatch");
        assert_eq!(error.code, "hypervisor_session_launch_recipe_target_mismatch");
        assert_eq!(error.status, 400);
    }

    #[test]
    fn blocks_workbench_without_code_editor_adapter() {
        let mut request = request();
        request["target_binding"]["code_editor_adapter_target_ref"] = Value::Null;
        let error = RuntimeHypervisorSessionLaunchRecipeAdmissionCore
            .admit(&request, "now")
            .expect_err("missing adapter");
        assert_eq!(error.code, "hypervisor_session_launch_recipe_workbench_adapter_required");
    }

    #[test]
    fn rejects_retired_aliases() {
        let mut request = request();
        request["recipeRef"] = json!("legacy");
        let error = RuntimeHypervisorSessionLaunchRecipeAdmissionCore
            .admit(&request, "now")
            .expect_err("retired alias");
        assert_eq!(error.code, "hypervisor_session_launch_recipe_retired_aliases");
    }

    #[test]
    fn rejects_authority_primitive_masquerade() {
        let mut request = request();
        request["authority_scope_refs"] = json!(["prim:shell.exec"]);
        let error = RuntimeHypervisorSessionLaunchRecipeAdmissionCore
            .admit(&request, "now")
            .expect_err("bad prefix");
        assert_eq!(error.code, "hypervisor_session_launch_recipe_ref_prefix_invalid");
    }

    #[test]
    fn requires_daemon_gate_and_runtime_truth() {
        let mut request = request();
        request["requires_daemon_gate"] = json!(false);
        let error = RuntimeHypervisorSessionLaunchRecipeAdmissionCore
            .admit(&request, "now")
            .expect_err("no gate");
        assert_eq!(error.code, "hypervisor_session_launch_recipe_daemon_gate_required");
    }

    #[test]
    fn requires_receipt_preview_binding() {
        let mut request = request();
        request["expected_receipt_refs"] = json!(["receipt-policy:harness-adapter/default"]);
        let error = RuntimeHypervisorSessionLaunchRecipeAdmissionCore
            .admit(&request, "now")
            .expect_err("unbound preview");
        assert_eq!(error.code, "hypervisor_session_launch_recipe_receipt_preview_unbound");
    }

    #[test]
    fn surface_must_match_kind() {
        let mut request = request();
        request["recipe"]["surface_id"] = json!("sessions");
        request["target_binding"]["surface_id"] = json!("sessions");
        let error = RuntimeHypervisorSessionLaunchRecipeAdmissionCore
            .admit(&request, "now")
            .expect_err("surface mismatch");
        assert_eq!(error.code, "hypervisor_session_launch_recipe_surface_mismatch");
    }

    #[test]
    fn js_number_to_string_matches_ecmascript() {
        // Expected values captured from Node `String(n)`.
        let cases: &[(f64, &str)] = &[
            (1e21, "1e+21"),
            (1e22, "1e+22"),
            (1e-7, "1e-7"),
            (1.5e-7, "1.5e-7"),
            (0.000001, "0.000001"),
            (1e-6, "0.000001"),
            (123.456, "123.456"),
            (0.1, "0.1"),
            (1000.0, "1000"),
            (1e20, "100000000000000000000"),
            (123456789012345680000.0, "123456789012345680000"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (-0.0, "0"),
            (-1.5e-7, "-1.5e-7"),
            (21.0, "21"),
            (0.5, "0.5"),
        ];
        for (input, expected) in cases {
            assert_eq!(js_number_to_string(*input), *expected, "String({input})");
        }
    }

    #[test]
    fn derives_operation_and_receipt_refs_when_absent() {
        let mut request = request();
        // Drop optional refs so the generated ones surface.
        request.as_object_mut().unwrap().remove("agentgres_operation_refs");
        request.as_object_mut().unwrap().remove("receipt_refs");
        request.as_object_mut().unwrap().remove("state_root");
        let admission = RuntimeHypervisorSessionLaunchRecipeAdmissionCore
            .admit(&request, "now")
            .expect("admitted");
        let safe = "target-binding_new-session_workbench-default_ioi";
        assert_eq!(
            admission["agentgres_operation_refs"],
            json!([format!("agentgres://operation/hypervisor/session-launch-recipe/{safe}")])
        );
        assert_eq!(
            admission["receipt_refs"],
            json!([format!("receipt://hypervisor/session-launch-recipe/{safe}/admitted")])
        );
        assert_eq!(
            admission["state_root"],
            json!(format!("agentgres://state-root/hypervisor/session-launch-recipe/{safe}"))
        );
    }
}
