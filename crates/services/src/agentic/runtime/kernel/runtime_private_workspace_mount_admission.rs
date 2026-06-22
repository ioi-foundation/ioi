//! Private-workspace-mount admission planner.
//!
//! A faithful Rust port of the retired JS `admitPrivateWorkspaceMount`
//! (`packages/runtime-daemon/src/runtime-private-workspace-mount-admission.mjs`). Pure
//! validation + canonicalization: asserts the custody-class / mount-target / execution-privacy
//! lane is admissible, the required controls / authority scopes / attestation / customer-boundary
//! / wallet / declassification refs are bound, and decides whether the mount is a plain admit, a
//! declassification, or an explicit unsafe-plaintext exception.
//!
//! STATUS varies per branch: the field-shape helpers (required/prefix/enum) reject HTTP 400; the
//! custody-lane policy assertions (`admissionError`) reject HTTP 403. The JS field-extraction
//! order is preserved (all extraction first, then `assertMountAdmission`). `prefixedRefs` and
//! `required_controls` use the SHARED `uniqueStrings(normalizeArray(value))` — NO trim;
//! `enumValue`/scalars use `optionalString` — trim. `prefixedString`/`prefixedRefs` reject bad
//! prefixes with a FIXED `..._ref_prefix_invalid` code (details key `ref`, not `value`).

use serde_json::{json, Map, Value};

pub const PRIVATE_WORKSPACE_MOUNT_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.runtime.private_workspace_mount_admission.v1";

const CUSTODY_CLASSES: &[&str] = &[
    "public_trunk",
    "redacted_projection",
    "encrypted_blob_ref",
    "private_head",
    "capability_exit",
    "unsafe_plaintext_mount",
];

const MOUNT_TARGETS: &[&str] = &[
    "local_device",
    "user_owned_node",
    "browser_client",
    "rented_gpu",
    "customer_cloud",
    "tee_session",
];

const EXECUTION_PRIVACY_POSTURES: &[&str] = &[
    "private_native",
    "ctee_split",
    "encrypted_storage_only",
    "confidential_compute",
    "remote_api_provider_trust",
    "unsafe_plaintext_mount",
];

const RETIRED_ALIASES: &[&str] = &[
    "workspaceMountProfile",
    "providerRootCanReadPlaintext",
    "protectedPlaintextRequested",
];

#[derive(Debug, Clone)]
pub struct RuntimePrivateWorkspaceMountAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimePrivateWorkspaceMountAdmissionError {
    fn new(status: u16, code: String, message: String, details: Value) -> Self {
        Self { status, code, message, details }
    }
}

type AdmitResult<T> = Result<T, RuntimePrivateWorkspaceMountAdmissionError>;

#[derive(Default)]
pub struct RuntimePrivateWorkspaceMountAdmissionCore;

impl RuntimePrivateWorkspaceMountAdmissionCore {
    pub fn admit(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        assert_no_retired_aliases(request)?;

        let workspace_ref =
            prefixed_string(request.get("workspace_ref"), "workspace_ref", "workspace://")?;
        let mount_ref = required_string(request.get("mount_ref"), "mount_ref")?;
        let segment_ref = required_string(request.get("segment_ref"), "segment_ref")?;
        let provider_ref =
            optional_value(request.get("provider_ref")).unwrap_or_else(|| "provider:unspecified".to_string());
        let custody_class = enum_value(request.get("custody_class"), "custody_class", CUSTODY_CLASSES)?;
        let mount_target = enum_value(request.get("mount_target"), "mount_target", MOUNT_TARGETS)?;
        let execution_privacy_posture = enum_value(
            request.get("execution_privacy_posture"),
            "execution_privacy_posture",
            EXECUTION_PRIVACY_POSTURES,
        )?;
        let provider_root_can_read_plaintext =
            boolean_value(request.get("provider_root_can_read_plaintext")).unwrap_or(false);
        let protected_plaintext_requested =
            boolean_value(request.get("protected_plaintext_requested")).unwrap_or(false);
        let required_controls = unique_strings_raw(request.get("required_controls"));
        let authority_scope_refs =
            prefixed_refs(request.get("authority_scope_refs"), "authority_scope_refs", "scope:", true)?;
        let wallet_approval_ref = optional_value(request.get("wallet_approval_ref"));
        let wallet_lease_ref = optional_value(request.get("wallet_lease_ref"));
        let user_disclosure_ref = optional_value(request.get("user_disclosure_ref"));
        let provider_trust_acceptance_ref = optional_value(request.get("provider_trust_acceptance_ref"));
        let tee_attestation_ref = optional_value(request.get("tee_attestation_ref"));
        let customer_boundary_ref = optional_value(request.get("customer_boundary_ref"));
        let declassification_receipt_refs = prefixed_refs(
            request.get("declassification_receipt_refs"),
            "declassification_receipt_refs",
            "receipt://",
            true,
        )?;
        let agentgres_operation_refs = prefixed_refs(
            request.get("agentgres_operation_refs"),
            "agentgres_operation_refs",
            "agentgres://operation/",
            false,
        )?;
        let artifact_refs = prefixed_refs(
            request.get("artifact_refs"),
            "artifact_refs",
            "artifact://",
            custody_class == "capability_exit",
        )?;
        let state_root_ref =
            prefixed_string(request.get("state_root_ref"), "state_root_ref", "agentgres://state-root/")?;

        assert_mount_admission(
            &custody_class,
            &mount_target,
            &execution_privacy_posture,
            provider_root_can_read_plaintext,
            protected_plaintext_requested,
            &required_controls,
            &authority_scope_refs,
            wallet_approval_ref.as_deref(),
            wallet_lease_ref.as_deref(),
            user_disclosure_ref.as_deref(),
            provider_trust_acceptance_ref.as_deref(),
            tee_attestation_ref.as_deref(),
            customer_boundary_ref.as_deref(),
            &declassification_receipt_refs,
        )?;

        let decision =
            decision_for(&custody_class, provider_root_can_read_plaintext, protected_plaintext_requested);

        let admission_id = optional_value(request.get("admission_id")).unwrap_or_else(|| {
            format!(
                "private-workspace-mount-admission:{}:{}:{}",
                safe_id(&workspace_ref),
                safe_id(&segment_ref),
                safe_id(&custody_class)
            )
        });
        let receipt_ref = optional_value(request.get("receipt_ref")).unwrap_or_else(|| {
            format!(
                "receipt://private-workspace-mount/{}/{}/{}",
                safe_id(&workspace_ref),
                safe_id(&segment_ref),
                safe_id(decision)
            )
        });
        let admitted_at =
            optional_value(request.get("admitted_at")).unwrap_or_else(|| now_iso.to_string());

        let exposed = protected_plaintext_requested && provider_root_can_read_plaintext;

        Ok(json!({
            "schema_version": PRIVATE_WORKSPACE_MOUNT_ADMISSION_SCHEMA_VERSION,
            "admission_id": admission_id,
            "decision": decision,
            "workspace_ref": workspace_ref,
            "mount_ref": mount_ref,
            "segment_ref": segment_ref,
            "provider_ref": provider_ref,
            "custody_class": custody_class,
            "mount_target": mount_target,
            "execution_privacy_posture": execution_privacy_posture,
            "provider_root_can_read_plaintext": provider_root_can_read_plaintext,
            "protected_plaintext_requested": protected_plaintext_requested,
            "protected_plaintext_exposed_to_provider_root": exposed,
            "protects_workspace_plaintext_from_provider_root": !exposed,
            "required_controls": required_controls,
            "authority_scope_refs": authority_scope_refs,
            "wallet_approval_ref": wallet_approval_ref,
            "wallet_lease_ref": wallet_lease_ref,
            "user_disclosure_ref": user_disclosure_ref,
            "provider_trust_acceptance_ref": provider_trust_acceptance_ref,
            "tee_attestation_ref": tee_attestation_ref,
            "customer_boundary_ref": customer_boundary_ref,
            "declassification_receipt_refs": declassification_receipt_refs,
            "agentgres_operation_refs": agentgres_operation_refs,
            "artifact_refs": artifact_refs,
            "state_root_ref": state_root_ref,
            "receipt_ref": receipt_ref,
            "admitted_at": admitted_at,
            "runtimeTruthSource": "daemon-runtime",
        }))
    }
}

#[allow(clippy::too_many_arguments)]
fn assert_mount_admission(
    custody_class: &str,
    mount_target: &str,
    execution_privacy_posture: &str,
    provider_root_can_read_plaintext: bool,
    protected_plaintext_requested: bool,
    required_controls: &[String],
    authority_scope_refs: &[String],
    wallet_approval_ref: Option<&str>,
    wallet_lease_ref: Option<&str>,
    user_disclosure_ref: Option<&str>,
    provider_trust_acceptance_ref: Option<&str>,
    tee_attestation_ref: Option<&str>,
    customer_boundary_ref: Option<&str>,
    declassification_receipt_refs: &[String],
) -> AdmitResult<()> {
    if custody_class == "public_trunk" {
        if protected_plaintext_requested {
            return Err(authority_error(
                "private_workspace_mount_public_trunk_plaintext_claim_invalid",
                "Public-trunk mounts cannot request protected private workspace plaintext.",
                json!({ "custody_class": custody_class }),
            ));
        }
        return Ok(());
    }

    if custody_class == "redacted_projection" {
        require_control(required_controls, "redaction_verified", custody_class)?;
        if protected_plaintext_requested {
            return Err(authority_error(
                "private_workspace_mount_redacted_plaintext_claim_invalid",
                "Redacted projection mounts cannot request protected private workspace plaintext.",
                json!({ "custody_class": custody_class }),
            ));
        }
        return Ok(());
    }

    if custody_class == "encrypted_blob_ref" {
        require_control(required_controls, "encrypted_blob_refs_only", custody_class)?;
        if protected_plaintext_requested || provider_root_can_read_plaintext {
            return Err(authority_error(
                "private_workspace_mount_encrypted_blob_plaintext_blocked",
                "Encrypted private workspace blob refs cannot materialize provider-readable plaintext.",
                json!({
                    "protected_plaintext_requested": protected_plaintext_requested,
                    "provider_root_can_read_plaintext": provider_root_can_read_plaintext,
                }),
            ));
        }
        return Ok(());
    }

    if custody_class == "capability_exit" {
        require_control(required_controls, "capability_exit_only", custody_class)?;
        require_scope(authority_scope_refs, "scope:capability.use", custody_class)?;
        if protected_plaintext_requested || provider_root_can_read_plaintext {
            return Err(authority_error(
                "private_workspace_mount_capability_exit_plaintext_blocked",
                "Capability-exit mounts expose operation handles, not private workspace plaintext.",
                json!({ "custody_class": custody_class }),
            ));
        }
        return Ok(());
    }

    if custody_class == "private_head" && matches!(mount_target, "tee_session" | "customer_cloud") {
        if tee_attestation_ref.is_some() {
            require_control(required_controls, "tee_attestation", custody_class)?;
        }
        if customer_boundary_ref.is_some() {
            require_control(required_controls, "customer_account_boundary", custody_class)?;
        }
        if tee_attestation_ref.is_none() && customer_boundary_ref.is_none() {
            return Err(authority_error(
                "private_workspace_mount_attestation_or_customer_boundary_required",
                "Private-head mounts into TEE/customer-cloud targets require attestation or a customer-boundary ref.",
                json!({ "required": ["tee_attestation_ref", "customer_boundary_ref"] }),
            ));
        }
        if provider_root_can_read_plaintext {
            return Err(authority_error(
                "private_workspace_mount_confidential_provider_root_plaintext_invalid",
                "Confidential private-head mounts cannot claim provider-root plaintext visibility.",
                json!({ "mount_target": mount_target }),
            ));
        }
        return Ok(());
    }

    if custody_class == "private_head"
        && matches!(mount_target, "local_device" | "user_owned_node" | "browser_client")
    {
        require_control(required_controls, "wallet_decryption_lease", custody_class)?;
        require_scope(authority_scope_refs, "scope:artifact.decrypt", custody_class)?;
        if provider_root_can_read_plaintext {
            return Err(authority_error(
                "private_workspace_mount_local_provider_root_plaintext_invalid",
                "Local/user-custody private-head mounts cannot expose plaintext to provider root.",
                json!({ "mount_target": mount_target }),
            ));
        }
        return Ok(());
    }

    if custody_class == "private_head"
        && mount_target == "rented_gpu"
        && !provider_root_can_read_plaintext
        && !protected_plaintext_requested
    {
        require_control(required_controls, "ctee_private_head_handle", custody_class)?;
        require_scope(authority_scope_refs, "scope:ctee.private-head.evaluate", custody_class)?;
        if execution_privacy_posture != "ctee_split" {
            return Err(authority_error(
                "private_workspace_mount_ctee_posture_required",
                "Rented-node private-head handles require cTEE split posture unless plaintext is explicitly declassified.",
                json!({ "execution_privacy_posture": execution_privacy_posture }),
            ));
        }
        return Ok(());
    }

    if custody_class == "unsafe_plaintext_mount"
        || (custody_class == "private_head"
            && mount_target == "rented_gpu"
            && provider_root_can_read_plaintext)
    {
        return require_unsafe_plaintext_exception(
            required_controls,
            authority_scope_refs,
            wallet_approval_ref,
            wallet_lease_ref,
            user_disclosure_ref,
            provider_trust_acceptance_ref,
            declassification_receipt_refs,
            protected_plaintext_requested,
            provider_root_can_read_plaintext,
        );
    }

    Err(authority_error(
        "private_workspace_mount_custody_target_not_admissible",
        "Private workspace mount custody and target combination is not admissible.",
        json!({ "custody_class": custody_class, "mount_target": mount_target }),
    ))
}

#[allow(clippy::too_many_arguments)]
fn require_unsafe_plaintext_exception(
    required_controls: &[String],
    authority_scope_refs: &[String],
    wallet_approval_ref: Option<&str>,
    wallet_lease_ref: Option<&str>,
    user_disclosure_ref: Option<&str>,
    provider_trust_acceptance_ref: Option<&str>,
    declassification_receipt_refs: &[String],
    protected_plaintext_requested: bool,
    provider_root_can_read_plaintext: bool,
) -> AdmitResult<()> {
    if !protected_plaintext_requested || !provider_root_can_read_plaintext {
        return Err(authority_error(
            "private_workspace_mount_unsafe_plaintext_shape_invalid",
            "Unsafe plaintext mount exceptions must explicitly request protected plaintext readable by provider root.",
            json!({
                "protected_plaintext_requested": protected_plaintext_requested,
                "provider_root_can_read_plaintext": provider_root_can_read_plaintext,
            }),
        ));
    }
    require_control(required_controls, "explicit_unsafe_plaintext_acceptance", "unsafe_plaintext_mount")?;
    require_scope(authority_scope_refs, "scope:privacy.unsafe_plaintext_mount", "unsafe_plaintext_mount")?;
    require_prefixed(wallet_approval_ref, "wallet_approval_ref", "approval://wallet/", "unsafe_plaintext_mount")?;
    require_prefixed(wallet_lease_ref, "wallet_lease_ref", "lease:", "unsafe_plaintext_mount")?;
    require_prefixed(user_disclosure_ref, "user_disclosure_ref", "disclosure://", "unsafe_plaintext_mount")?;
    require_prefixed(
        provider_trust_acceptance_ref,
        "provider_trust_acceptance_ref",
        "approval://provider-trust/",
        "unsafe_plaintext_mount",
    )?;
    if declassification_receipt_refs.is_empty() {
        return Err(authority_error(
            "private_workspace_mount_declassification_receipt_required",
            "Unsafe private workspace plaintext mounts require declassification receipts.",
            json!({ "required": "declassification_receipt_refs" }),
        ));
    }
    Ok(())
}

fn decision_for(
    custody_class: &str,
    provider_root_can_read_plaintext: bool,
    protected_plaintext_requested: bool,
) -> &'static str {
    if protected_plaintext_requested && provider_root_can_read_plaintext {
        "admitted_unsafe_exception"
    } else if custody_class == "private_head" {
        "admitted_declassification"
    } else {
        "admitted"
    }
}

fn assert_no_retired_aliases(request: &Value) -> AdmitResult<()> {
    let empty = Map::new();
    let object = request.as_object().unwrap_or(&empty);
    let retired: Vec<String> = RETIRED_ALIASES
        .iter()
        .filter(|alias| object.contains_key(**alias))
        .map(|alias| alias.to_string())
        .collect();
    if retired.is_empty() {
        return Ok(());
    }
    Err(RuntimePrivateWorkspaceMountAdmissionError::new(
        400,
        "private_workspace_mount_request_aliases_retired".to_string(),
        "Private workspace mount admission accepts only canonical snake_case request fields.".to_string(),
        json!({ "retired_aliases": retired }),
    ))
}

/// Mirror JS `enumValue` — optionalString (trim) + membership; 400 `_invalid`; dynamic field key.
fn enum_value(value: Option<&Value>, field: &str, allowed: &[&str]) -> AdmitResult<String> {
    let normalized = optional_value(value);
    match &normalized {
        Some(value) if allowed.contains(&value.as_str()) => Ok(value.clone()),
        _ => {
            let mut details = Map::new();
            details.insert(field.to_string(), normalized.map(Value::String).unwrap_or(Value::Null));
            details.insert("allowed_values".to_string(), json!(allowed));
            Err(RuntimePrivateWorkspaceMountAdmissionError::new(
                400,
                format!("private_workspace_mount_{field}_invalid"),
                format!("Private workspace mount admission requires a valid {field}."),
                Value::Object(details),
            ))
        }
    }
}

/// Mirror JS `prefixedString` — requiredString + startsWith; FIXED `_ref_prefix_invalid` code.
fn prefixed_string(value: Option<&Value>, field: &str, prefix: &str) -> AdmitResult<String> {
    let normalized = required_string(value, field)?;
    if !normalized.starts_with(prefix) {
        return Err(ref_prefix_error(field, &normalized, prefix));
    }
    Ok(normalized)
}

/// Mirror JS `prefixedRefs` — `uniqueStrings(normalizeArray(value))` (NO trim), required-non-empty
/// unless allow_empty, then prefix each.
fn prefixed_refs(
    value: Option<&Value>,
    field: &str,
    prefix: &str,
    allow_empty: bool,
) -> AdmitResult<Vec<String>> {
    let refs = unique_strings_raw(value);
    if !allow_empty && refs.is_empty() {
        return Err(RuntimePrivateWorkspaceMountAdmissionError::new(
            400,
            "private_workspace_mount_required_refs_missing".to_string(),
            format!("Private workspace mount admission requires {field}."),
            json!({ "field": field }),
        ));
    }
    for reference in &refs {
        if !reference.starts_with(prefix) {
            return Err(ref_prefix_error(field, reference, prefix));
        }
    }
    Ok(refs)
}

fn ref_prefix_error(field: &str, reference: &str, prefix: &str) -> RuntimePrivateWorkspaceMountAdmissionError {
    RuntimePrivateWorkspaceMountAdmissionError::new(
        400,
        "private_workspace_mount_ref_prefix_invalid".to_string(),
        format!("{field} must use {prefix} refs."),
        json!({ "field": field, "ref": reference, "expected_prefix": prefix }),
    )
}

/// Mirror JS `requiredString` — optionalString then 400 `_required`.
fn required_string(value: Option<&Value>, field: &str) -> AdmitResult<String> {
    optional_value(value).ok_or_else(|| {
        RuntimePrivateWorkspaceMountAdmissionError::new(
            400,
            format!("private_workspace_mount_{field}_required"),
            format!("Private workspace mount admission requires {field}."),
            json!({ "field": field }),
        )
    })
}

fn require_control(required_controls: &[String], control: &str, custody_class: &str) -> AdmitResult<()> {
    if required_controls.iter().any(|value| value == control) {
        return Ok(());
    }
    Err(authority_error(
        "private_workspace_mount_required_control_missing",
        &format!("Private workspace mount admission is missing required control {control}."),
        json!({ "custody_class": custody_class, "required_control": control }),
    ))
}

fn require_scope(authority_scope_refs: &[String], scope: &str, custody_class: &str) -> AdmitResult<()> {
    if authority_scope_refs.iter().any(|value| value == scope) {
        return Ok(());
    }
    Err(authority_error(
        "private_workspace_mount_required_scope_missing",
        &format!("Private workspace mount admission is missing required authority scope {scope}."),
        json!({ "custody_class": custody_class, "required_scope": scope }),
    ))
}

/// Mirror JS `requirePrefixed`: optionalString(value)?.startsWith(prefix) (value already trimmed).
fn require_prefixed(
    value: Option<&str>,
    field: &str,
    prefix: &str,
    custody_class: &str,
) -> AdmitResult<()> {
    if value.map(|inner| inner.starts_with(prefix)).unwrap_or(false) {
        return Ok(());
    }
    Err(authority_error(
        "private_workspace_mount_required_ref_missing",
        &format!("Private workspace mount admission requires {field}."),
        json!({ "custody_class": custody_class, "field": field, "expected_prefix": prefix }),
    ))
}

fn authority_error(code: &str, message: &str, details: Value) -> RuntimePrivateWorkspaceMountAdmissionError {
    RuntimePrivateWorkspaceMountAdmissionError::new(403, code.to_string(), message.to_string(), details)
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
/// objects → "[object Object]". Numbers via the ECMAScript Number→String algorithm.
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

/// Mirror ECMAScript `Number::toString` (base 10) for a finite f64.
fn js_number_to_string(value: f64) -> String {
    if value == 0.0 {
        return "0".to_string();
    }
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity".to_string() } else { "-Infinity".to_string() };
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

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request() -> Value {
        json!({
            "workspace_ref": "workspace://ioi",
            "mount_ref": "mount://workspace/public-trunk",
            "segment_ref": "workspace-segment:public-trunk",
            "provider_ref": "provider:akash/gpu-market",
            "custody_class": "public_trunk",
            "mount_target": "rented_gpu",
            "execution_privacy_posture": "ctee_split",
            "provider_root_can_read_plaintext": true,
            "protected_plaintext_requested": false,
            "required_controls": [],
            "authority_scope_refs": [],
            "agentgres_operation_refs": ["agentgres://operation/privacy/mount"],
            "artifact_refs": ["artifact://workspace/public-trunk"],
            "state_root_ref": "agentgres://state-root/workspace/ioi",
        })
    }

    #[test]
    fn admits_public_trunk() {
        let admission = RuntimePrivateWorkspaceMountAdmissionCore
            .admit(&base_request(), "2026-06-18T12:00:00.000Z")
            .expect("admitted");
        assert_eq!(admission["schema_version"], PRIVATE_WORKSPACE_MOUNT_ADMISSION_SCHEMA_VERSION);
        assert_eq!(admission["decision"], "admitted");
        assert_eq!(admission["custody_class"], "public_trunk");
        assert_eq!(admission["protected_plaintext_exposed_to_provider_root"], false);
        assert_eq!(admission["protects_workspace_plaintext_from_provider_root"], true);
        assert_eq!(admission["runtimeTruthSource"], "daemon-runtime");
        assert_eq!(admission["admitted_at"], "2026-06-18T12:00:00.000Z");
    }

    #[test]
    fn admits_ctee_private_head_rented_gpu() {
        let mut request = base_request();
        request["custody_class"] = json!("private_head");
        request["mount_target"] = json!("rented_gpu");
        request["execution_privacy_posture"] = json!("ctee_split");
        request["provider_root_can_read_plaintext"] = json!(false);
        request["required_controls"] = json!(["ctee_private_head_handle"]);
        request["authority_scope_refs"] = json!(["scope:ctee.private-head.evaluate"]);
        let admission = RuntimePrivateWorkspaceMountAdmissionCore.admit(&request, "now").expect("admitted");
        assert_eq!(admission["decision"], "admitted_declassification");
    }

    #[test]
    fn admits_unsafe_plaintext_exception() {
        let mut request = base_request();
        request["custody_class"] = json!("unsafe_plaintext_mount");
        request["execution_privacy_posture"] = json!("unsafe_plaintext_mount");
        request["provider_root_can_read_plaintext"] = json!(true);
        request["protected_plaintext_requested"] = json!(true);
        request["required_controls"] = json!(["explicit_unsafe_plaintext_acceptance"]);
        request["authority_scope_refs"] = json!(["scope:privacy.unsafe_plaintext_mount"]);
        request["wallet_approval_ref"] = json!("approval://wallet/privacy/unsafe-mount");
        request["wallet_lease_ref"] = json!("lease:wallet/privacy/unsafe-mount");
        request["user_disclosure_ref"] = json!("disclosure://privacy/unsafe-mount");
        request["provider_trust_acceptance_ref"] = json!("approval://provider-trust/unsafe-mount");
        request["declassification_receipt_refs"] = json!(["receipt://privacy/declassification/unsafe-mount"]);
        let admission = RuntimePrivateWorkspaceMountAdmissionCore.admit(&request, "now").expect("admitted");
        assert_eq!(admission["decision"], "admitted_unsafe_exception");
        assert_eq!(admission["protected_plaintext_exposed_to_provider_root"], true);
        assert_eq!(admission["protects_workspace_plaintext_from_provider_root"], false);
    }

    #[test]
    fn unsafe_plaintext_requires_wallet_approval() {
        let mut request = base_request();
        request["custody_class"] = json!("unsafe_plaintext_mount");
        request["execution_privacy_posture"] = json!("unsafe_plaintext_mount");
        request["provider_root_can_read_plaintext"] = json!(true);
        request["protected_plaintext_requested"] = json!(true);
        request["required_controls"] = json!(["explicit_unsafe_plaintext_acceptance"]);
        request["authority_scope_refs"] = json!(["scope:privacy.unsafe_plaintext_mount"]);
        request["user_disclosure_ref"] = json!("disclosure://privacy/unsafe-mount");
        request["provider_trust_acceptance_ref"] = json!("approval://provider-trust/unsafe-mount");
        let error = RuntimePrivateWorkspaceMountAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.code, "private_workspace_mount_required_ref_missing");
        assert_eq!(error.status, 403);
    }

    #[test]
    fn redacted_requires_control() {
        let mut request = base_request();
        request["custody_class"] = json!("redacted_projection");
        request["required_controls"] = json!([]);
        let error = RuntimePrivateWorkspaceMountAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.code, "private_workspace_mount_required_control_missing");
        assert_eq!(error.status, 403);
    }

    #[test]
    fn bad_workspace_prefix_is_400() {
        let mut request = base_request();
        request["workspace_ref"] = json!("nope://x");
        let error = RuntimePrivateWorkspaceMountAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.code, "private_workspace_mount_ref_prefix_invalid");
        assert_eq!(error.status, 400);
    }

    #[test]
    fn capability_exit_allows_empty_artifacts() {
        let mut request = base_request();
        request["custody_class"] = json!("capability_exit");
        request["provider_root_can_read_plaintext"] = json!(false);
        request["required_controls"] = json!(["capability_exit_only"]);
        request["authority_scope_refs"] = json!(["scope:capability.use"]);
        request["artifact_refs"] = json!([]);
        let admission = RuntimePrivateWorkspaceMountAdmissionCore.admit(&request, "now").expect("admitted");
        assert_eq!(admission["decision"], "admitted");
        assert_eq!(admission["custody_class"], "capability_exit");
    }

    #[test]
    fn rejects_retired_aliases() {
        let mut request = base_request();
        request["workspaceMountProfile"] = json!("legacy");
        request["providerRootCanReadPlaintext"] = json!(true);
        request["protectedPlaintextRequested"] = json!(true);
        let error = RuntimePrivateWorkspaceMountAdmissionCore.admit(&request, "now").expect_err("retired");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "private_workspace_mount_request_aliases_retired");
        assert_eq!(
            error.details["retired_aliases"],
            json!(["workspaceMountProfile", "providerRootCanReadPlaintext", "protectedPlaintextRequested"])
        );
    }
}
