//! Code-editor-adapter-launch-plan admission planner.
//!
//! A faithful Rust port of the retired JS `admitCodeEditorAdapterLaunchPlan`
//! (`packages/runtime-daemon/src/runtime-code-editor-adapter-launch-plan-admission.mjs`). Pure
//! validation: a code-editor adapter launch plan is admitted only when its refs/connection/control
//! metadata match the connection kind, it requires no durable secret release, and the adapter
//! claims no runtime truth.
//!
//! HELPER NOTE: LOCAL `uniqueStrings` TRIMS (`String(v).trim()`). STATUS: field-shape helpers
//! (required/enum/prefix/non-empty) reject 400; policy assertions reject 403. `requirePrefix`
//! rejects with a per-field `..._{field}_prefix_invalid` code (details keys `field`,`value`).

use serde_json::{json, Map, Value};

pub const CODE_EDITOR_ADAPTER_LAUNCH_PLAN_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.runtime.code_editor_adapter_launch_plan_admission.v1";

const LAUNCH_MODES: &[&str] = &["embedded", "external", "remote_url"];
const CONNECTION_KINDS: &[&str] = &["embedded_host", "desktop_editor", "browser_editor_url"];
const EXECUTOR_LANES: &[&str] =
    &["embedded_code_editor_host", "desktop_editor", "browser_code_editor"];
const CONTROL_ACTIONS: &[&str] =
    &["open_embedded_code_editor", "open_desktop_editor", "open_browser_editor"];
const CUSTODY_POSTURES: &[&str] = &["local_projection", "redacted_projection"];

const RETIRED_ALIASES: &[&str] = &[
    "launchPlanRef",
    "adapterRef",
    "targetRef",
    "launchMode",
    "connectionKind",
    "connectionContractRef",
    "executorLane",
    "controlAction",
    "controlChannelRef",
    "requiredAccessLeaseRefs",
    "requiredAuthorityScopeRefs",
    "requiredReceiptRefs",
    "secretReleasePolicy",
    "restoreArchivePolicy",
    "providerPostureRequired",
    "agentgresOperationRefs",
];

#[derive(Debug, Clone)]
pub struct RuntimeCodeEditorAdapterLaunchPlanAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimeCodeEditorAdapterLaunchPlanAdmissionError {
    fn new(status: u16, code: String, message: String, details: Value) -> Self {
        Self { status, code, message, details }
    }
}

type AdmitResult<T> = Result<T, RuntimeCodeEditorAdapterLaunchPlanAdmissionError>;

#[derive(Default)]
pub struct RuntimeCodeEditorAdapterLaunchPlanAdmissionCore;

impl RuntimeCodeEditorAdapterLaunchPlanAdmissionCore {
    pub fn admit(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        assert_no_retired_aliases(request)?;

        let launch_plan_ref = required_string(request.get("launch_plan_ref"), "launch_plan_ref")?;
        let adapter_ref = required_string(request.get("adapter_ref"), "adapter_ref")?;
        let target_ref = required_string(request.get("target_ref"), "target_ref")?;
        let launch_mode = enum_value(request.get("launch_mode"), "launch_mode", LAUNCH_MODES)?;
        let connection_kind = enum_value(request.get("connection_kind"), "connection_kind", CONNECTION_KINDS)?;
        let connection_contract_ref =
            required_string(request.get("connection_contract_ref"), "connection_contract_ref")?;
        let executor_lane = enum_value(request.get("executor_lane"), "executor_lane", EXECUTOR_LANES)?;
        let control_action = enum_value(request.get("control_action"), "control_action", CONTROL_ACTIONS)?;
        let control_channel_ref = required_string(request.get("control_channel_ref"), "control_channel_ref")?;
        let required_access_lease_refs =
            prefixed_refs(request.get("required_access_lease_refs"), "required_access_lease_refs", "lease:", false)?;
        let required_authority_scope_refs = prefixed_refs(
            request.get("required_authority_scope_refs"),
            "required_authority_scope_refs",
            "scope:",
            false,
        )?;
        let required_receipt_refs =
            prefixed_refs(request.get("required_receipt_refs"), "required_receipt_refs", "receipt-policy:", false)?;
        let custody_posture = enum_value(request.get("custody_posture"), "custody_posture", CUSTODY_POSTURES)?;
        let secret_release_policy = optional_value(request.get("secret_release_policy"))
            .unwrap_or_else(|| "no_durable_secret_release".to_string());
        let wallet_approval_ref = optional_value(request.get("wallet_approval_ref"));
        let agentgres_operation_refs = prefixed_refs(
            request.get("agentgres_operation_refs"),
            "agentgres_operation_refs",
            "agentgres://operation/",
            true,
        )?;
        let receipt_refs = prefixed_refs(request.get("receipt_refs"), "receipt_refs", "receipt://", true)?;
        let state_root = optional_value(request.get("state_root"));
        let adapter_runtime_truth_claimed =
            boolean_value(request.get("adapter_runtime_truth_claimed")).unwrap_or(false);

        // assertCodeEditorAdapterLaunchPlan.
        require_prefix(&launch_plan_ref, "code-editor-adapter:", "launch_plan_ref")?;
        require_prefix(&adapter_ref, "code-editor-adapter:", "adapter_ref")?;
        require_prefix(&target_ref, "adapter-target:", "target_ref")?;
        require_prefix(&connection_contract_ref, "connection-contract:code-editor-adapter/", "connection_contract_ref")?;
        require_prefix(&control_channel_ref, "control-channel:code-editor-adapter/", "control_channel_ref")?;
        require_non_empty(&required_access_lease_refs, "required_access_lease_refs")?;
        require_non_empty(&required_authority_scope_refs, "required_authority_scope_refs")?;
        require_non_empty(&required_receipt_refs, "required_receipt_refs")?;

        assert_connection_control_pair(&connection_kind, &executor_lane, &control_action)?;

        if secret_release_policy != "no_durable_secret_release" {
            return Err(authority_error(
                "code_editor_adapter_launch_durable_secret_release_blocked",
                "code editor adapter launch plans must not release durable secrets to adapter targets.",
                json!({ "secret_release_policy": secret_release_policy }),
            ));
        }
        if adapter_runtime_truth_claimed {
            return Err(authority_error(
                "code_editor_adapter_runtime_truth_claim_blocked",
                "code editor adapter targets cannot claim Hypervisor runtime truth.",
                json!({ "adapter_runtime_truth_claimed": adapter_runtime_truth_claimed }),
            ));
        }

        let admission_id = optional_value(request.get("admission_id")).unwrap_or_else(|| {
            format!("code-editor-adapter-launch:{}:{}", safe_id(&launch_plan_ref), safe_id(&connection_kind))
        });
        let admitted_at =
            optional_value(request.get("admitted_at")).unwrap_or_else(|| now_iso.to_string());

        Ok(json!({
            "schema_version": CODE_EDITOR_ADAPTER_LAUNCH_PLAN_ADMISSION_SCHEMA_VERSION,
            "admission_id": admission_id,
            "launch_plan_ref": launch_plan_ref,
            "adapter_ref": adapter_ref,
            "target_ref": target_ref,
            "launch_mode": launch_mode,
            "connection_kind": connection_kind,
            "connection_contract_ref": connection_contract_ref,
            "executor_lane": executor_lane,
            "control_action": control_action,
            "control_channel_ref": control_channel_ref,
            "required_access_lease_refs": required_access_lease_refs,
            "required_authority_scope_refs": required_authority_scope_refs,
            "required_receipt_refs": required_receipt_refs,
            "custody_posture": custody_posture,
            "secret_release_policy": secret_release_policy,
            "wallet_approval_ref": wallet_approval_ref,
            "agentgres_operation_refs": agentgres_operation_refs,
            "receipt_refs": receipt_refs,
            "state_root": state_root,
            "adapter_runtime_truth_claimed": false,
            "decision": "admitted",
            "requiresDaemonGate": true,
            "runtimeTruthSource": "daemon-runtime",
            "admitted_at": admitted_at,
        }))
    }
}

fn assert_connection_control_pair(
    connection_kind: &str,
    executor_lane: &str,
    control_action: &str,
) -> AdmitResult<()> {
    let expected = match connection_kind {
        "embedded_host" => Some(("embedded_code_editor_host", "open_embedded_code_editor")),
        "desktop_editor" => Some(("desktop_editor", "open_desktop_editor")),
        "browser_editor_url" => Some(("browser_code_editor", "open_browser_editor")),
        _ => None,
    };
    if let Some((expected_lane, expected_action)) = expected {
        if executor_lane != expected_lane || control_action != expected_action {
            return Err(authority_error(
                "code_editor_adapter_control_contract_mismatch",
                "code editor adapter control metadata must match its connection kind.",
                json!({
                    "connection_kind": connection_kind,
                    "executor_lane": executor_lane,
                    "control_action": control_action,
                }),
            ));
        }
    }
    Ok(())
}

fn prefixed_refs(
    value: Option<&Value>,
    field: &str,
    prefix: &str,
    allow_empty: bool,
) -> AdmitResult<Vec<String>> {
    let refs = unique_strings_trim(value);
    if !allow_empty {
        require_non_empty(&refs, field)?;
    }
    for reference in &refs {
        require_prefix(reference, prefix, field)?;
    }
    Ok(refs)
}

fn enum_value(value: Option<&Value>, field: &str, allowed: &[&str]) -> AdmitResult<String> {
    let normalized = optional_value(value);
    match &normalized {
        Some(value) if allowed.contains(&value.as_str()) => Ok(value.clone()),
        _ => {
            let mut details = Map::new();
            details.insert(field.to_string(), normalized.map(Value::String).unwrap_or(Value::Null));
            details.insert("allowed_values".to_string(), json!(allowed));
            Err(RuntimeCodeEditorAdapterLaunchPlanAdmissionError::new(
                400,
                format!("code_editor_adapter_launch_{field}_invalid"),
                format!("code editor adapter launch admission requires a valid {field}."),
                Value::Object(details),
            ))
        }
    }
}

fn required_string(value: Option<&Value>, field: &str) -> AdmitResult<String> {
    optional_value(value).ok_or_else(|| {
        RuntimeCodeEditorAdapterLaunchPlanAdmissionError::new(
            400,
            format!("code_editor_adapter_launch_{field}_required"),
            format!("code editor adapter launch admission requires {field}."),
            json!({ "field": field }),
        )
    })
}

fn require_non_empty(refs: &[String], field: &str) -> AdmitResult<()> {
    if !refs.is_empty() {
        return Ok(());
    }
    Err(RuntimeCodeEditorAdapterLaunchPlanAdmissionError::new(
        400,
        format!("code_editor_adapter_launch_{field}_required"),
        format!("code editor adapter launch admission requires {field}."),
        json!({ "field": field }),
    ))
}

fn require_prefix(value: &str, prefix: &str, field: &str) -> AdmitResult<()> {
    if value.starts_with(prefix) {
        return Ok(());
    }
    Err(RuntimeCodeEditorAdapterLaunchPlanAdmissionError::new(
        400,
        format!("code_editor_adapter_launch_{field}_prefix_invalid"),
        format!("code editor adapter launch admission requires {field} to start with {prefix}."),
        json!({ "field": field, "value": value }),
    ))
}

fn authority_error(code: &str, message: &str, details: Value) -> RuntimeCodeEditorAdapterLaunchPlanAdmissionError {
    RuntimeCodeEditorAdapterLaunchPlanAdmissionError::new(403, code.to_string(), message.to_string(), details)
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
    Err(RuntimeCodeEditorAdapterLaunchPlanAdmissionError::new(
        400,
        "code_editor_adapter_launch_request_aliases_retired".to_string(),
        "code editor adapter launch admission uses canonical snake_case request fields.".to_string(),
        json!({ "retired_aliases": present }),
    ))
}

fn optional_value(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => None,
        Some(value) => {
            let coerced = js_string_coerce(value);
            let trimmed = js_trim(&coerced);
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
    }
}

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

/// Mirror the LOCAL `uniqueStrings(normalizeArray(value))`: truthy raw items, `String(v).trim()`
/// (TRIMS via js_trim), drop blanks, first-seen dedup. Non-array → empty.
fn unique_strings_trim(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for item in items {
        if !is_truthy(item) {
            continue;
        }
        let trimmed = js_trim(&js_string_coerce(item)).to_string();
        if trimmed.is_empty() {
            continue;
        }
        if !out.contains(&trimmed) {
            out.push(trimmed);
        }
    }
    out
}

fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(boolean) => *boolean,
        Value::Number(number) => number.as_f64().map(|float| float != 0.0).unwrap_or(false),
        Value::String(string) => !string.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

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

fn is_js_whitespace(ch: char) -> bool {
    matches!(
        ch,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

fn js_trim(value: &str) -> &str {
    value.trim_matches(is_js_whitespace)
}

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
            "launch_plan_ref": "code-editor-adapter:vscode/launch",
            "adapter_ref": "code-editor-adapter:vscode",
            "target_ref": "adapter-target:vscode",
            "launch_mode": "embedded",
            "connection_kind": "embedded_host",
            "connection_contract_ref": "connection-contract:code-editor-adapter/vscode",
            "executor_lane": "embedded_code_editor_host",
            "control_action": "open_embedded_code_editor",
            "control_channel_ref": "control-channel:code-editor-adapter/vscode",
            "required_access_lease_refs": ["lease:workspace/read"],
            "required_authority_scope_refs": ["scope:workspace.read"],
            "required_receipt_refs": ["receipt-policy:code-editor/launch"],
            "custody_posture": "local_projection",
        })
    }

    #[test]
    fn admits_embedded_launch() {
        let admission = RuntimeCodeEditorAdapterLaunchPlanAdmissionCore
            .admit(&base_request(), "2026-06-18T00:00:00.000Z")
            .expect("admitted");
        assert_eq!(admission["schema_version"], CODE_EDITOR_ADAPTER_LAUNCH_PLAN_ADMISSION_SCHEMA_VERSION);
        assert_eq!(admission["decision"], "admitted");
        assert_eq!(
            admission["admission_id"],
            "code-editor-adapter-launch:code-editor-adapter_vscode_launch:embedded_host"
        );
        assert_eq!(admission["secret_release_policy"], "no_durable_secret_release");
        assert_eq!(admission["adapter_runtime_truth_claimed"], false);
    }

    #[test]
    fn blocks_control_contract_mismatch() {
        let mut request = base_request();
        request["control_action"] = json!("open_desktop_editor");
        let error = RuntimeCodeEditorAdapterLaunchPlanAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.code, "code_editor_adapter_control_contract_mismatch");
        assert_eq!(error.status, 403);
    }

    #[test]
    fn blocks_durable_secret_release() {
        let mut request = base_request();
        request["secret_release_policy"] = json!("release_durable");
        let error = RuntimeCodeEditorAdapterLaunchPlanAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.code, "code_editor_adapter_launch_durable_secret_release_blocked");
        assert_eq!(error.status, 403);
    }

    #[test]
    fn blocks_runtime_truth_claim() {
        let mut request = base_request();
        request["adapter_runtime_truth_claimed"] = json!(true);
        let error = RuntimeCodeEditorAdapterLaunchPlanAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.code, "code_editor_adapter_runtime_truth_claim_blocked");
    }

    #[test]
    fn bad_launch_plan_prefix_is_400() {
        let mut request = base_request();
        request["launch_plan_ref"] = json!("nope:x");
        let error = RuntimeCodeEditorAdapterLaunchPlanAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "code_editor_adapter_launch_launch_plan_ref_prefix_invalid");
    }

    #[test]
    fn requires_access_lease_refs() {
        let mut request = base_request();
        request["required_access_lease_refs"] = json!([]);
        let error = RuntimeCodeEditorAdapterLaunchPlanAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "code_editor_adapter_launch_required_access_lease_refs_required");
    }

    #[test]
    fn rejects_retired_aliases() {
        let mut request = base_request();
        request["launchPlanRef"] = json!("legacy");
        let error = RuntimeCodeEditorAdapterLaunchPlanAdmissionCore.admit(&request, "now").expect_err("retired");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "code_editor_adapter_launch_request_aliases_retired");
    }
}
