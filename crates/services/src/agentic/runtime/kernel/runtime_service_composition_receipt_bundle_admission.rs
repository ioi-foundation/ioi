//! Service-composition-receipt-bundle admission planner.
//!
//! A faithful Rust port of the retired JS `admitServiceCompositionReceiptBundle`
//! (`packages/runtime-daemon/src/runtime-service-composition-receipt-bundle.mjs`). Pure
//! validation: a multi-party service-delivery receipt bundle is admitted only when the
//! contribution / verifier / policy / routing / dispute / Agentgres / receipt refs are bound, it
//! carries delivery evidence (artifact or payload), provider logs are not the sole dispute truth,
//! and unsafe-plaintext exceptions are wallet-approved and never auto settlement-ready.
//!
//! HELPER NOTE: LOCAL `uniqueRefs` = `uniqueStrings(normalizeArray)` that TRIMS. STATUS: field-
//! shape helpers (required/enum/prefix) reject 400; bundle-policy assertions reject 403.
//! `requirePrefix` rejects with a per-field `..._{field}_invalid` code (NOT `_prefix_invalid`).

use serde_json::{json, Map, Value};

pub const SERVICE_COMPOSITION_RECEIPT_BUNDLE_SCHEMA_VERSION: &str =
    "ioi.runtime.service_composition_receipt_bundle.v1";

const PRIVATE_DATA_POSTURES: &[&str] = &[
    "public_only",
    "ctee_private_workspace",
    "customer_plaintext",
    "provider_trust_plaintext",
    "unsafe_plaintext_exception",
];

const DELIVERY_STATUSES: &[&str] = &["delivered", "partial", "failed", "disputed"];

const RETIRED_ALIASES: &[&str] = &[
    "compositionGraphRef",
    "contributionReceipts",
    "verifierReceipts",
    "policyReceipts",
    "routingReceipts",
    "privateDataPosture",
    "disputeEvidence",
    "agentgresOperationRefs",
    "stateRoot",
];

#[derive(Debug, Clone)]
pub struct RuntimeServiceCompositionReceiptBundleAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimeServiceCompositionReceiptBundleAdmissionError {
    fn new(status: u16, code: String, message: String, details: Value) -> Self {
        Self {
            status,
            code,
            message,
            details,
        }
    }
}

type AdmitResult<T> = Result<T, RuntimeServiceCompositionReceiptBundleAdmissionError>;

#[derive(Default)]
pub struct RuntimeServiceCompositionReceiptBundleAdmissionCore;

impl RuntimeServiceCompositionReceiptBundleAdmissionCore {
    pub fn admit(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        assert_no_retired_aliases(request)?;

        let service_ref = required_string(request.get("service_ref"), "service_ref")?;
        let delivery_ref = required_string(request.get("delivery_ref"), "delivery_ref")?;
        let composition_graph_ref = required_string(
            request.get("composition_graph_ref"),
            "composition_graph_ref",
        )?;
        let private_data_posture = enum_value(
            request.get("private_data_posture"),
            "private_data_posture",
            PRIVATE_DATA_POSTURES,
        )?;
        let delivery_status = enum_value(
            Some(&default_value(request.get("delivery_status"), "delivered")),
            "delivery_status",
            DELIVERY_STATUSES,
        )?;
        let contribution_receipt_refs = unique_refs(request.get("contribution_receipt_refs"));
        let verifier_receipt_refs = unique_refs(request.get("verifier_receipt_refs"));
        let policy_receipt_refs = unique_refs(request.get("policy_receipt_refs"));
        let routing_receipt_refs = unique_refs(request.get("routing_receipt_refs"));
        let dispute_evidence_refs = unique_refs(request.get("dispute_evidence_refs"));
        let agentgres_operation_refs = unique_refs(request.get("agentgres_operation_refs"));
        let artifact_refs = unique_refs(request.get("artifact_refs"));
        let payload_refs = unique_refs(request.get("payload_refs"));
        let receipt_refs = unique_refs(request.get("receipt_refs"));
        let provider_log_refs = unique_refs(request.get("provider_log_refs"));
        let state_root = required_string(request.get("state_root"), "state_root")?;
        let wallet_approval_ref = optional_value(request.get("wallet_approval_ref"));
        let unsafe_plaintext_exception_ref =
            optional_value(request.get("unsafe_plaintext_exception_ref"));
        let settlement_requested = boolean_value(request.get("settlement_requested"))
            .unwrap_or(delivery_status == "delivered");

        // assertServiceCompositionBundle.
        require_refs(&contribution_receipt_refs, "contribution_receipt_refs")?;
        require_refs(&verifier_receipt_refs, "verifier_receipt_refs")?;
        require_refs(&policy_receipt_refs, "policy_receipt_refs")?;
        require_refs(&routing_receipt_refs, "routing_receipt_refs")?;
        require_refs(&dispute_evidence_refs, "dispute_evidence_refs")?;
        require_refs(&agentgres_operation_refs, "agentgres_operation_refs")?;
        require_refs(&receipt_refs, "receipt_refs")?;
        if artifact_refs.is_empty() && payload_refs.is_empty() {
            return Err(authority_error(
                "service_composition_delivery_payload_or_artifact_required",
                "Service composition bundles require artifact or payload refs for delivery evidence.",
                json!({ "artifact_refs": artifact_refs, "payload_refs": payload_refs }),
            ));
        }
        require_prefix(&state_root, "state_root:", "state_root")?;

        if !provider_log_refs.is_empty() && dispute_evidence_refs.is_empty() {
            return Err(authority_error(
                "service_composition_provider_logs_not_dispute_truth",
                "Provider logs may support dispute evidence but cannot be the dispute truth by themselves.",
                json!({ "provider_log_refs": provider_log_refs }),
            ));
        }

        if private_data_posture == "unsafe_plaintext_exception"
            && (wallet_approval_ref.is_none() || unsafe_plaintext_exception_ref.is_none())
        {
            return Err(authority_error(
                "service_composition_unsafe_plaintext_exception_unapproved",
                "Unsafe plaintext service delivery exceptions require wallet approval and exception receipt refs.",
                json!({
                    "wallet_approval_ref": wallet_approval_ref,
                    "unsafe_plaintext_exception_ref": unsafe_plaintext_exception_ref,
                }),
            ));
        }

        if settlement_requested
            && delivery_status == "delivered"
            && private_data_posture == "unsafe_plaintext_exception"
        {
            return Err(authority_error(
                "service_composition_unsafe_plaintext_settlement_blocked",
                "Unsafe plaintext exception deliveries cannot be marked settlement-ready by default.",
                json!({ "private_data_posture": private_data_posture }),
            ));
        }

        let bundle_ref = optional_value(request.get("bundle_ref")).unwrap_or_else(|| {
            format!(
                "service-composition-bundle:{}:{}",
                safe_id(&delivery_ref),
                safe_id(&state_root)
            )
        });
        let admitted_at =
            optional_value(request.get("admitted_at")).unwrap_or_else(|| now_iso.to_string());

        let settlement_ready = settlement_requested
            && delivery_status == "delivered"
            && private_data_posture != "unsafe_plaintext_exception";

        Ok(json!({
            "schema_version": SERVICE_COMPOSITION_RECEIPT_BUNDLE_SCHEMA_VERSION,
            "bundle_ref": bundle_ref,
            "service_ref": service_ref,
            "delivery_ref": delivery_ref,
            "composition_graph_ref": composition_graph_ref,
            "delivery_status": delivery_status,
            "settlement_ready": settlement_ready,
            "contribution_receipt_refs": contribution_receipt_refs,
            "verifier_receipt_refs": verifier_receipt_refs,
            "policy_receipt_refs": policy_receipt_refs,
            "routing_receipt_refs": routing_receipt_refs,
            "private_data_posture": private_data_posture,
            "unsafe_plaintext_exception_ref": unsafe_plaintext_exception_ref,
            "dispute_evidence_refs": dispute_evidence_refs,
            "provider_log_refs": provider_log_refs,
            "artifact_refs": artifact_refs,
            "payload_refs": payload_refs,
            "receipt_refs": receipt_refs,
            "agentgres_operation_refs": agentgres_operation_refs,
            "state_root": state_root,
            "wallet_approval_ref": wallet_approval_ref,
            "admitted_at": admitted_at,
            "runtimeTruthSource": "daemon-runtime",
        }))
    }
}

fn require_refs(refs: &[String], field: &str) -> AdmitResult<()> {
    if !refs.is_empty() {
        return Ok(());
    }
    Err(authority_error(
        &format!("service_composition_{field}_required"),
        &format!("Service composition bundle requires {field}."),
        json!({ "field": field }),
    ))
}

fn require_prefix(value: &str, prefix: &str, field: &str) -> AdmitResult<()> {
    if value.starts_with(prefix) {
        return Ok(());
    }
    let mut details = Map::new();
    details.insert(field.to_string(), Value::String(value.to_string()));
    Err(RuntimeServiceCompositionReceiptBundleAdmissionError::new(
        400,
        format!("service_composition_{field}_invalid"),
        format!("Service composition {field} must start with {prefix}."),
        Value::Object(details),
    ))
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
    Err(RuntimeServiceCompositionReceiptBundleAdmissionError::new(
        400,
        "service_composition_request_aliases_retired".to_string(),
        "Service composition receipt bundle admission accepts only canonical snake_case request fields.".to_string(),
        json!({ "retired_aliases": retired }),
    ))
}

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
            Err(RuntimeServiceCompositionReceiptBundleAdmissionError::new(
                400,
                format!("service_composition_{field}_invalid"),
                format!("Service composition receipt bundle requires a valid {field}."),
                Value::Object(details),
            ))
        }
    }
}

fn required_string(value: Option<&Value>, field: &str) -> AdmitResult<String> {
    optional_value(value).ok_or_else(|| {
        RuntimeServiceCompositionReceiptBundleAdmissionError::new(
            400,
            format!("service_composition_{field}_required"),
            format!("Service composition receipt bundle requires {field}."),
            json!({ "field": field }),
        )
    })
}

fn authority_error(
    code: &str,
    message: &str,
    details: Value,
) -> RuntimeServiceCompositionReceiptBundleAdmissionError {
    RuntimeServiceCompositionReceiptBundleAdmissionError::new(
        403,
        code.to_string(),
        message.to_string(),
        details,
    )
}

fn default_value(value: Option<&Value>, fallback: &str) -> Value {
    match value {
        None | Some(Value::Null) => Value::String(fallback.to_string()),
        Some(value) => value.clone(),
    }
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

/// Mirror the LOCAL `uniqueRefs` = `uniqueStrings(normalizeArray(value))` that TRIMS each item.
fn unique_refs(value: Option<&Value>) -> Vec<String> {
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
            | '\u{2000}'
            ..='\u{200A}'
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
            "service_ref": "service:carwash/detailing",
            "delivery_ref": "delivery:carwash/order-42",
            "composition_graph_ref": "composition-graph:carwash/order-42",
            "private_data_posture": "public_only",
            "delivery_status": "delivered",
            "contribution_receipt_refs": ["receipt://contribution/a"],
            "verifier_receipt_refs": ["receipt://verifier/a"],
            "policy_receipt_refs": ["receipt://policy/a"],
            "routing_receipt_refs": ["receipt://routing/a"],
            "dispute_evidence_refs": ["receipt://dispute/a"],
            "agentgres_operation_refs": ["agentgres://operation/a"],
            "artifact_refs": ["artifact://delivery/a"],
            "receipt_refs": ["receipt://bundle/a"],
            "state_root": "state_root:carwash/order-42",
        })
    }

    #[test]
    fn admits_delivered_bundle() {
        let admission = RuntimeServiceCompositionReceiptBundleAdmissionCore
            .admit(&base_request(), "2026-06-18T00:00:00.000Z")
            .expect("admitted");
        assert_eq!(
            admission["schema_version"],
            SERVICE_COMPOSITION_RECEIPT_BUNDLE_SCHEMA_VERSION
        );
        assert_eq!(admission["settlement_ready"], true);
        assert_eq!(
            admission["bundle_ref"],
            "service-composition-bundle:delivery_carwash_order-42:state_root_carwash_order-42"
        );
    }

    #[test]
    fn requires_delivery_evidence() {
        let mut request = base_request();
        request["artifact_refs"] = json!([]);
        // payload_refs absent
        let error = RuntimeServiceCompositionReceiptBundleAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "service_composition_delivery_payload_or_artifact_required"
        );
        assert_eq!(error.status, 403);
    }

    #[test]
    fn payload_satisfies_delivery_evidence() {
        let mut request = base_request();
        request["artifact_refs"] = json!([]);
        request["payload_refs"] = json!(["payload://delivery/a"]);
        let admission = RuntimeServiceCompositionReceiptBundleAdmissionCore
            .admit(&request, "now")
            .expect("admitted");
        assert_eq!(admission["settlement_ready"], true);
    }

    #[test]
    fn unsafe_plaintext_requires_approval() {
        let mut request = base_request();
        request["private_data_posture"] = json!("unsafe_plaintext_exception");
        let error = RuntimeServiceCompositionReceiptBundleAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "service_composition_unsafe_plaintext_exception_unapproved"
        );
        assert_eq!(error.status, 403);
    }

    #[test]
    fn unsafe_plaintext_settlement_blocked() {
        let mut request = base_request();
        request["private_data_posture"] = json!("unsafe_plaintext_exception");
        request["wallet_approval_ref"] = json!("approval://wallet/x");
        request["unsafe_plaintext_exception_ref"] = json!("receipt://exception/x");
        let error = RuntimeServiceCompositionReceiptBundleAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "service_composition_unsafe_plaintext_settlement_blocked"
        );
    }

    #[test]
    fn bad_state_root_prefix_is_400() {
        let mut request = base_request();
        request["state_root"] = json!("nope:x");
        let error = RuntimeServiceCompositionReceiptBundleAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "service_composition_state_root_invalid");
    }

    #[test]
    fn requires_contribution_receipts() {
        let mut request = base_request();
        request["contribution_receipt_refs"] = json!([]);
        let error = RuntimeServiceCompositionReceiptBundleAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 403);
        assert_eq!(
            error.code,
            "service_composition_contribution_receipt_refs_required"
        );
    }

    #[test]
    fn rejects_retired_aliases() {
        let mut request = base_request();
        request["compositionGraphRef"] = json!("legacy");
        let error = RuntimeServiceCompositionReceiptBundleAdmissionCore
            .admit(&request, "now")
            .expect_err("retired");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "service_composition_request_aliases_retired");
    }
}
