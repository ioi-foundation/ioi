//! Artifact-availability-incident admission planner.
//!
//! A faithful Rust port of the retired JS `admitArtifactAvailabilityIncident`
//! (`packages/runtime-daemon/src/runtime-artifact-availability-incident.mjs`). Pure validation:
//! an artifact-availability incident is admitted only when its artifact/payload/backend refs +
//! Agentgres/incident-receipt/affected-object refs are bound, kind-specific hash/CID evidence is
//! present, lifecycle-state material (repair/verification/fallback/quarantine/restore) is bound,
//! and payload bytes are never silently mutated. The admitted record carries a derived
//! `agentgres_operation` envelope.
//!
//! HELPER NOTE: LOCAL `uniqueRefs` TRIMS. STATUS: field-shape helpers (required/enum/prefix)
//! reject 400; incident-policy assertions reject 403. `requirePrefix` uses `..._{field}_invalid`.

use serde_json::{json, Map, Value};

pub const ARTIFACT_AVAILABILITY_INCIDENT_SCHEMA_VERSION: &str =
    "ioi.runtime.artifact_availability_incident.v1";

pub const ARTIFACT_AVAILABILITY_AGENTGRES_OPERATION_SCHEMA_VERSION: &str =
    "ioi.agentgres.artifact_availability_incident_operation.v1";

const INCIDENT_KINDS: &[&str] = &[
    "missing",
    "unavailable",
    "invalid_hash",
    "invalid_cid",
    "decrypt_failed",
    "backend_unavailable",
    "stale_replica",
];

const LIFECYCLE_STATES: &[&str] = &[
    "opened",
    "fallback_attempted",
    "repaired",
    "quarantined",
    "unrecoverable",
    "closed",
];

const RETIRED_ALIASES: &[&str] = &[
    "artifactRef",
    "payloadRef",
    "backendRef",
    "repairReceiptRefs",
    "agentgresOperationRefs",
    "lifecycleState",
    "expectedHash",
    "observedHash",
];

#[derive(Debug, Clone)]
pub struct RuntimeArtifactAvailabilityIncidentAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimeArtifactAvailabilityIncidentAdmissionError {
    fn new(status: u16, code: String, message: String, details: Value) -> Self {
        Self {
            status,
            code,
            message,
            details,
        }
    }
}

type AdmitResult<T> = Result<T, RuntimeArtifactAvailabilityIncidentAdmissionError>;

#[derive(Default)]
pub struct RuntimeArtifactAvailabilityIncidentAdmissionCore;

impl RuntimeArtifactAvailabilityIncidentAdmissionCore {
    pub fn admit(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        assert_no_retired_aliases(request)?;

        let artifact_ref = required_string(request.get("artifact_ref"), "artifact_ref")?;
        let payload_ref = required_string(request.get("payload_ref"), "payload_ref")?;
        let backend_ref = required_string(request.get("backend_ref"), "backend_ref")?;
        let incident_kind = enum_value(
            request.get("incident_kind"),
            "incident_kind",
            INCIDENT_KINDS,
        )?;
        let lifecycle_state = enum_value(
            Some(&default_value(request.get("lifecycle_state"), "opened")),
            "lifecycle_state",
            LIFECYCLE_STATES,
        )?;
        let expected_hash = optional_value(request.get("expected_hash"));
        let observed_hash = optional_value(request.get("observed_hash"));
        let expected_cid = optional_value(request.get("expected_cid"));
        let observed_cid = optional_value(request.get("observed_cid"));
        let agentgres_operation_refs = unique_refs(request.get("agentgres_operation_refs"));
        let repair_receipt_refs = unique_refs(request.get("repair_receipt_refs"));
        let incident_receipt_refs = unique_refs(request.get("incident_receipt_refs"));
        let fallback_backend_refs = unique_refs(request.get("fallback_backend_refs"));
        let quarantine_refs = unique_refs(request.get("quarantine_refs"));
        let affected_object_refs = unique_refs(request.get("affected_object_refs"));
        let verification_refs = unique_refs(request.get("verification_refs"));
        let restore_import_refs = unique_refs(request.get("restore_import_refs"));
        let payload_bytes_mutated =
            boolean_value(request.get("payload_bytes_mutated")).unwrap_or(false);

        // assertIncidentAdmission.
        require_prefix(&artifact_ref, "artifact://", "artifact_ref")?;
        require_prefix(&payload_ref, "payload://", "payload_ref")?;
        require_prefix(&backend_ref, "storage://", "backend_ref")?;
        require_refs(&agentgres_operation_refs, "agentgres_operation_refs")?;
        require_refs(&incident_receipt_refs, "incident_receipt_refs")?;
        if affected_object_refs.is_empty() {
            return Err(authority_error(
                "artifact_availability_affected_object_refs_required",
                "Artifact availability incidents must bind affected Agentgres object refs or projections.",
                json!({ "artifact_ref": artifact_ref }),
            ));
        }
        if incident_kind == "invalid_hash" && (expected_hash.is_none() || observed_hash.is_none()) {
            return Err(authority_error(
                "artifact_availability_hash_evidence_required",
                "Invalid-hash incidents require expected_hash and observed_hash evidence.",
                json!({ "expected_hash": expected_hash, "observed_hash": observed_hash }),
            ));
        }
        if incident_kind == "invalid_cid" && (expected_cid.is_none() || observed_cid.is_none()) {
            return Err(authority_error(
                "artifact_availability_cid_evidence_required",
                "Invalid-CID incidents require expected_cid and observed_cid evidence.",
                json!({ "expected_cid": expected_cid, "observed_cid": observed_cid }),
            ));
        }
        if matches!(lifecycle_state.as_str(), "repaired" | "closed") {
            require_refs(&repair_receipt_refs, "repair_receipt_refs")?;
            require_refs(&verification_refs, "verification_refs")?;
        }
        if lifecycle_state == "fallback_attempted" {
            require_refs(&fallback_backend_refs, "fallback_backend_refs")?;
        }
        if lifecycle_state == "quarantined" {
            require_refs(&quarantine_refs, "quarantine_refs")?;
        }
        if lifecycle_state == "repaired" && restore_import_refs.is_empty() {
            return Err(authority_error(
                "artifact_availability_restore_import_ref_required",
                "Repaired artifact availability incidents require restore/import refs.",
                json!({ "lifecycle_state": lifecycle_state }),
            ));
        }
        if payload_bytes_mutated && repair_receipt_refs.is_empty() {
            return Err(authority_error(
                "artifact_availability_silent_payload_mutation_blocked",
                "Payload bytes cannot be silently replaced or mutated without a repair receipt.",
                json!({ "payload_bytes_mutated": payload_bytes_mutated }),
            ));
        }

        let incident_id = optional_value(request.get("incident_id")).unwrap_or_else(|| {
            format!(
                "artifact-availability-incident:{}:{}",
                safe_id(&artifact_ref),
                safe_id(&incident_kind)
            )
        });
        let admitted_at =
            optional_value(request.get("admitted_at")).unwrap_or_else(|| now_iso.to_string());

        let restore_validity = if restore_import_refs.is_empty() {
            "no_restore_import"
        } else {
            "restore_import_refs_bound"
        };
        let operation_ref = agentgres_operation_refs
            .first()
            .cloned()
            .unwrap_or_default();
        let mut operation_receipt_refs = incident_receipt_refs.clone();
        operation_receipt_refs.extend(repair_receipt_refs.iter().cloned());
        let operation_receipt_refs = dedupe_strings(operation_receipt_refs);

        let agentgres_operation = json!({
            "schema_version": ARTIFACT_AVAILABILITY_AGENTGRES_OPERATION_SCHEMA_VERSION,
            "operation_ref": operation_ref,
            "operation_kind": "artifact_availability_incident",
            "incident_id": incident_id,
            "artifact_ref": artifact_ref,
            "payload_ref": payload_ref,
            "backend_ref": backend_ref,
            "lifecycle_state": lifecycle_state,
            "incident_kind": incident_kind,
            "affected_object_refs": affected_object_refs,
            "incident_receipt_refs": incident_receipt_refs,
            "repair_receipt_refs": repair_receipt_refs,
            "verification_refs": verification_refs,
            "restore_import_refs": restore_import_refs,
            "fallback_backend_refs": fallback_backend_refs,
            "quarantine_refs": quarantine_refs,
            "payload_bytes_mutated": payload_bytes_mutated,
            "restore_validity": restore_validity,
            "state_root": format!("agentgres://state-root/artifact-availability-incident/{}", safe_id(&incident_id)),
            "receipt_refs": operation_receipt_refs,
            "runtimeTruthSource": "daemon-runtime",
            "agentgresTruthSource": "agentgres-operation",
        });

        Ok(json!({
            "schema_version": ARTIFACT_AVAILABILITY_INCIDENT_SCHEMA_VERSION,
            "incident_id": incident_id,
            "artifact_ref": artifact_ref,
            "payload_ref": payload_ref,
            "backend_ref": backend_ref,
            "incident_kind": incident_kind,
            "lifecycle_state": lifecycle_state,
            "expected_hash": expected_hash,
            "observed_hash": observed_hash,
            "expected_cid": expected_cid,
            "observed_cid": observed_cid,
            "agentgres_operation_refs": agentgres_operation_refs,
            "repair_receipt_refs": repair_receipt_refs,
            "incident_receipt_refs": incident_receipt_refs,
            "fallback_backend_refs": fallback_backend_refs,
            "quarantine_refs": quarantine_refs,
            "affected_object_refs": affected_object_refs,
            "verification_refs": verification_refs,
            "restore_import_refs": restore_import_refs,
            "payload_bytes_mutated": payload_bytes_mutated,
            "admitted_at": admitted_at,
            "runtimeTruthSource": "daemon-runtime",
            "agentgres_operation": agentgres_operation,
        }))
    }
}

fn require_refs(refs: &[String], field: &str) -> AdmitResult<()> {
    if !refs.is_empty() {
        return Ok(());
    }
    Err(authority_error(
        &format!("artifact_availability_{field}_required"),
        &format!("Artifact availability incident requires {field}."),
        json!({ "field": field }),
    ))
}

fn require_prefix(value: &str, prefix: &str, field: &str) -> AdmitResult<()> {
    if value.starts_with(prefix) {
        return Ok(());
    }
    let mut details = Map::new();
    details.insert(field.to_string(), Value::String(value.to_string()));
    Err(RuntimeArtifactAvailabilityIncidentAdmissionError::new(
        400,
        format!("artifact_availability_{field}_invalid"),
        format!("Artifact availability {field} must start with {prefix}."),
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
    Err(RuntimeArtifactAvailabilityIncidentAdmissionError::new(
        400,
        "artifact_availability_request_aliases_retired".to_string(),
        "Artifact availability incident admission accepts only canonical snake_case request fields.".to_string(),
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
            Err(RuntimeArtifactAvailabilityIncidentAdmissionError::new(
                400,
                format!("artifact_availability_{field}_invalid"),
                format!("Artifact availability incident requires a valid {field}."),
                Value::Object(details),
            ))
        }
    }
}

fn required_string(value: Option<&Value>, field: &str) -> AdmitResult<String> {
    optional_value(value).ok_or_else(|| {
        RuntimeArtifactAvailabilityIncidentAdmissionError::new(
            400,
            format!("artifact_availability_{field}_required"),
            format!("Artifact availability incident requires {field}."),
            json!({ "field": field }),
        )
    })
}

fn authority_error(
    code: &str,
    message: &str,
    details: Value,
) -> RuntimeArtifactAvailabilityIncidentAdmissionError {
    RuntimeArtifactAvailabilityIncidentAdmissionError::new(
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

/// First-seen dedup of an already-string list (the build's `uniqueRefs([...a, ...b])`).
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
            "artifact_ref": "artifact://a/1",
            "payload_ref": "payload://a/1",
            "backend_ref": "storage://ipfs/a",
            "incident_kind": "missing",
            "lifecycle_state": "opened",
            "agentgres_operation_refs": ["agentgres://operation/a"],
            "incident_receipt_refs": ["receipt://incident/a"],
            "affected_object_refs": ["object://a"],
        })
    }

    #[test]
    fn admits_incident_with_agentgres_operation() {
        let admission = RuntimeArtifactAvailabilityIncidentAdmissionCore
            .admit(&base_request(), "2026-06-18T00:00:00.000Z")
            .expect("admitted");
        assert_eq!(
            admission["schema_version"],
            ARTIFACT_AVAILABILITY_INCIDENT_SCHEMA_VERSION
        );
        assert_eq!(
            admission["incident_id"],
            "artifact-availability-incident:artifact_a_1:missing"
        );
        let op = &admission["agentgres_operation"];
        assert_eq!(
            op["schema_version"],
            ARTIFACT_AVAILABILITY_AGENTGRES_OPERATION_SCHEMA_VERSION
        );
        assert_eq!(op["operation_ref"], "agentgres://operation/a");
        assert_eq!(op["operation_kind"], "artifact_availability_incident");
        assert_eq!(op["restore_validity"], "no_restore_import");
        assert_eq!(op["receipt_refs"], json!(["receipt://incident/a"]));
        assert_eq!(op["agentgresTruthSource"], "agentgres-operation");
    }

    #[test]
    fn invalid_hash_requires_evidence() {
        let mut request = base_request();
        request["incident_kind"] = json!("invalid_hash");
        let error = RuntimeArtifactAvailabilityIncidentAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.code, "artifact_availability_hash_evidence_required");
        assert_eq!(error.status, 403);
    }

    #[test]
    fn repaired_requires_restore_and_repair() {
        let mut request = base_request();
        request["lifecycle_state"] = json!("repaired");
        request["verification_refs"] = json!(["verify://a"]);
        request["repair_receipt_refs"] = json!(["receipt://repair/a"]);
        // missing restore_import_refs
        let error = RuntimeArtifactAvailabilityIncidentAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "artifact_availability_restore_import_ref_required"
        );
    }

    #[test]
    fn admits_repaired_with_restore() {
        let mut request = base_request();
        request["lifecycle_state"] = json!("repaired");
        request["verification_refs"] = json!(["verify://a"]);
        request["repair_receipt_refs"] = json!(["receipt://repair/a"]);
        request["restore_import_refs"] = json!(["import://a"]);
        let admission = RuntimeArtifactAvailabilityIncidentAdmissionCore
            .admit(&request, "now")
            .expect("admitted");
        assert_eq!(
            admission["agentgres_operation"]["restore_validity"],
            "restore_import_refs_bound"
        );
        assert_eq!(
            admission["agentgres_operation"]["receipt_refs"],
            json!(["receipt://incident/a", "receipt://repair/a"])
        );
    }

    #[test]
    fn silent_payload_mutation_blocked() {
        let mut request = base_request();
        request["payload_bytes_mutated"] = json!(true);
        let error = RuntimeArtifactAvailabilityIncidentAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "artifact_availability_silent_payload_mutation_blocked"
        );
        assert_eq!(error.status, 403);
    }

    #[test]
    fn bad_artifact_prefix_is_400() {
        let mut request = base_request();
        request["artifact_ref"] = json!("nope://x");
        let error = RuntimeArtifactAvailabilityIncidentAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "artifact_availability_artifact_ref_invalid");
    }

    #[test]
    fn requires_affected_object_refs() {
        let mut request = base_request();
        request["affected_object_refs"] = json!([]);
        let error = RuntimeArtifactAvailabilityIncidentAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 403);
        assert_eq!(
            error.code,
            "artifact_availability_affected_object_refs_required"
        );
    }

    #[test]
    fn rejects_retired_aliases() {
        let mut request = base_request();
        request["artifactRef"] = json!("legacy");
        let error = RuntimeArtifactAvailabilityIncidentAdmissionCore
            .admit(&request, "now")
            .expect_err("retired");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "artifact_availability_request_aliases_retired");
    }
}
