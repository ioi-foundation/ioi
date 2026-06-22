//! Physical-action-intent admission planner.
//!
//! A faithful Rust port of the retired JS `admitPhysicalActionIntent`
//! (`packages/runtime-daemon/src/runtime-physical-action-intent-admission.mjs`). Pure validation:
//! actuator-affecting work is admitted only through the daemon-owned safety / supervision /
//! emergency-stop / receipt envelope, never as a generic tool call.
//!
//! GOTCHA: `optional_positive_integer` mirrors JS `Number(value)` coercion exactly (the
//! `js_number_coerce` helper): true→1, false→0, "0x10"→16, "0o17"→15, [250]→250 (array →
//! String → ToNumber), {}→NaN, "  10  "→10, ""→null. STATUS varies: field-shape helpers
//! (required/enum/prefix/target/actor/positive-integer) reject HTTP 400; policy assertions
//! (`admissionError`/requireRefs) reject HTTP 403. `requirePrefix` rejects with a per-field
//! `..._{field}_invalid` code (details key = the dynamic field name).

use serde_json::{json, Map, Value};

pub const PHYSICAL_ACTION_INTENT_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.runtime.physical_action_intent_admission.v1";

const ACTION_KINDS: &[&str] = &[
    "navigation",
    "manipulation",
    "vehicle_adjacent",
    "drone_flight",
    "facility_control",
    "tool_use",
    "access_control",
    "sensor_override",
    "emergency_stop_test",
    "other",
];

const SUPERVISION_MODES: &[&str] = &[
    "autonomous",
    "monitored",
    "human_on_loop",
    "human_in_loop",
    "manual_confirm_each_action",
];

const EXECUTION_PHASES: &[&str] = &[
    "intent_proposed",
    "preflight_verified",
    "command_issued",
    "stopped",
    "completed",
    "incident_opened",
];

const TARGET_PREFIXES: &[&str] = &[
    "robot://",
    "facility://",
    "vehicle://",
    "device://",
    "drone://",
    "actuator://",
];

const ACTOR_PREFIXES: &[&str] = &["worker:", "worker://", "service_engine:", "runtime:"];

const RETIRED_ALIASES: &[&str] = &[
    "intentId",
    "actorId",
    "targetSystemRef",
    "actionKind",
    "riskClass",
    "physicalActionPolicyRef",
    "safetyEnvelopeRef",
    "emergencyStopAuthorityRef",
    "sensorEvidenceReceiptRefs",
    "actuatorCommandReceiptRefs",
    "agentgresOperationRefs",
];

#[derive(Debug, Clone)]
pub struct RuntimePhysicalActionIntentAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimePhysicalActionIntentAdmissionError {
    fn new(status: u16, code: String, message: String, details: Value) -> Self {
        Self { status, code, message, details }
    }
}

type AdmitResult<T> = Result<T, RuntimePhysicalActionIntentAdmissionError>;

#[derive(Default)]
pub struct RuntimePhysicalActionIntentAdmissionCore;

impl RuntimePhysicalActionIntentAdmissionCore {
    pub fn admit(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        assert_no_retired_aliases(request)?;

        let intent_id = required_string(request.get("intent_id"), "intent_id")?;
        let actor_id = required_string(request.get("actor_id"), "actor_id")?;
        let task_id = optional_value(request.get("task_id"));
        let domain_ref = optional_value(request.get("domain_ref"));
        let target_system_ref = required_string(request.get("target_system_ref"), "target_system_ref")?;
        let action_kind = enum_value(request.get("action_kind"), "action_kind", ACTION_KINDS)?;
        let risk_class =
            optional_value(request.get("risk_class")).unwrap_or_else(|| "physical_action".to_string());
        let execution_phase = enum_value(
            Some(&default_value(request.get("execution_phase"), "preflight_verified")),
            "execution_phase",
            EXECUTION_PHASES,
        )?;
        let requested_primitives = unique_strings_raw(request.get("requested_primitives"));
        let requested_scopes = unique_strings_raw(request.get("requested_scopes"));
        let physical_action_policy_ref =
            required_string(request.get("physical_action_policy_ref"), "physical_action_policy_ref")?;
        let safety_envelope_ref = required_string(request.get("safety_envelope_ref"), "safety_envelope_ref")?;
        let human_supervision_policy_ref = optional_value(request.get("human_supervision_policy_ref"));
        let supervision_mode = enum_value(
            Some(&default_value(request.get("supervision_mode"), "monitored")),
            "supervision_mode",
            SUPERVISION_MODES,
        )?;
        let human_supervisor_refs = unique_strings_raw(request.get("human_supervisor_refs"));
        let emergency_stop_authority_ref =
            required_string(request.get("emergency_stop_authority_ref"), "emergency_stop_authority_ref")?;
        let emergency_stop_tested = boolean_value(request.get("emergency_stop_tested")).unwrap_or(false);
        let emergency_stop_max_latency_ms = optional_positive_integer(request.get("emergency_stop_max_latency_ms"))?;
        let sensor_evidence_receipt_refs = unique_strings_raw(request.get("sensor_evidence_receipt_refs"));
        let actuator_command_receipt_refs = unique_strings_raw(request.get("actuator_command_receipt_refs"));
        let incident_policy_ref = required_string(request.get("incident_policy_ref"), "incident_policy_ref")?;
        let rollback_or_compensation_policy_ref =
            optional_value(request.get("rollback_or_compensation_policy_ref"));
        let wallet_approval_ref = optional_value(request.get("wallet_approval_ref"));
        let authority_ref = optional_value(request.get("authority_ref")).or_else(|| wallet_approval_ref.clone());
        let policy_refs = unique_strings_raw(request.get("policy_refs"));
        let receipt_refs = unique_strings_raw(request.get("receipt_refs"));
        let agentgres_operation_refs = unique_strings_raw(request.get("agentgres_operation_refs"));
        let artifact_refs = unique_strings_raw(request.get("artifact_refs"));
        let state_root = optional_value(request.get("state_root"));
        let execution_channel = optional_value(request.get("execution_channel"));
        let simulation_only = boolean_value(request.get("simulation_only")).unwrap_or(false);
        let generic_tool_call = boolean_value(request.get("generic_tool_call")).unwrap_or(false);

        // assertPhysicalActionAdmission — prefixes (400) then policy assertions (403).
        require_prefix(&intent_id, "intent://", "intent_id")?;
        require_actor_ref(&actor_id)?;
        require_target_prefix(&target_system_ref)?;
        require_prefix(&physical_action_policy_ref, "policy://", "physical_action_policy_ref")?;
        require_prefix(&safety_envelope_ref, "safety://", "safety_envelope_ref")?;
        require_prefix(&emergency_stop_authority_ref, "estop://", "emergency_stop_authority_ref")?;
        require_prefix(&incident_policy_ref, "policy://", "incident_policy_ref")?;
        if let Some(ref supervision_policy) = human_supervision_policy_ref {
            require_prefix(supervision_policy, "supervision://", "human_supervision_policy_ref")?;
        }
        if risk_class != "physical_action" {
            return Err(authority_error(
                "physical_action_risk_class_required",
                "Actuator-affecting work must be classified as risk_class physical_action.",
                json!({ "risk_class": risk_class }),
            ));
        }
        if generic_tool_call || execution_channel.as_deref() == Some("tool.invoke") {
            return Err(authority_error(
                "physical_action_generic_tool_call_blocked",
                "No actuator command is a generic tool call; physical actions require the physical-action admission lifecycle.",
                json!({ "execution_channel": execution_channel, "generic_tool_call": generic_tool_call }),
            ));
        }
        if simulation_only && execution_phase != "intent_proposed" {
            return Err(authority_error(
                "physical_action_simulation_not_execution_receipt",
                "Simulation-only evidence cannot be admitted as a physical actuator execution.",
                json!({ "execution_phase": execution_phase }),
            ));
        }
        require_refs(&requested_primitives, "requested_primitives")?;
        require_refs(&requested_scopes, "requested_scopes")?;
        if !requested_primitives.iter().any(|reference| reference.starts_with("prim:physical.")) {
            return Err(authority_error(
                "physical_action_primitive_required",
                "Physical-action admission requires a prim:physical.* primitive.",
                json!({ "requested_primitives": requested_primitives }),
            ));
        }
        if !requested_scopes.iter().any(|reference| reference.starts_with("scope:physical.")) {
            return Err(authority_error(
                "physical_action_scope_required",
                "Physical-action admission requires a scope:physical.* scope.",
                json!({ "requested_scopes": requested_scopes }),
            ));
        }
        if !emergency_stop_tested {
            return Err(authority_error(
                "physical_action_emergency_stop_test_required",
                "Physical-action admission requires a currently tested EmergencyStopAuthority.",
                json!({ "emergency_stop_tested": emergency_stop_tested }),
            ));
        }
        if let Some(latency) = emergency_stop_max_latency_ms {
            if latency > 1000.0 {
                return Err(authority_error(
                    "physical_action_emergency_stop_latency_exceeded",
                    "Physical-action emergency stop latency must remain within the admitted safety envelope.",
                    json!({ "emergency_stop_max_latency_ms": latency_to_json(latency) }),
                ));
            }
        }
        require_refs(&sensor_evidence_receipt_refs, "sensor_evidence_receipt_refs")?;
        for reference in &sensor_evidence_receipt_refs {
            require_prefix(reference, "receipt://", "sensor_evidence_receipt_refs")?;
        }
        if execution_phase == "command_issued" || execution_phase == "completed" {
            require_refs(&actuator_command_receipt_refs, "actuator_command_receipt_refs")?;
        }
        for reference in &actuator_command_receipt_refs {
            require_prefix(reference, "receipt://", "actuator_command_receipt_refs")?;
        }
        if matches!(supervision_mode.as_str(), "human_in_loop" | "manual_confirm_each_action")
            && (human_supervisor_refs.is_empty() || wallet_approval_ref.is_none())
        {
            return Err(authority_error(
                "physical_action_human_supervision_authority_required",
                "Human-in-loop physical action requires supervisor refs and wallet approval.",
                json!({ "supervision_mode": supervision_mode }),
            ));
        }
        if authority_ref.is_none() {
            return Err(authority_error(
                "physical_action_authority_ref_required",
                "Physical-action admission requires wallet authority or approval.",
                json!({ "authority_ref": authority_ref }),
            ));
        }
        require_refs(&policy_refs, "policy_refs")?;
        require_refs(&receipt_refs, "receipt_refs")?;
        require_refs(&agentgres_operation_refs, "agentgres_operation_refs")?;

        let admission_id = optional_value(request.get("admission_id")).unwrap_or_else(|| {
            format!("physical-action-admission:{}:{}", safe_id(&intent_id), safe_id(&action_kind))
        });
        let admitted_at =
            optional_value(request.get("admitted_at")).unwrap_or_else(|| now_iso.to_string());

        Ok(json!({
            "schema_version": PHYSICAL_ACTION_INTENT_ADMISSION_SCHEMA_VERSION,
            "admission_id": admission_id,
            "intent_id": intent_id,
            "actor_id": actor_id,
            "task_id": task_id,
            "domain_ref": domain_ref,
            "target_system_ref": target_system_ref,
            "action_kind": action_kind,
            "risk_class": "physical_action",
            "execution_phase": execution_phase,
            "requested_primitives": requested_primitives,
            "requested_scopes": requested_scopes,
            "physical_action_policy_ref": physical_action_policy_ref,
            "safety_envelope_ref": safety_envelope_ref,
            "human_supervision_policy_ref": human_supervision_policy_ref,
            "supervision_mode": supervision_mode,
            "human_supervisor_refs": human_supervisor_refs,
            "emergency_stop_authority_ref": emergency_stop_authority_ref,
            "emergency_stop_tested": emergency_stop_tested,
            "emergency_stop_max_latency_ms": emergency_stop_max_latency_ms.map(latency_to_json).unwrap_or(Value::Null),
            "sensor_evidence_receipt_refs": sensor_evidence_receipt_refs,
            "actuator_command_receipt_refs": actuator_command_receipt_refs,
            "incident_policy_ref": incident_policy_ref,
            "rollback_or_compensation_policy_ref": rollback_or_compensation_policy_ref,
            "wallet_approval_ref": wallet_approval_ref,
            "authority_ref": authority_ref,
            "policy_refs": policy_refs,
            "receipt_refs": receipt_refs,
            "agentgres_operation_refs": agentgres_operation_refs,
            "artifact_refs": artifact_refs,
            "state_root": state_root,
            "execution_channel": execution_channel,
            "decision": "admitted",
            "requiresDaemonGate": true,
            "generic_tool_call_blocked": true,
            "simulation_only": simulation_only,
            "admitted_at": admitted_at,
            "runtimeTruthSource": "daemon-runtime",
        }))
    }
}

/// Serialize a validated positive-integer-valued f64 as a JSON number (integer when it fits i64,
/// matching JSON.stringify's full-decimal rendering). Values beyond i64 (absurd latencies, error-
/// detail-only) fall back to f64 — serde cannot emit them as a JSON integer without arbitrary
/// precision.
fn latency_to_json(value: f64) -> Value {
    if value.fract() == 0.0 && value.abs() < 9_223_372_036_854_775_808.0 {
        json!(value as i64)
    } else {
        json!(value)
    }
}

fn default_value(value: Option<&Value>, fallback: &str) -> Value {
    match value {
        None | Some(Value::Null) => Value::String(fallback.to_string()),
        Some(value) => value.clone(),
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
    Err(RuntimePhysicalActionIntentAdmissionError::new(
        400,
        "physical_action_request_aliases_retired".to_string(),
        "Physical-action admission accepts only canonical snake_case request fields.".to_string(),
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
            Err(RuntimePhysicalActionIntentAdmissionError::new(
                400,
                format!("physical_action_{field}_invalid"),
                format!("Physical-action admission requires a valid {field}."),
                Value::Object(details),
            ))
        }
    }
}

/// Mirror JS `requiredString` — optionalString then 400 `_required`.
fn required_string(value: Option<&Value>, field: &str) -> AdmitResult<String> {
    optional_value(value).ok_or_else(|| {
        RuntimePhysicalActionIntentAdmissionError::new(
            400,
            format!("physical_action_{field}_required"),
            format!("Physical-action admission requires {field}."),
            json!({ "field": field }),
        )
    })
}

/// Mirror JS `requirePrefix` — 400 `_{field}_invalid`; details `{[field]: value}`.
fn require_prefix(value: &str, prefix: &str, field: &str) -> AdmitResult<()> {
    if value.starts_with(prefix) {
        return Ok(());
    }
    let mut details = Map::new();
    details.insert(field.to_string(), Value::String(value.to_string()));
    Err(RuntimePhysicalActionIntentAdmissionError::new(
        400,
        format!("physical_action_{field}_invalid"),
        format!("Physical-action {field} must start with {prefix}."),
        Value::Object(details),
    ))
}

fn require_target_prefix(value: &str) -> AdmitResult<()> {
    if TARGET_PREFIXES.iter().any(|prefix| value.starts_with(prefix)) {
        return Ok(());
    }
    Err(RuntimePhysicalActionIntentAdmissionError::new(
        400,
        "physical_action_target_system_ref_invalid".to_string(),
        "Physical-action target_system_ref must identify a robot, facility, vehicle, device, drone, or actuator.".to_string(),
        json!({ "target_system_ref": value, "allowed_prefixes": TARGET_PREFIXES }),
    ))
}

fn require_actor_ref(value: &str) -> AdmitResult<()> {
    if ACTOR_PREFIXES.iter().any(|prefix| value.starts_with(prefix)) {
        return Ok(());
    }
    Err(RuntimePhysicalActionIntentAdmissionError::new(
        400,
        "physical_action_actor_id_invalid".to_string(),
        "Physical-action actor_id must identify a worker, service engine, or runtime.".to_string(),
        json!({ "actor_id": value, "allowed_prefixes": ACTOR_PREFIXES }),
    ))
}

fn require_refs(refs: &[String], field: &str) -> AdmitResult<()> {
    if !refs.is_empty() {
        return Ok(());
    }
    Err(authority_error(
        &format!("physical_action_{field}_required"),
        &format!("Physical-action admission requires {field}."),
        json!({ "field": field }),
    ))
}

fn authority_error(code: &str, message: &str, details: Value) -> RuntimePhysicalActionIntentAdmissionError {
    RuntimePhysicalActionIntentAdmissionError::new(403, code.to_string(), message.to_string(), details)
}

/// Mirror JS `optionalPositiveInteger`: null/undefined/"" → None; Number(value) coercion; must be
/// a positive integer else 400 (details carry the ORIGINAL raw value).
fn optional_positive_integer(value: Option<&Value>) -> AdmitResult<Option<f64>> {
    let raw = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(string)) if string.is_empty() => return Ok(None),
        Some(value) => value,
    };
    let number = js_number_coerce(raw);
    if number.is_finite() && number.fract() == 0.0 && number > 0.0 {
        return Ok(Some(number));
    }
    Err(RuntimePhysicalActionIntentAdmissionError::new(
        400,
        "physical_action_emergency_stop_max_latency_ms_invalid".to_string(),
        "Physical-action emergency_stop_max_latency_ms must be a positive integer when supplied.".to_string(),
        json!({ "emergency_stop_max_latency_ms": raw }),
    ))
}

/// Mirror JS `Number(value)` (ToNumber): bool→0/1; number verbatim; string via ToNumber(string);
/// array → ToNumber(String(array)); object → NaN.
fn js_number_coerce(value: &Value) -> f64 {
    match value {
        Value::Null => 0.0,
        Value::Bool(boolean) => {
            if *boolean {
                1.0
            } else {
                0.0
            }
        }
        Value::Number(number) => number.as_f64().unwrap_or(f64::NAN),
        Value::String(string) => js_string_to_number(string),
        Value::Array(_) => js_string_to_number(&js_string_coerce(value)),
        Value::Object(_) => f64::NAN,
    }
}

/// Mirror JS ToNumber(string): trim; ""→0; ±Infinity; 0x/0o/0b radix; else a decimal literal
/// (rejecting any char outside [0-9 + - . e E] so "inf"/"nan"/"1_0" → NaN, matching JS).
fn js_string_to_number(string: &str) -> f64 {
    let trimmed = js_trim(string);
    if trimmed.is_empty() {
        return 0.0;
    }
    match trimmed {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    if let Some(radix_value) = parse_radix_literal(trimmed) {
        return radix_value;
    }
    if trimmed
        .chars()
        .all(|ch| ch.is_ascii_digit() || matches!(ch, '+' | '-' | '.' | 'e' | 'E'))
    {
        trimmed.parse::<f64>().unwrap_or(f64::NAN)
    } else {
        f64::NAN
    }
}

/// JS numeric string non-decimal radix literals: 0x.. (16), 0o.. (8), 0b.. (2). No sign allowed.
fn parse_radix_literal(trimmed: &str) -> Option<f64> {
    let lowered_prefix = trimmed.get(0..2)?.to_ascii_lowercase();
    let radix = match lowered_prefix.as_str() {
        "0x" => 16,
        "0o" => 8,
        "0b" => 2,
        _ => return None,
    };
    let digits = &trimmed[2..];
    if digits.is_empty() {
        return Some(f64::NAN);
    }
    match u128::from_str_radix(digits, radix) {
        Ok(value) => Some(value as f64),
        Err(_) => Some(f64::NAN),
    }
}

/// Mirror JS `optionalString`: String(value).trim(), None when null/absent/blank. Uses the
/// ECMAScript trim set (js_trim), not Rust's Unicode White_Space (which differs on U+FEFF/U+0085).
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

/// JS `String.prototype.trim` whitespace set: WhiteSpace (TAB/VT/FF/SP/NBSP/ZWNBSP + Unicode Zs)
/// ∪ LineTerminator (LF/CR/LS/PS). NOTE this differs from Rust's `char::is_whitespace`
/// (Unicode White_Space): JS trims U+FEFF (BOM) but NOT U+0085 (NEL); Rust is the reverse.
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

/// Mirror the LOCAL `uniqueStrings(normalizeArray(value))`: truthy raw items, `String()`-coerced
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
            "intent_id": "intent://physical/carwash/prep-vehicle-001",
            "actor_id": "worker:carwash-prep-humanoid",
            "task_id": "task://carwash/prep-vehicle-001",
            "domain_ref": "domain://carwash/vehicle-prep",
            "target_system_ref": "robot://bay-3/humanoid-1",
            "action_kind": "manipulation",
            "risk_class": "physical_action",
            "execution_phase": "command_issued",
            "requested_primitives": ["prim:physical.actuate"],
            "requested_scopes": ["scope:physical.actuate"],
            "physical_action_policy_ref": "policy://physical/carwash-prep",
            "safety_envelope_ref": "safety://carwash/bay-3",
            "human_supervision_policy_ref": "supervision://carwash/on-loop",
            "supervision_mode": "human_on_loop",
            "human_supervisor_refs": ["user://operator/bay-3"],
            "emergency_stop_authority_ref": "estop://carwash/bay-3",
            "emergency_stop_tested": true,
            "emergency_stop_max_latency_ms": 250,
            "sensor_evidence_receipt_refs": ["receipt://sensor/bay-3/preflight"],
            "actuator_command_receipt_refs": ["receipt://actuator/bay-3/prep-command"],
            "incident_policy_ref": "policy://physical/incidents/carwash",
            "rollback_or_compensation_policy_ref": "policy://physical/compensation/carwash",
            "wallet_approval_ref": "approval://wallet/physical-action/carwash",
            "authority_ref": "grant://wallet/physical-action/carwash",
            "policy_refs": ["policy://physical/carwash-prep", "policy://physical/incidents/carwash"],
            "receipt_refs": ["receipt://sensor/bay-3/preflight", "receipt://actuator/bay-3/prep-command"],
            "agentgres_operation_refs": ["agentgres://operation/physical-action/carwash/prep-vehicle-001"],
            "artifact_refs": ["artifact://sensor-video/bay-3/preflight"],
            "state_root": "state_root:physical:carwash:001",
            "execution_channel": "physical_action_adapter",
        })
    }

    #[test]
    fn admits_physical_action() {
        let admission = RuntimePhysicalActionIntentAdmissionCore
            .admit(&base_request(), "2026-06-17T18:00:00.000Z")
            .expect("admitted");
        assert_eq!(admission["schema_version"], PHYSICAL_ACTION_INTENT_ADMISSION_SCHEMA_VERSION);
        assert_eq!(
            admission["admission_id"],
            "physical-action-admission:intent_physical_carwash_prep-vehicle-001:manipulation"
        );
        assert_eq!(admission["risk_class"], "physical_action");
        assert_eq!(admission["decision"], "admitted");
        assert_eq!(admission["requiresDaemonGate"], true);
        assert_eq!(admission["generic_tool_call_blocked"], true);
        assert_eq!(admission["emergency_stop_max_latency_ms"], json!(250));
    }

    #[test]
    fn blocks_generic_tool_call() {
        let mut request = base_request();
        request["execution_channel"] = json!("tool.invoke");
        request["generic_tool_call"] = json!(true);
        let error = RuntimePhysicalActionIntentAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.status, 403);
        assert_eq!(error.code, "physical_action_generic_tool_call_blocked");
    }

    #[test]
    fn requires_tested_emergency_stop() {
        let mut request = base_request();
        request["emergency_stop_tested"] = json!(false);
        let error = RuntimePhysicalActionIntentAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.code, "physical_action_emergency_stop_test_required");
        assert_eq!(error.status, 403);
    }

    #[test]
    fn requires_sensor_evidence() {
        let mut request = base_request();
        request["sensor_evidence_receipt_refs"] = json!([]);
        let error = RuntimePhysicalActionIntentAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.code, "physical_action_sensor_evidence_receipt_refs_required");
        assert_eq!(error.status, 403);
    }

    #[test]
    fn blocks_simulation_only_execution() {
        let mut request = base_request();
        request["simulation_only"] = json!(true);
        let error = RuntimePhysicalActionIntentAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.code, "physical_action_simulation_not_execution_receipt");
        assert_eq!(error.status, 403);
    }

    #[test]
    fn manual_confirm_requires_supervisors() {
        let mut request = base_request();
        request["supervision_mode"] = json!("manual_confirm_each_action");
        request["human_supervisor_refs"] = json!([]);
        request["wallet_approval_ref"] = Value::Null;
        request["authority_ref"] = Value::Null;
        let error = RuntimePhysicalActionIntentAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.code, "physical_action_human_supervision_authority_required");
        assert_eq!(error.status, 403);
    }

    #[test]
    fn optional_positive_integer_coercion() {
        // true→1, "0x10"→16, [250]→250, "  10  "→10
        assert_eq!(js_number_coerce(&json!(true)), 1.0);
        assert_eq!(js_number_coerce(&json!("0x10")), 16.0);
        assert_eq!(js_number_coerce(&json!([250])), 250.0);
        assert_eq!(js_number_coerce(&json!("  10  ")), 10.0);
        assert_eq!(js_number_coerce(&json!("0o17")), 15.0);
        assert!(js_number_coerce(&json!({})).is_nan());
        assert!(js_number_coerce(&json!("abc")).is_nan());
        // "" early-returns None
        assert_eq!(optional_positive_integer(Some(&json!(""))).unwrap(), None);
        assert_eq!(optional_positive_integer(None).unwrap(), None);
        // 2.5 → not integer → err
        assert!(optional_positive_integer(Some(&json!(2.5))).is_err());
        // []→0 → not >0 → err
        assert!(optional_positive_integer(Some(&json!([]))).is_err());
    }

    #[test]
    fn latency_over_1000_blocked() {
        let mut request = base_request();
        request["emergency_stop_max_latency_ms"] = json!(1500);
        let error = RuntimePhysicalActionIntentAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.code, "physical_action_emergency_stop_latency_exceeded");
        assert_eq!(error.status, 403);
    }

    #[test]
    fn bad_intent_prefix_is_400() {
        let mut request = base_request();
        request["intent_id"] = json!("nope://x");
        let error = RuntimePhysicalActionIntentAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "physical_action_intent_id_invalid");
    }

    #[test]
    fn js_trim_matches_ecmascript_whitespace_set() {
        // JS trims U+FEFF (BOM) but NOT U+0085 (NEL); Rust's is_whitespace is the reverse.
        assert_eq!(js_trim("\u{FEFF}intent://x\u{FEFF}"), "intent://x");
        assert_eq!(js_trim("\u{0085}x\u{0085}"), "\u{0085}x\u{0085}"); // NEL not trimmed
        assert_eq!(js_trim("\u{00A0}x\u{2028}"), "x"); // NBSP + LS trimmed
        // Number("﻿10") === 10 (BOM trimmed before parse).
        assert_eq!(js_number_coerce(&json!("\u{FEFF}10")), 10.0);
    }

    #[test]
    fn latency_to_json_renders_integers() {
        assert_eq!(latency_to_json(250.0), json!(250));
        assert_eq!(latency_to_json(1e16), json!(10_000_000_000_000_000i64));
        // 2^53 renders as a full integer, not 9007199254740992.0
        assert_eq!(latency_to_json(9_007_199_254_740_992.0), json!(9_007_199_254_740_992i64));
    }

    #[test]
    fn rejects_retired_aliases() {
        let mut request = base_request();
        request["intentId"] = json!("legacy");
        let error = RuntimePhysicalActionIntentAdmissionCore.admit(&request, "now").expect_err("retired");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "physical_action_request_aliases_retired");
    }
}
