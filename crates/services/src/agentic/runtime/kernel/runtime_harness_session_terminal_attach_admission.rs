//! Harness-session-terminal-attach admission planner.
//!
//! A faithful Rust port of the retired JS `admitHarnessSessionTerminalAttach`
//! (`packages/runtime-daemon/src/runtime-harness-session-terminal-attach.mjs`). Pure validation +
//! composition: the client may create/write the host PTY only after the daemon binds the spawned
//! command + readiness proof + authority scopes + receipts + transcript stream + workspace root.
//! It validates two nested daemon-admitted records (session_spawn, session_readiness) and composes
//! a client-attach contract + transcript projection from them.
//!
//! PASSTHROUGH SEMANTICS: most output fields are RAW clones of spawn fields, OMITTED when the
//! source is `undefined` (matching JSON.stringify), present (as null) when the source is null.
//! Cross-record equality checks use JS `===` reference semantics (distinct JSON parses → object/
//! array values are never equal). `uniqueStrings` here is the SHARED no-trim variant.

use serde_json::{json, Map, Value};

pub const HARNESS_SESSION_TERMINAL_ATTACH_SCHEMA_VERSION: &str =
    "ioi.runtime.harness_session_terminal_attach.v1";

const SPAWN_SCHEMA_VERSION: &str = "ioi.runtime.harness_session_spawn.v1";
const READINESS_SCHEMA_VERSION: &str = "ioi.runtime.harness_session_readiness.v1";

/// Spawn fields copied verbatim into the attach record, omitted when the source is undefined.
const SPAWN_PASSTHROUGH_FIELDS: &[&str] = &[
    "spawn_id",
    "launch_id",
    "session_binding_ref",
    "session_route_ref",
    "harness_selection_ref",
    "model_configuration_ref",
    "model_route_ref",
    "model_name",
    "workspace_ref",
    "workspace_root",
    "terminal_session_ref",
    "command_contract_ref",
    "command_contract",
    "workspace_mount_policy",
    "privacy_posture_ref",
    "receipt_policy_ref",
];

#[derive(Debug, Clone)]
pub struct RuntimeHarnessSessionTerminalAttachAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimeHarnessSessionTerminalAttachAdmissionError {
    fn new(status: u16, code: &str, message: &str, details: Value) -> Self {
        Self {
            status,
            code: code.to_string(),
            message: message.to_string(),
            details,
        }
    }
}

type AdmitResult<T> = Result<T, RuntimeHarnessSessionTerminalAttachAdmissionError>;

#[derive(Default)]
pub struct RuntimeHarnessSessionTerminalAttachAdmissionCore;

impl RuntimeHarnessSessionTerminalAttachAdmissionCore {
    pub fn admit(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        let spawn = require_spawn(request.get("session_spawn"))?;
        let readiness = require_readiness(request.get("session_readiness"), spawn)?;

        let attach_id = optional_value(request.get("attach_id")).unwrap_or_else(|| {
            format!(
                "harness-session-terminal-attach:{}",
                safe_id_value(readiness.get("readiness_id"))
            )
        });
        let receipt_ref = optional_value(request.get("attach_receipt_ref")).unwrap_or_else(|| {
            format!(
                "receipt://harness-session-terminal-attach/{}",
                safe_id(&attach_id)
            )
        });
        let transcript_id = optional_value(request.get("transcript_id"))
            .unwrap_or_else(|| format!("harness-terminal-transcript:{}", safe_id(&attach_id)));
        let transcript_stream_ref = optional_value(request.get("transcript_stream_ref"))
            .unwrap_or_else(|| {
                format!(
                    "agentgres://trace/harness-terminal-transcript/{}",
                    safe_id(&transcript_id)
                )
            });

        // command_line = optionalString(spawn.terminal_attach_contract?.command_line)
        let terminal_attach_contract = spawn.get("terminal_attach_contract");
        let command_line = terminal_attach_contract
            .and_then(|contract| contract.as_object())
            .and_then(|contract| contract.get("command_line"))
            .and_then(|value| optional_value(Some(value)));
        let Some(command_line) = command_line else {
            // JS uses RAW `spawn.spawn_id` here (not `?? null`), so an absent spawn_id is OMITTED
            // from the details (vs the other error paths which nullish-coalesce).
            let mut details = Map::new();
            insert_if_present(&mut details, "spawn_id", spawn.get("spawn_id"));
            return Err(RuntimeHarnessSessionTerminalAttachAdmissionError::new(
                400,
                "harness_session_terminal_attach_command_required",
                "Harness session terminal attach requires a daemon-resolved command line.",
                Value::Object(details),
            ));
        };

        let attached_at =
            optional_value(request.get("attached_at")).unwrap_or_else(|| now_iso.to_string());

        // client_attach_contract = {...spawn.terminal_attach_contract, <5 overrides>}.
        let mut client_attach_contract = match terminal_attach_contract {
            Some(Value::Object(map)) => map.clone(),
            _ => Map::new(),
        };
        client_attach_contract.insert("command_line".to_string(), json!(command_line));
        client_attach_contract.insert(
            "initial_write".to_string(),
            json!(format!("{command_line}\n")),
        );
        client_attach_contract.insert(
            "transcript_stream_ref".to_string(),
            json!(transcript_stream_ref),
        );
        client_attach_contract.insert(
            "pty_transport".to_string(),
            json!("hypervisor_client_terminal_adapter"),
        );
        client_attach_contract.insert(
            "process_custody".to_string(),
            json!("client_host_pty_after_daemon_attach_admission"),
        );

        let terminal_transcript_projection = json!({
            "schema_version": "ioi.runtime.harness_terminal_transcript_projection.v1",
            "transcript_id": transcript_id,
            "transcript_state": "awaiting_client_stream",
            "transcript_stream_ref": transcript_stream_ref,
            "cursor": 0,
            "lines": [
                { "stream": "system", "text": "Daemon admitted client PTY attach after harness spawn and host readiness checks." },
                { "stream": "stdin", "text": command_line },
            ],
            "runtimeTruthSource": "daemon-runtime",
        });

        let receipt_refs = unique_strings_concat(&[
            normalize_array_raw(readiness.get("receipt_refs")),
            normalize_array_raw(spawn.get("receipt_refs")),
            vec![Value::String(receipt_ref)],
        ]);
        let agentgres_operation_refs = unique_strings_concat(&[
            normalize_array_raw(readiness.get("agentgres_operation_refs")),
            normalize_array_raw(spawn.get("agentgres_operation_refs")),
            vec![Value::String(format!(
                "agentgres://operation/harness-session-terminal-attach/{}",
                safe_id(&attach_id)
            ))],
        ]);

        let mut out = Map::new();
        out.insert(
            "schema_version".to_string(),
            json!(HARNESS_SESSION_TERMINAL_ATTACH_SCHEMA_VERSION),
        );
        out.insert("attach_id".to_string(), json!(attach_id));
        out.insert("decision".to_string(), json!("admitted"));
        out.insert(
            "attach_state".to_string(),
            json!("client_pty_attach_admitted"),
        );
        out.insert(
            "attach_lane".to_string(),
            json!("hypervisor_client_terminal_adapter"),
        );
        insert_if_present(&mut out, "spawn_id", spawn.get("spawn_id"));
        insert_if_present(&mut out, "readiness_id", readiness.get("readiness_id"));
        for field in SPAWN_PASSTHROUGH_FIELDS {
            if *field == "spawn_id" {
                continue; // already inserted above in JS order
            }
            insert_if_present(&mut out, field, spawn.get(field));
        }
        out.insert(
            "agent_harness_adapter_id".to_string(),
            nullish(spawn.get("agent_harness_adapter_id")),
        );
        out.insert(
            "client_attach_contract".to_string(),
            Value::Object(client_attach_contract),
        );
        out.insert(
            "terminal_transcript_projection".to_string(),
            terminal_transcript_projection,
        );
        out.insert(
            "authority_scope_refs".to_string(),
            Value::Array(normalize_array_raw(spawn.get("authority_scope_refs"))),
        );
        out.insert("receipt_refs".to_string(), json!(receipt_refs));
        out.insert(
            "agentgres_operation_refs".to_string(),
            json!(agentgres_operation_refs),
        );
        out.insert(
            "state_root".to_string(),
            json!(format!(
                "agentgres://state-root/harness-session-terminal-attach/{}",
                safe_id(&attach_id)
            )),
        );
        out.insert("attached_at".to_string(), json!(attached_at));
        out.insert("requiresDaemonGate".to_string(), json!(true));
        out.insert("runtimeTruthSource".to_string(), json!("daemon-runtime"));
        out.insert(
            "terminal_attach_invariant".to_string(),
            json!("The client may create and write to the host PTY only after the daemon binds the spawned command, readiness proof, authority scopes, receipt refs, transcript stream, and workspace root in this attach object."),
        );

        Ok(Value::Object(out))
    }
}

fn require_spawn(value: Option<&Value>) -> AdmitResult<&Value> {
    let schema_ok = value
        .and_then(|spawn| spawn.as_object())
        .and_then(|spawn| spawn.get("schema_version"))
        .and_then(Value::as_str)
        == Some(SPAWN_SCHEMA_VERSION);
    let Some(spawn) = value
        .filter(|value| value.is_object())
        .filter(|_| schema_ok)
    else {
        return Err(RuntimeHarnessSessionTerminalAttachAdmissionError::new(
            400,
            "harness_session_terminal_attach_spawn_required",
            "Harness session terminal attach requires an admitted spawn.",
            json!({ "expected_schema_version": SPAWN_SCHEMA_VERSION }),
        ));
    };
    let pty_transport = spawn
        .get("command_contract")
        .and_then(|contract| contract.as_object())
        .and_then(|contract| contract.get("pty_transport"));
    let boundary_ok = spawn.get("decision") == Some(&json!("admitted"))
        && spawn.get("spawn_state") == Some(&json!("ready_for_client_pty_attach"))
        && spawn.get("requiresDaemonGate") == Some(&Value::Bool(true))
        && spawn.get("runtimeTruthSource") == Some(&json!("daemon-runtime"))
        && pty_transport == Some(&json!("hypervisor_client_terminal_adapter"));
    if !boundary_ok {
        return Err(RuntimeHarnessSessionTerminalAttachAdmissionError::new(
            403,
            "harness_session_terminal_attach_spawn_boundary_invalid",
            "Harness session terminal attach requires a daemon-gated spawn ready for client PTY attach.",
            json!({
                "decision": nullish(spawn.get("decision")),
                "spawn_state": nullish(spawn.get("spawn_state")),
                "requiresDaemonGate": nullish(spawn.get("requiresDaemonGate")),
                "runtimeTruthSource": nullish(spawn.get("runtimeTruthSource")),
                "pty_transport": nullish(pty_transport),
            }),
        ));
    }
    Ok(spawn)
}

fn require_readiness<'a>(value: Option<&'a Value>, spawn: &Value) -> AdmitResult<&'a Value> {
    let schema_ok = value
        .and_then(|readiness| readiness.as_object())
        .and_then(|readiness| readiness.get("schema_version"))
        .and_then(Value::as_str)
        == Some(READINESS_SCHEMA_VERSION);
    let Some(readiness) = value
        .filter(|value| value.is_object())
        .filter(|_| schema_ok)
    else {
        return Err(RuntimeHarnessSessionTerminalAttachAdmissionError::new(
            400,
            "harness_session_terminal_attach_readiness_required",
            "Harness session terminal attach requires host readiness.",
            json!({ "expected_schema_version": READINESS_SCHEMA_VERSION }),
        ));
    };
    let boundary_ok = readiness.get("decision") == Some(&json!("ready"))
        && readiness.get("readiness_state") == Some(&json!("ready_for_harness_pty_attach"))
        && js_strict_eq(readiness.get("spawn_id"), spawn.get("spawn_id"))
        && js_strict_eq(readiness.get("launch_id"), spawn.get("launch_id"))
        && js_strict_eq(
            readiness.get("session_binding_ref"),
            spawn.get("session_binding_ref"),
        )
        && readiness.get("requiresDaemonGate") == Some(&Value::Bool(true))
        && readiness.get("runtimeTruthSource") == Some(&json!("daemon-runtime"));
    if !boundary_ok {
        return Err(RuntimeHarnessSessionTerminalAttachAdmissionError::new(
            403,
            "harness_session_terminal_attach_readiness_boundary_invalid",
            "Harness session terminal attach requires readiness for the same daemon-gated spawn.",
            json!({
                "decision": nullish(readiness.get("decision")),
                "readiness_state": nullish(readiness.get("readiness_state")),
                "readiness_spawn_id": nullish(readiness.get("spawn_id")),
                "spawn_id": nullish(spawn.get("spawn_id")),
                "readiness_launch_id": nullish(readiness.get("launch_id")),
                "launch_id": nullish(spawn.get("launch_id")),
            }),
        ));
    }
    Ok(readiness)
}

/// Insert a raw-cloned passthrough field only when the source is present (JS omits undefined).
fn insert_if_present(out: &mut Map<String, Value>, key: &str, value: Option<&Value>) {
    if let Some(value) = value {
        out.insert(key.to_string(), value.clone());
    }
}

/// Mirror JS `value ?? null`: null/undefined → null, else the value.
fn nullish(value: Option<&Value>) -> Value {
    match value {
        None | Some(Value::Null) => Value::Null,
        Some(value) => value.clone(),
    }
}

/// Mirror JS `===` for two values that come from DISTINCT JSON parse trees: primitives compare by
/// value; objects/arrays are never equal (reference inequality); undefined===undefined / null===null.
fn js_strict_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true, // undefined === undefined
        (Some(Value::Null), Some(Value::Null)) => true,
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        // objects/arrays from distinct parses are never reference-equal; mixed types differ.
        _ => false,
    }
}

/// Mirror JS `normalizeArray`: Array.isArray ? value.filter(Boolean) : [] — keep truthy RAW items.
fn normalize_array_raw(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter(|item| is_truthy(item))
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

/// Mirror `uniqueStrings([...part1, ...part2, ...])` (SHARED, no trim): String()-coerce each
/// truthy item, drop blanks, first-seen dedup.
fn unique_strings_concat(parts: &[Vec<Value>]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in parts {
        for item in part {
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
    }
    out
}

/// Mirror JS `optionalString`: String(value).trim() (ECMAScript trim set), None when null/blank.
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

/// Mirror the SHARED `safeId(value)`: String(value ?? "runtime").replace([^A-Za-z0-9_.-]+, "_").
fn safe_id(value: &str) -> String {
    safe_id_string(value)
}

/// `safeId` applied to a raw value via String(value ?? "runtime") coercion.
fn safe_id_value(value: Option<&Value>) -> String {
    let coerced = match value {
        None | Some(Value::Null) => "runtime".to_string(),
        Some(value) => js_string_coerce(value),
    };
    safe_id_string(&coerced)
}

fn safe_id_string(value: &str) -> String {
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

    fn spawn() -> Value {
        json!({
            "schema_version": "ioi.runtime.harness_session_spawn.v1",
            "decision": "admitted",
            "spawn_state": "ready_for_client_pty_attach",
            "requiresDaemonGate": true,
            "runtimeTruthSource": "daemon-runtime",
            "spawn_id": "spawn:1",
            "launch_id": "launch:1",
            "session_binding_ref": "harness-session-binding:b/1",
            "session_route_ref": "session-route:sessions/m/p",
            "harness_selection_ref": "agent-harness-adapter:codex_cli",
            "agent_harness_adapter_id": "codex_cli",
            "model_configuration_ref": "model-config:local/qwen",
            "model_route_ref": "model-route:hypervisor/default",
            "model_name": "qwen",
            "workspace_ref": "workspace://ioi",
            "workspace_root": "/work/ioi",
            "terminal_session_ref": "terminal:1",
            "command_contract_ref": "command-contract:1",
            "command_contract": { "pty_transport": "hypervisor_client_terminal_adapter" },
            "terminal_attach_contract": { "command_line": "codex --foo", "rows": 40 },
            "workspace_mount_policy": "redacted_projection",
            "privacy_posture_ref": "privacy:redacted-projection",
            "authority_scope_refs": ["scope:workspace.read"],
            "receipt_policy_ref": "receipt-policy:harness/default",
            "receipt_refs": ["receipt://spawn/1"],
            "agentgres_operation_refs": ["agentgres://operation/spawn/1"],
        })
    }

    fn readiness() -> Value {
        json!({
            "schema_version": "ioi.runtime.harness_session_readiness.v1",
            "decision": "ready",
            "readiness_state": "ready_for_harness_pty_attach",
            "readiness_id": "readiness:1",
            "spawn_id": "spawn:1",
            "launch_id": "launch:1",
            "session_binding_ref": "harness-session-binding:b/1",
            "requiresDaemonGate": true,
            "runtimeTruthSource": "daemon-runtime",
            "receipt_refs": ["receipt://readiness/1"],
            "agentgres_operation_refs": ["agentgres://operation/readiness/1"],
        })
    }

    fn request() -> Value {
        json!({ "session_spawn": spawn(), "session_readiness": readiness() })
    }

    #[test]
    fn admits_terminal_attach() {
        let admission = RuntimeHarnessSessionTerminalAttachAdmissionCore
            .admit(&request(), "2026-06-18T00:00:00.000Z")
            .expect("admitted");
        assert_eq!(
            admission["schema_version"],
            HARNESS_SESSION_TERMINAL_ATTACH_SCHEMA_VERSION
        );
        assert_eq!(admission["decision"], "admitted");
        assert_eq!(
            admission["attach_id"],
            "harness-session-terminal-attach:readiness_1"
        );
        assert_eq!(admission["spawn_id"], "spawn:1");
        assert_eq!(
            admission["client_attach_contract"]["command_line"],
            "codex --foo"
        );
        assert_eq!(
            admission["client_attach_contract"]["initial_write"],
            "codex --foo\n"
        );
        assert_eq!(admission["client_attach_contract"]["rows"], 40); // spread preserved
        assert_eq!(
            admission["terminal_transcript_projection"]["lines"][1]["text"],
            "codex --foo"
        );
        assert_eq!(
            admission["receipt_refs"],
            json!([
                "receipt://readiness/1",
                "receipt://spawn/1",
                "receipt://harness-session-terminal-attach/harness-session-terminal-attach_readiness_1"
            ])
        );
        assert_eq!(admission["requiresDaemonGate"], true);
    }

    #[test]
    fn rejects_missing_spawn() {
        let error = RuntimeHarnessSessionTerminalAttachAdmissionCore
            .admit(&json!({ "session_readiness": readiness() }), "now")
            .expect_err("blocked");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "harness_session_terminal_attach_spawn_required");
    }

    #[test]
    fn rejects_spawn_boundary() {
        let mut request = request();
        request["session_spawn"]["spawn_state"] = json!("provisioning");
        let error = RuntimeHarnessSessionTerminalAttachAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 403);
        assert_eq!(
            error.code,
            "harness_session_terminal_attach_spawn_boundary_invalid"
        );
    }

    #[test]
    fn rejects_readiness_spawn_id_mismatch() {
        let mut request = request();
        request["session_readiness"]["spawn_id"] = json!("spawn:OTHER");
        let error = RuntimeHarnessSessionTerminalAttachAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 403);
        assert_eq!(
            error.code,
            "harness_session_terminal_attach_readiness_boundary_invalid"
        );
    }

    #[test]
    fn rejects_missing_command_line() {
        let mut request = request();
        request["session_spawn"]["terminal_attach_contract"] = json!({ "rows": 40 });
        let error = RuntimeHarnessSessionTerminalAttachAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 400);
        assert_eq!(
            error.code,
            "harness_session_terminal_attach_command_required"
        );
    }

    #[test]
    fn command_required_details_omit_absent_spawn_id() {
        // spawn passes boundary but lacks spawn_id + command_line; readiness lacks spawn_id too
        // (so undefined===undefined passes the cross-check). JS uses RAW spawn.spawn_id → omitted.
        let mut request = request();
        request["session_spawn"]
            .as_object_mut()
            .unwrap()
            .remove("spawn_id");
        request["session_spawn"]["terminal_attach_contract"] = json!({ "rows": 40 });
        request["session_readiness"]
            .as_object_mut()
            .unwrap()
            .remove("spawn_id");
        let error = RuntimeHarnessSessionTerminalAttachAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "harness_session_terminal_attach_command_required"
        );
        assert_eq!(error.details, json!({})); // spawn_id key omitted, not null
    }

    #[test]
    fn omits_undefined_passthrough_fields() {
        let mut request = request();
        request["session_spawn"]
            .as_object_mut()
            .unwrap()
            .remove("model_name");
        let admission = RuntimeHarnessSessionTerminalAttachAdmissionCore
            .admit(&request, "now")
            .expect("admitted");
        assert!(admission.as_object().unwrap().get("model_name").is_none());
        // agent_harness_adapter_id is always present (?? null).
        assert_eq!(admission["agent_harness_adapter_id"], "codex_cli");
    }

    #[test]
    fn authority_scope_refs_keep_raw_truthy() {
        let mut request = request();
        request["session_spawn"]["authority_scope_refs"] = json!(["scope:a", 0, { "p": 1 }]);
        let admission = RuntimeHarnessSessionTerminalAttachAdmissionCore
            .admit(&request, "now")
            .expect("admitted");
        // normalizeArray drops falsy 0 but keeps the raw object.
        assert_eq!(
            admission["authority_scope_refs"],
            json!(["scope:a", { "p": 1 }])
        );
    }
}
