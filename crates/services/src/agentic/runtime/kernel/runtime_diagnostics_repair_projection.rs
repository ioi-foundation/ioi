use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path};

pub const RUNTIME_DIAGNOSTICS_REPAIR_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-repair-projection-request.v1";
pub const RUNTIME_DIAGNOSTICS_REPAIR_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics_repair_projection.v1";
const RUNTIME_DIAGNOSTICS_REPAIR_DECISION_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics_repair_decision.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeDiagnosticsRepairProjectionRequest {
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub projection_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub decision_id: Option<String>,
    #[serde(default)]
    pub gate_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDiagnosticsRepairProjectionCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeDiagnosticsRepairProjectionCommandError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeDiagnosticsRepairProjectionCore;

#[derive(Debug, Clone)]
pub struct RuntimeDiagnosticsRepairProjectionRecord {
    pub operation: String,
    pub operation_kind: String,
    pub projection_kind: String,
    pub thread_id: String,
    pub decision_id: String,
    pub gate_id: Option<String>,
    pub source: String,
    pub projection: Value,
    pub record_count: usize,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
}

pub fn project_runtime_diagnostics_repair_projection_response(
    request: RuntimeDiagnosticsRepairProjectionRequest,
) -> Result<Value, RuntimeDiagnosticsRepairProjectionCommandError> {
    let record = RuntimeDiagnosticsRepairProjectionCore::default().project(&request)?;
    Ok(json!({
        "source": "rust_runtime_diagnostics_repair_projection_command",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

impl RuntimeDiagnosticsRepairProjectionCore {
    pub fn project(
        &self,
        request: &RuntimeDiagnosticsRepairProjectionRequest,
    ) -> Result<
        RuntimeDiagnosticsRepairProjectionRecord,
        RuntimeDiagnosticsRepairProjectionCommandError,
    > {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_DIAGNOSTICS_REPAIR_PROJECTION_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeDiagnosticsRepairProjectionCommandError::new(
                    "runtime_diagnostics_repair_projection_schema_version_invalid",
                    format!(
                        "expected {RUNTIME_DIAGNOSTICS_REPAIR_PROJECTION_REQUEST_SCHEMA_VERSION}, got {schema_version}"
                    ),
                ));
            }
        }
        reject_projection_candidate_transport(request)?;

        let projection_kind = normalized_projection_kind(request)?;
        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeDiagnosticsRepairProjectionCommandError::new(
                "runtime_diagnostics_repair_projection_thread_id_required",
                "diagnostics repair projection requires thread_id",
            )
        })?;
        let decision_id = optional_trimmed(request.decision_id.as_deref()).ok_or_else(|| {
            RuntimeDiagnosticsRepairProjectionCommandError::new(
                "runtime_diagnostics_repair_projection_decision_id_required",
                "diagnostics repair projection requires decision_id",
            )
        })?;
        let projection = projection_for_kind(&projection_kind, request, &thread_id, &decision_id)?;
        let record_count = record_count_for_projection(&projection);
        let operation = request
            .operation
            .clone()
            .unwrap_or_else(|| "runtime_diagnostics_repair_projection".to_string());
        let operation_kind = request
            .operation_kind
            .clone()
            .unwrap_or_else(|| format!("runtime.diagnostics_repair_projection.{projection_kind}"));
        let gate_id = optional_trimmed(request.gate_id.as_deref());
        let source = optional_trimmed(request.source.as_deref())
            .unwrap_or_else(|| "runtime.diagnostics_repair_projection.rust_command".to_string());
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_diagnostics_repair_decision_projection_rust_owned".to_string(),
                "rust_daemon_core_diagnostics_repair_projection_required".to_string(),
                "rust_daemon_core_diagnostics_repair_replay_required".to_string(),
                "agentgres_diagnostics_repair_projection_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };
        let receipt_refs = unique_strings(
            string_array_field(&projection, "receipt_refs")
                .into_iter()
                .chain(std::iter::once(format!(
                    "receipt_runtime_diagnostics_repair_projection_{projection_kind}"
                )))
                .collect(),
        );

        Ok(RuntimeDiagnosticsRepairProjectionRecord {
            operation,
            operation_kind,
            projection_kind,
            thread_id,
            decision_id,
            gate_id,
            source,
            projection,
            record_count,
            evidence_refs,
            receipt_refs,
        })
    }
}

impl RuntimeDiagnosticsRepairProjectionRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_DIAGNOSTICS_REPAIR_PROJECTION_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_diagnostics_repair_projection",
            "status": "projected",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "projection_kind": self.projection_kind,
            "thread_id": self.thread_id,
            "decision_id": self.decision_id,
            "gate_id": self.gate_id,
            "source": self.source,
            "projection": self.projection,
            "record_count": self.record_count,
            "evidence_refs": self.evidence_refs,
            "receipt_refs": self.receipt_refs,
        })
    }
}

fn projection_for_kind(
    projection_kind: &str,
    request: &RuntimeDiagnosticsRepairProjectionRequest,
    thread_id: &str,
    decision_id: &str,
) -> Result<Value, RuntimeDiagnosticsRepairProjectionCommandError> {
    match projection_kind {
        "decision" => Ok(decision_candidates(request, thread_id)?
            .into_iter()
            .find(|record| {
                matches_thread(record, thread_id)
                    && matches_decision_id(record, decision_id)
                    && matches_gate_id(record, request.gate_id.as_deref())
            })
            .map(|record| projected_decision_record(record, request, thread_id, decision_id))
            .unwrap_or(Value::Null)),
        _ => Err(RuntimeDiagnosticsRepairProjectionCommandError::new(
            "runtime_diagnostics_repair_projection_kind_invalid",
            format!("unsupported diagnostics repair projection kind {projection_kind}"),
        )),
    }
}

fn reject_projection_candidate_transport(
    request: &RuntimeDiagnosticsRepairProjectionRequest,
) -> Result<(), RuntimeDiagnosticsRepairProjectionCommandError> {
    for key in ["projection", "decision", "decisions", "repair_decisions"] {
        if request.extra.contains_key(key) {
            return Err(RuntimeDiagnosticsRepairProjectionCommandError::new(
                "runtime_diagnostics_repair_projection_candidate_transport_retired",
                format!(
                    "diagnostics repair projection rejects retired JS candidate transport {key}"
                ),
            ));
        }
    }
    Ok(())
}

fn normalized_projection_kind(
    request: &RuntimeDiagnosticsRepairProjectionRequest,
) -> Result<String, RuntimeDiagnosticsRepairProjectionCommandError> {
    let projection_kind =
        optional_trimmed_lower(request.projection_kind.as_deref()).or_else(|| {
            let operation_kind = optional_trimmed(request.operation_kind.as_deref())?;
            operation_kind
                .split('.')
                .next_back()
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        });
    match projection_kind.as_deref() {
        Some("decision") => Ok("decision".to_string()),
        Some(value) => Err(RuntimeDiagnosticsRepairProjectionCommandError::new(
            "runtime_diagnostics_repair_projection_kind_invalid",
            format!("{value} is not a Rust-owned diagnostics repair projection kind"),
        )),
        None => Err(RuntimeDiagnosticsRepairProjectionCommandError::new(
            "runtime_diagnostics_repair_projection_kind_required",
            "diagnostics repair projection kind is required",
        )),
    }
}

fn decision_candidates(
    request: &RuntimeDiagnosticsRepairProjectionRequest,
    thread_id: &str,
) -> Result<Vec<Value>, RuntimeDiagnosticsRepairProjectionCommandError> {
    let state_dir = optional_trimmed(request.state_dir.as_deref()).ok_or_else(|| {
        RuntimeDiagnosticsRepairProjectionCommandError::new(
            "runtime_diagnostics_repair_projection_state_dir_required",
            "diagnostics repair projection requires runtime state_dir for Agentgres event replay",
        )
    })?;
    let events_dir = Path::new(&state_dir).join("events");
    if !events_dir.exists() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(&events_dir).map_err(|error| {
        RuntimeDiagnosticsRepairProjectionCommandError::new(
            "runtime_diagnostics_repair_projection_replay_read_failed",
            format!("diagnostics repair projection could not read Agentgres events: {error}"),
        )
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            RuntimeDiagnosticsRepairProjectionCommandError::new(
                "runtime_diagnostics_repair_projection_replay_read_failed",
                format!(
                    "diagnostics repair projection could not inspect Agentgres event entry: {error}"
                ),
            )
        })?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|value| value.to_str()) == Some("jsonl") {
            paths.push(path);
        }
    }
    paths.sort();

    let mut candidates = Vec::new();
    for path in paths {
        let contents = fs::read_to_string(&path).map_err(|error| {
            RuntimeDiagnosticsRepairProjectionCommandError::new(
                "runtime_diagnostics_repair_projection_replay_read_failed",
                format!(
                    "diagnostics repair projection could not read Agentgres event record {}: {error}",
                    path.display()
                ),
            )
        })?;
        for (index, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let event: Value = serde_json::from_str(line).map_err(|error| {
                RuntimeDiagnosticsRepairProjectionCommandError::new(
                    "runtime_diagnostics_repair_projection_replay_record_invalid",
                    format!(
                        "diagnostics repair projection found invalid Agentgres event record {}:{}: {error}",
                        path.display(),
                        index + 1
                    ),
                )
            })?;
            if event_thread_id(&event).as_deref() == Some(thread_id) {
                candidates.extend(decision_candidates_from_event(&event, thread_id));
            }
        }
    }
    Ok(candidates)
}

fn decision_candidates_from_event(event: &Value, thread_id: &str) -> Vec<Value> {
    let payload = event_payload(event);
    let gate_id = string_field(&payload, "gate_id").or_else(|| string_field(event, "gate_id"));
    let event_receipt_refs = unique_strings(
        string_array_field(event, "receipt_refs")
            .into_iter()
            .chain(string_array_field(&payload, "receipt_refs"))
            .collect(),
    );
    let event_policy_decision_refs = unique_strings(
        string_array_field(event, "policy_decision_refs")
            .into_iter()
            .chain(string_array_field(&payload, "policy_decision_refs"))
            .collect(),
    );
    let mut candidates = Vec::new();
    for decision in repair_decision_values(&payload)
        .into_iter()
        .chain(repair_decision_values(event))
    {
        candidates.push(enrich_decision_candidate(
            decision,
            thread_id,
            gate_id.clone(),
            &event_receipt_refs,
            &event_policy_decision_refs,
        ));
    }
    if let Some(decision_id) = string_field(&payload, "decision_id") {
        let action =
            string_field(&payload, "action").or_else(|| string_field(&payload, "repair_action"));
        candidates.push(enrich_decision_candidate(
            json!({
                "decision_id": decision_id,
                "gate_id": gate_id,
                "action": action,
                "status": string_field(event, "status").unwrap_or_else(|| "accepted".to_string()),
                "receipt_refs": event_receipt_refs,
                "policy_decision_refs": event_policy_decision_refs,
            }),
            thread_id,
            None,
            &[],
            &[],
        ));
    }
    candidates
}

fn event_payload(event: &Value) -> Value {
    event
        .get("payload")
        .filter(|value| value.is_object())
        .or_else(|| {
            event
                .get("payload_summary")
                .filter(|value| value.is_object())
        })
        .cloned()
        .unwrap_or_else(|| json!({}))
}

fn event_thread_id(event: &Value) -> Option<String> {
    string_field(event, "thread_id").or_else(|| string_field(&event_payload(event), "thread_id"))
}

fn repair_decision_values(value: &Value) -> Vec<Value> {
    value
        .get("repair_decisions")
        .and_then(Value::as_array)
        .map(|records| {
            records
                .iter()
                .filter(|record| record.as_object().is_some())
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn enrich_decision_candidate(
    mut decision: Value,
    thread_id: &str,
    gate_id: Option<String>,
    receipt_refs: &[String],
    policy_decision_refs: &[String],
) -> Value {
    if let Some(object) = decision.as_object_mut() {
        object
            .entry("thread_id".to_string())
            .or_insert_with(|| Value::String(thread_id.to_string()));
        if let Some(gate_id) = gate_id {
            object
                .entry("gate_id".to_string())
                .or_insert_with(|| Value::String(gate_id));
        }
        if !receipt_refs.is_empty() && !object.contains_key("receipt_refs") {
            object.insert(
                "receipt_refs".to_string(),
                Value::Array(receipt_refs.iter().cloned().map(Value::String).collect()),
            );
        }
        if !policy_decision_refs.is_empty() && !object.contains_key("policy_decision_refs") {
            object.insert(
                "policy_decision_refs".to_string(),
                Value::Array(
                    policy_decision_refs
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
    }
    decision
}

fn projected_decision_record(
    record: Value,
    request: &RuntimeDiagnosticsRepairProjectionRequest,
    thread_id: &str,
    decision_id: &str,
) -> Value {
    let mut projected = record;
    let gate_id = string_field(&projected, "gate_id")
        .or_else(|| optional_trimmed(request.gate_id.as_deref()));
    let status = string_field(&projected, "status").unwrap_or_else(|| "accepted".to_string());
    let action =
        string_field(&projected, "action").or_else(|| string_field(&projected, "repair_action"));
    if let Some(object) = projected.as_object_mut() {
        object
            .entry("schema_version".to_string())
            .or_insert_with(|| {
                Value::String(RUNTIME_DIAGNOSTICS_REPAIR_DECISION_SCHEMA_VERSION.to_string())
            });
        object.entry("object".to_string()).or_insert_with(|| {
            Value::String("ioi.runtime_diagnostics_repair_decision".to_string())
        });
        object.insert(
            "thread_id".to_string(),
            Value::String(thread_id.to_string()),
        );
        object.insert(
            "decision_id".to_string(),
            Value::String(decision_id.to_string()),
        );
        object.insert("status".to_string(), Value::String(status));
        object.insert(
            "gate_id".to_string(),
            gate_id.map(Value::String).unwrap_or(Value::Null),
        );
        object.insert(
            "action".to_string(),
            action.map(Value::String).unwrap_or(Value::Null),
        );
    }
    projected
}

fn matches_thread(record: &Value, thread_id: &str) -> bool {
    string_field(record, "thread_id")
        .map(|value| value == thread_id)
        .unwrap_or(false)
}

fn matches_decision_id(record: &Value, decision_id: &str) -> bool {
    string_field(record, "decision_id")
        .or_else(|| string_field(record, "id"))
        .map(|value| value == decision_id)
        .unwrap_or(false)
}

fn matches_gate_id(record: &Value, gate_id: Option<&str>) -> bool {
    let Some(gate_id) = optional_trimmed(gate_id) else {
        return true;
    };
    string_field(record, "gate_id")
        .map(|value| value == gate_id)
        .unwrap_or(false)
}

fn record_count_for_projection(projection: &Value) -> usize {
    match projection {
        Value::Array(values) => values.len(),
        Value::Object(_) => 1,
        Value::Null => 0,
        _ => 0,
    }
}

fn string_field(record: &Value, key: &str) -> Option<String> {
    optional_trimmed(record.get(key)?.as_str())
}

fn string_array_field(record: &Value, key: &str) -> Vec<String> {
    record
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| optional_trimmed(value.as_str()))
                .collect()
        })
        .unwrap_or_default()
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for value in values {
        if !value.is_empty() && !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn optional_trimmed_lower(value: Option<&str>) -> Option<String> {
    optional_trimmed(value).map(|value| value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    fn write_runtime_event(state_dir: &Path, event: Value) {
        let event_dir = state_dir.join("events");
        fs::create_dir_all(&event_dir).expect("event dir");
        fs::write(
            event_dir.join("thread_alpha.jsonl"),
            format!("{}\n", serde_json::to_string(&event).expect("event json")),
        )
        .expect("write event");
    }

    fn blocking_gate_event() -> Value {
        json!({
            "event_id": "event_gate_alpha",
            "event_stream_id": "thread_alpha:events",
            "thread_id": "thread_alpha",
            "event_kind": "LspDiagnosticsBlockingGate",
            "component_kind": "lsp_diagnostics_gate",
            "seq": 3,
            "receipt_refs": ["receipt_gate_alpha"],
            "policy_decision_refs": ["policy_decision_alpha"],
            "payload": {
                "gate_id": "gate_alpha",
                "repair_decisions": [
                    {
                        "decision_id": "decision_alpha",
                        "action": "restore_apply",
                        "status": "accepted"
                    },
                    {
                        "decision_id": "decision_retry",
                        "action": "repair_retry",
                        "status": "available"
                    }
                ]
            }
        })
    }

    #[test]
    fn rust_replays_runtime_diagnostics_repair_decision_projection_from_state_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_runtime_event(temp.path(), blocking_gate_event());
        let record = RuntimeDiagnosticsRepairProjectionCore
            .project(&RuntimeDiagnosticsRepairProjectionRequest {
                schema_version: Some(
                    RUNTIME_DIAGNOSTICS_REPAIR_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
                ),
                projection_kind: Some("decision".to_string()),
                thread_id: Some("thread_alpha".to_string()),
                decision_id: Some("decision_alpha".to_string()),
                gate_id: Some("gate_alpha".to_string()),
                state_dir: Some(temp.path().to_string_lossy().to_string()),
                ..Default::default()
            })
            .expect("diagnostics repair decision projection");

        assert_eq!(record.projection_kind, "decision");
        assert_eq!(record.record_count, 1);
        assert_eq!(record.projection["decision_id"], "decision_alpha");
        assert_eq!(record.projection["thread_id"], "thread_alpha");
        assert_eq!(
            record.projection["object"],
            "ioi.runtime_diagnostics_repair_decision"
        );
        assert!(record
            .evidence_refs
            .contains(&"runtime_diagnostics_repair_decision_projection_rust_owned".to_string()));
        assert_eq!(
            record.receipt_refs,
            vec![
                "receipt_gate_alpha".to_string(),
                "receipt_runtime_diagnostics_repair_projection_decision".to_string()
            ]
        );
    }

    #[test]
    fn rust_shapes_runtime_diagnostics_repair_projection_command_response() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_runtime_event(temp.path(), blocking_gate_event());
        let response = project_runtime_diagnostics_repair_projection_response(
            RuntimeDiagnosticsRepairProjectionRequest {
                operation_kind: Some("runtime.diagnostics_repair_projection.decision".to_string()),
                projection_kind: Some("decision".to_string()),
                thread_id: Some("thread_alpha".to_string()),
                decision_id: Some("decision_alpha".to_string()),
                gate_id: Some("gate_alpha".to_string()),
                state_dir: Some(temp.path().to_string_lossy().to_string()),
                ..Default::default()
            },
        )
        .expect("command response");

        assert_eq!(
            response["source"],
            "rust_runtime_diagnostics_repair_projection_command"
        );
        assert_eq!(
            response["record"]["schema_version"],
            RUNTIME_DIAGNOSTICS_REPAIR_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(response["record"]["projection_kind"], "decision");
        assert_eq!(
            response["record"]["projection"]["decision_id"],
            "decision_alpha"
        );
    }

    #[test]
    fn rust_rejects_runtime_diagnostics_repair_projection_without_decision_id() {
        let error = RuntimeDiagnosticsRepairProjectionCore
            .project(&RuntimeDiagnosticsRepairProjectionRequest {
                projection_kind: Some("decision".to_string()),
                thread_id: Some("thread_alpha".to_string()),
                state_dir: Some("/tmp/runtime-state".to_string()),
                ..Default::default()
            })
            .expect_err("missing decision_id must fail closed");

        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_projection_decision_id_required"
        );
    }

    #[test]
    fn rust_rejects_runtime_diagnostics_repair_projection_candidate_transport() {
        let request: RuntimeDiagnosticsRepairProjectionRequest = serde_json::from_value(json!({
            "projection_kind": "decision",
            "thread_id": "thread_alpha",
            "decision_id": "decision_alpha",
            "projection": { "decisions": [] }
        }))
        .expect("request");

        let error = RuntimeDiagnosticsRepairProjectionCore
            .project(&request)
            .expect_err("candidate transport should fail");

        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_projection_candidate_transport_retired"
        );
    }

    #[test]
    fn rust_rejects_runtime_diagnostics_repair_projection_without_state_dir() {
        let error = RuntimeDiagnosticsRepairProjectionCore
            .project(&RuntimeDiagnosticsRepairProjectionRequest {
                projection_kind: Some("decision".to_string()),
                thread_id: Some("thread_alpha".to_string()),
                decision_id: Some("decision_alpha".to_string()),
                ..Default::default()
            })
            .expect_err("missing state_dir must fail closed");

        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_projection_state_dir_required"
        );
    }

    #[test]
    fn rust_rejects_unowned_runtime_diagnostics_repair_projection_kind() {
        let error = RuntimeDiagnosticsRepairProjectionCore
            .project(&RuntimeDiagnosticsRepairProjectionRequest {
                projection_kind: Some("legacy".to_string()),
                thread_id: Some("thread_alpha".to_string()),
                decision_id: Some("decision_alpha".to_string()),
                state_dir: Some("/tmp/runtime-state".to_string()),
                ..Default::default()
            })
            .expect_err("unsupported projection kind must fail closed");

        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_projection_kind_invalid"
        );
    }
}
