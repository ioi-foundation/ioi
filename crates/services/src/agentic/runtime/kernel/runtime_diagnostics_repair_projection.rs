use serde::Deserialize;
use serde_json::{json, Value};

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
    pub projection: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
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
        "decision" => Ok(decision_candidates(&request.projection)
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

fn decision_candidates(projection: &Value) -> Vec<Value> {
    if let Some(records) = projection.as_array() {
        return records.clone();
    }
    if let Some(record) = projection.get("decision").filter(|value| value.is_object()) {
        return vec![record.clone()];
    }
    for key in ["decisions", "repair_decisions"] {
        if let Some(records) = projection.get(key).and_then(Value::as_array) {
            return records.clone();
        }
    }
    if projection.get("decision_id").is_some() || projection.get("id").is_some() {
        return vec![projection.clone()];
    }
    Vec::new()
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

    fn projection_candidates() -> Value {
        json!({
            "decisions": [
                {
                    "decision_id": "decision_other",
                    "thread_id": "thread_other",
                    "gate_id": "gate_alpha",
                    "action": "repair_retry",
                    "status": "accepted"
                },
                {
                    "decision_id": "decision_alpha",
                    "thread_id": "thread_alpha",
                    "gate_id": "gate_alpha",
                    "action": "restore_apply",
                    "status": "accepted",
                    "receipt_refs": ["receipt_decision_alpha"],
                    "policy_decision_refs": ["policy_decision_alpha"]
                }
            ]
        })
    }

    #[test]
    fn rust_projects_runtime_diagnostics_repair_decision_projection() {
        let record = RuntimeDiagnosticsRepairProjectionCore
            .project(&RuntimeDiagnosticsRepairProjectionRequest {
                schema_version: Some(
                    RUNTIME_DIAGNOSTICS_REPAIR_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
                ),
                projection_kind: Some("decision".to_string()),
                thread_id: Some("thread_alpha".to_string()),
                decision_id: Some("decision_alpha".to_string()),
                gate_id: Some("gate_alpha".to_string()),
                projection: projection_candidates(),
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
                "receipt_decision_alpha".to_string(),
                "receipt_runtime_diagnostics_repair_projection_decision".to_string()
            ]
        );
    }

    #[test]
    fn rust_shapes_runtime_diagnostics_repair_projection_command_response() {
        let response = project_runtime_diagnostics_repair_projection_response(
            RuntimeDiagnosticsRepairProjectionRequest {
                operation_kind: Some("runtime.diagnostics_repair_projection.decision".to_string()),
                projection_kind: Some("decision".to_string()),
                thread_id: Some("thread_alpha".to_string()),
                decision_id: Some("decision_alpha".to_string()),
                gate_id: Some("gate_alpha".to_string()),
                projection: projection_candidates(),
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
                projection: projection_candidates(),
                ..Default::default()
            })
            .expect_err("missing decision_id must fail closed");

        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_projection_decision_id_required"
        );
    }

    #[test]
    fn rust_rejects_unowned_runtime_diagnostics_repair_projection_kind() {
        let error = RuntimeDiagnosticsRepairProjectionCore
            .project(&RuntimeDiagnosticsRepairProjectionRequest {
                projection_kind: Some("legacy".to_string()),
                thread_id: Some("thread_alpha".to_string()),
                decision_id: Some("decision_alpha".to_string()),
                projection: projection_candidates(),
                ..Default::default()
            })
            .expect_err("unsupported projection kind must fail closed");

        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_projection_kind_invalid"
        );
    }
}
