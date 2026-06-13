use serde::Deserialize;
use serde_json::{json, Value};

pub const RUNTIME_SUBAGENT_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.subagent-projection-request.v1";
pub const RUNTIME_SUBAGENT_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.subagent_projection.v1";
const RUNTIME_SUBAGENT_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.subagent-result.v1";
const RUNTIME_SUBAGENT_OUTPUT_CONTRACT_SCHEMA_VERSION: &str = "ioi.runtime.subagent-result.v1";
const DEFAULT_OUTPUT_SECTIONS: [&str; 6] = [
    "SUMMARY", "CHANGES", "EVIDENCE", "RISKS", "BLOCKERS", "RECEIPTS",
];

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeSubagentProjectionRequest {
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub projection_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub subagent_id: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub projection: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSubagentProjectionCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeSubagentProjectionCommandError {
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
pub struct RuntimeSubagentProjectionCore;

#[derive(Debug, Clone)]
pub struct RuntimeSubagentProjectionRecord {
    pub operation: String,
    pub operation_kind: String,
    pub projection_kind: String,
    pub thread_id: Option<String>,
    pub subagent_id: Option<String>,
    pub role: Option<String>,
    pub source: String,
    pub projection: Value,
    pub record_count: usize,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
}

pub fn project_runtime_subagent_projection_response(
    request: RuntimeSubagentProjectionRequest,
) -> Result<Value, RuntimeSubagentProjectionCommandError> {
    let record = RuntimeSubagentProjectionCore::default().project(&request)?;
    Ok(json!({
        "source": "rust_runtime_subagent_projection_command",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

impl RuntimeSubagentProjectionCore {
    pub fn project(
        &self,
        request: &RuntimeSubagentProjectionRequest,
    ) -> Result<RuntimeSubagentProjectionRecord, RuntimeSubagentProjectionCommandError> {
        let projection_kind = normalized_projection_kind(request)?;
        let projection = projection_for_kind(&projection_kind, request)?;
        let record_count = record_count_for_projection(&projection);
        let operation = request
            .operation
            .clone()
            .unwrap_or_else(|| "runtime_subagent_projection".to_string());
        let operation_kind = request
            .operation_kind
            .clone()
            .unwrap_or_else(|| format!("runtime.subagent_projection.{projection_kind}"));
        let source = optional_trimmed(request.source.as_deref())
            .unwrap_or_else(|| "runtime.subagent_projection.rust_command".to_string());
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_subagent_read_projection_rust_owned".to_string(),
                "agentgres_runtime_subagent_projection_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };

        Ok(RuntimeSubagentProjectionRecord {
            operation,
            operation_kind,
            projection_kind: projection_kind.clone(),
            thread_id: optional_trimmed(request.thread_id.as_deref()),
            subagent_id: optional_trimmed(request.subagent_id.as_deref()),
            role: optional_trimmed(request.role.as_deref()),
            source,
            projection,
            record_count,
            evidence_refs,
            receipt_refs: vec![format!(
                "receipt_runtime_subagent_projection_{projection_kind}"
            )],
        })
    }
}

impl RuntimeSubagentProjectionRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_SUBAGENT_PROJECTION_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_subagent_projection",
            "status": "projected",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "projection_kind": self.projection_kind,
            "thread_id": self.thread_id,
            "subagent_id": self.subagent_id,
            "role": self.role,
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
    request: &RuntimeSubagentProjectionRequest,
) -> Result<Value, RuntimeSubagentProjectionCommandError> {
    match projection_kind {
        "list" => {
            let mut records: Vec<Value> = subagent_candidates(&request.projection)
                .into_iter()
                .filter(|record| matches_thread(record, request.thread_id.as_deref()))
                .filter(|record| matches_role(record, request.role.as_deref()))
                .map(projected_subagent_record)
                .collect();
            records.sort_by(|left, right| created_at(right).cmp(&created_at(left)));
            Ok(Value::Array(records))
        }
        "get" => {
            let subagent_id =
                optional_trimmed(request.subagent_id.as_deref()).ok_or_else(|| {
                    RuntimeSubagentProjectionCommandError::new(
                        "runtime_subagent_projection_subagent_id_required",
                        "subagent get projection requires subagent_id",
                    )
                })?;
            Ok(subagent_candidates(&request.projection)
                .into_iter()
                .find(|record| {
                    matches_subagent_id(record, &subagent_id)
                        && matches_thread(record, request.thread_id.as_deref())
                })
                .map(projected_subagent_record)
                .unwrap_or(Value::Null))
        }
        "result" => {
            let subagent_id =
                optional_trimmed(request.subagent_id.as_deref()).ok_or_else(|| {
                    RuntimeSubagentProjectionCommandError::new(
                        "runtime_subagent_projection_subagent_id_required",
                        "subagent result projection requires subagent_id",
                    )
                })?;
            let subagent = subagent_candidates(&request.projection)
                .into_iter()
                .find(|record| {
                    matches_subagent_id(record, &subagent_id)
                        && matches_thread(record, request.thread_id.as_deref())
                });
            let Some(record) = subagent else {
                return Ok(Value::Null);
            };
            let run_id = string_field(&record, "run_id");
            let run = run_id
                .as_deref()
                .and_then(|id| {
                    run_candidates(&request.projection)
                        .into_iter()
                        .find(|run| matches_run_id(run, id))
                })
                .unwrap_or(Value::Null);
            Ok(projected_subagent_result(&record, &run))
        }
        _ => Err(RuntimeSubagentProjectionCommandError::new(
            "runtime_subagent_projection_kind_invalid",
            format!("unsupported runtime subagent projection kind {projection_kind}"),
        )),
    }
}

fn normalized_projection_kind(
    request: &RuntimeSubagentProjectionRequest,
) -> Result<String, RuntimeSubagentProjectionCommandError> {
    if let Some(value) = optional_trimmed_lower(request.projection_kind.as_deref()) {
        return Ok(value);
    }
    let operation_kind = optional_trimmed(request.operation_kind.as_deref()).unwrap_or_default();
    if let Some(last) = operation_kind.split('.').next_back() {
        if !last.is_empty() {
            return Ok(last.to_string());
        }
    }
    Err(RuntimeSubagentProjectionCommandError::new(
        "runtime_subagent_projection_kind_required",
        "runtime subagent projection kind is required",
    ))
}

fn subagent_candidates(projection: &Value) -> Vec<Value> {
    projection
        .get("subagents")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn run_candidates(projection: &Value) -> Vec<Value> {
    projection
        .get("runs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn projected_subagent_record(record: Value) -> Value {
    let mut projected = record;
    let output_contract_status = projected
        .get("output_contract_status")
        .cloned()
        .or_else(|| {
            projected
                .get("output_contract_validation")
                .and_then(|value| value.get("status"))
                .cloned()
        })
        .unwrap_or(Value::Null);
    if let Some(object) = projected.as_object_mut() {
        object
            .entry("schema_version")
            .or_insert_with(|| Value::String("ioi.runtime.subagent-manager.v1".to_string()));
        object
            .entry("object")
            .or_insert_with(|| Value::String("ioi.runtime_subagent".to_string()));
        object.insert("output_contract_status".to_string(), output_contract_status);
    }
    projected
}

fn projected_subagent_result(record: &Value, run: &Value) -> Value {
    let lifecycle_status = string_field(record, "lifecycle_status")
        .or_else(|| string_field(record, "status"))
        .or_else(|| string_field(run, "status"));
    let result_text = string_field(run, "result").unwrap_or_default();
    let receipt_refs = unique_strings(
        string_array_field(record, "receipt_refs")
            .into_iter()
            .chain(run_receipt_ids(run))
            .collect(),
    );
    json!({
        "schema_version": RUNTIME_SUBAGENT_RESULT_SCHEMA_VERSION,
        "object": "ioi.runtime_subagent_result",
        "subagent_id": string_field(record, "subagent_id"),
        "agent_id": string_field(record, "agent_id"),
        "run_id": string_field(run, "id").or_else(|| string_field(record, "run_id")),
        "status": lifecycle_status,
        "lifecycle_status": lifecycle_status,
        "result": result_text,
        "output": subagent_output_contract(run, &result_text, &receipt_refs),
        "output_contract_status": string_field(record, "output_contract_status"),
        "budget_status": record.get("budget_status").cloned().unwrap_or(Value::Null),
        "usage_telemetry": record.get("usage_telemetry").cloned().unwrap_or(Value::Null),
        "receipt_refs": receipt_refs,
    })
}

fn subagent_output_contract(run: &Value, result_text: &str, receipt_refs: &[String]) -> Value {
    json!({
        "schema_version": RUNTIME_SUBAGENT_OUTPUT_CONTRACT_SCHEMA_VERSION,
        "object": "ioi.runtime_subagent_output_contract",
        "required_sections": DEFAULT_OUTPUT_SECTIONS,
        "sections": {
            "SUMMARY": result_text,
            "CHANGES": trace_task_state_array(run, "changedObjects", "changed_objects"),
            "EVIDENCE": unique_strings(
                trace_task_state_array(run, "evidenceRefs", "evidence_refs")
                    .into_iter()
                    .chain(receipt_refs.iter().cloned())
                    .collect(),
            ),
            "RISKS": trace_task_state_array(run, "uncertainFacts", "uncertain_facts"),
            "BLOCKERS": trace_task_state_array(run, "blockers", "blockers"),
            "RECEIPTS": receipt_refs,
        },
        "text": result_text,
    })
}

fn matches_thread(record: &Value, thread_id: Option<&str>) -> bool {
    let Some(thread_id) = optional_trimmed(thread_id) else {
        return true;
    };
    string_field(record, "parent_thread_id")
        .map(|value| value == thread_id)
        .unwrap_or(false)
}

fn matches_role(record: &Value, role: Option<&str>) -> bool {
    let Some(role) = optional_trimmed_lower(role) else {
        return true;
    };
    string_field(record, "role")
        .map(|value| value.to_ascii_lowercase() == role)
        .unwrap_or(false)
}

fn matches_subagent_id(record: &Value, subagent_id: &str) -> bool {
    string_field(record, "subagent_id")
        .map(|value| value == subagent_id)
        .unwrap_or(false)
}

fn matches_run_id(run: &Value, run_id: &str) -> bool {
    string_field(run, "id")
        .map(|value| value == run_id)
        .unwrap_or(false)
}

fn created_at(record: &Value) -> String {
    string_field(record, "created_at").unwrap_or_default()
}

fn string_field(record: &Value, key: &str) -> Option<String> {
    record.get(key).and_then(Value::as_str).map(str::to_string)
}

fn string_array_field(record: &Value, key: &str) -> Vec<String> {
    record
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn run_receipt_ids(run: &Value) -> Vec<String> {
    run.get("receipts")
        .and_then(Value::as_array)
        .map(|receipts| {
            receipts
                .iter()
                .filter_map(|receipt| receipt.get("id").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn trace_task_state_array(run: &Value, camel_key: &str, snake_key: &str) -> Vec<String> {
    let task_state = run
        .get("trace")
        .and_then(|trace| trace.get("taskState").or_else(|| trace.get("task_state")));
    task_state
        .and_then(|state| state.get(snake_key).or_else(|| state.get(camel_key)))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
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

fn record_count_for_projection(projection: &Value) -> usize {
    match projection {
        Value::Array(values) => values.len(),
        Value::Null => 0,
        Value::Object(_) => 1,
        _ => 0,
    }
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
            "subagents": [
                {
                    "subagent_id": "subagent_old",
                    "agent_id": "agent_old",
                    "run_id": "run_old",
                    "parent_thread_id": "thread_1",
                    "role": "reviewer",
                    "lifecycle_status": "completed",
                    "created_at": "2026-06-04T12:00:01.000Z"
                },
                {
                    "subagent_id": "subagent_other",
                    "parent_thread_id": "thread_2",
                    "role": "reviewer",
                    "lifecycle_status": "running",
                    "created_at": "2026-06-04T12:00:03.000Z"
                },
                {
                    "subagent_id": "subagent_new",
                    "agent_id": "agent_new",
                    "run_id": "run_new",
                    "parent_thread_id": "thread_1",
                    "role": "reviewer",
                    "lifecycle_status": "completed",
                    "output_contract_status": "passed",
                    "receipt_refs": ["receipt_record_new"],
                    "created_at": "2026-06-04T12:00:02.000Z"
                }
            ],
            "runs": [
                {
                    "id": "run_new",
                    "status": "completed",
                    "result": "Subagent completed.",
                    "receipts": [{ "id": "receipt_run_new" }],
                    "trace": {
                        "taskState": {
                            "changedObjects": ["file-a"],
                            "evidenceRefs": ["evidence-run-new"],
                            "uncertainFacts": [],
                            "blockers": []
                        }
                    }
                }
            ]
        })
    }

    #[test]
    fn rust_projects_subagent_list_get_and_result() {
        let list = RuntimeSubagentProjectionCore
            .project(&RuntimeSubagentProjectionRequest {
                projection_kind: Some("list".to_string()),
                thread_id: Some("thread_1".to_string()),
                role: Some("reviewer".to_string()),
                projection: projection_candidates(),
                ..Default::default()
            })
            .expect("list projection");
        assert_eq!(list.projection_kind, "list");
        assert_eq!(list.record_count, 2);
        assert_eq!(list.projection[0]["subagent_id"], "subagent_new");
        assert_eq!(list.projection[0]["object"], "ioi.runtime_subagent");

        let get = RuntimeSubagentProjectionCore
            .project(&RuntimeSubagentProjectionRequest {
                projection_kind: Some("get".to_string()),
                thread_id: Some("thread_1".to_string()),
                subagent_id: Some("subagent_old".to_string()),
                projection: projection_candidates(),
                ..Default::default()
            })
            .expect("get projection");
        assert_eq!(get.record_count, 1);
        assert_eq!(get.projection["subagent_id"], "subagent_old");

        let result = RuntimeSubagentProjectionCore
            .project(&RuntimeSubagentProjectionRequest {
                projection_kind: Some("result".to_string()),
                thread_id: Some("thread_1".to_string()),
                subagent_id: Some("subagent_new".to_string()),
                projection: projection_candidates(),
                ..Default::default()
            })
            .expect("result projection");
        assert_eq!(result.record_count, 1);
        assert_eq!(result.projection["object"], "ioi.runtime_subagent_result");
        assert_eq!(result.projection["result"], "Subagent completed.");
        assert_eq!(
            result.projection["receipt_refs"],
            json!(["receipt_record_new", "receipt_run_new"])
        );
        assert_eq!(
            result.projection["output"]["sections"]["EVIDENCE"],
            json!(["evidence-run-new", "receipt_record_new", "receipt_run_new"])
        );
    }

    #[test]
    fn rust_shapes_subagent_projection_command_response() {
        let response =
            project_runtime_subagent_projection_response(RuntimeSubagentProjectionRequest {
                operation_kind: Some("runtime.subagent_projection.get".to_string()),
                projection_kind: Some("get".to_string()),
                thread_id: Some("thread_1".to_string()),
                subagent_id: Some("subagent_new".to_string()),
                projection: projection_candidates(),
                ..Default::default()
            })
            .expect("command response");

        assert_eq!(
            response["source"],
            "rust_runtime_subagent_projection_command"
        );
        assert_eq!(
            response["record"]["schema_version"],
            RUNTIME_SUBAGENT_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(response["record"]["projection_kind"], "get");
        assert_eq!(
            response["record"]["projection"]["subagent_id"],
            "subagent_new"
        );
    }

    #[test]
    fn rust_rejects_unknown_subagent_projection_kind() {
        let error = RuntimeSubagentProjectionCore
            .project(&RuntimeSubagentProjectionRequest {
                projection_kind: Some("legacy".to_string()),
                ..Default::default()
            })
            .expect_err("unsupported projection kind must fail");

        assert_eq!(error.code(), "runtime_subagent_projection_kind_invalid");
    }
}
