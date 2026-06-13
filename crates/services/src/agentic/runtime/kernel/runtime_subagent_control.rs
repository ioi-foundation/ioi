use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const RUNTIME_SUBAGENT_CONTROL_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.subagent-control-request.v1";
pub const RUNTIME_SUBAGENT_CONTROL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.subagent_control.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeSubagentControlRequest {
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub event_stream_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub event_seed: Option<String>,
    #[serde(default)]
    pub parent_agent: Value,
    #[serde(default)]
    pub thread: Value,
    #[serde(default)]
    pub subagent: Value,
    #[serde(default)]
    pub request: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSubagentControlCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeSubagentControlCommandError {
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
pub struct RuntimeSubagentControlCore;

#[derive(Debug, Clone)]
pub struct RuntimeSubagentControlRecord {
    pub operation: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub subagent_id: String,
    pub status: String,
    pub event: Value,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
}

pub fn plan_runtime_subagent_control_response(
    request: RuntimeSubagentControlRequest,
) -> Result<Value, RuntimeSubagentControlCommandError> {
    let record = RuntimeSubagentControlCore::default().plan(&request)?;
    Ok(json!({
        "source": "rust_runtime_subagent_control_command",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

impl RuntimeSubagentControlCore {
    pub fn plan(
        &self,
        request: &RuntimeSubagentControlRequest,
    ) -> Result<RuntimeSubagentControlRecord, RuntimeSubagentControlCommandError> {
        let operation_kind = optional_trimmed(request.operation_kind.as_deref())
            .unwrap_or_else(|| "subagent.wait".to_string());
        if !matches!(
            operation_kind.as_str(),
            "subagent.wait"
                | "subagent.spawn"
                | "subagent.input"
                | "subagent.resume"
                | "subagent.assign"
                | "subagent.cancel"
                | "subagent.cancel.propagate"
        ) {
            return Err(RuntimeSubagentControlCommandError::new(
                "runtime_subagent_control_operation_kind_unsupported",
                format!("{operation_kind} is not yet Rust-owned"),
            ));
        }
        let operation = optional_trimmed(request.operation.as_deref()).unwrap_or_else(|| {
            operation_kind
                .split('.')
                .next_back()
                .unwrap_or("wait")
                .to_string()
        });
        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeSubagentControlCommandError::new(
                "runtime_subagent_control_thread_id_required",
                "subagent control requires thread_id",
            )
        })?;
        let event_stream_id =
            optional_trimmed(request.event_stream_id.as_deref()).ok_or_else(|| {
                RuntimeSubagentControlCommandError::new(
                    "runtime_subagent_control_event_stream_required",
                    "subagent control requires event_stream_id",
                )
            })?;
        let subagent_id = string_field(&request.subagent, "subagent_id").ok_or_else(|| {
            RuntimeSubagentControlCommandError::new(
                "runtime_subagent_control_subagent_id_required",
                "subagent control requires subagent.subagent_id",
            )
        })?;
        let parent_thread_id =
            string_field(&request.subagent, "parent_thread_id").ok_or_else(|| {
                RuntimeSubagentControlCommandError::new(
                    "runtime_subagent_control_parent_thread_required",
                    "subagent control requires subagent.parent_thread_id",
                )
            })?;
        if parent_thread_id != thread_id {
            return Err(RuntimeSubagentControlCommandError::new(
                "runtime_subagent_control_thread_mismatch",
                format!(
                    "subagent parent_thread_id {parent_thread_id} does not match thread_id {thread_id}"
                ),
            ));
        }
        let status = optional_trimmed(request.status.as_deref())
            .or_else(|| string_field(&request.subagent, "status"))
            .or_else(|| string_field(&request.subagent, "lifecycle_status"))
            .unwrap_or_else(|| "running".to_string());
        let event_seed = optional_trimmed(request.event_seed.as_deref())
            .or_else(|| string_field(&request.subagent, "updated_at"))
            .unwrap_or_else(|| status.clone());
        let event_hash = short_hash(format!(
            "{thread_id}:{operation}:{subagent_id}:{event_seed}"
        ));
        let request_receipt_refs = string_array_field(&request.request, "receipt_refs");
        let request_policy_decision_refs =
            string_array_field(&request.request, "policy_decision_refs");
        let receipt_refs = unique_strings(
            request_receipt_refs
                .into_iter()
                .chain(std::iter::once(format!(
                    "receipt_subagent_{}_{event_hash}",
                    safe_id(&operation)
                )))
                .collect(),
        );
        let policy_decision_refs = subagent_policy_decision_refs(
            &operation,
            &event_hash,
            &request.subagent,
            request_policy_decision_refs,
        );
        let event = json!({
            "event_stream_id": event_stream_id,
            "thread_id": thread_id,
            "turn_id": string_field(&request.subagent, "parent_turn_id")
                .or_else(|| string_field(&request.thread, "latest_turn_id"))
                .unwrap_or_default(),
            "item_id": format!(
                "{}:item:subagent:{}:{}",
                string_field(&request.subagent, "parent_turn_id").unwrap_or_else(|| thread_id.clone()),
                safe_id(&operation),
                safe_id(&subagent_id)
            ),
            "idempotency_key": string_field(&request.request, "idempotency_key")
                .unwrap_or_else(|| format!("thread:{thread_id}:subagent.{operation}:{subagent_id}:{event_hash}")),
            "source": string_field(&request.request, "source").unwrap_or_else(|| "agent_studio".to_string()),
            "source_event_kind": subagent_operator_control_kind(&operation),
            "event_kind": subagent_runtime_event_kind(&operation),
            "status": status,
            "actor": "operator",
            "workspace_root": string_field(&request.parent_agent, "cwd").unwrap_or_default(),
            "workflow_graph_id": string_field(&request.request, "workflow_graph_id")
                .or_else(|| string_field(&request.subagent, "workflow_graph_id")),
            "workflow_node_id": string_field(&request.request, "workflow_node_id")
                .or_else(|| string_field(&request.subagent, "workflow_node_id"))
                .unwrap_or_else(|| format!("runtime.subagent.{operation}")),
            "component_kind": "subagent_lifecycle",
            "payload_schema_version": "ioi.runtime.subagent-manager.v1",
            "payload": subagent_control_payload(&operation, &status, &request.subagent),
            "receipt_refs": receipt_refs,
            "policy_decision_refs": policy_decision_refs,
            "artifact_refs": [],
            "rollback_refs": [],
            "redaction_profile": "internal",
            "fixture_profile": string_field(&request.parent_agent, "fixture_profile")
                .unwrap_or_else(|| "local_daemon_agentgres_projection".to_string()),
        });
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                subagent_control_evidence_ref(&operation_kind).to_string(),
                "runtime_subagent_control_event_rust_owned".to_string(),
                "agentgres_runtime_thread_event_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };

        Ok(RuntimeSubagentControlRecord {
            operation,
            operation_kind,
            thread_id,
            subagent_id,
            status,
            event,
            receipt_refs,
            policy_decision_refs,
            evidence_refs,
        })
    }
}

impl RuntimeSubagentControlRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_SUBAGENT_CONTROL_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_subagent_control",
            "status": "planned",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "thread_id": self.thread_id,
            "subagent_id": self.subagent_id,
            "control_status": self.status,
            "event": self.event,
            "receipt_refs": self.receipt_refs,
            "policy_decision_refs": self.policy_decision_refs,
            "evidence_refs": self.evidence_refs,
        })
    }
}

fn subagent_control_payload(operation: &str, status: &str, subagent: &Value) -> Value {
    let mut payload = json!({
        "operation": operation,
        "status": status,
        "subagent_id": string_field(subagent, "subagent_id"),
        "agent_id": string_field(subagent, "agent_id"),
        "run_id": string_field(subagent, "run_id"),
        "parent_thread_id": string_field(subagent, "parent_thread_id"),
        "parent_turn_id": string_field(subagent, "parent_turn_id"),
        "role": string_field(subagent, "role"),
        "lifecycle_status": string_field(subagent, "lifecycle_status")
            .or_else(|| string_field(subagent, "status")),
        "budget_status": string_field(subagent, "budget_status"),
        "output_contract_status": string_field(subagent, "output_contract_status"),
        "waited_at": string_field(subagent, "waited_at"),
        "input_id": string_field(subagent, "input_id"),
        "input_count": number_field(subagent, "input_count"),
        "last_input": string_field(subagent, "last_input"),
        "last_input_at": string_field(subagent, "last_input_at"),
        "previous_run_id": string_field(subagent, "previous_run_id"),
        "resume_id": string_field(subagent, "resume_id"),
        "restart_count": number_field(subagent, "restart_count"),
        "resumed_at": string_field(subagent, "resumed_at"),
        "cancellation_cleared_at": string_field(subagent, "cancellation_cleared_at"),
        "assignment_id": string_field(subagent, "assignment_id"),
        "assignment_count": number_field(subagent, "assignment_count"),
        "assigned_at": string_field(subagent, "assigned_at"),
        "target_agent_id": string_field(subagent, "target_agent_id"),
        "tool_pack": string_field(subagent, "tool_pack"),
        "model_route_id": string_field(subagent, "model_route_id"),
        "merge_policy": string_field(subagent, "merge_policy"),
        "cancellation_inheritance": string_field(subagent, "cancellation_inheritance"),
        "cancellation_reason": string_field(subagent, "cancellation_reason"),
        "cancellation_inherited": bool_field(subagent, "cancellation_inherited"),
        "propagated_from_thread_id": string_field(subagent, "propagated_from_thread_id"),
        "canceled_at": string_field(subagent, "canceled_at"),
    });
    if let Some(map) = payload.as_object_mut() {
        map.insert(
            "child_thread_id".to_string(),
            json!(string_field(subagent, "child_thread_id")),
        );
        map.insert(
            "parent_agent_id".to_string(),
            json!(string_field(subagent, "parent_agent_id")),
        );
        map.insert(
            "workflow_graph_id".to_string(),
            json!(string_field(subagent, "workflow_graph_id")),
        );
        map.insert(
            "workflow_node_id".to_string(),
            json!(string_field(subagent, "workflow_node_id")),
        );
        map.insert(
            "restart_status".to_string(),
            json!(string_field(subagent, "restart_status")),
        );
        map.insert(
            "fork_context".to_string(),
            json!(bool_field(subagent, "fork_context")),
        );
        map.insert(
            "context_mode".to_string(),
            json!(string_field(subagent, "context_mode")),
        );
        map.insert(
            "source_event_id".to_string(),
            json!(string_field(subagent, "source_event_id")),
        );
        map.insert(
            "source_receipt_refs".to_string(),
            json!(string_array_field(subagent, "source_receipt_refs")),
        );
        map.insert(
            "source_policy_decision_refs".to_string(),
            json!(string_array_field(subagent, "source_policy_decision_refs")),
        );
        map.insert(
            "created_at".to_string(),
            json!(string_field(subagent, "created_at")),
        );
    }
    payload
}

fn subagent_policy_decision_refs(
    operation: &str,
    event_hash: &str,
    subagent: &Value,
    request_refs: Vec<String>,
) -> Vec<String> {
    let budget_policy_decision_id = subagent
        .get("budget_policy_decision")
        .and_then(|value| string_field(value, "id"));
    let default_policy = if string_field(subagent, "budget_status").as_deref() == Some("exceeded") {
        budget_policy_decision_id
    } else {
        Some(format!(
            "policy_subagent_{}_allow_{event_hash}",
            safe_id(operation)
        ))
    };
    unique_strings(request_refs.into_iter().chain(default_policy).collect())
}

fn subagent_operator_control_kind(operation: &str) -> &'static str {
    match operation {
        "spawn" => "OperatorControl.SubagentSpawn",
        "wait" => "OperatorControl.SubagentWait",
        "input" => "OperatorControl.SubagentSendInput",
        "send_input" => "OperatorControl.SubagentSendInput",
        "cancel" => "OperatorControl.SubagentCancel",
        "resume" => "OperatorControl.SubagentResume",
        "assign" => "OperatorControl.SubagentAssign",
        _ => "OperatorControl.SubagentList",
    }
}

fn subagent_runtime_event_kind(operation: &str) -> &'static str {
    match operation {
        "spawn" => "subagent.spawned",
        "wait" => "subagent.wait_completed",
        "input" => "subagent.input_sent",
        "send_input" => "subagent.input_sent",
        "cancel" => "subagent.canceled",
        "resume" => "subagent.resumed",
        "assign" => "subagent.assigned",
        _ => "subagent.listed",
    }
}

fn subagent_control_evidence_ref(operation_kind: &str) -> &'static str {
    match operation_kind {
        "subagent.spawn" => "runtime_subagent_spawn_control_rust_owned",
        "subagent.wait" => "runtime_subagent_wait_control_rust_owned",
        "subagent.input" => "runtime_subagent_input_control_rust_owned",
        "subagent.resume" => "runtime_subagent_resume_control_rust_owned",
        "subagent.assign" => "runtime_subagent_assign_control_rust_owned",
        "subagent.cancel" => "runtime_subagent_cancel_control_rust_owned",
        "subagent.cancel.propagate" => "runtime_subagent_cancel_propagation_rust_owned",
        _ => "runtime_subagent_control_event_rust_owned",
    }
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn string_array_field(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .collect()
}

fn number_field(value: &Value, field: &str) -> Option<u64> {
    value.get(field).and_then(Value::as_u64)
}

fn bool_field(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn safe_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn short_hash(value: String) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(digest)[..12].to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn wait_request() -> RuntimeSubagentControlRequest {
        RuntimeSubagentControlRequest {
            operation: Some("wait".to_string()),
            operation_kind: Some("subagent.wait".to_string()),
            thread_id: Some("thread_1".to_string()),
            event_stream_id: Some("thread_1:events".to_string()),
            status: Some("completed".to_string()),
            event_seed: Some("1780586400000".to_string()),
            parent_agent: json!({
                "id": "agent_parent",
                "cwd": "/workspace/project",
            }),
            thread: json!({
                "thread_id": "thread_1",
                "latest_turn_id": "turn_latest",
            }),
            subagent: json!({
                "subagent_id": "subagent_1",
                "agent_id": "agent_child_1",
                "run_id": "run_1",
                "parent_thread_id": "thread_1",
                "parent_turn_id": "turn_1",
                "role": "reviewer",
                "status": "completed",
                "lifecycle_status": "completed",
                "waited_at": "2026-06-12T12:00:00.000Z",
                "updated_at": "2026-06-12T12:00:00.000Z",
            }),
            request: json!({
                "source": "agent_studio",
                "receipt_refs": ["receipt_request"],
                "policy_decision_refs": ["policy_request"],
            }),
            evidence_refs: vec![],
        }
    }

    #[test]
    fn rust_plans_subagent_wait_control_event() {
        let record = RuntimeSubagentControlCore
            .plan(&wait_request())
            .expect("wait control should plan");
        assert_eq!(record.operation_kind, "subagent.wait");
        assert_eq!(record.event["event_kind"], "subagent.wait_completed");
        assert_eq!(
            record.event["source_event_kind"],
            "OperatorControl.SubagentWait"
        );
        assert_eq!(record.event["payload"]["operation"], "wait");
        assert_eq!(
            record.event["receipt_refs"].as_array().unwrap()[0],
            "receipt_request"
        );
        assert!(record
            .event
            .get("policy_decision_refs")
            .and_then(Value::as_array)
            .unwrap()
            .contains(&json!("policy_request")));
    }

    #[test]
    fn rust_shapes_subagent_wait_control_command_response() {
        let response =
            plan_runtime_subagent_control_response(wait_request()).expect("response should shape");
        assert_eq!(response["source"], "rust_runtime_subagent_control_command");
        assert_eq!(response["record"]["operation_kind"], "subagent.wait");
        assert_eq!(
            response["record"]["event"]["component_kind"],
            "subagent_lifecycle"
        );
    }

    #[test]
    fn rust_plans_subagent_spawn_control_event() {
        let mut request = wait_request();
        request.operation = Some("spawn".to_string());
        request.operation_kind = Some("subagent.spawn".to_string());
        request.status = Some("running".to_string());
        request.subagent = json!({
            "subagent_id": "agent_child_spawned",
            "agent_id": "agent_child_spawned",
            "child_thread_id": "thread_child_spawned",
            "run_id": "run_child_spawned",
            "parent_thread_id": "thread_1",
            "parent_agent_id": "agent_parent",
            "parent_turn_id": "turn_1",
            "role": "reviewer",
            "status": "running",
            "lifecycle_status": "running",
            "restart_status": "not_restarted",
            "fork_context": true,
            "context_mode": "forked",
            "tool_pack": "analysis-tools",
            "model_route_id": "route.spawn",
            "workflow_graph_id": "workflow_spawn",
            "workflow_node_id": "node_spawn",
            "output_contract_status": "passed",
            "merge_policy": "manual",
            "cancellation_inheritance": "propagate",
            "source_event_id": "event_parent",
            "source_receipt_refs": ["receipt_parent"],
            "source_policy_decision_refs": ["policy_parent"],
            "created_at": "2026-06-12T12:04:00.000Z",
            "updated_at": "2026-06-12T12:04:00.000Z",
        });

        let record = RuntimeSubagentControlCore
            .plan(&request)
            .expect("spawn control should plan");

        assert_eq!(record.operation_kind, "subagent.spawn");
        assert_eq!(record.event["event_kind"], "subagent.spawned");
        assert_eq!(
            record.event["source_event_kind"],
            "OperatorControl.SubagentSpawn"
        );
        assert_eq!(record.event["payload"]["operation"], "spawn");
        assert_eq!(
            record.event["payload"]["child_thread_id"],
            "thread_child_spawned"
        );
        assert_eq!(record.event["payload"]["model_route_id"], "route.spawn");
        assert_eq!(
            record.event["payload"]["source_receipt_refs"][0],
            "receipt_parent"
        );
        assert!(record
            .evidence_refs
            .contains(&"runtime_subagent_spawn_control_rust_owned".to_string()));
    }

    #[test]
    fn rust_plans_subagent_assign_control_event() {
        let mut request = wait_request();
        request.operation = Some("assign".to_string());
        request.operation_kind = Some("subagent.assign".to_string());
        request.status = Some("running".to_string());
        request.subagent["assignment_id"] = json!("assignment_1");
        request.subagent["assignment_count"] = json!(1);
        request.subagent["assigned_at"] = json!("2026-06-12T12:05:00.000Z");
        request.subagent["target_agent_id"] = json!("agent_child_1");

        let record = RuntimeSubagentControlCore
            .plan(&request)
            .expect("assign control should plan");

        assert_eq!(record.operation_kind, "subagent.assign");
        assert_eq!(record.event["event_kind"], "subagent.assigned");
        assert_eq!(
            record.event["source_event_kind"],
            "OperatorControl.SubagentAssign"
        );
        assert_eq!(record.event["payload"]["assignment_id"], "assignment_1");
        assert_eq!(record.event["payload"]["assignment_count"], 1);
    }

    #[test]
    fn rust_plans_subagent_input_control_event() {
        let mut request = wait_request();
        request.operation = Some("send_input".to_string());
        request.operation_kind = Some("subagent.input".to_string());
        request.status = Some("completed".to_string());
        request.subagent["input_id"] = json!("input_1");
        request.subagent["input_count"] = json!(2);
        request.subagent["last_input"] = json!("Follow up.");
        request.subagent["last_input_at"] = json!("2026-06-12T12:07:00.000Z");
        request.subagent["previous_run_id"] = json!("run_previous");

        let record = RuntimeSubagentControlCore
            .plan(&request)
            .expect("input control should plan");

        assert_eq!(record.operation, "send_input");
        assert_eq!(record.operation_kind, "subagent.input");
        assert_eq!(record.event["event_kind"], "subagent.input_sent");
        assert_eq!(
            record.event["source_event_kind"],
            "OperatorControl.SubagentSendInput"
        );
        assert_eq!(record.event["payload"]["input_id"], "input_1");
        assert_eq!(record.event["payload"]["input_count"], 2);
        assert_eq!(record.event["payload"]["last_input"], "Follow up.");
    }

    #[test]
    fn rust_plans_subagent_resume_control_event() {
        let mut request = wait_request();
        request.operation = Some("resume".to_string());
        request.operation_kind = Some("subagent.resume".to_string());
        request.status = Some("completed".to_string());
        request.subagent["resume_id"] = json!("resume_1");
        request.subagent["restart_count"] = json!(3);
        request.subagent["resumed_at"] = json!("2026-06-12T12:08:00.000Z");
        request.subagent["cancellation_cleared_at"] = json!("2026-06-12T12:08:00.000Z");

        let record = RuntimeSubagentControlCore
            .plan(&request)
            .expect("resume control should plan");

        assert_eq!(record.operation_kind, "subagent.resume");
        assert_eq!(record.event["event_kind"], "subagent.resumed");
        assert_eq!(
            record.event["source_event_kind"],
            "OperatorControl.SubagentResume"
        );
        assert_eq!(record.event["payload"]["resume_id"], "resume_1");
        assert_eq!(record.event["payload"]["restart_count"], 3);
    }

    #[test]
    fn rust_plans_subagent_cancel_control_event() {
        let mut request = wait_request();
        request.operation = Some("cancel".to_string());
        request.operation_kind = Some("subagent.cancel".to_string());
        request.status = Some("canceled".to_string());
        request.subagent["status"] = json!("canceled");
        request.subagent["lifecycle_status"] = json!("canceled");
        request.subagent["cancellation_reason"] = json!("operator_cancel");
        request.subagent["cancellation_inherited"] = json!(false);
        request.subagent["canceled_at"] = json!("2026-06-12T12:06:00.000Z");

        let record = RuntimeSubagentControlCore
            .plan(&request)
            .expect("cancel control should plan");

        assert_eq!(record.operation_kind, "subagent.cancel");
        assert_eq!(record.event["event_kind"], "subagent.canceled");
        assert_eq!(
            record.event["source_event_kind"],
            "OperatorControl.SubagentCancel"
        );
        assert_eq!(
            record.event["payload"]["cancellation_reason"],
            "operator_cancel"
        );
        assert_eq!(record.event["payload"]["cancellation_inherited"], false);
    }

    #[test]
    fn rust_plans_subagent_cancel_propagation_control_event() {
        let mut request = wait_request();
        request.operation = Some("cancel".to_string());
        request.operation_kind = Some("subagent.cancel.propagate".to_string());
        request.status = Some("canceled".to_string());
        request.subagent["status"] = json!("canceled");
        request.subagent["lifecycle_status"] = json!("canceled");
        request.subagent["cancellation_reason"] = json!("parent_cancel");
        request.subagent["cancellation_inherited"] = json!(true);
        request.subagent["propagated_from_thread_id"] = json!("thread_1");
        request.subagent["canceled_at"] = json!("2026-06-12T12:09:00.000Z");

        let record = RuntimeSubagentControlCore
            .plan(&request)
            .expect("cancel propagation control should plan");

        assert_eq!(record.operation_kind, "subagent.cancel.propagate");
        assert_eq!(record.event["event_kind"], "subagent.canceled");
        assert_eq!(
            record.event["source_event_kind"],
            "OperatorControl.SubagentCancel"
        );
        assert_eq!(record.event["payload"]["cancellation_inherited"], true);
        assert_eq!(
            record.event["payload"]["propagated_from_thread_id"],
            "thread_1"
        );
        assert!(record
            .evidence_refs
            .contains(&"runtime_subagent_cancel_propagation_rust_owned".to_string()));
    }

    #[test]
    fn rust_rejects_unowned_subagent_control_kind() {
        let mut request = wait_request();
        request.operation_kind = Some("subagent.control.append".to_string());
        let error = RuntimeSubagentControlCore
            .plan(&request)
            .expect_err("direct append is not part of this cut");
        assert_eq!(
            error.code(),
            "runtime_subagent_control_operation_kind_unsupported"
        );
    }

    #[test]
    fn rust_rejects_subagent_wait_thread_mismatch() {
        let mut request = wait_request();
        request.thread_id = Some("thread_other".to_string());
        let error = RuntimeSubagentControlCore
            .plan(&request)
            .expect_err("thread mismatch should fail closed");
        assert_eq!(error.code(), "runtime_subagent_control_thread_mismatch");
    }
}
