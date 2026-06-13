use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const RUNTIME_MCP_SERVE_TOOL_CALL_PLAN_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-serve-tool-call-plan-request.v1";
pub const RUNTIME_MCP_SERVE_TOOL_CALL_PLAN_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp_serve_tool_call_plan.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeMcpServeToolCallPlanRequest {
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub tool_id: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub jsonrpc_id: Value,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub request: Value,
    #[serde(default)]
    pub mcp_serve_schema_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeMcpServeCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeMcpServeCommandError {
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
pub struct RuntimeMcpServeToolCallPlanCore;

#[derive(Debug, Clone)]
pub struct RuntimeMcpServeToolCallPlanRecord {
    pub operation: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub tool_id: String,
    pub tool_name: Option<String>,
    pub method: String,
    pub tool_call_id: String,
    pub idempotency_key: String,
    pub workflow_graph_id: String,
    pub workflow_node_id: String,
    pub request_hash: String,
    pub request: Value,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
}

pub fn plan_runtime_mcp_serve_tool_call_response(
    request: RuntimeMcpServeToolCallPlanRequest,
) -> Result<Value, RuntimeMcpServeCommandError> {
    let record = RuntimeMcpServeToolCallPlanCore.plan(&request)?;
    Ok(json!({
        "source": "rust_runtime_mcp_serve_tool_call_plan_command",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

impl RuntimeMcpServeToolCallPlanCore {
    pub fn plan(
        &self,
        request: &RuntimeMcpServeToolCallPlanRequest,
    ) -> Result<RuntimeMcpServeToolCallPlanRecord, RuntimeMcpServeCommandError> {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_MCP_SERVE_TOOL_CALL_PLAN_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeMcpServeCommandError::new(
                    "runtime_mcp_serve_tool_call_schema_version_invalid",
                    format!(
                        "expected {RUNTIME_MCP_SERVE_TOOL_CALL_PLAN_REQUEST_SCHEMA_VERSION}, got {schema_version}"
                    ),
                ));
            }
        }

        let operation = optional_trimmed(request.operation.as_deref())
            .unwrap_or_else(|| "runtime_mcp_serve_tool_call".to_string());
        let operation_kind = optional_trimmed(request.operation_kind.as_deref())
            .unwrap_or_else(|| "mcp.serve.tools.call".to_string());
        if operation_kind != "mcp.serve.tools.call" {
            return Err(RuntimeMcpServeCommandError::new(
                "runtime_mcp_serve_tool_call_operation_kind_unsupported",
                format!("{operation_kind} is not an MCP serve tools/call operation"),
            ));
        }
        let method = optional_trimmed(request.method.as_deref())
            .unwrap_or_else(|| "tools/call".to_string());
        if method != "tools/call" {
            return Err(RuntimeMcpServeCommandError::new(
                "runtime_mcp_serve_tool_call_method_unsupported",
                format!("{method} is not supported for MCP serve tool-call planning"),
            ));
        }
        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeMcpServeCommandError::new(
                "runtime_mcp_serve_tool_call_thread_id_required",
                "MCP serve tool-call planning requires thread_id",
            )
        })?;
        let tool_id = optional_trimmed(request.tool_id.as_deref()).ok_or_else(|| {
            RuntimeMcpServeCommandError::new(
                "runtime_mcp_serve_tool_call_tool_id_required",
                "MCP serve tool-call planning requires tool_id",
            )
        })?;
        let params = object_value(&request.params);
        let context = object_value(&request.request);
        let input = params
            .get("arguments")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let request_hash = request_hash(&request.jsonrpc_id, &input, &thread_id, &tool_id);
        let safe_tool_id = safe_id(&tool_id);
        let tool_call_id = params
            .get("tool_call_id")
            .and_then(Value::as_str)
            .and_then(trimmed_str)
            .or_else(|| {
                context
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .and_then(trimmed_str)
            })
            .unwrap_or_else(|| format!("mcp_serve_{safe_tool_id}_{}", &request_hash[..16]));
        let idempotency_key = params
            .get("idempotency_key")
            .and_then(Value::as_str)
            .and_then(trimmed_str)
            .or_else(|| {
                context
                    .get("idempotency_key")
                    .and_then(Value::as_str)
                    .and_then(trimmed_str)
            })
            .unwrap_or_else(|| format!("thread:{thread_id}:mcp-serve:{tool_call_id}"));
        let workflow_graph_id = context
            .get("workflow_graph_id")
            .and_then(Value::as_str)
            .and_then(trimmed_str)
            .unwrap_or_else(|| "runtime.mcp_serve".to_string());
        let workflow_node_id = context
            .get("workflow_node_id")
            .and_then(Value::as_str)
            .and_then(trimmed_str)
            .unwrap_or_else(|| format!("runtime.mcp_serve.{safe_tool_id}"));
        let mcp_serve_schema_version = optional_trimmed(request.mcp_serve_schema_version.as_deref())
            .unwrap_or_else(|| "ioi.runtime.mcp-serve.v1".to_string());

        let mut invocation_request = input;
        invocation_request.insert("source".to_string(), json!("mcp_serve"));
        invocation_request.insert("tool_call_id".to_string(), json!(tool_call_id));
        invocation_request.insert("idempotency_key".to_string(), json!(idempotency_key));
        invocation_request.insert("workflow_graph_id".to_string(), json!(workflow_graph_id));
        invocation_request.insert("workflow_node_id".to_string(), json!(workflow_node_id));
        invocation_request.insert(
            "mcp_serve_request".to_string(),
            json!({
                "schema_version": mcp_serve_schema_version,
                "jsonrpc_id": request.jsonrpc_id.clone(),
                "method": "tools/call",
                "thread_id": thread_id,
                "tool_id": tool_id,
                "tool_name": optional_trimmed(request.tool_name.as_deref()),
                "request_hash": request_hash,
            }),
        );

        Ok(RuntimeMcpServeToolCallPlanRecord {
            operation,
            operation_kind,
            thread_id,
            tool_id,
            tool_name: optional_trimmed(request.tool_name.as_deref()),
            method,
            tool_call_id: invocation_request
                .get("tool_call_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            idempotency_key: invocation_request
                .get("idempotency_key")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            workflow_graph_id: invocation_request
                .get("workflow_graph_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            workflow_node_id: invocation_request
                .get("workflow_node_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            request_hash,
            request: Value::Object(invocation_request),
            evidence_refs: vec![
                "runtime_mcp_serve_tool_call_rust_owned".to_string(),
                "rust_daemon_core_runtime_mcp_serve_tool_call_plan".to_string(),
                "agentgres_runtime_mcp_serve_tool_call_truth_required".to_string(),
                "wallet_runtime_mcp_serve_authority_required".to_string(),
            ],
            receipt_refs: vec![format!(
                "receipt_runtime_mcp_serve_tool_call_plan_{}",
                safe_tool_id
            )],
            policy_decision_refs: vec![format!(
                "policy_runtime_mcp_serve_tool_call_plan_{}",
                safe_tool_id
            )],
        })
    }
}

impl RuntimeMcpServeToolCallPlanRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_MCP_SERVE_TOOL_CALL_PLAN_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_mcp_serve_tool_call_plan",
            "status": "planned",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "thread_id": self.thread_id,
            "tool_id": self.tool_id,
            "tool_name": self.tool_name,
            "method": self.method,
            "tool_call_id": self.tool_call_id,
            "idempotency_key": self.idempotency_key,
            "workflow_graph_id": self.workflow_graph_id,
            "workflow_node_id": self.workflow_node_id,
            "request_hash": self.request_hash,
            "request": self.request,
            "evidence_refs": self.evidence_refs,
            "receipt_refs": self.receipt_refs,
            "policy_decision_refs": self.policy_decision_refs,
        })
    }
}

fn object_value(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

fn request_hash(
    jsonrpc_id: &Value,
    input: &Map<String, Value>,
    thread_id: &str,
    tool_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    let payload = json!({
        "id": jsonrpc_id,
        "input": input,
        "thread_id": thread_id,
        "tool_id": tool_id,
    });
    hasher.update(payload.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value.map(str::trim).filter(|value| !value.is_empty()).map(str::to_string)
}

fn trimmed_str(value: &str) -> Option<String> {
    optional_trimmed(Some(value))
}

fn safe_id(value: &str) -> String {
    let safe = value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if safe.is_empty() {
        "unknown".to_string()
    } else {
        safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> RuntimeMcpServeToolCallPlanRequest {
        RuntimeMcpServeToolCallPlanRequest {
            schema_version: Some(RUNTIME_MCP_SERVE_TOOL_CALL_PLAN_REQUEST_SCHEMA_VERSION.to_string()),
            operation: None,
            operation_kind: None,
            thread_id: Some("thread_one".to_string()),
            tool_id: Some("git.diff".to_string()),
            tool_name: Some("git.diff".to_string()),
            method: Some("tools/call".to_string()),
            jsonrpc_id: json!(7),
            params: json!({
                "name": "git.diff",
                "arguments": { "include_stat": true },
                "args": { "retired": true }
            }),
            request: json!({
                "workflow_graph_id": "graph_one",
                "workflowGraphId": "retired_graph"
            }),
            mcp_serve_schema_version: Some("ioi.runtime.mcp-serve.test".to_string()),
        }
    }

    #[test]
    fn rust_plans_mcp_serve_tool_call_request() {
        let record = RuntimeMcpServeToolCallPlanCore
            .plan(&request())
            .expect("mcp serve plan");
        assert_eq!(record.operation_kind, "mcp.serve.tools.call");
        assert_eq!(record.thread_id, "thread_one");
        assert_eq!(record.tool_id, "git.diff");
        assert!(record.tool_call_id.starts_with("mcp_serve_git_diff_"));
        assert_eq!(record.workflow_graph_id, "graph_one");
        assert_eq!(record.workflow_node_id, "runtime.mcp_serve.git_diff");
        assert_eq!(
            record.evidence_refs,
            vec![
                "runtime_mcp_serve_tool_call_rust_owned",
                "rust_daemon_core_runtime_mcp_serve_tool_call_plan",
                "agentgres_runtime_mcp_serve_tool_call_truth_required",
                "wallet_runtime_mcp_serve_authority_required",
            ]
        );
        let planned_request = record.request.as_object().expect("request object");
        assert_eq!(planned_request["include_stat"], true);
        assert_eq!(planned_request["source"], "mcp_serve");
        assert!(!planned_request.contains_key("args"));
        assert!(!planned_request.contains_key("workflowGraphId"));
        let mcp_request = planned_request["mcp_serve_request"]
            .as_object()
            .expect("mcp serve request");
        assert_eq!(mcp_request["schema_version"], "ioi.runtime.mcp-serve.test");
        assert_eq!(mcp_request["thread_id"], "thread_one");
        assert_eq!(mcp_request["tool_id"], "git.diff");
        assert!(!mcp_request.contains_key("toolId"));
    }

    #[test]
    fn rust_shapes_mcp_serve_tool_call_command_response() {
        let response =
            plan_runtime_mcp_serve_tool_call_response(request()).expect("command response");
        assert_eq!(
            response["source"],
            "rust_runtime_mcp_serve_tool_call_plan_command"
        );
        assert_eq!(response["record"]["operation_kind"], "mcp.serve.tools.call");
        assert_eq!(response["record"]["request"]["source"], "mcp_serve");
    }

    #[test]
    fn rust_rejects_non_tool_call_method() {
        let mut request = request();
        request.method = Some("resources/read".to_string());
        let error = RuntimeMcpServeToolCallPlanCore
            .plan(&request)
            .expect_err("method should fail");
        assert_eq!(
            error.code(),
            "runtime_mcp_serve_tool_call_method_unsupported"
        );
    }
}
