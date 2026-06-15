use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const RUNTIME_MCP_SERVE_TOOL_CALL_PLAN_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-serve-tool-call-plan-request.v1";
pub const RUNTIME_MCP_SERVE_TOOL_CALL_PLAN_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp_serve_tool_call_plan.v1";
pub const RUNTIME_MCP_SERVE_TOOL_RESULT_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-serve-tool-result-projection-request.v1";
pub const RUNTIME_MCP_SERVE_TOOL_RESULT_PROJECTION_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp_serve_tool_result_projection.v1";
pub const RUNTIME_MCP_SERVE_TOOL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.mcp-serve.v1";

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
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
    #[serde(default)]
    pub custody_ref: Option<String>,
    #[serde(default)]
    pub containment_ref: Option<String>,
    #[serde(default)]
    pub mcp_serve_schema_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeMcpServeToolResultProjectionRequest {
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
    pub jsonrpc_id: Value,
    #[serde(default)]
    pub plan: Value,
    #[serde(default)]
    pub invocation: Value,
    #[serde(default)]
    pub mcp_serve_schema_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeMcpServeError {
    code: &'static str,
    message: String,
}

impl RuntimeMcpServeError {
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
    pub authority_grant_refs: Vec<String>,
    pub authority_receipt_refs: Vec<String>,
    pub custody_ref: String,
    pub containment_ref: String,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RuntimeMcpServeToolResultProjectionRecord {
    pub operation: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub tool_id: String,
    pub tool_name: Option<String>,
    pub tool_call_id: Option<String>,
    pub workflow_graph_id: Option<String>,
    pub workflow_node_id: Option<String>,
    pub event_id: Option<String>,
    pub status: String,
    pub result: Value,
    pub live_result: Value,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
}

impl RuntimeMcpServeToolCallPlanCore {
    pub fn plan(
        &self,
        request: &RuntimeMcpServeToolCallPlanRequest,
    ) -> Result<RuntimeMcpServeToolCallPlanRecord, RuntimeMcpServeError> {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_MCP_SERVE_TOOL_CALL_PLAN_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeMcpServeError::new(
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
            return Err(RuntimeMcpServeError::new(
                "runtime_mcp_serve_tool_call_operation_kind_unsupported",
                format!("{operation_kind} is not an MCP serve tools/call operation"),
            ));
        }
        let method =
            optional_trimmed(request.method.as_deref()).unwrap_or_else(|| "tools/call".to_string());
        if method != "tools/call" {
            return Err(RuntimeMcpServeError::new(
                "runtime_mcp_serve_tool_call_method_unsupported",
                format!("{method} is not supported for MCP serve tool-call planning"),
            ));
        }
        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeMcpServeError::new(
                "runtime_mcp_serve_tool_call_thread_id_required",
                "MCP serve tool-call planning requires thread_id",
            )
        })?;
        let tool_id = optional_trimmed(request.tool_id.as_deref()).ok_or_else(|| {
            RuntimeMcpServeError::new(
                "runtime_mcp_serve_tool_call_tool_id_required",
                "MCP serve tool-call planning requires tool_id",
            )
        })?;
        let params = object_value(&request.params);
        let context = object_value(&request.request);
        let mut authority_grant_refs = canonical_string_vec(&request.authority_grant_refs);
        if authority_grant_refs.is_empty() {
            authority_grant_refs = string_array_field(&context, "authority_grant_refs");
        }
        let mut authority_receipt_refs = canonical_string_vec(&request.authority_receipt_refs);
        if authority_receipt_refs.is_empty() {
            authority_receipt_refs = string_array_field(&context, "authority_receipt_refs");
        }
        if authority_grant_refs.is_empty() || authority_receipt_refs.is_empty() {
            return Err(RuntimeMcpServeError::new(
                "runtime_mcp_serve_tool_call_authority_required",
                "MCP serve tool-call planning requires wallet authority grant and receipt refs",
            ));
        }
        let custody_ref = optional_trimmed(request.custody_ref.as_deref())
            .or_else(|| string_field(&context, "custody_ref"))
            .ok_or_else(|| {
                RuntimeMcpServeError::new(
                    "runtime_mcp_serve_tool_call_custody_required",
                    "MCP serve tool-call planning requires cTEE custody ref",
                )
            })?;
        let containment_ref = optional_trimmed(request.containment_ref.as_deref())
            .or_else(|| string_field(&context, "containment_ref"))
            .ok_or_else(|| {
                RuntimeMcpServeError::new(
                    "runtime_mcp_serve_tool_call_containment_required",
                    "MCP serve tool-call planning requires transport containment ref",
                )
            })?;
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
        let mcp_serve_schema_version =
            optional_trimmed(request.mcp_serve_schema_version.as_deref())
                .unwrap_or_else(|| "ioi.runtime.mcp-serve.v1".to_string());

        let mut invocation_request = input;
        invocation_request.insert("source".to_string(), json!("mcp_serve"));
        invocation_request.insert("tool_call_id".to_string(), json!(tool_call_id));
        invocation_request.insert("idempotency_key".to_string(), json!(idempotency_key));
        invocation_request.insert("workflow_graph_id".to_string(), json!(workflow_graph_id));
        invocation_request.insert("workflow_node_id".to_string(), json!(workflow_node_id));
        invocation_request.insert(
            "authority_grant_refs".to_string(),
            json!(authority_grant_refs),
        );
        invocation_request.insert(
            "authority_receipt_refs".to_string(),
            json!(authority_receipt_refs),
        );
        invocation_request.insert("custody_ref".to_string(), json!(custody_ref));
        invocation_request.insert("containment_ref".to_string(), json!(containment_ref));
        let mcp_serve_request = json!({
            "schema_version": mcp_serve_schema_version,
            "jsonrpc_id": request.jsonrpc_id.clone(),
            "method": "tools/call",
            "thread_id": thread_id,
            "tool_id": tool_id,
            "tool_name": optional_trimmed(request.tool_name.as_deref()),
            "request_hash": request_hash,
            "wallet_authority_boundary": "wallet.network.mcp_serve_tool_call",
            "authority_grant_refs": invocation_request.get("authority_grant_refs").cloned().unwrap_or(Value::Array(vec![])),
            "authority_receipt_refs": invocation_request.get("authority_receipt_refs").cloned().unwrap_or(Value::Array(vec![])),
            "custody_ref": invocation_request.get("custody_ref").cloned().unwrap_or(Value::Null),
            "containment_ref": invocation_request.get("containment_ref").cloned().unwrap_or(Value::Null),
        });
        invocation_request.insert("mcp_serve_request".to_string(), mcp_serve_request);
        let authority_grant_refs = string_array_field(&invocation_request, "authority_grant_refs");
        let authority_receipt_refs =
            string_array_field(&invocation_request, "authority_receipt_refs");
        let custody_ref = string_field(&invocation_request, "custody_ref").unwrap_or_default();
        let containment_ref =
            string_field(&invocation_request, "containment_ref").unwrap_or_default();

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
            authority_grant_refs,
            authority_receipt_refs,
            custody_ref,
            containment_ref,
            evidence_refs: vec![
                "runtime_mcp_serve_tool_call_rust_owned".to_string(),
                "rust_daemon_core_runtime_mcp_serve_tool_call_plan".to_string(),
                "agentgres_runtime_mcp_serve_tool_call_truth_required".to_string(),
                "wallet_runtime_mcp_serve_authority_required".to_string(),
                "ctee_runtime_mcp_serve_custody_required".to_string(),
                "runtime_mcp_serve_transport_containment_required".to_string(),
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

    pub fn project_result(
        &self,
        request: &RuntimeMcpServeToolResultProjectionRequest,
    ) -> Result<RuntimeMcpServeToolResultProjectionRecord, RuntimeMcpServeError> {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_MCP_SERVE_TOOL_RESULT_PROJECTION_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeMcpServeError::new(
                    "runtime_mcp_serve_tool_result_schema_version_invalid",
                    format!(
                        "expected {RUNTIME_MCP_SERVE_TOOL_RESULT_PROJECTION_REQUEST_SCHEMA_VERSION}, got {schema_version}"
                    ),
                ));
            }
        }

        let operation = optional_trimmed(request.operation.as_deref())
            .unwrap_or_else(|| "runtime_mcp_serve_tool_result".to_string());
        let operation_kind = optional_trimmed(request.operation_kind.as_deref())
            .unwrap_or_else(|| "mcp.serve.tools.result".to_string());
        if operation_kind != "mcp.serve.tools.result" {
            return Err(RuntimeMcpServeError::new(
                "runtime_mcp_serve_tool_result_operation_kind_unsupported",
                format!("{operation_kind} is not an MCP serve tools/call result projection"),
            ));
        }
        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeMcpServeError::new(
                "runtime_mcp_serve_tool_result_thread_id_required",
                "MCP serve result projection requires thread_id",
            )
        })?;
        let tool_id = optional_trimmed(request.tool_id.as_deref()).ok_or_else(|| {
            RuntimeMcpServeError::new(
                "runtime_mcp_serve_tool_result_tool_id_required",
                "MCP serve result projection requires tool_id",
            )
        })?;
        let plan = object_value(&request.plan);
        let invocation = object_value(&request.invocation);
        if plan.is_empty() {
            return Err(RuntimeMcpServeError::new(
                "runtime_mcp_serve_tool_result_plan_required",
                "MCP serve result projection requires the Rust tool-call plan",
            ));
        }
        if invocation.is_empty() {
            return Err(RuntimeMcpServeError::new(
                "runtime_mcp_serve_tool_result_invocation_required",
                "MCP serve result projection requires a Rust coding-tool invocation result",
            ));
        }
        let plan_thread_id = string_field(&plan, "thread_id");
        let plan_tool_id = string_field(&plan, "tool_id");
        if plan_thread_id.as_deref() != Some(thread_id.as_str())
            || plan_tool_id.as_deref() != Some(tool_id.as_str())
        {
            return Err(RuntimeMcpServeError::new(
                "runtime_mcp_serve_tool_result_plan_mismatch",
                "MCP serve result projection requires matching Rust plan identity",
            ));
        }
        let plan_request = plan
            .get("request")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let mcp_serve_request = plan_request
            .get("mcp_serve_request")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let authority_grant_refs = string_array_field(&mcp_serve_request, "authority_grant_refs");
        let authority_receipt_refs =
            string_array_field(&mcp_serve_request, "authority_receipt_refs");
        let custody_ref = string_field(&mcp_serve_request, "custody_ref");
        let containment_ref = string_field(&mcp_serve_request, "containment_ref");
        if authority_grant_refs.is_empty() || authority_receipt_refs.is_empty() {
            return Err(RuntimeMcpServeError::new(
                "runtime_mcp_serve_tool_result_authority_required",
                "MCP serve result projection requires wallet authority refs from the Rust plan",
            ));
        }
        let custody_ref = custody_ref.ok_or_else(|| {
            RuntimeMcpServeError::new(
                "runtime_mcp_serve_tool_result_custody_required",
                "MCP serve result projection requires cTEE custody ref from the Rust plan",
            )
        })?;
        let containment_ref = containment_ref.ok_or_else(|| {
            RuntimeMcpServeError::new(
                "runtime_mcp_serve_tool_result_containment_required",
                "MCP serve result projection requires transport containment ref from the Rust plan",
            )
        })?;

        let payload = invocation
            .get("event")
            .and_then(Value::as_object)
            .and_then(|event| event.get("payload_summary"))
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let status = string_field(&invocation, "status")
            .or_else(|| string_field(&payload, "status"))
            .unwrap_or_else(|| "completed".to_string());
        let tool_name = string_field(&invocation, "tool_name")
            .or_else(|| optional_trimmed(request.tool_name.as_deref()))
            .or_else(|| string_field(&plan, "tool_name"));
        let summary = string_field(&payload, "summary").unwrap_or_else(|| {
            format!(
                "IOI runtime tool {} {status}.",
                tool_name.as_deref().unwrap_or("unknown")
            )
        });
        let tool_call_id = string_field(&invocation, "tool_call_id")
            .or_else(|| string_field(&plan, "tool_call_id"));
        let workflow_graph_id = string_field(&invocation, "workflow_graph_id")
            .or_else(|| string_field(&plan, "workflow_graph_id"));
        let workflow_node_id = string_field(&invocation, "workflow_node_id")
            .or_else(|| string_field(&plan, "workflow_node_id"));
        let event_id = invocation
            .get("event")
            .and_then(Value::as_object)
            .and_then(|event| string_field(event, "event_id"));
        let receipt_refs = string_array_field(&invocation, "receipt_refs");
        if receipt_refs.is_empty() {
            return Err(RuntimeMcpServeError::new(
                "runtime_mcp_serve_tool_result_receipt_required",
                "MCP serve result projection requires Rust coding-tool receipt refs",
            ));
        }
        let receipt_id = receipt_refs.first().cloned().unwrap_or_default();
        let policy_decision_refs = string_array_field(&invocation, "policy_decision_refs");
        let artifact_refs = string_array_field(&invocation, "artifact_refs");
        let mcp_serve_schema_version =
            optional_trimmed(request.mcp_serve_schema_version.as_deref())
                .unwrap_or_else(|| RUNTIME_MCP_SERVE_TOOL_RESULT_SCHEMA_VERSION.to_string());
        let result_payload = invocation.get("result").cloned().unwrap_or(Value::Null);
        let error_payload = invocation.get("error").cloned().unwrap_or(Value::Null);
        let tool_result = json!({
            "content": [{ "type": "text", "text": summary }],
            "structuredContent": {
                "schema_version": mcp_serve_schema_version,
                "object": "ioi.runtime_mcp_serve_tool_result",
                "status": status,
                "tool_name": tool_name,
                "tool_call_id": tool_call_id,
                "thread_id": thread_id,
                "workflow_graph_id": workflow_graph_id,
                "workflow_node_id": workflow_node_id,
                "receipt_refs": receipt_refs,
                "policy_decision_refs": policy_decision_refs,
                "artifact_refs": artifact_refs,
                "wallet_authority_boundary": "wallet.network.mcp_serve_tool_call",
                "authority_grant_refs": authority_grant_refs,
                "authority_receipt_refs": authority_receipt_refs,
                "custody_ref": custody_ref,
                "containment_ref": containment_ref,
                "event_id": event_id,
                "result": result_payload,
                "error": error_payload,
            },
            "isError": status != "completed",
        });
        let identity = tool_call_id
            .clone()
            .or_else(|| event_id.clone())
            .or_else(|| string_field(&plan, "request_hash"))
            .unwrap_or_else(|| "result".to_string());
        let live_result_id = format!(
            "result_runtime_mcp_serve_{}_{}_{}",
            safe_id(&thread_id),
            safe_id(&tool_id),
            safe_id(&identity)
        );
        let event = invocation
            .get("event")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let created_at = string_field(&invocation, "created_at")
            .or_else(|| string_field(&event, "created_at"))
            .unwrap_or_else(|| "rust_policy_core".to_string());
        let payload_hash = value_hash(&tool_result);
        let payload_ref =
            format!("payload://runtime/mcp-live-results/{live_result_id}/protocol-result");
        let live_result_evidence_refs = vec![
            "runtime_mcp_serve_tool_result_rust_owned",
            "rust_daemon_core_runtime_mcp_serve_tool_result_projection",
            "runtime_mcp_live_result_rust_projection",
            "agentgres_runtime_mcp_live_result_truth_required",
            "runtime_mcp_serve_result_payload_materialized",
            "runtime_mcp_no_js_transport_result",
            "wallet_runtime_mcp_serve_authority_required",
            "ctee_runtime_mcp_serve_custody_required",
            "runtime_mcp_serve_transport_containment_required",
            "receipt_state_root_binding_required",
        ];
        let live_result_payload = json!({
            "schema_version": mcp_serve_schema_version,
            "protocol_result": tool_result,
            "payload_hash": payload_hash,
            "payload_ref": payload_ref
        });
        let live_result_details = json!({
            "rust_daemon_core_result_author": "runtime.mcp_serve",
            "control_kind": "mcp_serve_tool_call",
            "operation_kind": "mcp.serve.tools.result",
            "thread_id": thread_id,
            "tool_id": tool_id,
            "tool_name": tool_name,
            "tool_call_id": tool_call_id,
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
            "event_id": event_id,
            "receipt_id": receipt_id,
            "receipt_refs": receipt_refs,
            "policy_decision_refs": policy_decision_refs,
            "artifact_refs": artifact_refs,
            "wallet_authority_boundary": "wallet.network.mcp_serve_tool_call",
            "authority_grant_refs": authority_grant_refs,
            "authority_receipt_refs": authority_receipt_refs,
            "custody_ref": custody_ref,
            "containment_ref": containment_ref,
            "ctee_custody_required": true,
            "transport_containment_required": true,
            "payload_ref": payload_ref,
            "payload_hash": payload_hash,
            "result_materialized": true,
            "backend_materialization_status": "rust_step_module_invocation_materialized",
            "rust_coding_tool_invocation": true,
            "step_module_router_owner": "rust_daemon_core"
        });
        let live_result = json!({
            "schema_version": "ioi.runtime.mcp-live-result.v1",
            "object": "ioi.runtime_mcp_live_result",
            "id": live_result_id,
            "kind": "runtime_mcp_live_result",
            "status": if status == "completed" { "materialized" } else { "materialized_error" },
            "redaction": "redacted",
            "created_at": created_at,
            "receipt_id": receipt_id,
            "receipt_refs": receipt_refs,
            "evidence_refs": live_result_evidence_refs,
            "payload": live_result_payload,
            "details": live_result_details
        });

        Ok(RuntimeMcpServeToolResultProjectionRecord {
            operation,
            operation_kind,
            thread_id,
            tool_id,
            tool_name,
            tool_call_id,
            workflow_graph_id,
            workflow_node_id,
            event_id,
            status,
            result: tool_result,
            live_result,
            evidence_refs: vec![
                "runtime_mcp_serve_tool_result_rust_owned".to_string(),
                "rust_daemon_core_runtime_mcp_serve_tool_result_projection".to_string(),
                "agentgres_runtime_mcp_serve_tool_call_truth_required".to_string(),
                "wallet_runtime_mcp_serve_authority_required".to_string(),
                "ctee_runtime_mcp_serve_custody_required".to_string(),
                "runtime_mcp_serve_transport_containment_required".to_string(),
                "agentgres_runtime_mcp_live_result_truth_required".to_string(),
            ],
            receipt_refs,
            policy_decision_refs,
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
            "authority_grant_refs": self.authority_grant_refs,
            "authority_receipt_refs": self.authority_receipt_refs,
            "custody_ref": self.custody_ref,
            "containment_ref": self.containment_ref,
            "evidence_refs": self.evidence_refs,
            "receipt_refs": self.receipt_refs,
            "policy_decision_refs": self.policy_decision_refs,
        })
    }
}

impl RuntimeMcpServeToolResultProjectionRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_MCP_SERVE_TOOL_RESULT_PROJECTION_SCHEMA_VERSION,
            "object": "ioi.runtime_mcp_serve_tool_result_projection",
            "status": "projected",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "thread_id": self.thread_id,
            "tool_id": self.tool_id,
            "tool_name": self.tool_name,
            "tool_call_id": self.tool_call_id,
            "workflow_graph_id": self.workflow_graph_id,
            "workflow_node_id": self.workflow_node_id,
            "event_id": self.event_id,
            "tool_status": self.status,
            "result": self.result,
            "live_result": self.live_result,
            "evidence_refs": self.evidence_refs,
            "receipt_refs": self.receipt_refs,
            "policy_decision_refs": self.policy_decision_refs,
        })
    }
}

fn object_value(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

fn string_field(record: &Map<String, Value>, field: &str) -> Option<String> {
    record
        .get(field)
        .and_then(Value::as_str)
        .and_then(trimmed_str)
}

fn string_array_field(record: &Map<String, Value>, field: &str) -> Vec<String> {
    record
        .get(field)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter_map(trimmed_str)
                .collect()
        })
        .unwrap_or_default()
}

fn canonical_string_vec(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| trimmed_str(value))
        .collect()
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

fn value_hash(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|_| value.to_string().into_bytes());
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
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
            schema_version: Some(
                RUNTIME_MCP_SERVE_TOOL_CALL_PLAN_REQUEST_SCHEMA_VERSION.to_string(),
            ),
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
                "workflowGraphId": "retired_graph",
                "authority_grant_refs": ["wallet.network://grant/mcp-serve/git.diff"],
                "authority_receipt_refs": ["receipt://wallet.network/mcp-serve/git.diff"],
                "custody_ref": "ctee://workspace/thread_one",
                "containment_ref": "containment://mcp-serve/thread_one/git.diff"
            }),
            authority_grant_refs: vec![],
            authority_receipt_refs: vec![],
            custody_ref: None,
            containment_ref: None,
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
                "ctee_runtime_mcp_serve_custody_required",
                "runtime_mcp_serve_transport_containment_required",
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
        assert_eq!(
            mcp_request["authority_grant_refs"][0],
            "wallet.network://grant/mcp-serve/git.diff"
        );
        assert_eq!(mcp_request["custody_ref"], "ctee://workspace/thread_one");
        assert_eq!(
            mcp_request["containment_ref"],
            "containment://mcp-serve/thread_one/git.diff"
        );
        assert!(!mcp_request.contains_key("toolId"));
    }

    #[test]
    fn rust_shapes_mcp_serve_tool_call_direct_record() {
        let record = RuntimeMcpServeToolCallPlanCore
            .plan(&request())
            .expect("direct record");
        let value = record.to_value();
        assert_eq!(value["operation_kind"], "mcp.serve.tools.call");
        assert_eq!(value["request"]["source"], "mcp_serve");
    }

    #[test]
    fn rust_projects_mcp_serve_tool_call_result() {
        let plan = RuntimeMcpServeToolCallPlanCore
            .plan(&request())
            .expect("mcp serve plan")
            .to_value();
        let projection = RuntimeMcpServeToolCallPlanCore
            .project_result(&RuntimeMcpServeToolResultProjectionRequest {
                schema_version: Some(
                    RUNTIME_MCP_SERVE_TOOL_RESULT_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
                ),
                operation: None,
                operation_kind: None,
                thread_id: Some("thread_one".to_string()),
                tool_id: Some("git.diff".to_string()),
                tool_name: Some("git.diff".to_string()),
                jsonrpc_id: json!(7),
                plan,
                invocation: json!({
                    "status": "completed",
                    "tool_name": "git.diff",
                    "tool_call_id": "call_one",
                    "thread_id": "thread_one",
                    "workflow_graph_id": "graph_one",
                    "workflow_node_id": "node_one",
                    "receipt_refs": ["receipt_one"],
                    "policy_decision_refs": ["policy_one"],
                    "artifact_refs": ["artifact_one"],
                    "event": {
                        "id": "retired_event_id",
                        "event_id": "event_one",
                        "payload_summary": { "summary": "git diff completed" }
                    },
                    "result": { "ok": true }
                }),
                mcp_serve_schema_version: Some("ioi.runtime.mcp-serve.test".to_string()),
            })
            .expect("mcp serve result projection");
        assert_eq!(projection.operation_kind, "mcp.serve.tools.result");
        assert_eq!(projection.event_id.as_deref(), Some("event_one"));
        assert!(projection
            .evidence_refs
            .contains(&"runtime_mcp_serve_tool_result_rust_owned".to_string()));
        assert_eq!(
            projection.result["structuredContent"]["schema_version"],
            "ioi.runtime.mcp-serve.test"
        );
        assert_eq!(
            projection.result["structuredContent"]["event_id"],
            "event_one"
        );
        assert!(projection.result["structuredContent"]["event"].is_null());
        assert_eq!(
            projection.result["content"][0]["text"],
            "git diff completed"
        );
        assert_eq!(
            projection.live_result["details"]["rust_daemon_core_result_author"],
            "runtime.mcp_serve"
        );
        assert_eq!(
            projection.live_result["details"]["result_materialized"],
            true
        );
        assert!(projection.live_result["details"]["js_transport_invocation"].is_null());
        assert_eq!(
            projection.live_result["details"]["authority_grant_refs"][0],
            "wallet.network://grant/mcp-serve/git.diff"
        );
        assert_eq!(
            projection.live_result["details"]["custody_ref"],
            "ctee://workspace/thread_one"
        );
        assert_eq!(
            projection.live_result["details"]["containment_ref"],
            "containment://mcp-serve/thread_one/git.diff"
        );
        assert_eq!(
            projection.live_result["payload"]["protocol_result"]["structuredContent"]["event_id"],
            "event_one"
        );
        assert_eq!(
            projection.live_result["receipt_refs"],
            json!(["receipt_one"])
        );
    }

    #[test]
    fn rust_shapes_mcp_serve_tool_result_direct_record() {
        let plan = RuntimeMcpServeToolCallPlanCore
            .plan(&request())
            .expect("mcp serve plan")
            .to_value();
        let record = RuntimeMcpServeToolCallPlanCore
            .project_result(&RuntimeMcpServeToolResultProjectionRequest {
                schema_version: Some(
                    RUNTIME_MCP_SERVE_TOOL_RESULT_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
                ),
                operation: None,
                operation_kind: None,
                thread_id: Some("thread_one".to_string()),
                tool_id: Some("git.diff".to_string()),
                tool_name: Some("git.diff".to_string()),
                jsonrpc_id: json!(7),
                plan,
                invocation: json!({
                    "status": "completed",
                    "tool_name": "git.diff",
                    "receipt_refs": ["receipt_one"],
                    "event": { "payload_summary": { "summary": "ok" } }
                }),
                mcp_serve_schema_version: None,
            })
            .expect("direct record");
        let value = record.to_value();
        assert_eq!(
            value["result"]["structuredContent"]["object"],
            "ioi.runtime_mcp_serve_tool_result"
        );
        assert_eq!(
            value["live_result"]["object"],
            "ioi.runtime_mcp_live_result"
        );
        assert_eq!(
            value["live_result"]["details"]["backend_materialization_status"],
            "rust_step_module_invocation_materialized"
        );
    }

    #[test]
    fn rust_rejects_mcp_serve_result_without_receipt_refs() {
        let plan = RuntimeMcpServeToolCallPlanCore
            .plan(&request())
            .expect("mcp serve plan")
            .to_value();
        let error = RuntimeMcpServeToolCallPlanCore
            .project_result(&RuntimeMcpServeToolResultProjectionRequest {
                schema_version: Some(
                    RUNTIME_MCP_SERVE_TOOL_RESULT_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
                ),
                operation: None,
                operation_kind: None,
                thread_id: Some("thread_one".to_string()),
                tool_id: Some("git.diff".to_string()),
                tool_name: Some("git.diff".to_string()),
                jsonrpc_id: json!(7),
                plan,
                invocation: json!({
                    "status": "completed",
                    "tool_name": "git.diff",
                    "event": { "payload_summary": { "summary": "ok" } }
                }),
                mcp_serve_schema_version: None,
            })
            .expect_err("receipt refs are required for MCP serve result truth");
        assert_eq!(
            error.code(),
            "runtime_mcp_serve_tool_result_receipt_required"
        );
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

    #[test]
    fn rust_rejects_mcp_serve_without_authority_custody_or_containment() {
        let mut no_authority = request();
        no_authority.request = json!({});
        let error = RuntimeMcpServeToolCallPlanCore
            .plan(&no_authority)
            .expect_err("authority refs are required");
        assert_eq!(
            error.code(),
            "runtime_mcp_serve_tool_call_authority_required"
        );

        let mut no_custody = request();
        no_custody.request["authority_grant_refs"] =
            json!(["wallet.network://grant/mcp-serve/git.diff"]);
        no_custody.request["authority_receipt_refs"] =
            json!(["receipt://wallet.network/mcp-serve/git.diff"]);
        no_custody.request["custody_ref"] = Value::Null;
        let error = RuntimeMcpServeToolCallPlanCore
            .plan(&no_custody)
            .expect_err("custody ref is required");
        assert_eq!(error.code(), "runtime_mcp_serve_tool_call_custody_required");

        let mut no_containment = request();
        no_containment.request["containment_ref"] = Value::Null;
        let error = RuntimeMcpServeToolCallPlanCore
            .plan(&no_containment)
            .expect_err("containment ref is required");
        assert_eq!(
            error.code(),
            "runtime_mcp_serve_tool_call_containment_required"
        );
    }
}
