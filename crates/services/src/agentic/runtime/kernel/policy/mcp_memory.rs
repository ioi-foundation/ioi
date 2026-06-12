use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    MCP_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
    MCP_MANAGER_CATALOG_PROJECTION_RESULT_SCHEMA_VERSION,
    MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION,
    MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_RESULT_SCHEMA_VERSION,
    MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
    MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
    MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
    MCP_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION,
    MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION,
    MCP_SERVER_VALIDATION_INPUT_RESULT_SCHEMA_VERSION,
    MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION, MCP_SERVER_VALIDATION_RESULT_SCHEMA_VERSION,
    MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
    MEMORY_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
    MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
    MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION,
    THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    THREAD_MEMORY_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq)]
pub enum McpControlAgentStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum McpServerValidationError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum McpServerValidationInputError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum McpManagerValidationProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum McpManagerStatusProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum MemoryManagerValidationProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum MemoryManagerStatusProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpManagerCatalogProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpManagerCatalogSummaryProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreadMemoryAgentStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpControlAgentStateUpdateRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub agent: Value,
    pub control_kind: String,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpControlAgentStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub agent_id: String,
    pub updated_at: String,
    pub control: Value,
    pub agent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServerValidationRequest {
    pub schema_version: String,
    #[serde(default)]
    pub servers: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServerValidationRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub ok: bool,
    pub issue_count: usize,
    pub warning_count: usize,
    pub issues: Vec<Value>,
    pub warnings: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServerValidationInputRequest {
    pub schema_version: String,
    #[serde(default)]
    pub input: Value,
    #[serde(default)]
    pub workspace_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServerValidationInputRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub workspace_root: Option<String>,
    pub server_count: usize,
    pub servers: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerValidationProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub validation_schema_version: Option<String>,
    pub validation: Value,
    #[serde(default)]
    pub servers: Vec<Value>,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(default)]
    pub resources: Vec<Value>,
    #[serde(default)]
    pub prompts: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerValidationProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub ok: bool,
    pub status: String,
    pub server_count: usize,
    pub tool_count: usize,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub issue_count: usize,
    pub warning_count: usize,
    pub issues: Vec<Value>,
    pub warnings: Vec<Value>,
    pub servers: Vec<Value>,
    pub tools: Vec<Value>,
    pub resources: Vec<Value>,
    pub prompts: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerStatusProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    pub validation: Value,
    #[serde(default)]
    pub servers: Vec<Value>,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(default)]
    pub resources: Vec<Value>,
    #[serde(default)]
    pub prompts: Vec<Value>,
    #[serde(default)]
    pub enabled_tools: Vec<Value>,
    #[serde(default)]
    pub routes: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerStatusProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub server_count: usize,
    pub tool_count: usize,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub enabled_server_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_tool_count: Option<usize>,
    pub servers: Vec<Value>,
    pub tools: Vec<Value>,
    pub resources: Vec<Value>,
    pub prompts: Vec<Value>,
    pub validation: Value,
    pub routes: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryManagerValidationProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub validation_schema_version: Option<String>,
    #[serde(default)]
    pub projection: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryManagerValidationProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub ok: bool,
    pub status: String,
    pub issue_count: usize,
    pub warning_count: usize,
    pub record_count: usize,
    pub issues: Vec<Value>,
    pub warnings: Vec<Value>,
    pub policy: Value,
    pub paths: Value,
    pub filters: Value,
    pub records: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryManagerStatusProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    #[serde(default)]
    pub validation_schema_version: Option<String>,
    #[serde(default)]
    pub projection: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryManagerStatusProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub disabled: bool,
    pub injection_enabled: bool,
    pub read_only: bool,
    pub write_requires_approval: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_blocked_reason: Option<String>,
    pub record_count: usize,
    pub scope_count: usize,
    pub memory_key_count: usize,
    pub scopes: Vec<String>,
    pub memory_keys: Vec<String>,
    pub policy: Value,
    pub paths: Value,
    pub filters: Value,
    pub records: Vec<Value>,
    pub validation: Value,
    pub routes: Value,
    pub evidence_refs: Vec<String>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerCatalogProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    #[serde(default)]
    pub servers: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerCatalogProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub server_count: usize,
    pub tool_count: usize,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub enabled_tool_count: usize,
    pub servers: Vec<Value>,
    pub tools: Vec<Value>,
    pub resources: Vec<Value>,
    pub prompts: Vec<Value>,
    pub enabled_tools: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerCatalogSummaryProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    #[serde(default)]
    pub server: Value,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(default)]
    pub resources: Vec<Value>,
    #[serde(default)]
    pub prompts: Vec<Value>,
    #[serde(default)]
    pub live_mode: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub preview_limit: Option<usize>,
    #[serde(default)]
    pub deferred: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerCatalogSummaryProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub server_id: Option<String>,
    pub server_label: Option<String>,
    pub transport: Option<String>,
    pub execution_mode: Option<String>,
    pub catalog_hash: String,
    pub tool_count: usize,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub namespace_count: usize,
    pub namespaces: Vec<String>,
    pub preview_limit: usize,
    pub preview_tool_names: Vec<String>,
    pub deferred: bool,
    pub full_catalog_included: bool,
    pub error_code: Option<String>,
    pub search_route: String,
    pub fetch_route: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadMemoryAgentStateUpdateRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub agent: Value,
    pub control_kind: String,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadMemoryAgentStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub agent_id: String,
    pub updated_at: String,
    pub control: Value,
    pub agent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct McpMemoryCommandError {
    code: &'static str,
    message: String,
}

impl McpMemoryCommandError {
    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        self.message.as_str()
    }

    fn from_debug<E: std::fmt::Debug>(code: &'static str, error: E) -> Self {
        Self {
            code,
            message: format!("{error:?}"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct McpControlAgentStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: McpControlAgentStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct McpServerValidationBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: McpServerValidationRequest,
}

#[derive(Debug, Deserialize)]
pub struct McpServerValidationInputBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: McpServerValidationInputRequest,
}

#[derive(Debug, Deserialize)]
pub struct McpManagerStatusProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: McpManagerStatusProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub struct McpManagerValidationProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: McpManagerValidationProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub struct MemoryManagerStatusProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: MemoryManagerStatusProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub struct MemoryManagerValidationProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: MemoryManagerValidationProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub struct McpManagerCatalogProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: McpManagerCatalogProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub struct McpManagerCatalogSummaryProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: McpManagerCatalogSummaryProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub struct ThreadMemoryAgentStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ThreadMemoryAgentStateUpdateRequest,
}

pub fn plan_mcp_control_agent_state_update_response(
    request: McpControlAgentStateUpdateBridgeRequest,
) -> Result<Value, McpMemoryCommandError> {
    let record = McpControlAgentStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            McpMemoryCommandError::from_debug("mcp_control_agent_state_update_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_mcp_control_agent_state_update_command",
        "backend": mcp_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "control": record.control.clone(),
        "agent": record.agent.clone(),
    }))
}

pub fn validate_mcp_servers_response(
    request: McpServerValidationBridgeRequest,
) -> Result<Value, McpMemoryCommandError> {
    let record = McpServerValidationCore
        .validate(&request.request)
        .map_err(|error| {
            McpMemoryCommandError::from_debug("mcp_server_validation_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_mcp_server_validation_command",
        "backend": mcp_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "ok": record.ok,
        "issue_count": record.issue_count,
        "warning_count": record.warning_count,
        "issues": record.issues.clone(),
        "warnings": record.warnings.clone(),
    }))
}

pub fn project_mcp_server_validation_input_response(
    request: McpServerValidationInputBridgeRequest,
) -> Result<Value, McpMemoryCommandError> {
    let record = McpServerValidationInputCore
        .project(&request.request)
        .map_err(|error| {
            McpMemoryCommandError::from_debug("mcp_server_validation_input_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_mcp_server_validation_input_command",
        "backend": mcp_policy_backend(request.backend),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "status": record.status.clone(),
        "workspace_root": record.workspace_root.clone(),
        "server_count": record.server_count,
        "servers": record.servers.clone(),
    }))
}

pub fn plan_mcp_manager_status_projection_response(
    request: McpManagerStatusProjectionBridgeRequest,
) -> Result<Value, McpMemoryCommandError> {
    let record = McpManagerStatusProjectionCore
        .project(&request.request)
        .map_err(|error| {
            McpMemoryCommandError::from_debug("mcp_manager_status_projection_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_mcp_manager_status_projection_command",
        "backend": mcp_policy_backend(request.backend),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "status": record.status.clone(),
        "server_count": record.server_count,
        "tool_count": record.tool_count,
        "resource_count": record.resource_count,
        "prompt_count": record.prompt_count,
        "enabled_server_count": record.enabled_server_count,
        "enabled_tool_count": record.enabled_tool_count,
        "servers": record.servers.clone(),
        "tools": record.tools.clone(),
        "resources": record.resources.clone(),
        "prompts": record.prompts.clone(),
        "validation": record.validation.clone(),
        "routes": record.routes.clone(),
    }))
}

pub fn plan_mcp_manager_validation_projection_response(
    request: McpManagerValidationProjectionBridgeRequest,
) -> Result<Value, McpMemoryCommandError> {
    let record = McpManagerValidationProjectionCore
        .project(&request.request)
        .map_err(|error| {
            McpMemoryCommandError::from_debug("mcp_manager_validation_projection_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_mcp_manager_validation_projection_command",
        "backend": mcp_policy_backend(request.backend),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "ok": record.ok,
        "status": record.status.clone(),
        "server_count": record.server_count,
        "tool_count": record.tool_count,
        "resource_count": record.resource_count,
        "prompt_count": record.prompt_count,
        "issue_count": record.issue_count,
        "warning_count": record.warning_count,
        "issues": record.issues.clone(),
        "warnings": record.warnings.clone(),
        "servers": record.servers.clone(),
        "tools": record.tools.clone(),
        "resources": record.resources.clone(),
        "prompts": record.prompts.clone(),
    }))
}

pub fn plan_memory_manager_status_projection_response(
    request: MemoryManagerStatusProjectionBridgeRequest,
) -> Result<Value, McpMemoryCommandError> {
    let record = MemoryManagerStatusProjectionCore
        .project(&request.request)
        .map_err(|error| {
            McpMemoryCommandError::from_debug("memory_manager_status_projection_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_memory_manager_status_projection_command",
        "backend": mcp_policy_backend(request.backend),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "status": record.status.clone(),
        "disabled": record.disabled,
        "injection_enabled": record.injection_enabled,
        "read_only": record.read_only,
        "write_requires_approval": record.write_requires_approval,
        "write_blocked_reason": record.write_blocked_reason.clone(),
        "record_count": record.record_count,
        "scope_count": record.scope_count,
        "memory_key_count": record.memory_key_count,
        "scopes": record.scopes.clone(),
        "memory_keys": record.memory_keys.clone(),
        "policy": record.policy.clone(),
        "paths": record.paths.clone(),
        "filters": record.filters.clone(),
        "records": record.records.clone(),
        "validation": record.validation.clone(),
        "routes": record.routes.clone(),
        "evidence_refs": record.evidence_refs.clone(),
    }))
}

pub fn plan_memory_manager_validation_projection_response(
    request: MemoryManagerValidationProjectionBridgeRequest,
) -> Result<Value, McpMemoryCommandError> {
    let record = MemoryManagerValidationProjectionCore
        .project(&request.request)
        .map_err(|error| {
            McpMemoryCommandError::from_debug("memory_manager_validation_projection_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_memory_manager_validation_projection_command",
        "backend": mcp_policy_backend(request.backend),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "ok": record.ok,
        "status": record.status.clone(),
        "issue_count": record.issue_count,
        "warning_count": record.warning_count,
        "record_count": record.record_count,
        "issues": record.issues.clone(),
        "warnings": record.warnings.clone(),
        "policy": record.policy.clone(),
        "paths": record.paths.clone(),
        "filters": record.filters.clone(),
        "records": record.records.clone(),
    }))
}

pub fn plan_mcp_manager_catalog_projection_response(
    request: McpManagerCatalogProjectionBridgeRequest,
) -> Result<Value, McpMemoryCommandError> {
    let record = McpManagerCatalogProjectionCore
        .project(&request.request)
        .map_err(|error| {
            McpMemoryCommandError::from_debug("mcp_manager_catalog_projection_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_mcp_manager_catalog_projection_command",
        "backend": mcp_policy_backend(request.backend),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "status": record.status.clone(),
        "server_count": record.server_count,
        "tool_count": record.tool_count,
        "resource_count": record.resource_count,
        "prompt_count": record.prompt_count,
        "enabled_tool_count": record.enabled_tool_count,
        "servers": record.servers.clone(),
        "tools": record.tools.clone(),
        "resources": record.resources.clone(),
        "prompts": record.prompts.clone(),
        "enabled_tools": record.enabled_tools.clone(),
    }))
}

pub fn plan_mcp_manager_catalog_summary_projection_response(
    request: McpManagerCatalogSummaryProjectionBridgeRequest,
) -> Result<Value, McpMemoryCommandError> {
    let record = McpManagerCatalogSummaryProjectionCore
        .project(&request.request)
        .map_err(|error| {
            McpMemoryCommandError::from_debug(
                "mcp_manager_catalog_summary_projection_invalid",
                error,
            )
        })?;
    Ok(json!({
        "source": "rust_mcp_manager_catalog_summary_projection_command",
        "backend": mcp_policy_backend(request.backend),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "status": record.status.clone(),
        "server_id": record.server_id.clone(),
        "server_label": record.server_label.clone(),
        "transport": record.transport.clone(),
        "execution_mode": record.execution_mode.clone(),
        "catalog_hash": record.catalog_hash.clone(),
        "tool_count": record.tool_count,
        "resource_count": record.resource_count,
        "prompt_count": record.prompt_count,
        "namespace_count": record.namespace_count,
        "namespaces": record.namespaces.clone(),
        "preview_limit": record.preview_limit,
        "preview_tool_names": record.preview_tool_names.clone(),
        "deferred": record.deferred,
        "full_catalog_included": record.full_catalog_included,
        "error_code": record.error_code.clone(),
        "search_route": record.search_route.clone(),
        "fetch_route": record.fetch_route.clone(),
    }))
}

pub fn plan_thread_memory_agent_state_update_response(
    request: ThreadMemoryAgentStateUpdateBridgeRequest,
) -> Result<Value, McpMemoryCommandError> {
    let record = ThreadMemoryAgentStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            McpMemoryCommandError::from_debug("thread_memory_agent_state_update_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_thread_memory_agent_state_update_command",
        "backend": mcp_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "control": record.control.clone(),
        "agent": record.agent.clone(),
    }))
}

fn mcp_policy_backend(backend: Option<String>) -> String {
    backend.unwrap_or_else(|| "rust_policy".to_string())
}

#[derive(Debug, Default, Clone)]
pub struct McpControlAgentStateUpdateCore;

impl McpControlAgentStateUpdateCore {
    pub fn plan(
        &self,
        request: &McpControlAgentStateUpdateRequest,
    ) -> Result<McpControlAgentStateUpdateRecord, McpControlAgentStateUpdateError> {
        request.validate()?;
        let mut agent = object_value(&request.agent)
            .ok_or(McpControlAgentStateUpdateError::MissingField("agent"))?;
        let agent_id = optional_json_string(&Value::Object(agent.clone()), "id")
            .ok_or(McpControlAgentStateUpdateError::MissingField("agent.id"))?;
        let control_kind = optional_trimmed(Some(request.control_kind.as_str())).ok_or(
            McpControlAgentStateUpdateError::MissingField("control_kind"),
        )?;
        agent.insert(
            "updatedAt".to_string(),
            Value::String(request.created_at.clone()),
        );
        let control = json!({
            "control_kind": control_kind,
            "event_id": request.event_id,
            "seq": request.seq,
            "created_at": request.created_at,
        });

        Ok(McpControlAgentStateUpdateRecord {
            schema_version: MCP_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_mcp_control_agent_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: format!("thread.{control_kind}"),
            thread_id: request.thread_id.clone(),
            agent_id,
            updated_at: request.created_at.clone(),
            control,
            agent: Value::Object(agent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpServerValidationCore;

impl McpServerValidationCore {
    pub fn validate(
        &self,
        request: &McpServerValidationRequest,
    ) -> Result<McpServerValidationRecord, McpServerValidationError> {
        request.validate()?;
        let mut issues = Vec::new();
        let mut warnings = Vec::new();

        for server in &request.servers {
            let transport = normalize_mcp_transport(json_string_value(server, "transport"));
            let server_id = json_string_value(server, "id");
            let server_url = json_string_value(server, "server_url")
                .or_else(|| json_string_value(server, "endpoint"));

            if !matches!(transport.as_str(), "stdio" | "http" | "sse") {
                issues.push(mcp_validation_diagnostic(
                    "mcp_transport_unsupported",
                    "error",
                    server_id.as_deref(),
                    json!({
                        "transport": transport,
                        "message": "MCP server transport must be stdio, http, or sse."
                    }),
                ));
            }
            if transport == "stdio" && json_string_value(server, "command").is_none() {
                issues.push(mcp_validation_diagnostic(
                    "mcp_server_transport_missing",
                    "error",
                    server_id.as_deref(),
                    json!({
                        "message": "MCP stdio server must declare a command."
                    }),
                ));
            }
            if matches!(transport.as_str(), "http" | "sse") && server_url.is_none() {
                issues.push(mcp_validation_diagnostic(
                    "mcp_server_transport_missing",
                    "error",
                    server_id.as_deref(),
                    json!({
                        "message": "MCP HTTP/SSE server must declare a remote URL."
                    }),
                ));
            }
            if matches!(transport.as_str(), "http" | "sse")
                && server_url.as_deref().is_some_and(|url| !is_http_url(url))
            {
                issues.push(mcp_validation_diagnostic(
                    "mcp_remote_url_invalid",
                    "error",
                    server_id.as_deref(),
                    json!({
                        "message": "MCP HTTP/SSE server URL must use http:// or https://."
                    }),
                ));
            }
            if matches!(transport.as_str(), "http" | "sse")
                && json_bool_path(server, &["containment", "allow_network_egress"]) == Some(false)
            {
                issues.push(mcp_validation_diagnostic(
                    "mcp_remote_network_blocked",
                    "error",
                    server_id.as_deref(),
                    json!({
                        "message": "MCP HTTP/SSE server requires network egress in containment policy."
                    }),
                ));
            }

            if let Some(secret_refs) = server.get("secret_refs").and_then(Value::as_object) {
                for (key, value) in secret_refs {
                    if value.get("invalidVaultRef").and_then(Value::as_bool) == Some(true) {
                        issues.push(mcp_validation_diagnostic(
                            "mcp_secret_not_vault_ref",
                            "error",
                            server_id.as_deref(),
                            json!({
                                "key": key,
                                "message": "MCP env/header secrets must be represented as vault:// refs before activation."
                            }),
                        ));
                    }
                }
            }

            let allowed_tool_count = server
                .get("allowed_tools")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            if allowed_tool_count == 0 {
                warnings.push(mcp_validation_diagnostic(
                    "mcp_allowed_tools_empty",
                    "warning",
                    server_id.as_deref(),
                    json!({
                        "message": "No allowed_tools list is declared; invocation remains unavailable until tools are narrowed."
                    }),
                ));
            }
        }

        let ok = issues.is_empty();
        Ok(McpServerValidationRecord {
            schema_version: MCP_SERVER_VALIDATION_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_mcp_server_validation".to_string(),
            status: if ok { "pass" } else { "blocked" }.to_string(),
            ok,
            issue_count: issues.len(),
            warning_count: warnings.len(),
            issues,
            warnings,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpServerValidationInputCore;

impl McpServerValidationInputCore {
    pub fn project(
        &self,
        request: &McpServerValidationInputRequest,
    ) -> Result<McpServerValidationInputRecord, McpServerValidationInputError> {
        request.validate()?;
        let workspace_root = request
            .workspace_root
            .as_deref()
            .and_then(|value| optional_trimmed(Some(value)));
        let raw = request.input.get("mcp_json").unwrap_or(&request.input);
        let servers = raw
            .get("mcp_servers")
            .or_else(|| raw.get("servers"))
            .or_else(|| if raw.is_array() { Some(raw) } else { None });
        let records = match servers {
            Some(Value::Array(items)) => items
                .iter()
                .enumerate()
                .map(|(index, server)| {
                    let label = mcp_validation_server_label(server)
                        .unwrap_or_else(|| format!("server_{}", index + 1));
                    normalize_mcp_validation_server_record(
                        &label,
                        server,
                        workspace_root.as_deref(),
                        json_string_value(server, "source")
                            .as_deref()
                            .unwrap_or("validation_input"),
                        json_string_value(server, "source_scope")
                            .as_deref()
                            .unwrap_or("validation"),
                        json_string_value(server, "status")
                            .as_deref()
                            .unwrap_or("configured"),
                    )
                })
                .collect::<Vec<_>>(),
            Some(Value::Object(map)) => map
                .iter()
                .map(|(label, config)| {
                    normalize_mcp_validation_server_record(
                        label,
                        config,
                        workspace_root.as_deref(),
                        "validation_input",
                        "validation",
                        "configured",
                    )
                })
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };

        Ok(McpServerValidationInputRecord {
            schema_version: MCP_SERVER_VALIDATION_INPUT_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_mcp_server_validation_input".to_string(),
            status: "projected".to_string(),
            workspace_root,
            server_count: records.len(),
            servers: records,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpManagerValidationProjectionCore;

impl McpManagerValidationProjectionCore {
    pub fn project(
        &self,
        request: &McpManagerValidationProjectionRequest,
    ) -> Result<McpManagerValidationProjectionRecord, McpManagerValidationProjectionError> {
        request.validate()?;

        let ok = request
            .validation
            .get("ok")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let issues = request
            .validation
            .get("issues")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let warnings = request
            .validation
            .get("warnings")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        Ok(McpManagerValidationProjectionRecord {
            schema_version: request
                .validation_schema_version
                .clone()
                .unwrap_or_else(|| {
                    MCP_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string()
                }),
            object: "ioi.runtime_mcp_manager_validation".to_string(),
            ok,
            status: if ok { "pass" } else { "blocked" }.to_string(),
            server_count: request.servers.len(),
            tool_count: request.tools.len(),
            resource_count: request.resources.len(),
            prompt_count: request.prompts.len(),
            issue_count: issues.len(),
            warning_count: warnings.len(),
            issues,
            warnings,
            servers: request.servers.clone(),
            tools: request.tools.clone(),
            resources: request.resources.clone(),
            prompts: request.prompts.clone(),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpManagerCatalogProjectionCore;

impl McpManagerCatalogProjectionCore {
    pub fn project(
        &self,
        request: &McpManagerCatalogProjectionRequest,
    ) -> Result<McpManagerCatalogProjectionRecord, McpManagerCatalogProjectionError> {
        request.validate()?;

        let mut tools = Vec::new();
        let mut resources = Vec::new();
        let mut prompts = Vec::new();
        let mut enabled_tools = Vec::new();

        for server in &request.servers {
            let server_tools = mcp_catalog_tools_for_server(server);
            if server.get("enabled").and_then(Value::as_bool) != Some(false) {
                enabled_tools.extend(server_tools.clone());
            }
            tools.extend(server_tools);
            resources.extend(mcp_catalog_resources_for_server(server));
            prompts.extend(mcp_catalog_prompts_for_server(server));
        }

        resources.sort_by(|left, right| {
            mcp_catalog_resource_key(left).cmp(&mcp_catalog_resource_key(right))
        });
        prompts.sort_by(|left, right| {
            mcp_catalog_prompt_key(left).cmp(&mcp_catalog_prompt_key(right))
        });

        Ok(McpManagerCatalogProjectionRecord {
            schema_version: request.status_schema_version.clone().unwrap_or_else(|| {
                MCP_MANAGER_CATALOG_PROJECTION_RESULT_SCHEMA_VERSION.to_string()
            }),
            object: "ioi.runtime_mcp_manager_catalog_projection".to_string(),
            status: "projected".to_string(),
            server_count: request.servers.len(),
            tool_count: tools.len(),
            resource_count: resources.len(),
            prompt_count: prompts.len(),
            enabled_tool_count: enabled_tools.len(),
            servers: request.servers.clone(),
            tools,
            resources,
            prompts,
            enabled_tools,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpManagerCatalogSummaryProjectionCore;

impl McpManagerCatalogSummaryProjectionCore {
    pub fn project(
        &self,
        request: &McpManagerCatalogSummaryProjectionRequest,
    ) -> Result<McpManagerCatalogSummaryProjectionRecord, McpManagerCatalogSummaryProjectionError>
    {
        request.validate()?;

        let mut tool_names = request
            .tools
            .iter()
            .filter_map(|tool| mcp_catalog_field_string(tool, &["tool_name", "name"]))
            .collect::<Vec<_>>();
        tool_names.sort();

        let namespaces = mcp_tool_namespaces(&tool_names);
        let preview_limit = request.preview_limit.unwrap_or(25).clamp(1, 100);
        let deferred = request
            .deferred
            .unwrap_or_else(|| request.tools.len() > preview_limit);
        let preview_tool_names = tool_names
            .iter()
            .take(preview_limit.min(20))
            .cloned()
            .collect::<Vec<_>>();
        let catalog_hash = mcp_catalog_summary_hash(
            &request.server,
            &request.tools,
            &request.resources,
            &request.prompts,
        );

        Ok(McpManagerCatalogSummaryProjectionRecord {
            schema_version: request.status_schema_version.clone().unwrap_or_else(|| {
                MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_RESULT_SCHEMA_VERSION.to_string()
            }),
            object: "ioi.runtime_mcp_catalog_summary".to_string(),
            status: request
                .status
                .clone()
                .unwrap_or_else(|| "completed".to_string()),
            server_id: json_string_value(&request.server, "id"),
            server_label: json_string_value(&request.server, "label")
                .or_else(|| json_string_value(&request.server, "name"))
                .or_else(|| json_string_value(&request.server, "id")),
            transport: json_string_value(&request.server, "transport"),
            execution_mode: request.live_mode.clone(),
            catalog_hash,
            tool_count: request.tools.len(),
            resource_count: request.resources.len(),
            prompt_count: request.prompts.len(),
            namespace_count: namespaces.len(),
            namespaces,
            preview_limit,
            preview_tool_names,
            deferred,
            full_catalog_included: !deferred,
            error_code: request.error_code.clone(),
            search_route: "/v1/mcp/tools/search".to_string(),
            fetch_route: "/v1/mcp/tools/{tool_id}".to_string(),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpManagerStatusProjectionCore;

impl McpManagerStatusProjectionCore {
    pub fn project(
        &self,
        request: &McpManagerStatusProjectionRequest,
    ) -> Result<McpManagerStatusProjectionRecord, McpManagerStatusProjectionError> {
        request.validate()?;

        let server_count = request.servers.len();
        let tool_count = request.tools.len();
        let resource_count = request.resources.len();
        let prompt_count = request.prompts.len();
        let enabled_server_count = request
            .servers
            .iter()
            .filter(|server| server.get("enabled").and_then(Value::as_bool) != Some(false))
            .count();
        let enabled_tool_count = if request.enabled_tools.is_empty() {
            None
        } else {
            Some(request.enabled_tools.len())
        };
        let ok = request
            .validation
            .get("ok")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let validation = extend_json_object(
            request.validation.clone(),
            json!({
                "server_count": server_count,
                "tool_count": tool_count,
                "resource_count": resource_count,
                "prompt_count": prompt_count,
                "servers": request.servers.clone(),
                "tools": request.tools.clone(),
                "resources": request.resources.clone(),
                "prompts": request.prompts.clone(),
            }),
        );

        Ok(McpManagerStatusProjectionRecord {
            schema_version: request
                .status_schema_version
                .clone()
                .unwrap_or_else(|| MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION.to_string()),
            object: "ioi.runtime_mcp_manager_status".to_string(),
            status: if ok { "ready" } else { "needs_review" }.to_string(),
            server_count,
            tool_count,
            resource_count,
            prompt_count,
            enabled_server_count,
            enabled_tool_count,
            servers: request.servers.clone(),
            tools: request.tools.clone(),
            resources: request.resources.clone(),
            prompts: request.prompts.clone(),
            validation,
            routes: request.routes.clone(),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemoryManagerValidationProjectionCore;

impl MemoryManagerValidationProjectionCore {
    pub fn project(
        &self,
        request: &MemoryManagerValidationProjectionRequest,
    ) -> Result<MemoryManagerValidationProjectionRecord, MemoryManagerValidationProjectionError>
    {
        request.validate()?;
        let records = memory_projection_records(&request.projection);
        let policy = memory_projection_object(&request.projection, "policy");
        let paths = memory_projection_object(&request.projection, "paths");
        let filters = memory_projection_object(&request.projection, "filters");
        let mut issues = Vec::new();
        let mut warnings = Vec::new();

        validate_memory_manager_policy(&policy, &mut issues, &mut warnings);
        validate_memory_manager_paths(&paths, &mut issues, &mut warnings);
        for record in &records {
            validate_memory_manager_record(record, &mut issues, &mut warnings);
        }

        let ok = issues.is_empty();
        Ok(MemoryManagerValidationProjectionRecord {
            schema_version: request
                .validation_schema_version
                .clone()
                .unwrap_or_else(|| {
                    MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string()
                }),
            object: "ioi.runtime_memory_manager_validation".to_string(),
            ok,
            status: if ok { "pass" } else { "blocked" }.to_string(),
            issue_count: issues.len(),
            warning_count: warnings.len(),
            record_count: records.len(),
            issues,
            warnings,
            policy,
            paths,
            filters,
            records,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemoryManagerStatusProjectionCore;

impl MemoryManagerStatusProjectionCore {
    pub fn project(
        &self,
        request: &MemoryManagerStatusProjectionRequest,
    ) -> Result<MemoryManagerStatusProjectionRecord, MemoryManagerStatusProjectionError> {
        request.validate()?;
        let validation = MemoryManagerValidationProjectionCore
            .project(&MemoryManagerValidationProjectionRequest {
                schema_version: MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION
                    .to_string(),
                validation_schema_version: request.validation_schema_version.clone(),
                projection: request.projection.clone(),
            })
            .map_err(|error| match error {
                MemoryManagerValidationProjectionError::InvalidSchemaVersion {
                    expected,
                    actual,
                } => MemoryManagerStatusProjectionError::InvalidSchemaVersion { expected, actual },
            })?;
        let records = memory_projection_records(&request.projection);
        let policy = memory_projection_object(&request.projection, "policy");
        let paths = memory_projection_object(&request.projection, "paths");
        let filters = memory_projection_object(&request.projection, "filters");
        let disabled = json_bool_value(&policy, "disabled").unwrap_or(false);
        let injection_enabled = json_bool_value(&policy, "injection_enabled").unwrap_or(true);
        let read_only = json_bool_value(&policy, "read_only").unwrap_or(false);
        let write_requires_approval =
            json_bool_value(&policy, "write_requires_approval").unwrap_or(false);
        let scopes = memory_unique_strings(
            records
                .iter()
                .filter_map(|record| json_string_value(record, "scope"))
                .collect(),
        );
        let memory_keys = memory_unique_strings(
            records
                .iter()
                .filter_map(|record| json_string_value(record, "memory_key"))
                .collect(),
        );
        let write_blocked_reason = if disabled {
            Some("memory_disabled".to_string())
        } else if read_only {
            Some("memory_read_only".to_string())
        } else if write_requires_approval {
            Some("memory_write_requires_approval".to_string())
        } else {
            None
        };
        let status = if validation.ok {
            if disabled {
                "disabled"
            } else {
                "ready"
            }
        } else {
            "needs_review"
        };
        let validation_value =
            serde_json::to_value(&validation).unwrap_or_else(|_| Value::Object(Default::default()));

        Ok(MemoryManagerStatusProjectionRecord {
            schema_version: request.status_schema_version.clone().unwrap_or_else(|| {
                MEMORY_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION.to_string()
            }),
            object: "ioi.runtime_memory_manager_status".to_string(),
            status: status.to_string(),
            disabled,
            injection_enabled,
            read_only,
            write_requires_approval,
            write_blocked_reason,
            record_count: records.len(),
            scope_count: scopes.len(),
            memory_key_count: memory_keys.len(),
            scopes,
            memory_keys,
            policy: policy.clone(),
            paths: paths.clone(),
            filters,
            records: records.clone(),
            validation: validation_value,
            routes: json!({
                "records": "/v1/threads/{thread_id}/memory",
                "status": "/v1/threads/{thread_id}/memory/status",
                "validate": "/v1/threads/{thread_id}/memory/validate",
                "policy": "/v1/threads/{thread_id}/memory/policy",
                "path": "/v1/threads/{thread_id}/memory/path",
                "remember": "/v1/threads/{thread_id}/memory",
                "edit": "/v1/threads/{thread_id}/memory/{memory_id}",
                "delete": "/v1/threads/{thread_id}/memory/{memory_id}",
            }),
            evidence_refs: memory_status_evidence_refs(&policy, &paths, &records),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct ThreadMemoryAgentStateUpdateCore;

impl ThreadMemoryAgentStateUpdateCore {
    pub fn plan(
        &self,
        request: &ThreadMemoryAgentStateUpdateRequest,
    ) -> Result<ThreadMemoryAgentStateUpdateRecord, ThreadMemoryAgentStateUpdateError> {
        request.validate()?;
        let mut agent = object_value(&request.agent)
            .ok_or(ThreadMemoryAgentStateUpdateError::MissingField("agent"))?;
        let agent_id = optional_json_string(&Value::Object(agent.clone()), "id")
            .ok_or(ThreadMemoryAgentStateUpdateError::MissingField("agent.id"))?;
        let control_kind = optional_trimmed(Some(request.control_kind.as_str())).ok_or(
            ThreadMemoryAgentStateUpdateError::MissingField("control_kind"),
        )?;
        agent.insert(
            "updatedAt".to_string(),
            Value::String(request.created_at.clone()),
        );
        let control = json!({
            "control_kind": control_kind,
            "event_id": request.event_id,
            "seq": request.seq,
            "created_at": request.created_at,
        });

        Ok(ThreadMemoryAgentStateUpdateRecord {
            schema_version: THREAD_MEMORY_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_thread_memory_agent_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: format!("thread.{control_kind}"),
            thread_id: request.thread_id.clone(),
            agent_id,
            updated_at: request.created_at.clone(),
            control,
            agent: Value::Object(agent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

impl McpControlAgentStateUpdateRequest {
    pub fn validate(&self) -> Result<(), McpControlAgentStateUpdateError> {
        if self.schema_version != MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(McpControlAgentStateUpdateError::InvalidSchemaVersion {
                expected: MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(McpControlAgentStateUpdateError::MissingField("thread_id"));
        }
        if !self.agent.is_object() {
            return Err(McpControlAgentStateUpdateError::MissingField("agent"));
        }
        if optional_trimmed(Some(self.control_kind.as_str())).is_none() {
            return Err(McpControlAgentStateUpdateError::MissingField(
                "control_kind",
            ));
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(McpControlAgentStateUpdateError::MissingField("event_id"));
        }
        if self.seq == 0 {
            return Err(McpControlAgentStateUpdateError::MissingField("seq"));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(McpControlAgentStateUpdateError::MissingField("created_at"));
        }
        let agent_value = Value::Object(object_value(&self.agent).unwrap_or_default());
        if optional_json_string(&agent_value, "id").is_none() {
            return Err(McpControlAgentStateUpdateError::MissingField("agent.id"));
        }
        Ok(())
    }
}

impl McpServerValidationRequest {
    pub fn validate(&self) -> Result<(), McpServerValidationError> {
        if self.schema_version != MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION {
            return Err(McpServerValidationError::InvalidSchemaVersion {
                expected: MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl McpServerValidationInputRequest {
    pub fn validate(&self) -> Result<(), McpServerValidationInputError> {
        if self.schema_version != MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION {
            return Err(McpServerValidationInputError::InvalidSchemaVersion {
                expected: MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl McpManagerStatusProjectionRequest {
    pub fn validate(&self) -> Result<(), McpManagerStatusProjectionError> {
        if self.schema_version != MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(McpManagerStatusProjectionError::InvalidSchemaVersion {
                expected: MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl McpManagerValidationProjectionRequest {
    pub fn validate(&self) -> Result<(), McpManagerValidationProjectionError> {
        if self.schema_version != MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(McpManagerValidationProjectionError::InvalidSchemaVersion {
                expected: MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl MemoryManagerValidationProjectionRequest {
    pub fn validate(&self) -> Result<(), MemoryManagerValidationProjectionError> {
        if self.schema_version != MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(
                MemoryManagerValidationProjectionError::InvalidSchemaVersion {
                    expected: MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        Ok(())
    }
}

impl MemoryManagerStatusProjectionRequest {
    pub fn validate(&self) -> Result<(), MemoryManagerStatusProjectionError> {
        if self.schema_version != MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(MemoryManagerStatusProjectionError::InvalidSchemaVersion {
                expected: MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl McpManagerCatalogProjectionRequest {
    pub fn validate(&self) -> Result<(), McpManagerCatalogProjectionError> {
        if self.schema_version != MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(McpManagerCatalogProjectionError::InvalidSchemaVersion {
                expected: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl McpManagerCatalogSummaryProjectionRequest {
    pub fn validate(&self) -> Result<(), McpManagerCatalogSummaryProjectionError> {
        if self.schema_version != MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(
                McpManagerCatalogSummaryProjectionError::InvalidSchemaVersion {
                    expected: MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        Ok(())
    }
}

impl ThreadMemoryAgentStateUpdateRequest {
    pub fn validate(&self) -> Result<(), ThreadMemoryAgentStateUpdateError> {
        if self.schema_version != THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(ThreadMemoryAgentStateUpdateError::InvalidSchemaVersion {
                expected: THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField("thread_id"));
        }
        if !self.agent.is_object() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField("agent"));
        }
        if optional_trimmed(Some(self.control_kind.as_str())).is_none() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField(
                "control_kind",
            ));
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField("event_id"));
        }
        if self.seq == 0 {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField("seq"));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField(
                "created_at",
            ));
        }
        let agent_value = Value::Object(object_value(&self.agent).unwrap_or_default());
        if optional_json_string(&agent_value, "id").is_none() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField("agent.id"));
        }
        Ok(())
    }
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn safe_id(value: &str) -> String {
    let mut output = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    while output.contains("__") {
        output = output.replace("__", "_");
    }
    output.trim_matches('_').to_string()
}

fn mcp_catalog_server_label(server: &Value) -> String {
    optional_trimmed(server.get("label").and_then(Value::as_str))
        .or_else(|| optional_trimmed(server.get("name").and_then(Value::as_str)))
        .or_else(|| optional_trimmed(server.get("id").and_then(Value::as_str)))
        .unwrap_or_else(|| "mcp".to_string())
}

fn mcp_catalog_server_status(server: &Value) -> String {
    if server.get("enabled").and_then(Value::as_bool) == Some(false) {
        "disabled".to_string()
    } else {
        optional_trimmed(server.get("status").and_then(Value::as_str))
            .unwrap_or_else(|| "configured".to_string())
    }
}

fn mcp_catalog_server_transport(server: &Value) -> String {
    optional_trimmed(server.get("transport").and_then(Value::as_str))
        .unwrap_or_else(|| "stdio".to_string())
}

fn mcp_catalog_items(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter(|item| !item.is_null())
            .cloned()
            .collect(),
        Some(Value::Object(map)) => map
            .iter()
            .map(|(name, entry)| {
                if let Value::Object(entry_map) = entry {
                    let mut item = serde_json::Map::new();
                    item.insert("name".to_string(), Value::String(name.clone()));
                    item.extend(entry_map.clone());
                    Value::Object(item)
                } else {
                    json!({
                        "name": name,
                        "uri": match entry {
                            Value::Null => name.clone(),
                            Value::String(text) => text.clone(),
                            other => other.to_string(),
                        },
                    })
                }
            })
            .collect(),
        Some(value) if !value.is_null() => vec![value.clone()],
        _ => Vec::new(),
    }
}

fn mcp_catalog_value_string(value: &Value) -> Option<String> {
    value
        .as_str()
        .and_then(|text| optional_trimmed(Some(text)))
        .or_else(|| match value {
            Value::Null | Value::Array(_) | Value::Object(_) => None,
            other => optional_trimmed(Some(other.to_string().as_str())),
        })
}

fn mcp_catalog_field_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .and_then(|text| optional_trimmed(Some(text)))
    })
}

fn mcp_catalog_tools_for_server(server: &Value) -> Vec<Value> {
    let server_label = mcp_catalog_server_label(server);
    let safe_server = safe_id(&server_label);
    let server_id = server.get("id").cloned().unwrap_or(Value::Null);
    let status = mcp_catalog_server_status(server);
    let transport = mcp_catalog_server_transport(server);

    mcp_catalog_items(server.get("allowed_tools"))
        .into_iter()
        .map(|tool| {
            let tool_name = mcp_catalog_field_string(&tool, &["name", "tool_name", "toolName"])
                .or_else(|| mcp_catalog_value_string(&tool))
                .unwrap_or_else(|| "tool".to_string());
            let safe_tool = safe_id(&tool_name);
            json!({
                "schema_version": MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
                "stable_tool_id": format!("mcp.{safe_server}.{safe_tool}"),
                "display_name": format!("{server_label}.{tool_name}"),
                "pack": "mcp",
                "server_id": server_id.clone(),
                "server_label": server_label,
                "tool_name": tool_name,
                "description": mcp_catalog_field_string(&tool, &["description"]),
                "status": status,
                "transport": transport,
                "primitive_capabilities": ["prim:connector.invoke"],
                "authority_scope_requirements": ["scope:mcp.invoke"],
                "effect_class": "connector_call",
                "risk_domain": "connector",
                "input_schema": tool.get("input_schema").or_else(|| tool.get("inputSchema")).cloned().unwrap_or_else(|| json!({ "type": "object" })),
                "output_schema": tool.get("output_schema").or_else(|| tool.get("outputSchema")).cloned().unwrap_or_else(|| json!({ "type": "object" })),
                "evidence_requirements": ["mcp_containment_receipt"],
                "workflow_node_type": "McpToolNode",
                "workflow_config_fields": ["server_id", "tool_name", "allowed_tools", "containment"],
                "workflow_node_id": format!("runtime.mcp-tool.{safe_server}.{safe_tool}"),
                "receipt_refs": [],
            })
        })
        .collect()
}

fn mcp_catalog_resources_for_server(server: &Value) -> Vec<Value> {
    let server_label = mcp_catalog_server_label(server);
    let safe_server = safe_id(&server_label);
    let server_id = server.get("id").cloned().unwrap_or(Value::Null);
    let status = mcp_catalog_server_status(server);
    let transport = mcp_catalog_server_transport(server);

    mcp_catalog_items(
        server
            .get("resources")
            .or_else(|| server.get("allowed_resources")),
    )
    .into_iter()
    .map(|resource| {
        let uri = mcp_catalog_field_string(&resource, &["uri", "url", "resource_uri"])
            .or_else(|| mcp_catalog_value_string(&resource))
            .unwrap_or_else(|| format!("resource://{safe_server}/unknown"));
        let name =
            mcp_catalog_field_string(&resource, &["name", "title"]).unwrap_or_else(|| uri.clone());
        let safe_uri = safe_id(&uri);
        json!({
            "schema_version": MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
            "stable_resource_id": format!("mcp.{safe_server}.resource.{safe_uri}"),
            "display_name": format!("{server_label}.{name}"),
            "pack": "mcp",
            "server_id": server_id.clone(),
            "server_label": server_label,
            "uri": uri,
            "name": name,
            "description": mcp_catalog_field_string(&resource, &["description"]),
            "mime_type": mcp_catalog_field_string(&resource, &["mime_type", "mimeType"]),
            "status": status,
            "transport": transport,
            "primitive_capabilities": ["prim:connector.resource.read"],
            "authority_scope_requirements": ["scope:mcp.resource.read"],
            "effect_class": "read_only_catalog",
            "risk_domain": "connector",
            "evidence_requirements": ["mcp_resource_catalog_receipt"],
            "workflow_node_type": "McpResourceNode",
            "workflow_config_fields": ["server_id", "uri", "containment"],
            "workflow_node_id": format!("runtime.mcp-resource.{safe_server}.{safe_uri}"),
            "receipt_refs": [],
        })
    })
    .collect()
}

fn mcp_catalog_prompts_for_server(server: &Value) -> Vec<Value> {
    let server_label = mcp_catalog_server_label(server);
    let safe_server = safe_id(&server_label);
    let server_id = server.get("id").cloned().unwrap_or(Value::Null);
    let status = mcp_catalog_server_status(server);
    let transport = mcp_catalog_server_transport(server);

    mcp_catalog_items(
        server
            .get("prompts")
            .or_else(|| server.get("allowed_prompts")),
    )
    .into_iter()
    .map(|prompt| {
        let name = mcp_catalog_field_string(&prompt, &["name", "title"])
            .or_else(|| mcp_catalog_value_string(&prompt))
            .unwrap_or_else(|| "prompt".to_string());
        let safe_prompt = safe_id(&name);
        let arguments = prompt
            .get("arguments")
            .filter(|value| value.is_array())
            .cloned()
            .unwrap_or_else(|| json!([]));
        json!({
            "schema_version": MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
            "stable_prompt_id": format!("mcp.{safe_server}.prompt.{safe_prompt}"),
            "display_name": format!("{server_label}.{name}"),
            "pack": "mcp",
            "server_id": server_id.clone(),
            "server_label": server_label,
            "name": name,
            "description": mcp_catalog_field_string(&prompt, &["description"]),
            "arguments": arguments.clone(),
            "prompt_arguments": arguments,
            "status": status,
            "transport": transport,
            "primitive_capabilities": ["prim:connector.prompt.read"],
            "authority_scope_requirements": ["scope:mcp.prompt.read"],
            "effect_class": "read_only_catalog",
            "risk_domain": "connector",
            "evidence_requirements": ["mcp_prompt_catalog_receipt"],
            "workflow_node_type": "McpPromptNode",
            "workflow_config_fields": ["server_id", "prompt_name", "containment"],
            "workflow_node_id": format!("runtime.mcp-prompt.{safe_server}.{safe_prompt}"),
            "receipt_refs": [],
        })
    })
    .collect()
}

fn mcp_catalog_resource_key(resource: &Value) -> String {
    mcp_catalog_field_string(resource, &["stable_resource_id"]).unwrap_or_else(|| {
        format!(
            "{}:{}",
            mcp_catalog_field_string(resource, &["server_id"])
                .unwrap_or_else(|| "mcp.unknown".to_string()),
            mcp_catalog_field_string(resource, &["uri"]).unwrap_or_else(|| "resource".to_string())
        )
    })
}

fn mcp_catalog_prompt_key(prompt: &Value) -> String {
    mcp_catalog_field_string(prompt, &["stable_prompt_id"]).unwrap_or_else(|| {
        format!(
            "{}:{}",
            mcp_catalog_field_string(prompt, &["server_id"])
                .unwrap_or_else(|| "mcp.unknown".to_string()),
            mcp_catalog_field_string(prompt, &["name"]).unwrap_or_else(|| "prompt".to_string())
        )
    })
}

fn mcp_catalog_summary_hash(
    server: &Value,
    tools: &[Value],
    resources: &[Value],
    prompts: &[Value],
) -> String {
    let payload = json!({
        "server_id": json_string_value(server, "id"),
        "tools": tools.iter().map(|tool| {
            json!({
                "stable_tool_id": json_string_value(tool, "stable_tool_id"),
                "tool_name": json_string_value(tool, "tool_name"),
                "description": json_string_value(tool, "description"),
                "input_schema": tool.get("input_schema").cloned().unwrap_or(Value::Null),
            })
        }).collect::<Vec<_>>(),
        "resources": resources.iter().map(|resource| {
            json!({
                "stable_resource_id": json_string_value(resource, "stable_resource_id"),
                "uri": json_string_value(resource, "uri"),
                "name": json_string_value(resource, "name"),
            })
        }).collect::<Vec<_>>(),
        "prompts": prompts.iter().map(|prompt| {
            json!({
                "stable_prompt_id": json_string_value(prompt, "stable_prompt_id"),
                "name": json_string_value(prompt, "name"),
            })
        }).collect::<Vec<_>>(),
    });
    let bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| payload.to_string().into_bytes());
    hex::encode(Sha256::digest(bytes))
}

fn mcp_tool_namespaces(tool_names: &[String]) -> Vec<String> {
    let mut namespaces = tool_names
        .iter()
        .filter_map(|name| {
            let namespace = name
                .split("__")
                .next()
                .unwrap_or(name)
                .split(['.', ':', '/', '-'])
                .next()
                .unwrap_or(name);
            optional_trimmed(Some(namespace))
        })
        .collect::<Vec<_>>();
    namespaces.sort();
    namespaces.dedup();
    namespaces.truncate(25);
    namespaces
}

fn object_value(value: &Value) -> Option<serde_json::Map<String, Value>> {
    value.as_object().cloned()
}

fn json_string_value(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| optional_trimmed(Some(value)))
}

fn optional_json_string(value: &Value, key: &str) -> Option<String> {
    json_string_value(value, key)
}

fn json_bool_value(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn extend_json_object(base: Value, extension: Value) -> Value {
    let mut object = match base {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    if let Value::Object(extension) = extension {
        object.extend(extension);
    }
    Value::Object(object)
}

fn memory_projection_object(projection: &Value, key: &str) -> Value {
    projection
        .get(key)
        .and_then(Value::as_object)
        .cloned()
        .map(Value::Object)
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()))
}

fn memory_projection_records(projection: &Value) -> Vec<Value> {
    projection
        .get("records")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn validate_memory_manager_policy(
    policy: &Value,
    issues: &mut Vec<Value>,
    warnings: &mut Vec<Value>,
) {
    if !policy.is_object() {
        issues.push(memory_diagnostic(
            "memory_policy_missing",
            "error",
            "Memory status requires an effective policy.",
            json!({}),
        ));
        return;
    }
    if json_string_value(policy, "id").is_none() {
        issues.push(memory_diagnostic(
            "memory_policy_id_missing",
            "error",
            "Memory policy must have a stable id.",
            json!({}),
        ));
    }
    if let Some(scope) = json_string_value(policy, "scope") {
        if !matches!(
            scope.as_str(),
            "global" | "workspace" | "thread" | "workflow" | "subagent"
        ) {
            issues.push(memory_diagnostic(
                "memory_policy_scope_invalid",
                "error",
                "Memory policy scope is not supported.",
                json!({ "memory_scope": scope }),
            ));
        }
    }
    if let Some(redaction) = json_string_value(policy, "redaction") {
        if !matches!(redaction.as_str(), "none" | "redacted") {
            issues.push(memory_diagnostic(
                "memory_policy_redaction_invalid",
                "error",
                "Memory policy redaction must be none or redacted.",
                json!({}),
            ));
        }
    }
    if let Some(retention) = json_string_value(policy, "retention") {
        if !matches!(retention.as_str(), "persistent" | "session" | "ephemeral") {
            warnings.push(memory_diagnostic(
                "memory_policy_retention_unknown",
                "warning",
                "Memory retention is not one of the governed presets.",
                json!({}),
            ));
        }
    }
    if let Some(inheritance) = json_string_value(policy, "subagent_inheritance") {
        if !matches!(
            inheritance.as_str(),
            "none" | "explicit" | "read_only" | "full"
        ) {
            issues.push(memory_diagnostic(
                "memory_subagent_inheritance_invalid",
                "error",
                "Subagent memory inheritance mode is not supported.",
                json!({}),
            ));
        }
    }
    let disabled = json_bool_value(policy, "disabled").unwrap_or(false);
    let injection_enabled = json_bool_value(policy, "injection_enabled").unwrap_or(true);
    let read_only = json_bool_value(policy, "read_only").unwrap_or(false);
    let write_requires_approval =
        json_bool_value(policy, "write_requires_approval").unwrap_or(false);
    if disabled && injection_enabled {
        warnings.push(memory_diagnostic(
            "memory_disabled_with_injection_enabled",
            "warning",
            "Disabled memory should also disable prompt injection.",
            json!({}),
        ));
    }
    if read_only && write_requires_approval {
        warnings.push(memory_diagnostic(
            "memory_read_only_with_approval_required",
            "warning",
            "Read-only memory makes write approval unreachable.",
            json!({}),
        ));
    }
}

fn validate_memory_manager_paths(
    paths: &Value,
    issues: &mut Vec<Value>,
    warnings: &mut Vec<Value>,
) {
    for (canonical, label) in [("records_path", "records"), ("policies_path", "policies")] {
        let value = json_string_value(paths, canonical);
        if value.is_none() {
            issues.push(memory_diagnostic(
                &format!("memory_{label}_path_missing"),
                "error",
                &format!("Memory {label} path is missing."),
                json!({}),
            ));
            continue;
        }
        warnings.push(memory_diagnostic(
            &format!("memory_{label}_path_unverified_by_rust_core"),
            "warning",
            &format!("Memory {label} path is projected by Rust but disk access remains outside this pure projection core."),
            json!({ "path": value }),
        ));
    }
}

fn validate_memory_manager_record(
    record: &Value,
    issues: &mut Vec<Value>,
    warnings: &mut Vec<Value>,
) {
    if !record.is_object() {
        issues.push(memory_diagnostic(
            "memory_record_invalid",
            "error",
            "Memory record must be an object.",
            json!({}),
        ));
        return;
    }
    let record_id = json_string_value(record, "id");
    if record_id.is_none() {
        issues.push(memory_diagnostic(
            "memory_record_id_missing",
            "error",
            "Memory record id is required.",
            json!({}),
        ));
    }
    if json_string_value(record, "fact").is_none() {
        issues.push(memory_diagnostic(
            "memory_record_fact_missing",
            "error",
            "Memory record fact text is required.",
            json!({ "memory_record_id": record_id.clone() }),
        ));
    }
    if let Some(scope) = json_string_value(record, "scope") {
        if !matches!(
            scope.as_str(),
            "global" | "workspace" | "thread" | "workflow" | "subagent"
        ) {
            issues.push(memory_diagnostic(
                "memory_record_scope_invalid",
                "error",
                "Memory record scope is not supported.",
                json!({
                    "memory_record_id": record_id.clone(),
                    "memory_scope": scope,
                }),
            ));
        }
    }
    let fact_hash = json_string_value(record, "fact_hash");
    if json_string_value(record, "redaction").as_deref() == Some("redacted") && fact_hash.is_none()
    {
        warnings.push(memory_diagnostic(
            "memory_record_redacted_hash_missing",
            "warning",
            "Redacted memory records should include a fact hash.",
            json!({ "memory_record_id": record_id }),
        ));
    }
}

fn memory_diagnostic(code: &str, severity: &str, message: &str, extra: Value) -> Value {
    extend_json_object(
        json!({
            "code": code,
            "severity": severity,
            "message": message,
        }),
        extra,
    )
}

fn memory_unique_strings(values: Vec<String>) -> Vec<String> {
    let mut values: Vec<String> = values
        .into_iter()
        .filter_map(|value| optional_trimmed(Some(value.as_str())))
        .collect();
    values.sort();
    values.dedup();
    values
}

fn memory_status_evidence_refs(policy: &Value, paths: &Value, records: &[Value]) -> Vec<String> {
    let mut refs = vec![
        "runtime_memory_manager",
        "memory.status",
        "rust_memory_manager_status_projection_command",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    if let Some(policy_id) = json_string_value(policy, "id") {
        refs.push(policy_id);
    }
    if let Some(effective_policy_id) = json_string_value(paths, "effective_policy_id") {
        refs.push(effective_policy_id);
    }
    for record in records {
        if let Some(record_id) = json_string_value(record, "id") {
            refs.push(record_id);
        }
    }
    memory_unique_strings(refs)
}

fn json_bool_path(value: &Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_bool()
}

fn normalize_mcp_transport(value: Option<String>) -> String {
    match value
        .unwrap_or_else(|| "stdio".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "streamable_http" | "streamable-http" | "http-json-rpc" => "http".to_string(),
        "server-sent-events" | "eventsource" => "sse".to_string(),
        other => other.to_string(),
    }
}

fn is_http_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn mcp_validation_diagnostic(
    code: &str,
    severity: &str,
    server_id: Option<&str>,
    detail: Value,
) -> Value {
    let mut diagnostic = object_value(&detail).unwrap_or_default();
    diagnostic.insert("code".to_string(), Value::String(code.to_string()));
    diagnostic.insert("severity".to_string(), Value::String(severity.to_string()));
    diagnostic.insert(
        "server_id".to_string(),
        server_id
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    Value::Object(diagnostic)
}

fn mcp_validation_server_label(server: &Value) -> Option<String> {
    json_string_value(server, "label")
        .or_else(|| json_string_value(server, "name"))
        .or_else(|| json_string_value(server, "id"))
}

fn normalize_mcp_validation_server_record(
    label: &str,
    config: &Value,
    workspace_root: Option<&str>,
    source: &str,
    source_scope: &str,
    status: &str,
) -> Value {
    let name = optional_trimmed(Some(label))
        .or_else(|| json_string_value(config, "label"))
        .or_else(|| json_string_value(config, "name"))
        .unwrap_or_else(|| "mcp".to_string());
    let id = json_string_value(config, "id").unwrap_or_else(|| format!("mcp.{}", safe_id(&name)));
    let server_url = json_string_value(config, "server_url")
        .or_else(|| json_string_value(config, "url"))
        .or_else(|| json_string_value(config, "endpoint"));
    let transport = normalize_mcp_transport(json_string_value(config, "transport").or_else(|| {
        server_url.as_ref().map(|url| {
            if url.contains("/sse") {
                "sse".to_string()
            } else {
                "http".to_string()
            }
        })
    }));
    let enabled = config.get("enabled").and_then(Value::as_bool) != Some(false)
        && config.get("disabled").and_then(Value::as_bool) != Some(true);
    let allowed_tools = normalize_mcp_allowed_tools(config);
    let resources = normalize_mcp_catalog_items_for_validation(
        config
            .get("resources")
            .or_else(|| config.get("allowed_resources")),
        "resource",
    );
    let prompts = normalize_mcp_catalog_items_for_validation(
        config
            .get("prompts")
            .or_else(|| config.get("allowed_prompts")),
        "prompt",
    );
    let headers = config
        .get("headers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let env = config
        .get("env")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let header_secret_refs = public_mcp_secret_refs(&headers, "header");
    let env_secret_refs = public_mcp_secret_refs(&env, "env");
    let secret_refs = merge_json_objects(&env_secret_refs, &header_secret_refs);
    let header_names = {
        let mut names = headers.keys().cloned().collect::<Vec<_>>();
        names.sort();
        names
    };
    let containment_mode = json_string_value(config, "containment_mode")
        .or_else(|| json_path_string(config, &["containment", "mode"]))
        .unwrap_or_else(|| "sandboxed".to_string());
    let allow_network_egress = config
        .get("allow_network_egress")
        .and_then(Value::as_bool)
        .or_else(|| json_bool_path(config, &["containment", "allow_network_egress"]))
        .unwrap_or(server_url.is_some());
    let allow_child_processes = config
        .get("allow_child_processes")
        .and_then(Value::as_bool)
        .or_else(|| json_bool_path(config, &["containment", "allow_child_processes"]))
        .unwrap_or_else(|| json_string_value(config, "command").is_some());
    let source_path = json_string_value(config, "source_path");
    let config_source = json_string_value(config, "source").unwrap_or_else(|| source.to_string());
    let config_source_scope =
        json_string_value(config, "source_scope").unwrap_or_else(|| source_scope.to_string());
    let config_compatibility = json_string_value(config, "config_compatibility");
    let mut evidence_refs = vec![
        "mcp.manager.validation_input".to_string(),
        config_source.clone(),
        config_source_scope.clone(),
        id.clone(),
    ];
    if let Some(path) = &source_path {
        evidence_refs.push(path.clone());
    }
    if let Some(compatibility) = &config_compatibility {
        evidence_refs.push(compatibility.clone());
    }
    evidence_refs.sort();
    evidence_refs.dedup();

    json!({
        "schema_version": MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
        "id": id,
        "label": name,
        "name": name,
        "enabled": enabled,
        "status": json_string_value(config, "status").unwrap_or_else(|| status.to_string()),
        "transport": transport,
        "command": json_string_value(config, "command"),
        "args": config.get("args").and_then(Value::as_array).map(|items| {
            items.iter().map(|item| {
                item.as_str().map(ToString::to_string).unwrap_or_else(|| item.to_string())
            }).collect::<Vec<_>>()
        }).unwrap_or_default(),
        "server_url": server_url,
        "endpoint": server_url,
        "header_names": header_names,
        "header_secret_refs": header_secret_refs,
        "env_secret_refs": env_secret_refs,
        "source": config_source,
        "source_path": source_path,
        "source_scope": config_source_scope,
        "config_compatibility": config_compatibility,
        "workspace_root": workspace_root,
        "allowed_tools": allowed_tools,
        "tool_count": allowed_tools.len(),
        "resources": resources,
        "resource_count": resources.len(),
        "prompts": prompts,
        "prompt_count": prompts.len(),
        "containment": {
            "mode": containment_mode,
            "allow_network_egress": allow_network_egress,
            "allow_child_processes": allow_child_processes,
            "workspace_root": workspace_root,
        },
        "secret_refs": secret_refs,
        "vault_boundary": {
            "required": !secret_refs.as_object().unwrap_or(&serde_json::Map::new()).is_empty(),
            "header_ref_count": header_secret_refs.as_object().map(|map| map.len()).unwrap_or(0),
            "env_ref_count": env_secret_refs.as_object().map(|map| map.len()).unwrap_or(0),
            "secret_values_included": false,
            "runtime_resolution": "execution_time_only",
        },
        "health": {
            "status": if json_string_value(config, "status").as_deref() == Some("connected") { "connected" } else { "not_connected" },
            "live_probe": false,
            "reason": "read_only_catalog_status",
        },
        "evidence_refs": evidence_refs,
    })
}

fn normalize_mcp_allowed_tools(config: &Value) -> Vec<String> {
    let mut tools = Vec::new();
    if let Some(items) = config.get("allowed_tools").and_then(Value::as_array) {
        for item in items {
            if let Some(text) = item.as_str().and_then(|text| optional_trimmed(Some(text))) {
                tools.push(text);
            } else if let Some(name) = mcp_catalog_field_string(item, &["name", "tool_name"]) {
                tools.push(name);
            }
        }
    }
    if let Some(map) = config.get("tools").and_then(Value::as_object) {
        tools.extend(map.keys().cloned());
    }
    tools.sort();
    tools.dedup();
    tools
}

fn normalize_mcp_catalog_items_for_validation(
    value: Option<&Value>,
    fallback_key: &str,
) -> Vec<Value> {
    mcp_catalog_items(value)
        .into_iter()
        .enumerate()
        .map(|(index, item)| {
            if item.is_object() {
                item
            } else {
                json!({ fallback_key: mcp_catalog_value_string(&item).unwrap_or_else(|| format!("{fallback_key}_{index}")) })
            }
        })
        .collect()
}

fn public_mcp_secret_refs(source: &serde_json::Map<String, Value>, prefix: &str) -> Value {
    let mut refs = serde_json::Map::new();
    for (key, value) in source {
        match value {
            Value::String(text) if text.starts_with("vault://") => {
                refs.insert(key.clone(), Value::String(text.clone()));
            }
            Value::Object(object) if object.contains_key("secret_ref") => {
                refs.insert(
                    key.clone(),
                    object.get("secret_ref").cloned().unwrap_or(Value::Null),
                );
            }
            Value::Object(object) if object.contains_key("invalidVaultRef") => {
                refs.insert(key.clone(), Value::Object(object.clone()));
            }
            Value::Null => {}
            _ => {
                refs.insert(
                    key.clone(),
                    json!({
                        "invalidVaultRef": true,
                        "source": prefix,
                    }),
                );
            }
        }
    }
    Value::Object(refs)
}

fn merge_json_objects(left: &Value, right: &Value) -> Value {
    let mut merged = left.as_object().cloned().unwrap_or_default();
    if let Some(right) = right.as_object() {
        merged.extend(right.clone());
    }
    Value::Object(merged)
}

fn json_path_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current
        .as_str()
        .and_then(|entry| optional_trimmed(Some(entry)))
}
#[cfg(test)]
mod tests {
    use super::*;

    fn mcp_control_agent_state_update_request() -> McpControlAgentStateUpdateRequest {
        McpControlAgentStateUpdateRequest {
            schema_version: MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_1".to_string(),
            agent: json!({
                "id": "agent_1",
                "cwd": "/workspace",
                "mcpRegistry": {
                    "servers": [
                        { "id": "mcp.docs", "enabled": true }
                    ]
                },
                "updatedAt": "2026-06-06T05:00:00.000Z"
            }),
            control_kind: "mcp_add".to_string(),
            event_id: "event_mcp_add".to_string(),
            seq: 4,
            created_at: "2026-06-06T05:45:00.000Z".to_string(),
        }
    }

    fn mcp_server_validation_request() -> McpServerValidationRequest {
        McpServerValidationRequest {
            schema_version: MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION.to_string(),
            servers: vec![
                json!({
                    "id": "mcp.docs",
                    "transport": "stdio",
                    "command": "npx",
                    "allowed_tools": ["search"]
                }),
                json!({
                    "id": "mcp.remote",
                    "transport": "http",
                    "server_url": "https://mcp.example.test",
                    "allowed_tools": ["fetch"],
                    "containment": {
                        "allow_network_egress": true
                    }
                }),
            ],
        }
    }

    fn mcp_server_validation_input_request() -> McpServerValidationInputRequest {
        McpServerValidationInputRequest {
            schema_version: MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION.to_string(),
            workspace_root: Some("/workspace".to_string()),
            input: json!({
                "mcp_json": {
                    "mcp_servers": {
                        "docs": {
                            "transport": "stdio",
                            "command": "npx",
                            "tools": {
                                "search": { "description": "Search docs" }
                            },
                            "sourcePath": "/retired/mcp.json",
                            "source_scope": "validation"
                        }
                    }
                },
                "mcpJson": {
                    "mcpServers": {
                        "retired": { "transport": "stdio", "command": "retired" }
                    }
                }
            }),
        }
    }

    fn thread_memory_agent_state_update_request() -> ThreadMemoryAgentStateUpdateRequest {
        ThreadMemoryAgentStateUpdateRequest {
            schema_version: THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_1".to_string(),
            agent: json!({
                "id": "agent_1",
                "cwd": "/workspace",
                "updatedAt": "2026-06-06T05:00:00.000Z"
            }),
            control_kind: "memory_status".to_string(),
            event_id: "event_memory_status".to_string(),
            seq: 6,
            created_at: "2026-06-06T06:05:00.000Z".to_string(),
        }
    }

    #[test]
    fn rust_policy_plans_mcp_control_agent_state_update() {
        let record = McpControlAgentStateUpdateCore
            .plan(&mcp_control_agent_state_update_request())
            .expect("mcp control agent state update");

        assert_eq!(
            record.schema_version,
            MCP_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "thread.mcp_add");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.agent_id, "agent_1");
        assert_eq!(record.updated_at, "2026-06-06T05:45:00.000Z");
        assert_eq!(record.control["control_kind"], "mcp_add");
        assert_eq!(record.control["event_id"], "event_mcp_add");
        assert!(record.control.get("controlKind").is_none());
        assert!(record.control.get("eventId").is_none());
        assert!(record.control.get("createdAt").is_none());
        assert_eq!(record.agent["updatedAt"], "2026-06-06T05:45:00.000Z");
        assert_eq!(record.agent["mcpRegistry"]["servers"][0]["id"], "mcp.docs");
    }

    #[test]
    fn rust_policy_shapes_mcp_control_agent_state_update_command_response() {
        let response =
            plan_mcp_control_agent_state_update_response(McpControlAgentStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: mcp_control_agent_state_update_request(),
            })
            .expect("mcp control agent state update command response");

        assert_eq!(
            response["source"],
            "rust_mcp_control_agent_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.mcp_add");
        assert_eq!(response["control"]["control_kind"], "mcp_add");
        assert_eq!(response["control"]["event_id"], "event_mcp_add");
        assert!(response["control"].get("controlKind").is_none());
        assert!(response["control"].get("eventId").is_none());
        assert!(response["control"].get("createdAt").is_none());
        assert_eq!(response["agent"]["id"], "agent_1");
        assert_eq!(response["agent"]["updatedAt"], "2026-06-06T05:45:00.000Z");
        assert_eq!(
            response["agent"]["mcpRegistry"]["servers"][0]["id"],
            "mcp.docs"
        );
    }

    #[test]
    fn rust_policy_validates_mcp_servers() {
        let record = McpServerValidationCore
            .validate(&mcp_server_validation_request())
            .expect("mcp server validation");

        assert_eq!(
            record.schema_version,
            MCP_SERVER_VALIDATION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_server_validation");
        assert_eq!(record.status, "pass");
        assert!(record.ok);
        assert_eq!(record.issue_count, 0);
        assert_eq!(record.warning_count, 0);
        assert!(record.issues.is_empty());
        assert!(record.warnings.is_empty());
    }

    #[test]
    fn rust_policy_shapes_mcp_server_validation_command_response() {
        let mut request = mcp_server_validation_request();
        request.servers = vec![json!({
            "id": "mcp.remote",
            "transport": "http",
            "server_url": "file:///tmp/socket",
            "allowed_tools": ["fetch"],
            "containment": {
                "allow_network_egress": false
            }
        })];

        let response = validate_mcp_servers_response(McpServerValidationBridgeRequest {
            backend: Some("rust_policy".to_string()),
            request,
        })
        .expect("mcp server validation command response");

        assert_eq!(response["source"], "rust_mcp_server_validation_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["ok"], false);
        assert_eq!(response["issue_count"], 2);
        assert_eq!(response["issues"][0]["code"], "mcp_remote_url_invalid");
        assert_eq!(response["issues"][1]["code"], "mcp_remote_network_blocked");
        assert!(response["issues"][0].get("serverId").is_none());
    }

    #[test]
    fn rust_policy_projects_mcp_server_validation_input() {
        let record = McpServerValidationInputCore
            .project(&mcp_server_validation_input_request())
            .expect("mcp server validation input");

        assert_eq!(
            record.schema_version,
            MCP_SERVER_VALIDATION_INPUT_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_server_validation_input");
        assert_eq!(record.status, "projected");
        assert_eq!(record.workspace_root.as_deref(), Some("/workspace"));
        assert_eq!(record.server_count, 1);
        assert_eq!(record.servers[0]["id"], "mcp.docs");
        assert_eq!(record.servers[0]["label"], "docs");
        assert_eq!(record.servers[0]["workspace_root"], "/workspace");
        assert_eq!(record.servers[0]["source_scope"], "validation");
        assert_eq!(record.servers[0]["tool_count"], 1);
        assert_eq!(record.servers[0]["allowed_tools"][0], "search");
        assert!(record.servers[0].get("sourcePath").is_none());
        assert!(record.servers[0].get("sourceScope").is_none());
    }

    #[test]
    fn rust_policy_shapes_mcp_server_validation_input_command_response() {
        let response =
            project_mcp_server_validation_input_response(McpServerValidationInputBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: mcp_server_validation_input_request(),
            })
            .expect("mcp server validation input command response");

        assert_eq!(
            response["source"],
            "rust_mcp_server_validation_input_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "projected");
        assert_eq!(response["workspace_root"], "/workspace");
        assert_eq!(response["server_count"], 1);
        assert_eq!(response["servers"][0]["id"], "mcp.docs");
        assert_eq!(response["servers"][0]["tool_count"], 1);
        assert!(response["servers"][0].get("sourceScope").is_none());
    }

    #[test]
    fn rust_policy_projects_mcp_manager_status() {
        let validation = McpServerValidationCore
            .validate(&mcp_server_validation_request())
            .expect("mcp server validation");
        let request = McpManagerStatusProjectionRequest {
            schema_version: MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            status_schema_version: Some("ioi.runtime.mcp-manager-status.v1".to_string()),
            validation: serde_json::to_value(validation).expect("validation value"),
            servers: vec![
                json!({
                    "id": "mcp.docs",
                    "enabled": true,
                }),
                json!({
                    "id": "mcp.disabled",
                    "enabled": false,
                }),
            ],
            tools: vec![json!({ "stable_tool_id": "mcp.docs.search" })],
            resources: vec![json!({ "uri": "mcp.docs://root" })],
            prompts: vec![json!({ "name": "ask" })],
            enabled_tools: vec![json!({ "stable_tool_id": "mcp.docs.search" })],
            routes: json!({
                "search_tools": "/v1/mcp/tools/search",
            }),
        };

        let record = McpManagerStatusProjectionCore
            .project(&request)
            .expect("mcp manager status projection");

        assert_eq!(
            record.schema_version,
            MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_manager_status");
        assert_eq!(record.status, "ready");
        assert_eq!(record.server_count, 2);
        assert_eq!(record.tool_count, 1);
        assert_eq!(record.resource_count, 1);
        assert_eq!(record.prompt_count, 1);
        assert_eq!(record.enabled_server_count, 1);
        assert_eq!(record.enabled_tool_count, Some(1));
        assert_eq!(record.validation["server_count"], 2);
        assert_eq!(
            record.validation["tools"][0]["stable_tool_id"],
            "mcp.docs.search"
        );
        assert_eq!(record.routes["search_tools"], "/v1/mcp/tools/search");
        assert!(record.validation.get("serverCount").is_none());
        assert!(record.routes.get("searchTools").is_none());
    }

    #[test]
    fn rust_policy_shapes_mcp_manager_status_command_response() {
        let validation = McpServerValidationCore
            .validate(&mcp_server_validation_request())
            .expect("mcp server validation");
        let response =
            plan_mcp_manager_status_projection_response(McpManagerStatusProjectionBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: McpManagerStatusProjectionRequest {
                    schema_version: MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    status_schema_version: Some("ioi.runtime.mcp-manager-status.v1".to_string()),
                    validation: serde_json::to_value(validation).expect("validation value"),
                    servers: vec![
                        json!({ "id": "mcp.docs", "enabled": true }),
                        json!({ "id": "mcp.disabled", "enabled": false }),
                    ],
                    tools: vec![json!({ "stable_tool_id": "mcp.docs.search" })],
                    resources: vec![json!({ "uri": "mcp.docs://root" })],
                    prompts: vec![json!({ "name": "ask" })],
                    enabled_tools: vec![json!({ "stable_tool_id": "mcp.docs.search" })],
                    routes: json!({
                        "search_tools": "/v1/mcp/tools/search"
                    }),
                },
            })
            .expect("mcp manager status command response");

        assert_eq!(
            response["source"],
            "rust_mcp_manager_status_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "ready");
        assert_eq!(response["server_count"], 2);
        assert_eq!(response["enabled_server_count"], 1);
        assert_eq!(response["enabled_tool_count"], 1);
        assert_eq!(response["validation"]["server_count"], 2);
        assert_eq!(
            response["validation"]["tools"][0]["stable_tool_id"],
            "mcp.docs.search"
        );
        assert_eq!(response["routes"]["search_tools"], "/v1/mcp/tools/search");
        assert!(response.get("serverCount").is_none());
        assert!(response["routes"].get("searchTools").is_none());
    }

    #[test]
    fn rust_policy_projects_memory_manager_validation() {
        let request = MemoryManagerValidationProjectionRequest {
            schema_version: MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            validation_schema_version: Some(
                MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
            ),
            projection: json!({
                "policy": {
                    "id": "policy.thread",
                    "scope": "thread",
                    "injection_enabled": true,
                    "read_only": false,
                    "write_requires_approval": true,
                    "readOnly": true
                },
                "paths": {
                    "records_path": "/state/memory",
                    "policies_path": "/state/policies",
                    "recordsPath": "/retired/memory"
                },
                "filters": {
                    "scope": "thread"
                },
                "records": [{
                    "id": "memory.one",
                    "fact": "Remember the runtime boundary.",
                    "scope": "thread",
                    "memory_key": "project",
                    "redaction": "redacted"
                }]
            }),
        };

        let record = MemoryManagerValidationProjectionCore
            .project(&request)
            .expect("memory manager validation projection");

        assert_eq!(
            record.schema_version,
            MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_memory_manager_validation");
        assert!(record.ok);
        assert_eq!(record.status, "pass");
        assert_eq!(record.record_count, 1);
        assert_eq!(record.warning_count, 3);
        assert!(record
            .warnings
            .iter()
            .any(|warning| warning["code"] == "memory_record_redacted_hash_missing"));
        assert!(record.policy.get("readOnly").is_some());
        assert_eq!(record.policy["read_only"], false);
        assert_eq!(record.paths["records_path"], "/state/memory");
    }

    #[test]
    fn rust_policy_shapes_memory_manager_validation_command_response() {
        let response = plan_memory_manager_validation_projection_response(
            MemoryManagerValidationProjectionBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: MemoryManagerValidationProjectionRequest {
                    schema_version: MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    validation_schema_version: Some(
                        MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
                    ),
                    projection: json!({
                        "policy": {
                            "id": "policy.thread",
                            "scope": "thread"
                        },
                        "paths": {},
                        "records": [{
                            "id": "memory.one",
                            "fact": "Remember the runtime boundary.",
                            "scope": "thread"
                        }]
                    }),
                },
            },
        )
        .expect("memory manager validation command response");

        assert_eq!(
            response["source"],
            "rust_memory_manager_validation_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["ok"], false);
        assert_eq!(response["issue_count"], 2);
        assert_eq!(response["issues"][0]["code"], "memory_records_path_missing");
        assert_eq!(
            response["issues"][1]["code"],
            "memory_policies_path_missing"
        );
        assert!(response.get("issueCount").is_none());
        assert!(response.get("recordCount").is_none());
    }

    #[test]
    fn rust_policy_projects_memory_manager_status() {
        let request = MemoryManagerStatusProjectionRequest {
            schema_version: MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            status_schema_version: Some(
                MEMORY_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
            ),
            validation_schema_version: Some(
                MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
            ),
            projection: json!({
                "policy": {
                    "id": "policy.thread",
                    "scope": "thread",
                    "injection_enabled": true,
                    "read_only": false,
                    "write_requires_approval": true,
                    "writeRequiresApproval": false
                },
                "paths": {
                    "records_path": "/state/memory",
                    "policies_path": "/state/policies",
                    "effective_policy_id": "policy.thread",
                    "effectivePolicyId": "policy.retired"
                },
                "records": [{
                    "id": "memory.one",
                    "fact": "Remember the runtime boundary.",
                    "scope": "thread",
                    "memoryKey": "retired.project",
                    "memory_key": "project"
                }]
            }),
        };

        let record = MemoryManagerStatusProjectionCore
            .project(&request)
            .expect("memory manager status projection");

        assert_eq!(
            record.schema_version,
            MEMORY_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_memory_manager_status");
        assert_eq!(record.status, "ready");
        assert_eq!(record.record_count, 1);
        assert_eq!(record.scope_count, 1);
        assert_eq!(record.memory_key_count, 1);
        assert_eq!(record.memory_keys, vec!["project".to_string()]);
        assert_eq!(record.write_requires_approval, true);
        assert_eq!(
            record.write_blocked_reason.as_deref(),
            Some("memory_write_requires_approval")
        );
        assert_eq!(
            record.validation["object"],
            "ioi.runtime_memory_manager_validation"
        );
        assert_eq!(
            record.routes["status"],
            "/v1/threads/{thread_id}/memory/status"
        );
        assert!(record.evidence_refs.contains(&"policy.thread".to_string()));
        assert!(!record.evidence_refs.contains(&"policy.retired".to_string()));
        assert!(record.evidence_refs.contains(&"memory.one".to_string()));
    }

    #[test]
    fn rust_policy_shapes_memory_manager_status_command_response() {
        let response = plan_memory_manager_status_projection_response(
            MemoryManagerStatusProjectionBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: MemoryManagerStatusProjectionRequest {
                    schema_version: MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    status_schema_version: Some(
                        MEMORY_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
                    ),
                    validation_schema_version: Some(
                        MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
                    ),
                    projection: json!({
                        "policy": {
                            "id": "policy.thread",
                            "scope": "thread",
                            "injection_enabled": true,
                            "read_only": false,
                            "write_requires_approval": true,
                            "writeRequiresApproval": false
                        },
                        "paths": {
                            "records_path": "/state/memory",
                            "policies_path": "/state/policies"
                        },
                        "records": [{
                            "id": "memory.one",
                            "fact": "Remember the runtime boundary.",
                            "scope": "thread",
                            "memoryKey": "retired.project",
                            "memory_key": "project"
                        }]
                    }),
                },
            },
        )
        .expect("memory manager status command response");

        assert_eq!(
            response["source"],
            "rust_memory_manager_status_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "ready");
        assert_eq!(response["record_count"], 1);
        assert_eq!(response["memory_key_count"], 1);
        assert_eq!(response["memory_keys"][0], "project");
        assert_eq!(response["write_requires_approval"], true);
        assert_eq!(
            response["write_blocked_reason"],
            "memory_write_requires_approval"
        );
        assert_eq!(
            response["routes"]["status"],
            "/v1/threads/{thread_id}/memory/status"
        );
        assert!(response.get("memoryKeys").is_none());
        assert!(response.get("writeRequiresApproval").is_none());
    }

    #[test]
    fn rust_policy_projects_mcp_manager_catalog_rows() {
        let request = McpManagerCatalogProjectionRequest {
            schema_version: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            status_schema_version: None,
            servers: vec![
                json!({
                    "id": "mcp.docs",
                    "label": "Docs",
                    "enabled": true,
                    "transport": "stdio",
                    "allowed_tools": [
                        {
                            "name": "search",
                            "description": "Search docs",
                            "input_schema": { "type": "object" }
                        }
                    ],
                    "resources": [
                        {
                            "uri": "docs://index",
                            "name": "index",
                            "mime_type": "text/plain"
                        }
                    ],
                    "prompts": [
                        {
                            "name": "summarize",
                            "arguments": [{ "name": "topic" }]
                        }
                    ]
                }),
                json!({
                    "id": "mcp.disabled",
                    "label": "Disabled",
                    "enabled": false,
                    "allowed_tools": ["noop"]
                }),
            ],
        };

        let record = McpManagerCatalogProjectionCore
            .project(&request)
            .expect("mcp manager catalog projection");

        assert_eq!(
            record.schema_version,
            MCP_MANAGER_CATALOG_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_manager_catalog_projection");
        assert_eq!(record.status, "projected");
        assert_eq!(record.server_count, 2);
        assert_eq!(record.tool_count, 2);
        assert_eq!(record.enabled_tool_count, 1);
        assert_eq!(record.resource_count, 1);
        assert_eq!(record.prompt_count, 1);
        assert_eq!(record.tools[0]["stable_tool_id"], "mcp.Docs.search");
        assert_eq!(record.tools[1]["status"], "disabled");
        assert_eq!(
            record.resources[0]["stable_resource_id"],
            "mcp.Docs.resource.docs_index"
        );
        assert_eq!(
            record.prompts[0]["stable_prompt_id"],
            "mcp.Docs.prompt.summarize"
        );
        assert!(record.tools[0].get("stableToolId").is_none());
        assert!(record.resources[0].get("stableResourceId").is_none());
        assert!(record.prompts[0].get("stablePromptId").is_none());
    }

    #[test]
    fn rust_policy_shapes_mcp_manager_catalog_command_response() {
        let response = plan_mcp_manager_catalog_projection_response(
            McpManagerCatalogProjectionBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: McpManagerCatalogProjectionRequest {
                    schema_version: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    status_schema_version: None,
                    servers: vec![
                        json!({
                            "id": "mcp.docs",
                            "label": "Docs",
                            "enabled": true,
                            "allowed_tools": [{ "name": "search" }],
                            "resources": [{ "uri": "docs://index" }],
                            "prompts": [{ "name": "summarize" }]
                        }),
                        json!({
                            "id": "mcp.disabled",
                            "label": "Disabled",
                            "enabled": false,
                            "allowed_tools": ["noop"]
                        }),
                    ],
                },
            },
        )
        .expect("mcp manager catalog command response");

        assert_eq!(
            response["source"],
            "rust_mcp_manager_catalog_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "projected");
        assert_eq!(response["server_count"], 2);
        assert_eq!(response["tool_count"], 2);
        assert_eq!(response["enabled_tool_count"], 1);
        assert_eq!(response["tools"][0]["stable_tool_id"], "mcp.Docs.search");
        assert_eq!(response["tools"][1]["status"], "disabled");
        assert_eq!(
            response["resources"][0]["stable_resource_id"],
            "mcp.Docs.resource.docs_index"
        );
        assert_eq!(
            response["prompts"][0]["stable_prompt_id"],
            "mcp.Docs.prompt.summarize"
        );
        assert!(response.get("stableToolId").is_none());
        assert!(response["tools"][0].get("stableToolId").is_none());
    }

    #[test]
    fn rust_policy_projects_mcp_manager_catalog_summary() {
        let catalog = McpManagerCatalogProjectionCore
            .project(&McpManagerCatalogProjectionRequest {
                schema_version: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
                status_schema_version: None,
                servers: vec![json!({
                    "id": "mcp.docs",
                    "label": "Docs",
                    "transport": "stdio",
                    "enabled": true,
                    "allowed_tools": [{ "name": "search.index" }],
                    "resources": [{ "uri": "docs://index" }],
                    "prompts": [{ "name": "summarize" }]
                })],
            })
            .expect("mcp catalog projection");
        let request = McpManagerCatalogSummaryProjectionRequest {
            schema_version: MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION
                .to_string(),
            status_schema_version: None,
            server: catalog.servers[0].clone(),
            tools: catalog.tools.clone(),
            resources: catalog.resources.clone(),
            prompts: catalog.prompts.clone(),
            live_mode: Some("declared_catalog".to_string()),
            status: None,
            error_code: None,
            preview_limit: Some(25),
            deferred: Some(false),
        };

        let record = McpManagerCatalogSummaryProjectionCore
            .project(&request)
            .expect("mcp catalog summary projection");

        assert_eq!(
            record.schema_version,
            MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_catalog_summary");
        assert_eq!(record.status, "completed");
        assert_eq!(record.server_id.as_deref(), Some("mcp.docs"));
        assert_eq!(record.server_label.as_deref(), Some("Docs"));
        assert_eq!(record.execution_mode.as_deref(), Some("declared_catalog"));
        assert_eq!(record.tool_count, 1);
        assert_eq!(record.resource_count, 1);
        assert_eq!(record.prompt_count, 1);
        assert_eq!(record.namespace_count, 1);
        assert_eq!(record.namespaces[0], "search");
        assert_eq!(record.preview_tool_names[0], "search.index");
        assert_eq!(record.search_route, "/v1/mcp/tools/search");
        assert_eq!(record.fetch_route, "/v1/mcp/tools/{tool_id}");
        assert!(!record.catalog_hash.is_empty());
    }

    #[test]
    fn rust_policy_shapes_mcp_manager_catalog_summary_command_response() {
        let catalog = McpManagerCatalogProjectionCore
            .project(&McpManagerCatalogProjectionRequest {
                schema_version: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
                status_schema_version: None,
                servers: vec![json!({
                    "id": "mcp.docs",
                    "label": "Docs",
                    "transport": "stdio",
                    "enabled": true,
                    "allowed_tools": [{ "name": "search.index" }],
                    "resources": [{ "uri": "docs://index" }],
                    "prompts": [{ "name": "summarize" }]
                })],
            })
            .expect("mcp catalog projection");
        let response = plan_mcp_manager_catalog_summary_projection_response(
            McpManagerCatalogSummaryProjectionBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: McpManagerCatalogSummaryProjectionRequest {
                    schema_version: MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    status_schema_version: None,
                    server: catalog.servers[0].clone(),
                    tools: catalog.tools.clone(),
                    resources: catalog.resources.clone(),
                    prompts: catalog.prompts.clone(),
                    live_mode: Some("declared_catalog".to_string()),
                    status: None,
                    error_code: None,
                    preview_limit: Some(25),
                    deferred: Some(false),
                },
            },
        )
        .expect("mcp manager catalog summary command response");

        assert_eq!(
            response["source"],
            "rust_mcp_manager_catalog_summary_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["object"], "ioi.runtime_mcp_catalog_summary");
        assert_eq!(response["status"], "completed");
        assert_eq!(response["server_id"], "mcp.docs");
        assert_eq!(response["tool_count"], 1);
        assert_eq!(response["resource_count"], 1);
        assert_eq!(response["prompt_count"], 1);
        assert_eq!(response["namespaces"][0], "search");
        assert_eq!(response["preview_tool_names"][0], "search.index");
        assert_eq!(response["search_route"], "/v1/mcp/tools/search");
        assert!(response.get("catalogHash").is_none());
        assert!(response.get("toolCount").is_none());
    }

    #[test]
    fn rust_policy_projects_mcp_manager_validation_envelope() {
        let validation = McpServerValidationCore
            .validate(&mcp_server_validation_request())
            .expect("mcp server validation");
        let catalog = McpManagerCatalogProjectionCore
            .project(&McpManagerCatalogProjectionRequest {
                schema_version: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
                status_schema_version: None,
                servers: vec![json!({
                    "id": "mcp.docs",
                    "label": "Docs",
                    "enabled": true,
                    "allowed_tools": [{ "name": "search" }],
                    "resources": [{ "uri": "docs://index" }],
                    "prompts": [{ "name": "summarize" }]
                })],
            })
            .expect("mcp catalog projection");
        let request = McpManagerValidationProjectionRequest {
            schema_version: MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            validation_schema_version: Some("ioi.runtime.mcp-manager-validation.v1".to_string()),
            validation: serde_json::to_value(validation).expect("validation value"),
            servers: catalog.servers.clone(),
            tools: catalog.tools.clone(),
            resources: catalog.resources.clone(),
            prompts: catalog.prompts.clone(),
        };

        let record = McpManagerValidationProjectionCore
            .project(&request)
            .expect("mcp validation projection");

        assert_eq!(
            record.schema_version,
            MCP_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_manager_validation");
        assert!(record.ok);
        assert_eq!(record.status, "pass");
        assert_eq!(record.server_count, 1);
        assert_eq!(record.tool_count, 1);
        assert_eq!(record.resource_count, 1);
        assert_eq!(record.prompt_count, 1);
        assert_eq!(record.issue_count, 0);
        assert_eq!(record.warning_count, 0);
        assert_eq!(record.tools[0]["stable_tool_id"], "mcp.Docs.search");
        assert!(record.tools[0].get("stableToolId").is_none());
    }

    #[test]
    fn rust_policy_shapes_mcp_manager_validation_command_response() {
        let response = plan_mcp_manager_validation_projection_response(
            McpManagerValidationProjectionBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: McpManagerValidationProjectionRequest {
                    schema_version: MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    validation_schema_version: Some(
                        "ioi.runtime.mcp-manager-validation.v1".to_string(),
                    ),
                    validation: json!({
                        "ok": false,
                        "status": "blocked",
                        "issues": [{ "code": "mcp_server_transport_missing", "server_id": "mcp.docs" }],
                        "warnings": []
                    }),
                    servers: vec![json!({ "id": "mcp.docs" })],
                    tools: vec![json!({ "stable_tool_id": "mcp.docs.search" })],
                    resources: vec![json!({ "uri": "docs://index" })],
                    prompts: vec![json!({ "name": "summarize" })],
                },
            },
        )
        .expect("mcp manager validation command response");

        assert_eq!(
            response["source"],
            "rust_mcp_manager_validation_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(
            response["schema_version"],
            "ioi.runtime.mcp-manager-validation.v1"
        );
        assert_eq!(response["object"], "ioi.runtime_mcp_manager_validation");
        assert_eq!(response["ok"], false);
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["server_count"], 1);
        assert_eq!(response["tool_count"], 1);
        assert_eq!(response["issue_count"], 1);
        assert_eq!(response["issues"][0]["server_id"], "mcp.docs");
        assert_eq!(response["tools"][0]["stable_tool_id"], "mcp.docs.search");
        assert!(response.get("serverCount").is_none());
        assert!(response["tools"][0].get("stableToolId").is_none());
    }

    #[test]
    fn rust_policy_rejects_invalid_mcp_server_records() {
        let mut request = mcp_server_validation_request();
        request.servers = vec![
            json!({
                "id": "mcp.bad-stdio",
                "transport": "stdio",
                "allowed_tools": []
            }),
            json!({
                "id": "mcp.remote",
                "transport": "http",
                "server_url": "file:///tmp/socket",
                "allowed_tools": ["fetch"],
                "containment": {
                    "allow_network_egress": false
                }
            }),
            json!({
                "id": "mcp.secret",
                "transport": "stdio",
                "command": "npx",
                "allowed_tools": ["secret"],
                "secret_refs": {
                    "Authorization": { "invalidVaultRef": true }
                },
                "secretRefs": {
                    "Authorization": { "invalidVaultRef": false }
                }
            }),
        ];

        let record = McpServerValidationCore
            .validate(&request)
            .expect("mcp server validation");

        assert_eq!(record.status, "blocked");
        assert!(!record.ok);
        assert_eq!(record.issue_count, 4);
        assert_eq!(record.warning_count, 1);
        let codes = record
            .issues
            .iter()
            .filter_map(|issue| issue["code"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            vec![
                "mcp_server_transport_missing",
                "mcp_remote_url_invalid",
                "mcp_remote_network_blocked",
                "mcp_secret_not_vault_ref",
            ]
        );
        assert_eq!(record.issues[3]["server_id"], "mcp.secret");
        assert_eq!(record.issues[3]["key"], "Authorization");
        assert!(record.issues[3].get("serverId").is_none());
        assert_eq!(record.warnings[0]["code"], "mcp_allowed_tools_empty");
        assert!(record.warnings[0].get("serverId").is_none());
    }

    #[test]
    fn rust_policy_rejects_invalid_mcp_server_validation_schema() {
        let mut request = mcp_server_validation_request();
        request.schema_version = "legacy.mcp-validation".to_string();

        let error = McpServerValidationCore
            .validate(&request)
            .expect_err("invalid schema should be rejected");

        assert_eq!(
            error,
            McpServerValidationError::InvalidSchemaVersion {
                expected: MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION,
                actual: "legacy.mcp-validation".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_plans_thread_memory_agent_state_update() {
        let record = ThreadMemoryAgentStateUpdateCore
            .plan(&thread_memory_agent_state_update_request())
            .expect("thread memory agent state update");

        assert_eq!(
            record.schema_version,
            THREAD_MEMORY_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "thread.memory_status");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.agent_id, "agent_1");
        assert_eq!(record.updated_at, "2026-06-06T06:05:00.000Z");
        assert_eq!(record.control["control_kind"], "memory_status");
        assert_eq!(record.control["event_id"], "event_memory_status");
        assert!(record.control.get("controlKind").is_none());
        assert!(record.control.get("eventId").is_none());
        assert!(record.control.get("createdAt").is_none());
        assert_eq!(record.agent["updatedAt"], "2026-06-06T06:05:00.000Z");
    }

    #[test]
    fn rust_policy_shapes_thread_memory_agent_state_update_command_response() {
        let response = plan_thread_memory_agent_state_update_response(
            ThreadMemoryAgentStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: thread_memory_agent_state_update_request(),
            },
        )
        .expect("thread memory agent state update command response");

        assert_eq!(
            response["source"],
            "rust_thread_memory_agent_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.memory_status");
        assert_eq!(response["control"]["control_kind"], "memory_status");
        assert_eq!(response["control"]["event_id"], "event_memory_status");
        assert!(response["control"].get("controlKind").is_none());
        assert!(response["control"].get("eventId").is_none());
        assert!(response["control"].get("createdAt").is_none());
        assert_eq!(response["agent"]["id"], "agent_1");
        assert_eq!(response["agent"]["updatedAt"], "2026-06-06T06:05:00.000Z");
    }

    #[test]
    fn rust_policy_rejects_invalid_mcp_control_agent_state_update_schema() {
        let mut request = mcp_control_agent_state_update_request();
        request.schema_version = "legacy.mcp-control-state-update".to_string();

        let error = McpControlAgentStateUpdateCore
            .plan(&request)
            .expect_err("invalid schema should be rejected");

        assert_eq!(
            error,
            McpControlAgentStateUpdateError::InvalidSchemaVersion {
                expected: MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.mcp-control-state-update".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_thread_memory_agent_state_update_schema() {
        let mut request = thread_memory_agent_state_update_request();
        request.schema_version = "legacy.thread-memory-state-update".to_string();

        let error = ThreadMemoryAgentStateUpdateCore
            .plan(&request)
            .expect_err("invalid schema should be rejected");

        assert_eq!(
            error,
            ThreadMemoryAgentStateUpdateError::InvalidSchemaVersion {
                expected: THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.thread-memory-state-update".to_string(),
            }
        );
    }
}
