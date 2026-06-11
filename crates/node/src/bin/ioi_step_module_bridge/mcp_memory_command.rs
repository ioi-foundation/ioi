use ioi_services::agentic::runtime::kernel::policy::{
    McpControlAgentStateUpdateCore, McpControlAgentStateUpdateRequest,
    McpManagerCatalogProjectionCore, McpManagerCatalogProjectionRequest,
    McpManagerCatalogSummaryProjectionCore, McpManagerCatalogSummaryProjectionRequest,
    McpManagerStatusProjectionCore, McpManagerStatusProjectionRequest,
    McpManagerValidationProjectionCore, McpManagerValidationProjectionRequest,
    McpServerValidationCore, McpServerValidationInputCore, McpServerValidationInputRequest,
    McpServerValidationRequest, MemoryManagerStatusProjectionCore,
    MemoryManagerStatusProjectionRequest, MemoryManagerValidationProjectionCore,
    MemoryManagerValidationProjectionRequest, ThreadMemoryAgentStateUpdateCore,
    ThreadMemoryAgentStateUpdateRequest,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::BridgeError;

#[derive(Debug, Deserialize)]
pub(super) struct McpControlAgentStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: McpControlAgentStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct McpServerValidationBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: McpServerValidationRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct McpServerValidationInputBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: McpServerValidationInputRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct McpManagerStatusProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: McpManagerStatusProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct McpManagerValidationProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: McpManagerValidationProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct MemoryManagerStatusProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: MemoryManagerStatusProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct MemoryManagerValidationProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: MemoryManagerValidationProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct McpManagerCatalogProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: McpManagerCatalogProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct McpManagerCatalogSummaryProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: McpManagerCatalogSummaryProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ThreadMemoryAgentStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ThreadMemoryAgentStateUpdateRequest,
}

pub(super) fn plan_mcp_control_agent_state_update(
    request: McpControlAgentStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = McpControlAgentStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "mcp_control_agent_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_mcp_control_agent_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "control": record.control.clone(),
        "agent": record.agent.clone(),
    }))
}

pub(super) fn validate_mcp_servers(
    request: McpServerValidationBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = McpServerValidationCore
        .validate(&request.request)
        .map_err(|error| BridgeError::new("mcp_server_validation_invalid", format!("{error:?}")))?;
    Ok(json!({
        "source": "rust_mcp_server_validation_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "ok": record.ok,
        "issue_count": record.issue_count,
        "warning_count": record.warning_count,
        "issues": record.issues.clone(),
        "warnings": record.warnings.clone(),
    }))
}

pub(super) fn project_mcp_server_validation_input(
    request: McpServerValidationInputBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = McpServerValidationInputCore
        .project(&request.request)
        .map_err(|error| {
            BridgeError::new("mcp_server_validation_input_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_mcp_server_validation_input_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "status": record.status.clone(),
        "workspace_root": record.workspace_root.clone(),
        "server_count": record.server_count,
        "servers": record.servers.clone(),
    }))
}

pub(super) fn plan_mcp_manager_status_projection(
    request: McpManagerStatusProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = McpManagerStatusProjectionCore
        .project(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "mcp_manager_status_projection_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_mcp_manager_status_projection_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
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

pub(super) fn plan_mcp_manager_validation_projection(
    request: McpManagerValidationProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = McpManagerValidationProjectionCore
        .project(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "mcp_manager_validation_projection_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_mcp_manager_validation_projection_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
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

pub(super) fn plan_memory_manager_status_projection(
    request: MemoryManagerStatusProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = MemoryManagerStatusProjectionCore
        .project(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "memory_manager_status_projection_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_memory_manager_status_projection_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
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

pub(super) fn plan_memory_manager_validation_projection(
    request: MemoryManagerValidationProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = MemoryManagerValidationProjectionCore
        .project(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "memory_manager_validation_projection_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_memory_manager_validation_projection_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
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

pub(super) fn plan_mcp_manager_catalog_projection(
    request: McpManagerCatalogProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = McpManagerCatalogProjectionCore
        .project(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "mcp_manager_catalog_projection_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_mcp_manager_catalog_projection_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
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

pub(super) fn plan_mcp_manager_catalog_summary_projection(
    request: McpManagerCatalogSummaryProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = McpManagerCatalogSummaryProjectionCore
        .project(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "mcp_manager_catalog_summary_projection_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_mcp_manager_catalog_summary_projection_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
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

pub(super) fn plan_thread_memory_agent_state_update(
    request: ThreadMemoryAgentStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = ThreadMemoryAgentStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "thread_memory_agent_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_thread_memory_agent_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "control": record.control.clone(),
        "agent": record.agent.clone(),
    }))
}
