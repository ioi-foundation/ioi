use ioi_services::agentic::runtime::kernel::policy::{
    plan_mcp_control_agent_state_update_response as core_plan_mcp_control_agent_state_update,
    plan_mcp_manager_catalog_projection_response as core_plan_mcp_manager_catalog_projection,
    plan_mcp_manager_catalog_summary_projection_response as core_plan_mcp_manager_catalog_summary_projection,
    plan_mcp_manager_status_projection_response as core_plan_mcp_manager_status_projection,
    plan_mcp_manager_validation_projection_response as core_plan_mcp_manager_validation_projection,
    plan_memory_manager_status_projection_response as core_plan_memory_manager_status_projection,
    plan_memory_manager_validation_projection_response as core_plan_memory_manager_validation_projection,
    plan_thread_memory_agent_state_update_response as core_plan_thread_memory_agent_state_update,
    project_mcp_server_validation_input_response as core_project_mcp_server_validation_input,
    validate_mcp_servers_response as core_validate_mcp_servers, McpMemoryCommandError,
};
use serde_json::Value;

use super::BridgeError;

pub(super) use ioi_services::agentic::runtime::kernel::policy::{
    McpControlAgentStateUpdateBridgeRequest, McpManagerCatalogProjectionBridgeRequest,
    McpManagerCatalogSummaryProjectionBridgeRequest, McpManagerStatusProjectionBridgeRequest,
    McpManagerValidationProjectionBridgeRequest, McpServerValidationBridgeRequest,
    McpServerValidationInputBridgeRequest, MemoryManagerStatusProjectionBridgeRequest,
    MemoryManagerValidationProjectionBridgeRequest, ThreadMemoryAgentStateUpdateBridgeRequest,
};

pub(super) fn plan_mcp_control_agent_state_update(
    request: McpControlAgentStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_mcp_control_agent_state_update(request).map_err(bridge_error)
}

pub(super) fn validate_mcp_servers(
    request: McpServerValidationBridgeRequest,
) -> Result<Value, BridgeError> {
    core_validate_mcp_servers(request).map_err(bridge_error)
}

pub(super) fn project_mcp_server_validation_input(
    request: McpServerValidationInputBridgeRequest,
) -> Result<Value, BridgeError> {
    core_project_mcp_server_validation_input(request).map_err(bridge_error)
}

pub(super) fn plan_mcp_manager_status_projection(
    request: McpManagerStatusProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_mcp_manager_status_projection(request).map_err(bridge_error)
}

pub(super) fn plan_mcp_manager_validation_projection(
    request: McpManagerValidationProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_mcp_manager_validation_projection(request).map_err(bridge_error)
}

pub(super) fn plan_memory_manager_status_projection(
    request: MemoryManagerStatusProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_memory_manager_status_projection(request).map_err(bridge_error)
}

pub(super) fn plan_memory_manager_validation_projection(
    request: MemoryManagerValidationProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_memory_manager_validation_projection(request).map_err(bridge_error)
}

pub(super) fn plan_mcp_manager_catalog_projection(
    request: McpManagerCatalogProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_mcp_manager_catalog_projection(request).map_err(bridge_error)
}

pub(super) fn plan_mcp_manager_catalog_summary_projection(
    request: McpManagerCatalogSummaryProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_mcp_manager_catalog_summary_projection(request).map_err(bridge_error)
}

pub(super) fn plan_thread_memory_agent_state_update(
    request: ThreadMemoryAgentStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_thread_memory_agent_state_update(request).map_err(bridge_error)
}

fn bridge_error(error: McpMemoryCommandError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}
