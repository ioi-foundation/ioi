use ioi_services::agentic::runtime::kernel::policy::{
    plan_repository_workflow_projection_required_response as core_plan_repository_workflow_projection_required,
    plan_runtime_lifecycle_projection_required_response as core_plan_runtime_lifecycle_projection_required,
    plan_runtime_tool_catalog_projection_required_response as core_plan_runtime_tool_catalog_projection_required,
    plan_skill_hook_registry_projection_required_response as core_plan_skill_hook_registry_projection_required,
    ProjectionRequiredCommandError,
};
use serde_json::Value;

use super::BridgeError;
pub(super) use ioi_services::agentic::runtime::kernel::policy::{
    RepositoryWorkflowProjectionRequiredBridgeRequest,
    RuntimeLifecycleProjectionRequiredBridgeRequest,
    RuntimeToolCatalogProjectionRequiredBridgeRequest,
    SkillHookRegistryProjectionRequiredBridgeRequest,
};

pub(super) fn plan_skill_hook_registry_projection_required(
    request: SkillHookRegistryProjectionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_skill_hook_registry_projection_required(request).map_err(bridge_error)
}

pub(super) fn plan_repository_workflow_projection_required(
    request: RepositoryWorkflowProjectionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_repository_workflow_projection_required(request).map_err(bridge_error)
}

pub(super) fn plan_runtime_tool_catalog_projection_required(
    request: RuntimeToolCatalogProjectionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_runtime_tool_catalog_projection_required(request).map_err(bridge_error)
}

pub(super) fn plan_runtime_lifecycle_projection_required(
    request: RuntimeLifecycleProjectionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_runtime_lifecycle_projection_required(request).map_err(bridge_error)
}

fn bridge_error(error: ProjectionRequiredCommandError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}
