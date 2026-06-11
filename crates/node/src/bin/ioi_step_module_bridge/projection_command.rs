use ioi_services::agentic::runtime::kernel::policy::{
    RepositoryWorkflowProjectionRequiredCore, RepositoryWorkflowProjectionRequiredRequest,
    RuntimeLifecycleProjectionRequiredCore, RuntimeLifecycleProjectionRequiredRequest,
    RuntimeToolCatalogProjectionRequiredCore, RuntimeToolCatalogProjectionRequiredRequest,
    SkillHookRegistryProjectionRequiredCore, SkillHookRegistryProjectionRequiredRequest,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{BridgeError, DAEMON_CORE_COMMAND_SCHEMA_VERSION};

#[derive(Debug, Deserialize)]
pub(super) struct SkillHookRegistryProjectionRequiredBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: SkillHookRegistryProjectionRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RepositoryWorkflowProjectionRequiredBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: RepositoryWorkflowProjectionRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeToolCatalogProjectionRequiredBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: RuntimeToolCatalogProjectionRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeLifecycleProjectionRequiredBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: RuntimeLifecycleProjectionRequiredRequest,
}

pub(super) fn plan_skill_hook_registry_projection_required(
    request: SkillHookRegistryProjectionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_skill_hook_registry_projection_required" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = SkillHookRegistryProjectionRequiredCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "skill_hook_registry_projection_required_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_skill_hook_registry_projection_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "status_code": record.status_code,
        "code": record.code.clone(),
        "message": record.message.clone(),
        "rust_core_boundary": record.rust_core_boundary.clone(),
        "operation_kind": record.operation_kind.clone(),
        "details": record.details.clone(),
    }))
}

pub(super) fn plan_repository_workflow_projection_required(
    request: RepositoryWorkflowProjectionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_repository_workflow_projection_required" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = RepositoryWorkflowProjectionRequiredCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "repository_workflow_projection_required_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_repository_workflow_projection_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "status_code": record.status_code,
        "code": record.code.clone(),
        "message": record.message.clone(),
        "rust_core_boundary": record.rust_core_boundary.clone(),
        "operation_kind": record.operation_kind.clone(),
        "details": record.details.clone(),
    }))
}

pub(super) fn plan_runtime_tool_catalog_projection_required(
    request: RuntimeToolCatalogProjectionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_runtime_tool_catalog_projection_required" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = RuntimeToolCatalogProjectionRequiredCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_tool_catalog_projection_required_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_runtime_tool_catalog_projection_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "status_code": record.status_code,
        "code": record.code.clone(),
        "message": record.message.clone(),
        "rust_core_boundary": record.rust_core_boundary.clone(),
        "operation_kind": record.operation_kind.clone(),
        "details": record.details.clone(),
    }))
}

pub(super) fn plan_runtime_lifecycle_projection_required(
    request: RuntimeLifecycleProjectionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_runtime_lifecycle_projection_required" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = RuntimeLifecycleProjectionRequiredCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_lifecycle_projection_required_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_runtime_lifecycle_projection_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "status_code": record.status_code,
        "code": record.code.clone(),
        "message": record.message.clone(),
        "rust_core_boundary": record.rust_core_boundary.clone(),
        "operation_kind": record.operation_kind.clone(),
        "details": record.details.clone(),
    }))
}
