use ioi_services::agentic::runtime::kernel::workspace_restore::{
    WorkspaceRestoreApplyPolicyCore, WorkspaceRestoreApplyPolicyRequest,
    WorkspaceRestoreOperationsCore, WorkspaceRestoreOperationsRequest,
    WorkspaceSnapshotCaptureCore, WorkspaceSnapshotCaptureRequest,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{BridgeError, DAEMON_CORE_COMMAND_SCHEMA_VERSION};

#[derive(Debug, Deserialize)]
pub(super) struct WorkspaceRestoreApplyPolicyBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: WorkspaceRestoreApplyPolicyRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct WorkspaceRestoreOperationsBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: WorkspaceRestoreOperationsRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct WorkspaceSnapshotCaptureBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: WorkspaceSnapshotCaptureRequest,
}

pub(super) fn plan_workspace_restore_apply_policy(
    request: WorkspaceRestoreApplyPolicyBridgeRequest,
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
    if request.operation != "plan_workspace_restore_apply_policy" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let plan = WorkspaceRestoreApplyPolicyCore
        .plan_apply_policy(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "workspace_restore_apply_policy_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_workspace_restore_policy_command",
        "backend": request.backend.unwrap_or_else(|| "rust_workspace_restore".to_string()),
        "plan": plan.clone(),
        "approval": plan.approval.clone(),
        "allow_conflicts": plan.allow_conflicts,
        "conflict_policy": plan.conflict_policy.clone(),
        "hard_blocked": plan.hard_blocked,
        "conflict_blocked": plan.conflict_blocked,
        "policy_status": plan.policy_status.clone(),
        "apply_status": plan.apply_status.clone(),
        "policy_decision_refs": plan.policy_decision_refs.clone(),
        "operation_policies": plan.operation_policies.clone(),
        "summary": plan.summary.clone(),
    }))
}

pub(super) fn preview_workspace_restore_operations(
    request: WorkspaceRestoreOperationsBridgeRequest,
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
    if request.operation != "preview_workspace_restore_operations" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let operations = WorkspaceRestoreOperationsCore
        .preview_operations(&request.request)
        .map_err(|error| {
            BridgeError::new("workspace_restore_operations_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_workspace_restore_operations_command",
        "backend": request.backend.unwrap_or_else(|| "rust_workspace_restore".to_string()),
        "operation": "preview_workspace_restore_operations",
        "operations": operations,
    }))
}

pub(super) fn apply_workspace_restore_operations(
    request: WorkspaceRestoreOperationsBridgeRequest,
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
    if request.operation != "apply_workspace_restore_operations" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let operations = WorkspaceRestoreOperationsCore
        .apply_operations(&request.request)
        .map_err(|error| {
            BridgeError::new("workspace_restore_operations_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_workspace_restore_operations_command",
        "backend": request.backend.unwrap_or_else(|| "rust_workspace_restore".to_string()),
        "operation": "apply_workspace_restore_operations",
        "operations": operations,
    }))
}

pub(super) fn capture_workspace_snapshot_files(
    request: WorkspaceSnapshotCaptureBridgeRequest,
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
    if request.operation != "capture_workspace_snapshot_files" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let capture = WorkspaceSnapshotCaptureCore
        .capture_files(&request.request)
        .map_err(|error| {
            BridgeError::new("workspace_snapshot_capture_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_workspace_snapshot_capture_command",
        "backend": request.backend.unwrap_or_else(|| "rust_workspace_restore".to_string()),
        "capture": capture.clone(),
        "files": capture.files.clone(),
        "content_files": capture.content_files.clone(),
        "captured_file_count": capture.captured_file_count,
        "omitted_file_count": capture.omitted_file_count,
        "content_captured": capture.content_captured,
    }))
}
