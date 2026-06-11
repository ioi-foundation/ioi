use ioi_services::agentic::runtime::kernel::workspace_restore::{
    apply_workspace_restore_operations_response as core_apply_workspace_restore_operations,
    capture_workspace_snapshot_files_response as core_capture_workspace_snapshot_files,
    plan_workspace_restore_apply_policy_response as core_plan_workspace_restore_apply_policy,
    WorkspaceRestoreCommandError,
};
use serde_json::Value;

use super::BridgeError;
pub(super) use ioi_services::agentic::runtime::kernel::workspace_restore::{
    WorkspaceRestoreApplyPolicyBridgeRequest, WorkspaceRestoreOperationsBridgeRequest,
    WorkspaceSnapshotCaptureBridgeRequest,
};

pub(super) fn plan_workspace_restore_apply_policy(
    request: WorkspaceRestoreApplyPolicyBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_workspace_restore_apply_policy(request).map_err(bridge_error)
}

pub(super) fn apply_workspace_restore_operations(
    request: WorkspaceRestoreOperationsBridgeRequest,
) -> Result<Value, BridgeError> {
    core_apply_workspace_restore_operations(request).map_err(bridge_error)
}

pub(super) fn capture_workspace_snapshot_files(
    request: WorkspaceSnapshotCaptureBridgeRequest,
) -> Result<Value, BridgeError> {
    core_capture_workspace_snapshot_files(request).map_err(bridge_error)
}

fn bridge_error(error: WorkspaceRestoreCommandError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}
