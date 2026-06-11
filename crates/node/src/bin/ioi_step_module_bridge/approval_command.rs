use ioi_services::agentic::runtime::kernel::approval::{
    plan_approval_decision_state_update_response as core_plan_approval_decision_state_update,
    plan_approval_request_state_update_response as core_plan_approval_request_state_update,
    plan_approval_revoke_state_update_response as core_plan_approval_revoke_state_update,
    plan_coding_tool_approval_manifest_response as core_plan_coding_tool_approval_manifest,
    ApprovalCommandError,
};
use serde_json::Value;

use super::BridgeError;
pub(super) use ioi_services::agentic::runtime::kernel::approval::{
    ApprovalDecisionStateUpdateBridgeRequest, ApprovalRequestStateUpdateBridgeRequest,
    ApprovalRevokeStateUpdateBridgeRequest, CodingToolApprovalBridgeRequest,
};

pub(super) fn plan_coding_tool_approval_manifest(
    request: CodingToolApprovalBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_coding_tool_approval_manifest(request).map_err(bridge_error)
}

pub(super) fn plan_approval_request_state_update(
    request: ApprovalRequestStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_approval_request_state_update(request).map_err(bridge_error)
}

pub(super) fn plan_approval_decision_state_update(
    request: ApprovalDecisionStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_approval_decision_state_update(request).map_err(bridge_error)
}

pub(super) fn plan_approval_revoke_state_update(
    request: ApprovalRevokeStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_approval_revoke_state_update(request).map_err(bridge_error)
}

fn bridge_error(error: ApprovalCommandError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}
