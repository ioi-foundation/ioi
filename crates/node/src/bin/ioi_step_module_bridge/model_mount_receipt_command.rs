use ioi_services::agentic::runtime::kernel::model_mount_receipt::{
    bind_model_mount_invocation_receipt_response as core_bind_model_mount_invocation_receipt,
    plan_model_mount_accepted_receipt_head_response as core_plan_model_mount_accepted_receipt_head,
    plan_model_mount_accepted_receipt_transition_response as core_plan_model_mount_accepted_receipt_transition,
    ModelMountReceiptError,
};
use serde_json::Value;

use super::BridgeError;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount_receipt::{
    ModelMountAcceptedReceiptHeadBridgeRequest, ModelMountAcceptedReceiptTransitionBridgeRequest,
    ModelMountInvocationReceiptBindingBridgeRequest,
};

pub(super) fn plan_model_mount_accepted_receipt_head(
    request: ModelMountAcceptedReceiptHeadBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_accepted_receipt_head(request).map_err(bridge_error)
}

pub(super) fn plan_model_mount_accepted_receipt_transition(
    request: ModelMountAcceptedReceiptTransitionBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_accepted_receipt_transition(request).map_err(bridge_error)
}

pub(super) fn bind_model_mount_invocation_receipt(
    request: ModelMountInvocationReceiptBindingBridgeRequest,
) -> Result<Value, BridgeError> {
    core_bind_model_mount_invocation_receipt(request).map_err(bridge_error)
}

fn bridge_error(error: ModelMountReceiptError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}
