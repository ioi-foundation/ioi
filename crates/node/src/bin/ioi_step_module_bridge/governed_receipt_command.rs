use ioi_services::agentic::runtime::kernel::governed_receipt::{
    admit_worker_service_package_invocation_response as core_admit_worker_service_package_invocation,
    execute_private_workspace_ctee_action_response as core_execute_private_workspace_ctee_action,
    GovernedReceiptError,
};
use serde_json::Value;

use super::BridgeError;
pub(super) use ioi_services::agentic::runtime::kernel::governed_receipt::{
    CteePrivateWorkspaceBridgeRequest, WorkerServicePackageInvocationBridgeRequest,
};

pub(super) fn execute_private_workspace_ctee_action(
    request: CteePrivateWorkspaceBridgeRequest,
) -> Result<Value, BridgeError> {
    core_execute_private_workspace_ctee_action(request).map_err(bridge_error)
}

pub(super) fn admit_worker_service_package_invocation(
    request: WorkerServicePackageInvocationBridgeRequest,
) -> Result<Value, BridgeError> {
    core_admit_worker_service_package_invocation(request).map_err(bridge_error)
}

fn bridge_error(error: GovernedReceiptError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}
