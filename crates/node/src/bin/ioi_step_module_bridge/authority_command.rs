use ioi_services::agentic::runtime::kernel::authority::{
    authorize_external_capability_exit_response as core_authorize_external_capability_exit,
    AuthorityCommandError,
};
use serde_json::Value;

use super::BridgeError;
pub(super) use ioi_services::agentic::runtime::kernel::authority::ExternalCapabilityExitAuthorityBridgeRequest;

pub(super) fn authorize_external_capability_exit(
    request: ExternalCapabilityExitAuthorityBridgeRequest,
) -> Result<Value, BridgeError> {
    core_authorize_external_capability_exit(request).map_err(bridge_error)
}

fn bridge_error(error: AuthorityCommandError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}
