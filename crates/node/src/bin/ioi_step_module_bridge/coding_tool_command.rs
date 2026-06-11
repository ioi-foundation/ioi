use ioi_services::agentic::runtime::kernel::coding_tool_step_module::{
    artifact_read_response as core_artifact_read_response,
    computer_use_request_lease_response as core_computer_use_request_lease_response,
    file_apply_patch_response as core_file_apply_patch_response,
    run_coding_tool_step_module_response as core_run_coding_tool_step_module,
    tool_retrieve_result_response as core_tool_retrieve_result_response,
    CodingToolStepModuleCommandError,
};
use serde_json::Value;

use super::BridgeError;

pub(super) use ioi_services::agentic::runtime::kernel::coding_tool_step_module::CodingToolStepModuleBridgeRequest as StepModuleBridgeRequest;

pub(super) fn run_coding_tool_step_module(
    request: StepModuleBridgeRequest,
) -> Result<Value, BridgeError> {
    core_run_coding_tool_step_module(request).map_err(bridge_error)
}

pub(super) fn file_apply_patch_response(
    request: StepModuleBridgeRequest,
) -> Result<Value, BridgeError> {
    core_file_apply_patch_response(request).map_err(bridge_error)
}

pub(super) fn artifact_read_response(
    request: StepModuleBridgeRequest,
) -> Result<Value, BridgeError> {
    core_artifact_read_response(request).map_err(bridge_error)
}

pub(super) fn tool_retrieve_result_response(
    request: StepModuleBridgeRequest,
) -> Result<Value, BridgeError> {
    core_tool_retrieve_result_response(request).map_err(bridge_error)
}

pub(super) fn computer_use_request_lease_response(
    request: StepModuleBridgeRequest,
) -> Result<Value, BridgeError> {
    core_computer_use_request_lease_response(request).map_err(bridge_error)
}

fn bridge_error(error: CodingToolStepModuleCommandError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}
