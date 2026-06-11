use ioi_services::agentic::runtime::kernel::coding_tool_step_module::{
    coding_tool_step_module_response as core_step_module_response,
    coding_tool_step_module_response_with_expected_heads as core_step_module_response_with_expected_heads,
    successful_coding_tool_step_module_result as core_successful_step_module_result,
    CodingToolStepModuleRequest,
};
use ioi_services::agentic::runtime::kernel::step_module::StepModuleResult;
use serde_json::Value;

use super::coding_tool_command::StepModuleBridgeRequest;

pub(super) fn successful_step_module_result(
    request: &StepModuleBridgeRequest,
    tool_id: &str,
    component_kind: &str,
) -> StepModuleResult {
    core_successful_step_module_result(&core_request(request), tool_id, component_kind)
}

pub(super) fn step_module_response(
    request: StepModuleBridgeRequest,
    result: StepModuleResult,
    workload_observation: Value,
) -> Value {
    core_step_module_response(core_request(&request), result, workload_observation)
}

pub(super) fn step_module_response_with_expected_heads(
    request: StepModuleBridgeRequest,
    result: StepModuleResult,
    workload_observation: Value,
    expected_heads: Vec<String>,
) -> Value {
    core_step_module_response_with_expected_heads(
        core_request(&request),
        result,
        workload_observation,
        expected_heads,
    )
}

fn core_request(request: &StepModuleBridgeRequest) -> CodingToolStepModuleRequest {
    CodingToolStepModuleRequest {
        backend: request.backend.clone(),
        invocation: request.invocation.clone(),
    }
}
