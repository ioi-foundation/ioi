use ioi_services::agentic::runtime::kernel::coding_tool_computer_use::{
    build_computer_use_lease_request as build_core_computer_use_lease_request,
    CodingToolComputerUseError,
};
use serde_json::Value;

pub(super) fn build_computer_use_lease_request(
    workspace_root: &str,
    input: &Value,
) -> Result<Value, CodingToolComputerUseError> {
    build_core_computer_use_lease_request(workspace_root, input)
}
