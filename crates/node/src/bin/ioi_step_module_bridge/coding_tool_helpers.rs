use ioi_services::agentic::runtime::kernel::coding_tool_workspace::{
    inspect_git_diff as inspect_core_git_diff,
    inspect_lsp_diagnostics as inspect_core_lsp_diagnostics,
    inspect_test_run as inspect_core_test_run,
    inspect_workspace_path as inspect_core_workspace_path,
    inspect_workspace_status as inspect_core_workspace_status,
};
use serde_json::Value;

use super::BridgeError;

pub(super) fn inspect_test_run(workspace_root: &str, input: &Value) -> Result<Value, BridgeError> {
    inspect_core_test_run(workspace_root, input)
        .map_err(|error| BridgeError::new(error.code(), error.message().to_string()))
}

pub(super) fn inspect_lsp_diagnostics(
    workspace_root: &str,
    input: &Value,
) -> Result<Value, BridgeError> {
    inspect_core_lsp_diagnostics(workspace_root, input)
        .map_err(|error| BridgeError::new(error.code(), error.message().to_string()))
}

pub(super) fn inspect_workspace_status(
    workspace_root: &str,
    input: &Value,
) -> Result<Value, BridgeError> {
    inspect_core_workspace_status(workspace_root, input)
        .map_err(|error| BridgeError::new(error.code(), error.message().to_string()))
}

pub(super) fn inspect_git_diff(workspace_root: &str, input: &Value) -> Result<Value, BridgeError> {
    inspect_core_git_diff(workspace_root, input)
        .map_err(|error| BridgeError::new(error.code(), error.message().to_string()))
}

pub(super) fn inspect_workspace_path(
    workspace_root: &str,
    selected_path: &str,
    input: &Value,
) -> Result<Value, BridgeError> {
    inspect_core_workspace_path(workspace_root, selected_path, input)
        .map_err(|error| BridgeError::new(error.code(), error.message().to_string()))
}

#[cfg(test)]
pub(super) fn sha256_hex(bytes: &[u8]) -> Result<String, BridgeError> {
    ioi_crypto::algorithms::hash::sha256(bytes)
        .map(hex::encode)
        .map_err(|error| BridgeError::new("sha256_failed", error.to_string()))
}
