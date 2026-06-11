use ioi_services::agentic::runtime::kernel::coding_tool_workspace::{
    apply_workspace_patch as apply_core_workspace_patch, inspect_git_diff as inspect_core_git_diff,
    inspect_lsp_diagnostics as inspect_core_lsp_diagnostics,
    inspect_test_run as inspect_core_test_run,
    inspect_workspace_path as inspect_core_workspace_path,
    inspect_workspace_status as inspect_core_workspace_status, WorkspacePatchOutcome,
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

pub(super) fn apply_workspace_patch(
    workspace_root: &str,
    input: &Value,
) -> Result<WorkspacePatchOutcome, BridgeError> {
    apply_core_workspace_patch(workspace_root, input)
        .map_err(|error| BridgeError::new(error.code(), error.message().to_string()))
}

pub(super) fn sanitize_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .take(100)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub(super) fn json_string_refs(value: &Value, keys: &[&str]) -> Vec<String> {
    for key in keys {
        let refs = sanitize_string_array(value.get(*key));
        if !refs.is_empty() {
            return refs;
        }
    }
    Vec::new()
}

pub(super) fn optional_json_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn unique_string_refs(values: Vec<String>) -> Vec<String> {
    values.into_iter().fold(Vec::new(), |mut unique, value| {
        if !unique.contains(&value) {
            unique.push(value);
        }
        unique
    })
}

pub(super) fn sha256_hex(bytes: &[u8]) -> Result<String, BridgeError> {
    ioi_crypto::algorithms::hash::sha256(bytes)
        .map(hex::encode)
        .map_err(|error| BridgeError::new("sha256_failed", error.to_string()))
}

pub(super) fn safe_ref_path(value: &str) -> String {
    let safe = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .take(48)
        .collect::<String>();
    if safe.is_empty() {
        "file".to_string()
    } else {
        safe
    }
}
