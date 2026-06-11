use ioi_services::agentic::runtime::kernel::coding_tool_artifact::{
    normalize_artifact_read, normalize_tool_retrieve_result,
};
use ioi_services::agentic::runtime::kernel::step_module::StepModuleInvocation;
use serde::Deserialize;
use serde_json::{json, Value};

use super::coding_tool_helpers::{
    apply_workspace_patch, inspect_git_diff, inspect_lsp_diagnostics, inspect_test_run,
    inspect_workspace_path, inspect_workspace_status, json_string_refs, optional_json_string,
    safe_ref_path, unique_string_refs,
};
use super::coding_tool_receipt_command::{
    step_module_response, step_module_response_with_expected_heads, successful_step_module_result,
};
use super::{computer_use, BridgeError};

#[derive(Debug, Deserialize)]
pub(super) struct StepModuleBridgeRequest {
    pub(super) backend: String,
    pub(super) invocation: StepModuleInvocation,
    #[serde(default)]
    pub(super) workspace_root: Option<String>,
    #[serde(default)]
    pub(super) input: Value,
}

pub(super) fn run_coding_tool_step_module(
    request: StepModuleBridgeRequest,
) -> Result<Value, BridgeError> {
    request
        .invocation
        .validate()
        .map_err(|errors| BridgeError::new("invocation_invalid", format!("{errors:?}")))?;

    match request.invocation.module_ref.id.as_str() {
        "workspace.status" => workspace_status_response(request),
        "git.diff" => git_diff_response(request),
        "file.inspect" => file_inspect_response(request),
        "file.apply_patch" => file_apply_patch_response(request),
        "test.run" => test_run_response(request),
        "lsp.diagnostics" => lsp_diagnostics_response(request),
        "artifact.read" => artifact_read_response(request),
        "tool.retrieve_result" => tool_retrieve_result_response(request),
        "computer_use.request_lease" => computer_use_request_lease_response(request),
        other => Err(BridgeError::new(
            "tool_unsupported",
            format!("unsupported StepModule tool {}", other),
        )),
    }
}

pub(super) fn workspace_status_response(
    request: StepModuleBridgeRequest,
) -> Result<Value, BridgeError> {
    let workspace_root = request.workspace_root.clone().ok_or_else(|| {
        BridgeError::new(
            "workspace_root_required",
            "workspace_root is required".to_string(),
        )
    })?;
    let status_result = inspect_workspace_status(&workspace_root, &request.input)?;
    let result = successful_step_module_result(&request, "workspace.status", "CodingToolNode");
    Ok(step_module_response(
        request,
        result,
        json!({
            "tool": "workspace.status",
            "result": status_result,
        }),
    ))
}

pub(super) fn git_diff_response(request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
    let workspace_root = request.workspace_root.clone().ok_or_else(|| {
        BridgeError::new(
            "workspace_root_required",
            "workspace_root is required".to_string(),
        )
    })?;
    let diff_result = inspect_git_diff(&workspace_root, &request.input)?;
    let result = successful_step_module_result(&request, "git.diff", "GitToolNode");
    Ok(step_module_response(
        request,
        result,
        json!({
            "tool": "git.diff",
            "result": diff_result,
        }),
    ))
}

pub(super) fn file_inspect_response(
    request: StepModuleBridgeRequest,
) -> Result<Value, BridgeError> {
    let workspace_root = request.workspace_root.clone().ok_or_else(|| {
        BridgeError::new(
            "workspace_root_required",
            "workspace_root is required".to_string(),
        )
    })?;
    let selected_path = request
        .input
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            BridgeError::new(
                "file_inspect_path_required",
                "file.inspect requires path".to_string(),
            )
        })?;
    let inspected = inspect_workspace_path(&workspace_root, selected_path, &request.input)?;
    let result = successful_step_module_result(&request, "file.inspect", "FilesystemToolNode");
    Ok(step_module_response(
        request,
        result,
        json!({
            "tool": "file.inspect",
            "result": inspected,
        }),
    ))
}

pub(super) fn file_apply_patch_response(
    mut request: StepModuleBridgeRequest,
) -> Result<Value, BridgeError> {
    let workspace_root = request.workspace_root.clone().ok_or_else(|| {
        BridgeError::new(
            "workspace_root_required",
            "workspace_root is required".to_string(),
        )
    })?;
    let patch = apply_workspace_patch(&workspace_root, &request.input)?;
    let mut expected_heads = vec![];
    if let Some(transition) = patch.transition.as_ref() {
        request.invocation.input.state_root_before = Some(transition.state_root_before.clone());
        request.invocation.input.projection_watermark = Some(format!(
            "projection://agentgres/{}",
            transition.resulting_head
        ));
        expected_heads = transition.expected_heads.clone();
    }
    let mut result =
        successful_step_module_result(&request, "file.apply_patch", "FilesystemPatchNode");
    if let Some(transition) = patch.transition.as_ref() {
        result.agentgres_operation_refs = vec![transition.operation_ref.clone()];
        result.payload_refs = vec![transition.payload_ref.clone()];
        result.state_root_after = Some(transition.state_root_after.clone());
        result.resulting_head = Some(transition.resulting_head.clone());
        result.workflow_projection.evidence_refs.push(format!(
            "evidence://agentgres/{}",
            safe_ref_path(&transition.operation_ref)
        ));
    }
    Ok(step_module_response_with_expected_heads(
        request,
        result,
        json!({
            "tool": "file.apply_patch",
            "result": patch.observation,
        }),
        expected_heads,
    ))
}

pub(super) fn test_run_response(request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
    let workspace_root = request.workspace_root.clone().ok_or_else(|| {
        BridgeError::new(
            "workspace_root_required",
            "workspace_root is required".to_string(),
        )
    })?;
    let test_result = inspect_test_run(&workspace_root, &request.input)?;
    let result = successful_step_module_result(&request, "test.run", "TestRunNode");
    Ok(step_module_response(
        request,
        result,
        json!({
            "tool": "test.run",
            "result": test_result,
        }),
    ))
}

pub(super) fn lsp_diagnostics_response(
    request: StepModuleBridgeRequest,
) -> Result<Value, BridgeError> {
    let workspace_root = request.workspace_root.clone().ok_or_else(|| {
        BridgeError::new(
            "workspace_root_required",
            "workspace_root is required".to_string(),
        )
    })?;
    let diagnostics_result = inspect_lsp_diagnostics(&workspace_root, &request.input)?;
    let result = successful_step_module_result(&request, "lsp.diagnostics", "LspDiagnosticsNode");
    Ok(step_module_response(
        request,
        result,
        json!({
            "tool": "lsp.diagnostics",
            "result": diagnostics_result,
        }),
    ))
}

pub(super) fn artifact_read_response(
    request: StepModuleBridgeRequest,
) -> Result<Value, BridgeError> {
    let read_result = normalize_artifact_read(&request.input).map_err(artifact_bridge_error)?;
    let mut result = successful_step_module_result(&request, "artifact.read", "ArtifactReadNode");
    result.artifact_refs = read_result.artifact_refs.clone();
    result.receipt_refs = unique_string_refs(
        result
            .receipt_refs
            .into_iter()
            .chain(read_result.receipt_refs.clone())
            .collect(),
    );
    result.workflow_projection.evidence_refs.push(format!(
        "evidence://rust-workload/artifact.read/{}",
        read_result.evidence_ref
    ));
    Ok(step_module_response(
        request,
        result,
        json!({
            "tool": "artifact.read",
            "result": read_result.observation,
        }),
    ))
}

pub(super) fn tool_retrieve_result_response(
    request: StepModuleBridgeRequest,
) -> Result<Value, BridgeError> {
    let retrieve_result =
        normalize_tool_retrieve_result(&request.input).map_err(artifact_bridge_error)?;
    let mut result =
        successful_step_module_result(&request, "tool.retrieve_result", "ToolRetrieveResultNode");
    result.artifact_refs = retrieve_result.artifact_refs.clone();
    result.receipt_refs = unique_string_refs(
        result
            .receipt_refs
            .into_iter()
            .chain(retrieve_result.receipt_refs.clone())
            .collect(),
    );
    result.workflow_projection.evidence_refs.push(format!(
        "evidence://rust-workload/tool.retrieve_result/{}",
        retrieve_result.evidence_ref
    ));
    Ok(step_module_response(
        request,
        result,
        json!({
            "tool": "tool.retrieve_result",
            "result": retrieve_result.observation,
        }),
    ))
}

pub(super) fn computer_use_request_lease_response(
    request: StepModuleBridgeRequest,
) -> Result<Value, BridgeError> {
    let workspace_root = request.workspace_root.clone().ok_or_else(|| {
        BridgeError::new(
            "workspace_root_required",
            "workspace_root is required".to_string(),
        )
    })?;
    let lease_request =
        computer_use::build_computer_use_lease_request(&workspace_root, &request.input)
            .map_err(|error| BridgeError::new(error.code(), error.message().to_string()))?;
    let mut result = successful_step_module_result(
        &request,
        "computer_use.request_lease",
        "ComputerUseLeaseRequestNode",
    );
    result.receipt_refs = unique_string_refs(
        result
            .receipt_refs
            .into_iter()
            .chain(json_string_refs(&lease_request, &["receipt_refs"]))
            .collect(),
    );
    result.workflow_projection.evidence_refs.push(format!(
        "evidence://rust-workload/computer_use.request_lease/{}",
        optional_json_string(&lease_request, &["request_ref"])
            .map(|value| safe_ref_path(&value))
            .unwrap_or_else(|| "unknown".to_string())
    ));
    Ok(step_module_response(
        request,
        result,
        json!({
            "tool": "computer_use.request_lease",
            "result": lease_request,
        }),
    ))
}

fn artifact_bridge_error(
    error: ioi_services::agentic::runtime::kernel::coding_tool_artifact::CodingToolArtifactError,
) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}
