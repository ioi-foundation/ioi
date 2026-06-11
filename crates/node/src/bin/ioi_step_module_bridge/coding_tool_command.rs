use ioi_client::workload_client::{
    WorkloadClient, WorkloadStepModuleDispatchRequest, WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::agentgres_admission::{
    AgentgresAdmissionCore, AgentgresOperationProposal, AGENTGRES_ADMISSION_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::projection::RustProjectionCore;
use ioi_services::agentic::runtime::kernel::receipt_binder::ReceiptBinder;
use ioi_services::agentic::runtime::kernel::step_module::{
    StepModuleInvocation, StepModuleNext, StepModuleProjectionStatus, StepModuleResult,
    StepModuleStatus, StepModuleWorkflowProjection, STEP_MODULE_RESULT_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::step_router::StepModuleRouterCore;
use serde::Deserialize;
use serde_json::{json, Value};

use super::coding_tool_helpers::{
    apply_workspace_patch, inspect_git_diff, inspect_lsp_diagnostics, inspect_test_run,
    inspect_workspace_path, inspect_workspace_status, json_string_refs, optional_json_string,
    safe_ref_path, sha256_hex, unique_string_refs,
};
use super::{computer_use, BridgeError, CODING_TOOL_RESULT_SCHEMA_VERSION, COMMAND_SCHEMA_VERSION};

#[derive(Debug, Deserialize)]
pub(super) struct StepModuleBridgeRequest {
    #[serde(rename = "schema_version")]
    pub(super) schema_version: String,
    pub(super) operation: String,
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
    if request.schema_version != COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "run_coding_tool_step_module" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
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
    let read_result = normalize_prefetched_artifact_result(
        "artifact.read",
        &request.input,
        "rust_artifact_read",
    )?;
    let mut result = successful_step_module_result(&request, "artifact.read", "ArtifactReadNode");
    result.artifact_refs = json_string_refs(&read_result, &["artifactRefs", "artifact_refs"]);
    result.receipt_refs = unique_string_refs(
        result
            .receipt_refs
            .into_iter()
            .chain(json_string_refs(
                &read_result,
                &["receiptRefs", "receipt_refs"],
            ))
            .collect(),
    );
    result.workflow_projection.evidence_refs.push(format!(
        "evidence://rust-workload/artifact.read/{}",
        optional_json_string(
            &read_result,
            &["artifactId", "artifact_id", "artifactRef", "artifact_ref"]
        )
        .map(|value| safe_ref_path(&value))
        .unwrap_or_else(|| "unknown".to_string())
    ));
    Ok(step_module_response(
        request,
        result,
        json!({
            "tool": "artifact.read",
            "result": read_result,
        }),
    ))
}

pub(super) fn tool_retrieve_result_response(
    request: StepModuleBridgeRequest,
) -> Result<Value, BridgeError> {
    let retrieve_result = normalize_prefetched_artifact_result(
        "tool.retrieve_result",
        &request.input,
        "rust_tool_result_retrieve",
    )?;
    let mut result =
        successful_step_module_result(&request, "tool.retrieve_result", "ToolRetrieveResultNode");
    result.artifact_refs = json_string_refs(&retrieve_result, &["artifactRefs", "artifact_refs"]);
    result.receipt_refs = unique_string_refs(
        result
            .receipt_refs
            .into_iter()
            .chain(json_string_refs(
                &retrieve_result,
                &["receiptRefs", "receipt_refs"],
            ))
            .collect(),
    );
    result.workflow_projection.evidence_refs.push(format!(
        "evidence://rust-workload/tool.retrieve_result/{}",
        optional_json_string(
            &retrieve_result,
            &["toolCallId", "tool_call_id", "artifactId", "artifact_id"]
        )
        .map(|value| safe_ref_path(&value))
        .unwrap_or_else(|| "unknown".to_string())
    ));
    Ok(step_module_response(
        request,
        result,
        json!({
            "tool": "tool.retrieve_result",
            "result": retrieve_result,
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
            .map_err(|error| BridgeError::new("computer_use_lease_request_failed", error))?;
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

pub(super) fn successful_step_module_result(
    request: &StepModuleBridgeRequest,
    tool_id: &str,
    component_kind: &str,
) -> StepModuleResult {
    let invocation_id = request.invocation.invocation_id.clone();
    let suffix = short_suffix(&invocation_id);
    let receipt_ref = format!("receipt://rust-workload/{tool_id}/{suffix}");
    StepModuleResult {
        schema_version: STEP_MODULE_RESULT_SCHEMA_VERSION.to_string(),
        invocation_id,
        status: StepModuleStatus::Success,
        execution_result_ref: format!("result://rust-workload/{tool_id}/{suffix}"),
        normalized_observation_ref: format!("observation://rust-workload/{tool_id}/{suffix}"),
        receipt_refs: vec![receipt_ref.clone()],
        artifact_refs: vec![],
        payload_refs: vec![],
        agentgres_operation_refs: vec![],
        state_root_after: None,
        resulting_head: None,
        workflow_projection: StepModuleWorkflowProjection {
            workflow_graph_id: request
                .invocation
                .workflow_graph_id
                .clone()
                .unwrap_or_else(|| "workflow:projection".to_string()),
            workflow_node_id: request
                .invocation
                .workflow_node_id
                .clone()
                .unwrap_or_else(|| format!("node:coding-tool:{tool_id}")),
            component_kind: component_kind.to_string(),
            status: projection_status_for_backend(&request.backend),
            attempt_id: format!("attempt://rust-workload/{tool_id}/{suffix}"),
            evidence_refs: vec![format!("evidence://rust-workload/{tool_id}")],
            receipt_refs: vec![receipt_ref],
        },
        next: StepModuleNext {
            model_reentry_required: false,
            verifier_required: false,
        },
    }
}

pub(super) fn step_module_response(
    request: StepModuleBridgeRequest,
    result: StepModuleResult,
    workload_observation: Value,
) -> Value {
    step_module_response_with_expected_heads(request, result, workload_observation, vec![])
}

pub(super) fn step_module_response_with_expected_heads(
    request: StepModuleBridgeRequest,
    mut result: StepModuleResult,
    workload_observation: Value,
    expected_heads: Vec<String>,
) -> Value {
    let workload_dispatch = match WorkloadClient::plan_step_module_dispatch(
        &workload_step_module_dispatch_request(&request),
    ) {
        Ok(plan) => plan,
        Err(error) => {
            return json!({
                "source": "rust_workload_command",
                "error": {
                    "code": "workload_client_dispatch_invalid",
                    "message": format!("{error:?}"),
                }
            });
        }
    };
    result.workflow_projection.evidence_refs = unique_string_refs(
        result
            .workflow_projection
            .evidence_refs
            .into_iter()
            .chain(workload_dispatch.evidence_refs.clone())
            .collect(),
    );
    if let Err(errors) = result.validate() {
        return json!({
            "source": "rust_workload_command",
            "error": {
                "code": "result_invalid",
                "message": format!("{errors:?}"),
            }
        });
    }
    let router_admission = match StepModuleRouterCore.admit_execution(&request.invocation, &result)
    {
        Ok(record) => record,
        Err(error) => {
            return json!({
                "source": "rust_workload_command",
                "error": {
                    "code": "router_admission_invalid",
                    "message": format!("{error:?}"),
                }
            });
        }
    };
    let receipt_binding =
        match ReceiptBinder.bind_step_module_result(&request.invocation, &result, expected_heads) {
            Ok(binding) => binding,
            Err(error) => {
                return json!({
                    "source": "rust_workload_command",
                    "error": {
                        "code": "receipt_binding_invalid",
                        "message": format!("{error:?}"),
                    }
                });
            }
        };
    let agentgres_admission = if result.agentgres_operation_refs.is_empty() {
        Value::Null
    } else {
        let proposal = AgentgresOperationProposal {
            schema_version: AGENTGRES_ADMISSION_SCHEMA_VERSION.to_string(),
            operation_ref: result
                .agentgres_operation_refs
                .first()
                .cloned()
                .unwrap_or_default(),
            invocation_id: result.invocation_id.clone(),
            receipt_binding_ref: receipt_binding.binding_hash.clone(),
            receipt_refs: result.receipt_refs.clone(),
            artifact_refs: result.artifact_refs.clone(),
            payload_refs: result.payload_refs.clone(),
            expected_heads: receipt_binding.expected_heads.clone(),
            state_root_before: receipt_binding.state_root_before.clone(),
            state_root_after: result.state_root_after.clone(),
            resulting_head: result.resulting_head.clone(),
        };
        match AgentgresAdmissionCore.admit(&proposal, &receipt_binding) {
            Ok(record) => json!(record),
            Err(error) => {
                return json!({
                    "source": "rust_workload_command",
                    "error": {
                        "code": "agentgres_admission_invalid",
                        "message": format!("{error:?}"),
                    }
                });
            }
        }
    };
    let projection_record = match RustProjectionCore.project_step_module_result(
        &request.invocation,
        &result,
        &receipt_binding,
    ) {
        Ok(record) => record,
        Err(error) => {
            return json!({
                "source": "rust_workload_command",
                "error": {
                    "code": "projection_record_invalid",
                    "message": format!("{error:?}"),
                }
            });
        }
    };
    json!({
        "source": "rust_workload_command",
        "backend": request.backend,
        "invocation": request.invocation,
        "workload_dispatch": workload_dispatch,
        "result": result,
        "router_admission": router_admission,
        "receipt_binding": receipt_binding,
        "agentgres_admission": agentgres_admission,
        "projection_record": projection_record,
        "workload_observation": workload_observation,
    })
}

pub(super) fn workload_step_module_dispatch_request(
    request: &StepModuleBridgeRequest,
) -> WorkloadStepModuleDispatchRequest {
    WorkloadStepModuleDispatchRequest {
        schema_version: WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION.to_string(),
        invocation_id: request.invocation.invocation_id.clone(),
        module_kind: serde_json::to_value(&request.invocation.module_ref.kind)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "unknown".to_string()),
        module_ref: request.invocation.module_ref.id.clone(),
        execution_backend: serde_json::to_value(&request.invocation.execution.backend)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "unknown".to_string()),
        artifact_refs: request.invocation.input.artifact_refs.clone(),
        payload_refs: request.invocation.input.payload_refs.clone(),
        data_plane_handle: request
            .invocation
            .input
            .data_plane_handle
            .as_ref()
            .and_then(|handle| serde_json::to_value(handle).ok()),
    }
}

pub(super) fn normalize_prefetched_artifact_result(
    tool_id: &str,
    input: &Value,
    backend: &str,
) -> Result<Value, BridgeError> {
    let envelope = input
        .get("rustWorkloadDataPlane")
        .or_else(|| input.get("rust_workload_data_plane"))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            BridgeError::new(
                "data_plane_payload_required",
                format!("{tool_id} requires a daemon-provided data-plane payload"),
            )
        })?;
    let source = envelope
        .get("source")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            BridgeError::new(
                "data_plane_source_required",
                format!("{tool_id} requires a data-plane source"),
            )
        })?;
    if source != "daemon_artifact_store" {
        return Err(BridgeError::new(
            "data_plane_source_unsupported",
            format!("{tool_id} does not accept data-plane source {source}"),
        ));
    }
    let operation = envelope
        .get("operation")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            BridgeError::new(
                "data_plane_operation_required",
                format!("{tool_id} requires a data-plane operation"),
            )
        })?;
    if operation != tool_id {
        return Err(BridgeError::new(
            "data_plane_operation_mismatch",
            format!("{tool_id} received data-plane operation {operation}"),
        ));
    }
    let mut normalized = envelope.get("result").cloned().ok_or_else(|| {
        BridgeError::new(
            "data_plane_result_required",
            format!("{tool_id} requires a data-plane result"),
        )
    })?;
    let fallback_artifact_ref = optional_json_string(
        &normalized,
        &["artifactId", "artifact_id", "artifactRef", "artifact_ref"],
    );
    let object = normalized.as_object_mut().ok_or_else(|| {
        BridgeError::new(
            "data_plane_result_invalid",
            format!("{tool_id} data-plane result must be an object"),
        )
    })?;
    let content = object
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            BridgeError::new(
                "data_plane_content_required",
                format!("{tool_id} data-plane result must include content"),
            )
        })?
        .to_string();
    let content_hash = sha256_hex(content.as_bytes())?;
    object.insert(
        "schemaVersion".to_string(),
        json!(CODING_TOOL_RESULT_SCHEMA_VERSION),
    );
    object.insert("backend".to_string(), json!(backend));
    object.insert("dataPlaneSource".to_string(), json!(source));
    object.insert("data_plane_source".to_string(), json!(source));
    object.insert("rustWorkloadDataPlane".to_string(), json!(true));
    object.insert("rust_workload_data_plane".to_string(), json!(true));
    object.insert("contentHash".to_string(), json!(content_hash));
    object.insert("content_hash".to_string(), json!(content_hash));
    object.insert("shellFallbackUsed".to_string(), json!(false));
    object.insert("shell_fallback_used".to_string(), json!(false));
    if !object.contains_key("artifactRefs") && !object.contains_key("artifact_refs") {
        if let Some(artifact_id) = fallback_artifact_ref {
            object.insert("artifactRefs".to_string(), json!([artifact_id]));
        }
    }
    Ok(normalized)
}

pub(super) fn projection_status_for_backend(backend: &str) -> StepModuleProjectionStatus {
    match backend {
        "rust_workload_live" => StepModuleProjectionStatus::Live,
        "rust_workload_gated" => StepModuleProjectionStatus::Gated,
        _ => StepModuleProjectionStatus::Shadow,
    }
}

pub(super) fn short_suffix(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(24)
        .collect::<String>()
}
