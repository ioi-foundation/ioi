use ioi_client::workload_client::{
    WorkloadClient, WorkloadStepModuleDispatchRequest, WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::agentgres_admission::{
    AgentgresAdmissionCore, AgentgresOperationProposal, AGENTGRES_ADMISSION_SCHEMA_VERSION,
};
use super::coding_tool_artifact::{normalize_artifact_read, normalize_tool_retrieve_result};
use super::coding_tool_computer_use::build_computer_use_lease_request;
use super::coding_tool_workspace::{
    apply_workspace_patch, inspect_git_diff, inspect_lsp_diagnostics, inspect_test_run,
    inspect_workspace_path, inspect_workspace_status,
};
use super::projection::RustProjectionCore;
use super::receipt_binder::ReceiptBinder;
use super::step_module::{
    StepModuleInvocation, StepModuleNext, StepModuleProjectionStatus, StepModuleResult,
    StepModuleStatus, StepModuleWorkflowProjection, STEP_MODULE_RESULT_SCHEMA_VERSION,
};
use super::step_router::StepModuleRouterCore;

#[derive(Debug, Clone)]
pub struct CodingToolStepModuleRequest {
    pub backend: String,
    pub invocation: StepModuleInvocation,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CodingToolStepModuleBridgeRequest {
    pub backend: String,
    pub invocation: StepModuleInvocation,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub input: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodingToolStepModuleCommandError {
    code: &'static str,
    message: String,
}

impl CodingToolStepModuleCommandError {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

pub fn run_coding_tool_step_module_response(
    request: CodingToolStepModuleBridgeRequest,
) -> Result<Value, CodingToolStepModuleCommandError> {
    request.invocation.validate().map_err(|errors| {
        CodingToolStepModuleCommandError::new("invocation_invalid", format!("{errors:?}"))
    })?;

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
        other => Err(CodingToolStepModuleCommandError::new(
            "tool_unsupported",
            format!("unsupported StepModule tool {other}"),
        )),
    }
}

pub fn workspace_status_response(
    request: CodingToolStepModuleBridgeRequest,
) -> Result<Value, CodingToolStepModuleCommandError> {
    let workspace_root = required_workspace_root(&request)?;
    let status_result =
        inspect_workspace_status(&workspace_root, &request.input).map_err(workspace_error)?;
    let result = successful_coding_tool_step_module_result(
        &request.core_request(),
        "workspace.status",
        "CodingToolNode",
    );
    Ok(coding_tool_step_module_response(
        request.core_request(),
        result,
        json!({
            "tool": "workspace.status",
            "result": status_result,
        }),
    ))
}

pub fn git_diff_response(
    request: CodingToolStepModuleBridgeRequest,
) -> Result<Value, CodingToolStepModuleCommandError> {
    let workspace_root = required_workspace_root(&request)?;
    let diff_result = inspect_git_diff(&workspace_root, &request.input).map_err(workspace_error)?;
    let result = successful_coding_tool_step_module_result(
        &request.core_request(),
        "git.diff",
        "GitToolNode",
    );
    Ok(coding_tool_step_module_response(
        request.core_request(),
        result,
        json!({
            "tool": "git.diff",
            "result": diff_result,
        }),
    ))
}

pub fn file_inspect_response(
    request: CodingToolStepModuleBridgeRequest,
) -> Result<Value, CodingToolStepModuleCommandError> {
    let workspace_root = required_workspace_root(&request)?;
    let selected_path = request
        .input
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CodingToolStepModuleCommandError::new(
                "file_inspect_path_required",
                "file.inspect requires path".to_string(),
            )
        })?;
    let inspected = inspect_workspace_path(&workspace_root, selected_path, &request.input)
        .map_err(workspace_error)?;
    let result = successful_coding_tool_step_module_result(
        &request.core_request(),
        "file.inspect",
        "FilesystemToolNode",
    );
    Ok(coding_tool_step_module_response(
        request.core_request(),
        result,
        json!({
            "tool": "file.inspect",
            "result": inspected,
        }),
    ))
}

pub fn file_apply_patch_response(
    mut request: CodingToolStepModuleBridgeRequest,
) -> Result<Value, CodingToolStepModuleCommandError> {
    let workspace_root = required_workspace_root(&request)?;
    let patch = apply_workspace_patch(&workspace_root, &request.input).map_err(workspace_error)?;
    let mut expected_heads = vec![];
    if let Some(transition) = patch.transition.as_ref() {
        request.invocation.input.state_root_before = Some(transition.state_root_before.clone());
        request.invocation.input.projection_watermark = Some(format!(
            "projection://agentgres/{}",
            transition.resulting_head
        ));
        expected_heads = transition.expected_heads.clone();
    }
    let mut result = successful_coding_tool_step_module_result(
        &request.core_request(),
        "file.apply_patch",
        "FilesystemPatchNode",
    );
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
    Ok(coding_tool_step_module_response_with_expected_heads(
        request.core_request(),
        result,
        json!({
            "tool": "file.apply_patch",
            "result": patch.observation,
        }),
        expected_heads,
    ))
}

pub fn test_run_response(
    request: CodingToolStepModuleBridgeRequest,
) -> Result<Value, CodingToolStepModuleCommandError> {
    let workspace_root = required_workspace_root(&request)?;
    let test_result = inspect_test_run(&workspace_root, &request.input).map_err(workspace_error)?;
    let result = successful_coding_tool_step_module_result(
        &request.core_request(),
        "test.run",
        "TestRunNode",
    );
    Ok(coding_tool_step_module_response(
        request.core_request(),
        result,
        json!({
            "tool": "test.run",
            "result": test_result,
        }),
    ))
}

pub fn lsp_diagnostics_response(
    request: CodingToolStepModuleBridgeRequest,
) -> Result<Value, CodingToolStepModuleCommandError> {
    let workspace_root = required_workspace_root(&request)?;
    let diagnostics_result =
        inspect_lsp_diagnostics(&workspace_root, &request.input).map_err(workspace_error)?;
    let result = successful_coding_tool_step_module_result(
        &request.core_request(),
        "lsp.diagnostics",
        "LspDiagnosticsNode",
    );
    Ok(coding_tool_step_module_response(
        request.core_request(),
        result,
        json!({
            "tool": "lsp.diagnostics",
            "result": diagnostics_result,
        }),
    ))
}

pub fn artifact_read_response(
    request: CodingToolStepModuleBridgeRequest,
) -> Result<Value, CodingToolStepModuleCommandError> {
    let read_result = normalize_artifact_read(&request.input).map_err(artifact_error)?;
    let mut result = successful_coding_tool_step_module_result(
        &request.core_request(),
        "artifact.read",
        "ArtifactReadNode",
    );
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
    Ok(coding_tool_step_module_response(
        request.core_request(),
        result,
        json!({
            "tool": "artifact.read",
            "result": read_result.observation,
        }),
    ))
}

pub fn tool_retrieve_result_response(
    request: CodingToolStepModuleBridgeRequest,
) -> Result<Value, CodingToolStepModuleCommandError> {
    let retrieve_result = normalize_tool_retrieve_result(&request.input).map_err(artifact_error)?;
    let mut result = successful_coding_tool_step_module_result(
        &request.core_request(),
        "tool.retrieve_result",
        "ToolRetrieveResultNode",
    );
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
    Ok(coding_tool_step_module_response(
        request.core_request(),
        result,
        json!({
            "tool": "tool.retrieve_result",
            "result": retrieve_result.observation,
        }),
    ))
}

pub fn computer_use_request_lease_response(
    request: CodingToolStepModuleBridgeRequest,
) -> Result<Value, CodingToolStepModuleCommandError> {
    let workspace_root = required_workspace_root(&request)?;
    let lease_request = build_computer_use_lease_request(&workspace_root, &request.input)
        .map_err(computer_use_error)?;
    let mut result = successful_coding_tool_step_module_result(
        &request.core_request(),
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
    Ok(coding_tool_step_module_response(
        request.core_request(),
        result,
        json!({
            "tool": "computer_use.request_lease",
            "result": lease_request,
        }),
    ))
}

pub fn successful_coding_tool_step_module_result(
    request: &CodingToolStepModuleRequest,
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
            status: coding_tool_projection_status_for_backend(&request.backend),
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

pub fn coding_tool_step_module_response(
    request: CodingToolStepModuleRequest,
    result: StepModuleResult,
    workload_observation: Value,
) -> Value {
    coding_tool_step_module_response_with_expected_heads(
        request,
        result,
        workload_observation,
        vec![],
    )
}

pub fn coding_tool_step_module_response_with_expected_heads(
    request: CodingToolStepModuleRequest,
    mut result: StepModuleResult,
    workload_observation: Value,
    expected_heads: Vec<String>,
) -> Value {
    let workload_dispatch = match WorkloadClient::plan_step_module_dispatch(
        &coding_tool_workload_step_module_dispatch_request(&request),
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

pub fn coding_tool_workload_step_module_dispatch_request(
    request: &CodingToolStepModuleRequest,
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

pub fn coding_tool_projection_status_for_backend(backend: &str) -> StepModuleProjectionStatus {
    match backend {
        "rust_workload_live" => StepModuleProjectionStatus::Live,
        "rust_workload_gated" => StepModuleProjectionStatus::Gated,
        _ => StepModuleProjectionStatus::Shadow,
    }
}

fn unique_string_refs(values: Vec<String>) -> Vec<String> {
    let mut refs = Vec::new();
    for value in values {
        if !value.trim().is_empty() && !refs.contains(&value) {
            refs.push(value);
        }
    }
    refs
}

fn required_workspace_root(
    request: &CodingToolStepModuleBridgeRequest,
) -> Result<String, CodingToolStepModuleCommandError> {
    request.workspace_root.clone().ok_or_else(|| {
        CodingToolStepModuleCommandError::new(
            "workspace_root_required",
            "workspace_root is required".to_string(),
        )
    })
}

fn json_string_refs(value: &Value, keys: &[&str]) -> Vec<String> {
    for key in keys {
        let refs = value
            .get(*key)
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
            .unwrap_or_default();
        if !refs.is_empty() {
            return refs;
        }
    }
    Vec::new()
}

fn optional_json_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn safe_ref_path(value: &str) -> String {
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

fn workspace_error(
    error: super::coding_tool_workspace::CodingToolWorkspaceError,
) -> CodingToolStepModuleCommandError {
    CodingToolStepModuleCommandError::new(error.code(), error.message().to_string())
}

fn artifact_error(
    error: super::coding_tool_artifact::CodingToolArtifactError,
) -> CodingToolStepModuleCommandError {
    CodingToolStepModuleCommandError::new(error.code(), error.message().to_string())
}

fn computer_use_error(
    error: super::coding_tool_computer_use::CodingToolComputerUseError,
) -> CodingToolStepModuleCommandError {
    CodingToolStepModuleCommandError::new(error.code(), error.message().to_string())
}

impl CodingToolStepModuleBridgeRequest {
    fn core_request(&self) -> CodingToolStepModuleRequest {
        CodingToolStepModuleRequest {
            backend: self.backend.clone(),
            invocation: self.invocation.clone(),
        }
    }
}

fn short_suffix(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(24)
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::step_module::{
        StepModuleActor, StepModuleAuthority, StepModuleBackend, StepModuleCustody,
        StepModuleExecution, StepModuleInput, StepModuleKind, StepModulePlaintextPolicy,
        StepModulePrivacyProfile, StepModuleRef, STEP_MODULE_INVOCATION_SCHEMA_VERSION,
    };

    fn request(backend: &str) -> CodingToolStepModuleRequest {
        CodingToolStepModuleRequest {
            backend: backend.to_string(),
            invocation: StepModuleInvocation {
                schema_version: STEP_MODULE_INVOCATION_SCHEMA_VERSION.to_string(),
                invocation_id: "invocation://coding-tool-step-module-test".to_string(),
                run_id: "run:coding-tool-step-module".to_string(),
                task_id: "task:coding-tool-step-module".to_string(),
                thread_id: Some("thread:coding-tool-step-module".to_string()),
                workflow_graph_id: Some("workflow:coding-tool-step-module".to_string()),
                workflow_node_id: Some("node:coding-tool-step-module".to_string()),
                context_chamber_ref: None,
                action_proposal_ref: "action:coding-tool-step-module".to_string(),
                gate_result_ref: "gate:coding-tool-step-module".to_string(),
                module_ref: StepModuleRef {
                    kind: StepModuleKind::WorkloadJob,
                    id: "workspace.status".to_string(),
                    version: "1".to_string(),
                    manifest_ref: None,
                },
                actor: StepModuleActor {
                    actor_id: "runtime:hypervisor-daemon".to_string(),
                    runtime_node_ref: "node://local".to_string(),
                },
                authority: StepModuleAuthority {
                    authority_grant_refs: vec![],
                    policy_hash: "sha256:policy".to_string(),
                    primitive_capabilities: vec!["prim:workspace.status".to_string()],
                    authority_scopes: vec![],
                    approval_ref: None,
                },
                input: StepModuleInput {
                    input_hash: "sha256:input".to_string(),
                    expected_schema_ref: "schema://coding-tool/workspace.status/input".to_string(),
                    context_refs: vec![],
                    artifact_refs: vec!["artifact://input".to_string()],
                    payload_refs: vec!["payload://input".to_string()],
                    state_root_before: Some("sha256:before".to_string()),
                    projection_watermark: Some("domain_seq:coding-tool-step-module".to_string()),
                    data_plane_handle: None,
                },
                custody: StepModuleCustody {
                    privacy_profile: StepModulePrivacyProfile::Internal,
                    plaintext_policy: StepModulePlaintextPolicy {
                        node_plaintext_allowed: true,
                        declassification_required: false,
                    },
                    custody_proof_ref: None,
                    leakage_profile_ref: None,
                },
                execution: StepModuleExecution {
                    backend: StepModuleBackend::WorkloadGrpc,
                    idempotency_key: "idem:coding-tool-step-module".to_string(),
                    deadline_ms: 1_000,
                    resource_lease_ref: None,
                    retry_policy_ref: None,
                },
            },
        }
    }

    #[test]
    fn successful_result_uses_backend_projection_status() {
        let result = successful_coding_tool_step_module_result(
            &request("rust_workload_live"),
            "workspace.status",
            "CodingToolNode",
        );

        assert_eq!(
            result.workflow_projection.status,
            StepModuleProjectionStatus::Live
        );
        assert_eq!(
            result.receipt_refs,
            vec!["receipt://rust-workload/workspace.status/invocationcodingtoolstep".to_string()]
        );
    }

    #[test]
    fn rust_core_builds_response_admission_receipt_and_projection() {
        let request = request("rust_workload_live");
        let result = successful_coding_tool_step_module_result(
            &request,
            "workspace.status",
            "CodingToolNode",
        );
        let response = coding_tool_step_module_response(
            request,
            result,
            json!({
                "tool": "workspace.status",
                "result": {
                    "clean": true
                }
            }),
        );

        assert_eq!(response["source"], "rust_workload_command");
        assert_eq!(
            response["workload_dispatch"]["schema_version"],
            WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION
        );
        assert_eq!(
            response["router_admission"]["authoritative_transition"],
            true
        );
        assert!(response["receipt_binding"]["binding_hash"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256:")));
        assert_eq!(response["agentgres_admission"], Value::Null);
        assert_eq!(
            response["projection_record"]["workflow_graph_id"],
            "workflow:coding-tool-step-module"
        );
        assert!(response["result"]["workflow_projection"]["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_workload_client_step_module_dispatch"));
    }
}
