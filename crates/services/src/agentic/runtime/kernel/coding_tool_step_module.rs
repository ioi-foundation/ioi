use ioi_client::workload_client::{
    WorkloadClient, WorkloadStepModuleDispatchRequest, WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

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
    StepModuleActor, StepModuleAuthority, StepModuleBackend, StepModuleCustody,
    StepModuleDataPlaneHandle, StepModuleExecution, StepModuleInput, StepModuleInvocation,
    StepModuleKind, StepModuleNext, StepModulePlaintextPolicy, StepModulePrivacyProfile,
    StepModuleProjectionStatus, StepModuleRef, StepModuleResult, StepModuleStatus,
    StepModuleWorkflowProjection, STEP_MODULE_INVOCATION_SCHEMA_VERSION,
    STEP_MODULE_RESULT_SCHEMA_VERSION,
};
use super::step_router::StepModuleRouterCore;

pub const CODING_TOOL_STEP_MODULE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-step-module-request.v1";
const CODING_TOOL_PACK_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-pack.v1";
const RUST_WORKLOAD_LIVE_BACKEND: &str = "rust_workload_live";
const DEFAULT_POLICY_HASH: &str = "sha256:rust-daemon-core-coding-tool-policy";
const DEFAULT_ACTOR_ID: &str = "runtime:hypervisor-daemon";
const DEFAULT_RUNTIME_NODE_REF: &str = "node://local";

#[derive(Debug, Clone)]
pub struct CodingToolStepModuleRequest {
    pub backend: String,
    pub invocation: StepModuleInvocation,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CodingToolStepModuleBridgeRequest {
    pub backend: String,
    #[serde(default)]
    pub tool_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub input: Value,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub workflow_graph_id: Option<String>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
    #[serde(default)]
    pub context_chamber_ref: Option<String>,
    #[serde(default)]
    pub action_proposal_ref: Option<String>,
    #[serde(default)]
    pub gate_result_ref: Option<String>,
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub approval_ref: Option<String>,
    #[serde(default)]
    pub state_root_before: Option<String>,
    #[serde(default)]
    pub projection_watermark: Option<String>,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub payload_refs: Vec<String>,
    #[serde(default)]
    pub data_plane_handle: Option<StepModuleDataPlaneHandle>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    #[serde(default)]
    pub manifest_ref: Option<String>,
    #[serde(default)]
    pub invocation: Option<Value>,
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
    let tool_id = request.required_tool_id()?;
    match tool_id.as_str() {
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
    let core_request = request.try_core_request()?;
    let status_result =
        inspect_workspace_status(&workspace_root, &request.input).map_err(workspace_error)?;
    let result = successful_coding_tool_step_module_result(
        &core_request,
        "workspace.status",
        "CodingToolNode",
    );
    Ok(coding_tool_step_module_response(
        core_request,
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
    let core_request = request.try_core_request()?;
    let diff_result = inspect_git_diff(&workspace_root, &request.input).map_err(workspace_error)?;
    let result =
        successful_coding_tool_step_module_result(&core_request, "git.diff", "GitToolNode");
    Ok(coding_tool_step_module_response(
        core_request,
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
    let core_request = request.try_core_request()?;
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
        &core_request,
        "file.inspect",
        "FilesystemToolNode",
    );
    Ok(coding_tool_step_module_response(
        core_request,
        result,
        json!({
            "tool": "file.inspect",
            "result": inspected,
        }),
    ))
}

pub fn file_apply_patch_response(
    request: CodingToolStepModuleBridgeRequest,
) -> Result<Value, CodingToolStepModuleCommandError> {
    let workspace_root = required_workspace_root(&request)?;
    let mut core_request = request.try_core_request()?;
    let patch = apply_workspace_patch(&workspace_root, &request.input).map_err(workspace_error)?;
    let mut expected_heads = vec![];
    if let Some(transition) = patch.transition.as_ref() {
        core_request.invocation.input.state_root_before =
            Some(transition.state_root_before.clone());
        core_request.invocation.input.projection_watermark = Some(format!(
            "projection://agentgres/{}",
            transition.resulting_head
        ));
        expected_heads = transition.expected_heads.clone();
    }
    let mut result = successful_coding_tool_step_module_result(
        &core_request,
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
        core_request,
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
    let core_request = request.try_core_request()?;
    let test_result = inspect_test_run(&workspace_root, &request.input).map_err(workspace_error)?;
    let result =
        successful_coding_tool_step_module_result(&core_request, "test.run", "TestRunNode");
    Ok(coding_tool_step_module_response(
        core_request,
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
    let core_request = request.try_core_request()?;
    let diagnostics_result =
        inspect_lsp_diagnostics(&workspace_root, &request.input).map_err(workspace_error)?;
    let result = successful_coding_tool_step_module_result(
        &core_request,
        "lsp.diagnostics",
        "LspDiagnosticsNode",
    );
    Ok(coding_tool_step_module_response(
        core_request,
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
    let core_request = request.try_core_request()?;
    let read_result = normalize_artifact_read(&request.input).map_err(artifact_error)?;
    let mut result = successful_coding_tool_step_module_result(
        &core_request,
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
        core_request,
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
    let core_request = request.try_core_request()?;
    let retrieve_result = normalize_tool_retrieve_result(&request.input).map_err(artifact_error)?;
    let mut result = successful_coding_tool_step_module_result(
        &core_request,
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
        core_request,
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
    let core_request = request.try_core_request()?;
    let lease_request = build_computer_use_lease_request(&workspace_root, &request.input)
        .map_err(computer_use_error)?;
    let mut result = successful_coding_tool_step_module_result(
        &core_request,
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
        core_request,
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
    fn try_core_request(
        &self,
    ) -> Result<CodingToolStepModuleRequest, CodingToolStepModuleCommandError> {
        if self.invocation.is_some() {
            return Err(CodingToolStepModuleCommandError::new(
                "js_step_module_invocation_retired",
                "coding-tool StepModule invocations are constructed by Rust daemon-core"
                    .to_string(),
            ));
        }
        let backend = trimmed_required("backend", Some(&self.backend))?;
        if backend != RUST_WORKLOAD_LIVE_BACKEND {
            return Err(CodingToolStepModuleCommandError::new(
                "rust_workload_live_required",
                format!("coding-tool StepModule execution requires {RUST_WORKLOAD_LIVE_BACKEND}"),
            ));
        }
        let tool_id = self.required_tool_id()?;
        let contract = coding_tool_contract(&tool_id)?;
        let input_hash = step_module_value_hash(&self.input)?;
        let thread_id = trimmed_optional(self.thread_id.as_deref());
        let run_id = trimmed_optional(self.run_id.as_deref())
            .or_else(|| thread_id.as_ref().map(|value| format!("run:{value}")))
            .unwrap_or_else(|| "run:coding-tool".to_string());
        let task_id = trimmed_optional(self.task_id.as_deref())
            .or_else(|| thread_id.as_ref().map(|value| format!("task:{value}")))
            .unwrap_or_else(|| "task:coding-tool".to_string());
        let workflow_graph_id = trimmed_optional(self.workflow_graph_id.as_deref());
        let workflow_node_id = trimmed_optional(self.workflow_node_id.as_deref())
            .or_else(|| Some(format!("node:coding-tool:{}", safe_ref_path(&tool_id))));
        let action_proposal_ref = trimmed_optional(self.action_proposal_ref.as_deref())
            .unwrap_or_else(|| format!("action:coding-tool:{}", safe_ref_path(&tool_id)));
        let gate_result_ref = trimmed_optional(self.gate_result_ref.as_deref())
            .unwrap_or_else(|| format!("gate:coding-tool:{}", safe_ref_path(&tool_id)));
        let idempotency_key =
            trimmed_optional(self.idempotency_key.as_deref()).unwrap_or_else(|| {
                format!(
                    "step-module:{run_id}:{task_id}:{tool_id}:{}",
                    short_hash_suffix(&input_hash, 16)
                )
            });
        let invocation_hash = step_module_value_hash(&json!({
            "run_id": run_id.clone(),
            "task_id": task_id.clone(),
            "tool_id": tool_id.clone(),
            "input_hash": input_hash.clone(),
            "idempotency_key": idempotency_key.clone(),
        }))?;
        let invocation_id = format!(
            "invocation://rust-daemon-core/coding-tool/{}",
            short_hash_suffix(&invocation_hash, 32)
        );
        let invocation = StepModuleInvocation {
            schema_version: STEP_MODULE_INVOCATION_SCHEMA_VERSION.to_string(),
            invocation_id,
            run_id,
            task_id,
            thread_id,
            workflow_graph_id,
            workflow_node_id,
            context_chamber_ref: trimmed_optional(self.context_chamber_ref.as_deref()),
            action_proposal_ref,
            gate_result_ref,
            module_ref: StepModuleRef {
                kind: StepModuleKind::WorkloadJob,
                id: tool_id.clone(),
                version: contract.schema_version.to_string(),
                manifest_ref: trimmed_optional(self.manifest_ref.as_deref()),
            },
            actor: StepModuleActor {
                actor_id: DEFAULT_ACTOR_ID.to_string(),
                runtime_node_ref: DEFAULT_RUNTIME_NODE_REF.to_string(),
            },
            authority: StepModuleAuthority {
                authority_grant_refs: unique_string_refs(self.authority_grant_refs.clone()),
                policy_hash: DEFAULT_POLICY_HASH.to_string(),
                primitive_capabilities: contract
                    .primitive_capabilities
                    .iter()
                    .map(|value| value.to_string())
                    .collect(),
                authority_scopes: contract
                    .authority_scope_requirements
                    .iter()
                    .map(|value| value.to_string())
                    .collect(),
                approval_ref: trimmed_optional(self.approval_ref.as_deref()),
            },
            input: StepModuleInput {
                input_hash,
                expected_schema_ref: format!("schema://coding-tool/{tool_id}/input"),
                context_refs: vec![],
                artifact_refs: unique_string_refs(self.artifact_refs.clone()),
                payload_refs: unique_string_refs(self.payload_refs.clone()),
                state_root_before: trimmed_optional(self.state_root_before.as_deref()),
                projection_watermark: trimmed_optional(self.projection_watermark.as_deref()),
                data_plane_handle: self.data_plane_handle.clone(),
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
                idempotency_key,
                deadline_ms: self.deadline_ms.unwrap_or(60_000),
                resource_lease_ref: None,
                retry_policy_ref: None,
            },
        };
        invocation.validate().map_err(|errors| {
            CodingToolStepModuleCommandError::new("invocation_invalid", format!("{errors:?}"))
        })?;
        Ok(CodingToolStepModuleRequest {
            backend,
            invocation,
        })
    }

    fn required_tool_id(&self) -> Result<String, CodingToolStepModuleCommandError> {
        let tool_id = trimmed_required("tool_id", self.tool_id.as_deref())?;
        coding_tool_contract(&tool_id)?;
        Ok(tool_id)
    }
}

#[derive(Debug, Clone, Copy)]
struct CodingToolContract {
    schema_version: &'static str,
    primitive_capabilities: &'static [&'static str],
    authority_scope_requirements: &'static [&'static str],
}

fn coding_tool_contract(
    tool_id: &str,
) -> Result<CodingToolContract, CodingToolStepModuleCommandError> {
    let contract = match tool_id {
        "workspace.status" => CodingToolContract {
            schema_version: CODING_TOOL_PACK_SCHEMA_VERSION,
            primitive_capabilities: &["prim:workspace.status", "prim:git.status"],
            authority_scope_requirements: &[],
        },
        "git.diff" => CodingToolContract {
            schema_version: CODING_TOOL_PACK_SCHEMA_VERSION,
            primitive_capabilities: &["prim:git.diff"],
            authority_scope_requirements: &[],
        },
        "file.inspect" => CodingToolContract {
            schema_version: CODING_TOOL_PACK_SCHEMA_VERSION,
            primitive_capabilities: &["prim:fs.inspect"],
            authority_scope_requirements: &[],
        },
        "file.apply_patch" => CodingToolContract {
            schema_version: CODING_TOOL_PACK_SCHEMA_VERSION,
            primitive_capabilities: &["prim:fs.apply_patch", "prim:fs.write"],
            authority_scope_requirements: &["scope:workspace.write"],
        },
        "test.run" => CodingToolContract {
            schema_version: CODING_TOOL_PACK_SCHEMA_VERSION,
            primitive_capabilities: &["prim:test.run", "prim:process.exec_file"],
            authority_scope_requirements: &["scope:workspace.test"],
        },
        "lsp.diagnostics" => CodingToolContract {
            schema_version: CODING_TOOL_PACK_SCHEMA_VERSION,
            primitive_capabilities: &["prim:lsp.diagnostics", "prim:process.exec_file"],
            authority_scope_requirements: &[],
        },
        "artifact.read" => CodingToolContract {
            schema_version: CODING_TOOL_PACK_SCHEMA_VERSION,
            primitive_capabilities: &["prim:artifact.read"],
            authority_scope_requirements: &[],
        },
        "tool.retrieve_result" => CodingToolContract {
            schema_version: CODING_TOOL_PACK_SCHEMA_VERSION,
            primitive_capabilities: &["prim:tool.retrieve_result", "prim:artifact.read"],
            authority_scope_requirements: &[],
        },
        "computer_use.request_lease" => CodingToolContract {
            schema_version: CODING_TOOL_PACK_SCHEMA_VERSION,
            primitive_capabilities: &[
                "prim:computer_use.lease.request",
                "prim:computer_use.manifest",
            ],
            authority_scope_requirements: &["computer_use.lease.request"],
        },
        other => {
            return Err(CodingToolStepModuleCommandError::new(
                "tool_unsupported",
                format!("unsupported StepModule tool {other}"),
            ));
        }
    };
    Ok(contract)
}

fn trimmed_required(
    field: &'static str,
    value: Option<&str>,
) -> Result<String, CodingToolStepModuleCommandError> {
    trimmed_optional(value).ok_or_else(|| {
        CodingToolStepModuleCommandError::new(
            "required_field_missing",
            format!("{field} is required"),
        )
    })
}

fn trimmed_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn step_module_value_hash(value: &Value) -> Result<String, CodingToolStepModuleCommandError> {
    let stable = stable_json_value(value)?;
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(stable.as_bytes()))
    ))
}

fn stable_json_value(value: &Value) -> Result<String, CodingToolStepModuleCommandError> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).map_err(hash_error)
        }
        Value::Array(items) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                parts.push(stable_json_value(item)?);
            }
            Ok(format!("[{}]", parts.join(",")))
        }
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            let mut parts = Vec::with_capacity(keys.len());
            for key in keys {
                let key_json = serde_json::to_string(key).map_err(hash_error)?;
                let value_json = stable_json_value(&map[key])?;
                parts.push(format!("{key_json}:{value_json}"));
            }
            Ok(format!("{{{}}}", parts.join(",")))
        }
    }
}

fn hash_error(error: serde_json::Error) -> CodingToolStepModuleCommandError {
    CodingToolStepModuleCommandError::new("hash_failed", error.to_string())
}

fn short_hash_suffix(value: &str, len: usize) -> String {
    value
        .trim_start_matches("sha256:")
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(len)
        .collect()
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
    use std::fs;

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
    fn rust_core_builds_coding_tool_invocation_from_canonical_request() {
        let request = bridge_request(
            "file.apply_patch",
            "/tmp/workspace",
            json!({
                "path": "README.md",
                "oldText": "before",
                "newText": "after"
            }),
        );

        let core_request = request
            .try_core_request()
            .expect("canonical request should build invocation");

        assert_eq!(core_request.backend, RUST_WORKLOAD_LIVE_BACKEND);
        assert_eq!(
            core_request.invocation.module_ref.kind,
            StepModuleKind::WorkloadJob
        );
        assert_eq!(core_request.invocation.module_ref.id, "file.apply_patch");
        assert_eq!(
            core_request.invocation.module_ref.version,
            CODING_TOOL_PACK_SCHEMA_VERSION
        );
        assert_eq!(
            core_request.invocation.execution.backend,
            StepModuleBackend::WorkloadGrpc
        );
        assert_eq!(
            core_request.invocation.authority.primitive_capabilities,
            vec!["prim:fs.apply_patch", "prim:fs.write"]
        );
        assert_eq!(
            core_request.invocation.authority.authority_scopes,
            vec!["scope:workspace.write"]
        );
        assert_eq!(
            core_request.invocation.input.expected_schema_ref,
            "schema://coding-tool/file.apply_patch/input"
        );
        assert!(core_request
            .invocation
            .input
            .input_hash
            .starts_with("sha256:"));
        assert!(core_request
            .invocation
            .invocation_id
            .starts_with("invocation://rust-daemon-core/coding-tool/"));
    }

    #[test]
    fn rust_core_rejects_js_supplied_coding_tool_step_module_invocation() {
        let mut request = bridge_request("workspace.status", "/tmp/workspace", json!({}));
        request.invocation = Some(json!({
            "schema_version": STEP_MODULE_INVOCATION_SCHEMA_VERSION,
            "invocation_id": "invocation://js-owned"
        }));

        let error = run_coding_tool_step_module_response(request)
            .expect_err("JS-supplied invocation must be retired");

        assert_eq!(error.code(), "js_step_module_invocation_retired");
    }

    #[test]
    fn rust_core_rejects_non_live_coding_tool_step_module_backend() {
        let mut request = bridge_request("workspace.status", "/tmp/workspace", json!({}));
        request.backend = "rust_workload_shadow".to_string();

        let error =
            run_coding_tool_step_module_response(request).expect_err("non-live backend must fail");

        assert_eq!(error.code(), "rust_workload_live_required");
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

    #[test]
    fn rust_core_file_apply_patch_writes_and_binds_agentgres_admission() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("README.md"), "before\n").expect("fixture file");
        let request = bridge_request(
            "file.apply_patch",
            workspace.to_str().expect("utf8 path"),
            json!({
                "path": "README.md",
                "oldText": "before",
                "newText": "after"
            }),
        );

        let response = file_apply_patch_response(request).expect("patch response");

        assert_eq!(
            fs::read_to_string(workspace.join("README.md")).expect("updated file"),
            "after\n"
        );
        assert_eq!(response["workload_observation"]["result"]["applied"], true);
        assert_eq!(
            response["router_admission"]["authoritative_transition"],
            true
        );
        assert_eq!(
            response["workload_dispatch"]["schema_version"],
            WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION,
        );
        assert_eq!(
            response["result"]["agentgres_operation_refs"][0],
            response["agentgres_admission"]["operation_ref"],
        );
        assert!(response["result"]["state_root_after"]
            .as_str()
            .expect("state root")
            .starts_with("state://workspace/"));
        assert_eq!(
            response["agentgres_admission"]["state_root_after"],
            response["result"]["state_root_after"],
        );
    }

    #[test]
    fn rust_core_file_apply_patch_dry_run_has_no_agentgres_transition() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("README.md"), "before\n").expect("fixture file");
        let request = bridge_request(
            "file.apply_patch",
            workspace.to_str().expect("utf8 path"),
            json!({
                "path": "README.md",
                "oldText": "before",
                "newText": "after",
                "dryRun": true
            }),
        );

        let response = file_apply_patch_response(request).expect("patch response");

        assert_eq!(
            fs::read_to_string(workspace.join("README.md")).expect("original file"),
            "before\n"
        );
        assert_eq!(response["workload_observation"]["result"]["applied"], false);
        assert_eq!(response["result"]["agentgres_operation_refs"], json!([]));
        assert_eq!(response["agentgres_admission"], Value::Null);
        assert_eq!(response["result"]["state_root_after"], Value::Null);
    }

    #[test]
    fn rust_core_artifact_read_uses_prefetched_data_plane_payload() {
        let request = bridge_request(
            "artifact.read",
            "/tmp",
            json!({
                "artifact_id": "artifact_alpha",
                "rust_workload_data_plane": {
                    "schema_version": "ioi.runtime.coding-tool-data-plane.v1",
                    "source": "daemon_artifact_store",
                    "operation": "artifact.read",
                    "artifact_id": "artifact_alpha",
                    "result": {
                        "schema_version": "ioi.runtime.coding-tool-result.v1",
                        "artifact_id": "artifact_alpha",
                        "artifact_ref": "artifact_alpha",
                        "artifact_refs": ["artifact_alpha"],
                        "content": "hello artifact\n",
                        "receipt_refs": ["receipt_artifact_prefetch"],
                        "schemaVersion": "retired",
                        "artifactRefs": ["retired_artifact"],
                        "contentHash": "retired-hash",
                        "receiptRefs": ["retired_receipt"],
                        "shellFallbackUsed": true
                    }
                }
            }),
        );

        let response = artifact_read_response(request).expect("artifact read response");

        assert_eq!(
            response["workload_observation"]["result"]["backend"],
            "rust_artifact_read"
        );
        assert_eq!(
            response["workload_observation"]["result"]["data_plane_source"],
            "daemon_artifact_store"
        );
        assert_eq!(
            response["workload_observation"]["result"]["shell_fallback_used"],
            false
        );
        assert_eq!(
            response["workload_observation"]["result"]["content_hash"]
                .as_str()
                .expect("content hash")
                .len(),
            64
        );
        for retired_field in [
            "schemaVersion",
            "artifactRefs",
            "contentHash",
            "receiptRefs",
            "shellFallbackUsed",
        ] {
            assert_eq!(
                response["workload_observation"]["result"][retired_field],
                Value::Null
            );
        }
        assert_eq!(
            response["result"]["artifact_refs"],
            json!(["artifact_alpha"])
        );
        assert!(response["result"]["receipt_refs"]
            .as_array()
            .expect("receipt refs")
            .iter()
            .any(|value| value == "receipt_artifact_prefetch"));
    }

    #[test]
    fn rust_core_artifact_read_requires_prefetched_data_plane_payload() {
        let request = bridge_request(
            "artifact.read",
            "/tmp",
            json!({
                "artifact_id": "artifact_alpha"
            }),
        );

        let error = artifact_read_response(request).expect_err("missing payload should fail");

        assert_eq!(error.code(), "data_plane_payload_required");
    }

    #[test]
    fn rust_core_tool_retrieve_result_uses_prefetched_data_plane_payload() {
        let request = bridge_request(
            "tool.retrieve_result",
            "/tmp",
            json!({
                "tool_call_id": "tool_patch",
                "channel": "stdout",
                "rust_workload_data_plane": {
                    "schema_version": "ioi.runtime.coding-tool-data-plane.v1",
                    "source": "daemon_artifact_store",
                    "operation": "tool.retrieve_result",
                    "query": {
                        "tool_call_id": "tool_patch",
                        "channel": "stdout"
                    },
                    "result": {
                        "schema_version": "ioi.runtime.coding-tool-result.v1",
                        "tool_call_id": "tool_patch",
                        "artifact_id": "artifact_result",
                        "artifact_ref": "artifact_result",
                        "artifact_refs": ["artifact_result"],
                        "channel": "stdout",
                        "content": "stored stdout\n",
                        "receipt_refs": ["receipt_tool_result_prefetch"],
                        "schemaVersion": "retired",
                        "artifactRefs": ["retired_artifact"],
                        "contentHash": "retired-hash",
                        "receiptRefs": ["retired_receipt"],
                        "shellFallbackUsed": true
                    }
                }
            }),
        );

        let response = tool_retrieve_result_response(request).expect("retrieve response");

        assert_eq!(
            response["workload_observation"]["result"]["backend"],
            "rust_tool_result_retrieve"
        );
        assert_eq!(
            response["workload_observation"]["result"]["tool_call_id"],
            "tool_patch"
        );
        assert_eq!(
            response["workload_observation"]["result"]["content_hash"]
                .as_str()
                .expect("content hash")
                .len(),
            64
        );
        for retired_field in [
            "schemaVersion",
            "artifactRefs",
            "contentHash",
            "receiptRefs",
            "shellFallbackUsed",
        ] {
            assert_eq!(
                response["workload_observation"]["result"][retired_field],
                Value::Null
            );
        }
        assert_eq!(
            response["result"]["artifact_refs"],
            json!(["artifact_result"])
        );
        assert!(response["result"]["receipt_refs"]
            .as_array()
            .expect("receipt refs")
            .iter()
            .any(|value| value == "receipt_tool_result_prefetch"));
    }

    #[test]
    fn rust_core_computer_use_request_lease_ignores_retired_aliases() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try retired aliases.",
                "computerUseLane": "sandboxed_hosted",
                "actionKind": "click",
                "approvalRef": "approval_legacy",
                "targetRef": "target_retired",
                "sessionMode": "hosted_sandbox",
                "observationRetentionMode": "local_raw_artifacts"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");
        let workload_result = &response["workload_observation"]["result"];

        assert_eq!(workload_result["lease_request"]["lane"], "native_browser");
        assert_eq!(workload_result["lease_request"]["action_kind"], "inspect");
        assert_eq!(
            workload_result["lease_request"]["approval_ref"],
            Value::Null
        );
        assert_eq!(
            workload_result["lease_request"]["authority_scope"],
            "computer_use.native_browser.read"
        );
        assert_eq!(
            workload_result["thread_tool"]["input"]["target_ref"],
            Value::Null
        );
        assert_eq!(
            workload_result["thread_tool"]["input"]["session_mode"],
            "owned_hermetic_browser"
        );
        assert_eq!(
            workload_result["thread_tool"]["input"]["observation_retention_mode"],
            "prompt_visible_summary_only"
        );
    }

    #[test]
    fn rust_core_computer_use_request_lease_ignores_retired_approval_alias() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to satisfy approval through a retired alias.",
                "lane": "native_browser",
                "action_kind": "click",
                "approvalRef": "approval_legacy"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");
        let workload_result = &response["workload_observation"]["result"];

        assert_eq!(
            workload_result["lease_request"]["authority_scope"],
            "computer_use.native_browser.act"
        );
        assert_eq!(
            workload_result["lease_request"]["approval_ref"],
            Value::Null
        );
        assert_eq!(workload_result["approval_required_before_execution"], true);
        assert_eq!(
            workload_result["wallet_network_authority_boundary"]["required_before_execution"],
            true
        );
    }

    #[test]
    fn rust_core_computer_use_request_lease_ignores_retired_action_kind_alias() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to escalate authority through a retired action alias.",
                "lane": "native_browser",
                "actionKind": "click"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");
        let workload_result = &response["workload_observation"]["result"];

        assert_eq!(workload_result["lease_request"]["action_kind"], "inspect");
        assert_eq!(
            workload_result["lease_request"]["authority_scope"],
            "computer_use.native_browser.read"
        );
        assert_eq!(workload_result["approval_required_before_execution"], false);
        assert_eq!(
            workload_result["wallet_network_authority_boundary"]["required_before_execution"],
            false
        );
    }

    #[test]
    fn rust_core_computer_use_request_lease_binds_canonical_receipt_and_request_refs() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Bind canonical computer-use refs.",
                "lane": "native_browser",
                "action_kind": "inspect"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");
        let workload_result = &response["workload_observation"]["result"];
        let canonical_receipt_ref = workload_result["receipt_refs"][0]
            .as_str()
            .expect("canonical receipt ref");
        let canonical_request_ref = workload_result["request_ref"]
            .as_str()
            .expect("canonical request ref");
        let evidence_ref =
            format!("evidence://rust-workload/computer_use.request_lease/{canonical_request_ref}");

        assert!(response["result"]["receipt_refs"]
            .as_array()
            .expect("result receipt refs")
            .iter()
            .any(|value| value == canonical_receipt_ref));
        assert!(response["result"]["workflow_projection"]["evidence_refs"]
            .as_array()
            .expect("projection evidence refs")
            .iter()
            .any(|value| value == &evidence_ref));
        for retired_field in [
            "schemaVersion",
            "requestRef",
            "leaseRequest",
            "threadTool",
            "providerRegistry",
            "approvalRequiredBeforeExecution",
            "walletNetworkAuthorityBoundary",
            "evidenceRefs",
            "receiptRefs",
            "shellFallbackUsed",
        ] {
            assert!(
                workload_result.get(retired_field).is_none(),
                "retired workload result field {retired_field} must not be emitted"
            );
        }
    }

    fn bridge_request(
        tool_id: &str,
        workspace_root: &str,
        input: Value,
    ) -> CodingToolStepModuleBridgeRequest {
        CodingToolStepModuleBridgeRequest {
            backend: RUST_WORKLOAD_LIVE_BACKEND.to_string(),
            tool_id: Some(tool_id.to_string()),
            workspace_root: Some(workspace_root.to_string()),
            input,
            run_id: Some("run:coding-tool-step-module".to_string()),
            task_id: Some("task:coding-tool-step-module".to_string()),
            thread_id: Some("thread:coding-tool-step-module".to_string()),
            workflow_graph_id: Some("workflow:coding-tool-step-module".to_string()),
            workflow_node_id: Some(format!("node:test:{tool_id}")),
            action_proposal_ref: Some(format!("action:test:{tool_id}")),
            gate_result_ref: Some(format!("gate:test:{tool_id}")),
            idempotency_key: Some(format!("idempotency:test:{tool_id}")),
            ..Default::default()
        }
    }
}
