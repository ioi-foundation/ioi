use ioi_client::workload_client::{
    WorkloadClient, WorkloadStepModuleDispatchRequest, WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION,
};
use ioi_services::agentic::evolution::{GovernedEvolutionCore, GovernedRuntimeImprovementProposal};
use ioi_services::agentic::runtime::kernel::agentgres_admission::{
    AgentgresAdmissionCore, AgentgresOperationProposal, RuntimeAgentStateCommitRequest,
    RuntimeArtifactStateCommitRequest, RuntimeMemoryStateCommitRequest,
    RuntimeModelMountReceiptStateCommitRequest, RuntimeModelMountRecordStateCommitRequest,
    RuntimeRunStateCommitRequest, RuntimeStatePersistenceRecord, RuntimeStateStorageWriteRecord,
    RuntimeSubagentStateCommitRequest, StorageBackendWriteProposal,
    AGENTGRES_ADMISSION_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::approval::{
    ApprovalDecisionStateUpdateCore, ApprovalDecisionStateUpdateRequest,
    ApprovalRequestStateUpdateCore, ApprovalRequestStateUpdateRequest,
    ApprovalRevokeStateUpdateCore, ApprovalRevokeStateUpdateRequest, CodingToolApprovalCore,
    CodingToolApprovalRequest,
};
use ioi_services::agentic::runtime::kernel::authority::{
    ExternalCapabilityExitRequest, WalletAuthorityCore,
};
use ioi_services::agentic::runtime::kernel::ctee::{CteeNodeTrust, PrivateWorkspaceCteeModule};
use ioi_services::agentic::runtime::kernel::marketplace::{
    WorkerServicePackageInvocationCore, WorkerServicePackageInvocationRequest,
};
use ioi_services::agentic::runtime::kernel::model_mount::{
    ModelMountAcceptedReceiptHeadRequest, ModelMountAcceptedReceiptTransition,
    ModelMountAcceptedReceiptTransitionRequest, ModelMountBackendProcessPlanRequest,
    ModelMountCore, ModelMountInstanceLifecycleRequest, ModelMountInvocationAdmissionRequest,
    ModelMountProviderExecutionRequest, ModelMountProviderInventoryRequest,
    ModelMountProviderInvocationRequest, ModelMountProviderLifecycleRequest,
    ModelMountProviderResultAdmissionRequest, ModelMountRouteDecisionRequest,
};
use ioi_services::agentic::runtime::kernel::policy::{
    AgentCreateStateUpdateCore, AgentCreateStateUpdateRequest, AgentStatusStateUpdateCore,
    AgentStatusStateUpdateRequest, CodingToolBudgetRecoveryStateUpdateCore,
    CodingToolBudgetRecoveryStateUpdateRequest, CompactionPolicyCore, CompactionPolicyRequest,
    ContextBudgetPolicyCore, ContextBudgetPolicyRequest, ContextCompactionPlanCore,
    ContextCompactionPlanRequest, ContextCompactionStateUpdateCore,
    ContextCompactionStateUpdateRequest, DiagnosticsOperatorOverrideStateUpdateCore,
    DiagnosticsOperatorOverrideStateUpdateRequest, McpControlAgentStateUpdateCore,
    McpControlAgentStateUpdateRequest, McpManagerCatalogProjectionCore,
    McpManagerCatalogProjectionRequest, McpManagerCatalogSummaryProjectionCore,
    McpManagerCatalogSummaryProjectionRequest, McpManagerStatusProjectionCore,
    McpManagerStatusProjectionRequest, McpManagerValidationProjectionCore,
    McpManagerValidationProjectionRequest, McpServerValidationCore, McpServerValidationInputCore,
    McpServerValidationInputRequest, McpServerValidationRequest, MemoryManagerStatusProjectionCore,
    MemoryManagerStatusProjectionRequest, MemoryManagerValidationProjectionCore,
    MemoryManagerValidationProjectionRequest, OperatorInterruptStateUpdateCore,
    OperatorInterruptStateUpdateRequest, OperatorSteerStateUpdateCore,
    OperatorSteerStateUpdateRequest, RunCancelStateUpdateCore, RunCancelStateUpdateRequest,
    RunCreateStateUpdateCore, RunCreateStateUpdateRequest,
    RuntimeBridgeThreadStartAgentStateUpdateCore, RuntimeBridgeThreadStartAgentStateUpdateRequest,
    RuntimeBridgeTurnRunStateUpdateCore, RuntimeBridgeTurnRunStateUpdateRequest,
    SubagentRecordStateUpdateCore, SubagentRecordStateUpdateRequest,
    ThreadControlAgentStateUpdateCore, ThreadControlAgentStateUpdateRequest,
    ThreadMemoryAgentStateUpdateCore, ThreadMemoryAgentStateUpdateRequest,
};
use ioi_services::agentic::runtime::kernel::projection::RustProjectionCore;
use ioi_services::agentic::runtime::kernel::receipt_binder::{
    AcceptedReceiptAppendIssuer, AcceptedReceiptAppendRequest, ReceiptBinder,
    ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::settlement::{
    L1SettlementAttempt, L1SettlementTriggerGuard,
};
use ioi_services::agentic::runtime::kernel::step_module::{
    StepModuleBackend, StepModuleInvocation, StepModuleKind, StepModuleNext,
    StepModuleProjectionStatus, StepModuleResult, StepModuleStatus, StepModuleWorkflowProjection,
    STEP_MODULE_RESULT_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::step_router::StepModuleRouterCore;
use ioi_services::agentic::runtime::kernel::workspace_restore::{
    WorkspaceRestoreApplyPolicyCore, WorkspaceRestoreApplyPolicyRequest,
    WorkspaceRestoreOperationsCore, WorkspaceRestoreOperationsRequest,
    WorkspaceSnapshotCaptureCore, WorkspaceSnapshotCaptureRequest,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

mod computer_use;

const STEP_MODULE_COMMAND_SCHEMA_VERSION: &str = "ioi.step_module.command_bridge.v1";
const DAEMON_CORE_COMMAND_SCHEMA_VERSION: &str = "ioi.runtime.daemon_core.command.v1";
const COMMAND_SCHEMA_VERSION: &str = STEP_MODULE_COMMAND_SCHEMA_VERSION;
const CODING_TOOL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-result.v1";
const MODEL_MOUNT_RUNTIME_SCHEMA_VERSION: &str = "ioi.model-mounting.runtime.v1";
const MODEL_CAPABILITY_SCHEMA_VERSION: &str = "ioi.model-capability.v1";
const DEFAULT_PREVIEW_BYTES: u64 = 16 * 1024;
const MAX_PREVIEW_BYTES: u64 = 64 * 1024;
const MAX_DIFF_BYTES: u64 = 64 * 1024;
const DIAGNOSTIC_DEFAULT_TIMEOUT_MS: u64 = 30 * 1000;
const DIAGNOSTIC_MAX_TIMEOUT_MS: u64 = 2 * 60 * 1000;
const DIAGNOSTIC_DEFAULT_OUTPUT_BYTES: u64 = 64 * 1024;
const DIAGNOSTIC_MAX_OUTPUT_BYTES: u64 = 64 * 1024;
const TEST_DEFAULT_TIMEOUT_MS: u64 = 60 * 1000;
const TEST_MAX_TIMEOUT_MS: u64 = 5 * 60 * 1000;
const TEST_DEFAULT_OUTPUT_BYTES: u64 = 64 * 1024;
const TEST_MAX_OUTPUT_BYTES: u64 = 64 * 1024;
const APPLY_PATCH_MAX_FILE_BYTES: u64 = 1024 * 1024;
const APPLY_PATCH_MAX_DIFF_BYTES: usize = 32 * 1024;
const APPLY_PATCH_MAX_EDITS: usize = 20;
const DEFAULT_PREVIEW_LINES: usize = 200;
const MAX_PREVIEW_LINES: usize = 500;
const DIAGNOSTIC_COMMAND_IDS: [&str; 3] = ["auto", "node.check", "typescript.check"];
const TEST_COMMAND_IDS: [&str; 4] = ["node.test", "npm.test", "cargo.test", "cargo.check"];

#[derive(Debug, Deserialize)]
struct BridgeEnvelope {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
}

#[derive(Debug, Deserialize)]
struct StepModuleBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    backend: String,
    invocation: StepModuleInvocation,
    #[serde(default)]
    workspace_root: Option<String>,
    #[serde(default)]
    input: Value,
}

#[derive(Debug, Deserialize)]
struct ModelMountRouteDecisionBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountRouteDecisionRequest,
}

#[derive(Debug, Deserialize)]
struct ModelMountInvocationAdmissionBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountInvocationAdmissionRequest,
}

#[derive(Debug, Deserialize)]
struct ModelMountProviderExecutionBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountProviderExecutionRequest,
}

#[derive(Debug, Deserialize)]
struct ModelMountProviderInvocationBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountProviderInvocationRequest,
}

#[derive(Debug, Deserialize)]
struct ModelMountProviderLifecycleBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountProviderLifecycleRequest,
}

#[derive(Debug, Deserialize)]
struct ModelMountProviderInventoryBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountProviderInventoryRequest,
}

#[derive(Debug, Deserialize)]
struct ModelMountInstanceLifecycleBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountInstanceLifecycleRequest,
}

#[derive(Debug, Deserialize)]
struct ModelMountProviderResultAdmissionBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountProviderResultAdmissionRequest,
}

#[derive(Debug, Deserialize)]
struct ModelMountBackendProcessPlanBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountBackendProcessPlanRequest,
}

#[derive(Debug, Deserialize)]
struct ModelMountAcceptedReceiptHeadBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountAcceptedReceiptHeadRequest,
}

#[derive(Debug, Deserialize)]
struct ModelMountAcceptedReceiptTransitionBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountAcceptedReceiptTransitionRequest,
}

#[derive(Debug, Deserialize)]
struct ModelMountInvocationReceiptBindingBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    invocation: StepModuleInvocation,
    result: StepModuleResult,
    #[serde(default)]
    expected_heads: Vec<String>,
    #[serde(default)]
    accepted_receipt_transition: Option<ModelMountAcceptedReceiptTransition>,
    #[serde(default)]
    receipt_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ModelMountReadProjectionBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountReadProjectionRequest,
}

#[derive(Debug, Deserialize)]
struct ModelMountReadProjectionRequest {
    projection_kind: String,
    #[serde(default)]
    schema_version: Option<String>,
    #[serde(default)]
    generated_at: Option<String>,
    #[serde(default)]
    receipt_id: Option<String>,
    #[serde(default)]
    engine_id: Option<String>,
    #[serde(default)]
    provider_id: Option<String>,
    state: Value,
}

#[derive(Debug, Deserialize)]
struct CteePrivateWorkspaceBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    invocation: StepModuleInvocation,
    node_trust: CteeNodeTrust,
    #[serde(default)]
    expected_heads: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct WorkerServicePackageInvocationBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: WorkerServicePackageInvocationRequest,
}

#[derive(Debug, Deserialize)]
struct L1SettlementAdmissionBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    attempt: L1SettlementAttempt,
}

#[derive(Debug, Deserialize)]
struct GovernedRuntimeImprovementBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    proposal: GovernedRuntimeImprovementProposal,
}

#[derive(Debug, Deserialize)]
struct WorkspaceRestoreApplyPolicyBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: WorkspaceRestoreApplyPolicyRequest,
}

#[derive(Debug, Deserialize)]
struct WorkspaceRestoreOperationsBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: WorkspaceRestoreOperationsRequest,
}

#[derive(Debug, Deserialize)]
struct WorkspaceSnapshotCaptureBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: WorkspaceSnapshotCaptureRequest,
}

#[derive(Debug, Deserialize)]
struct CodingToolApprovalBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: CodingToolApprovalRequest,
}

#[derive(Debug, Deserialize)]
struct ApprovalRequestStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ApprovalRequestStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct ApprovalDecisionStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ApprovalDecisionStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct ApprovalRevokeStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ApprovalRevokeStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct ContextBudgetPolicyBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ContextBudgetPolicyRequest,
}

#[derive(Debug, Deserialize)]
struct CompactionPolicyBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: CompactionPolicyRequest,
}

#[derive(Debug, Deserialize)]
struct ContextCompactionPlanBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ContextCompactionPlanRequest,
}

#[derive(Debug, Deserialize)]
struct ContextCompactionStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ContextCompactionStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct CodingToolBudgetRecoveryStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: CodingToolBudgetRecoveryStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct DiagnosticsOperatorOverrideStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: DiagnosticsOperatorOverrideStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct OperatorInterruptStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: OperatorInterruptStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct OperatorSteerStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: OperatorSteerStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct RunCancelStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: RunCancelStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct ThreadControlAgentStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ThreadControlAgentStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct McpControlAgentStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: McpControlAgentStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct McpServerValidationBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: McpServerValidationRequest,
}

#[derive(Debug, Deserialize)]
struct McpServerValidationInputBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: McpServerValidationInputRequest,
}

#[derive(Debug, Deserialize)]
struct McpManagerStatusProjectionBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: McpManagerStatusProjectionRequest,
}

#[derive(Debug, Deserialize)]
struct McpManagerValidationProjectionBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: McpManagerValidationProjectionRequest,
}

#[derive(Debug, Deserialize)]
struct MemoryManagerStatusProjectionBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: MemoryManagerStatusProjectionRequest,
}

#[derive(Debug, Deserialize)]
struct MemoryManagerValidationProjectionBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: MemoryManagerValidationProjectionRequest,
}

#[derive(Debug, Deserialize)]
struct McpManagerCatalogProjectionBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: McpManagerCatalogProjectionRequest,
}

#[derive(Debug, Deserialize)]
struct McpManagerCatalogSummaryProjectionBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: McpManagerCatalogSummaryProjectionRequest,
}

#[derive(Debug, Deserialize)]
struct ThreadMemoryAgentStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ThreadMemoryAgentStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: RuntimeBridgeThreadStartAgentStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct RuntimeBridgeTurnRunStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: RuntimeBridgeTurnRunStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct SubagentRecordStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: SubagentRecordStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct AgentCreateStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: AgentCreateStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct AgentStatusStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: AgentStatusStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct RunCreateStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: RunCreateStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
struct StorageBackendWriteBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: StorageBackendWriteProposal,
}

#[derive(Debug, Deserialize)]
struct RuntimeRunStateCommitBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeRunStateCommitRequest,
}

#[derive(Debug, Deserialize)]
struct RuntimeAgentStateCommitBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeAgentStateCommitRequest,
}

#[derive(Debug, Deserialize)]
struct RuntimeMemoryStateCommitBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeMemoryStateCommitRequest,
}

#[derive(Debug, Deserialize)]
struct RuntimeSubagentStateCommitBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeSubagentStateCommitRequest,
}

#[derive(Debug, Deserialize)]
struct RuntimeArtifactStateCommitBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeArtifactStateCommitRequest,
}

#[derive(Debug, Deserialize)]
struct RuntimeModelMountRecordStateCommitBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeModelMountRecordStateCommitRequest,
}

#[derive(Debug, Deserialize)]
struct RuntimeModelMountReceiptStateCommitBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeModelMountReceiptStateCommitRequest,
}

#[derive(Debug, Deserialize)]
struct ExternalCapabilityExitAuthorityBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ExternalCapabilityExitRequest,
}

pub fn run_bridge_response_from_stdin() -> Value {
    match run_bridge() {
        Ok(response) => json!({ "ok": true, "result": response }),
        Err(error) => json!({
            "ok": false,
            "error": {
                "code": error.code,
                "message": error.message,
            }
        }),
    }
}

fn run_bridge() -> Result<Value, BridgeError> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| BridgeError::new("stdin_read_failed", error.to_string()))?;
    let raw_request: Value = serde_json::from_str(&input)
        .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
    let envelope: BridgeEnvelope = serde_json::from_value(raw_request.clone())
        .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
    let expected_schema_version = expected_command_schema_version(&envelope.operation);
    if envelope.schema_version != expected_schema_version {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                expected_schema_version, envelope.schema_version
            ),
        ));
    }

    match envelope.operation.as_str() {
        "run_coding_tool_step_module" => {
            let request: StepModuleBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            run_coding_tool_step_module(request)
        }
        "admit_model_mount_route_decision" => {
            let request: ModelMountRouteDecisionBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_model_mount_route_decision(request)
        }
        "admit_model_mount_invocation" => {
            let request: ModelMountInvocationAdmissionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_model_mount_invocation(request)
        }
        "admit_model_mount_provider_execution" => {
            let request: ModelMountProviderExecutionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_model_mount_provider_execution(request)
        }
        "execute_model_mount_provider_invocation" => {
            let request: ModelMountProviderInvocationBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            execute_model_mount_provider_invocation(request)
        }
        "execute_model_mount_provider_stream_invocation" => {
            let request: ModelMountProviderInvocationBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            execute_model_mount_provider_stream_invocation(request)
        }
        "plan_model_mount_provider_lifecycle" => {
            let request: ModelMountProviderLifecycleBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_provider_lifecycle(request)
        }
        "plan_model_mount_provider_inventory" => {
            let request: ModelMountProviderInventoryBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_provider_inventory(request)
        }
        "plan_model_mount_instance_lifecycle" => {
            let request: ModelMountInstanceLifecycleBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_instance_lifecycle(request)
        }
        "admit_model_mount_provider_result" => {
            let request: ModelMountProviderResultAdmissionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_model_mount_provider_result(request)
        }
        "plan_model_mount_backend_process" => {
            let request: ModelMountBackendProcessPlanBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_backend_process(request)
        }
        "plan_model_mount_accepted_receipt_head" => {
            let request: ModelMountAcceptedReceiptHeadBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_accepted_receipt_head(request)
        }
        "plan_model_mount_accepted_receipt_transition" => {
            let request: ModelMountAcceptedReceiptTransitionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_accepted_receipt_transition(request)
        }
        "bind_model_mount_invocation_receipt" => {
            let request: ModelMountInvocationReceiptBindingBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            bind_model_mount_invocation_receipt(request)
        }
        "plan_model_mount_read_projection" => {
            let request: ModelMountReadProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_read_projection(request)
        }
        "execute_private_workspace_ctee_action" => {
            let request: CteePrivateWorkspaceBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            execute_private_workspace_ctee_action(request)
        }
        "admit_worker_service_package_invocation" => {
            let request: WorkerServicePackageInvocationBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_worker_service_package_invocation(request)
        }
        "admit_l1_settlement_attempt" => {
            let request: L1SettlementAdmissionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_l1_settlement_attempt(request)
        }
        "admit_governed_runtime_improvement_proposal" => {
            let request: GovernedRuntimeImprovementBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_governed_runtime_improvement_proposal(request)
        }
        "plan_workspace_restore_apply_policy" => {
            let request: WorkspaceRestoreApplyPolicyBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_workspace_restore_apply_policy(request)
        }
        "preview_workspace_restore_operations" => {
            let request: WorkspaceRestoreOperationsBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            preview_workspace_restore_operations(request)
        }
        "apply_workspace_restore_operations" => {
            let request: WorkspaceRestoreOperationsBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            apply_workspace_restore_operations(request)
        }
        "capture_workspace_snapshot_files" => {
            let request: WorkspaceSnapshotCaptureBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            capture_workspace_snapshot_files(request)
        }
        "plan_coding_tool_approval_manifest" => {
            let request: CodingToolApprovalBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_coding_tool_approval_manifest(request)
        }
        "plan_approval_request_state_update" => {
            let request: ApprovalRequestStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_approval_request_state_update(request)
        }
        "plan_approval_decision_state_update" => {
            let request: ApprovalDecisionStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_approval_decision_state_update(request)
        }
        "plan_approval_revoke_state_update" => {
            let request: ApprovalRevokeStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_approval_revoke_state_update(request)
        }
        "authorize_external_capability_exit" => {
            let request: ExternalCapabilityExitAuthorityBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            authorize_external_capability_exit(request)
        }
        "evaluate_context_budget_policy" => {
            let request: ContextBudgetPolicyBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            evaluate_context_budget_policy(request)
        }
        "evaluate_coding_tool_budget_policy" => {
            let request: ContextBudgetPolicyBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            evaluate_coding_tool_budget_policy(request)
        }
        "evaluate_compaction_policy" => {
            let request: CompactionPolicyBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            evaluate_compaction_policy(request)
        }
        "plan_context_compaction" => {
            let request: ContextCompactionPlanBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_context_compaction(request)
        }
        "plan_context_compaction_state_update" => {
            let request: ContextCompactionStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_context_compaction_state_update(request)
        }
        "plan_coding_tool_budget_recovery_state_update" => {
            let request: CodingToolBudgetRecoveryStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_coding_tool_budget_recovery_state_update(request)
        }
        "plan_diagnostics_operator_override_state_update" => {
            let request: DiagnosticsOperatorOverrideStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_diagnostics_operator_override_state_update(request)
        }
        "plan_operator_interrupt_state_update" => {
            let request: OperatorInterruptStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_operator_interrupt_state_update(request)
        }
        "plan_operator_steer_state_update" => {
            let request: OperatorSteerStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_operator_steer_state_update(request)
        }
        "plan_run_cancel_state_update" => {
            let request: RunCancelStateUpdateBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_run_cancel_state_update(request)
        }
        "plan_thread_control_agent_state_update" => {
            let request: ThreadControlAgentStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_thread_control_agent_state_update(request)
        }
        "plan_mcp_control_agent_state_update" => {
            let request: McpControlAgentStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_mcp_control_agent_state_update(request)
        }
        "validate_mcp_servers" => {
            let request: McpServerValidationBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            validate_mcp_servers(request)
        }
        "project_mcp_server_validation_input" => {
            let request: McpServerValidationInputBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            project_mcp_server_validation_input(request)
        }
        "plan_mcp_manager_status_projection" => {
            let request: McpManagerStatusProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_mcp_manager_status_projection(request)
        }
        "plan_mcp_manager_validation_projection" => {
            let request: McpManagerValidationProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_mcp_manager_validation_projection(request)
        }
        "plan_memory_manager_status_projection" => {
            let request: MemoryManagerStatusProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_memory_manager_status_projection(request)
        }
        "plan_memory_manager_validation_projection" => {
            let request: MemoryManagerValidationProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_memory_manager_validation_projection(request)
        }
        "plan_mcp_manager_catalog_projection" => {
            let request: McpManagerCatalogProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_mcp_manager_catalog_projection(request)
        }
        "plan_mcp_manager_catalog_summary_projection" => {
            let request: McpManagerCatalogSummaryProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_mcp_manager_catalog_summary_projection(request)
        }
        "plan_thread_memory_agent_state_update" => {
            let request: ThreadMemoryAgentStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_thread_memory_agent_state_update(request)
        }
        "plan_runtime_bridge_thread_start_agent_state_update" => {
            let request: RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_runtime_bridge_thread_start_agent_state_update(request)
        }
        "plan_runtime_bridge_turn_run_state_update" => {
            let request: RuntimeBridgeTurnRunStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_runtime_bridge_turn_run_state_update(request)
        }
        "plan_subagent_record_state_update" => {
            let request: SubagentRecordStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_subagent_record_state_update(request)
        }
        "plan_agent_create_state_update" => {
            let request: AgentCreateStateUpdateBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_agent_create_state_update(request)
        }
        "plan_agent_status_state_update" => {
            let request: AgentStatusStateUpdateBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_agent_status_state_update(request)
        }
        "plan_run_create_state_update" => {
            let request: RunCreateStateUpdateBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_run_create_state_update(request)
        }
        "admit_storage_backend_write" => {
            let request: StorageBackendWriteBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_storage_backend_write(request)
        }
        "commit_runtime_run_state" => {
            let request: RuntimeRunStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_run_state(request)
        }
        "commit_runtime_agent_state" => {
            let request: RuntimeAgentStateCommitBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_agent_state(request)
        }
        "commit_runtime_memory_state" => {
            let request: RuntimeMemoryStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_memory_state(request)
        }
        "commit_runtime_subagent_state" => {
            let request: RuntimeSubagentStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_subagent_state(request)
        }
        "commit_runtime_artifact_state" => {
            let request: RuntimeArtifactStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_artifact_state(request)
        }
        "commit_runtime_model_mount_record_state" => {
            let request: RuntimeModelMountRecordStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_model_mount_record_state(request)
        }
        "commit_runtime_model_mount_receipt_state" => {
            let request: RuntimeModelMountReceiptStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_model_mount_receipt_state(request)
        }
        other => Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {other}"),
        )),
    }
}

fn expected_command_schema_version(operation: &str) -> &'static str {
    if is_daemon_core_operation(operation) {
        DAEMON_CORE_COMMAND_SCHEMA_VERSION
    } else {
        STEP_MODULE_COMMAND_SCHEMA_VERSION
    }
}

fn is_daemon_core_operation(operation: &str) -> bool {
    matches!(
        operation,
        "admit_storage_backend_write"
            | "admit_model_mount_route_decision"
            | "admit_model_mount_invocation"
            | "admit_model_mount_provider_execution"
            | "execute_model_mount_provider_invocation"
            | "execute_model_mount_provider_stream_invocation"
            | "plan_model_mount_provider_lifecycle"
            | "plan_model_mount_provider_inventory"
            | "plan_model_mount_instance_lifecycle"
            | "admit_model_mount_provider_result"
            | "plan_model_mount_backend_process"
            | "plan_model_mount_accepted_receipt_head"
            | "plan_model_mount_accepted_receipt_transition"
            | "bind_model_mount_invocation_receipt"
            | "plan_model_mount_read_projection"
            | "admit_worker_service_package_invocation"
            | "commit_runtime_run_state"
            | "commit_runtime_agent_state"
            | "commit_runtime_memory_state"
            | "commit_runtime_subagent_state"
            | "commit_runtime_artifact_state"
            | "commit_runtime_model_mount_record_state"
            | "commit_runtime_model_mount_receipt_state"
            | "authorize_external_capability_exit"
            | "execute_private_workspace_ctee_action"
            | "admit_l1_settlement_attempt"
            | "admit_governed_runtime_improvement_proposal"
            | "plan_workspace_restore_apply_policy"
            | "preview_workspace_restore_operations"
            | "apply_workspace_restore_operations"
            | "capture_workspace_snapshot_files"
            | "plan_coding_tool_approval_manifest"
            | "plan_approval_request_state_update"
            | "plan_approval_decision_state_update"
            | "plan_approval_revoke_state_update"
            | "evaluate_context_budget_policy"
            | "evaluate_coding_tool_budget_policy"
            | "evaluate_compaction_policy"
            | "plan_context_compaction"
            | "plan_context_compaction_state_update"
            | "plan_coding_tool_budget_recovery_state_update"
            | "plan_diagnostics_operator_override_state_update"
            | "plan_operator_interrupt_state_update"
            | "plan_operator_steer_state_update"
            | "plan_run_cancel_state_update"
            | "plan_thread_control_agent_state_update"
            | "plan_mcp_control_agent_state_update"
            | "plan_thread_memory_agent_state_update"
            | "plan_runtime_bridge_thread_start_agent_state_update"
            | "plan_runtime_bridge_turn_run_state_update"
            | "plan_subagent_record_state_update"
            | "plan_agent_create_state_update"
            | "plan_run_create_state_update"
            | "plan_agent_status_state_update"
    )
}

fn run_coding_tool_step_module(request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
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

fn admit_model_mount_route_decision(
    request: ModelMountRouteDecisionBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "admit_model_mount_route_decision" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = ModelMountCore
        .admit_route_decision(&request.request)
        .map_err(|error| {
            BridgeError::new("model_mount_route_decision_rejected", format!("{error:?}"))
        })?;
    let accepted_receipt_record = rust_authored_route_selection_receipt(&record)?;
    Ok(json!({
        "source": "rust_model_mount_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_live".to_string()),
        "record": record,
        "route_decision_ref": record.route_decision_ref,
        "route_decision_hash": record.route_decision_hash,
        "receipt_refs": record.receipt_refs,
        "accepted_receipt_record": accepted_receipt_record,
        "evidence_refs": [
            "rust_model_mount_core",
            record.route_decision_ref,
        ],
    }))
}

fn rust_authored_route_selection_receipt(
    record: &ioi_services::agentic::runtime::kernel::model_mount::ModelMountRouteDecisionRecord,
) -> Result<Value, BridgeError> {
    let receipt_ref = record.receipt_refs.first().ok_or_else(|| {
        BridgeError::new(
            "model_mount_route_receipt_missing",
            "route decision missing receipt ref".to_string(),
        )
    })?;
    let receipt_id = receipt_ref
        .strip_prefix("receipt://")
        .unwrap_or(receipt_ref.as_str())
        .to_string();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| {
            BridgeError::new("model_mount_route_receipt_time_failed", error.to_string())
        })?
        .as_secs();
    Ok(json!({
        "id": receipt_id,
        "runId": null,
        "kind": "model_route_selection",
        "summary": format!("Route {} selected {}.", record.route_ref, record.model_ref),
        "redaction": "none",
        "evidenceRefs": [
            "model_router",
            "rust_model_mount_core",
            "rust_daemon_core_model_route_selection_receipt",
            record.route_ref,
            record.endpoint_ref,
            record.route_decision_ref,
        ],
        "createdAt": format!("unix:{created_at}"),
        "details": {
            "rust_daemon_core_receipt_author": "ModelMountCore.admit_route_decision",
            "route_id": record.route_ref,
            "selected_model": record.model_ref,
            "endpoint_id": record.endpoint_ref,
            "provider_id": record.provider_ref,
            "capability": record.capability,
            "policy_hash": record.policy_hash,
            "response_id": null,
            "previous_response_id": null,
            "model_route_decision_schema_version": record.schema_version,
            "model_route_decision_event_kind": "model_route_decision",
            "model_route_decision_id": record.idempotency_key,
            "model_route_decision": {
                "decision_id": record.idempotency_key,
                "route_id": record.route_ref,
                "selected_model": record.model_ref,
                "selected_endpoint_id": record.endpoint_ref,
                "provider_id": record.provider_ref,
                "capability": record.capability,
                "policy_hash": record.policy_hash,
            },
            "model_mount_route_decision_schema_version": record.schema_version,
            "model_mount_route_decision_ref": record.route_decision_ref,
            "model_mount_route_decision_hash": record.route_decision_hash,
            "model_mount_route_decision_source": "rust_model_mount_command",
            "model_mount_route_decision_backend": "rust_model_mount_live",
            "model_mount_route_decision_receipt_refs": record.receipt_refs,
            "model_mount_route_decision": record,
            "workflow_graph_id": record.workflow_graph_ref,
            "workflow_node_id": record.workflow_node_ref,
            "workflow_node_type": null,
        },
        "schemaVersion": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
    }))
}

fn admit_model_mount_invocation(
    request: ModelMountInvocationAdmissionBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "admit_model_mount_invocation" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = ModelMountCore
        .admit_invocation(&request.request)
        .map_err(|error| {
            BridgeError::new("model_mount_invocation_rejected", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_model_mount_invocation_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_live".to_string()),
        "record": record,
        "invocation_admission_ref": record.invocation_admission_ref,
        "invocation_admission_hash": record.invocation_admission_hash,
        "receipt_refs": record.receipt_refs,
        "evidence_refs": [
            "rust_model_mount_core",
            record.invocation_admission_ref,
        ],
    }))
}

fn admit_model_mount_provider_execution(
    request: ModelMountProviderExecutionBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "admit_model_mount_provider_execution" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = ModelMountCore
        .admit_provider_execution(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_provider_execution_rejected",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_model_mount_provider_execution_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_live".to_string()),
        "record": record,
        "provider_execution_ref": record.provider_execution_ref,
        "provider_execution_hash": record.provider_execution_hash,
        "receipt_refs": record.receipt_refs,
        "evidence_refs": [
            "rust_model_mount_core",
            record.provider_execution_ref,
        ],
    }))
}

fn execute_model_mount_provider_invocation(
    request: ModelMountProviderInvocationBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "execute_model_mount_provider_invocation" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let result = ModelMountCore
        .invoke_provider(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_provider_invocation_rejected",
                format!("{error:?}"),
            )
        })?;
    let output_text = result.output_text.clone();
    let token_count = result.token_count.clone();
    let provider_response_kind = result.provider_response_kind.clone();
    let execution_backend = result.execution_backend.clone();
    let backend_id = result.backend_id.clone();
    let provider_execution_ref = result.provider_execution_ref.clone();
    let provider_execution_hash = result.provider_execution_hash.clone();
    let invocation_hash = result.invocation_hash.clone();
    let evidence_refs = result.evidence_refs.clone();
    Ok(json!({
        "source": "rust_model_mount_provider_invocation_command",
        "backend": request.backend.unwrap_or_else(|| execution_backend.clone()),
        "result": result,
        "outputText": output_text.clone(),
        "output_text": output_text,
        "tokenCount": token_count.clone(),
        "token_count": token_count,
        "providerResponse": null,
        "provider_response": null,
        "providerResponseKind": provider_response_kind.clone(),
        "provider_response_kind": provider_response_kind,
        "execution_backend": execution_backend,
        "backendId": backend_id.clone(),
        "backend_id": backend_id,
        "provider_execution_ref": provider_execution_ref,
        "provider_execution_hash": provider_execution_hash,
        "invocation_hash": invocation_hash,
        "evidence_refs": evidence_refs,
    }))
}

fn execute_model_mount_provider_stream_invocation(
    request: ModelMountProviderInvocationBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "execute_model_mount_provider_stream_invocation" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let result = ModelMountCore
        .invoke_provider_stream(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_provider_stream_invocation_rejected",
                format!("{error:?}"),
            )
        })?;
    let output_text = result.output_text.clone();
    let token_count = result.token_count.clone();
    let provider_response_kind = result.provider_response_kind.clone();
    let execution_backend = result.execution_backend.clone();
    let backend_id = result.backend_id.clone();
    let stream_format = result.stream_format.clone();
    let stream_kind = result.stream_kind.clone();
    let stream_chunks = result.stream_chunks.clone();
    let provider_execution_ref = result.provider_execution_ref.clone();
    let provider_execution_hash = result.provider_execution_hash.clone();
    let invocation_hash = result.invocation_hash.clone();
    let evidence_refs = result.evidence_refs.clone();
    Ok(json!({
        "source": "rust_model_mount_provider_stream_invocation_command",
        "backend": request.backend.unwrap_or_else(|| execution_backend.clone()),
        "result": result,
        "outputText": output_text.clone(),
        "output_text": output_text,
        "tokenCount": token_count.clone(),
        "token_count": token_count,
        "providerResponse": null,
        "provider_response": null,
        "providerResponseKind": provider_response_kind.clone(),
        "provider_response_kind": provider_response_kind,
        "execution_backend": execution_backend,
        "backendId": backend_id.clone(),
        "backend_id": backend_id,
        "streamFormat": stream_format.clone(),
        "stream_format": stream_format,
        "streamKind": stream_kind.clone(),
        "stream_kind": stream_kind,
        "streamChunks": stream_chunks.clone(),
        "stream_chunks": stream_chunks,
        "provider_execution_ref": provider_execution_ref,
        "provider_execution_hash": provider_execution_hash,
        "invocation_hash": invocation_hash,
        "evidence_refs": evidence_refs,
    }))
}

fn plan_model_mount_provider_lifecycle(
    request: ModelMountProviderLifecycleBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_model_mount_provider_lifecycle" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let result = ModelMountCore
        .plan_provider_lifecycle(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_provider_lifecycle_rejected",
                format!("{error:?}"),
            )
        })?;
    let status = result.status.clone();
    let backend = result.backend.clone();
    let backend_id = result.backend_id.clone();
    let driver = result.driver.clone();
    let execution_backend = result.execution_backend.clone();
    let lifecycle_hash = result.lifecycle_hash.clone();
    let evidence_refs = result.evidence_refs.clone();
    Ok(json!({
        "source": "rust_model_mount_provider_lifecycle_command",
        "backend": request.backend.unwrap_or_else(|| execution_backend.clone()),
        "result": result,
        "status": status,
        "backend_id": backend_id,
        "provider_backend": backend,
        "driver": driver,
        "execution_backend": execution_backend,
        "lifecycle_hash": lifecycle_hash,
        "evidence_refs": evidence_refs,
    }))
}

fn plan_model_mount_provider_inventory(
    request: ModelMountProviderInventoryBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_model_mount_provider_inventory" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let result = ModelMountCore
        .plan_provider_inventory(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_provider_inventory_rejected",
                format!("{error:?}"),
            )
        })?;
    let status = result.status.clone();
    let backend = result.backend.clone();
    let backend_id = result.backend_id.clone();
    let driver = result.driver.clone();
    let execution_backend = result.execution_backend.clone();
    let item_refs = result.item_refs.clone();
    let item_count = result.item_count;
    let inventory_hash = result.inventory_hash.clone();
    let evidence_refs = result.evidence_refs.clone();
    Ok(json!({
        "source": "rust_model_mount_provider_inventory_command",
        "backend": request.backend.unwrap_or_else(|| execution_backend.clone()),
        "result": result,
        "status": status,
        "backend_id": backend_id,
        "provider_backend": backend,
        "driver": driver,
        "execution_backend": execution_backend,
        "item_refs": item_refs,
        "item_count": item_count,
        "inventory_hash": inventory_hash,
        "evidence_refs": evidence_refs,
    }))
}

fn plan_model_mount_instance_lifecycle(
    request: ModelMountInstanceLifecycleBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_model_mount_instance_lifecycle" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let result = ModelMountCore
        .plan_instance_lifecycle(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_instance_lifecycle_rejected",
                format!("{error:?}"),
            )
        })?;
    let status = result.status.clone();
    let backend_id = result.backend_id.clone();
    let driver = result.driver.clone();
    let execution_backend = result.execution_backend.clone();
    let provider_lifecycle_hash = result.provider_lifecycle_hash.clone();
    let instance_lifecycle_hash = result.instance_lifecycle_hash.clone();
    let evidence_refs = result.evidence_refs.clone();
    Ok(json!({
        "source": "rust_model_mount_instance_lifecycle_command",
        "backend": request.backend.unwrap_or_else(|| execution_backend.clone()),
        "result": result,
        "status": status,
        "backendId": backend_id.clone(),
        "backend_id": backend_id,
        "driver": driver,
        "execution_backend": execution_backend,
        "provider_lifecycle_hash": provider_lifecycle_hash,
        "instance_lifecycle_hash": instance_lifecycle_hash,
        "evidence_refs": evidence_refs,
    }))
}

fn admit_model_mount_provider_result(
    request: ModelMountProviderResultAdmissionBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "admit_model_mount_provider_result" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = ModelMountCore
        .admit_provider_result(&request.request)
        .map_err(|error| {
            BridgeError::new("model_mount_provider_result_rejected", format!("{error:?}"))
        })?;
    let provider_result_ref = record.provider_result_ref.clone();
    let provider_result_hash = record.provider_result_hash.clone();
    let receipt_refs = record.receipt_refs.clone();
    let evidence_refs = record.evidence_refs.clone();
    Ok(json!({
        "source": "rust_model_mount_provider_result_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_live".to_string()),
        "record": record,
        "provider_result_ref": provider_result_ref,
        "provider_result_hash": provider_result_hash,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
    }))
}

fn plan_model_mount_backend_process(
    request: ModelMountBackendProcessPlanBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_model_mount_backend_process" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let plan = ModelMountCore
        .plan_backend_process(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_backend_process_plan_rejected",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_model_mount_backend_process_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_backend_process".to_string()),
        "result": plan.clone(),
        "supports_supervision": plan.supports_supervision,
        "supervisor_kind": plan.supervisor_kind,
        "public_args": plan.public_args,
        "spawn_args": plan.spawn_args,
        "spawn_required": plan.spawn_required,
        "spawn_status": plan.spawn_status,
        "plan_hash": plan.plan_hash,
        "evidence_refs": plan.evidence_refs,
    }))
}

fn plan_model_mount_accepted_receipt_head(
    request: ModelMountAcceptedReceiptHeadBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_model_mount_accepted_receipt_head" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let head = ModelMountCore
        .plan_accepted_receipt_head(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_accepted_receipt_head_rejected",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_model_mount_accepted_receipt_head_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_accepted_receipt_head".to_string()),
        "head": head.clone(),
        "sequence": head.sequence,
        "head_ref": head.head_ref,
        "state_root": head.state_root,
        "projection_watermark": head.projection_watermark,
        "head_hash": head.head_hash,
        "evidence_refs": head.evidence_refs,
    }))
}

fn plan_model_mount_accepted_receipt_transition(
    request: ModelMountAcceptedReceiptTransitionBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_model_mount_accepted_receipt_transition" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let transition = ModelMountCore
        .plan_accepted_receipt_transition(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_accepted_receipt_transition_rejected",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_model_mount_accepted_receipt_transition_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_accepted_receipt_transition".to_string()),
        "transition": transition.clone(),
        "operation_id": transition.operation_id,
        "operation_ref": transition.operation_ref,
        "expected_heads": transition.expected_heads,
        "state_root_before": transition.state_root_before,
        "state_root_after": transition.state_root_after,
        "resulting_head": transition.resulting_head,
        "projection_watermark": transition.projection_watermark,
        "transition_hash": transition.transition_hash,
        "evidence_refs": transition.evidence_refs,
    }))
}

fn bind_model_mount_invocation_receipt(
    request: ModelMountInvocationReceiptBindingBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "bind_model_mount_invocation_receipt" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    if request.invocation.module_ref.kind != StepModuleKind::ModelMount
        || request.invocation.execution.backend != StepModuleBackend::ModelMount
    {
        return Err(BridgeError::new(
            "model_mount_step_module_required",
            "model invocation receipt binding requires a model_mount StepModule invocation"
                .to_string(),
        ));
    }
    if !request.expected_heads.is_empty() {
        return Err(BridgeError::new(
            "model_mount_caller_supplied_expected_heads",
            "model mount invocation expected heads must come from the Rust accepted-receipt transition planner".to_string(),
        ));
    }
    let expected_heads = if request.result.agentgres_operation_refs.is_empty() {
        vec![]
    } else {
        let transition = request.accepted_receipt_transition.as_ref().ok_or_else(|| {
            BridgeError::new(
                "model_mount_accepted_receipt_transition_required",
                "model invocation Agentgres admission requires a Rust-planned accepted receipt transition".to_string(),
            )
        })?;
        ModelMountCore
            .validate_accepted_receipt_transition(transition)
            .map_err(|error| {
                BridgeError::new(
                    "model_mount_accepted_receipt_transition_invalid",
                    format!("{error:?}"),
                )
            })?;
        let operation_ref = request
            .result
            .agentgres_operation_refs
            .first()
            .cloned()
            .unwrap_or_default();
        if operation_ref != transition.operation_ref
            || request.result.state_root_after.as_deref()
                != Some(transition.state_root_after.as_str())
            || request.result.resulting_head.as_deref() != Some(transition.resulting_head.as_str())
            || request.invocation.input.state_root_before.as_deref()
                != Some(transition.state_root_before.as_str())
        {
            return Err(BridgeError::new(
                "model_mount_accepted_receipt_transition_mismatch",
                "model invocation StepModule result must match the Rust-planned accepted receipt transition".to_string(),
            ));
        }
        transition.expected_heads.clone()
    };
    let router_admission = StepModuleRouterCore
        .admit_execution(&request.invocation, &request.result)
        .map_err(|error| BridgeError::new("router_admission_invalid", format!("{error:?}")))?;
    let receipt_binding = ReceiptBinder
        .bind_step_module_result(&request.invocation, &request.result, expected_heads)
        .map_err(|error| BridgeError::new("receipt_binding_invalid", format!("{error:?}")))?;
    let receipt_ref = request
        .receipt_ref
        .clone()
        .or_else(|| request.result.receipt_refs.first().cloned())
        .ok_or_else(|| {
            BridgeError::new(
                "receipt_ref_required",
                "model invocation receipt binding requires a receipt ref".to_string(),
            )
        })?;
    let accepted_receipt_append = ReceiptBinder
        .append_accepted_receipt(
            &AcceptedReceiptAppendRequest {
                schema_version: ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION.to_string(),
                receipt_ref: receipt_ref.clone(),
                invocation_id: request.invocation.invocation_id.clone(),
                receipt_binding_ref: receipt_binding.binding_hash.clone(),
                issuer: AcceptedReceiptAppendIssuer::RustReceiptCore,
                state_root_before: receipt_binding.state_root_before.clone(),
                state_root_after: receipt_binding.state_root_after.clone(),
                resulting_head: receipt_binding.resulting_head.clone(),
            },
            &receipt_binding,
        )
        .map_err(|error| {
            BridgeError::new("accepted_receipt_append_invalid", format!("{error:?}"))
        })?;
    let agentgres_admission = if request.result.agentgres_operation_refs.is_empty() {
        Value::Null
    } else {
        let proposal = AgentgresOperationProposal {
            schema_version: AGENTGRES_ADMISSION_SCHEMA_VERSION.to_string(),
            operation_ref: request
                .result
                .agentgres_operation_refs
                .first()
                .cloned()
                .unwrap_or_default(),
            invocation_id: request.result.invocation_id.clone(),
            receipt_binding_ref: receipt_binding.binding_hash.clone(),
            receipt_refs: request.result.receipt_refs.clone(),
            artifact_refs: request.result.artifact_refs.clone(),
            payload_refs: request.result.payload_refs.clone(),
            expected_heads: receipt_binding.expected_heads.clone(),
            state_root_before: receipt_binding.state_root_before.clone(),
            state_root_after: request.result.state_root_after.clone(),
            resulting_head: request.result.resulting_head.clone(),
        };
        match AgentgresAdmissionCore.admit(&proposal, &receipt_binding) {
            Ok(record) => json!(record),
            Err(error) => {
                return Err(BridgeError::new(
                    "agentgres_admission_invalid",
                    format!("{error:?}"),
                ));
            }
        }
    };
    let projection_record = RustProjectionCore
        .project_step_module_result(&request.invocation, &request.result, &receipt_binding)
        .map_err(|error| BridgeError::new("projection_record_invalid", format!("{error:?}")))?;
    let receipt_refs = request.result.receipt_refs.clone();
    let binding_hash = receipt_binding.binding_hash.clone();
    let append_hash = accepted_receipt_append.append_hash.clone();
    Ok(json!({
        "source": "rust_model_mount_receipt_binding_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_live".to_string()),
        "invocation": request.invocation,
        "result": request.result,
        "router_admission": router_admission,
        "receipt_binding": receipt_binding,
        "accepted_receipt_append": accepted_receipt_append,
        "agentgres_admission": agentgres_admission,
        "projection_record": projection_record,
        "receipt_refs": receipt_refs,
        "evidence_refs": [
            "rust_receipt_binder_core",
            binding_hash,
            append_hash,
        ],
    }))
}

fn plan_model_mount_read_projection(
    request: ModelMountReadProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_model_mount_read_projection" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let projection = model_mount_read_projection(&request.request)?;
    Ok(json!({
        "source": "rust_model_mount_read_projection_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_read_projection".to_string()),
        "projection_kind": request.request.projection_kind,
        "projection": projection,
        "evidence_refs": [
            "rust_daemon_core_model_mount_projection",
            "agentgres_model_mount_read_truth",
            "model_mount_js_read_projection_authoring_retired",
        ],
    }))
}

fn model_mount_read_projection(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, BridgeError> {
    match request.projection_kind.as_str() {
        "snapshot" => Ok(model_mount_snapshot(request)),
        "projection" => Ok(model_mount_projection(request)),
        "projection_summary" => Ok(model_mount_projection_summary(request)),
        "receipt_replay" => model_mount_receipt_replay(request),
        "model_route_decisions" => Ok(model_mount_route_decisions(request)),
        "authority_snapshot" => Ok(model_mount_authority_snapshot(request)),
        "server_status" => Ok(object_or_null(request.state.get("server"))),
        "artifacts" => Ok(Value::Array(array_field(&request.state, "artifacts"))),
        "product_artifacts" => Ok(Value::Array(model_mount_product_artifacts(&request.state))),
        "providers" => Ok(Value::Array(array_field(&request.state, "providers"))),
        "endpoints" => Ok(Value::Array(array_field(&request.state, "endpoints"))),
        "instances" => Ok(Value::Array(array_field(&request.state, "instances"))),
        "routes" => Ok(Value::Array(array_field(&request.state, "routes"))),
        "model_capabilities" => Ok(model_mount_model_capabilities(&request.state)),
        "downloads" => Ok(Value::Array(array_field(&request.state, "downloads"))),
        "oauth_sessions" => Ok(Value::Array(array_field(&request.state, "oauth_sessions"))),
        "oauth_states" => Ok(Value::Array(array_field(&request.state, "oauth_states"))),
        "provider_health" => Ok(Value::Array(array_field(&request.state, "provider_health"))),
        "workflow_bindings" => Ok(model_mount_workflow_bindings()),
        "adapter_boundaries" => Ok(model_mount_adapter_boundaries(&request.state)),
        "runtime_engines" => Ok(Value::Array(array_field(&request.state, "runtime_engines"))),
        "runtime_engine_profiles" => Ok(Value::Array(array_field(
            &request.state,
            "runtime_engine_profiles",
        ))),
        "runtime_preference" => Ok(object_or_null(request.state.get("runtime_preference"))),
        "runtime_preference_for_endpoint" => {
            Ok(object_or_null(request.state.get("runtime_preference")))
        }
        "runtime_default_load_options" => {
            Ok(object_or_null(request.state.get("default_load_options")))
        }
        "runtime_engine_detail" => model_mount_runtime_engine_detail(request),
        "runtime_model_catalog" => Ok(model_mount_runtime_model_catalog(&request.state)),
        "open_ai_model_list" => Ok(model_mount_open_ai_model_list(
            &request.state,
            model_mount_projection_generated_at(request),
        )),
        "latest_provider_health" => model_mount_latest_provider_health(request),
        "latest_vault_health" => model_mount_latest_vault_health(request),
        "latest_runtime_survey" => Ok(model_mount_latest_runtime_survey(request)),
        other => Err(BridgeError::new(
            "model_mount_read_projection_kind_unsupported",
            format!("unsupported model_mount read projection kind {other}"),
        )),
    }
}

fn model_mount_snapshot(request: &ModelMountReadProjectionRequest) -> Value {
    let state = &request.state;
    let receipts = array_field(state, "receipts");
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "server": object_or_null(state.get("server")),
        "catalog": object_or_null(state.get("catalog")),
        "catalogProviderConfigs": array_field(state, "catalog_provider_configs"),
        "oauthSessions": array_field(state, "oauth_sessions"),
        "oauthStates": array_field(state, "oauth_states"),
        "artifacts": array_field(state, "artifacts"),
        "productArtifacts": model_mount_product_artifacts(state),
        "backends": array_field(state, "backends"),
        "backendProcesses": array_field(state, "backend_processes"),
        "endpoints": array_field(state, "endpoints"),
        "instances": array_field(state, "instances"),
        "providers": array_field(state, "providers"),
        "routes": array_field(state, "routes"),
        "modelCapabilities": model_mount_model_capabilities(state),
        "runtimeModelCatalog": model_mount_runtime_model_catalog(state),
        "openAiModelList": model_mount_open_ai_model_list(state, model_mount_projection_generated_at(request)),
        "downloads": array_field(state, "downloads"),
        "providerHealth": array_field(state, "provider_health"),
        "runtimeEngines": array_field(state, "runtime_engines"),
        "runtimeEngineProfiles": array_field(state, "runtime_engine_profiles"),
        "runtimePreference": object_or_null(state.get("runtime_preference")),
        "runtimeSurvey": state.get("runtime_survey").cloned().unwrap_or(Value::Null),
        "tokens": array_field(state, "grants"),
        "vaultRefs": array_field(state, "vault_refs"),
        "mcpServers": array_field(state, "mcp_servers"),
        "conversationStates": array_field(state, "conversation_states"),
        "workflowNodes": model_mount_workflow_bindings(),
        "receipts": receipts.into_iter().rev().take(25).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>(),
        "projection": model_mount_projection_summary(request),
        "adapterBoundaries": model_mount_adapter_boundaries(state),
    })
}

fn model_mount_projection(request: &ModelMountReadProjectionRequest) -> Value {
    let state = &request.state;
    let receipts = array_field(state, "receipts");
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "source": "agentgres_model_mounting_projection",
        "generatedAt": model_mount_projection_generated_at(request),
        "watermark": receipts.len(),
        "artifacts": array_field(state, "artifacts"),
        "productArtifacts": model_mount_product_artifacts(state),
        "endpoints": array_field(state, "endpoints"),
        "instances": array_field(state, "instances"),
        "routes": array_field(state, "routes"),
        "modelCapabilities": model_mount_model_capabilities(state),
        "runtimeModelCatalog": model_mount_runtime_model_catalog(state),
        "openAiModelList": model_mount_open_ai_model_list(state, model_mount_projection_generated_at(request)),
        "backends": array_field(state, "backends"),
        "backendProcesses": array_field(state, "backend_processes"),
        "providers": array_field(state, "providers"),
        "catalog": object_or_null(state.get("catalog")),
        "catalogProviderConfigs": array_field(state, "catalog_provider_configs"),
        "oauthSessions": array_field(state, "oauth_sessions"),
        "oauthStates": array_field(state, "oauth_states"),
        "downloads": array_field(state, "downloads"),
        "providerHealth": array_field(state, "provider_health"),
        "runtimeEngines": array_field(state, "runtime_engines"),
        "runtimeEngineProfiles": array_field(state, "runtime_engine_profiles"),
        "runtimePreference": object_or_null(state.get("runtime_preference")),
        "runtimeSurvey": state.get("runtime_survey").cloned().unwrap_or(Value::Null),
        "grants": array_field(state, "grants"),
        "vaultRefs": array_field(state, "vault_refs"),
        "mcpServers": array_field(state, "mcp_servers"),
        "conversationStates": array_field(state, "conversation_states"),
        "workflowBindings": model_mount_workflow_bindings(),
        "adapterBoundaries": model_mount_adapter_boundaries(state),
        "lifecycleEvents": receipts_by_kind(&receipts, "model_lifecycle"),
        "routeReceipts": receipts_by_kind(&receipts, "model_route_selection"),
        "routeDecisions": route_decisions_from_receipts(&receipts),
        "providerHealthReceipts": receipts_by_kind(&receipts, "provider_health"),
        "runtimeSurveyReceipts": receipts_by_kind(&receipts, "runtime_survey"),
        "invocationReceipts": receipts_by_kind(&receipts, "model_invocation"),
        "toolReceipts": receipts_by_kind(&receipts, "mcp_tool_invocation"),
        "receipts": receipts,
    })
}

fn model_mount_adapter_boundaries(state: &Value) -> Value {
    json!({
        "wallet": object_or_null(state.get("wallet")),
        "vault": object_or_null(state.get("vault")),
        "oauth": {
            "port": "OAuthCredentialProvider",
            "implementation": "agentgres_vault_oauth_session",
            "methods": [
                "startAuthorization",
                "completeAuthorization",
                "exchangeAuthorizationCode",
                "refreshAccessToken",
                "revokeSession",
                "resolveAccessHeader",
            ],
            "plaintextPersistence": false,
            "evidenceRefs": [
                "OAuthCredentialProvider",
                "VaultOAuthAuthorizationState",
                "VaultOAuthSession",
                "oauth_tokens_not_persisted",
            ],
        },
        "agentgres": object_or_null(state.get("agentgres_store")),
    })
}

fn model_mount_workflow_bindings() -> Value {
    Value::Array(
        [
            ("Model Call", "chat"),
            ("Structured Output", "responses"),
            ("Verifier", "chat"),
            ("Planner", "chat"),
            ("Embedding", "embeddings"),
            ("Reranker", "rerank"),
            ("Vision", "vision"),
            ("Local Tool/MCP", "mcp"),
            ("Model Router", "chat"),
            ("Receipt Gate", "receipt_gate"),
        ]
        .into_iter()
        .map(|(node, capability)| {
            json!({
                "node": node,
                "modelId": Value::Null,
                "supportsExplicitModelId": true,
                "supportsModelPolicy": true,
                "capability": capability,
                "receiptRequired": true,
                "routeId": "route.local-first",
                "daemonApi": if node == "Receipt Gate" {
                    "/api/v1/workflows/receipt-gate"
                } else {
                    "/api/v1/workflows/nodes/execute"
                },
            })
        })
        .collect(),
    )
}

fn model_mount_runtime_engine_detail(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, BridgeError> {
    let engine_id = request
        .engine_id
        .as_deref()
        .unwrap_or("unknown_runtime_engine");
    let runtime_engine = object_or_null(request.state.get("runtime_engine"));
    if runtime_engine.is_null() {
        return Err(BridgeError::new(
            "model_mount_runtime_engine_not_found",
            format!("runtime engine not found: {engine_id}"),
        ));
    }
    Ok(runtime_engine)
}

fn model_mount_product_artifacts(state: &Value) -> Vec<Value> {
    let include_internal_fixtures = state
        .get("product_artifact_policy")
        .and_then(|policy| policy.get("include_internal_fixtures"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    array_field(state, "artifacts")
        .into_iter()
        .filter(|artifact| {
            include_internal_fixtures || !model_mount_artifact_is_internal_fixture(artifact)
        })
        .collect()
}

fn model_mount_runtime_model_catalog(state: &Value) -> Value {
    let mut artifacts = model_mount_product_artifacts(state);
    artifacts.sort_by(|left, right| {
        json_string_field(left, "modelId")
            .unwrap_or_default()
            .cmp(&json_string_field(right, "modelId").unwrap_or_default())
    });
    Value::Array(
        artifacts
            .iter()
            .map(|artifact| {
                let provider_id = json_string_field(artifact, "providerId");
                json!({
                    "id": artifact.get("modelId").cloned().unwrap_or(Value::Null),
                    "provider": if matches!(
                        provider_id.as_deref(),
                        Some("provider.local.folder" | "provider.autopilot.local")
                    ) {
                        Value::String("ioi-daemon-local".to_string())
                    } else {
                        artifact.get("providerId").cloned().unwrap_or(Value::Null)
                    },
                    "cost": if json_string_field(artifact, "privacyClass").as_deref() == Some("local_private") {
                        "local"
                    } else {
                        "metered"
                    },
                    "quality": if json_string_field(artifact, "family").as_deref() == Some("fixture") {
                        "adaptive"
                    } else {
                        "provider"
                    },
                    "capabilities": artifact.get("capabilities").cloned().unwrap_or_else(|| Value::Array(vec![])),
                    "privacyClass": artifact.get("privacyClass").cloned().unwrap_or(Value::Null),
                    "route": "route.local-first",
                })
            })
            .collect(),
    )
}

fn model_mount_open_ai_model_list(state: &Value, generated_at: String) -> Value {
    json!({
        "object": "list",
        "data": model_mount_product_artifacts(state)
            .iter()
            .map(|artifact| {
                json!({
                    "id": artifact.get("modelId").cloned().unwrap_or(Value::Null),
                    "object": "model",
                    "created": artifact
                        .get("discoveredAt")
                        .and_then(Value::as_str)
                        .and_then(parse_iso_epoch_seconds)
                        .unwrap_or_else(|| parse_iso_epoch_seconds(&generated_at).unwrap_or(0)),
                    "owned_by": artifact.get("providerId").cloned().unwrap_or(Value::Null),
                    "permission": [],
                    "root": artifact.get("modelId").cloned().unwrap_or(Value::Null),
                    "parent": Value::Null,
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn model_mount_artifact_is_internal_fixture(artifact: &Value) -> bool {
    [
        "id",
        "modelId",
        "model_id",
        "displayName",
        "name",
        "family",
        "quantization",
        "source",
        "driver",
        "providerId",
        "provider_id",
        "artifactPath",
        "artifact_path",
    ]
    .iter()
    .filter_map(|key| artifact.get(*key))
    .filter_map(Value::as_str)
    .map(str::to_lowercase)
    .any(|value| {
        value.contains("fixture")
            || value.contains("local:auto")
            || value.contains("autopilot:native-fixture")
            || value.contains("stories260k")
    })
}

fn parse_iso_epoch_seconds(value: &str) -> Option<i64> {
    let date_time = value.split_once('T')?;
    let mut date = date_time.0.split('-').map(|part| part.parse::<i64>().ok());
    let year = date.next()??;
    let month = date.next()??;
    let day = date.next()??;
    let time_part = date_time
        .1
        .trim_end_matches('Z')
        .split_once('.')
        .map(|(time, _)| time)
        .unwrap_or_else(|| date_time.1.trim_end_matches('Z'));
    let mut time = time_part.split(':').map(|part| part.parse::<i64>().ok());
    let hour = time.next()??;
    let minute = time.next()??;
    let second = time.next()??;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let days_before_year = (1970..year).map(days_in_year).sum::<i64>();
    let days_before_month = (1..month)
        .map(|candidate| days_in_month(year, candidate))
        .sum::<i64>();
    Some(
        (days_before_year + days_before_month + day - 1) * 86_400
            + hour * 3_600
            + minute * 60
            + second,
    )
}

fn days_in_year(year: i64) -> i64 {
    if is_leap_year(year) {
        366
    } else {
        365
    }
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn model_mount_model_capabilities(state: &Value) -> Value {
    let artifacts = array_field(state, "artifacts");
    let endpoints = array_field(state, "endpoints");
    let instances = array_field(state, "instances");
    let providers = array_field(state, "providers");
    let routes = array_field(state, "routes");

    let endpoint_by_id = endpoints
        .iter()
        .filter_map(|endpoint| json_string_field(endpoint, "id").map(|id| (id, endpoint)))
        .collect::<HashMap<_, _>>();
    let provider_by_id = providers
        .iter()
        .filter_map(|provider| json_string_field(provider, "id").map(|id| (id, provider)))
        .collect::<HashMap<_, _>>();
    let artifact_by_model_id = artifacts
        .iter()
        .filter_map(|artifact| json_string_field(artifact, "modelId").map(|id| (id, artifact)))
        .collect::<HashMap<_, _>>();
    let loaded_endpoint_ids = instances
        .iter()
        .filter(|instance| json_string_field(instance, "status").as_deref() == Some("loaded"))
        .filter_map(|instance| json_string_field(instance, "endpointId"))
        .collect::<HashSet<_>>();

    Value::Array(
        routes
            .iter()
            .map(|route| {
                model_mount_model_capability_for_route(
                    route,
                    &artifact_by_model_id,
                    &endpoint_by_id,
                    &loaded_endpoint_ids,
                    &provider_by_id,
                )
            })
            .collect(),
    )
}

fn model_mount_model_capability_for_route(
    route: &Value,
    artifact_by_model_id: &HashMap<String, &Value>,
    endpoint_by_id: &HashMap<String, &Value>,
    loaded_endpoint_ids: &HashSet<String>,
    provider_by_id: &HashMap<String, &Value>,
) -> Value {
    let route_id = json_string_field(route, "id").unwrap_or_default();
    let fallback_endpoint_ids = route
        .get("fallback")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let candidates = fallback_endpoint_ids
        .iter()
        .enumerate()
        .map(|(priority, endpoint_id)| {
            model_mount_candidate_readiness(
                route,
                endpoint_id,
                priority,
                artifact_by_model_id,
                endpoint_by_id,
                loaded_endpoint_ids,
                provider_by_id,
            )
        })
        .collect::<Vec<_>>();
    let ready_candidates = candidates
        .iter()
        .filter(|candidate| {
            candidate
                .get("ready")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    let missing_vault_count = candidates
        .iter()
        .filter(|candidate| {
            candidate
                .get("vault_required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                && !candidate
                    .get("vault_ready")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
        })
        .count();
    let selected_candidate = ready_candidates
        .first()
        .copied()
        .or_else(|| candidates.first());
    let route_active = json_string_field(route, "status").as_deref() == Some("active");
    let available = route_active && !ready_candidates.is_empty();
    let capability = selected_candidate
        .and_then(|candidate| json_string_field(candidate, "capability"))
        .unwrap_or_else(|| "chat".to_string());
    let evidence_refs = compact_evidence(
        candidates
            .iter()
            .flat_map(|candidate| {
                candidate
                    .get("evidence_refs")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
            })
            .collect(),
    );

    json!({
        "schema_version": MODEL_CAPABILITY_SCHEMA_VERSION,
        "object": "ioi.model_capability",
        "id": format!("model-capability:{route_id}"),
        "route_id": route_id,
        "role": route.get("role").cloned().unwrap_or(Value::Null),
        "model_role": route.get("role").cloned().unwrap_or(Value::Null),
        "capability": capability,
        "primitive_capability": format!("prim:model.{capability}"),
        "authority_scope_requirements": [
            format!("route.use:{route_id}"),
            format!("model.{capability}:*"),
        ],
        "policy_target": model_mount_model_policy_target(&route_id),
        "privacy_tier": route.get("privacy").cloned().unwrap_or(Value::Null),
        "provider_priority": route.get("providerEligibility").cloned().unwrap_or(Value::Null),
        "fallback_policy": {
            "allowed": fallback_endpoint_ids.len() > 1,
            "endpoint_ids": fallback_endpoint_ids,
            "denied_providers": route.get("deniedProviders").cloned().unwrap_or(Value::Null),
            "selected_endpoint_id": selected_candidate
                .and_then(|candidate| candidate.get("endpoint_id"))
                .cloned()
                .unwrap_or(Value::Null),
            "deterministic_order": true,
        },
        "fallback_evidence": candidates
            .iter()
            .map(|candidate| candidate.get("evidence").cloned().unwrap_or(Value::Null))
            .collect::<Vec<_>>(),
        "cost_estimate_visibility": {
            "visible": true,
            "max_cost_usd": route.get("maxCostUsd").cloned().unwrap_or(Value::Null),
            "max_latency_ms": route.get("maxLatencyMs").cloned().unwrap_or(Value::Null),
            "source": "model_route_policy",
        },
        "credential_readiness": {
            "status": model_mount_readiness_status(route, &candidates, ready_candidates.len()),
            "reason": model_mount_readiness_reason(route, &candidates, ready_candidates.len()),
            "evidence_refs": evidence_refs,
        },
        "vault_readiness": {
            "status": if missing_vault_count == 0 { "ready" } else { "missing" },
            "required_count": candidates.iter().filter(|candidate| {
                candidate.get("vault_required").and_then(Value::as_bool).unwrap_or(false)
            }).count(),
            "configured_count": candidates.iter().filter(|candidate| {
                candidate.get("vault_required").and_then(Value::as_bool).unwrap_or(false)
                    && candidate.get("vault_ready").and_then(Value::as_bool).unwrap_or(false)
            }).count(),
            "missing_count": missing_vault_count,
        },
        "byok_required": candidates.iter().any(|candidate| {
            candidate.get("vault_required").and_then(Value::as_bool).unwrap_or(false)
        }),
        "receipt_behavior": {
            "receipt_required": true,
            "required_receipt_types": ["model_route_selection", "model_invocation"],
        },
        "workflow_availability": {
            "available": available,
            "reason": if available {
                "At least one route candidate is executable."
            } else {
                "No executable model route candidate is ready."
            },
            "config_fields": ["model_ref", "route_id", "model_binding"],
            "evidence_refs": evidence_refs,
        },
        "agent_availability": {
            "available": available,
            "reason": if available {
                "Agent runtime can request this route capability."
            } else {
                "Agent runtime must resolve model readiness first."
            },
            "evidence_refs": evidence_refs,
        },
        "candidates": candidates,
    })
}

fn model_mount_candidate_readiness(
    route: &Value,
    endpoint_id: &str,
    priority: usize,
    artifact_by_model_id: &HashMap<String, &Value>,
    endpoint_by_id: &HashMap<String, &Value>,
    loaded_endpoint_ids: &HashSet<String>,
    provider_by_id: &HashMap<String, &Value>,
) -> Value {
    let endpoint = endpoint_by_id.get(endpoint_id).copied();
    let provider = endpoint
        .and_then(|endpoint| json_string_field(endpoint, "providerId"))
        .and_then(|provider_id| provider_by_id.get(&provider_id).copied());
    let artifact = endpoint
        .and_then(|endpoint| json_string_field(endpoint, "modelId"))
        .and_then(|model_id| artifact_by_model_id.get(&model_id).copied());
    let vault_required = model_mount_provider_requires_vault(provider);
    let vault_ready = !vault_required
        || provider
            .map(|provider| {
                provider
                    .get("secretConfigured")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    || provider
                        .get("vaultBoundary")
                        .and_then(|boundary| boundary.get("configured"))
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
            })
            .unwrap_or(false);
    let provider_ready = provider
        .and_then(|provider| json_string_field(provider, "status"))
        .map(|status| matches!(status.as_str(), "available" | "configured" | "running"))
        .unwrap_or(false);
    let endpoint_ready = endpoint
        .map(|endpoint| {
            json_string_field(endpoint, "status").as_deref() == Some("mounted")
                || json_string_field(endpoint, "id")
                    .map(|id| loaded_endpoint_ids.contains(&id))
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    let route_active = json_string_field(route, "status").as_deref() == Some("active");
    let ready = route_active && endpoint_ready && provider_ready && vault_ready;
    let reason = model_mount_readiness_candidate_reason(
        endpoint,
        endpoint_ready,
        provider,
        provider_ready,
        vault_required,
        vault_ready,
    );
    let evidence_refs = compact_evidence(
        vec![
            endpoint
                .and_then(|endpoint| endpoint.get("lastReceiptId"))
                .cloned()
                .unwrap_or(Value::Null),
            provider
                .and_then(|provider| provider.get("lastReceiptId"))
                .cloned()
                .unwrap_or(Value::Null),
            artifact
                .and_then(|artifact| artifact.get("lastReceiptId"))
                .cloned()
                .unwrap_or(Value::Null),
        ]
        .into_iter()
        .chain(array_field(
            endpoint.unwrap_or(&Value::Null),
            "evidenceRefs",
        ))
        .chain(array_field(
            provider.unwrap_or(&Value::Null),
            "evidenceRefs",
        ))
        .collect(),
    );
    json!({
        "endpoint_id": endpoint_id,
        "priority": priority,
        "model_id": endpoint
            .and_then(|endpoint| endpoint.get("modelId"))
            .cloned()
            .unwrap_or(Value::Null),
        "provider_id": provider
            .and_then(|provider| provider.get("id"))
            .cloned()
            .unwrap_or(Value::Null),
        "provider_kind": provider
            .and_then(|provider| provider.get("kind"))
            .cloned()
            .unwrap_or(Value::Null),
        "capability": first_model_mount_capability(
            endpoint.and_then(|endpoint| endpoint.get("capabilities"))
                .or_else(|| artifact.and_then(|artifact| artifact.get("capabilities"))),
        ),
        "privacy_tier": endpoint
            .and_then(|endpoint| endpoint.get("privacyClass"))
            .or_else(|| provider.and_then(|provider| provider.get("privacyClass")))
            .or_else(|| route.get("privacy"))
            .cloned()
            .unwrap_or(Value::Null),
        "status": if ready { "ready" } else { "blocked" },
        "ready": ready,
        "vault_required": vault_required,
        "vault_ready": vault_ready,
        "reason": reason,
        "evidence_refs": evidence_refs,
        "evidence": {
            "endpoint_id": endpoint_id,
            "provider_id": provider
                .and_then(|provider| provider.get("id"))
                .cloned()
                .unwrap_or(Value::Null),
            "status": if ready { "ready" } else { "blocked" },
            "reason": reason,
            "vault_required": vault_required,
            "vault_ready": vault_ready,
        },
    })
}

fn model_mount_provider_requires_vault(provider: Option<&Value>) -> bool {
    let Some(provider) = provider else {
        return false;
    };
    provider
        .get("vaultBoundary")
        .and_then(|boundary| boundary.get("required"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || json_string_field(provider, "kind")
            .map(|kind| {
                matches!(
                    kind.as_str(),
                    "openai" | "anthropic" | "gemini" | "custom_http"
                )
            })
            .unwrap_or(false)
}

fn model_mount_model_policy_target(route_id: &str) -> String {
    if route_id.starts_with("route.") {
        format!("model.{route_id}")
    } else {
        format!("model.route.{route_id}")
    }
}

fn model_mount_readiness_status(
    route: &Value,
    candidates: &[Value],
    ready_candidate_count: usize,
) -> &'static str {
    if json_string_field(route, "status").as_deref() != Some("active") {
        return "disabled";
    }
    if ready_candidate_count > 0 {
        return "ready";
    }
    if candidates.iter().any(|candidate| {
        candidate
            .get("vault_required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            && !candidate
                .get("vault_ready")
                .and_then(Value::as_bool)
                .unwrap_or(false)
    }) {
        return "missing";
    }
    "degraded"
}

fn model_mount_readiness_reason(
    route: &Value,
    candidates: &[Value],
    ready_candidate_count: usize,
) -> String {
    if json_string_field(route, "status").as_deref() != Some("active") {
        return "Model route is disabled.".to_string();
    }
    if ready_candidate_count > 0 {
        return "Route has an executable candidate.".to_string();
    }
    candidates
        .first()
        .and_then(|candidate| json_string_field(candidate, "reason"))
        .unwrap_or_else(|| "Route has no configured fallback candidates.".to_string())
}

fn model_mount_readiness_candidate_reason(
    endpoint: Option<&Value>,
    endpoint_ready: bool,
    provider: Option<&Value>,
    provider_ready: bool,
    vault_required: bool,
    vault_ready: bool,
) -> String {
    if endpoint.is_none() {
        return "Route fallback endpoint is not registered.".to_string();
    }
    if provider.is_none() {
        return "Endpoint provider is not registered.".to_string();
    }
    if !provider_ready {
        let status = provider
            .and_then(|provider| json_string_field(provider, "status"))
            .unwrap_or_else(|| "null".to_string());
        return format!("Provider status is {status}.");
    }
    if vault_required && !vault_ready {
        return "Provider requires wallet vault credentials.".to_string();
    }
    if !endpoint_ready {
        let status = endpoint
            .and_then(|endpoint| json_string_field(endpoint, "status"))
            .unwrap_or_else(|| "null".to_string());
        return format!("Endpoint status is {status}.");
    }
    "Endpoint, provider, and credential posture are ready.".to_string()
}

fn first_model_mount_capability(capabilities: Option<&Value>) -> String {
    capabilities
        .and_then(Value::as_array)
        .and_then(|values| values.first())
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| "chat".to_string())
}

fn compact_evidence(values: Vec<Value>) -> Value {
    let mut seen = HashSet::new();
    Value::Array(
        values
            .into_iter()
            .filter_map(|value| value.as_str().map(str::trim).map(str::to_string))
            .filter(|value| !value.is_empty())
            .filter(|value| seen.insert(value.clone()))
            .map(Value::String)
            .collect(),
    )
}

fn model_mount_projection_summary(request: &ModelMountReadProjectionRequest) -> Value {
    let receipts = array_field(&request.state, "receipts");
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "source": "agentgres_model_mounting_projection",
        "watermark": receipts.len(),
        "receiptCount": receipts.len(),
        "generatedAt": model_mount_projection_generated_at(request),
    })
}

fn model_mount_receipt_replay(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, BridgeError> {
    let receipt_id = request.receipt_id.as_deref().ok_or_else(|| {
        BridgeError::new(
            "model_mount_receipt_id_required",
            "model_mount receipt replay projection requires receipt_id".to_string(),
        )
    })?;
    let projection = model_mount_receipt_replay_context(request);
    let receipt = find_receipt(&projection, receipt_id)?;
    Ok(model_mount_receipt_replay_projection(
        request,
        &projection,
        &receipt,
    ))
}

fn model_mount_receipt_replay_context(request: &ModelMountReadProjectionRequest) -> Value {
    let state = &request.state;
    let receipts = array_field(state, "receipts");
    json!({
        "watermark": receipts.len(),
        "receipts": receipts,
        "routes": array_field(state, "routes"),
        "endpoints": array_field(state, "endpoints"),
        "instances": array_field(state, "instances"),
        "providers": array_field(state, "providers"),
    })
}

fn find_receipt(projection: &Value, receipt_id: &str) -> Result<Value, BridgeError> {
    projection
        .get("receipts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .find(|candidate| json_string_field(candidate, "id").as_deref() == Some(receipt_id))
        .ok_or_else(|| {
            BridgeError::new(
                "model_mount_receipt_not_found",
                format!("model_mount receipt not found: {receipt_id}"),
            )
        })
}

fn model_mount_receipt_replay_projection(
    request: &ModelMountReadProjectionRequest,
    projection: &Value,
    receipt: &Value,
) -> Value {
    let receipts = projection
        .get("receipts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let details = receipt.get("details").cloned().unwrap_or(Value::Null);
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "source": "agentgres_model_mounting_projection_replay",
        "receipt": receipt,
        "model_route_decision": details.get("model_route_decision").cloned().unwrap_or(Value::Null),
        "route": projection_lookup(&projection, "routes", details.get("route_id")),
        "endpoint": projection_lookup(&projection, "endpoints", details.get("endpoint_id")),
        "instance": projection_lookup(&projection, "instances", details.get("instance_id")),
        "provider": projection_lookup(&projection, "providers", details.get("provider_id")),
        "toolReceipts": tool_receipts_from_details(&receipts, &details),
        "projectionWatermark": projection.get("watermark").cloned().unwrap_or(Value::Null),
    })
}

fn model_mount_route_decisions(request: &ModelMountReadProjectionRequest) -> Value {
    Value::Array(route_decisions_from_receipts(&array_field(
        &request.state,
        "receipts",
    )))
}

fn model_mount_authority_snapshot(request: &ModelMountReadProjectionRequest) -> Value {
    let state = &request.state;
    let grants = array_field(state, "grants");
    let vault_refs = array_field(state, "vault_refs");
    let authority_receipts = array_field(state, "receipts")
        .into_iter()
        .filter(|receipt| {
            matches!(
                json_string_field(receipt, "kind").as_deref(),
                Some("permission_token")
                    | Some("permission_token_revocation")
                    | Some("vault_ref_binding")
                    | Some("vault_ref_removal")
                    | Some("vault_adapter_health")
            )
        })
        .rev()
        .take(25)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    let wallet = object_or_null(state.get("wallet"));
    let active_grants = grants
        .iter()
        .filter(|grant| grant.get("revokedAt").is_none())
        .count();
    let revoked_grants = grants.len().saturating_sub(active_grants);
    let vault_ref_count = vault_refs.len();
    let authority_receipt_count = authority_receipts.len();
    let remote_wallet_configured = wallet
        .get("remoteAdapter")
        .and_then(|remote| remote.get("configured"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    json!({
        "schemaVersion": "ioi.wallet-core-lite.authority.v1",
        "source": "agentgres_wallet_authority_projection",
        "generatedAt": model_mount_projection_generated_at(request),
        "server": object_or_null(state.get("server")),
        "wallet": wallet,
        "vault": object_or_null(state.get("vault")),
        "grants": grants,
        "vaultRefs": vault_refs,
        "approvals": [],
        "approvalQueue": {
            "status": "not_configured",
            "pendingCount": 0,
            "evidenceRefs": ["wallet.network.approval_queue.pending_runtime_adapter"],
        },
        "receipts": authority_receipts,
        "summary": {
            "activeGrants": active_grants,
            "revokedGrants": revoked_grants,
            "vaultRefs": vault_ref_count,
            "pendingApprovals": 0,
            "receiptCount": authority_receipt_count,
            "remoteWalletConfigured": remote_wallet_configured,
        },
    })
}

fn model_mount_latest_provider_health(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, BridgeError> {
    let provider_id = request.provider_id.as_deref().ok_or_else(|| {
        BridgeError::new(
            "model_mount_provider_id_required",
            "latest provider health projection requires provider_id".to_string(),
        )
    })?;
    let provider_exists = array_field(&request.state, "providers")
        .into_iter()
        .any(|record| json_string_field(&record, "id").as_deref() == Some(provider_id));
    if !provider_exists {
        return Err(BridgeError::new(
            "model_mount_provider_not_found",
            format!("model_mount provider not found: {provider_id}"),
        ));
    }
    let health = array_field(&request.state, "provider_health")
        .into_iter()
        .filter(|record| json_string_field(record, "providerId").as_deref() == Some(provider_id))
        .last()
        .ok_or_else(|| {
            BridgeError::new(
                "model_mount_provider_health_not_found",
                format!("provider health has not been checked: {provider_id}"),
            )
        })?;
    let receipt_id = json_string_field(&health, "receiptId").ok_or_else(|| {
        BridgeError::new(
            "model_mount_provider_health_receipt_missing",
            format!("provider health missing receipt id: {provider_id}"),
        )
    })?;
    let projection = model_mount_projection(request);
    let receipt = find_receipt(&projection, &receipt_id)?;
    Ok(json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "source": "agentgres_provider_health_latest",
        "providerId": provider_id,
        "health": health,
        "receipt": receipt,
        "replay": model_mount_receipt_replay_projection(request, &projection, &receipt),
        "projectionWatermark": projection.get("watermark").cloned().unwrap_or(Value::Null),
    }))
}

fn model_mount_latest_vault_health(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, BridgeError> {
    let projection = model_mount_projection(request);
    let receipt = projection
        .get("receipts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|candidate| {
            json_string_field(candidate, "kind").as_deref() == Some("vault_adapter_health")
        })
        .last()
        .ok_or_else(|| {
            BridgeError::new(
                "model_mount_vault_health_not_found",
                "vault adapter health has not been checked".to_string(),
            )
        })?;
    Ok(json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "source": "agentgres_vault_health_latest",
        "health": receipt.get("details").cloned().unwrap_or(Value::Null),
        "receipt": receipt,
        "replay": model_mount_receipt_replay_projection(request, &projection, &receipt),
        "projectionWatermark": projection.get("watermark").cloned().unwrap_or(Value::Null),
    }))
}

fn model_mount_latest_runtime_survey(request: &ModelMountReadProjectionRequest) -> Value {
    let receipts = array_field(&request.state, "receipts");
    let runtime_survey_default = object_or_null(request.state.get("runtime_survey_default"));
    let Some(receipt) = receipts.iter().rev().find(|candidate| {
        json_string_field(candidate, "kind").as_deref() == Some("runtime_survey")
    }) else {
        return runtime_survey_default;
    };
    let details = receipt.get("details").unwrap_or(&Value::Null);
    json!({
        "status": "checked",
        "receiptId": json_string_field(receipt, "id").unwrap_or_else(|| "none".to_string()),
        "checkedAt": details
            .get("checked_at")
            .cloned()
            .or_else(|| receipt.get("createdAt").cloned())
            .unwrap_or(Value::Null),
        "engineCount": details
            .get("engine_count")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        "selectedEngines": array_field(details, "selected_engines"),
        "runtimePreference": details
            .get("runtime_preference")
            .cloned()
            .unwrap_or_else(|| {
                runtime_survey_default
                    .get("runtimePreference")
                    .cloned()
                    .unwrap_or(Value::Null)
            }),
        "hardware": details.get("hardware").cloned().unwrap_or_else(|| {
            runtime_survey_default
                .get("hardware")
                .cloned()
                .unwrap_or(Value::Null)
        }),
        "lmStudio": details
            .get("lm_studio")
            .cloned()
            .unwrap_or_else(|| json!({"status": "unknown"})),
    })
}

fn model_mount_projection_schema_version(request: &ModelMountReadProjectionRequest) -> String {
    request
        .schema_version
        .clone()
        .unwrap_or_else(|| MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string())
}

fn model_mount_projection_generated_at(request: &ModelMountReadProjectionRequest) -> String {
    request
        .generated_at
        .clone()
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string())
}

fn array_field(value: &Value, key: &str) -> Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn object_or_null(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Object(_)) => value.cloned().unwrap_or(Value::Null),
        Some(Value::Null) | None => Value::Null,
        Some(other) => other.clone(),
    }
}

fn receipts_by_kind(receipts: &[Value], kind: &str) -> Vec<Value> {
    receipts
        .iter()
        .filter(|receipt| json_string_field(receipt, "kind").as_deref() == Some(kind))
        .cloned()
        .collect()
}

fn route_decisions_from_receipts(receipts: &[Value]) -> Vec<Value> {
    receipts
        .iter()
        .filter(|receipt| {
            json_string_field(receipt, "kind").as_deref() == Some("model_route_selection")
        })
        .filter_map(route_decision_from_receipt)
        .collect()
}

fn route_decision_from_receipt(receipt: &Value) -> Option<Value> {
    let mut decision = receipt
        .get("details")
        .and_then(|details| details.get("model_route_decision"))
        .and_then(Value::as_object)
        .cloned()?;
    decision.insert(
        "receipt_id".to_string(),
        receipt.get("id").cloned().unwrap_or(Value::Null),
    );
    decision.insert(
        "receipt_created_at".to_string(),
        receipt.get("createdAt").cloned().unwrap_or(Value::Null),
    );
    decision.insert(
        "receipt_kind".to_string(),
        receipt.get("kind").cloned().unwrap_or(Value::Null),
    );
    Some(Value::Object(decision))
}

fn projection_lookup(projection: &Value, collection_key: &str, id: Option<&Value>) -> Value {
    let Some(id) = id.and_then(Value::as_str) else {
        return Value::Null;
    };
    projection
        .get(collection_key)
        .and_then(Value::as_array)
        .and_then(|records| {
            records
                .iter()
                .find(|record| json_string_field(record, "id").as_deref() == Some(id))
        })
        .cloned()
        .unwrap_or(Value::Null)
}

fn tool_receipts_from_details(receipts: &[Value], details: &Value) -> Vec<Value> {
    let refs = match details.get("tool_receipt_ids") {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>(),
        Some(Value::String(value)) if !value.trim().is_empty() => vec![value.clone()],
        _ => vec![],
    };
    refs.into_iter()
        .filter_map(|receipt_id| {
            receipts
                .iter()
                .find(|receipt| {
                    json_string_field(receipt, "id").as_deref() == Some(receipt_id.as_str())
                })
                .cloned()
        })
        .collect()
}

fn json_string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn execute_private_workspace_ctee_action(
    request: CteePrivateWorkspaceBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "execute_private_workspace_ctee_action" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    if request.invocation.module_ref.kind != StepModuleKind::PrivateWorkspaceCteeAction
        || request.invocation.execution.backend != StepModuleBackend::CteeOperator
    {
        return Err(BridgeError::new(
            "ctee_step_module_required",
            "private workspace cTEE execution requires a ctee_operator StepModule invocation"
                .to_string(),
        ));
    }
    PrivateWorkspaceCteeModule
        .reject_caller_supplied_expected_heads(&request.expected_heads)
        .map_err(|error| BridgeError::new("ctee_execution_invalid", format!("{error:?}")))?;
    let record = PrivateWorkspaceCteeModule
        .execute_and_admit(&request.invocation, &request.node_trust)
        .map_err(|error| BridgeError::new("ctee_execution_invalid", format!("{error:?}")))?;
    let accepted_receipt_append = ReceiptBinder
        .append_accepted_receipt(
            &AcceptedReceiptAppendRequest {
                schema_version: ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION.to_string(),
                receipt_ref: record.receipt.receipt_ref.clone(),
                invocation_id: record.result.invocation_id.clone(),
                receipt_binding_ref: record.receipt_binding.binding_hash.clone(),
                issuer: AcceptedReceiptAppendIssuer::RustReceiptCore,
                state_root_before: record.receipt_binding.state_root_before.clone(),
                state_root_after: record.receipt_binding.state_root_after.clone(),
                resulting_head: record.receipt_binding.resulting_head.clone(),
            },
            &record.receipt_binding,
        )
        .map_err(|error| {
            BridgeError::new("accepted_receipt_append_invalid", format!("{error:?}"))
        })?;
    let receipt_refs = record.result.receipt_refs.clone();
    let evidence_refs = record.projection.evidence_refs.clone();
    Ok(json!({
        "source": "rust_ctee_private_workspace_command",
        "backend": request.backend.unwrap_or_else(|| "ctee_operator".to_string()),
        "record": record.clone(),
        "receipt": record.receipt.clone(),
        "result": record.result.clone(),
        "receipt_binding": record.receipt_binding.clone(),
        "accepted_receipt_append": accepted_receipt_append,
        "agentgres_admission": record.agentgres_admission.clone(),
        "projection_record": record.projection.clone(),
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
    }))
}

fn admit_worker_service_package_invocation(
    request: WorkerServicePackageInvocationBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "admit_worker_service_package_invocation" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = WorkerServicePackageInvocationCore
        .admit_invocation(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "worker_service_package_invocation_invalid",
                format!("{error:?}"),
            )
        })?;
    let receipt_ref = record.receipt_refs.first().cloned().ok_or_else(|| {
        BridgeError::new(
            "receipt_ref_required",
            "worker/service package invocation requires a receipt ref".to_string(),
        )
    })?;
    let accepted_receipt_append = ReceiptBinder
        .append_accepted_receipt(
            &AcceptedReceiptAppendRequest {
                schema_version: ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION.to_string(),
                receipt_ref,
                invocation_id: record.invocation_id.clone(),
                receipt_binding_ref: record.receipt_binding.binding_hash.clone(),
                issuer: AcceptedReceiptAppendIssuer::RustReceiptCore,
                state_root_before: record.receipt_binding.state_root_before.clone(),
                state_root_after: record.receipt_binding.state_root_after.clone(),
                resulting_head: record.receipt_binding.resulting_head.clone(),
            },
            &record.receipt_binding,
        )
        .map_err(|error| {
            BridgeError::new("accepted_receipt_append_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_worker_service_package_invocation_command",
        "backend": request.backend.unwrap_or_else(|| "rust_package_invocation".to_string()),
        "record": record.clone(),
        "router_admission": record.router_admission.clone(),
        "receipt_binding": record.receipt_binding.clone(),
        "accepted_receipt_append": accepted_receipt_append,
        "agentgres_admission": record.agentgres_admission.clone(),
        "projection_record": record.projection.clone(),
        "receipt_refs": record.receipt_refs.clone(),
        "artifact_refs": record.artifact_refs.clone(),
        "payload_refs": record.payload_refs.clone(),
        "authority_grant_refs": record.authority_grant_refs.clone(),
    }))
}

fn admit_l1_settlement_attempt(
    request: L1SettlementAdmissionBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "admit_l1_settlement_attempt" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = L1SettlementTriggerGuard
        .admit(&request.attempt)
        .map_err(|error| {
            BridgeError::new("l1_settlement_admission_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_l1_settlement_guard_command",
        "backend": request.backend.unwrap_or_else(|| "l1_settlement_guard".to_string()),
        "record": record.clone(),
        "settlement_ref": record.settlement_ref,
        "domain_ref": record.domain_ref,
        "state_root_ref": record.state_root_ref,
        "trigger_refs": record.trigger_refs,
        "receipt_refs": record.receipt_refs,
        "admission_hash": record.admission_hash,
    }))
}

fn admit_governed_runtime_improvement_proposal(
    request: GovernedRuntimeImprovementBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "admit_governed_runtime_improvement_proposal" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = GovernedEvolutionCore
        .admit_proposal(&request.proposal)
        .map_err(|error| {
            BridgeError::new("governed_runtime_improvement_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_governed_meta_improvement_command",
        "backend": request.backend.unwrap_or_else(|| "rust_governed_evolution".to_string()),
        "record": record.clone(),
        "proposal_id": record.proposal_id.clone(),
        "target_ref": record.target_ref.clone(),
        "candidate_ref": record.candidate_ref.clone(),
        "admission_hash": record.admission_hash.clone(),
        "agentgres_operation_ref": record.agentgres_operation_ref.clone(),
        "expected_heads": record.expected_heads.clone(),
        "state_root_before": record.state_root_before.clone(),
        "state_root_after": record.state_root_after.clone(),
        "resulting_head": record.resulting_head.clone(),
        "eval_receipt_refs": record.eval_receipt_refs.clone(),
        "verifier_receipt_refs": record.verifier_receipt_refs.clone(),
        "approval_ref": record.approval_ref.clone(),
        "rollback_ref": record.rollback_ref.clone(),
    }))
}

fn plan_workspace_restore_apply_policy(
    request: WorkspaceRestoreApplyPolicyBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_workspace_restore_apply_policy" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let plan = WorkspaceRestoreApplyPolicyCore
        .plan_apply_policy(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "workspace_restore_apply_policy_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_workspace_restore_policy_command",
        "backend": request.backend.unwrap_or_else(|| "rust_workspace_restore".to_string()),
        "plan": plan.clone(),
        "approval": plan.approval.clone(),
        "allow_conflicts": plan.allow_conflicts,
        "conflict_policy": plan.conflict_policy.clone(),
        "hard_blocked": plan.hard_blocked,
        "conflict_blocked": plan.conflict_blocked,
        "policy_status": plan.policy_status.clone(),
        "apply_status": plan.apply_status.clone(),
        "policy_decision_refs": plan.policy_decision_refs.clone(),
        "operation_policies": plan.operation_policies.clone(),
        "summary": plan.summary.clone(),
    }))
}

fn preview_workspace_restore_operations(
    request: WorkspaceRestoreOperationsBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "preview_workspace_restore_operations" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let operations = WorkspaceRestoreOperationsCore
        .preview_operations(&request.request)
        .map_err(|error| {
            BridgeError::new("workspace_restore_operations_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_workspace_restore_operations_command",
        "backend": request.backend.unwrap_or_else(|| "rust_workspace_restore".to_string()),
        "operation": "preview_workspace_restore_operations",
        "operations": operations,
    }))
}

fn apply_workspace_restore_operations(
    request: WorkspaceRestoreOperationsBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "apply_workspace_restore_operations" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let operations = WorkspaceRestoreOperationsCore
        .apply_operations(&request.request)
        .map_err(|error| {
            BridgeError::new("workspace_restore_operations_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_workspace_restore_operations_command",
        "backend": request.backend.unwrap_or_else(|| "rust_workspace_restore".to_string()),
        "operation": "apply_workspace_restore_operations",
        "operations": operations,
    }))
}

fn capture_workspace_snapshot_files(
    request: WorkspaceSnapshotCaptureBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "capture_workspace_snapshot_files" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let capture = WorkspaceSnapshotCaptureCore
        .capture_files(&request.request)
        .map_err(|error| {
            BridgeError::new("workspace_snapshot_capture_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_workspace_snapshot_capture_command",
        "backend": request.backend.unwrap_or_else(|| "rust_workspace_restore".to_string()),
        "capture": capture.clone(),
        "files": capture.files.clone(),
        "content_files": capture.content_files.clone(),
        "captured_file_count": capture.captured_file_count,
        "omitted_file_count": capture.omitted_file_count,
        "content_captured": capture.content_captured,
    }))
}

fn plan_coding_tool_approval_manifest(
    request: CodingToolApprovalBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_coding_tool_approval_manifest" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let plan = CodingToolApprovalCore
        .plan_manifest(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "coding_tool_approval_manifest_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_coding_tool_approval_command",
        "backend": request.backend.unwrap_or_else(|| "rust_authority".to_string()),
        "plan": plan.clone(),
        "approval_required": plan.approval_required,
        "workflow_policy": plan.workflow_policy.clone(),
        "manifest": plan.manifest.clone(),
        "input_hash": plan.input_hash.clone(),
    }))
}

fn plan_approval_request_state_update(
    request: ApprovalRequestStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_approval_request_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = ApprovalRequestStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "approval_request_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_approval_request_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_authority".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "target_kind": record.target_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "run": record.run.clone(),
        "agent": record.agent.clone(),
    }))
}

fn plan_approval_decision_state_update(
    request: ApprovalDecisionStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_approval_decision_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = ApprovalDecisionStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "approval_decision_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_approval_decision_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_authority".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "target_kind": record.target_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "run": record.run.clone(),
        "agent": record.agent.clone(),
    }))
}

fn plan_approval_revoke_state_update(
    request: ApprovalRevokeStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_approval_revoke_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = ApprovalRevokeStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("approval_revoke_state_update_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_approval_revoke_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_authority".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "target_kind": record.target_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "run": record.run.clone(),
        "agent": record.agent.clone(),
    }))
}

fn authorize_external_capability_exit(
    request: ExternalCapabilityExitAuthorityBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "authorize_external_capability_exit" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = WalletAuthorityCore
        .authorize_external_capability_exit(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "external_capability_exit_authority_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_external_capability_exit_authority_command",
        "backend": request.backend.unwrap_or_else(|| "rust_authority".to_string()),
        "authority": record.clone(),
        "wallet_network_grant_refs": record.wallet_network_grant_refs.clone(),
        "authority_receipt_refs": record.authority_receipt_refs.clone(),
        "authority_hash": record.authority_hash.clone(),
    }))
}

fn evaluate_context_budget_policy(
    request: ContextBudgetPolicyBridgeRequest,
) -> Result<Value, BridgeError> {
    evaluate_context_budget_policy_bridge(
        request,
        "evaluate_context_budget_policy",
        "rust_context_budget_policy_command",
        "context_budget_policy_invalid",
    )
}

fn evaluate_coding_tool_budget_policy(
    request: ContextBudgetPolicyBridgeRequest,
) -> Result<Value, BridgeError> {
    evaluate_context_budget_policy_bridge(
        request,
        "evaluate_coding_tool_budget_policy",
        "rust_coding_tool_budget_policy_command",
        "coding_tool_budget_policy_invalid",
    )
}

fn evaluate_context_budget_policy_bridge(
    request: ContextBudgetPolicyBridgeRequest,
    expected_operation: &'static str,
    source: &'static str,
    error_code: &'static str,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != expected_operation {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = ContextBudgetPolicyCore
        .evaluate(&request.request)
        .map_err(|error| BridgeError::new(error_code, format!("{error:?}")))?;
    Ok(json!({
        "source": source,
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "mode": record.mode.clone(),
        "usage_telemetry": record.usage_telemetry.clone(),
        "usage_summary": record.usage_summary.clone(),
        "policy_decision_id": record.policy_decision_id.clone(),
        "policy_decision": record.policy_decision.clone(),
        "receipt_refs": record.receipt_refs.clone(),
        "policy_decision_refs": record.policy_decision_refs.clone(),
        "warnings": record.warnings.clone(),
        "violations": record.violations.clone(),
        "would_block": record.would_block,
        "runtime_event_kind": record.runtime_event_kind.clone(),
        "runtime_event_status": record.runtime_event_status.clone(),
        "runtime_event_item_id": record.runtime_event_item_id.clone(),
        "runtime_event_idempotency_key": record.runtime_event_idempotency_key.clone(),
        "summary": record.summary.clone(),
    }))
}

fn evaluate_compaction_policy(
    request: CompactionPolicyBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "evaluate_compaction_policy" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = CompactionPolicyCore
        .evaluate(&request.request)
        .map_err(|error| BridgeError::new("compaction_policy_invalid", format!("{error:?}")))?;
    Ok(json!({
        "source": "rust_compaction_policy_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "action": record.action.clone(),
        "selected_action": record.selected_action.clone(),
        "budget_status": record.budget_status.clone(),
        "policy_decision_id": record.policy_decision_id.clone(),
        "receipt_refs": record.receipt_refs.clone(),
        "policy_decision_refs": record.policy_decision_refs.clone(),
        "approval_id": record.approval_id.clone(),
        "approval_required": record.approval_required,
        "approval_granted": record.approval_granted,
        "approval_satisfied": record.approval_satisfied,
        "execute_compaction": record.execute_compaction,
        "compaction_requested": record.compaction_requested,
        "compact_reason": record.compact_reason.clone(),
        "compact_scope": record.compact_scope.clone(),
        "runtime_event_kind": record.runtime_event_kind.clone(),
        "runtime_event_status": record.runtime_event_status.clone(),
        "runtime_event_item_id": record.runtime_event_item_id.clone(),
        "runtime_event_idempotency_key": record.runtime_event_idempotency_key.clone(),
        "compact_idempotency_key": record.compact_idempotency_key.clone(),
        "compact_workflow_node_id": record.compact_workflow_node_id.clone(),
        "continuation_allowed": record.continuation_allowed,
        "summary": record.summary.clone(),
    }))
}

fn plan_context_compaction(
    request: ContextCompactionPlanBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_context_compaction" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = ContextCompactionPlanCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("context_compaction_plan_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_context_compaction_plan_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "event_source": record.source.clone(),
        "actor": record.actor.clone(),
        "item_id": record.item_id.clone(),
        "idempotency_key": record.idempotency_key.clone(),
        "compact_hash": record.compact_hash.clone(),
        "source_event_kind": record.source_event_kind.clone(),
        "event_kind": record.event_kind.clone(),
        "component_kind": record.component_kind.clone(),
        "payload_schema_version": record.payload_schema_version.clone(),
        "payload": record.payload.clone(),
        "receipt_refs": record.receipt_refs.clone(),
        "policy_decision_refs": record.policy_decision_refs.clone(),
        "artifact_refs": record.artifact_refs.clone(),
        "rollback_refs": record.rollback_refs.clone(),
        "redaction_profile": record.redaction_profile.clone(),
        "reason": record.reason.clone(),
        "scope": record.scope.clone(),
        "requested_by": record.requested_by.clone(),
        "previous_latest_seq": record.previous_latest_seq,
    }))
}

fn plan_context_compaction_state_update(
    request: ContextCompactionStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_context_compaction_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = ContextCompactionStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "context_compaction_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_context_compaction_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "target_kind": record.target_kind.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "context_compaction": record.context_compaction.clone(),
        "run": record.run.clone(),
        "agent": record.agent.clone(),
    }))
}

fn plan_mcp_control_agent_state_update(
    request: McpControlAgentStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_mcp_control_agent_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = McpControlAgentStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "mcp_control_agent_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_mcp_control_agent_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "control": record.control.clone(),
        "agent": record.agent.clone(),
    }))
}

fn validate_mcp_servers(request: McpServerValidationBridgeRequest) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "validate_mcp_servers" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = McpServerValidationCore
        .validate(&request.request)
        .map_err(|error| BridgeError::new("mcp_server_validation_invalid", format!("{error:?}")))?;
    Ok(json!({
        "source": "rust_mcp_server_validation_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "ok": record.ok,
        "issue_count": record.issue_count,
        "warning_count": record.warning_count,
        "issues": record.issues.clone(),
        "warnings": record.warnings.clone(),
    }))
}

fn project_mcp_server_validation_input(
    request: McpServerValidationInputBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "project_mcp_server_validation_input" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = McpServerValidationInputCore
        .project(&request.request)
        .map_err(|error| {
            BridgeError::new("mcp_server_validation_input_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_mcp_server_validation_input_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "status": record.status.clone(),
        "workspace_root": record.workspace_root.clone(),
        "server_count": record.server_count,
        "servers": record.servers.clone(),
    }))
}

fn plan_mcp_manager_status_projection(
    request: McpManagerStatusProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_mcp_manager_status_projection" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = McpManagerStatusProjectionCore
        .project(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "mcp_manager_status_projection_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_mcp_manager_status_projection_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "status": record.status.clone(),
        "server_count": record.server_count,
        "tool_count": record.tool_count,
        "resource_count": record.resource_count,
        "prompt_count": record.prompt_count,
        "enabled_server_count": record.enabled_server_count,
        "enabled_tool_count": record.enabled_tool_count,
        "servers": record.servers.clone(),
        "tools": record.tools.clone(),
        "resources": record.resources.clone(),
        "prompts": record.prompts.clone(),
        "validation": record.validation.clone(),
        "routes": record.routes.clone(),
    }))
}

fn plan_mcp_manager_validation_projection(
    request: McpManagerValidationProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_mcp_manager_validation_projection" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = McpManagerValidationProjectionCore
        .project(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "mcp_manager_validation_projection_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_mcp_manager_validation_projection_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "ok": record.ok,
        "status": record.status.clone(),
        "server_count": record.server_count,
        "tool_count": record.tool_count,
        "resource_count": record.resource_count,
        "prompt_count": record.prompt_count,
        "issue_count": record.issue_count,
        "warning_count": record.warning_count,
        "issues": record.issues.clone(),
        "warnings": record.warnings.clone(),
        "servers": record.servers.clone(),
        "tools": record.tools.clone(),
        "resources": record.resources.clone(),
        "prompts": record.prompts.clone(),
    }))
}

fn plan_memory_manager_status_projection(
    request: MemoryManagerStatusProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_memory_manager_status_projection" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = MemoryManagerStatusProjectionCore
        .project(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "memory_manager_status_projection_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_memory_manager_status_projection_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "status": record.status.clone(),
        "disabled": record.disabled,
        "injection_enabled": record.injection_enabled,
        "read_only": record.read_only,
        "write_requires_approval": record.write_requires_approval,
        "write_blocked_reason": record.write_blocked_reason.clone(),
        "record_count": record.record_count,
        "scope_count": record.scope_count,
        "memory_key_count": record.memory_key_count,
        "scopes": record.scopes.clone(),
        "memory_keys": record.memory_keys.clone(),
        "policy": record.policy.clone(),
        "paths": record.paths.clone(),
        "filters": record.filters.clone(),
        "records": record.records.clone(),
        "validation": record.validation.clone(),
        "routes": record.routes.clone(),
        "evidence_refs": record.evidence_refs.clone(),
    }))
}

fn plan_memory_manager_validation_projection(
    request: MemoryManagerValidationProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_memory_manager_validation_projection" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = MemoryManagerValidationProjectionCore
        .project(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "memory_manager_validation_projection_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_memory_manager_validation_projection_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "ok": record.ok,
        "status": record.status.clone(),
        "issue_count": record.issue_count,
        "warning_count": record.warning_count,
        "record_count": record.record_count,
        "issues": record.issues.clone(),
        "warnings": record.warnings.clone(),
        "policy": record.policy.clone(),
        "paths": record.paths.clone(),
        "filters": record.filters.clone(),
        "records": record.records.clone(),
    }))
}

fn plan_mcp_manager_catalog_projection(
    request: McpManagerCatalogProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_mcp_manager_catalog_projection" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = McpManagerCatalogProjectionCore
        .project(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "mcp_manager_catalog_projection_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_mcp_manager_catalog_projection_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "status": record.status.clone(),
        "server_count": record.server_count,
        "tool_count": record.tool_count,
        "resource_count": record.resource_count,
        "prompt_count": record.prompt_count,
        "enabled_tool_count": record.enabled_tool_count,
        "servers": record.servers.clone(),
        "tools": record.tools.clone(),
        "resources": record.resources.clone(),
        "prompts": record.prompts.clone(),
        "enabled_tools": record.enabled_tools.clone(),
    }))
}

fn plan_mcp_manager_catalog_summary_projection(
    request: McpManagerCatalogSummaryProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_mcp_manager_catalog_summary_projection" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = McpManagerCatalogSummaryProjectionCore
        .project(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "mcp_manager_catalog_summary_projection_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_mcp_manager_catalog_summary_projection_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "status": record.status.clone(),
        "server_id": record.server_id.clone(),
        "server_label": record.server_label.clone(),
        "transport": record.transport.clone(),
        "execution_mode": record.execution_mode.clone(),
        "catalog_hash": record.catalog_hash.clone(),
        "tool_count": record.tool_count,
        "resource_count": record.resource_count,
        "prompt_count": record.prompt_count,
        "namespace_count": record.namespace_count,
        "namespaces": record.namespaces.clone(),
        "preview_limit": record.preview_limit,
        "preview_tool_names": record.preview_tool_names.clone(),
        "deferred": record.deferred,
        "full_catalog_included": record.full_catalog_included,
        "error_code": record.error_code.clone(),
        "search_route": record.search_route.clone(),
        "fetch_route": record.fetch_route.clone(),
    }))
}

fn plan_thread_memory_agent_state_update(
    request: ThreadMemoryAgentStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_thread_memory_agent_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = ThreadMemoryAgentStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "thread_memory_agent_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_thread_memory_agent_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "control": record.control.clone(),
        "agent": record.agent.clone(),
    }))
}

fn plan_runtime_bridge_thread_start_agent_state_update(
    request: RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_runtime_bridge_thread_start_agent_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = RuntimeBridgeThreadStartAgentStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_bridge_thread_start_agent_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_runtime_bridge_thread_start_agent_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "bridge_start": record.bridge_start.clone(),
        "agent": record.agent.clone(),
    }))
}

fn plan_runtime_bridge_turn_run_state_update(
    request: RuntimeBridgeTurnRunStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_runtime_bridge_turn_run_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = RuntimeBridgeTurnRunStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_bridge_turn_run_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_runtime_bridge_turn_run_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "run": record.run.clone(),
    }))
}

fn plan_subagent_record_state_update(
    request: SubagentRecordStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_subagent_record_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = SubagentRecordStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("subagent_record_state_update_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_subagent_record_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "subagent": record.subagent.clone(),
    }))
}

fn plan_coding_tool_budget_recovery_state_update(
    request: CodingToolBudgetRecoveryStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_coding_tool_budget_recovery_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = CodingToolBudgetRecoveryStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "coding_tool_budget_recovery_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_coding_tool_budget_recovery_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "run": record.run.clone(),
    }))
}

fn plan_diagnostics_operator_override_state_update(
    request: DiagnosticsOperatorOverrideStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_diagnostics_operator_override_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = DiagnosticsOperatorOverrideStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "diagnostics_operator_override_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_diagnostics_operator_override_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "run": record.run.clone(),
    }))
}

fn plan_operator_interrupt_state_update(
    request: OperatorInterruptStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_operator_interrupt_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = OperatorInterruptStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "operator_interrupt_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_operator_interrupt_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "stop_condition": record.stop_condition.clone(),
        "run": record.run.clone(),
    }))
}

fn plan_operator_steer_state_update(
    request: OperatorSteerStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_operator_steer_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = OperatorSteerStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("operator_steer_state_update_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_operator_steer_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "run": record.run.clone(),
    }))
}

fn plan_run_cancel_state_update(
    request: RunCancelStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_run_cancel_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = RunCancelStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("run_cancel_state_update_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_run_cancel_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "stop_condition": record.stop_condition.clone(),
        "runtime_task": record.runtime_task.clone(),
        "runtime_job": record.runtime_job.clone(),
        "runtime_checklist": record.runtime_checklist.clone(),
        "run": record.run.clone(),
    }))
}

fn plan_thread_control_agent_state_update(
    request: ThreadControlAgentStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_thread_control_agent_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = ThreadControlAgentStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "thread_control_agent_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_thread_control_agent_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "control": record.control.clone(),
        "agent": record.agent.clone(),
    }))
}

fn plan_agent_create_state_update(
    request: AgentCreateStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_agent_create_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = AgentCreateStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("agent_create_state_update_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_agent_create_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "created_at": record.created_at.clone(),
        "updated_at": record.updated_at.clone(),
        "agent": record.agent.clone(),
    }))
}

fn plan_agent_status_state_update(
    request: AgentStatusStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_agent_status_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = AgentStatusStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("agent_status_state_update_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_agent_status_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "agent": record.agent.clone(),
    }))
}

fn plan_run_create_state_update(
    request: RunCreateStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_run_create_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = RunCreateStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("run_create_state_update_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_run_create_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "created_at": record.created_at.clone(),
        "updated_at": record.updated_at.clone(),
        "run": record.run.clone(),
    }))
}

fn admit_storage_backend_write(
    request: StorageBackendWriteBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "admit_storage_backend_write" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = AgentgresAdmissionCore
        .admit_storage_backend_write(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "storage_backend_write_admission_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_agentgres_storage_write_admission_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "admission_hash": record.admission_hash.clone(),
        "storage_backend_ref": record.storage_backend_ref.clone(),
        "object_ref": record.object_ref.clone(),
        "content_hash": record.content_hash.clone(),
        "artifact_refs": record.artifact_refs.clone(),
        "payload_refs": record.payload_refs.clone(),
        "receipt_refs": record.receipt_refs.clone(),
        "evidence_refs": [
            "rust_agentgres_storage_write_admission",
            record.admission_hash,
        ],
    }))
}

fn commit_runtime_run_state(
    request: RuntimeRunStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "commit_runtime_run_state" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let state_root = ensure_runtime_state_dir(&request.state_dir)?;
    let mut commit_request = request.request;
    if commit_request.previous_transition.is_none() {
        commit_request.previous_transition =
            read_runtime_state_previous_transition(&state_root, &commit_request.run_id)?;
    }
    if commit_request.projection_watermark.is_none() {
        commit_request.projection_watermark = Some(runtime_state_projection_watermark(
            &state_root,
            &commit_request.run_id,
        )?);
    }
    let record = AgentgresAdmissionCore
        .commit_runtime_run_state(&commit_request)
        .map_err(|error| {
            BridgeError::new("runtime_run_state_commit_invalid", format!("{error:?}"))
        })?;
    let written_records =
        write_runtime_state_persistence_records(&request.state_dir, &record.persistence)?;
    Ok(json!({
        "source": "rust_agentgres_runtime_run_state_commit_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "transition": record.transition.clone(),
        "persistence": record.persistence.clone(),
        "operation_ref": record.transition.operation_ref.clone(),
        "state_root_after": record.transition.state_root_after.clone(),
        "resulting_head": record.transition.resulting_head.clone(),
        "transition_hash": record.transition.transition_hash.clone(),
        "materialization_hash": record.persistence.materialization.materialization_hash.clone(),
        "write_set_hash": record.persistence.storage_write_set.write_set_hash.clone(),
        "persistence_hash": record.persistence.persistence_hash.clone(),
        "commit_hash": record.commit_hash.clone(),
        "records": record.persistence.storage_write_set.records.clone(),
        "written_records": written_records,
        "evidence_refs": [
            "rust_agentgres_runtime_run_state_commit",
            record.commit_hash,
        ],
    }))
}

fn commit_runtime_agent_state(
    request: RuntimeAgentStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "commit_runtime_agent_state" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = AgentgresAdmissionCore
        .commit_runtime_agent_state(&request.request)
        .map_err(|error| {
            BridgeError::new("runtime_agent_state_commit_invalid", format!("{error:?}"))
        })?;
    let written_record = write_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.agent,
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_agent_state_commit_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "storage_record": record.record.clone(),
        "agent_id": record.agent_id.clone(),
        "operation_kind": record.operation_kind.clone(),
        "storage_backend_ref": record.storage_backend_ref.clone(),
        "object_ref": record.record.object_ref.clone(),
        "content_hash": record.record.content_hash.clone(),
        "payload_refs": record.record.payload_refs.clone(),
        "receipt_refs": record.record.receipt_refs.clone(),
        "admission_hash": record.record.admission.admission_hash.clone(),
        "commit_hash": record.commit_hash.clone(),
        "written_record": written_record,
        "evidence_refs": [
            "rust_agentgres_runtime_agent_state_commit",
            record.commit_hash,
        ],
    }))
}

fn commit_runtime_memory_state(
    request: RuntimeMemoryStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "commit_runtime_memory_state" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = AgentgresAdmissionCore
        .commit_runtime_memory_state(&request.request)
        .map_err(|error| {
            BridgeError::new("runtime_memory_state_commit_invalid", format!("{error:?}"))
        })?;
    let written_record = write_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.payload,
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_memory_state_commit_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "storage_record": record.record.clone(),
        "memory_state_kind": record.memory_state_kind.clone(),
        "state_id": record.state_id.clone(),
        "operation_kind": record.operation_kind.clone(),
        "storage_backend_ref": record.storage_backend_ref.clone(),
        "object_ref": record.record.object_ref.clone(),
        "content_hash": record.record.content_hash.clone(),
        "payload_refs": record.record.payload_refs.clone(),
        "receipt_refs": record.record.receipt_refs.clone(),
        "admission_hash": record.record.admission.admission_hash.clone(),
        "commit_hash": record.commit_hash.clone(),
        "written_record": written_record,
        "evidence_refs": [
            "rust_agentgres_runtime_memory_state_commit",
            record.commit_hash,
        ],
    }))
}

fn commit_runtime_subagent_state(
    request: RuntimeSubagentStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "commit_runtime_subagent_state" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = AgentgresAdmissionCore
        .commit_runtime_subagent_state(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_subagent_state_commit_invalid",
                format!("{error:?}"),
            )
        })?;
    let written_record = write_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.subagent,
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_subagent_state_commit_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "storage_record": record.record.clone(),
        "subagent_id": record.subagent_id.clone(),
        "operation_kind": record.operation_kind.clone(),
        "storage_backend_ref": record.storage_backend_ref.clone(),
        "object_ref": record.record.object_ref.clone(),
        "content_hash": record.record.content_hash.clone(),
        "payload_refs": record.record.payload_refs.clone(),
        "receipt_refs": record.record.receipt_refs.clone(),
        "admission_hash": record.record.admission.admission_hash.clone(),
        "commit_hash": record.commit_hash.clone(),
        "written_record": written_record,
        "evidence_refs": [
            "rust_agentgres_runtime_subagent_state_commit",
            record.commit_hash,
        ],
    }))
}

fn commit_runtime_artifact_state(
    request: RuntimeArtifactStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "commit_runtime_artifact_state" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = AgentgresAdmissionCore
        .commit_runtime_artifact_state(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_artifact_state_commit_invalid",
                format!("{error:?}"),
            )
        })?;
    let written_record = write_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.artifact,
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_artifact_state_commit_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "storage_record": record.record.clone(),
        "artifact_id": record.artifact_id.clone(),
        "operation_kind": record.operation_kind.clone(),
        "storage_backend_ref": record.storage_backend_ref.clone(),
        "object_ref": record.record.object_ref.clone(),
        "content_hash": record.record.content_hash.clone(),
        "payload_refs": record.record.payload_refs.clone(),
        "receipt_refs": record.record.receipt_refs.clone(),
        "admission_hash": record.record.admission.admission_hash.clone(),
        "commit_hash": record.commit_hash.clone(),
        "written_record": written_record,
        "evidence_refs": [
            "rust_agentgres_runtime_artifact_state_commit",
            record.commit_hash,
        ],
    }))
}

fn commit_runtime_model_mount_record_state(
    request: RuntimeModelMountRecordStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "commit_runtime_model_mount_record_state" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = AgentgresAdmissionCore
        .commit_runtime_model_mount_record_state(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_model_mount_record_state_commit_invalid",
                format!("{error:?}"),
            )
        })?;
    let written_record = write_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.record,
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_model_mount_record_state_commit_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "storage_record": record.record.clone(),
        "record_dir": record.record_dir.clone(),
        "record_id": record.record_id.clone(),
        "operation_kind": record.operation_kind.clone(),
        "storage_backend_ref": record.storage_backend_ref.clone(),
        "object_ref": record.record.object_ref.clone(),
        "content_hash": record.record.content_hash.clone(),
        "payload_refs": record.record.payload_refs.clone(),
        "receipt_refs": record.record.receipt_refs.clone(),
        "admission_hash": record.record.admission.admission_hash.clone(),
        "commit_hash": record.commit_hash.clone(),
        "written_record": written_record,
        "evidence_refs": [
            "rust_agentgres_runtime_model_mount_record_state_commit",
            record.commit_hash,
        ],
    }))
}

fn commit_runtime_model_mount_receipt_state(
    request: RuntimeModelMountReceiptStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "commit_runtime_model_mount_receipt_state" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = AgentgresAdmissionCore
        .commit_runtime_model_mount_receipt_state(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_model_mount_receipt_state_commit_invalid",
                format!("{error:?}"),
            )
        })?;
    let written_record = write_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.receipt,
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_model_mount_receipt_state_commit_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "storage_record": record.record.clone(),
        "receipt_id": record.receipt_id.clone(),
        "operation_kind": record.operation_kind.clone(),
        "storage_backend_ref": record.storage_backend_ref.clone(),
        "object_ref": record.record.object_ref.clone(),
        "content_hash": record.record.content_hash.clone(),
        "payload_refs": record.record.payload_refs.clone(),
        "receipt_refs": record.record.receipt_refs.clone(),
        "admission_hash": record.record.admission.admission_hash.clone(),
        "commit_hash": record.commit_hash.clone(),
        "written_record": written_record,
        "evidence_refs": [
            "rust_agentgres_runtime_model_mount_receipt_state_commit",
            record.commit_hash,
        ],
    }))
}

fn write_runtime_state_persistence_records(
    state_dir: &str,
    record: &RuntimeStatePersistenceRecord,
) -> Result<Vec<Value>, BridgeError> {
    let state_root = ensure_runtime_state_dir(state_dir)?;
    let mut written_records = Vec::with_capacity(record.materialization.records.len());
    for materialized in &record.materialization.records {
        let planned = record
            .storage_write_set
            .records
            .iter()
            .find(|entry| entry.record_path == materialized.record_path)
            .ok_or_else(|| {
                BridgeError::new(
                    "runtime_state_storage_plan_missing_record",
                    format!(
                        "storage write set is missing record {}",
                        materialized.record_path
                    ),
                )
            })?;
        let target = runtime_state_record_path(&state_root, &materialized.record_path)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                BridgeError::new("runtime_state_record_dir_create_failed", error.to_string())
            })?;
        }
        let payload = serde_json::to_string_pretty(&materialized.payload).map_err(|error| {
            BridgeError::new("runtime_state_record_json_failed", error.to_string())
        })?;
        let file_content = format!("{payload}\n");
        fs::write(&target, file_content.as_bytes()).map_err(|error| {
            BridgeError::new("runtime_state_record_write_failed", error.to_string())
        })?;
        written_records.push(json!({
            "record_path": materialized.record_path,
            "absolute_path": target.to_string_lossy(),
            "object_ref": planned.object_ref,
            "content_hash": planned.content_hash,
            "payload_refs": planned.payload_refs,
            "receipt_refs": planned.receipt_refs,
            "admission_hash": planned.admission.admission_hash,
        }));
    }
    Ok(written_records)
}

fn write_runtime_state_storage_record(
    state_dir: &str,
    record: &RuntimeStateStorageWriteRecord,
    payload: &Value,
) -> Result<Value, BridgeError> {
    let state_root = ensure_runtime_state_dir(state_dir)?;
    let target = runtime_state_record_path(&state_root, &record.record_path)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            BridgeError::new("runtime_state_record_dir_create_failed", error.to_string())
        })?;
    }
    let payload = serde_json::to_string_pretty(payload)
        .map_err(|error| BridgeError::new("runtime_state_record_json_failed", error.to_string()))?;
    let file_content = format!("{payload}\n");
    fs::write(&target, file_content.as_bytes()).map_err(|error| {
        BridgeError::new("runtime_state_record_write_failed", error.to_string())
    })?;
    Ok(json!({
        "record_path": record.record_path,
        "absolute_path": target.to_string_lossy(),
        "object_ref": record.object_ref,
        "content_hash": record.content_hash,
        "payload_refs": record.payload_refs,
        "receipt_refs": record.receipt_refs,
        "admission_hash": record.admission.admission_hash,
    }))
}

fn ensure_runtime_state_dir(state_dir: &str) -> Result<PathBuf, BridgeError> {
    let state_root_input = Path::new(state_dir);
    fs::create_dir_all(state_root_input)
        .map_err(|error| BridgeError::new("runtime_state_dir_create_failed", error.to_string()))?;
    fs::canonicalize(state_root_input)
        .map_err(|error| BridgeError::new("runtime_state_dir_invalid", error.to_string()))
}

fn read_runtime_state_previous_transition(
    state_root: &Path,
    run_id: &str,
) -> Result<Option<Value>, BridgeError> {
    let task_path = runtime_state_record_path(state_root, &format!("tasks/{run_id}.json"))?;
    if !task_path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&task_path).map_err(|error| {
        BridgeError::new(
            "runtime_state_previous_transition_read_failed",
            error.to_string(),
        )
    })?;
    let task_record: Value = serde_json::from_str(&content).map_err(|error| {
        BridgeError::new(
            "runtime_state_previous_transition_json_invalid",
            error.to_string(),
        )
    })?;
    match task_record.get("agentgresTransition") {
        Some(value) if value.is_object() => Ok(Some(value.clone())),
        _ => Ok(None),
    }
}

fn runtime_state_projection_watermark(
    state_root: &Path,
    run_id: &str,
) -> Result<String, BridgeError> {
    let runs_dir = state_root.join("runs");
    let mut run_count = 0usize;
    if runs_dir.exists() {
        for entry in fs::read_dir(&runs_dir).map_err(|error| {
            BridgeError::new("runtime_state_runs_dir_read_failed", error.to_string())
        })? {
            let entry = entry.map_err(|error| {
                BridgeError::new("runtime_state_runs_dir_entry_failed", error.to_string())
            })?;
            if entry
                .file_type()
                .map_err(|error| {
                    BridgeError::new("runtime_state_runs_dir_entry_failed", error.to_string())
                })?
                .is_file()
                && entry.path().extension().and_then(|value| value.to_str()) == Some("json")
            {
                run_count += 1;
            }
        }
    }
    let watermark = run_count.max(if run_id.trim().is_empty() { 0 } else { 1 });
    Ok(format!("runtime-state:{watermark}"))
}

fn runtime_state_record_path(root: &Path, record_path: &str) -> Result<PathBuf, BridgeError> {
    if record_path.trim().is_empty() {
        return Err(BridgeError::new(
            "runtime_state_record_path_invalid",
            "runtime state record path is required".to_string(),
        ));
    }
    let mut target = root.to_path_buf();
    let mut saw_component = false;
    for component in Path::new(record_path).components() {
        match component {
            Component::Normal(segment) => {
                target.push(segment);
                saw_component = true;
            }
            Component::CurDir => {}
            _ => {
                return Err(BridgeError::new(
                    "runtime_state_record_path_invalid",
                    format!("runtime state record path cannot escape state dir: {record_path}"),
                ));
            }
        }
    }
    if !saw_component || !target.starts_with(root) {
        return Err(BridgeError::new(
            "runtime_state_record_path_invalid",
            format!("runtime state record path cannot escape state dir: {record_path}"),
        ));
    }
    Ok(target)
}

fn workspace_status_response(request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
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

fn git_diff_response(request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
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

fn file_inspect_response(request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
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

fn file_apply_patch_response(mut request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
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

fn test_run_response(request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
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

fn lsp_diagnostics_response(request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
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

fn artifact_read_response(request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
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

fn tool_retrieve_result_response(request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
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

fn computer_use_request_lease_response(
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

fn successful_step_module_result(
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

fn step_module_response(
    request: StepModuleBridgeRequest,
    result: StepModuleResult,
    workload_observation: Value,
) -> Value {
    step_module_response_with_expected_heads(request, result, workload_observation, vec![])
}

fn step_module_response_with_expected_heads(
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

fn workload_step_module_dispatch_request(
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

fn normalize_prefetched_artifact_result(
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

fn inspect_test_run(workspace_root: &str, input: &Value) -> Result<Value, BridgeError> {
    let root = fs::canonicalize(workspace_root)
        .map_err(|error| BridgeError::new("workspace_root_invalid", error.to_string()))?;
    let command_id = input
        .get("commandId")
        .or_else(|| input.get("command_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("node.test");
    if !TEST_COMMAND_IDS.contains(&command_id) {
        return Err(BridgeError::new(
            "test_run_command_not_allowed",
            format!("test.run commandId is not allowlisted: {command_id}"),
        ));
    }
    let cwd = input
        .get("cwd")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(".");
    let run_cwd = workspace_directory(&root, cwd, "test_run_cwd_missing")?;
    let paths = workspace_tool_paths(&root, input)?;
    let timeout_ms = bounded_u64(
        input
            .get("timeoutMs")
            .or_else(|| input.get("timeout_ms"))
            .and_then(Value::as_u64),
        TEST_DEFAULT_TIMEOUT_MS,
        1,
        TEST_MAX_TIMEOUT_MS,
    );
    let max_output_bytes = bounded_u64(
        input
            .get("maxOutputBytes")
            .or_else(|| input.get("max_output_bytes"))
            .and_then(Value::as_u64),
        TEST_DEFAULT_OUTPUT_BYTES,
        1,
        TEST_MAX_OUTPUT_BYTES,
    ) as usize;
    let command = test_command_for_input(command_id, &run_cwd.absolute_path, &paths);
    let mut args = command.args;
    args.extend(sanitize_string_array(input.get("args")));
    let env_overrides = sanitize_test_env(input.get("env"));
    let started = Instant::now();
    let run = run_command_with_timeout(
        command.executable,
        &args,
        &run_cwd.absolute_path,
        timeout_ms,
        &env_overrides,
    )?;
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let (stdout, stdout_truncated) = utf8_preview(&run.stdout, max_output_bytes);
    let (stderr, stderr_truncated) = utf8_preview(&run.stderr, max_output_bytes);
    let output_text = format!("{}\n{}", run.stdout, run.stderr);
    let output_hash = ioi_crypto::algorithms::hash::sha256(output_text.as_bytes())
        .map(|hash| hex::encode(hash))
        .map_err(|error| BridgeError::new("test_run_hash_failed", error.to_string()))?;
    let truncated = stdout_truncated || stderr_truncated;
    let test_status = if run.timed_out {
        "timed_out"
    } else if run.exit_code == 0 {
        "passed"
    } else {
        "failed"
    };
    Ok(json!({
        "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
        "workspaceRoot": workspace_root,
        "commandId": command_id,
        "command": command.display_command,
        "executable": command.executable,
        "args": args,
        "cwd": run_cwd.relative_path,
        "exitCode": run.exit_code,
        "signal": null,
        "testStatus": test_status,
        "timedOut": run.timed_out,
        "durationMs": duration_ms,
        "timeoutMs": timeout_ms,
        "stdout": stdout,
        "stderr": stderr,
        "stdoutBytes": run.stdout.len(),
        "stderrBytes": run.stderr.len(),
        "outputBytes": run.stdout.len() + run.stderr.len(),
        "outputHash": output_hash,
        "truncated": truncated,
        "spilloverRecommended": truncated,
        "artifactDrafts": [],
        "allowedCommandIds": TEST_COMMAND_IDS,
        "shellFallbackUsed": false,
    }))
}

fn inspect_lsp_diagnostics(workspace_root: &str, input: &Value) -> Result<Value, BridgeError> {
    let root = fs::canonicalize(workspace_root)
        .map_err(|error| BridgeError::new("workspace_root_invalid", error.to_string()))?;
    let command_id = input
        .get("commandId")
        .or_else(|| input.get("command_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("auto");
    if !DIAGNOSTIC_COMMAND_IDS.contains(&command_id) {
        return Err(BridgeError::new(
            "lsp_diagnostics_command_not_allowed",
            format!("lsp.diagnostics commandId is not allowlisted: {command_id}"),
        ));
    }
    let cwd = input
        .get("cwd")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(".");
    let run_cwd = workspace_directory(&root, cwd, "lsp_diagnostics_cwd_missing")?;
    let paths = workspace_tool_paths(&root, input)?;
    if paths.is_empty() {
        return Err(BridgeError::new(
            "lsp_diagnostics_path_required",
            "lsp.diagnostics requires path or paths".to_string(),
        ));
    }
    let timeout_ms = bounded_u64(
        input
            .get("timeoutMs")
            .or_else(|| input.get("timeout_ms"))
            .and_then(Value::as_u64),
        DIAGNOSTIC_DEFAULT_TIMEOUT_MS,
        1,
        DIAGNOSTIC_MAX_TIMEOUT_MS,
    );
    let max_output_bytes = bounded_u64(
        input
            .get("maxOutputBytes")
            .or_else(|| input.get("max_output_bytes"))
            .and_then(Value::as_u64),
        DIAGNOSTIC_DEFAULT_OUTPUT_BYTES,
        1,
        DIAGNOSTIC_MAX_OUTPUT_BYTES,
    ) as usize;
    let project_context = diagnostics_project_context(&root, &run_cwd.absolute_path, &paths);
    let has_typescript_path = paths
        .iter()
        .any(|path| typescript_path_supported(&path.relative_path));
    let run_typescript =
        command_id == "typescript.check" || (command_id == "auto" && has_typescript_path);
    let started = Instant::now();
    let run = if run_typescript {
        run_typescript_check(
            &root,
            &run_cwd.absolute_path,
            &paths,
            timeout_ms,
            input,
            project_context,
        )?
    } else {
        run_node_check(&run_cwd.absolute_path, &paths, timeout_ms, project_context)?
    };
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let (stdout, stdout_truncated) = utf8_preview(&run.stdout, max_output_bytes);
    let (stderr, stderr_truncated) = utf8_preview(&run.stderr, max_output_bytes);
    let output_text = format!("{}\n{}", run.stdout, run.stderr);
    let output_hash = ioi_crypto::algorithms::hash::sha256(output_text.as_bytes())
        .map(|hash| hex::encode(hash))
        .map_err(|error| BridgeError::new("lsp_diagnostics_hash_failed", error.to_string()))?;
    let truncated = stdout_truncated || stderr_truncated;
    let diagnostics = run.diagnostics;
    let diagnostic_count = diagnostics.len();
    let path_refs = paths
        .iter()
        .map(|path| path.relative_path.clone())
        .collect::<Vec<_>>();
    Ok(json!({
        "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
        "workspaceRoot": workspace_root,
        "commandId": command_id,
        "requestedCommandId": command_id,
        "resolvedCommandId": run.resolved_command_id,
        "command": run.display_command,
        "cwd": run_cwd.relative_path.clone(),
        "backend": run.backend,
        "backendStatus": run.backend_status,
        "backendReason": run.backend_reason,
        "fallbackUsed": run.fallback_used,
        "fallbackFrom": run.fallback_from,
        "projectContext": run.project_context,
        "diagnosticStatus": run.diagnostic_status,
        "diagnostics": diagnostics,
        "diagnosticCount": diagnostic_count,
        "paths": path_refs,
        "exitCode": run.exit_code,
        "timedOut": run.timed_out,
        "durationMs": duration_ms,
        "timeoutMs": timeout_ms,
        "stdout": stdout,
        "stderr": stderr,
        "outputBytes": run.stdout.len() + run.stderr.len(),
        "outputHash": output_hash,
        "truncated": truncated,
        "spilloverRecommended": truncated,
        "artifactDrafts": [],
        "allowedCommandIds": DIAGNOSTIC_COMMAND_IDS,
        "shellFallbackUsed": false,
    }))
}

fn inspect_workspace_status(workspace_root: &str, input: &Value) -> Result<Value, BridgeError> {
    let root = fs::canonicalize(workspace_root)
        .map_err(|error| BridgeError::new("workspace_root_invalid", error.to_string()))?;
    let include_ignored = input
        .get("includeIgnored")
        .or_else(|| input.get("include_ignored"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut args = vec![
        "status".to_string(),
        "--short".to_string(),
        "--branch".to_string(),
        "--untracked-files=all".to_string(),
    ];
    if include_ignored {
        args.push("--ignored".to_string());
    }
    let status = run_git_read_only(&root, &args)?;
    if !status.ok {
        return Ok(json!({
            "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
            "workspaceRoot": workspace_root,
            "git": {
                "available": false,
                "status": "not_git_repository",
                "error": nonempty_command_error(&status, "git status failed"),
            },
            "changedFiles": [],
            "counts": {
                "changed": 0,
                "untracked": 0,
                "ignored": 0,
            },
            "shellFallbackUsed": false,
        }));
    }

    let lines = status
        .stdout
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let branch = lines
        .iter()
        .find_map(|line| line.strip_prefix("##").map(str::trim))
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned);
    let mut changed_files = Vec::new();
    let mut changed = 0u64;
    let mut untracked = 0u64;
    let mut ignored = 0u64;
    for line in lines.iter().filter(|line| !line.starts_with("##")) {
        let path = line.get(3..).unwrap_or("").trim();
        if path.is_empty() {
            continue;
        }
        let status_code = line.get(0..2).unwrap_or("").trim();
        let status_code = if status_code.is_empty() {
            "modified"
        } else {
            status_code
        };
        changed += 1;
        if status_code.contains('?') {
            untracked += 1;
        }
        if status_code.contains('!') {
            ignored += 1;
        }
        changed_files.push(json!({
            "status": status_code,
            "path": path,
        }));
    }
    let porcelain_hash = ioi_crypto::algorithms::hash::sha256(status.stdout.as_bytes())
        .map(|hash| hex::encode(hash))
        .map_err(|error| BridgeError::new("workspace_status_hash_failed", error.to_string()))?;
    Ok(json!({
        "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
        "workspaceRoot": workspace_root,
        "git": {
            "available": true,
            "branch": branch,
            "porcelainHash": porcelain_hash,
        },
        "changedFiles": changed_files,
        "counts": {
            "changed": changed,
            "untracked": untracked,
            "ignored": ignored,
        },
        "shellFallbackUsed": false,
    }))
}

fn inspect_git_diff(workspace_root: &str, input: &Value) -> Result<Value, BridgeError> {
    let root = fs::canonicalize(workspace_root)
        .map_err(|error| BridgeError::new("workspace_root_invalid", error.to_string()))?;
    let paths = workspace_diff_paths(&root, input)?;
    let max_bytes = bounded_u64(
        input
            .get("maxBytes")
            .or_else(|| input.get("max_bytes"))
            .and_then(Value::as_u64),
        MAX_DIFF_BYTES,
        1,
        MAX_DIFF_BYTES,
    ) as usize;
    let mut diff_args = vec!["diff".to_string(), "--".to_string()];
    diff_args.extend(paths.iter().cloned());
    let diff_output = run_git_read_only(&root, &diff_args)?;
    if !diff_output.ok {
        return Err(BridgeError::new(
            "git_diff_failed",
            nonempty_command_error(&diff_output, "git diff failed"),
        ));
    }
    let mut stat_args = vec!["diff".to_string(), "--stat".to_string(), "--".to_string()];
    stat_args.extend(paths.iter().cloned());
    let stat_output = run_git_read_only(&root, &stat_args)?;
    let (diff_preview, truncated) = utf8_preview(&diff_output.stdout, max_bytes);
    let diff_hash = ioi_crypto::algorithms::hash::sha256(diff_output.stdout.as_bytes())
        .map(|hash| hex::encode(hash))
        .map_err(|error| BridgeError::new("git_diff_hash_failed", error.to_string()))?;
    Ok(json!({
        "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
        "workspaceRoot": workspace_root,
        "paths": paths,
        "git": { "available": true },
        "diff": diff_preview,
        "diffBytes": diff_output.stdout.len(),
        "diffHash": diff_hash,
        "truncated": truncated,
        "stat": if stat_output.ok { stat_output.stdout } else { String::new() },
        "shellFallbackUsed": false,
    }))
}

fn inspect_workspace_path(
    workspace_root: &str,
    selected_path: &str,
    input: &Value,
) -> Result<Value, BridgeError> {
    let root = fs::canonicalize(workspace_root)
        .map_err(|error| BridgeError::new("workspace_root_invalid", error.to_string()))?;
    let target = workspace_target(&root, selected_path)?;
    let metadata =
        fs::metadata(&target).map_err(|error| BridgeError::new("not_found", error.to_string()))?;
    let relative_path = target
        .strip_prefix(&root)
        .unwrap_or(target.as_path())
        .to_string_lossy()
        .replace('\\', "/");
    if metadata.is_dir() {
        let mut entries = fs::read_dir(&target)
            .map_err(|error| BridgeError::new("file_inspect_read_dir_failed", error.to_string()))?
            .take(100)
            .map(|entry| {
                entry
                    .map_err(|error| BridgeError::new("file_inspect_read_dir_failed", error.to_string()))
                    .and_then(|entry| {
                        let kind = entry
                            .file_type()
                            .map_err(|error| BridgeError::new("file_inspect_file_type_failed", error.to_string()))?;
                        Ok(json!({
                            "name": entry.file_name().to_string_lossy(),
                            "kind": if kind.is_dir() { "directory" } else if kind.is_file() { "file" } else { "other" },
                        }))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by(|left, right| {
            left.get("name")
                .and_then(Value::as_str)
                .cmp(&right.get("name").and_then(Value::as_str))
        });
        return Ok(json!({
            "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
            "workspaceRoot": workspace_root,
            "path": relative_path,
            "kind": "directory",
            "exists": true,
            "sizeBytes": metadata.len(),
            "entries": entries,
            "entryCount": entries.len(),
            "shellFallbackUsed": false,
        }));
    }
    if !metadata.is_file() {
        return Ok(json!({
            "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
            "workspaceRoot": workspace_root,
            "path": relative_path,
            "kind": "other",
            "exists": true,
            "sizeBytes": metadata.len(),
            "shellFallbackUsed": false,
        }));
    }
    let max_bytes = bounded_u64(
        input
            .get("maxBytes")
            .or_else(|| input.get("max_bytes"))
            .and_then(Value::as_u64),
        DEFAULT_PREVIEW_BYTES,
        1,
        MAX_PREVIEW_BYTES,
    );
    let preview_lines = bounded_usize(
        input
            .get("previewLines")
            .or_else(|| input.get("preview_lines"))
            .and_then(Value::as_u64),
        DEFAULT_PREVIEW_LINES,
        1,
        MAX_PREVIEW_LINES,
    );
    let bytes_to_read = metadata.len().min(max_bytes) as usize;
    let mut file = fs::File::open(&target)
        .map_err(|error| BridgeError::new("file_inspect_open_failed", error.to_string()))?;
    let mut buffer = vec![0u8; bytes_to_read];
    let bytes_read = file
        .read(&mut buffer)
        .map_err(|error| BridgeError::new("file_inspect_read_failed", error.to_string()))?;
    buffer.truncate(bytes_read);
    let preview = String::from_utf8_lossy(&buffer);
    let lines = preview.split('\n').collect::<Vec<_>>();
    let line_preview = lines
        .iter()
        .take(preview_lines)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    let preview_hash = ioi_crypto::algorithms::hash::sha256(line_preview.as_bytes())
        .map(|hash| format!("sha256:{}", hex::encode(hash)))
        .map_err(|error| BridgeError::new("file_inspect_hash_failed", error.to_string()))?;
    Ok(json!({
        "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
        "workspaceRoot": workspace_root,
        "path": relative_path,
        "kind": "file",
        "exists": true,
        "sizeBytes": metadata.len(),
        "preview": line_preview,
        "previewBytes": line_preview.len(),
        "previewHash": preview_hash,
        "truncated": bytes_read < metadata.len() as usize || lines.len() > preview_lines,
        "previewLineCount": lines.len().min(preview_lines),
        "shellFallbackUsed": false,
    }))
}

fn apply_workspace_patch(workspace_root: &str, input: &Value) -> Result<PatchOutcome, BridgeError> {
    let root = fs::canonicalize(workspace_root)
        .map_err(|error| BridgeError::new("workspace_root_invalid", error.to_string()))?;
    let selected_path = input
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            BridgeError::new(
                "file_apply_patch_path_required",
                "file.apply_patch requires a workspace-relative path.".to_string(),
            )
        })?;
    let target = workspace_path_allow_missing(&root, selected_path)?;
    let dry_run = input
        .get("dryRun")
        .or_else(|| input.get("dry_run"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let create = input
        .get("create")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let exists = target.absolute_path.exists();
    let before_metadata = if exists {
        Some(fs::metadata(&target.absolute_path).map_err(|error| {
            BridgeError::new("file_apply_patch_metadata_failed", error.to_string())
        })?)
    } else {
        None
    };
    if !exists && !create {
        return Err(BridgeError::new(
            "not_found",
            format!("File not found: {}", target.relative_path),
        ));
    }
    if let Some(metadata) = before_metadata.as_ref() {
        if !metadata.is_file() {
            return Err(BridgeError::new(
                "file_apply_patch_not_file",
                "file.apply_patch can only edit regular files.".to_string(),
            ));
        }
        if metadata.len() > APPLY_PATCH_MAX_FILE_BYTES {
            return Err(BridgeError::new(
                "file_apply_patch_file_too_large",
                "file.apply_patch refused a file over the edit size limit.".to_string(),
            ));
        }
    } else if let Some(parent) = target.absolute_path.parent() {
        if !parent.exists() || !parent.is_dir() {
            return Err(BridgeError::new(
                "file_apply_patch_parent_missing",
                "file.apply_patch create mode requires an existing parent directory.".to_string(),
            ));
        }
    }
    let before = if exists {
        fs::read_to_string(&target.absolute_path)
            .map_err(|error| BridgeError::new("file_apply_patch_read_failed", error.to_string()))?
    } else {
        String::new()
    };
    let edits = normalize_patch_edits(input)?;
    if edits.is_empty() {
        return Err(BridgeError::new(
            "file_apply_patch_empty",
            "file.apply_patch requires at least one edit.".to_string(),
        ));
    }
    let mut after = before.clone();
    let mut applied_edits = Vec::new();
    for edit in &edits {
        let applied = apply_patch_edit(&after, edit, &target.relative_path)?;
        after = applied.text;
        applied_edits.push(applied.summary);
    }
    let before_hash = sha256_hex(before.as_bytes())?;
    let after_hash = sha256_hex(after.as_bytes())?;
    let changed = before_hash != after_hash;
    let diff = text_diff_preview(&target.relative_path, &before, &after)?;
    if !dry_run && changed {
        fs::write(&target.absolute_path, after.as_bytes()).map_err(|error| {
            BridgeError::new("file_apply_patch_write_failed", error.to_string())
        })?;
    }
    let after_metadata = if !dry_run && target.absolute_path.exists() {
        fs::metadata(&target.absolute_path).ok()
    } else {
        None
    };
    let before_bytes = before.len();
    let after_bytes = after.len();
    let changed_file = json!({
        "path": target.relative_path,
        "beforeHash": before_hash,
        "afterHash": after_hash,
        "beforeExists": exists,
        "afterExists": if !dry_run { true } else { exists },
        "beforeSizeBytes": if exists { before_bytes } else { 0 },
        "afterSizeBytes": after_bytes,
        "beforeMtimeMs": before_metadata.as_ref().and_then(metadata_mtime_ms),
        "afterMtimeMs": after_metadata.as_ref().and_then(metadata_mtime_ms),
        "created": !exists,
        "diagnosticsRecommended": !dry_run,
    });
    let transition = if changed && !dry_run {
        Some(patch_transition(
            &target.relative_path,
            &before_hash,
            &after_hash,
        )?)
    } else {
        None
    };
    let transition_payload_ref = transition
        .as_ref()
        .map(|transition| transition.payload_ref.clone());
    let observation = json!({
        "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
        "workspaceRoot": workspace_root,
        "path": target.relative_path,
        "dryRun": dry_run,
        "applied": !dry_run && changed,
        "changed": changed,
        "created": !exists,
        "editCount": applied_edits.len(),
        "edits": applied_edits,
        "beforeHash": before_hash,
        "afterHash": after_hash,
        "diff": diff.text,
        "diffBytes": diff.bytes,
        "diffHash": diff.hash,
        "truncated": diff.truncated,
        "changedFiles": if changed { vec![changed_file] } else { vec![] },
        "workspaceSnapshotDrafts": if changed && !dry_run {
            vec![json!({
                "path": target.relative_path,
                "encoding": "utf8",
                "beforeExists": exists,
                "afterExists": true,
                "beforeContent": if exists { Some(before.clone()) } else { None },
                "afterContent": after,
            })]
        } else {
            vec![]
        },
        "diagnosticsRecommended": changed && !dry_run,
        "receiptRefs": [
            format!("receipt_file_apply_patch_{}_{}", safe_ref_path(&target.relative_path), after_hash.chars().take(12).collect::<String>())
        ],
        "payloadRefs": transition_payload_ref.into_iter().collect::<Vec<_>>(),
        "shellFallbackUsed": false,
    });
    Ok(PatchOutcome {
        observation,
        transition,
    })
}

fn workspace_diff_paths(root: &Path, input: &Value) -> Result<Vec<String>, BridgeError> {
    let selected_paths = selected_workspace_paths(input);
    selected_paths
        .iter()
        .map(|selected_path| workspace_relative_path_allow_missing(root, selected_path))
        .collect()
}

fn workspace_tool_paths(root: &Path, input: &Value) -> Result<Vec<WorkspacePath>, BridgeError> {
    selected_workspace_paths(input)
        .iter()
        .map(|selected_path| workspace_path_allow_missing(root, selected_path))
        .collect()
}

fn selected_workspace_paths(input: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(values) = input.get("paths").and_then(Value::as_array) {
        paths.extend(
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        );
    }
    if let Some(path) = input
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        paths.push(path.to_string());
    }
    paths
}

fn workspace_relative_path_allow_missing(
    root: &Path,
    selected_path: &str,
) -> Result<String, BridgeError> {
    Ok(workspace_path_allow_missing(root, selected_path)?.relative_path)
}

fn workspace_path_allow_missing(
    root: &Path,
    selected_path: &str,
) -> Result<WorkspacePath, BridgeError> {
    let candidate = path_candidate(root, selected_path);
    let normalized_root = normalize_path_lexically(root);
    let normalized_candidate = normalize_path_lexically(&candidate);
    if !normalized_candidate.starts_with(&normalized_root) {
        return Err(BridgeError::new(
            "path_outside_workspace",
            "git.diff path must stay inside workspace".to_string(),
        ));
    }
    if let Some(boundary) = nearest_existing_path(&normalized_candidate) {
        let real_boundary = fs::canonicalize(&boundary)
            .map_err(|error| BridgeError::new("path_boundary_invalid", error.to_string()))?;
        if !real_boundary.starts_with(root) {
            return Err(BridgeError::new(
                "path_outside_workspace",
                "git.diff path must stay inside workspace".to_string(),
            ));
        }
    }
    let relative = normalized_candidate
        .strip_prefix(&normalized_root)
        .map_err(|_| {
            BridgeError::new(
                "path_outside_workspace",
                "git.diff path must stay inside workspace".to_string(),
            )
        })?
        .to_string_lossy()
        .replace('\\', "/");
    Ok(if relative.is_empty() {
        WorkspacePath {
            absolute_path: normalized_candidate,
            relative_path: ".".to_string(),
        }
    } else {
        WorkspacePath {
            absolute_path: normalized_candidate,
            relative_path: relative,
        }
    })
}

fn workspace_directory(
    root: &Path,
    selected_path: &str,
    error_code: &'static str,
) -> Result<WorkspacePath, BridgeError> {
    let path = workspace_path_allow_missing(root, selected_path)?;
    if !path.absolute_path.is_dir() {
        return Err(BridgeError::new(
            error_code,
            "workspace directory must exist".to_string(),
        ));
    }
    Ok(path)
}

fn workspace_target(root: &Path, selected_path: &str) -> Result<PathBuf, BridgeError> {
    let candidate = path_candidate(root, selected_path);
    let canonical = fs::canonicalize(&candidate)
        .map_err(|error| BridgeError::new("not_found", error.to_string()))?;
    if !canonical.starts_with(root) {
        return Err(BridgeError::new(
            "path_outside_workspace",
            "file.inspect path must stay inside workspace".to_string(),
        ));
    }
    Ok(canonical)
}

fn path_candidate(root: &Path, selected_path: &str) -> PathBuf {
    if Path::new(selected_path).is_absolute() {
        PathBuf::from(selected_path)
    } else {
        root.join(selected_path)
    }
}

fn relative_path_between(base: &Path, target: &Path) -> String {
    let normalized_base = normalize_path_lexically(base);
    let normalized_target = normalize_path_lexically(target);
    let base_parts = normal_path_parts(&normalized_base);
    let target_parts = normal_path_parts(&normalized_target);
    let common_len = base_parts
        .iter()
        .zip(target_parts.iter())
        .take_while(|(left, right)| left == right)
        .count();
    let mut parts = Vec::new();
    parts.extend(std::iter::repeat("..".to_string()).take(base_parts.len() - common_len));
    parts.extend(target_parts[common_len..].iter().cloned());
    if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}

fn normal_path_parts(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_string()),
            _ => None,
        })
        .collect()
}

fn nearest_existing_path(path: &Path) -> Option<PathBuf> {
    let mut current = path.to_path_buf();
    while !current.exists() {
        if !current.pop() {
            return None;
        }
    }
    Some(current)
}

fn normalize_path_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(value) => normalized.push(value),
        }
    }
    normalized
}

struct CommandOutput {
    ok: bool,
    stdout: String,
    stderr: String,
}

struct WorkspacePath {
    absolute_path: PathBuf,
    relative_path: String,
}

struct PatchOutcome {
    observation: Value,
    transition: Option<PatchTransition>,
}

struct PatchTransition {
    operation_ref: String,
    payload_ref: String,
    expected_heads: Vec<String>,
    state_root_before: String,
    state_root_after: String,
    resulting_head: String,
}

struct PatchDiffPreview {
    text: String,
    bytes: usize,
    hash: String,
    truncated: bool,
}

struct PatchEditApplication {
    text: String,
    summary: Value,
}

enum PatchEdit {
    Replace {
        old_text: String,
        new_text: String,
        occurrence: String,
    },
    Append {
        text: String,
    },
    Prepend {
        text: String,
    },
}

struct DiagnosticRun {
    backend: &'static str,
    resolved_command_id: &'static str,
    display_command: &'static str,
    stdout: String,
    stderr: String,
    exit_code: i32,
    timed_out: bool,
    backend_status: &'static str,
    backend_reason: Option<&'static str>,
    fallback_used: bool,
    fallback_from: Option<&'static str>,
    project_context: Value,
    diagnostic_status: &'static str,
    diagnostics: Vec<Value>,
}

struct DiagnosticsProjectContext {
    workspace_root: PathBuf,
    project_root_absolute_path: PathBuf,
    tsconfig_absolute_path: Option<PathBuf>,
    tsconfig_paths: Vec<PathBuf>,
    package_root_absolute_path: Option<PathBuf>,
    path_count: usize,
}

struct CapturedCommand {
    stdout: String,
    stderr: String,
    exit_code: i32,
    timed_out: bool,
}

struct TestCommand {
    executable: &'static str,
    display_command: &'static str,
    args: Vec<String>,
}

fn test_command_for_input(command_id: &str, cwd: &Path, paths: &[WorkspacePath]) -> TestCommand {
    match command_id {
        "node.test" => {
            let mut args = vec!["--test".to_string()];
            args.extend(
                paths
                    .iter()
                    .map(|path| relative_path_between(cwd, &path.absolute_path)),
            );
            TestCommand {
                executable: "node",
                display_command: "node --test",
                args,
            }
        }
        "npm.test" => TestCommand {
            executable: "npm",
            display_command: "npm test",
            args: vec!["test".to_string()],
        },
        "cargo.test" => TestCommand {
            executable: "cargo",
            display_command: "cargo test",
            args: vec!["test".to_string()],
        },
        "cargo.check" => TestCommand {
            executable: "cargo",
            display_command: "cargo check",
            args: vec!["check".to_string()],
        },
        _ => unreachable!("test command id is validated before command mapping"),
    }
}

fn diagnostics_project_context(
    root: &Path,
    run_cwd: &Path,
    paths: &[WorkspacePath],
) -> DiagnosticsProjectContext {
    let mut tsconfig_paths = Vec::new();
    for path in paths {
        let start = path
            .absolute_path
            .parent()
            .unwrap_or(path.absolute_path.as_path());
        if let Some(tsconfig_path) = find_nearest_file(start, "tsconfig.json", root) {
            if !tsconfig_paths.contains(&tsconfig_path) {
                tsconfig_paths.push(tsconfig_path);
            }
        }
    }
    let tsconfig_absolute_path = tsconfig_paths
        .first()
        .cloned()
        .or_else(|| find_nearest_file(run_cwd, "tsconfig.json", root));
    let project_root_absolute_path = tsconfig_absolute_path
        .as_ref()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| run_cwd.to_path_buf());
    let package_root_absolute_path =
        find_nearest_file(&project_root_absolute_path, "package.json", root)
            .and_then(|path| path.parent().map(Path::to_path_buf));
    DiagnosticsProjectContext {
        workspace_root: root.to_path_buf(),
        project_root_absolute_path,
        tsconfig_absolute_path,
        tsconfig_paths,
        package_root_absolute_path,
        path_count: paths.len(),
    }
}

impl DiagnosticsProjectContext {
    fn to_json(&self, tsc_available: bool) -> Value {
        json!({
            "schemaVersion": "ioi.runtime.diagnostics-project-context.v1",
            "projectRoot": workspace_relative_from_absolute(&self.workspace_root, &self.project_root_absolute_path),
            "tsconfigPath": self.tsconfig_absolute_path
                .as_ref()
                .map(|path| workspace_relative_from_absolute(&self.workspace_root, path)),
            "tsconfigPaths": self.tsconfig_paths
                .iter()
                .map(|path| workspace_relative_from_absolute(&self.workspace_root, path))
                .collect::<Vec<_>>(),
            "packageRoot": self.package_root_absolute_path
                .as_ref()
                .map(|path| workspace_relative_from_absolute(&self.workspace_root, path)),
            "packageManager": self.package_root_absolute_path
                .as_ref()
                .and_then(|path| package_manager_for_directory(path)),
            "pathCount": self.path_count,
            "tscAvailable": tsc_available,
        })
    }
}

fn run_typescript_check(
    root: &Path,
    cwd: &Path,
    paths: &[WorkspacePath],
    timeout_ms: u64,
    input: &Value,
    project_context: DiagnosticsProjectContext,
) -> Result<DiagnosticRun, BridgeError> {
    let backend = if project_context.tsconfig_absolute_path.is_some() {
        "typescript.project.check"
    } else {
        "typescript.file.check"
    };
    let display_command = if project_context.tsconfig_absolute_path.is_some() {
        "tsc --noEmit --pretty false -p tsconfig.json"
    } else {
        "tsc --noEmit --pretty false"
    };
    let executable = local_tsc_executable(root, &project_context.project_root_absolute_path);
    let project_context_json = project_context.to_json(executable.is_some());
    let Some(executable) = executable else {
        return Ok(DiagnosticRun {
            backend,
            resolved_command_id: "typescript.check",
            display_command,
            stdout: String::new(),
            stderr: "typescript.check degraded: local node_modules/.bin/tsc was not found."
                .to_string(),
            exit_code: 0,
            timed_out: false,
            backend_status: "degraded",
            backend_reason: Some("typescript_executable_missing"),
            fallback_used: false,
            fallback_from: None,
            project_context: project_context_json,
            diagnostic_status: "degraded",
            diagnostics: vec![],
        });
    };
    let mut args = vec![
        "--noEmit".to_string(),
        "--pretty".to_string(),
        "false".to_string(),
    ];
    if let Some(tsconfig_path) = project_context.tsconfig_absolute_path.as_ref() {
        args.push("-p".to_string());
        args.push(relative_path_between(cwd, tsconfig_path));
    } else {
        args.extend(
            paths
                .iter()
                .map(|path| relative_path_between(cwd, &path.absolute_path)),
        );
    }
    args.extend(sanitize_string_array(input.get("args")));
    let executable_text = executable.to_string_lossy().to_string();
    let run = run_command_with_timeout(&executable_text, &args, cwd, timeout_ms, &[])?;
    let mut diagnostics = if run.exit_code == 0 && !run.timed_out {
        vec![]
    } else {
        typescript_output_diagnostics(root, cwd, &format!("{}\n{}", run.stdout, run.stderr))
    };
    if run.timed_out && diagnostics.is_empty() {
        diagnostics.push(json!({
            "path": project_context.tsconfig_absolute_path
                .as_ref()
                .map(|path| workspace_relative_from_absolute(root, path))
                .or_else(|| paths.first().map(|path| path.relative_path.clone())),
            "severity": "error",
            "source": "typescript.check",
            "code": "timeout",
            "message": "typescript.check timed out.",
            "line": null,
            "column": null,
        }));
    }
    let diagnostic_status = if run.timed_out || !diagnostics.is_empty() {
        "findings"
    } else {
        "clean"
    };
    Ok(DiagnosticRun {
        backend,
        resolved_command_id: "typescript.check",
        display_command,
        stdout: run.stdout,
        stderr: run.stderr,
        exit_code: run.exit_code,
        timed_out: run.timed_out,
        backend_status: if run.timed_out {
            "timed_out"
        } else {
            "available"
        },
        backend_reason: None,
        fallback_used: false,
        fallback_from: None,
        project_context: project_context_json,
        diagnostic_status,
        diagnostics,
    })
}

fn typescript_path_supported(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".ts")
        || lower.ends_with(".tsx")
        || lower.ends_with(".mts")
        || lower.ends_with(".cts")
}

fn typescript_output_diagnostics(root: &Path, cwd: &Path, output: &str) -> Vec<Value> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| typescript_output_diagnostic(root, cwd, line))
        .collect()
}

fn typescript_output_diagnostic(root: &Path, cwd: &Path, line: &str) -> Option<Value> {
    let marker = "): error ";
    let marker_index = line.find(marker)?;
    let prefix = &line[..marker_index + 1];
    let rest = &line[marker_index + marker.len()..];
    let open_index = prefix.rfind('(')?;
    let close_index = prefix.rfind(')')?;
    let path_text = prefix[..open_index].trim();
    let location = &prefix[open_index + 1..close_index];
    let mut location_parts = location.split(',');
    let line_number = location_parts.next()?.trim().parse::<u64>().ok()?;
    let column_number = location_parts.next()?.trim().parse::<u64>().ok()?;
    let code_end = rest.find(':')?;
    let code = rest[..code_end].trim();
    let message = rest[code_end + 1..].trim();
    if code.is_empty() || message.is_empty() {
        return None;
    }
    Some(json!({
        "path": normalize_diagnostic_path(root, cwd, path_text),
        "severity": "error",
        "source": "typescript.check",
        "code": code,
        "message": message,
        "line": line_number,
        "column": column_number,
    }))
}

fn normalize_diagnostic_path(root: &Path, cwd: &Path, diagnostic_path: &str) -> String {
    let normalized = diagnostic_path.replace('\\', "/");
    let candidate = if Path::new(&normalized).is_absolute() {
        PathBuf::from(&normalized)
    } else {
        cwd.join(&normalized)
    };
    let normalized_candidate = normalize_path_lexically(&candidate);
    if normalized_candidate.starts_with(root) {
        workspace_relative_from_absolute(root, &normalized_candidate)
    } else {
        normalized
    }
}

fn local_tsc_executable(root: &Path, preferred_directory: &Path) -> Option<PathBuf> {
    let executable_name = if cfg!(windows) { "tsc.cmd" } else { "tsc" };
    let mut current = if preferred_directory.starts_with(root) {
        preferred_directory.to_path_buf()
    } else {
        root.to_path_buf()
    };
    loop {
        let candidate = current
            .join("node_modules")
            .join(".bin")
            .join(executable_name);
        if candidate.exists() {
            return Some(candidate);
        }
        if current == root || !current.pop() {
            break;
        }
    }
    None
}

fn find_nearest_file(start_directory: &Path, file_name: &str, root: &Path) -> Option<PathBuf> {
    let mut current = normalize_path_lexically(start_directory);
    if !current.starts_with(root) {
        current = root.to_path_buf();
    }
    loop {
        let candidate = current.join(file_name);
        if candidate.exists() {
            return Some(candidate);
        }
        if current == root || !current.pop() {
            break;
        }
    }
    None
}

fn package_manager_for_directory(directory: &Path) -> Option<&'static str> {
    if directory.join("pnpm-lock.yaml").exists() {
        Some("pnpm")
    } else if directory.join("yarn.lock").exists() {
        Some("yarn")
    } else if directory.join("bun.lockb").exists() {
        Some("bun")
    } else if directory.join("package-lock.json").exists()
        || directory.join("package.json").exists()
    {
        Some("npm")
    } else {
        None
    }
}

fn workspace_relative_from_absolute(root: &Path, target: &Path) -> String {
    let normalized_root = normalize_path_lexically(root);
    let normalized_target = normalize_path_lexically(target);
    normalized_target
        .strip_prefix(&normalized_root)
        .ok()
        .map(|path| {
            let relative = path.to_string_lossy().replace('\\', "/");
            if relative.is_empty() {
                ".".to_string()
            } else {
                relative
            }
        })
        .unwrap_or_else(|| normalized_target.to_string_lossy().replace('\\', "/"))
}

fn normalize_patch_edits(input: &Value) -> Result<Vec<PatchEdit>, BridgeError> {
    let mut edits = Vec::new();
    if let Some(values) = input.get("edits").and_then(Value::as_array) {
        for value in values.iter().take(APPLY_PATCH_MAX_EDITS) {
            edits.push(patch_edit_from_value(value)?);
        }
    }
    if input.get("oldText").is_some() || input.get("old_text").is_some() {
        edits.push(PatchEdit::Replace {
            old_text: string_field(input, &["oldText", "old_text"]).unwrap_or_default(),
            new_text: string_field(input, &["newText", "new_text"]).unwrap_or_default(),
            occurrence: string_field(input, &["occurrence"]).unwrap_or_else(|| "only".to_string()),
        });
    }
    if input.get("appendText").is_some() || input.get("append_text").is_some() {
        edits.push(PatchEdit::Append {
            text: string_field(input, &["appendText", "append_text"]).unwrap_or_default(),
        });
    }
    if input.get("prependText").is_some() || input.get("prepend_text").is_some() {
        edits.push(PatchEdit::Prepend {
            text: string_field(input, &["prependText", "prepend_text"]).unwrap_or_default(),
        });
    }
    edits.truncate(APPLY_PATCH_MAX_EDITS);
    Ok(edits)
}

fn patch_edit_from_value(value: &Value) -> Result<PatchEdit, BridgeError> {
    let object = value.as_object().ok_or_else(|| {
        BridgeError::new(
            "file_apply_patch_unknown_edit",
            "Patch edit entries must be objects.".to_string(),
        )
    })?;
    let edit_value = Value::Object(object.clone());
    let edit_type = string_field(&edit_value, &["type"]).unwrap_or_default();
    match edit_type.as_str() {
        "append" => Ok(PatchEdit::Append {
            text: string_field(&edit_value, &["text"]).unwrap_or_default(),
        }),
        "prepend" => Ok(PatchEdit::Prepend {
            text: string_field(&edit_value, &["text"]).unwrap_or_default(),
        }),
        "replace" => Ok(PatchEdit::Replace {
            old_text: string_field(&edit_value, &["oldText", "old_text"]).unwrap_or_default(),
            new_text: string_field(&edit_value, &["newText", "new_text"]).unwrap_or_default(),
            occurrence: string_field(&edit_value, &["occurrence"])
                .unwrap_or_else(|| "only".to_string()),
        }),
        _ => Err(BridgeError::new(
            "file_apply_patch_unknown_edit",
            "Unsupported file.apply_patch edit type.".to_string(),
        )),
    }
}

fn apply_patch_edit(
    text: &str,
    edit: &PatchEdit,
    relative_path: &str,
) -> Result<PatchEditApplication, BridgeError> {
    match edit {
        PatchEdit::Append { text: addition } => Ok(PatchEditApplication {
            text: format!("{text}{addition}"),
            summary: json!({
                "type": "append",
                "bytesAdded": addition.len(),
            }),
        }),
        PatchEdit::Prepend { text: addition } => Ok(PatchEditApplication {
            text: format!("{addition}{text}"),
            summary: json!({
                "type": "prepend",
                "bytesAdded": addition.len(),
            }),
        }),
        PatchEdit::Replace {
            old_text,
            new_text,
            occurrence,
        } => {
            if old_text.is_empty() {
                return Err(BridgeError::new(
                    "file_apply_patch_empty_old_text",
                    "Replace edits require non-empty oldText.".to_string(),
                ));
            }
            let count = count_occurrences(text, old_text);
            if count == 0 {
                return Err(BridgeError::new(
                    "file_apply_patch_old_text_missing",
                    format!("file.apply_patch could not find oldText in {relative_path}."),
                ));
            }
            if occurrence == "only" && count != 1 {
                return Err(BridgeError::new(
                    "file_apply_patch_old_text_ambiguous",
                    format!("file.apply_patch oldText matched more than once in {relative_path}."),
                ));
            }
            let next_text = if occurrence == "all" {
                text.replace(old_text, new_text)
            } else {
                text.replacen(old_text, new_text, 1)
            };
            Ok(PatchEditApplication {
                text: next_text,
                summary: json!({
                    "type": "replace",
                    "occurrence": occurrence,
                    "matches": if occurrence == "all" { count } else { 1 },
                    "oldHash": sha256_hex(old_text.as_bytes())?,
                    "newHash": sha256_hex(new_text.as_bytes())?,
                }),
            })
        }
    }
}

fn count_occurrences(text: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut offset = 0;
    while let Some(found) = text[offset..].find(needle) {
        count += 1;
        offset += found + needle.len();
        if offset > text.len() {
            break;
        }
    }
    count
}

fn text_diff_preview(
    relative_path: &str,
    before: &str,
    after: &str,
) -> Result<PatchDiffPreview, BridgeError> {
    if before == after {
        return Ok(PatchDiffPreview {
            text: String::new(),
            bytes: 0,
            hash: sha256_hex(b"")?,
            truncated: false,
        });
    }
    let raw = format!("--- a/{relative_path}\n+++ b/{relative_path}\n@@\n-{before}\n+{after}\n");
    let bytes = raw.len();
    let (text, truncated) = utf8_preview(&raw, APPLY_PATCH_MAX_DIFF_BYTES);
    let hash = sha256_hex(raw.as_bytes())?;
    Ok(PatchDiffPreview {
        text,
        bytes,
        hash,
        truncated,
    })
}

fn patch_transition(
    relative_path: &str,
    before_hash: &str,
    after_hash: &str,
) -> Result<PatchTransition, BridgeError> {
    let path_ref = safe_ref_path(relative_path);
    Ok(PatchTransition {
        operation_ref: format!(
            "agentgres://operation/file.apply_patch/{}/{}",
            path_ref,
            &after_hash[..12]
        ),
        payload_ref: format!(
            "payload://workspace/file.apply_patch/{path_ref}/{}",
            &after_hash[..12]
        ),
        expected_heads: vec![format!(
            "head://workspace/{path_ref}/{}",
            &before_hash[..12]
        )],
        state_root_before: format!("state://workspace/{path_ref}/{}", &before_hash[..12]),
        state_root_after: format!("state://workspace/{path_ref}/{}", &after_hash[..12]),
        resulting_head: format!("head://workspace/{path_ref}/{}", &after_hash[..12]),
    })
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn run_node_check(
    cwd: &Path,
    paths: &[WorkspacePath],
    timeout_ms: u64,
    project_context: DiagnosticsProjectContext,
) -> Result<DiagnosticRun, BridgeError> {
    let mut stdout_parts = Vec::new();
    let mut stderr_parts = Vec::new();
    let mut diagnostics = Vec::new();
    let mut exit_code = 0;
    let mut timed_out = false;
    let mut unsupported_count = 0usize;
    for target in paths {
        if !node_check_path_supported(&target.relative_path) {
            unsupported_count += 1;
            diagnostics.push(json!({
                "path": target.relative_path,
                "severity": "warning",
                "source": "node.check",
                "code": "unsupported_path",
                "message": "node.check only supports .js, .mjs, and .cjs files.",
                "line": null,
                "column": null,
            }));
            continue;
        }
        let run = run_command_with_timeout(
            "node",
            &[
                "--check".to_string(),
                target.absolute_path.to_string_lossy().to_string(),
            ],
            cwd,
            timeout_ms,
            &[],
        )?;
        if !run.stdout.is_empty() {
            stdout_parts.push(run.stdout.clone());
        }
        let stderr_entry = ["# ".to_string() + &target.relative_path, run.stderr.clone()]
            .into_iter()
            .filter(|entry| !entry.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        if !stderr_entry.is_empty() {
            stderr_parts.push(stderr_entry);
        }
        exit_code = exit_code.max(run.exit_code);
        timed_out = timed_out || run.timed_out;
        if run.exit_code != 0 || run.timed_out {
            diagnostics.extend(node_check_output_diagnostics(target, &run));
        }
    }
    let backend_status = if unsupported_count == paths.len() {
        "degraded"
    } else if timed_out {
        "timed_out"
    } else {
        "available"
    };
    let diagnostic_status = if backend_status == "degraded" {
        "degraded"
    } else if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.get("severity").and_then(Value::as_str) == Some("error"))
    {
        "findings"
    } else {
        "clean"
    };
    Ok(DiagnosticRun {
        backend: "node.check",
        resolved_command_id: "node.check",
        display_command: "node --check",
        stdout: stdout_parts.join("\n"),
        stderr: stderr_parts.join("\n"),
        exit_code: if timed_out { 124 } else { exit_code },
        timed_out,
        backend_status,
        backend_reason: if backend_status == "degraded" {
            Some("unsupported_path")
        } else {
            None
        },
        fallback_used: false,
        fallback_from: None,
        project_context: project_context.to_json(false),
        diagnostic_status,
        diagnostics,
    })
}

fn node_check_path_supported(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".js") || lower.ends_with(".mjs") || lower.ends_with(".cjs")
}

fn run_command_with_timeout(
    command: &str,
    args: &[String],
    cwd: &Path,
    timeout_ms: u64,
    env_overrides: &[(String, String)],
) -> Result<CapturedCommand, BridgeError> {
    let command_env = safe_subprocess_env(env_overrides);
    let mut child = Command::new(command)
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(command_env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| BridgeError::new("diagnostic_command_spawn_failed", error.to_string()))?;
    let started = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let mut timed_out = false;
    loop {
        match child.try_wait().map_err(|error| {
            BridgeError::new("diagnostic_command_wait_failed", error.to_string())
        })? {
            Some(_) => break,
            None if started.elapsed() >= timeout => {
                timed_out = true;
                let _ = child.kill();
                break;
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| BridgeError::new("diagnostic_command_output_failed", error.to_string()))?;
    Ok(CapturedCommand {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: if timed_out {
            124
        } else {
            output.status.code().unwrap_or(1)
        },
        timed_out,
    })
}

fn sanitize_string_array(value: Option<&Value>) -> Vec<String> {
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

fn json_string_refs(value: &Value, keys: &[&str]) -> Vec<String> {
    for key in keys {
        let refs = sanitize_string_array(value.get(*key));
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

fn unique_string_refs(values: Vec<String>) -> Vec<String> {
    values.into_iter().fold(Vec::new(), |mut unique, value| {
        if !unique.contains(&value) {
            unique.push(value);
        }
        unique
    })
}

fn sanitize_test_env(value: Option<&Value>) -> Vec<(String, String)> {
    value
        .and_then(Value::as_object)
        .map(|items| {
            items
                .iter()
                .filter_map(|(key, value)| {
                    let value = value.as_str()?;
                    if env_key_allowed(key) {
                        Some((key.clone(), value.to_string()))
                    } else {
                        None
                    }
                })
                .take(40)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn safe_subprocess_env(overrides: &[(String, String)]) -> Vec<(String, String)> {
    let mut env_values = env::vars()
        .filter(|(key, _)| env_key_allowed(key) && !key.starts_with("NODE_TEST"))
        .collect::<Vec<_>>();
    for (key, value) in overrides {
        if env_key_allowed(key) && !key.starts_with("NODE_TEST") {
            env_values.retain(|(existing_key, _)| existing_key != key);
            env_values.push((key.clone(), value.clone()));
        }
    }
    env_values
}

fn env_key_allowed(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    if !chars.all(|character| character == '_' || character.is_ascii_alphanumeric()) {
        return false;
    }
    !is_sensitive_env_key(key)
}

fn is_sensitive_env_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "credential",
        "authorization",
        "cookie",
        "session",
        "vault",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        || lower.contains("apikey")
        || lower.contains("api_key")
        || lower.contains("api-key")
        || lower.contains("privatekey")
        || lower.contains("private_key")
        || lower.contains("private-key")
}

fn node_check_output_diagnostics(target: &WorkspacePath, run: &CapturedCommand) -> Vec<Value> {
    if run.timed_out {
        return vec![json!({
            "path": target.relative_path,
            "severity": "error",
            "source": "node.check",
            "code": "timeout",
            "message": "node.check timed out.",
            "line": null,
            "column": null,
        })];
    }
    let message = run
        .stderr
        .lines()
        .find(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("SyntaxError")
                || trimmed.starts_with("TypeError")
                || trimmed.starts_with("ReferenceError")
                || trimmed.starts_with("Error:")
        })
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            run.stderr
                .lines()
                .rev()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "node.check reported a diagnostic.".to_string());
    vec![json!({
        "path": target.relative_path,
        "severity": "error",
        "source": "node.check",
        "code": diagnostic_code(&message),
        "message": message,
        "line": null,
        "column": null,
    })]
}

fn diagnostic_code(message: &str) -> String {
    let head = message.split(':').next().unwrap_or("diagnostic");
    let code = head
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if code.is_empty() {
        "diagnostic".to_string()
    } else {
        code
    }
}

fn run_git_read_only(root: &Path, args: &[String]) -> Result<CommandOutput, BridgeError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| BridgeError::new("git_spawn_failed", error.to_string()))?;
    Ok(CommandOutput {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn nonempty_command_error(output: &CommandOutput, fallback: &str) -> String {
    let stderr = output.stderr.trim();
    if !stderr.is_empty() {
        return stderr.to_string();
    }
    let stdout = output.stdout.trim();
    if !stdout.is_empty() {
        return stdout.to_string();
    }
    fallback.to_string()
}

fn sha256_hex(bytes: &[u8]) -> Result<String, BridgeError> {
    ioi_crypto::algorithms::hash::sha256(bytes)
        .map(hex::encode)
        .map_err(|error| BridgeError::new("sha256_failed", error.to_string()))
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

fn metadata_mtime_ms(metadata: &fs::Metadata) -> Option<u128> {
    metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis())
}

fn utf8_preview(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_string(), false);
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

fn bounded_u64(value: Option<u64>, default: u64, min: u64, max: u64) -> u64 {
    value.unwrap_or(default).clamp(min, max)
}

fn bounded_usize(value: Option<u64>, default: usize, min: usize, max: usize) -> usize {
    value
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(default)
        .clamp(min, max)
}

fn projection_status_for_backend(backend: &str) -> StepModuleProjectionStatus {
    match backend {
        "rust_workload_live" => StepModuleProjectionStatus::Live,
        "rust_workload_gated" => StepModuleProjectionStatus::Gated,
        _ => StepModuleProjectionStatus::Shadow,
    }
}

fn short_suffix(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(24)
        .collect::<String>()
}

#[derive(Debug)]
struct BridgeError {
    code: &'static str,
    message: String,
}

impl BridgeError {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn bridge_command_schema_version_alias_is_retired() {
        let canonical: BridgeEnvelope = serde_json::from_value(json!({
            "schema_version": COMMAND_SCHEMA_VERSION,
            "operation": "run_coding_tool_step_module"
        }))
        .expect("canonical bridge envelope");

        assert_eq!(canonical.schema_version, COMMAND_SCHEMA_VERSION);

        let retired_alias = serde_json::from_value::<BridgeEnvelope>(json!({
            "schemaVersion": COMMAND_SCHEMA_VERSION,
            "operation": "run_coding_tool_step_module"
        }));

        assert!(
            retired_alias.is_err(),
            "Rust bridge command intake must require canonical schema_version"
        );
    }

    fn temp_workspace(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ioi-step-module-bridge-workspace-restore-{}-{}",
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&path).expect("workspace dir");
        path
    }

    #[test]
    fn bridge_admits_model_mount_route_decision_through_rust_core() {
        let request: ModelMountRouteDecisionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_model_mount_route_decision",
            "backend": "rust_model_mount_live",
            "request": {
                "schema_version": "ioi.model_mount.route_decision.v1",
                "route_ref": "route.local-first",
                "provider_ref": "provider.local",
                "endpoint_ref": "endpoint.local",
                "model_ref": "model.local",
                "capability": "chat",
                "policy_hash": "sha256:policy",
                "idempotency_key": "model_route_decision:test",
                "receipt_refs": ["receipt://route"],
                "authority_grant_refs": [],
                "authority_receipt_refs": [],
                "privacy_profile": "local_private",
                "node_plaintext_allowed": false
            }
        }))
        .expect("bridge request");

        let response = admit_model_mount_route_decision(request).expect("admitted");

        assert_eq!(response["source"], "rust_model_mount_command");
        assert_eq!(response["backend"], "rust_model_mount_live");
        assert_eq!(response["record"]["model_ref"], "model.local");
        assert_eq!(response["record"]["receipt_refs"][0], "receipt://route");
        assert!(response["route_decision_ref"]
            .as_str()
            .expect("route decision ref")
            .starts_with("model_mount://route_decision/"));
    }

    #[test]
    fn model_mount_route_decision_rejects_step_module_command_schema() {
        let request: ModelMountRouteDecisionBridgeRequest = serde_json::from_value(json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_model_mount_route_decision",
            "backend": "rust_model_mount_live",
            "request": {
                "schema_version": "ioi.model_mount.route_decision.v1",
                "route_ref": "route.local-first",
                "provider_ref": "provider.local",
                "endpoint_ref": "endpoint.local",
                "model_ref": "model.local",
                "capability": "chat",
                "policy_hash": "sha256:policy",
                "idempotency_key": "model_route_decision:test",
                "receipt_refs": ["receipt://route"],
                "authority_grant_refs": [],
                "authority_receipt_refs": [],
                "privacy_profile": "local_private",
                "node_plaintext_allowed": false
            }
        }))
        .expect("bridge request");

        let error = admit_model_mount_route_decision(request)
            .expect_err("daemon-core model_mount rejects StepModule command schema");

        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_admits_model_mount_invocation_through_rust_core() {
        let request: ModelMountInvocationAdmissionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_model_mount_invocation",
            "backend": "rust_model_mount_live",
            "request": {
                "schema_version": "ioi.model_mount.invocation_admission.v1",
                "invocation_ref": "model-invocation://response/test",
                "route_decision_ref": "model_mount://route_decision/test",
                "route_receipt_ref": "receipt://route/test",
                "invocation_receipt_ref": "receipt://invocation/test",
                "route_ref": "route.local-first",
                "provider_ref": "provider.local",
                "endpoint_ref": "endpoint.local",
                "model_ref": "model.local",
                "capability": "chat",
                "invocation_kind": "responses",
                "policy_hash": "sha256:policy",
                "input_hash": "sha256:input",
                "output_hash": "sha256:output",
                "idempotency_key": "model_invocation:test",
                "receipt_refs": ["receipt://route/test", "receipt://invocation/test"],
                "authority_grant_refs": ["grant://wallet/model-chat"],
                "authority_receipt_refs": ["receipt://wallet/model-chat"],
                "provider_auth_evidence_refs": [],
                "backend_evidence_refs": [],
                "tool_receipt_refs": [],
                "privacy_profile": "local_private",
                "node_plaintext_allowed": false
            }
        }))
        .expect("bridge request");

        let response = admit_model_mount_invocation(request).expect("admitted");

        assert_eq!(response["source"], "rust_model_mount_invocation_command");
        assert_eq!(response["backend"], "rust_model_mount_live");
        assert_eq!(response["record"]["model_ref"], "model.local");
        assert_eq!(
            response["record"]["route_receipt_ref"],
            "receipt://route/test"
        );
        assert_eq!(
            response["record"]["invocation_receipt_ref"],
            "receipt://invocation/test"
        );
        assert!(response["invocation_admission_ref"]
            .as_str()
            .expect("invocation admission ref")
            .starts_with("model_mount://invocation_admission/"));
    }

    #[test]
    fn bridge_admits_model_mount_provider_execution_through_rust_core() {
        let request: ModelMountProviderExecutionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_model_mount_provider_execution",
            "backend": "rust_model_mount_live",
            "request": {
                "schema_version": "ioi.model_mount.provider_execution.v1",
                "invocation_ref": "model-provider-execution://response/test",
                "route_decision_ref": "model_mount://route_decision/test",
                "route_receipt_ref": "receipt://route/test",
                "route_ref": "route.local-first",
                "provider_ref": "provider.local",
                "endpoint_ref": "endpoint.local",
                "model_ref": "model.local",
                "capability": "chat",
                "invocation_kind": "responses",
                "policy_hash": "sha256:policy",
                "input_hash": "sha256:input",
                "request_hash": "sha256:request",
                "idempotency_key": "model_provider_execution:test",
                "receipt_refs": ["receipt://route/test"],
                "authority_grant_refs": ["grant://wallet/model-chat"],
                "authority_receipt_refs": ["receipt://wallet/model-chat"],
                "provider_auth_evidence_refs": [],
                "backend_evidence_refs": ["backend://native-local"],
                "tool_receipt_refs": [],
                "privacy_profile": "local_private",
                "node_plaintext_allowed": false
            }
        }))
        .expect("bridge request");

        let response = admit_model_mount_provider_execution(request).expect("admitted");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_execution_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_live");
        assert_eq!(response["record"]["request_hash"], "sha256:request");
        assert_eq!(
            response["record"]["route_receipt_ref"],
            "receipt://route/test"
        );
        assert!(response["provider_execution_ref"]
            .as_str()
            .expect("provider execution ref")
            .starts_with("model_mount://provider_execution/"));
    }

    #[test]
    fn bridge_executes_model_mount_provider_invocation_through_rust_core() {
        let provider_execution_request: ModelMountProviderExecutionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "admit_model_mount_provider_execution",
                "backend": "rust_model_mount_live",
                "request": {
                    "schema_version": "ioi.model_mount.provider_execution.v1",
                    "invocation_ref": "model-provider-execution://response/test",
                    "route_decision_ref": "model_mount://route_decision/test",
                    "route_receipt_ref": "receipt://route/test",
                    "route_ref": "route.local-first",
                    "provider_ref": "provider.local",
                    "endpoint_ref": "endpoint.local",
                    "model_ref": "model.local",
                    "capability": "chat",
                    "invocation_kind": "chat.completions",
                    "policy_hash": "sha256:policy",
                    "input_hash": "sha256:input",
                    "request_hash": "sha256:request",
                    "idempotency_key": "model_provider_execution:test",
                    "receipt_refs": ["receipt://route/test"],
                    "authority_grant_refs": ["grant://wallet/model-chat"],
                    "authority_receipt_refs": ["receipt://wallet/model-chat"],
                    "provider_auth_evidence_refs": [],
                    "backend_evidence_refs": ["backend.fixture"],
                    "tool_receipt_refs": [],
                    "privacy_profile": "local_private",
                    "node_plaintext_allowed": false
                }
            }))
            .expect("provider execution request");
        let admission_response =
            admit_model_mount_provider_execution(provider_execution_request).expect("admitted");
        let admission = admission_response["record"].clone();
        let provider_execution_ref = admission["provider_execution_ref"]
            .as_str()
            .expect("provider execution ref");
        let provider_execution_hash = admission["provider_execution_hash"]
            .as_str()
            .expect("provider execution hash");

        let request: ModelMountProviderInvocationBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "execute_model_mount_provider_invocation",
            "backend": "rust_model_mount_fixture",
            "request": {
                "schema_version": "ioi.model_mount.provider_invocation.v1",
                "provider_execution_ref": provider_execution_ref,
                "provider_execution_hash": provider_execution_hash,
                "route_decision_ref": "model_mount://route_decision/test",
                "route_receipt_ref": "receipt://route/test",
                "route_ref": "route.local-first",
                "provider_ref": "provider.local",
                "provider_kind": "local_folder",
                "endpoint_ref": "endpoint.local",
                "model_ref": "model.local",
                "capability": "chat",
                "invocation_kind": "chat.completions",
                "input": "user: hello",
                "request_hash": "sha256:request",
                "execution_backend": "rust_model_mount_fixture",
                "api_format": "ioi_fixture",
                "driver": "fixture",
                "backend_ref": "backend.fixture",
                "receipt_refs": ["receipt://route/test"],
                "evidence_refs": [provider_execution_ref],
                "admitted_provider_execution": admission.clone()
            }
        }))
        .expect("provider invocation bridge request");

        let response = execute_model_mount_provider_invocation(request).expect("fixture executed");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_invocation_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_fixture");
        assert_eq!(response["execution_backend"], "rust_model_mount_fixture");
        assert_eq!(response["backendId"], "backend.fixture");
        assert!(response["outputText"]
            .as_str()
            .expect("output text")
            .starts_with("IOI model router fixture response from model.local."));
        assert_eq!(
            response["provider_execution_ref"],
            admission["provider_execution_ref"]
        );
        assert!(response["invocation_hash"]
            .as_str()
            .expect("invocation hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn bridge_executes_native_local_model_mount_provider_invocation_through_rust_core() {
        let provider_execution_request: ModelMountProviderExecutionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "admit_model_mount_provider_execution",
                "backend": "rust_model_mount_live",
                "request": {
                    "schema_version": "ioi.model_mount.provider_execution.v1",
                    "invocation_ref": "model-provider-execution://native-local/response/test",
                    "route_decision_ref": "model_mount://route_decision/native-local/test",
                    "route_receipt_ref": "receipt://route/native-local/test",
                    "route_ref": "route.native-local",
                    "provider_ref": "provider.autopilot.local",
                    "endpoint_ref": "endpoint.native-local",
                    "model_ref": "model://qwen/qwen3.5-9b",
                    "capability": "responses",
                    "invocation_kind": "responses",
                    "policy_hash": "sha256:policy",
                    "input_hash": "sha256:input",
                    "request_hash": "sha256:request",
                    "idempotency_key": "model_provider_execution:native-local:test",
                    "receipt_refs": ["receipt://route/native-local/test"],
                    "authority_grant_refs": ["grant://wallet/model-responses"],
                    "authority_receipt_refs": ["receipt://wallet/model-responses"],
                    "provider_auth_evidence_refs": [],
                    "backend_evidence_refs": ["backend.autopilot.native-local.fixture"],
                    "tool_receipt_refs": [],
                    "privacy_profile": "local_private",
                    "node_plaintext_allowed": false
                }
            }))
            .expect("native-local provider execution request");
        let admission_response =
            admit_model_mount_provider_execution(provider_execution_request).expect("admitted");
        let admission = admission_response["record"].clone();
        let provider_execution_ref = admission["provider_execution_ref"]
            .as_str()
            .expect("provider execution ref");
        let provider_execution_hash = admission["provider_execution_hash"]
            .as_str()
            .expect("provider execution hash");

        let request: ModelMountProviderInvocationBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "execute_model_mount_provider_invocation",
            "backend": "rust_model_mount_native_local",
            "request": {
                "schema_version": "ioi.model_mount.provider_invocation.v1",
                "provider_execution_ref": provider_execution_ref,
                "provider_execution_hash": provider_execution_hash,
                "route_decision_ref": "model_mount://route_decision/native-local/test",
                "route_receipt_ref": "receipt://route/native-local/test",
                "route_ref": "route.native-local",
                "provider_ref": "provider.autopilot.local",
                "provider_kind": "ioi_native_local",
                "endpoint_ref": "endpoint.native-local",
                "model_ref": "model://qwen/qwen3.5-9b",
                "capability": "responses",
                "invocation_kind": "responses",
                "input": "user: hello",
                "request_hash": "sha256:request",
                "execution_backend": "rust_model_mount_native_local",
                "api_format": "ioi_native",
                "driver": "native_local",
                "backend_ref": "backend.autopilot.native-local.fixture",
                "receipt_refs": ["receipt://route/native-local/test"],
                "evidence_refs": [provider_execution_ref],
                "admitted_provider_execution": admission.clone()
            }
        }))
        .expect("native-local provider invocation bridge request");

        let response = execute_model_mount_provider_invocation(request)
            .expect("native-local provider invocation executed");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_invocation_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_native_local");
        assert_eq!(
            response["execution_backend"],
            "rust_model_mount_native_local"
        );
        assert_eq!(
            response["result"]["backend"],
            "autopilot.native_local.fixture"
        );
        assert_eq!(
            response["backendId"],
            "backend.autopilot.native-local.fixture"
        );
        assert_eq!(
            response["providerResponseKind"],
            "rust_model_mount.native_local"
        );
        assert!(response["outputText"]
            .as_str()
            .expect("output text")
            .starts_with("Autopilot native local model response from model://qwen/qwen3.5-9b."));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_native_local_backend"));
    }

    #[test]
    fn bridge_executes_native_local_model_mount_provider_stream_through_rust_core() {
        let provider_execution_request: ModelMountProviderExecutionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "admit_model_mount_provider_execution",
                "backend": "rust_model_mount_live",
                "request": {
                    "schema_version": "ioi.model_mount.provider_execution.v1",
                    "invocation_ref": "model-provider-execution://native-local/stream/test",
                    "route_decision_ref": "model_mount://route_decision/native-local/stream/test",
                    "route_receipt_ref": "receipt://route/native-local/stream/test",
                    "route_ref": "route.native-local",
                    "provider_ref": "provider.autopilot.local",
                    "endpoint_ref": "endpoint.native-local",
                    "model_ref": "model://qwen/qwen3.5-9b",
                    "capability": "responses",
                    "invocation_kind": "responses",
                    "policy_hash": "sha256:policy",
                    "input_hash": "sha256:input",
                    "request_hash": "sha256:request",
                    "idempotency_key": "model_provider_execution:native-local-stream:test",
                    "receipt_refs": ["receipt://route/native-local/stream/test"],
                    "authority_grant_refs": ["grant://wallet/model-responses"],
                    "authority_receipt_refs": ["receipt://wallet/model-responses"],
                    "provider_auth_evidence_refs": [],
                    "backend_evidence_refs": ["backend.autopilot.native-local.fixture"],
                    "tool_receipt_refs": [],
                    "privacy_profile": "local_private",
                    "node_plaintext_allowed": false,
                    "stream_status": "started"
                }
            }))
            .expect("native-local stream provider execution request");
        let admission_response =
            admit_model_mount_provider_execution(provider_execution_request).expect("admitted");
        let admission = admission_response["record"].clone();
        let provider_execution_ref = admission["provider_execution_ref"]
            .as_str()
            .expect("provider execution ref");
        let provider_execution_hash = admission["provider_execution_hash"]
            .as_str()
            .expect("provider execution hash");

        let request: ModelMountProviderInvocationBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "execute_model_mount_provider_stream_invocation",
            "backend": "rust_model_mount_native_local_stream",
            "request": {
                "schema_version": "ioi.model_mount.provider_invocation.v1",
                "provider_execution_ref": provider_execution_ref,
                "provider_execution_hash": provider_execution_hash,
                "route_decision_ref": "model_mount://route_decision/native-local/stream/test",
                "route_receipt_ref": "receipt://route/native-local/stream/test",
                "route_ref": "route.native-local",
                "provider_ref": "provider.autopilot.local",
                "provider_kind": "ioi_native_local",
                "endpoint_ref": "endpoint.native-local",
                "model_ref": "model://qwen/qwen3.5-9b",
                "capability": "responses",
                "invocation_kind": "responses",
                "input": "user: hello",
                "request_hash": "sha256:request",
                "execution_backend": "rust_model_mount_native_local_stream",
                "api_format": "ioi_native",
                "driver": "native_local",
                "backend_ref": "backend.autopilot.native-local.fixture",
                "stream_status": "started",
                "receipt_refs": ["receipt://route/native-local/stream/test"],
                "evidence_refs": [provider_execution_ref],
                "admitted_provider_execution": admission.clone()
            }
        }))
        .expect("native-local provider stream invocation bridge request");

        let response = execute_model_mount_provider_stream_invocation(request)
            .expect("native-local provider stream executed");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_stream_invocation_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_native_local_stream");
        assert_eq!(
            response["execution_backend"],
            "rust_model_mount_native_local_stream"
        );
        assert_eq!(response["streamFormat"], "ioi_jsonl");
        assert_eq!(response["streamKind"], "openai_responses_native_local");
        assert_eq!(
            response["providerResponseKind"],
            "rust_model_mount.native_local.stream"
        );
        assert!(response["streamChunks"]
            .as_array()
            .expect("stream chunks")
            .iter()
            .any(|value| value.as_str().unwrap_or("").contains("\"done\":true")));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_native_local_stream_backend"));
    }

    #[test]
    fn bridge_plans_native_local_model_mount_provider_lifecycle_through_rust_core() {
        let request: ModelMountProviderLifecycleBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_provider_lifecycle",
            "backend": "rust_model_mount_native_local_lifecycle",
            "request": {
                "schema_version": "ioi.model_mount.provider_lifecycle.v1",
                "provider_ref": "provider.autopilot.local",
                "provider_kind": "ioi_native_local",
                "endpoint_ref": "endpoint.native-local",
                "model_ref": "model://qwen/qwen3.5-9b",
                "action": "load",
                "execution_backend": "rust_model_mount_native_local_lifecycle",
                "api_format": "ioi_native",
                "driver": "native_local",
                "backend_ref": "backend.autopilot.native-local.fixture",
                "evidence_refs": ["daemon_model_load_request"],
                "process_evidence_refs": ["autopilot_native_local_process_started"]
            }
        }))
        .expect("native-local lifecycle bridge request");

        let response =
            plan_model_mount_provider_lifecycle(request).expect("lifecycle planned in Rust");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_lifecycle_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_native_local_lifecycle"
        );
        assert_eq!(response["status"], "loaded");
        assert_eq!(
            response["backend_id"],
            "backend.autopilot.native-local.fixture"
        );
        assert_eq!(
            response["provider_backend"],
            "autopilot.native_local.fixture"
        );
        assert!(response.get("backendId").is_none());
        assert!(response.get("providerBackend").is_none());
        assert_eq!(response["driver"], "native_local");
        assert!(response["lifecycle_hash"]
            .as_str()
            .expect("lifecycle hash")
            .starts_with("sha256:"));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_native_local_lifecycle_backend"));
    }

    #[test]
    fn bridge_plans_model_mount_backend_process_through_rust_core() {
        let request: ModelMountBackendProcessPlanBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_backend_process",
            "backend": "rust_model_mount_backend_process",
            "request": {
                "schema_version": "ioi.model_mount.backend_process_plan.v1",
                "backend_ref": "backend.llama",
                "backend_kind": "llama_cpp",
                "base_url": "http://127.0.0.1:8091/v1",
                "model_ref": "model://qwen/qwen3.5-9b",
                "artifact_path": "/models/private/model.gguf",
                "binary_configured": true,
                "load_options": {
                    "context_length": 4096,
                    "parallel": 2,
                    "gpu": "auto",
                    "identifier": "llama profile",
                    "embeddings": true
                }
            }
        }))
        .expect("backend process bridge request");

        let response =
            plan_model_mount_backend_process(request).expect("backend process planned in Rust");

        assert_eq!(
            response["source"],
            "rust_model_mount_backend_process_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_backend_process");
        assert_eq!(response["supports_supervision"], true);
        assert_eq!(response["spawn_status"], "spawn_ready");
        assert_eq!(response["spawn_required"], true);
        assert!(response.get("spawnStatus").is_none());
        assert!(response["public_args"]
            .as_array()
            .expect("public args")
            .iter()
            .any(|value| value.as_str().unwrap_or("").starts_with("artifact:")));
        assert_eq!(response["spawn_args"][0], "--model");
        assert_eq!(response["spawn_args"][1], "/models/private/model.gguf");
        assert!(response["plan_hash"]
            .as_str()
            .expect("plan hash")
            .starts_with("sha256:"));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_backend_process_plan"));
    }

    #[test]
    fn bridge_plans_model_mount_accepted_receipt_transition_through_rust_core() {
        let request: ModelMountAcceptedReceiptTransitionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_accepted_receipt_transition",
                "backend": "rust_model_mount_accepted_receipt_transition",
                "request": {
                    "schema_version": "ioi.model_mount.accepted_receipt_transition.v1",
                    "current_sequence": 0,
                    "current_head_ref": "agentgres://model-mounting/accepted-receipts/head/0",
                    "current_state_root": "sha256:state-0",
                    "receipt_id": "receipt.invoke",
                    "receipt_kind": "model_invocation",
                    "route_decision_ref": "model_mount://route_decision/test",
                    "invocation_admission_ref": "model_mount://invocation_admission/test",
                    "invocation_admission_hash": "sha256:invocation-test",
                    "input_hash": "sha256:input",
                    "output_hash": "sha256:output"
                }
            }))
            .expect("accepted receipt transition bridge request");

        let response = plan_model_mount_accepted_receipt_transition(request)
            .expect("accepted receipt transition planned in Rust");

        assert_eq!(
            response["source"],
            "rust_model_mount_accepted_receipt_transition_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_accepted_receipt_transition"
        );
        assert_eq!(response["operation_id"], "op_00000001_model_invocation");
        assert_eq!(
            response["operation_ref"],
            "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation"
        );
        assert_eq!(
            response["expected_heads"][0],
            "agentgres://model-mounting/accepted-receipts/head/0"
        );
        assert_eq!(response["state_root_before"], "sha256:state-0");
        assert!(response["state_root_after"]
            .as_str()
            .expect("state root after")
            .starts_with("sha256:"));
        assert_eq!(
            response["resulting_head"],
            "agentgres://model-mounting/accepted-receipts/head/1"
        );
        assert_eq!(
            response["projection_watermark"],
            "model-mounting-accepted-receipts:1"
        );
        assert!(response["transition_hash"]
            .as_str()
            .expect("transition hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn bridge_plans_model_mount_accepted_receipt_head_through_rust_core() {
        let request: ModelMountAcceptedReceiptHeadBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_accepted_receipt_head",
            "backend": "rust_model_mount_accepted_receipt_head",
            "request": {
                "schema_version": "ioi.model_mount.accepted_receipt_head.v1",
                "sequence": 2
            }
        }))
        .expect("accepted receipt head bridge request");

        let response =
            plan_model_mount_accepted_receipt_head(request).expect("accepted receipt head planned");

        assert_eq!(
            response["source"],
            "rust_model_mount_accepted_receipt_head_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_accepted_receipt_head"
        );
        assert_eq!(response["sequence"], 2);
        assert_eq!(
            response["head_ref"],
            "agentgres://model-mounting/accepted-receipts/head/2"
        );
        assert!(response["state_root"]
            .as_str()
            .expect("state root")
            .starts_with("sha256:"));
        assert_eq!(
            response["projection_watermark"],
            "model-mounting-accepted-receipts:2"
        );
        assert!(response["head_hash"]
            .as_str()
            .expect("head hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn bridge_plans_model_mount_read_projection_through_rust_core() {
        let state = json!({
            "artifacts": [{
                "id": "artifact.local",
                "modelId": "model.local",
                "providerId": "provider.local.folder",
                "privacyClass": "local_private",
                "family": "local",
                "capabilities": ["chat"],
                "lastReceiptId": "receipt-artifact"
            }, {
                "id": "artifact.fixture",
                "modelId": "local:auto",
                "providerId": "provider.fixture",
                "privacyClass": "local_private",
                "family": "fixture",
                "capabilities": ["chat"]
            }],
            "endpoints": [{
                "id": "endpoint.local",
                "modelId": "model.local",
                "providerId": "provider.local",
                "status": "mounted",
                "capabilities": ["chat"],
                "privacyClass": "local_private",
                "lastReceiptId": "receipt-endpoint"
            }],
            "instances": [],
            "routes": [{
                "id": "route.local-first",
                "role": "default",
                "status": "active",
                "fallback": ["endpoint.local"],
                "privacy": "local_private",
                "providerEligibility": ["provider.local"],
                "deniedProviders": [],
                "maxCostUsd": 0,
                "maxLatencyMs": 1000
            }],
            "backends": [],
            "backend_processes": [],
            "providers": [{
                "id": "provider.local",
                "kind": "local",
                "status": "running",
                "lastReceiptId": "receipt-provider"
            }],
            "catalog": {"status": "ready"},
            "catalog_provider_configs": [],
            "oauth_sessions": [],
            "oauth_states": [],
            "downloads": [],
            "provider_health": [],
            "product_artifact_policy": {"include_internal_fixtures": false},
            "runtime_engines": [],
            "runtime_engine_profiles": [],
            "runtime_preference": {"routeId": "route.local-first"},
            "runtime_survey": null,
            "grants": [],
            "vault_refs": [],
            "mcp_servers": [],
            "conversation_states": [],
            "wallet": {"port": "WalletAuthorityPort"},
            "vault": {"port": "VaultPort"},
            "agentgres_store": {"port": "AgentgresStorePort"},
            "server": {"status": "running"},
            "receipts": [
                {
                    "id": "receipt-route",
                    "kind": "model_route_selection",
                    "createdAt": "2026-06-08T00:00:00.000Z",
                    "details": {
                        "model_route_decision": {
                            "schema_version": "ioi.model-route-decision.v1",
                            "route_id": "route.local-first",
                            "selected_model": "model.local"
                        },
                        "route_id": "route.local-first",
                        "endpoint_id": "endpoint.local",
                        "provider_id": "provider.local"
                    }
                },
                {
                    "id": "receipt-provider-health",
                    "kind": "provider_health",
                    "createdAt": "2026-06-08T00:01:00.000Z",
                    "details": {
                        "providerId": "provider.local",
                        "status": "healthy"
                    }
                },
                {
                    "id": "receipt-vault-health",
                    "kind": "vault_adapter_health",
                    "createdAt": "2026-06-08T00:02:00.000Z",
                    "details": {
                        "status": "healthy",
                        "implementation": "runtime_memory_vault"
                    }
                }
            ]
        });
        let mut state_with_health = state.clone();
        state_with_health["provider_health"] = json!([{
            "providerId": "provider.local",
            "receiptId": "receipt-provider-health",
            "status": "healthy"
        }]);
        let request: ModelMountReadProjectionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_read_projection",
            "backend": "rust_model_mount_read_projection",
            "request": {
                "projection_kind": "projection",
                "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                "generated_at": "2026-06-08T00:00:00.000Z",
                "state": state.clone()
            }
        }))
        .expect("model_mount read projection bridge request");

        let response =
            plan_model_mount_read_projection(request).expect("read projection planned in Rust");

        assert_eq!(
            response["source"],
            "rust_model_mount_read_projection_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_read_projection");
        assert_eq!(response["projection_kind"], "projection");
        assert_eq!(
            response["projection"]["source"],
            "agentgres_model_mounting_projection"
        );
        assert_eq!(response["projection"]["watermark"], 3);
        assert_eq!(
            response["projection"]["routeDecisions"][0]["receipt_id"],
            "receipt-route"
        );
        assert_eq!(
            response["projection"]["adapterBoundaries"]["agentgres"]["port"],
            "AgentgresStorePort"
        );
        assert_eq!(
            response["projection"]["adapterBoundaries"]["oauth"]["plaintextPersistence"],
            false
        );
        assert_eq!(
            response["projection"]["workflowBindings"]
                .as_array()
                .expect("workflow bindings")
                .len(),
            10
        );
        assert_eq!(
            response["projection"]["workflowBindings"][4]["capability"],
            "embeddings"
        );
        assert_eq!(
            response["projection"]["workflowBindings"][9]["daemonApi"],
            "/api/v1/workflows/receipt-gate"
        );
        assert_eq!(
            response["projection"]["routeDecisions"][0]["selected_model"],
            "model.local"
        );
        assert_eq!(
            response["projection"]["productArtifacts"]
                .as_array()
                .expect("product artifacts")
                .len(),
            1
        );
        assert_eq!(
            response["projection"]["runtimeModelCatalog"][0]["provider"],
            "ioi-daemon-local"
        );
        assert_eq!(
            response["projection"]["openAiModelList"]["data"][0]["id"],
            "model.local"
        );
        assert_eq!(
            response["projection"]["modelCapabilities"][0]["credential_readiness"]["status"],
            "ready"
        );
        assert_eq!(
            response["projection"]["modelCapabilities"][0]["candidates"][0]["model_id"],
            "model.local"
        );
        assert!(response["projection"].get("route_decisions").is_none());
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "model_mount_js_read_projection_authoring_retired"));

        let receipt_replay_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "receipt_replay",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "receipt_id": "receipt-route",
                    "state": {
                        "receipts": state["receipts"].clone(),
                        "routes": state["routes"].clone(),
                        "endpoints": state["endpoints"].clone(),
                        "instances": state["instances"].clone(),
                        "providers": state["providers"].clone()
                    }
                }
            }))
            .expect("model_mount receipt replay request");

        let receipt_replay_response = plan_model_mount_read_projection(receipt_replay_request)
            .expect("receipt replay projected from slim Rust context");
        assert_eq!(receipt_replay_response["projection_kind"], "receipt_replay");
        assert_eq!(
            receipt_replay_response["projection"]["receipt"]["id"],
            "receipt-route"
        );
        assert_eq!(
            receipt_replay_response["projection"]["route"]["id"],
            "route.local-first"
        );
        assert_eq!(
            receipt_replay_response["projection"]["projectionWatermark"],
            3
        );

        let workflow_bindings_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "workflow_bindings",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {}
                }
            }))
            .expect("model_mount workflow bindings request");

        let workflow_bindings_response =
            plan_model_mount_read_projection(workflow_bindings_request)
                .expect("workflow bindings projected in Rust");
        assert_eq!(
            workflow_bindings_response["projection_kind"],
            "workflow_bindings"
        );
        assert_eq!(
            workflow_bindings_response["projection"][9]["daemonApi"],
            "/api/v1/workflows/receipt-gate"
        );

        let adapter_boundaries_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "adapter_boundaries",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "wallet": {"port": "WalletAuthorityPort"},
                        "vault": {"port": "VaultPort"},
                        "agentgres_store": {"port": "AgentgresStorePort"}
                    }
                }
            }))
            .expect("model_mount adapter boundaries request");

        let adapter_boundaries_response =
            plan_model_mount_read_projection(adapter_boundaries_request)
                .expect("adapter boundaries projected in Rust");
        assert_eq!(
            adapter_boundaries_response["projection_kind"],
            "adapter_boundaries"
        );
        assert_eq!(
            adapter_boundaries_response["projection"]["agentgres"]["port"],
            "AgentgresStorePort"
        );
        assert_eq!(
            adapter_boundaries_response["projection"]["oauth"]["plaintextPersistence"],
            false
        );

        let server_status_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "server_status",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "server": {
                            "schemaVersion": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                            "status": "running",
                            "gatewayStatus": "running",
                            "nativeBaseUrl": "http://127.0.0.1:3200/api/v1",
                            "openAiCompatibleBaseUrl": "http://127.0.0.1:3200/v1"
                        }
                    }
                }
            }))
            .expect("model_mount server status request");
        let server_status_response = plan_model_mount_read_projection(server_status_request)
            .expect("server status projected in Rust");
        assert_eq!(server_status_response["projection_kind"], "server_status");
        assert_eq!(server_status_response["projection"]["status"], "running");
        assert_eq!(
            server_status_response["projection"]["nativeBaseUrl"],
            "http://127.0.0.1:3200/api/v1"
        );

        let runtime_engines_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "runtime_engines",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "runtime_engines": [{
                            "id": "backend.llama-cpp",
                            "kind": "llama_cpp",
                            "status": "configured"
                        }]
                    }
                }
            }))
            .expect("model_mount runtime engines request");
        let runtime_engines_response = plan_model_mount_read_projection(runtime_engines_request)
            .expect("runtime engines projected in Rust");
        assert_eq!(
            runtime_engines_response["projection_kind"],
            "runtime_engines"
        );
        assert_eq!(
            runtime_engines_response["projection"][0]["id"],
            "backend.llama-cpp"
        );

        let runtime_profiles_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "runtime_engine_profiles",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "runtime_engine_profiles": [{
                            "id": "backend.llama-cpp",
                            "defaultLoadOptions": {"gpu": "auto"}
                        }]
                    }
                }
            }))
            .expect("model_mount runtime engine profiles request");
        let runtime_profiles_response = plan_model_mount_read_projection(runtime_profiles_request)
            .expect("runtime engine profiles projected in Rust");
        assert_eq!(
            runtime_profiles_response["projection_kind"],
            "runtime_engine_profiles"
        );
        assert_eq!(
            runtime_profiles_response["projection"][0]["defaultLoadOptions"]["gpu"],
            "auto"
        );

        let runtime_preference_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "runtime_preference",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "runtime_preference": {
                            "selectedEngineId": "backend.llama-cpp"
                        }
                    }
                }
            }))
            .expect("model_mount runtime preference request");
        let runtime_preference_response =
            plan_model_mount_read_projection(runtime_preference_request)
                .expect("runtime preference projected in Rust");
        assert_eq!(
            runtime_preference_response["projection"]["selectedEngineId"],
            "backend.llama-cpp"
        );

        let runtime_endpoint_preference_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "runtime_preference_for_endpoint",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "runtime_preference": {
                            "selectedEngineId": "backend.llama-cpp",
                            "endpointBackendId": "backend.llama-cpp"
                        }
                    }
                }
            }))
            .expect("model_mount endpoint runtime preference request");
        let runtime_endpoint_preference_response =
            plan_model_mount_read_projection(runtime_endpoint_preference_request)
                .expect("endpoint runtime preference projected in Rust");
        assert_eq!(
            runtime_endpoint_preference_response["projection"]["endpointBackendId"],
            "backend.llama-cpp"
        );

        let runtime_default_load_options_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "runtime_default_load_options",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "engine_id": "backend.llama-cpp",
                    "state": {
                        "default_load_options": {
                            "gpu": "auto"
                        }
                    }
                }
            }))
            .expect("model_mount runtime default load options request");
        let runtime_default_load_options_response =
            plan_model_mount_read_projection(runtime_default_load_options_request)
                .expect("runtime default load options projected in Rust");
        assert_eq!(
            runtime_default_load_options_response["projection"]["gpu"],
            "auto"
        );

        let runtime_engine_detail_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "runtime_engine_detail",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "engine_id": "backend.llama-cpp",
                    "state": {
                        "runtime_engine": {
                            "id": "backend.llama-cpp",
                            "profile": {"id": "backend.llama-cpp"},
                            "latestReceipts": [{"id": "receipt-runtime"}]
                        }
                    }
                }
            }))
            .expect("model_mount runtime engine detail request");
        let runtime_engine_detail_response =
            plan_model_mount_read_projection(runtime_engine_detail_request)
                .expect("runtime engine detail projected in Rust");
        assert_eq!(
            runtime_engine_detail_response["projection"]["id"],
            "backend.llama-cpp"
        );
        assert_eq!(
            runtime_engine_detail_response["projection"]["latestReceipts"][0]["id"],
            "receipt-runtime"
        );

        let missing_runtime_engine_detail_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "runtime_engine_detail",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "engine_id": "backend.missing",
                    "state": {
                        "runtime_engine": null
                    }
                }
            }))
            .expect("missing model_mount runtime engine detail request");
        let missing_runtime_engine_detail_error =
            plan_model_mount_read_projection(missing_runtime_engine_detail_request)
                .expect_err("runtime engine detail fails closed when engine is missing");
        assert_eq!(
            missing_runtime_engine_detail_error.code,
            "model_mount_runtime_engine_not_found"
        );

        let latest_runtime_survey_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "latest_runtime_survey",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "receipts": [],
                        "runtime_survey_default": {
                            "status": "not_checked",
                            "receiptId": "none",
                            "engineCount": 1,
                            "hardware": {"cpuCount": 8},
                            "runtimePreference": {"selectedEngineId": "backend.llama-cpp"},
                            "lmStudio": {"status": "not_checked"}
                        }
                    }
                }
            }))
            .expect("model_mount latest runtime survey request");
        let latest_runtime_survey_response =
            plan_model_mount_read_projection(latest_runtime_survey_request)
                .expect("latest runtime survey default projected in Rust");
        assert_eq!(
            latest_runtime_survey_response["projection_kind"],
            "latest_runtime_survey"
        );
        assert_eq!(
            latest_runtime_survey_response["projection"]["status"],
            "not_checked"
        );
        assert_eq!(
            latest_runtime_survey_response["projection"]["runtimePreference"]["selectedEngineId"],
            "backend.llama-cpp"
        );

        let checked_runtime_survey_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "latest_runtime_survey",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": {
                        "runtime_survey_default": {
                            "status": "not_checked",
                            "receiptId": "none",
                            "hardware": {"cpuCount": 8},
                            "runtimePreference": {"selectedEngineId": "backend.llama-cpp"}
                        },
                        "receipts": [{
                            "id": "receipt-runtime-survey",
                            "kind": "runtime_survey",
                            "createdAt": "2026-06-08T00:03:00.000Z",
                            "details": {
                                "checked_at": "2026-06-08T00:03:00.000Z",
                                "engine_count": 1,
                                "selected_engines": ["backend.llama-cpp"],
                                "runtime_preference": {"selectedEngineId": "backend.llama-cpp"},
                                "hardware": {"cpuCount": 16},
                                "lm_studio": {"status": "available"}
                            }
                        }]
                    }
                }
            }))
            .expect("checked model_mount latest runtime survey request");
        let checked_runtime_survey_response =
            plan_model_mount_read_projection(checked_runtime_survey_request)
                .expect("latest runtime survey receipt projected in Rust");
        assert_eq!(
            checked_runtime_survey_response["projection"]["receiptId"],
            "receipt-runtime-survey"
        );
        assert_eq!(
            checked_runtime_survey_response["projection"]["selectedEngines"][0],
            "backend.llama-cpp"
        );
        assert_eq!(
            checked_runtime_survey_response["projection"]["hardware"]["cpuCount"],
            16
        );

        let snapshot_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "snapshot",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": state
                }
            }))
            .expect("model_mount snapshot bridge request");

        let snapshot_response = plan_model_mount_read_projection(snapshot_request)
            .expect("snapshot projection planned in Rust");

        assert_eq!(snapshot_response["projection_kind"], "snapshot");
        assert_eq!(
            snapshot_response["projection"]["projection"]["source"],
            "agentgres_model_mounting_projection"
        );
        assert_eq!(
            snapshot_response["projection"]["projection"]["watermark"],
            3
        );
        assert_eq!(
            snapshot_response["projection"]["projection"]["receiptCount"],
            3
        );
        assert_eq!(
            snapshot_response["projection"]["adapterBoundaries"]["agentgres"]["port"],
            "AgentgresStorePort"
        );
        assert_eq!(
            snapshot_response["projection"]["workflowNodes"]
                .as_array()
                .expect("snapshot workflow nodes")
                .len(),
            10
        );
        assert!(snapshot_response["projection"]
            .get("workflow_bindings")
            .is_none());

        let provider_health_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "latest_provider_health",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "provider_id": "provider.local",
                    "state": state_with_health.clone()
                }
            }))
            .expect("model_mount latest provider health request");

        let provider_health_response = plan_model_mount_read_projection(provider_health_request)
            .expect("latest provider health projected in Rust");

        assert_eq!(
            provider_health_response["projection_kind"],
            "latest_provider_health"
        );
        assert_eq!(
            provider_health_response["projection"]["receipt"]["id"],
            "receipt-provider-health"
        );
        assert_eq!(
            provider_health_response["projection"]["replay"]["receipt"]["id"],
            "receipt-provider-health"
        );

        let mut missing_provider_state = state_with_health.clone();
        missing_provider_state["providers"] = json!([]);
        let missing_provider_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "latest_provider_health",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "provider_id": "provider.local",
                    "state": missing_provider_state
                }
            }))
            .expect("missing provider latest health request");
        let missing_provider_error = plan_model_mount_read_projection(missing_provider_request)
            .expect_err("latest provider health fails closed when provider is missing");
        assert_eq!(
            missing_provider_error.code,
            "model_mount_provider_not_found"
        );

        let vault_health_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "latest_vault_health",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": state_with_health.clone()
                }
            }))
            .expect("model_mount latest vault health request");

        let vault_health_response = plan_model_mount_read_projection(vault_health_request)
            .expect("latest vault health projected in Rust");

        assert_eq!(
            vault_health_response["projection_kind"],
            "latest_vault_health"
        );
        assert_eq!(
            vault_health_response["projection"]["receipt"]["id"],
            "receipt-vault-health"
        );
        assert_eq!(
            vault_health_response["projection"]["replay"]["receipt"]["id"],
            "receipt-vault-health"
        );

        let mut missing_vault_health_state = state_with_health;
        missing_vault_health_state["receipts"] = json!([]);
        let missing_vault_health_request: ModelMountReadProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_read_projection",
                "backend": "rust_model_mount_read_projection",
                "request": {
                    "projection_kind": "latest_vault_health",
                    "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                    "generated_at": "2026-06-08T00:00:00.000Z",
                    "state": missing_vault_health_state
                }
            }))
            .expect("missing vault health request");
        let missing_vault_health_error =
            plan_model_mount_read_projection(missing_vault_health_request)
                .expect_err("latest vault health fails closed when health receipt is missing");
        assert_eq!(
            missing_vault_health_error.code,
            "model_mount_vault_health_not_found"
        );
    }

    #[test]
    fn bridge_plans_local_model_mount_provider_inventory_through_rust_core() {
        let request: ModelMountProviderInventoryBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_provider_inventory",
            "backend": "rust_model_mount_native_local_inventory",
            "request": {
                "schema_version": "ioi.model_mount.provider_inventory.v1",
                "provider_ref": "provider.autopilot.local",
                "provider_kind": "ioi_native_local",
                "action": "list_loaded",
                "execution_backend": "rust_model_mount_native_local_inventory",
                "api_format": "ioi_native",
                "driver": "native_local",
                "backend_ref": "backend.autopilot.native-local.fixture",
                "item_refs": ["model_instance://native/qwen3"],
                "evidence_refs": ["daemon_native_local_list_loaded_request"]
            }
        }))
        .expect("native-local inventory bridge request");

        let response =
            plan_model_mount_provider_inventory(request).expect("inventory planned in Rust");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_inventory_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_native_local_inventory"
        );
        assert_eq!(response["status"], "listed");
        assert_eq!(
            response["backend_id"],
            "backend.autopilot.native-local.fixture"
        );
        assert_eq!(
            response["provider_backend"],
            "autopilot.native_local.fixture"
        );
        assert_eq!(response["driver"], "native_local");
        assert_eq!(response["item_count"], 1);
        assert!(response.get("backendId").is_none());
        assert!(response.get("providerBackend").is_none());
        assert!(response.get("itemRefs").is_none());
        assert!(response.get("itemCount").is_none());
        assert!(response["inventory_hash"]
            .as_str()
            .expect("inventory hash")
            .starts_with("sha256:"));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_native_local_inventory_backend"));
    }

    #[test]
    fn bridge_plans_model_mount_instance_lifecycle_through_rust_core() {
        let request: ModelMountInstanceLifecycleBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_instance_lifecycle",
            "backend": "rust_model_mount_instance_lifecycle",
            "request": {
                "schema_version": "ioi.model_mount.instance_lifecycle.v1",
                "instance_ref": "model_instance://native/qwen3",
                "endpoint_ref": "endpoint.native-local",
                "model_ref": "model://qwen/qwen3.5-9b",
                "provider_ref": "provider.autopilot.local",
                "action": "load",
                "target_status": "loaded",
                "execution_backend": "rust_model_mount_instance_lifecycle",
                "backend_ref": "backend.autopilot.native-local.fixture",
                "driver": "native_local",
                "provider_lifecycle_hash": "sha256:provider-lifecycle",
                "evidence_refs": ["rust_model_mount_provider_lifecycle"]
            }
        }))
        .expect("instance lifecycle bridge request");

        let response =
            plan_model_mount_instance_lifecycle(request).expect("instance lifecycle planned");

        assert_eq!(
            response["source"],
            "rust_model_mount_instance_lifecycle_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_instance_lifecycle");
        assert_eq!(response["status"], "loaded");
        assert_eq!(
            response["backendId"],
            "backend.autopilot.native-local.fixture"
        );
        assert_eq!(response["driver"], "native_local");
        assert_eq!(
            response["provider_lifecycle_hash"],
            "sha256:provider-lifecycle"
        );
        assert!(response.get("providerLifecycleHash").is_none());
        assert!(response["instance_lifecycle_hash"]
            .as_str()
            .expect("instance lifecycle hash")
            .starts_with("sha256:"));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_model_mount_instance_lifecycle"));
    }

    #[test]
    fn bridge_admits_model_mount_provider_result_through_rust_core() {
        let provider_execution_request: ModelMountProviderExecutionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "admit_model_mount_provider_execution",
                "backend": "rust_model_mount_live",
                "request": {
                    "schema_version": "ioi.model_mount.provider_execution.v1",
                    "invocation_ref": "model-provider-execution://response/test",
                    "route_decision_ref": "model_mount://route_decision/test",
                    "route_receipt_ref": "receipt://route/test",
                    "route_ref": "route.local-first",
                    "provider_ref": "provider.openai",
                    "endpoint_ref": "endpoint.openai",
                    "model_ref": "model.openai",
                    "capability": "chat",
                    "invocation_kind": "chat.completions",
                    "policy_hash": "sha256:policy",
                    "input_hash": "sha256:input",
                    "request_hash": "sha256:request",
                    "idempotency_key": "model_provider_execution:test",
                    "receipt_refs": ["receipt://route/test"],
                    "authority_grant_refs": ["grant://wallet/model-chat"],
                    "authority_receipt_refs": ["receipt://wallet/model-chat"],
                    "provider_auth_evidence_refs": [],
                    "backend_evidence_refs": ["backend.openai-compatible"],
                    "tool_receipt_refs": [],
                    "privacy_profile": "local_private",
                    "node_plaintext_allowed": false
                }
            }))
            .expect("provider execution request");
        let admission_response =
            admit_model_mount_provider_execution(provider_execution_request).expect("admitted");
        let admission = admission_response["record"].clone();
        let provider_execution_ref = admission["provider_execution_ref"]
            .as_str()
            .expect("provider execution ref");
        let provider_execution_hash = admission["provider_execution_hash"]
            .as_str()
            .expect("provider execution hash");
        let output_text = "hosted provider answer";
        let output_hash = format!(
            "sha256:{}",
            sha256_hex(output_text.as_bytes()).expect("output hash")
        );

        let request: ModelMountProviderResultAdmissionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "admit_model_mount_provider_result",
                "backend": "rust_model_mount_live",
                "request": {
                    "schema_version": "ioi.model_mount.provider_result.v1",
                    "provider_execution_ref": provider_execution_ref,
                    "provider_execution_hash": provider_execution_hash,
                    "route_decision_ref": "model_mount://route_decision/test",
                    "route_receipt_ref": "receipt://route/test",
                    "route_ref": "route.local-first",
                    "provider_ref": "provider.openai",
                    "provider_kind": "openai",
                    "endpoint_ref": "endpoint.openai",
                    "model_ref": "model.openai",
                    "capability": "chat",
                    "invocation_kind": "chat.completions",
                    "request_hash": "sha256:request",
                    "output_text": output_text,
                    "output_hash": output_hash,
                    "token_count": { "prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3 },
                    "provider_response_kind": "openai.chat",
                    "execution_backend": "js_provider_driver_observation",
                    "backend_ref": "backend.openai-compatible",
                    "receipt_refs": ["receipt://route/test"],
                    "provider_auth_evidence_refs": ["provider.auth"],
                    "backend_evidence_refs": ["backend.openai-compatible"],
                    "evidence_refs": [provider_execution_ref],
                    "admitted_provider_execution": admission.clone()
                }
            }))
            .expect("provider result bridge request");

        let response = admit_model_mount_provider_result(request).expect("result admitted");

        assert_eq!(
            response["source"],
            "rust_model_mount_provider_result_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_live");
        assert_eq!(
            response["record"]["execution_backend"],
            "js_provider_driver_observation"
        );
        assert_eq!(response["record"]["output_hash"], output_hash);
        assert!(response["provider_result_ref"]
            .as_str()
            .expect("provider result ref")
            .starts_with("model_mount://provider_result/"));
        assert!(response["provider_result_hash"]
            .as_str()
            .expect("provider result hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn bridge_binds_model_mount_invocation_receipt_through_rust_core() {
        let accepted_receipt_transition = ModelMountCore
            .plan_accepted_receipt_transition(&ModelMountAcceptedReceiptTransitionRequest {
                schema_version: "ioi.model_mount.accepted_receipt_transition.v1".to_string(),
                current_sequence: 0,
                current_head_ref: "agentgres://model-mounting/accepted-receipts/head/0".to_string(),
                current_state_root: "sha256:state-0".to_string(),
                receipt_id: "receipt.test".to_string(),
                receipt_kind: "model_invocation".to_string(),
                route_decision_ref: Some("model_mount://route_decision/test".to_string()),
                invocation_admission_ref: Some(
                    "model_mount://invocation_admission/test".to_string(),
                ),
                invocation_admission_hash: Some("sha256:admission".to_string()),
                input_hash: Some("sha256:input".to_string()),
                output_hash: None,
            })
            .expect("accepted receipt transition planned");
        let request: ModelMountInvocationReceiptBindingBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "bind_model_mount_invocation_receipt",
                "backend": "rust_model_mount_live",
                "invocation": {
                    "schema_version": "ioi.step_module_invocation.v1",
                    "invocation_id": "model-invocation://receipt.test",
                    "run_id": "run:model-mount",
                    "task_id": "task:model-mount",
                    "thread_id": null,
                    "workflow_graph_id": "workflow.graph",
                    "workflow_node_id": "workflow.node",
                    "context_chamber_ref": null,
                    "action_proposal_ref": "action:model-mount:receipt.test",
                    "gate_result_ref": "gate:model-mount:receipt.test",
                    "module_ref": {
                        "kind": "model_mount",
                        "id": "chat:route.local-first:endpoint.local",
                        "version": "migration",
                        "manifest_ref": null
                    },
                    "actor": {
                        "actor_id": "runtime:hypervisor-daemon",
                        "runtime_node_ref": "node://local"
                    },
                    "authority": {
                        "authority_grant_refs": ["grant://wallet/model-chat"],
                        "policy_hash": "sha256:policy",
                        "primitive_capabilities": ["model:chat"],
                        "authority_scopes": [],
                        "approval_ref": null
                    },
                    "input": {
                        "input_hash": "sha256:input",
                        "expected_schema_ref": "schema://model-mount/chat/input",
                        "context_refs": [
                            "model_mount://route_decision/test",
                            "receipt://route/test"
                        ],
                        "artifact_refs": [],
                        "payload_refs": [],
                        "state_root_before": accepted_receipt_transition.state_root_before.clone(),
                        "projection_watermark": "model-mounting-accepted-receipts:0",
                        "data_plane_handle": null
                    },
                    "custody": {
                        "privacy_profile": "internal",
                        "plaintext_policy": {
                            "node_plaintext_allowed": false,
                            "declassification_required": false
                        },
                        "custody_proof_ref": null,
                        "leakage_profile_ref": null
                    },
                    "execution": {
                        "backend": "model_mount",
                        "idempotency_key": "model_invocation:receipt.test",
                        "deadline_ms": 300000,
                        "resource_lease_ref": null,
                        "retry_policy_ref": null
                    }
                },
                "result": {
                    "schema_version": "ioi.step_module_result.v1",
                    "invocation_id": "model-invocation://receipt.test",
                    "status": "success",
                    "execution_result_ref": "result://model-mount/receipt.test",
                    "normalized_observation_ref": "observation://model-mount/receipt.test",
                    "receipt_refs": ["receipt://receipt.test"],
                    "artifact_refs": [],
                    "payload_refs": [],
                    "agentgres_operation_refs": [accepted_receipt_transition.operation_ref.clone()],
                    "state_root_after": accepted_receipt_transition.state_root_after.clone(),
                    "resulting_head": accepted_receipt_transition.resulting_head.clone(),
                    "workflow_projection": {
                        "workflow_graph_id": "workflow.graph",
                        "workflow_node_id": "workflow.node",
                        "component_kind": "ModelInvocationNode",
                        "status": "live",
                        "attempt_id": "attempt://model-mount/receipt.test",
                        "evidence_refs": ["model_mount://invocation_admission/test"],
                        "receipt_refs": ["receipt://receipt.test"]
                    },
                    "next": {
                        "model_reentry_required": false,
                        "verifier_required": false
                    }
                },
                "accepted_receipt_transition": accepted_receipt_transition.clone(),
                "receipt_ref": "receipt://receipt.test"
            }))
            .expect("bridge request");

        let response = bind_model_mount_invocation_receipt(request).expect("receipt bound");

        assert_eq!(
            response["source"],
            "rust_model_mount_receipt_binding_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_live");
        assert_eq!(response["router_admission"]["backend"], "model_mount");
        assert_eq!(
            response["accepted_receipt_append"]["receipt_ref"],
            "receipt://receipt.test"
        );
        assert_eq!(
            response["projection_record"]["component_kind"],
            "ModelInvocationNode"
        );
        assert_eq!(
            response["receipt_binding"]["receipt_refs"][0],
            "receipt://receipt.test"
        );
        assert_eq!(
            response["receipt_binding"]["expected_heads"][0],
            "agentgres://model-mounting/accepted-receipts/head/0"
        );
        assert_eq!(
            response["agentgres_admission"]["operation_ref"],
            "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation"
        );
    }

    #[test]
    fn bridge_executes_private_workspace_ctee_action_through_rust_core() {
        let request: CteePrivateWorkspaceBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "execute_private_workspace_ctee_action",
            "backend": "ctee_operator",
            "invocation": {
                "schema_version": "ioi.step_module_invocation.v1",
                "invocation_id": "invocation://ctee.bridge.test",
                "run_id": "run:ctee",
                "task_id": "task:ctee",
                "thread_id": "thread:ctee",
                "workflow_graph_id": "workflow.ctee",
                "workflow_node_id": "node.ctee.private-workspace",
                "context_chamber_ref": "chamber:ctee",
                "action_proposal_ref": "action:ctee:private-workspace",
                "gate_result_ref": "gate:ctee:private-workspace",
                "module_ref": {
                    "kind": "private_workspace_ctee_action",
                    "id": "private_workspace.mount",
                    "version": "1",
                    "manifest_ref": "module://ctee/private-workspace@1"
                },
                "actor": {
                    "actor_id": "runtime:hypervisor-daemon",
                    "runtime_node_ref": "node://private-workspace"
                },
                "authority": {
                    "authority_grant_refs": ["grant://ctee/private-workspace"],
                    "policy_hash": "sha256:ctee-policy",
                    "primitive_capabilities": ["prim:private_workspace.mount"],
                    "authority_scopes": ["scope:ctee.private_workspace"],
                    "approval_ref": "approval://declassify"
                },
                "input": {
                    "input_hash": "sha256:ctee-input",
                    "expected_schema_ref": "schema://ctee/private-workspace/input",
                    "context_refs": ["ctx://redacted"],
                    "artifact_refs": ["artifact://encrypted-capsule"],
                    "payload_refs": ["payload://sealed-private-workspace"],
                    "state_root_before": "sha256:ctee-before",
                    "projection_watermark": "agentgres:ctee:0",
                    "data_plane_handle": null
                },
                "custody": {
                    "privacy_profile": "private_workspace_ctee",
                    "plaintext_policy": {
                        "node_plaintext_allowed": false,
                        "declassification_required": true
                    },
                    "custody_proof_ref": "artifact://custody-proof",
                    "leakage_profile_ref": "artifact://leakage-profile"
                },
                "execution": {
                    "backend": "ctee_operator",
                    "idempotency_key": "idem:ctee.bridge",
                    "deadline_ms": 300000,
                    "resource_lease_ref": "lease://ctee",
                    "retry_policy_ref": null
                }
            },
            "node_trust": {
                "runtime_node_ref": "node://rented-untrusted",
                "trusted_for_plaintext": false,
                "attestation_ref": null
            }
        }))
        .expect("ctee bridge request");

        let response =
            execute_private_workspace_ctee_action(request).expect("ctee action executed");

        assert_eq!(response["source"], "rust_ctee_private_workspace_command");
        assert_eq!(response["backend"], "ctee_operator");
        assert_eq!(response["result"]["status"], "success");
        assert_eq!(
            response["receipt"]["custody_proof_ref"],
            "artifact://custody-proof"
        );
        assert_eq!(
            response["receipt_binding"]["expected_heads"][0],
            "agentgres://ctee/private-workspace/head/current"
        );
        assert_eq!(
            response["accepted_receipt_append"]["receipt_ref"],
            response["receipt"]["receipt_ref"]
        );
        assert_eq!(
            response["agentgres_admission"]["operation_ref"],
            response["result"]["agentgres_operation_refs"][0]
        );
        assert_eq!(
            response["projection_record"]["component_kind"],
            "PrivateWorkspaceCteeAction"
        );
        assert_eq!(response["projection_record"]["status"], "live");
    }

    #[test]
    fn ctee_private_workspace_rejects_step_module_command_schema() {
        let request: CteePrivateWorkspaceBridgeRequest = serde_json::from_value(json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "execute_private_workspace_ctee_action",
            "backend": "ctee_operator",
            "invocation": {
                "schema_version": "ioi.step_module_invocation.v1",
                "invocation_id": "invocation://ctee.bridge.test",
                "run_id": "run:ctee",
                "task_id": "task:ctee",
                "thread_id": "thread:ctee",
                "workflow_graph_id": "workflow.ctee",
                "workflow_node_id": "node.ctee.private-workspace",
                "context_chamber_ref": "chamber:ctee",
                "action_proposal_ref": "action:ctee:private-workspace",
                "gate_result_ref": "gate:ctee:private-workspace",
                "module_ref": {
                    "kind": "private_workspace_ctee_action",
                    "id": "private_workspace.mount",
                    "version": "1",
                    "manifest_ref": "module://ctee/private-workspace@1"
                },
                "actor": {
                    "actor_id": "runtime:hypervisor-daemon",
                    "runtime_node_ref": "node://private-workspace"
                },
                "authority": {
                    "authority_grant_refs": ["grant://ctee/private-workspace"],
                    "policy_hash": "sha256:ctee-policy",
                    "primitive_capabilities": ["prim:private_workspace.mount"],
                    "authority_scopes": ["scope:ctee.private_workspace"],
                    "approval_ref": "approval://declassify"
                },
                "input": {
                    "input_hash": "sha256:ctee-input",
                    "expected_schema_ref": "schema://ctee/private-workspace/input",
                    "context_refs": ["ctx://redacted"],
                    "artifact_refs": ["artifact://encrypted-capsule"],
                    "payload_refs": ["payload://sealed-private-workspace"],
                    "state_root_before": "sha256:ctee-before",
                    "projection_watermark": "agentgres:ctee:0",
                    "data_plane_handle": null
                },
                "custody": {
                    "privacy_profile": "private_workspace_ctee",
                    "plaintext_policy": {
                        "node_plaintext_allowed": false,
                        "declassification_required": true
                    },
                    "custody_proof_ref": "artifact://custody-proof",
                    "leakage_profile_ref": "artifact://leakage-profile"
                },
                "execution": {
                    "backend": "ctee_operator",
                    "idempotency_key": "idem:ctee.bridge",
                    "deadline_ms": 300000,
                    "resource_lease_ref": "lease://ctee",
                    "retry_policy_ref": null
                }
            },
            "node_trust": {
                "runtime_node_ref": "node://rented-untrusted",
                "trusted_for_plaintext": false,
                "attestation_ref": null
            }
        }))
        .expect("ctee bridge request");

        let error = execute_private_workspace_ctee_action(request)
            .expect_err("daemon-core cTEE custody rejects StepModule command schema");

        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_admits_worker_service_package_invocation_through_rust_core() {
        let request: WorkerServicePackageInvocationBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "admit_worker_service_package_invocation",
                "backend": "rust_package_invocation",
                "request": {
                    "schema_version": "ioi.worker_service_package_invocation.v1",
                    "package_kind": "worker_package",
                    "package_ref": "worker://runtime-auditor",
                    "manifest_ref": "worker://runtime-auditor@1",
                    "invocation": {
                        "schema_version": "ioi.step_module_invocation.v1",
                        "invocation_id": "invocation://worker-package/bridge",
                        "run_id": "run:worker-package",
                        "task_id": "task:worker-package",
                        "thread_id": "thread:worker-package",
                        "workflow_graph_id": "workflow.worker-package",
                        "workflow_node_id": "node.worker-package",
                        "context_chamber_ref": null,
                        "action_proposal_ref": "action:worker-package",
                        "gate_result_ref": "gate:worker-package",
                        "module_ref": {
                            "kind": "workload_job",
                            "id": "worker://runtime-auditor",
                            "version": "1",
                            "manifest_ref": "worker://runtime-auditor@1"
                        },
                        "actor": {
                            "actor_id": "runtime:hypervisor-daemon",
                            "runtime_node_ref": "node://local"
                        },
                        "authority": {
                            "authority_grant_refs": ["grant://wallet/worker-package"],
                            "policy_hash": "sha256:worker-policy",
                            "primitive_capabilities": ["prim:worker.invoke"],
                            "authority_scopes": ["scope:repo.read"],
                            "approval_ref": "approval://worker-package"
                        },
                        "input": {
                            "input_hash": "sha256:worker-input",
                            "expected_schema_ref": "schema://worker-package/runtime-auditor/input",
                            "context_refs": ["agentgres://project/hypervisor"],
                            "artifact_refs": [],
                            "payload_refs": ["payload://worker-package/input"],
                            "state_root_before": "sha256:package-before",
                            "projection_watermark": "agentgres:worker-package:0",
                            "data_plane_handle": null
                        },
                        "custody": {
                            "privacy_profile": "internal",
                            "plaintext_policy": {
                                "node_plaintext_allowed": true,
                                "declassification_required": false
                            },
                            "custody_proof_ref": null,
                            "leakage_profile_ref": null
                        },
                        "execution": {
                            "backend": "workload_grpc",
                            "idempotency_key": "idem:worker-package-bridge",
                            "deadline_ms": 300000,
                            "resource_lease_ref": "lease://worker-package",
                            "retry_policy_ref": null
                        }
                    },
                    "result": {
                        "schema_version": "ioi.step_module_result.v1",
                        "invocation_id": "invocation://worker-package/bridge",
                        "status": "success",
                        "execution_result_ref": "result://worker-package/bridge",
                        "normalized_observation_ref": "observation://worker-package/bridge",
                        "receipt_refs": ["receipt://worker-package/bridge"],
                        "artifact_refs": ["artifact://worker-package/report"],
                        "payload_refs": ["payload://worker-package/output"],
                        "agentgres_operation_refs": ["agentgres://worker-service-package/operations/bridge"],
                        "state_root_after": "sha256:package-after",
                        "resulting_head": "agentgres://worker-service-package/head/bridge",
                        "workflow_projection": {
                            "workflow_graph_id": "workflow.worker-package",
                            "workflow_node_id": "node.worker-package",
                            "component_kind": "WorkerPackageNode",
                            "status": "live",
                            "attempt_id": "attempt://worker-package/bridge",
                            "evidence_refs": ["artifact://worker-package/report"],
                            "receipt_refs": ["receipt://worker-package/bridge"]
                        },
                        "next": {
                            "model_reentry_required": false,
                            "verifier_required": true
                        }
                    }
                }
            }))
            .expect("worker package bridge request");

        let response = admit_worker_service_package_invocation(request)
            .expect("worker package invocation admitted");

        assert_eq!(
            response["source"],
            "rust_worker_service_package_invocation_command"
        );
        assert_eq!(response["backend"], "rust_package_invocation");
        assert_eq!(response["record"]["package_kind"], "worker_package");
        assert_eq!(response["router_admission"]["backend"], "workload_grpc");
        assert_eq!(
            response["accepted_receipt_append"]["receipt_ref"],
            "receipt://worker-package/bridge"
        );
        assert_eq!(
            response["agentgres_admission"]["operation_ref"],
            "agentgres://worker-service-package/operations/bridge"
        );
        assert_eq!(
            response["receipt_binding"]["expected_heads"][0],
            "agentgres://worker-service-package/head/current"
        );
        assert_eq!(
            response["projection_record"]["component_kind"],
            "WorkerPackageNode"
        );
        assert_eq!(
            response["authority_grant_refs"][0],
            "grant://wallet/worker-package"
        );
    }

    #[test]
    fn worker_service_package_rejects_step_module_command_schema() {
        let request: WorkerServicePackageInvocationBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
                "operation": "admit_worker_service_package_invocation",
                "backend": "rust_package_invocation",
                "request": {
                    "schema_version": "ioi.worker_service_package_invocation.v1",
                    "package_kind": "worker_package",
                    "package_ref": "worker://runtime-auditor",
                    "manifest_ref": "worker://runtime-auditor@1",
                    "invocation": {
                        "schema_version": "ioi.step_module_invocation.v1",
                        "invocation_id": "invocation://worker-package/bridge",
                        "run_id": "run:worker-package",
                        "task_id": "task:worker-package",
                        "thread_id": "thread:worker-package",
                        "workflow_graph_id": "workflow.worker-package",
                        "workflow_node_id": "node.worker-package",
                        "context_chamber_ref": null,
                        "action_proposal_ref": "action:worker-package",
                        "gate_result_ref": "gate:worker-package",
                        "module_ref": {
                            "kind": "workload_job",
                            "id": "worker://runtime-auditor",
                            "version": "1",
                            "manifest_ref": "worker://runtime-auditor@1"
                        },
                        "actor": {
                            "actor_id": "runtime:hypervisor-daemon",
                            "runtime_node_ref": "node://local"
                        },
                        "authority": {
                            "authority_grant_refs": ["grant://wallet/worker-package"],
                            "policy_hash": "sha256:worker-policy",
                            "primitive_capabilities": ["prim:worker.invoke"],
                            "authority_scopes": ["scope:repo.read"],
                            "approval_ref": "approval://worker-package"
                        },
                        "input": {
                            "input_hash": "sha256:worker-input",
                            "expected_schema_ref": "schema://worker-package/runtime-auditor/input",
                            "context_refs": ["agentgres://project/hypervisor"],
                            "artifact_refs": [],
                            "payload_refs": ["payload://worker-package/input"],
                            "state_root_before": "sha256:package-before",
                            "projection_watermark": "agentgres:worker-package:0",
                            "data_plane_handle": null
                        },
                        "custody": {
                            "privacy_profile": "internal",
                            "plaintext_policy": {
                                "node_plaintext_allowed": true,
                                "declassification_required": false
                            },
                            "custody_proof_ref": null,
                            "leakage_profile_ref": null
                        },
                        "execution": {
                            "backend": "workload_grpc",
                            "idempotency_key": "idem:worker-package-bridge",
                            "deadline_ms": 300000,
                            "resource_lease_ref": "lease://worker-package",
                            "retry_policy_ref": null
                        }
                    },
                    "result": {
                        "schema_version": "ioi.step_module_result.v1",
                        "invocation_id": "invocation://worker-package/bridge",
                        "status": "success",
                        "execution_result_ref": "result://worker-package/bridge",
                        "normalized_observation_ref": "observation://worker-package/bridge",
                        "receipt_refs": ["receipt://worker-package/bridge"],
                        "artifact_refs": ["artifact://worker-package/report"],
                        "payload_refs": ["payload://worker-package/output"],
                        "agentgres_operation_refs": ["agentgres://worker-service-package/operations/bridge"],
                        "state_root_after": "sha256:package-after",
                        "resulting_head": "agentgres://worker-service-package/head/bridge",
                        "workflow_projection": {
                            "workflow_graph_id": "workflow.worker-package",
                            "workflow_node_id": "node.worker-package",
                            "component_kind": "WorkerPackageNode",
                            "status": "live",
                            "attempt_id": "attempt://worker-package/bridge",
                            "evidence_refs": ["artifact://worker-package/report"],
                            "receipt_refs": ["receipt://worker-package/bridge"]
                        },
                        "next": {
                            "model_reentry_required": false,
                            "verifier_required": true
                        }
                    }
                }
            }))
            .expect("worker package bridge request");

        let error = admit_worker_service_package_invocation(request)
            .expect_err("daemon-core worker/service package rejects StepModule command schema");

        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_admits_l1_settlement_attempt_through_rust_core() {
        let request: L1SettlementAdmissionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_l1_settlement_attempt",
            "backend": "l1_settlement_guard",
            "attempt": {
                "schema_version": "ioi.l1_settlement_admission.v1",
                "settlement_ref": "l1://settlement/marketplace-transaction",
                "domain_ref": "domain://marketplace/services",
                "state_root_ref": "state-root://agentgres/marketplace/after",
                "trigger_refs": ["l1-trigger://service-contract/payment"],
                "receipt_refs": ["receipt://local-settlement/payment"]
            }
        }))
        .expect("L1 settlement bridge request");

        let response = admit_l1_settlement_attempt(request).expect("L1 settlement admitted");

        assert_eq!(response["source"], "rust_l1_settlement_guard_command");
        assert_eq!(response["backend"], "l1_settlement_guard");
        assert_eq!(
            response["settlement_ref"],
            "l1://settlement/marketplace-transaction"
        );
        assert_eq!(
            response["trigger_refs"][0],
            "l1-trigger://service-contract/payment"
        );
        assert_eq!(
            response["record"]["receipt_refs"][0],
            "receipt://local-settlement/payment"
        );
        assert_ne!(response["admission_hash"][0], 0);
    }

    #[test]
    fn l1_settlement_rejects_step_module_command_schema() {
        let request: L1SettlementAdmissionBridgeRequest = serde_json::from_value(json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_l1_settlement_attempt",
            "backend": "l1_settlement_guard",
            "attempt": {
                "schema_version": "ioi.l1_settlement_admission.v1",
                "settlement_ref": "l1://settlement/marketplace-transaction",
                "domain_ref": "domain://marketplace/services",
                "state_root_ref": "state-root://agentgres/marketplace/after",
                "trigger_refs": ["l1-trigger://service-contract/payment"],
                "receipt_refs": ["receipt://local-settlement/payment"]
            }
        }))
        .expect("L1 settlement bridge request");

        let error = admit_l1_settlement_attempt(request)
            .expect_err("daemon-core settlement rejects StepModule command schema");

        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_authorizes_external_capability_exit_through_rust_authority_core() {
        let request: ExternalCapabilityExitAuthorityBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "authorize_external_capability_exit",
            "backend": "rust_authority",
            "request": {
                "schema_version": "ioi.external_capability_exit_authority.v1",
                "exit_ref": "exit://aiip/slack-post-message",
                "capability_ref": "capability://connector/slack.postMessage",
                "target_ref": "aiip://workspace/channel/runtime",
                "policy_hash": "sha256:external-capability-policy",
                "idempotency_key": "idem:external-capability-exit",
                "authority_grant_refs": [
                    "wallet.network://grant/external-capability/slack-post-message"
                ],
                "authority_receipt_refs": [
                    "receipt://wallet.network/authority/slack-post-message"
                ]
            }
        }))
        .expect("external capability exit bridge request");

        let response = authorize_external_capability_exit(request)
            .expect("external capability exit authorized");

        assert_eq!(
            response["source"],
            "rust_external_capability_exit_authority_command"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(
            response["wallet_network_grant_refs"][0],
            "wallet.network://grant/external-capability/slack-post-message"
        );
        assert_eq!(
            response["authority_receipt_refs"][0],
            "receipt://wallet.network/authority/slack-post-message"
        );
        assert!(response["authority_hash"]
            .as_str()
            .expect("authority hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn bridge_rejects_external_capability_exit_without_wallet_network_authority() {
        let request: ExternalCapabilityExitAuthorityBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "authorize_external_capability_exit",
            "request": {
                "schema_version": "ioi.external_capability_exit_authority.v1",
                "exit_ref": "exit://aiip/slack-post-message",
                "capability_ref": "capability://connector/slack.postMessage",
                "target_ref": "aiip://workspace/channel/runtime",
                "policy_hash": "sha256:external-capability-policy",
                "idempotency_key": "idem:external-capability-exit",
                "authority_grant_refs": ["grant://local-debug-only"],
                "authority_receipt_refs": [
                    "receipt://wallet.network/authority/slack-post-message"
                ]
            }
        }))
        .expect("external capability exit bridge request");

        let error = authorize_external_capability_exit(request)
            .expect_err("wallet.network authority is required");

        assert_eq!(error.code, "external_capability_exit_authority_invalid");
        assert!(error.message.contains("MissingWalletNetworkAuthority"));
    }

    #[test]
    fn external_capability_authority_rejects_step_module_command_schema() {
        let request: ExternalCapabilityExitAuthorityBridgeRequest = serde_json::from_value(json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "authorize_external_capability_exit",
            "backend": "rust_authority",
            "request": {
                "schema_version": "ioi.external_capability_exit_authority.v1",
                "exit_ref": "exit://aiip/slack-post-message",
                "capability_ref": "capability://connector/slack.postMessage",
                "target_ref": "aiip://workspace/channel/runtime",
                "policy_hash": "sha256:external-capability-policy",
                "idempotency_key": "idem:external-capability-exit",
                "authority_grant_refs": [
                    "wallet.network://grant/external-capability/slack-post-message"
                ],
                "authority_receipt_refs": [
                    "receipt://wallet.network/authority/slack-post-message"
                ]
            }
        }))
        .expect("external capability exit bridge request");

        let error = authorize_external_capability_exit(request)
            .expect_err("daemon-core authority rejects StepModule command schema");

        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_admits_governed_runtime_improvement_proposal_through_rust_core() {
        let request: GovernedRuntimeImprovementBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_governed_runtime_improvement_proposal",
            "backend": "rust_governed_evolution",
            "proposal": {
                "schema_version": "ioi.governed_runtime_improvement.v1",
                "proposal_id": "proposal://runtime-improvement/bridge",
                "target_ref": "skill://runtime-auditor/current",
                "candidate_ref": "skill-candidate://runtime-auditor/from-trace",
                "surface": "skill",
                "source_trace_ref": "trace://runtime-improvement/high-fitness",
                "eval_receipt_refs": ["receipt://eval/bridge-holdout-pass"],
                "verifier_receipt_refs": ["receipt://verifier/bridge-regression-pass"],
                "approval_ref": "approval://wallet/runtime-improvement/bridge",
                "rollback_ref": "rollback://skill/runtime-auditor/current"
            }
        }))
        .expect("governed runtime improvement bridge request");

        let response = admit_governed_runtime_improvement_proposal(request)
            .expect("governed runtime improvement proposal admitted");

        assert_eq!(response["source"], "rust_governed_meta_improvement_command");
        assert_eq!(response["backend"], "rust_governed_evolution");
        assert_eq!(
            response["record"]["proposal_id"],
            "proposal://runtime-improvement/bridge"
        );
        assert!(response["agentgres_operation_ref"]
            .as_str()
            .expect("operation ref")
            .starts_with("agentgres://runtime-improvement/operations/"));
        assert_eq!(
            response["expected_heads"][0],
            "agentgres://runtime-improvement/head/current"
        );
        assert!(response["state_root_before"]
            .as_str()
            .expect("state root before")
            .starts_with("sha256:"));
        assert!(response["state_root_after"]
            .as_str()
            .expect("state root after")
            .starts_with("sha256:"));
        assert!(response["resulting_head"]
            .as_str()
            .expect("resulting head")
            .starts_with("agentgres://runtime-improvement/head/"));
        assert_eq!(
            response["eval_receipt_refs"][0],
            "receipt://eval/bridge-holdout-pass"
        );
        assert_eq!(
            response["verifier_receipt_refs"][0],
            "receipt://verifier/bridge-regression-pass"
        );
        assert_eq!(
            response["approval_ref"],
            "approval://wallet/runtime-improvement/bridge"
        );
        assert_eq!(
            response["rollback_ref"],
            "rollback://skill/runtime-auditor/current"
        );
        assert!(response["admission_hash"]
            .as_str()
            .expect("admission hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn governed_improvement_rejects_step_module_command_schema() {
        let request: GovernedRuntimeImprovementBridgeRequest = serde_json::from_value(json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_governed_runtime_improvement_proposal",
            "backend": "rust_governed_evolution",
            "proposal": {
                "schema_version": "ioi.governed_runtime_improvement.v1",
                "proposal_id": "proposal://runtime-improvement/retired-schema",
                "target_ref": "skill://runtime-auditor/current",
                "candidate_ref": "skill-candidate://runtime-auditor/from-trace",
                "surface": "skill",
                "source_trace_ref": "trace://runtime-improvement/high-fitness",
                "eval_receipt_refs": ["receipt://eval/bridge-holdout-pass"],
                "verifier_receipt_refs": ["receipt://verifier/bridge-regression-pass"],
                "approval_ref": "approval://wallet/runtime-improvement/bridge",
                "rollback_ref": "rollback://skill/runtime-auditor/current"
            }
        }))
        .expect("governed runtime improvement bridge request");

        let error = admit_governed_runtime_improvement_proposal(request)
            .expect_err("daemon-core governed improvement rejects StepModule command schema");

        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_plans_workspace_restore_apply_policy_through_rust_core() {
        let request: WorkspaceRestoreApplyPolicyBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_workspace_restore_apply_policy",
            "backend": "rust_workspace_restore",
            "request": {
                "schema_version": "ioi.workspace_restore_apply_policy_request.v1",
                "snapshot_id": "workspace_snapshot_alpha",
                "confirm_restore_apply": true,
                "restore_conflict_policy": "override_conflicts",
                "operations": [
                    {
                        "path": "src/app.js",
                        "status": "conflict"
                    }
                ],
                "counts": {
                    "file_count": 1,
                    "conflict_count": 1,
                    "applied_count": 1
                }
            }
        }))
        .expect("workspace restore apply policy bridge request");

        let response = plan_workspace_restore_apply_policy(request)
            .expect("workspace restore apply policy planned");

        assert_eq!(response["source"], "rust_workspace_restore_policy_command");
        assert_eq!(response["backend"], "rust_workspace_restore");
        assert_eq!(response["approval"]["satisfied"], true);
        assert_eq!(response["allow_conflicts"], true);
        assert_eq!(response["conflict_policy"], "override_conflicts");
        assert_eq!(response["apply_status"], "applied");
        assert_eq!(
            response["policy_decision_refs"][1],
            "policy_workspace_restore_apply_workspace_snapshot_alpha_conflict_override"
        );
        assert_eq!(
            response["summary"],
            "Restore apply restored 1 file(s) from workspace_snapshot_alpha with conflict override."
        );
    }

    #[test]
    fn bridge_applies_workspace_restore_operations_through_rust_core() {
        let workspace = temp_workspace("apply");
        let target = workspace.join("src/app.js");
        fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
        fs::write(&target, "new").expect("write current");
        let old_hash = sha256_hex(b"old").expect("old hash");
        let new_hash = sha256_hex(b"new").expect("new hash");
        let request: WorkspaceRestoreOperationsBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "apply_workspace_restore_operations",
            "backend": "rust_workspace_restore",
            "request": {
                "schema_version": "ioi.workspace_restore_apply_operations_request.v1",
                "workspace_root": workspace.to_string_lossy(),
                "max_diff_bytes": 4096,
                "allow_conflicts": false,
                "files": [
                    {
                        "path": "src/app.js",
                        "before": {
                            "exists": true,
                            "content_hash": old_hash,
                            "content": "old"
                        },
                        "after": {
                            "exists": true,
                            "content_hash": new_hash
                        }
                    }
                ]
            }
        }))
        .expect("workspace restore operations bridge request");

        let response = apply_workspace_restore_operations(request)
            .expect("workspace restore operations applied");

        assert_eq!(
            response["source"],
            "rust_workspace_restore_operations_command"
        );
        assert_eq!(response["backend"], "rust_workspace_restore");
        assert_eq!(response["operation"], "apply_workspace_restore_operations");
        assert_eq!(response["operations"][0]["status"], "ready");
        assert_eq!(response["operations"][0]["apply_status"], "applied");
        assert_eq!(fs::read_to_string(&target).expect("restored"), "old");
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn workspace_restore_apply_rejects_step_module_command_schema() {
        let workspace = temp_workspace("apply-retired-schema");
        let target = workspace.join("src/app.js");
        fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
        fs::write(&target, "new").expect("write current");
        let old_hash = sha256_hex(b"old").expect("old hash");
        let new_hash = sha256_hex(b"new").expect("new hash");
        let request: WorkspaceRestoreOperationsBridgeRequest = serde_json::from_value(json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "apply_workspace_restore_operations",
            "backend": "rust_workspace_restore",
            "request": {
                "schema_version": "ioi.workspace_restore_apply_operations_request.v1",
                "workspace_root": workspace.to_string_lossy(),
                "max_diff_bytes": 4096,
                "allow_conflicts": false,
                "files": [
                    {
                        "path": "src/app.js",
                        "before": {
                            "exists": true,
                            "content_hash": old_hash,
                            "content": "old"
                        },
                        "after": {
                            "exists": true,
                            "content_hash": new_hash
                        }
                    }
                ]
            }
        }))
        .expect("workspace restore operations bridge request");

        let error = apply_workspace_restore_operations(request)
            .expect_err("daemon-core workspace restore rejects StepModule command schema");

        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
        assert_eq!(fs::read_to_string(&target).expect("not restored"), "new");
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn bridge_captures_workspace_snapshot_files_through_rust_core() {
        let old_hash = sha256_hex(b"old").expect("old hash");
        let new_hash = sha256_hex(b"new").expect("new hash");
        let request: WorkspaceSnapshotCaptureBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "capture_workspace_snapshot_files",
            "backend": "rust_workspace_restore",
            "request": {
                "schema_version": "ioi.workspace_snapshot_capture_request.v1",
                "max_content_bytes": 262144,
                "changed_files": [
                    {
                        "path": "src/app.js",
                        "before_hash": old_hash,
                        "after_hash": new_hash,
                        "before_exists": true,
                        "after_exists": true,
                        "before_size_bytes": 3,
                        "after_size_bytes": 3
                    }
                ],
                "content_drafts": [
                    {
                        "path": "src/app.js",
                        "before_content": "old",
                        "after_content": "new"
                    }
                ]
            }
        }))
        .expect("workspace snapshot capture bridge request");

        let response =
            capture_workspace_snapshot_files(request).expect("workspace snapshot files captured");

        assert_eq!(
            response["source"],
            "rust_workspace_snapshot_capture_command"
        );
        assert_eq!(response["backend"], "rust_workspace_restore");
        assert_eq!(response["captured_file_count"], 1);
        assert_eq!(response["omitted_file_count"], 0);
        assert_eq!(response["files"][0]["path"], "src/app.js");
        assert_eq!(response["files"][0]["before"]["content"].is_null(), true);
        assert_eq!(response["content_files"][0]["before"]["content"], "old");
    }

    #[test]
    fn bridge_plans_coding_tool_approval_manifest_through_rust_core() {
        let request: CodingToolApprovalBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_coding_tool_approval_manifest",
            "backend": "rust_authority",
            "request": {
                "schema_version": "ioi.runtime.coding-tool-approval-request.v1",
                "thread_id": "thread_approval",
                "turn_id": "turn_approval",
                "tool_id": "file.apply_patch",
                "tool_call_id": "call_approval",
                "effect_class": "workspace_write",
                "risk_domain": "workspace",
                "authority_scope_requirements": ["workspace.write", "workspace.write"],
                "primitive_capabilities": ["fs.write"],
                "thread_mode": "plan",
                "approval_mode": "suggest",
                "trust_profile": "local_private",
                "requested_mode": "agent",
                "normalized_requested_mode": "agent",
                "requested_approval_mode": "human_required",
                "workflow_graph_id": "graph_approval",
                "workflow_node_id": "node_approval",
                "workflow_policy": {
                    "node_approval_override": "inherit",
                    "approval_mode": "human_required",
                    "trust_profile": "restricted",
                    "requires_approval": false
                },
                "input_summary": {
                    "path": "src/app.js",
                    "dryRun": false
                },
                "input": {
                    "path": "src/app.js",
                    "dry_run": false
                }
            }
        }))
        .expect("coding-tool approval bridge request");

        let response = plan_coding_tool_approval_manifest(request)
            .expect("coding-tool approval manifest planned");

        assert_eq!(response["source"], "rust_coding_tool_approval_command");
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["approval_required"], true);
        assert_eq!(
            response["manifest"]["schema_version"],
            "ioi.runtime.coding-tool-approval-manifest.v1"
        );
        assert_eq!(
            response["manifest"]["policy_reason"],
            "thread_plan_mode_requires_approval"
        );
        assert_eq!(
            response["manifest"]["authority_scope_requirements"],
            json!(["workspace.write"])
        );
        assert!(response["input_hash"]
            .as_str()
            .expect("input hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn bridge_plans_approval_request_state_update_through_rust_core() {
        let request: ApprovalRequestStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_approval_request_state_update",
            "backend": "rust_authority",
            "request": {
                "schema_version": "ioi.runtime.approval-request-state-update-request.v1",
                "thread_id": "thread_alpha",
                "run_id": "run_alpha",
                "run": {
                    "id": "run_alpha",
                    "agentId": "agent_alpha",
                    "status": "running",
                    "turnStatus": "running",
                    "trace": {}
                },
                "event_id": "event_approval",
                "seq": 3,
                "created_at": "2026-06-06T04:30:00.000Z",
                "approval_id": "approval_alpha",
                "source": "runtime_auto",
                "reason": "Need permission",
                "receipt_refs": ["receipt_approval"],
                "policy_decision_refs": ["policy_approval"]
            }
        }))
        .expect("approval request state update bridge request");

        let response =
            plan_approval_request_state_update(request).expect("approval state update planned");

        assert_eq!(
            response["source"],
            "rust_approval_request_state_update_command"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "approval.required");
        assert_eq!(
            response["operator_control"]["approval_id"],
            "approval_alpha"
        );
        assert!(response["operator_control"].get("approvalId").is_none());
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("receiptRefs").is_none());
        assert!(response["operator_control"]
            .get("policyDecisionRefs")
            .is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(response["run"]["status"], "blocked");
        assert_eq!(
            response["run"]["trace"]["approvalRequests"][0]["event_id"],
            "event_approval"
        );
    }

    #[test]
    fn bridge_plans_approval_request_agent_state_update_through_rust_core() {
        let request: ApprovalRequestStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_approval_request_state_update",
            "backend": "rust_authority",
            "request": {
                "schema_version": "ioi.runtime.approval-request-state-update-request.v1",
                "target_kind": "agent",
                "thread_id": "thread_alpha",
                "run_id": null,
                "run": null,
                "agent": {
                    "id": "agent_alpha",
                    "cwd": "/workspace/project"
                },
                "event_id": "event_approval",
                "seq": 3,
                "created_at": "2026-06-06T04:30:00.000Z",
                "approval_id": "approval_alpha",
                "source": "runtime_auto",
                "reason": "Need permission",
                "receipt_refs": ["receipt_approval"],
                "policy_decision_refs": ["policy_approval"]
            }
        }))
        .expect("approval request agent state update bridge request");

        let response = plan_approval_request_state_update(request)
            .expect("approval agent state update planned");

        assert_eq!(
            response["source"],
            "rust_approval_request_state_update_command"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "approval.required");
        assert_eq!(response["target_kind"], "agent");
        assert!(response["run"].is_null());
        assert_eq!(response["agent"]["id"], "agent_alpha");
        assert_eq!(response["agent"]["updatedAt"], "2026-06-06T04:30:00.000Z");
    }

    #[test]
    fn bridge_plans_approval_decision_state_update_through_rust_core() {
        let request: ApprovalDecisionStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_approval_decision_state_update",
            "backend": "rust_authority",
            "request": {
                "schema_version": "ioi.runtime.approval-decision-state-update-request.v1",
                "thread_id": "thread_alpha",
                "run_id": "run_alpha",
                "run": {
                    "id": "run_alpha",
                    "agentId": "agent_alpha",
                    "status": "blocked",
                    "turnStatus": "waiting_for_approval",
                    "trace": {}
                },
                "event_id": "event_decision",
                "seq": 4,
                "created_at": "2026-06-06T04:35:00.000Z",
                "approval_id": "approval_alpha",
                "lease_id": "lease_alpha",
                "lease_status": "active",
                "decision": "approve",
                "status": "approved",
                "source": "runtime_auto",
                "reason": "Looks good",
                "receipt_refs": ["receipt_decision"],
                "policy_decision_refs": ["policy_decision"]
            }
        }))
        .expect("approval decision state update bridge request");

        let response =
            plan_approval_decision_state_update(request).expect("approval decision planned");

        assert_eq!(
            response["source"],
            "rust_approval_decision_state_update_command"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "approval.approve");
        assert_eq!(response["operator_control"]["lease_id"], "lease_alpha");
        assert!(response["operator_control"].get("approvalId").is_none());
        assert!(response["operator_control"].get("leaseId").is_none());
        assert!(response["operator_control"].get("leaseStatus").is_none());
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("receiptRefs").is_none());
        assert!(response["operator_control"]
            .get("policyDecisionRefs")
            .is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(
            response["run"]["trace"]["approvalDecisions"][0]["event_id"],
            "event_decision"
        );
    }

    #[test]
    fn bridge_plans_approval_revoke_state_update_through_rust_core() {
        let request: ApprovalRevokeStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_approval_revoke_state_update",
            "backend": "rust_authority",
            "request": {
                "schema_version": "ioi.runtime.approval-revoke-state-update-request.v1",
                "thread_id": "thread_alpha",
                "run_id": "run_alpha",
                "run": {
                    "id": "run_alpha",
                    "agentId": "agent_alpha",
                    "status": "blocked",
                    "turnStatus": "waiting_for_approval",
                    "trace": {}
                },
                "event_id": "event_revoke",
                "seq": 5,
                "created_at": "2026-06-06T04:40:00.000Z",
                "approval_id": "approval_alpha",
                "lease_id": "lease_alpha",
                "source": "runtime_auto",
                "reason": "Changed my mind",
                "receipt_refs": ["receipt_revoke"],
                "policy_decision_refs": ["policy_revoke"]
            }
        }))
        .expect("approval revoke state update bridge request");

        let response = plan_approval_revoke_state_update(request).expect("approval revoke planned");

        assert_eq!(
            response["source"],
            "rust_approval_revoke_state_update_command"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "approval.revoke");
        assert_eq!(response["operator_control"]["lease_status"], "revoked");
        assert!(response["operator_control"].get("approvalId").is_none());
        assert!(response["operator_control"].get("leaseId").is_none());
        assert!(response["operator_control"].get("leaseStatus").is_none());
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("receiptRefs").is_none());
        assert!(response["operator_control"]
            .get("policyDecisionRefs")
            .is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(response["run"]["turnStatus"], "waiting_for_input");
        assert_eq!(
            response["run"]["trace"]["approvalRevocations"][0]["event_id"],
            "event_revoke"
        );
    }

    #[test]
    fn approval_authority_rejects_step_module_command_schema() {
        let request: CodingToolApprovalBridgeRequest = serde_json::from_value(json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_coding_tool_approval_manifest",
            "backend": "rust_authority",
            "request": {
                "schema_version": "ioi.runtime.coding-tool-approval-request.v1",
                "thread_id": "thread_approval",
                "tool_id": "file.apply_patch",
                "tool_call_id": "call_approval",
                "effect_class": "workspace_write",
                "input": { "path": "src/app.js" }
            }
        }))
        .expect("coding-tool approval bridge request");

        let error = plan_coding_tool_approval_manifest(request)
            .expect_err("approval authority must reject StepModule bridge schema");
        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn approval_state_rejects_step_module_command_schema() {
        let request: ApprovalRequestStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_approval_request_state_update",
            "backend": "rust_authority",
            "request": {
                "schema_version": "ioi.runtime.approval-request-state-update-request.v1",
                "thread_id": "thread_alpha",
                "run_id": "run_alpha",
                "run": { "id": "run_alpha", "trace": {} },
                "event_id": "event_approval",
                "seq": 3,
                "created_at": "2026-06-06T04:30:00.000Z",
                "approval_id": "approval_alpha",
                "source": "runtime_auto",
                "reason": "Need permission"
            }
        }))
        .expect("approval request state update bridge request");

        let error = plan_approval_request_state_update(request)
            .expect_err("approval state must reject StepModule bridge schema");
        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_evaluates_context_budget_policy_through_rust_core() {
        let request: ContextBudgetPolicyBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "evaluate_context_budget_policy",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.context-budget-policy-request.v1",
                "usage_telemetry": {
                    "total_tokens": 120,
                    "estimated_cost_usd": 0.03,
                    "context_pressure": 0.2
                },
                "thresholds": {
                    "max_total_tokens": 100,
                    "warn_at_ratio": 0.8
                },
                "mode": "block",
                "scope": "thread",
                "thread_id": "thread_budget",
                "turn_id": "turn_budget",
                "workflow_graph_id": "graph_budget",
                "workflow_node_id": "node_budget",
                "source": "react_flow"
            }
        }))
        .expect("context budget bridge request");

        let response =
            evaluate_context_budget_policy(request).expect("context budget policy evaluated");

        assert_eq!(response["source"], "rust_context_budget_policy_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "blocked");
        assert_eq!(
            response["record"]["event_kind"],
            "RuntimeContextBudget.Evaluate"
        );
        assert_eq!(response["record"]["component_kind"], "context_budget");
        assert_eq!(response["usage_summary"]["total_tokens"], 120.0);
        assert_eq!(response["violations"][0]["id"], "total_tokens");
        assert_eq!(response["runtime_event_kind"], "policy.blocked");
        assert_eq!(response["runtime_event_status"], "blocked");
        assert!(response["runtime_event_item_id"]
            .as_str()
            .expect("runtime event item id")
            .starts_with("turn_budget:item:context-budget:policy_context_budget_thread_"));
        assert!(response["runtime_event_idempotency_key"]
            .as_str()
            .expect("runtime event idempotency key")
            .starts_with("thread:thread_budget:context-budget:policy_context_budget_thread_"));
    }

    #[test]
    fn context_policy_rejects_step_module_command_schema() {
        let request: ContextBudgetPolicyBridgeRequest = serde_json::from_value(json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "evaluate_context_budget_policy",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.context-budget-policy-request.v1",
                "usage_telemetry": { "total_tokens": 10 },
                "thresholds": { "max_total_tokens": 100 },
                "mode": "simulate",
                "scope": "thread",
                "thread_id": "thread_budget",
                "turn_id": "turn_budget"
            }
        }))
        .expect("context budget bridge request");

        let error = evaluate_context_budget_policy(request)
            .expect_err("context policy must reject StepModule bridge schema");
        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_evaluates_coding_tool_budget_policy_through_rust_core() {
        let request: ContextBudgetPolicyBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "evaluate_coding_tool_budget_policy",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.coding-tool-budget-policy-request.v1",
                "usage_telemetry": {
                    "total_tokens": 120,
                    "estimated_cost_usd": 0.03,
                    "context_pressure": 0.2
                },
                "thresholds": {
                    "max_total_tokens": 100,
                    "warn_at_ratio": 0.8
                },
                "mode": "block",
                "scope": "thread",
                "thread_id": "thread_budget",
                "tool_id": "file.inspect",
                "tool_call_id": "call_budget",
                "workflow_graph_id": "graph_budget",
                "workflow_node_id": "node_budget",
                "source": "react_flow"
            }
        }))
        .expect("coding-tool budget bridge request");

        let response = evaluate_coding_tool_budget_policy(request)
            .expect("coding-tool budget policy evaluated");

        assert_eq!(response["source"], "rust_coding_tool_budget_policy_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["usage_summary"]["total_tokens"], 120.0);
        assert_eq!(response["violations"][0]["id"], "total_tokens");
        assert!(response["policy_decision_id"]
            .as_str()
            .expect("policy decision")
            .starts_with("policy_context_budget_thread_"));
        assert_eq!(
            response["policy_decision_refs"][0],
            response["policy_decision_id"]
        );
    }

    #[test]
    fn bridge_evaluates_compaction_policy_through_rust_core() {
        let request: CompactionPolicyBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "evaluate_compaction_policy",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.compaction-policy-request.v1",
                "thread_id": "thread_budget",
                "turn_id": "turn_budget",
                "context_budget": {
                    "status": "blocked",
                    "summary": "Context budget blocked: total tokens exceeded."
                },
                "actions": {
                    "blocked_action": "compact",
                    "warn_action": "warn",
                    "ok_action": "noop"
                },
                "approval": {
                    "approval_required": true,
                    "approval_granted": false
                },
                "compact": {
                    "execute_compaction": false,
                    "compact_workflow_node_id": "node_compact",
                    "compact_scope": "thread"
                },
                "workflow_graph_id": "graph_budget",
                "workflow_node_id": "node_policy",
                "source": "react_flow"
            }
        }))
        .expect("compaction policy bridge request");

        let response = evaluate_compaction_policy(request).expect("compaction policy evaluated");

        assert_eq!(response["source"], "rust_compaction_policy_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "waiting");
        assert_eq!(response["action"], "approval_required");
        assert_eq!(response["selected_action"], "compact");
        assert_eq!(response["budget_status"], "blocked");
        assert_eq!(response["runtime_event_kind"], "approval.required");
        assert_eq!(response["runtime_event_status"], "waiting");
        assert!(response["runtime_event_item_id"]
            .as_str()
            .expect("runtime event item id")
            .starts_with("turn_budget:item:compaction-policy:policy_compaction_thread_budget_"));
        assert!(response["compact_idempotency_key"]
            .as_str()
            .expect("compact idempotency key")
            .starts_with(
                "thread:thread_budget:compaction-policy:compact:policy_compaction_thread_budget_"
            ));
        assert!(response["approval_id"]
            .as_str()
            .expect("approval id")
            .starts_with("approval_compaction_thread_budget_"));
    }

    #[test]
    fn bridge_plans_context_compaction_through_rust_core() {
        let request: ContextCompactionPlanBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_context_compaction",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.context-compaction-plan-request.v1",
                "thread_id": "thread_budget",
                "agent_id": "agent_budget",
                "turn_id": "turn_budget",
                "run_id": "run_budget",
                "session_id": "session_budget",
                "workspace_root": "/workspace",
                "reason": "trim context",
                "scope": "thread",
                "source": "react_flow",
                "requested_by": "operator_one",
                "workflow_graph_id": "graph_budget",
                "workflow_node_id": "node_compact",
                "event_stream_id": "thread_budget:events",
                "previous_latest_seq": 7
            }
        }))
        .expect("context compaction plan bridge request");

        let response = plan_context_compaction(request).expect("context compaction planned");

        assert_eq!(response["source"], "rust_context_compaction_plan_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["event_kind"], "context.compacted");
        assert_eq!(response["component_kind"], "context_compaction");
        assert_eq!(
            response["payload_schema_version"],
            "ioi.runtime.context-compaction.v1"
        );
        assert!(response["item_id"]
            .as_str()
            .expect("item id")
            .starts_with("turn_budget:item:context-compact:"));
        assert!(response["idempotency_key"]
            .as_str()
            .expect("idempotency key")
            .starts_with("thread:thread_budget:context.compact:"));
        assert!(response["receipt_refs"][0]
            .as_str()
            .expect("receipt ref")
            .starts_with("receipt_run_budget_context_compaction_"));
        assert_eq!(
            response["policy_decision_refs"][0],
            "policy_run_budget_context_compaction_allow"
        );
        assert_eq!(response["payload"]["reason"], "trim context");
        assert_eq!(response["payload"]["requested_by"], "operator_one");
        assert_eq!(response["payload"]["previous_latest_seq"], 7);
    }

    #[test]
    fn bridge_plans_context_compaction_state_update_through_rust_core() {
        let request: ContextCompactionStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_context_compaction_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.context-compaction-state-update-request.v1",
                "target_kind": "run",
                "thread_id": "thread_budget",
                "agent_id": "agent_budget",
                "run_id": "run_budget",
                "run": {
                    "id": "run_budget",
                    "agentId": "agent_budget",
                    "trace": {}
                },
                "agent": {
                    "id": "agent_budget",
                    "cwd": "/workspace"
                },
                "event_id": "event_budget",
                "seq": 8,
                "created_at": "2026-06-06T03:40:00.000Z",
                "source": "react_flow",
                "reason": "trim context",
                "scope": "thread"
            }
        }))
        .expect("context compaction state update bridge request");

        let response = plan_context_compaction_state_update(request)
            .expect("context compaction state update planned");

        assert_eq!(
            response["source"],
            "rust_context_compaction_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["target_kind"], "run");
        assert_eq!(response["operation_kind"], "thread.compact");
        assert_eq!(response["operator_control"]["event_id"], "event_budget");
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(
            response["run"]["trace"]["contextCompaction"]["event_id"],
            "event_budget"
        );
        assert!(response["run"]["trace"]["contextCompaction"]
            .get("eventId")
            .is_none());
        assert_eq!(
            response["run"]["trace"]["contextCompaction"]["reason"],
            "trim context"
        );
        assert_eq!(
            response["run"]["trace"]["operatorControls"][0]["control"],
            "compact"
        );
    }

    #[test]
    fn bridge_plans_coding_tool_budget_recovery_state_update_through_rust_core() {
        let request: CodingToolBudgetRecoveryStateUpdateBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_coding_tool_budget_recovery_state_update",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.coding-tool-budget-recovery-state-update-request.v1",
                    "thread_id": "thread_budget",
                    "run_id": "run_budget",
                    "run": {
                        "id": "run_budget",
                        "agentId": "agent_budget",
                        "trace": {}
                    },
                    "event_id": "event_retry",
                    "seq": 9,
                    "created_at": "2026-06-06T04:05:00.000Z",
                    "approval_id": "approval_budget",
                    "source": "runtime_auto",
                    "receipt_refs": ["receipt_retry"],
                    "policy_decision_refs": ["policy_retry"]
                }
            }))
            .expect("coding tool budget recovery state update bridge request");

        let response = plan_coding_tool_budget_recovery_state_update(request)
            .expect("coding tool budget recovery state update planned");

        assert_eq!(
            response["source"],
            "rust_coding_tool_budget_recovery_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "workflow.run.retry_completed");
        assert_eq!(
            response["operator_control"]["approval_id"],
            "approval_budget"
        );
        assert!(response["operator_control"].get("approvalId").is_none());
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("receiptRefs").is_none());
        assert!(response["operator_control"]
            .get("policyDecisionRefs")
            .is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(
            response["run"]["trace"]["operatorControls"][0]["control"],
            "coding_tool_budget_recovery"
        );
    }

    #[test]
    fn bridge_plans_diagnostics_operator_override_state_update_through_rust_core() {
        let request: DiagnosticsOperatorOverrideStateUpdateBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_diagnostics_operator_override_state_update",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.diagnostics-operator-override-state-update-request.v1",
                    "thread_id": "thread_budget",
                    "run_id": "run_blocked",
                    "run": {
                        "id": "run_blocked",
                        "agentId": "agent_budget",
                        "status": "blocked",
                        "turnStatus": "waiting_for_input",
                        "diagnosticsBlockingGate": {
                            "status": "blocked"
                        },
                        "trace": {
                            "stopCondition": {
                                "reason": "lsp_diagnostics_blocked"
                            }
                        },
                        "operatorControls": []
                    },
                    "event_id": "event_override",
                    "seq": 10,
                    "created_at": "2026-06-06T04:15:00.000Z",
                    "decision_id": "decision_override",
                    "gate_event_id": "event_gate",
                    "source": "runtime_auto",
                    "approval_required": true,
                    "approval_satisfied": true,
                    "approval_source": "boolean_confirmation",
                    "snapshot_id": "snapshot_alpha"
                }
            }))
            .expect("diagnostics operator override state update bridge request");

        let response = plan_diagnostics_operator_override_state_update(request)
            .expect("diagnostics operator override state update planned");

        assert_eq!(
            response["source"],
            "rust_diagnostics_operator_override_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(
            response["operation_kind"],
            "diagnostics.operator_override.event"
        );
        assert_eq!(
            response["operator_control"]["control"],
            "diagnostics_operator_override"
        );
        assert_eq!(
            response["operator_control"]["decision_id"],
            "decision_override"
        );
        for field in [
            "decisionId",
            "gateEventId",
            "approvalRequired",
            "approvalSatisfied",
            "approvalSource",
            "snapshotId",
            "eventId",
            "createdAt",
        ] {
            assert!(response["operator_control"].get(field).is_none());
        }
        assert_eq!(response["run"]["status"], "completed");
        assert_eq!(
            response["run"]["diagnosticsBlockingGate"]["status"],
            "overridden"
        );
        assert_eq!(
            response["run"]["trace"]["operatorControls"][0]["event_id"],
            "event_override"
        );
    }

    #[test]
    fn bridge_plans_operator_interrupt_state_update_through_rust_core() {
        let request: OperatorInterruptStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_operator_interrupt_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.operator-interrupt-state-update-request.v1",
                "thread_id": "thread_budget",
                "turn_id": "turn_budget",
                "run_id": "run_budget",
                "run": {
                    "id": "run_budget",
                    "agentId": "agent_budget",
                    "status": "running",
                    "turnStatus": "running",
                    "trace": {
                        "qualityLedger": {
                            "failureOntologyLabels": ["existing_label"]
                        }
                    },
                    "operatorControls": []
                },
                "event_id": "event_interrupt",
                "seq": 11,
                "created_at": "2026-06-06T04:25:00.000Z",
                "source": "runtime_auto",
                "reason": "operator_stop"
            }
        }))
        .expect("operator interrupt state update bridge request");

        let response = plan_operator_interrupt_state_update(request)
            .expect("operator interrupt state update planned");

        assert_eq!(
            response["source"],
            "rust_operator_interrupt_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "turn.interrupt");
        assert_eq!(response["operator_control"]["control"], "interrupt");
        assert_eq!(response["operator_control"]["event_id"], "event_interrupt");
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(
            response["run"]["trace"]["operatorControls"][0]["event_id"],
            "event_interrupt"
        );
        assert_eq!(response["run"]["status"], "canceled");
        assert_eq!(response["run"]["turnStatus"], "interrupted");
        assert_eq!(
            response["run"]["trace"]["qualityLedger"]["failureOntologyLabels"][1],
            "operator_interrupt"
        );
    }

    #[test]
    fn bridge_plans_operator_steer_state_update_through_rust_core() {
        let request: OperatorSteerStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_operator_steer_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.operator-steer-state-update-request.v1",
                "thread_id": "thread_budget",
                "turn_id": "turn_budget",
                "run_id": "run_budget",
                "run": {
                    "id": "run_budget",
                    "agentId": "agent_budget",
                    "status": "running",
                    "turnStatus": "running",
                    "trace": {},
                    "operatorControls": []
                },
                "event_id": "event_steer",
                "seq": 12,
                "created_at": "2026-06-06T04:35:00.000Z",
                "source": "react_flow",
                "guidance": "focus on the failing bridge assertion"
            }
        }))
        .expect("operator steer state update bridge request");

        let response =
            plan_operator_steer_state_update(request).expect("operator steer state update planned");

        assert_eq!(
            response["source"],
            "rust_operator_steer_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "turn.steer");
        assert_eq!(response["operator_control"]["control"], "steer");
        assert_eq!(
            response["operator_control"]["guidance"],
            "focus on the failing bridge assertion"
        );
        assert_eq!(response["operator_control"]["event_id"], "event_steer");
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(response["run"]["status"], "running");
        assert_eq!(
            response["run"]["trace"]["operatorControls"][0]["event_id"],
            "event_steer"
        );
    }

    #[test]
    fn bridge_plans_run_cancel_state_update_through_rust_core() {
        let request: RunCancelStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_run_cancel_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.run-cancel-state-update-request.v1",
                "run_id": "run_cancel_bridge",
                "canceled_at": "2026-06-06T04:45:00.000Z",
                "run": {
                    "id": "run_cancel_bridge",
                    "agentId": "agent_bridge",
                    "status": "running",
                    "objective": "Cancel bridge run",
                    "mode": "send",
                    "createdAt": "2026-06-04T00:00:00.000Z",
                    "updatedAt": "2026-06-04T00:00:01.000Z",
                    "events": [
                        {
                            "id": "run_cancel_bridge:event:000:delta",
                            "type": "delta",
                            "data": { "text": "partial" }
                        },
                        {
                            "id": "run_cancel_bridge:event:001:completed",
                            "type": "completed",
                            "data": { "status": "completed" }
                        }
                    ],
                    "trace": {
                        "events": [],
                        "receipts": [],
                        "qualityLedger": {
                            "failureOntologyLabels": []
                        }
                    },
                    "receipts": [],
                    "artifacts": []
                }
            }
        }))
        .expect("run cancel bridge request");

        let response =
            plan_run_cancel_state_update(request).expect("run cancel state update planned");

        assert_eq!(response["source"], "rust_run_cancel_state_update_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "run.cancel");
        assert_eq!(response["run"]["status"], "canceled");
        assert_eq!(response["run"]["events"][1]["type"], "runtime_task");
        assert_eq!(response["run"]["events"][3]["type"], "job_canceled");
        assert_eq!(response["runtime_job"]["status"], "canceled");
    }

    #[test]
    fn bridge_plans_thread_control_agent_state_update_through_rust_core() {
        let request: ThreadControlAgentStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_thread_control_agent_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.thread-control-agent-state-update-request.v1",
                "thread_id": "thread_1",
                "agent": {
                    "id": "agent_1",
                    "cwd": "/workspace",
                    "runtimeControls": {
                        "mode": "agent",
                        "approvalMode": "suggest",
                        "model": {
                            "id": "auto",
                            "routeId": "route.local-first"
                        }
                    }
                },
                "control_kind": "thinking",
                "controls": {
                    "mode": "agent",
                    "approvalMode": "suggest",
                    "model": {
                        "id": "auto",
                            "routeId": "route.local-first",
                            "selectedModel": "local-model"
                    },
                    "updatedAt": "2026-06-06T05:00:00.000Z"
                },
                "event_id": "evt_thread_control",
                "seq": 7,
                "created_at": "2026-06-06T05:00:00.000Z",
                "model_route": {
                    "requested_model_id": "auto",
                    "selected_model": "local-model",
                    "route_id": "route.local-first",
                    "endpoint_id": "endpoint_1",
                    "provider_id": "provider_1",
                    "receipt_id": "receipt_route_1",
                    "decision": {
                        "workflow_node_id": "runtime.model-router.custom"
                    }
                }
            }
        }))
        .expect("thread control agent state update bridge request");

        let response = plan_thread_control_agent_state_update(request)
            .expect("thread control agent state update planned");

        assert_eq!(
            response["source"],
            "rust_thread_control_agent_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.thinking");
        assert_eq!(response["control"]["control_kind"], "thinking");
        assert_eq!(response["control"]["event_id"], "evt_thread_control");
        for field in [
            "controlKind",
            "eventId",
            "createdAt",
            "workspaceTrustWarningEventId",
        ] {
            assert!(response["control"].get(field).is_none());
        }
        assert_eq!(
            response["agent"]["runtimeControls"]["model"]["selectedModel"],
            "local-model"
        );
        assert_eq!(response["agent"]["modelId"], "local-model");
        assert_eq!(response["agent"]["modelRouteReceiptId"], "receipt_route_1");
    }

    #[test]
    fn bridge_plans_mcp_control_agent_state_update_through_rust_core() {
        let request: McpControlAgentStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_mcp_control_agent_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.mcp-control-agent-state-update-request.v1",
                "thread_id": "thread_1",
                "agent": {
                    "id": "agent_1",
                    "cwd": "/workspace",
                    "mcpRegistry": {
                        "servers": [
                            {
                                "id": "mcp.docs",
                                "enabled": true,
                                "tools": [{ "name": "search" }]
                            }
                        ]
                    }
                },
                "control_kind": "mcp_add",
                "event_id": "event_mcp_add",
                "seq": 5,
                "created_at": "2026-06-06T05:45:00.000Z"
            }
        }))
        .expect("mcp control agent state update bridge request");

        let response = plan_mcp_control_agent_state_update(request)
            .expect("mcp control agent state update planned");

        assert_eq!(
            response["source"],
            "rust_mcp_control_agent_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.mcp_add");
        assert_eq!(response["control"]["control_kind"], "mcp_add");
        assert_eq!(response["control"]["event_id"], "event_mcp_add");
        assert!(response["control"].get("controlKind").is_none());
        assert!(response["control"].get("eventId").is_none());
        assert!(response["control"].get("createdAt").is_none());
        assert_eq!(response["agent"]["id"], "agent_1");
        assert_eq!(response["agent"]["updatedAt"], "2026-06-06T05:45:00.000Z");
        assert_eq!(
            response["agent"]["mcpRegistry"]["servers"][0]["id"],
            "mcp.docs"
        );
    }

    #[test]
    fn bridge_validates_mcp_servers_through_rust_core() {
        let request: McpServerValidationBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "validate_mcp_servers",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.mcp-server-validation-request.v1",
                "servers": [
                    {
                        "id": "mcp.remote",
                        "transport": "http",
                        "server_url": "file:///tmp/socket",
                        "allowed_tools": ["fetch"],
                        "containment": {
                            "allow_network_egress": false
                        }
                    }
                ]
            }
        }))
        .expect("mcp server validation bridge request");

        let response = validate_mcp_servers(request).expect("mcp server validation planned");

        assert_eq!(response["source"], "rust_mcp_server_validation_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["ok"], false);
        assert_eq!(response["issue_count"], 2);
        assert_eq!(response["issues"][0]["code"], "mcp_remote_url_invalid");
        assert_eq!(response["issues"][1]["code"], "mcp_remote_network_blocked");
        assert!(response["issues"][0].get("serverId").is_none());
    }

    #[test]
    fn bridge_projects_mcp_server_validation_input_through_rust_core() {
        let request: McpServerValidationInputBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "project_mcp_server_validation_input",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.mcp-server-validation-input-request.v1",
                "workspace_root": "/workspace",
                "input": {
                    "mcp_json": {
                        "mcp_servers": {
                            "docs": {
                                "transport": "stdio",
                                "command": "npx",
                                "tools": {
                                    "search": { "description": "Search docs" }
                                }
                            }
                        }
                    },
                    "mcpJson": {
                        "mcpServers": {
                            "retired": {
                                "transport": "stdio",
                                "command": "retired"
                            }
                        }
                    }
                }
            }
        }))
        .expect("mcp server validation input bridge request");

        let response = project_mcp_server_validation_input(request)
            .expect("mcp server validation input projected");

        assert_eq!(
            response["source"],
            "rust_mcp_server_validation_input_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "projected");
        assert_eq!(response["workspace_root"], "/workspace");
        assert_eq!(response["server_count"], 1);
        assert_eq!(response["servers"][0]["id"], "mcp.docs");
        assert_eq!(response["servers"][0]["tool_count"], 1);
        assert!(response["servers"][0].get("sourceScope").is_none());
    }

    #[test]
    fn bridge_projects_mcp_manager_status_through_rust_core() {
        let request: McpManagerStatusProjectionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_mcp_manager_status_projection",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.mcp-manager-status-projection-request.v1",
                "status_schema_version": "ioi.runtime.mcp-manager-status.v1",
                "validation": {
                    "ok": true,
                    "status": "pass",
                    "issues": [],
                    "warnings": []
                },
                "servers": [
                    { "id": "mcp.docs", "enabled": true },
                    { "id": "mcp.disabled", "enabled": false }
                ],
                "tools": [{ "stable_tool_id": "mcp.docs.search" }],
                "enabled_tools": [{ "stable_tool_id": "mcp.docs.search" }],
                "resources": [{ "uri": "mcp.docs://root" }],
                "prompts": [{ "name": "ask" }],
                "routes": {
                    "search_tools": "/v1/mcp/tools/search"
                }
            }
        }))
        .expect("mcp manager status projection bridge request");

        let response = plan_mcp_manager_status_projection(request)
            .expect("mcp manager status projection planned");

        assert_eq!(
            response["source"],
            "rust_mcp_manager_status_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "ready");
        assert_eq!(response["server_count"], 2);
        assert_eq!(response["enabled_server_count"], 1);
        assert_eq!(response["enabled_tool_count"], 1);
        assert_eq!(response["validation"]["server_count"], 2);
        assert_eq!(
            response["validation"]["tools"][0]["stable_tool_id"],
            "mcp.docs.search"
        );
        assert_eq!(response["routes"]["search_tools"], "/v1/mcp/tools/search");
        assert!(response.get("serverCount").is_none());
        assert!(response["routes"].get("searchTools").is_none());
    }

    #[test]
    fn bridge_projects_memory_manager_status_through_rust_core() {
        let request: MemoryManagerStatusProjectionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_memory_manager_status_projection",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.memory-manager-status-projection-request.v1",
                "status_schema_version": "ioi.runtime.memory-manager-status.v1",
                "validation_schema_version": "ioi.runtime.memory-manager-validation.v1",
                "projection": {
                    "policy": {
                        "id": "policy.thread",
                        "scope": "thread",
                        "injection_enabled": true,
                        "read_only": false,
                        "write_requires_approval": true,
                        "writeRequiresApproval": false
                    },
                    "paths": {
                        "records_path": "/state/memory",
                        "policies_path": "/state/policies"
                    },
                    "records": [{
                        "id": "memory.one",
                        "fact": "Remember the runtime boundary.",
                        "scope": "thread",
                        "memoryKey": "retired.project",
                        "memory_key": "project"
                    }]
                }
            }
        }))
        .expect("memory manager status projection bridge request");

        let response = plan_memory_manager_status_projection(request)
            .expect("memory manager status projection planned");

        assert_eq!(
            response["source"],
            "rust_memory_manager_status_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "ready");
        assert_eq!(response["record_count"], 1);
        assert_eq!(response["memory_key_count"], 1);
        assert_eq!(response["memory_keys"][0], "project");
        assert_eq!(response["write_requires_approval"], true);
        assert_eq!(
            response["write_blocked_reason"],
            "memory_write_requires_approval"
        );
        assert_eq!(
            response["routes"]["status"],
            "/v1/threads/{thread_id}/memory/status"
        );
        assert!(response.get("memoryKeys").is_none());
        assert!(response.get("writeRequiresApproval").is_none());
    }

    #[test]
    fn bridge_projects_memory_manager_validation_through_rust_core() {
        let request: MemoryManagerValidationProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_memory_manager_validation_projection",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.memory-manager-validation-projection-request.v1",
                    "validation_schema_version": "ioi.runtime.memory-manager-validation.v1",
                    "projection": {
                        "policy": {
                            "id": "policy.thread",
                            "scope": "thread"
                        },
                        "paths": {},
                        "records": [{
                            "id": "memory.one",
                            "fact": "Remember the runtime boundary.",
                            "scope": "thread"
                        }]
                    }
                }
            }))
            .expect("memory manager validation projection bridge request");

        let response = plan_memory_manager_validation_projection(request)
            .expect("memory manager validation projection planned");

        assert_eq!(
            response["source"],
            "rust_memory_manager_validation_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["ok"], false);
        assert_eq!(response["issue_count"], 2);
        assert_eq!(response["issues"][0]["code"], "memory_records_path_missing");
        assert_eq!(
            response["issues"][1]["code"],
            "memory_policies_path_missing"
        );
        assert!(response.get("issueCount").is_none());
        assert!(response.get("recordCount").is_none());
    }

    #[test]
    fn bridge_projects_mcp_manager_catalog_through_rust_core() {
        let request: McpManagerCatalogProjectionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_mcp_manager_catalog_projection",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.mcp-manager-catalog-projection-request.v1",
                "servers": [
                    {
                        "id": "mcp.docs",
                        "label": "Docs",
                        "enabled": true,
                        "allowed_tools": [{ "name": "search" }],
                        "resources": [{ "uri": "docs://index" }],
                        "prompts": [{ "name": "summarize" }]
                    },
                    {
                        "id": "mcp.disabled",
                        "label": "Disabled",
                        "enabled": false,
                        "allowed_tools": ["noop"]
                    }
                ]
            }
        }))
        .expect("mcp manager catalog projection bridge request");

        let response = plan_mcp_manager_catalog_projection(request)
            .expect("mcp manager catalog projection planned");

        assert_eq!(
            response["source"],
            "rust_mcp_manager_catalog_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "projected");
        assert_eq!(response["server_count"], 2);
        assert_eq!(response["tool_count"], 2);
        assert_eq!(response["enabled_tool_count"], 1);
        assert_eq!(response["tools"][0]["stable_tool_id"], "mcp.Docs.search");
        assert_eq!(response["tools"][1]["status"], "disabled");
        assert_eq!(
            response["resources"][0]["stable_resource_id"],
            "mcp.Docs.resource.docs_index"
        );
        assert_eq!(
            response["prompts"][0]["stable_prompt_id"],
            "mcp.Docs.prompt.summarize"
        );
        assert!(response.get("stableToolId").is_none());
        assert!(response["tools"][0].get("stableToolId").is_none());
    }

    #[test]
    fn bridge_projects_mcp_manager_catalog_summary_through_rust_core() {
        let request: McpManagerCatalogSummaryProjectionBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_mcp_manager_catalog_summary_projection",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.mcp-manager-catalog-summary-projection-request.v1",
                    "server": {
                        "id": "mcp.docs",
                        "label": "Docs",
                        "transport": "stdio"
                    },
                    "tools": [{
                        "stable_tool_id": "mcp.docs.search",
                        "tool_name": "search.index",
                        "input_schema": { "type": "object" }
                    }],
                    "resources": [{ "stable_resource_id": "mcp.docs.resource.docs", "uri": "docs://index" }],
                    "prompts": [{ "stable_prompt_id": "mcp.docs.prompt.summarize", "name": "summarize" }],
                    "live_mode": "declared_catalog",
                    "preview_limit": 25,
                    "deferred": false
                }
            }))
            .expect("mcp manager catalog summary projection bridge request");

        let response = plan_mcp_manager_catalog_summary_projection(request)
            .expect("mcp manager catalog summary projection planned");

        assert_eq!(
            response["source"],
            "rust_mcp_manager_catalog_summary_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["object"], "ioi.runtime_mcp_catalog_summary");
        assert_eq!(response["status"], "completed");
        assert_eq!(response["server_id"], "mcp.docs");
        assert_eq!(response["tool_count"], 1);
        assert_eq!(response["resource_count"], 1);
        assert_eq!(response["prompt_count"], 1);
        assert_eq!(response["namespaces"][0], "search");
        assert_eq!(response["preview_tool_names"][0], "search.index");
        assert_eq!(response["search_route"], "/v1/mcp/tools/search");
        assert!(response.get("catalogHash").is_none());
        assert!(response.get("toolCount").is_none());
    }

    #[test]
    fn bridge_projects_mcp_manager_validation_through_rust_core() {
        let request: McpManagerValidationProjectionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_mcp_manager_validation_projection",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.mcp-manager-validation-projection-request.v1",
                "validation_schema_version": "ioi.runtime.mcp-manager-validation.v1",
                "validation": {
                    "ok": false,
                    "status": "blocked",
                    "issues": [{ "code": "mcp_server_transport_missing", "server_id": "mcp.docs" }],
                    "warnings": []
                },
                "servers": [{ "id": "mcp.docs" }],
                "tools": [{ "stable_tool_id": "mcp.docs.search" }],
                "resources": [{ "uri": "docs://index" }],
                "prompts": [{ "name": "summarize" }]
            }
        }))
        .expect("mcp manager validation projection bridge request");

        let response = plan_mcp_manager_validation_projection(request)
            .expect("mcp manager validation projection planned");

        assert_eq!(
            response["source"],
            "rust_mcp_manager_validation_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(
            response["schema_version"],
            "ioi.runtime.mcp-manager-validation.v1"
        );
        assert_eq!(response["object"], "ioi.runtime_mcp_manager_validation");
        assert_eq!(response["ok"], false);
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["server_count"], 1);
        assert_eq!(response["tool_count"], 1);
        assert_eq!(response["issue_count"], 1);
        assert_eq!(response["issues"][0]["server_id"], "mcp.docs");
        assert_eq!(response["tools"][0]["stable_tool_id"], "mcp.docs.search");
        assert!(response.get("serverCount").is_none());
        assert!(response["tools"][0].get("stableToolId").is_none());
    }

    #[test]
    fn bridge_plans_thread_memory_agent_state_update_through_rust_core() {
        let request: ThreadMemoryAgentStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_thread_memory_agent_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.thread-memory-agent-state-update-request.v1",
                "thread_id": "thread_1",
                "agent": {
                    "id": "agent_1",
                    "cwd": "/workspace",
                    "updatedAt": "2026-06-06T05:00:00.000Z"
                },
                "control_kind": "memory_status",
                "event_id": "event_memory_status",
                "seq": 6,
                "created_at": "2026-06-06T06:05:00.000Z"
            }
        }))
        .expect("thread memory agent state update bridge request");

        let response = plan_thread_memory_agent_state_update(request)
            .expect("thread memory agent state update planned");

        assert_eq!(
            response["source"],
            "rust_thread_memory_agent_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.memory_status");
        assert_eq!(response["control"]["control_kind"], "memory_status");
        assert_eq!(response["control"]["event_id"], "event_memory_status");
        assert!(response["control"].get("controlKind").is_none());
        assert!(response["control"].get("eventId").is_none());
        assert!(response["control"].get("createdAt").is_none());
        assert_eq!(response["agent"]["id"], "agent_1");
        assert_eq!(response["agent"]["updatedAt"], "2026-06-06T06:05:00.000Z");
    }

    #[test]
    fn bridge_plans_runtime_bridge_thread_start_agent_state_update_through_rust_core() {
        let request: RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_runtime_bridge_thread_start_agent_state_update",
                "backend": "rust_policy",
                "request": {
                    "schema_version": "ioi.runtime.runtime-bridge-thread-start-agent-state-update-request.v1",
                    "thread_id": "thread_1",
                    "agent": {
                        "id": "agent_1",
                        "cwd": "/workspace",
                        "fixtureProfile": "fixture.local",
                        "updatedAt": "2026-06-06T05:00:00.000Z"
                    },
                    "runtime_profile": "runtime_service",
                    "session_id": "session_runtime",
                    "bridge_id": "bridge_runtime",
                    "status": "active",
                    "source": "runtime_service",
                    "updated_at": "2026-06-06T06:15:00.000Z"
                }
            }))
            .expect("runtime bridge thread start agent state update bridge request");

        let response = plan_runtime_bridge_thread_start_agent_state_update(request)
            .expect("runtime bridge thread start agent state update planned");

        assert_eq!(
            response["source"],
            "rust_runtime_bridge_thread_start_agent_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.runtime_bridge.start");
        assert_eq!(response["bridge_start"]["session_id"], "session_runtime");
        assert_eq!(response["bridge_start"]["bridge_id"], "bridge_runtime");
        for field in ["runtimeProfile", "sessionId", "bridgeId", "updatedAt"] {
            assert!(response["bridge_start"].get(field).is_none());
        }
        assert_eq!(response["agent"]["runtimeSessionId"], "session_runtime");
        assert_eq!(response["agent"]["runtimeBridgeId"], "bridge_runtime");
        assert_eq!(response["agent"]["fixtureProfile"], Value::Null);
    }

    #[test]
    fn bridge_plans_runtime_bridge_turn_run_state_update_through_rust_core() {
        let request: RuntimeBridgeTurnRunStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_runtime_bridge_turn_run_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.runtime-bridge-turn-run-state-update-request.v1",
                "thread_id": "thread_1",
                "agent": {
                    "id": "agent_1",
                    "cwd": "/workspace"
                },
                "projection": {
                    "run_id": "run_runtime_bridge",
                    "turn_id": "turn_runtime_bridge"
                },
                "run": {
                    "id": "run_runtime_bridge",
                    "agentId": "agent_1",
                    "mode": "send",
                    "status": "completed",
                    "createdAt": "2026-06-06T06:34:00.000Z",
                    "updatedAt": "2026-06-06T06:35:00.000Z"
                }
            }
        }))
        .expect("runtime bridge turn run state update bridge request");

        let response = plan_runtime_bridge_turn_run_state_update(request)
            .expect("runtime bridge turn run state update planned");

        assert_eq!(
            response["source"],
            "rust_runtime_bridge_turn_run_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "turn.runtime_bridge.submit");
        assert_eq!(response["run"]["id"], "run_runtime_bridge");
        assert_eq!(response["run"]["agentId"], "agent_1");
    }

    #[test]
    fn bridge_plans_subagent_record_state_update_through_rust_core() {
        let request: SubagentRecordStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_subagent_record_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.subagent-record-state-update-request.v1",
                "operation_kind": "subagent.wait",
                "thread_id": "thread_1",
                "subagent": {
                    "schema_version": "ioi.runtime.subagent.v1",
                    "object": "ioi.runtime_subagent",
                    "subagent_id": "subagent_1",
                    "parent_thread_id": "thread_1",
                    "status": "completed",
                    "lifecycle_status": "completed",
                    "updated_at": "2026-06-06T07:04:00.000Z"
                }
            }
        }))
        .expect("subagent record state update bridge request");

        let response =
            plan_subagent_record_state_update(request).expect("subagent state update planned");

        assert_eq!(
            response["source"],
            "rust_subagent_record_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "subagent.wait");
        assert_eq!(response["subagent"]["subagent_id"], "subagent_1");
    }

    #[test]
    fn bridge_plans_agent_create_state_update_through_rust_core() {
        let request: AgentCreateStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_agent_create_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.agent-create-state-update-request.v1",
                "agent": {
                    "id": "agent_create_bridge",
                    "status": "active",
                    "runtime": "local",
                    "cwd": "/workspace",
                    "runtimeControls": {
                        "mode": "agent"
                    },
                    "createdAt": "2026-06-06T05:15:00.000Z",
                    "updatedAt": "2026-06-06T05:15:00.000Z"
                }
            }
        }))
        .expect("agent create state update bridge request");

        let response =
            plan_agent_create_state_update(request).expect("agent create state update planned");

        assert_eq!(response["source"], "rust_agent_create_state_update_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "agent.create");
        assert_eq!(response["agent"]["id"], "agent_create_bridge");
    }

    #[test]
    fn bridge_plans_agent_status_state_update_through_rust_core() {
        let request: AgentStatusStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_agent_status_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.agent-status-state-update-request.v1",
                "agent": {
                    "id": "agent_status_bridge",
                    "status": "active",
                    "createdAt": "2026-06-06T05:15:00.000Z",
                    "updatedAt": "2026-06-06T05:15:00.000Z"
                },
                "status": "archived",
                "operation_kind": "agent.archive",
                "updated_at": "2026-06-06T06:25:00.000Z"
            }
        }))
        .expect("agent status state update bridge request");

        let response =
            plan_agent_status_state_update(request).expect("agent status state update planned");

        assert_eq!(response["source"], "rust_agent_status_state_update_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "agent.archive");
        assert_eq!(response["agent"]["id"], "agent_status_bridge");
        assert_eq!(response["agent"]["status"], "archived");
        assert_eq!(response["agent"]["updatedAt"], "2026-06-06T06:25:00.000Z");
    }

    #[test]
    fn bridge_plans_run_create_state_update_through_rust_core() {
        let request: RunCreateStateUpdateBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_run_create_state_update",
            "backend": "rust_policy",
            "request": {
                "schema_version": "ioi.runtime.run-create-state-update-request.v1",
                "run": {
                    "id": "run_create_bridge",
                    "agentId": "agent_create_bridge",
                    "status": "completed",
                    "mode": "send",
                    "createdAt": "2026-06-06T05:16:00.000Z",
                    "updatedAt": "2026-06-06T05:16:00.000Z",
                    "usage": {
                        "total_tokens": 7
                    },
                    "usage_telemetry": {
                        "total_tokens": 7
                    },
                    "trace": {
                        "usage_telemetry": {
                            "total_tokens": 7
                        }
                    }
                }
            }
        }))
        .expect("run create state update bridge request");

        let response =
            plan_run_create_state_update(request).expect("run create state update planned");

        assert_eq!(response["source"], "rust_run_create_state_update_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "run.create");
        assert_eq!(response["run"]["id"], "run_create_bridge");
        assert_eq!(
            response["run"]["trace"]["usage_telemetry"]["total_tokens"],
            7
        );
    }

    #[test]
    fn runtime_agentgres_storage_rejects_step_module_command_schema() {
        let request: StorageBackendWriteBridgeRequest = serde_json::from_value(json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_storage_backend_write",
            "backend": "rust_agentgres_storage",
            "request": {
                "schema_version": "ioi.storage_backend_write_admission.v1",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "object_ref": "agentgres://runtime-state/runs/run_1/records/runs/run_1.json",
                "content_hash": "sha256:runtime-state-write",
                "artifact_refs": [],
                "payload_refs": ["payload://runtime/runs/run_1/records/runs/run_1.json"],
                "receipt_refs": ["receipt_policy"]
            }
        }))
        .expect("storage write bridge request");

        let error = admit_storage_backend_write(request)
            .expect_err("runtime Agentgres storage admission must reject StepModule bridge schema");
        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn runtime_agentgres_commit_rejects_step_module_command_schema() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeAgentStateCommitBridgeRequest = serde_json::from_value(json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "commit_runtime_agent_state",
            "backend": "rust_agentgres_storage",
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_agent_state_commit.v1",
                "agent_id": "agent_1",
                "operation_kind": "agent.create",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "agent": {
                    "id": "agent_1",
                    "status": "active",
                    "runtime": "local",
                    "updated_at": "2026-06-06T00:00:00.000Z",
                    "receipt_refs": ["receipt_agent"]
                }
            }
        }))
        .expect("runtime agent-state commit bridge request");

        let error = commit_runtime_agent_state(request)
            .expect_err("runtime Agentgres commit must reject StepModule bridge schema");
        assert_eq!(error.code, "schema_version_invalid");
        assert!(error.message.contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message.contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn bridge_admits_storage_backend_write_through_rust_core() {
        let request: StorageBackendWriteBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "admit_storage_backend_write",
            "backend": "rust_agentgres_storage",
            "request": {
                "schema_version": "ioi.storage_backend_write_admission.v1",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "object_ref": "agentgres://runtime-state/runs/run_1/records/runs/run_1.json",
                "content_hash": "sha256:runtime-state-write",
                "artifact_refs": [],
                "payload_refs": ["payload://runtime/runs/run_1/records/runs/run_1.json"],
                "receipt_refs": ["receipt_policy"]
            }
        }))
        .expect("storage write bridge request");

        let response = admit_storage_backend_write(request).expect("storage write admitted");

        assert_eq!(
            response["source"],
            "rust_agentgres_storage_write_admission_command"
        );
        assert_eq!(response["backend"], "rust_agentgres_storage");
        assert_eq!(
            response["record"]["storage_backend_ref"],
            "storage://runtime-agentgres/local-json"
        );
        assert_eq!(
            response["object_ref"],
            "agentgres://runtime-state/runs/run_1/records/runs/run_1.json"
        );
        assert!(response["admission_hash"]
            .as_str()
            .expect("admission hash")
            .starts_with("sha256:"));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_storage_write_admission"));
    }

    #[test]
    fn bridge_commits_runtime_run_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        fs::create_dir_all(state_dir.join("tasks")).expect("tasks dir");
        fs::write(
            state_dir.join("tasks/run_1.json"),
            serde_json::to_string_pretty(&json!({
                "runId": "run_1",
                "agentgresTransition": {
                    "state_root_after": "sha256:previous-state-root",
                    "resulting_head": "agentgres://runtime-state/runs/run_1/head/previous"
                }
            }))
            .expect("previous transition"),
        )
        .expect("previous transition file");
        let request: RuntimeRunStateCommitBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "commit_runtime_run_state",
            "backend": "rust_agentgres_storage",
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_run_state_commit.v1",
                "run_id": "run_1",
                "operation_kind": "run.cancel",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "run": {
                    "id": "run_1",
                    "agentId": "agent_1",
                    "status": "canceled",
                    "mode": "send",
                    "objective": "Ship the runtime state slice",
                    "createdAt": "2026-06-04T00:00:00.000Z",
                    "updatedAt": "2026-06-04T00:00:01.000Z",
                    "events": [
                        { "type": "started" },
                        { "type": "canceled" }
                    ],
                    "receipts": [
                        {
                            "id": "receipt_cancel",
                            "kind": "run_cancel"
                        }
                    ],
                    "artifacts": [],
                    "trace": {
                        "traceBundleId": "trace_bundle_1",
                        "taskState": {
                            "state": "canceled"
                        },
                        "postconditions": [],
                        "semanticImpact": {
                            "impact": "local"
                        },
                        "stopCondition": {
                            "reason": "operator_cancel"
                        },
                        "scorecard": {
                            "score": 1
                        },
                        "qualityLedger": {
                            "entries": []
                        }
                    }
                },
                "agent": {
                    "id": "agent_1",
                    "status": "active",
                    "runtime": "local",
                    "updatedAt": "2026-06-04T00:00:01.000Z"
                },
                "canonical_projection": {
                    "runId": "run_1",
                    "projection": "canonical"
                }
            }
        }))
        .expect("runtime run-state commit bridge request");

        let response = commit_runtime_run_state(request).expect("run state committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_run_state_commit_command"
        );
        assert_eq!(
            response["transition"]["expected_heads"][0],
            "agentgres://runtime-state/runs/run_1/head/previous"
        );
        assert_eq!(
            response["transition"]["state_root_before"],
            "sha256:previous-state-root"
        );
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir.join("tasks/run_1.json").exists());
        assert!(state_dir.join("agents/agent_1.json").exists());
        let agent_record =
            fs::read_to_string(state_dir.join("agents/agent_1.json")).expect("agent record");
        assert!(agent_record.contains("\"id\": \"agent_1\""));
        let task_record =
            fs::read_to_string(state_dir.join("tasks/run_1.json")).expect("task record");
        assert!(task_record.contains("\"agentgresTransition\""));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_run_state_commit"));
    }

    #[test]
    fn bridge_commits_runtime_agent_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeAgentStateCommitBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "commit_runtime_agent_state",
            "backend": "rust_agentgres_storage",
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_agent_state_commit.v1",
                "agent_id": "agent_1",
                "operation_kind": "agent.create",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "agent": {
                    "id": "agent_1",
                    "status": "active",
                    "runtime": "local",
                    "updated_at": "2026-06-06T00:00:00.000Z",
                    "receipt_refs": ["receipt_agent"]
                }
            }
        }))
        .expect("runtime agent-state commit bridge request");

        let response = commit_runtime_agent_state(request).expect("agent state committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_agent_state_commit_command"
        );
        assert_eq!(response["agent_id"], "agent_1");
        assert_eq!(response["operation_kind"], "agent.create");
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir.join("agents/agent_1.json").exists());
        let agent_record =
            fs::read_to_string(state_dir.join("agents/agent_1.json")).expect("agent record");
        assert!(agent_record.contains("\"id\": \"agent_1\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://runtime-state/agents/agent_1/records/agents/agent_1.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_agent_state_commit"));
    }

    #[test]
    fn bridge_commits_runtime_memory_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeMemoryStateCommitBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "commit_runtime_memory_state",
            "backend": "rust_agentgres_storage",
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_memory_state_commit.v1",
                "memory_state_kind": "record",
                "state_id": "memory_1",
                "operation_kind": "memory.write",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "payload": {
                    "schemaVersion": "ioi.agent-runtime.memory.v1",
                    "id": "memory_1",
                    "object": "ioi.agent_memory_record",
                    "fact": "Remember the launch checklist.",
                    "threadId": "thread_1",
                    "agentId": "agent_1",
                    "receipt_refs": ["receipt_memory"]
                }
            }
        }))
        .expect("runtime memory-state commit bridge request");

        let response = commit_runtime_memory_state(request).expect("memory state committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_memory_state_commit_command"
        );
        assert_eq!(response["memory_state_kind"], "record");
        assert_eq!(response["state_id"], "memory_1");
        assert_eq!(response["operation_kind"], "memory.write");
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir.join("memory-records/memory_1.json").exists());
        let memory_record = fs::read_to_string(state_dir.join("memory-records/memory_1.json"))
            .expect("memory record");
        assert!(memory_record.contains("\"id\": \"memory_1\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://runtime-state/memory/record/memory_1/records/memory-records/memory_1.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_memory_state_commit"));
    }

    #[test]
    fn bridge_commits_runtime_subagent_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeSubagentStateCommitBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "commit_runtime_subagent_state",
            "backend": "rust_agentgres_storage",
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_subagent_state_commit.v1",
                "subagent_id": "subagent_1",
                "operation_kind": "subagent.wait",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "subagent": {
                    "subagent_id": "subagent_1",
                    "parent_thread_id": "thread_1",
                    "agent_id": "agent_1",
                    "role": "research",
                    "lifecycle_status": "completed",
                    "updated_at": "2026-06-06T00:00:00.000Z",
                    "receipt_refs": ["receipt_subagent"]
                }
            }
        }))
        .expect("runtime subagent-state commit bridge request");

        let response = commit_runtime_subagent_state(request).expect("subagent state committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_subagent_state_commit_command"
        );
        assert_eq!(response["subagent_id"], "subagent_1");
        assert_eq!(response["operation_kind"], "subagent.wait");
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir.join("subagents/subagent_1.json").exists());
        let subagent_record = fs::read_to_string(state_dir.join("subagents/subagent_1.json"))
            .expect("subagent record");
        assert!(subagent_record.contains("\"subagent_id\": \"subagent_1\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://runtime-state/subagents/subagent_1/records/subagents/subagent_1.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_subagent_state_commit"));
    }

    #[test]
    fn bridge_commits_runtime_artifact_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeArtifactStateCommitBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "commit_runtime_artifact_state",
            "backend": "rust_agentgres_storage",
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_artifact_state_commit.v1",
                "artifact_id": "artifact_1",
                "operation_kind": "artifact.coding_tool_draft",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "artifact": {
                    "schema_version": "ioi.runtime.coding-tool-artifact.v1",
                    "id": "artifact_1",
                    "thread_id": "thread_1",
                    "tool_name": "file.read",
                    "tool_call_id": "tool_call_1",
                    "channel": "stdout",
                    "media_type": "text/plain",
                    "receipt_id": "receipt_artifact",
                    "content": "hello",
                    "content_bytes": 5,
                    "content_hash": "sha256:content"
                }
            }
        }))
        .expect("runtime artifact-state commit bridge request");

        let response = commit_runtime_artifact_state(request).expect("artifact state committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_artifact_state_commit_command"
        );
        assert_eq!(response["artifact_id"], "artifact_1");
        assert_eq!(response["operation_kind"], "artifact.coding_tool_draft");
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir.join("artifacts/artifact_1.json").exists());
        let artifact_record = fs::read_to_string(state_dir.join("artifacts/artifact_1.json"))
            .expect("artifact record");
        assert!(artifact_record.contains("\"id\": \"artifact_1\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://runtime-state/artifacts/artifact_1/records/artifacts/artifact_1.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_artifact_state_commit"));
    }

    #[test]
    fn bridge_commits_runtime_model_mount_record_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeModelMountRecordStateCommitBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "commit_runtime_model_mount_record_state",
                "backend": "rust_agentgres_storage",
                "state_dir": state_dir,
                "request": {
                    "schema_version": "ioi.runtime_model_mount_record_state_commit.v1",
                    "record_dir": "provider-health",
                    "record_id": "health.provider_openai",
                    "operation_kind": "model_mount.provider_health.write",
                    "storage_backend_ref": "storage://runtime-agentgres/local-json",
                    "record": {
                        "id": "health.provider_openai",
                        "provider_id": "provider.openai",
                        "status": "available",
                        "checked_at": "2026-06-04T00:00:00.000Z",
                        "receipt_id": "receipt_provider_health",
                        "evidence_refs": ["provider_http_health"]
                    }
                }
            }))
            .expect("runtime model-mount record-state commit bridge request");

        let response =
            commit_runtime_model_mount_record_state(request).expect("model-mount record committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_model_mount_record_state_commit_command"
        );
        assert_eq!(response["record_dir"], "provider-health");
        assert_eq!(response["record_id"], "health.provider_openai");
        assert_eq!(
            response["operation_kind"],
            "model_mount.provider_health.write"
        );
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir
            .join("provider-health/health.provider_openai.json")
            .exists());
        let health_record =
            fs::read_to_string(state_dir.join("provider-health/health.provider_openai.json"))
                .expect("provider health record");
        assert!(health_record.contains("\"id\": \"health.provider_openai\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://model-mounting/records/provider-health/health.provider_openai/records/provider-health/health.provider_openai.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_model_mount_record_state_commit"));
    }

    #[test]
    fn bridge_commits_runtime_model_mount_receipt_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeModelMountReceiptStateCommitBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "commit_runtime_model_mount_receipt_state",
                "backend": "rust_agentgres_storage",
                "state_dir": state_dir,
                "request": {
                    "schema_version": "ioi.runtime_model_mount_receipt_state_commit.v1",
                    "receipt_id": "receipt_model_invocation",
                    "operation_kind": "model_mount.receipt.write",
                    "storage_backend_ref": "storage://runtime-agentgres/local-json",
                    "receipt": {
                        "id": "receipt_model_invocation",
                        "kind": "model_invocation",
                        "redaction": "redacted",
                        "evidenceRefs": ["rust_receipt_binder_core", "rust_agentgres_admission"],
                        "details": {
                            "model_mount_receipt_binding_ref": "sha256:binding",
                            "model_mount_accepted_receipt_append_hash": "sha256:append",
                            "model_mount_agentgres_operation_ref": "agentgres://model-mounting/accepted-receipts/op_1",
                            "model_mount_agentgres_admission_hash": "sha256:agentgres"
                        }
                    }
                }
            }))
            .expect("runtime model-mount receipt-state commit bridge request");

        let response = commit_runtime_model_mount_receipt_state(request)
            .expect("model-mount receipt committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_model_mount_receipt_state_commit_command"
        );
        assert_eq!(response["receipt_id"], "receipt_model_invocation");
        assert_eq!(response["operation_kind"], "model_mount.receipt.write");
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir
            .join("receipts/receipt_model_invocation.json")
            .exists());
        let receipt_record =
            fs::read_to_string(state_dir.join("receipts/receipt_model_invocation.json"))
                .expect("model-mount receipt record");
        assert!(receipt_record.contains("\"id\": \"receipt_model_invocation\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://model-mounting/receipts/receipt_model_invocation/records/receipts/receipt_model_invocation.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_model_mount_receipt_state_commit"));
    }

    #[test]
    fn workspace_status_reads_git_porcelain_status() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        run_test_git(&workspace, &["init"]);
        run_test_git(&workspace, &["config", "user.email", "test@example.com"]);
        run_test_git(&workspace, &["config", "user.name", "IOI Test"]);
        fs::write(workspace.join("README.md"), "before\n").expect("fixture file");
        run_test_git(&workspace, &["add", "README.md"]);
        run_test_git(&workspace, &["commit", "-m", "initial"]);
        fs::write(workspace.join("README.md"), "after\n").expect("updated file");
        fs::write(workspace.join("new.txt"), "new\n").expect("new file");

        let result = inspect_workspace_status(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "includeIgnored": true
            }),
        )
        .expect("status result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["git"]["available"], true);
        assert!(
            result["git"]["branch"]
                .as_str()
                .expect("branch")
                .contains("main")
                || result["git"]["branch"]
                    .as_str()
                    .expect("branch")
                    .contains("master")
        );
        assert!(result["changedFiles"]
            .as_array()
            .expect("changed files")
            .iter()
            .any(|entry| entry["path"] == "README.md"));
        assert!(result["changedFiles"]
            .as_array()
            .expect("changed files")
            .iter()
            .any(|entry| entry["path"] == "new.txt" && entry["status"] == "??"));
        assert_eq!(result["counts"]["changed"], 2);
        assert_eq!(result["counts"]["untracked"], 1);
        assert_eq!(
            result["git"]["porcelainHash"].as_str().expect("hash").len(),
            64
        );
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn workspace_status_reports_not_git_repository_without_failing_step() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");

        let result = inspect_workspace_status(workspace.to_str().expect("utf8 path"), &json!({}))
            .expect("status result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["git"]["available"], false);
        assert_eq!(result["git"]["status"], "not_git_repository");
        assert_eq!(result["changedFiles"], json!([]));
        assert_eq!(result["counts"]["changed"], 0);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn test_run_node_test_reports_passed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(
            workspace.join("passing.test.mjs"),
            "import test from 'node:test';\nimport assert from 'node:assert/strict';\ntest('passes', () => assert.equal(1, 1));\n",
        )
        .expect("fixture file");

        let result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.test",
                "path": "passing.test.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("test result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["commandId"], "node.test");
        assert_eq!(result["command"], "node --test");
        assert_eq!(result["args"], json!(["--test", "passing.test.mjs"]));
        assert_eq!(result["testStatus"], "passed");
        assert_eq!(result["exitCode"], 0);
        assert_eq!(result["timedOut"], false);
        assert_eq!(result["shellFallbackUsed"], false);
        assert_eq!(result["outputHash"].as_str().expect("hash").len(), 64);
    }

    #[test]
    fn test_run_node_test_reports_failure() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(
            workspace.join("failing.test.mjs"),
            "import test from 'node:test';\nimport assert from 'node:assert/strict';\ntest('fails', () => assert.equal(1, 2));\n",
        )
        .expect("fixture file");

        let result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.test",
                "path": "failing.test.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("test result");

        assert_eq!(result["commandId"], "node.test");
        assert_eq!(result["testStatus"], "failed");
        assert_ne!(result["exitCode"], 0);
        assert_eq!(result["timedOut"], false);
    }

    #[cfg(unix)]
    #[test]
    fn test_run_npm_test_uses_sanitized_env_and_extra_args() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let bin = temp.path().join("bin");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::create_dir(&bin).expect("bin dir");
        write_fake_executable(
            &bin.join("npm"),
            "#!/bin/sh\nif [ -n \"$SECRET_TOKEN\" ]; then exit 7; fi\nif [ -n \"$NODE_TEST_CONTEXT\" ]; then exit 8; fi\necho fake npm \"$@\"\n",
        );
        let path_env = format!(
            "{}:{}",
            bin.to_string_lossy(),
            std::env::var("PATH").unwrap_or_default()
        );

        let result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "npm.test",
                "args": ["--", "unit"],
                "timeoutMs": 5000,
                "env": {
                    "PATH": path_env,
                    "SECRET_TOKEN": "must-not-leak",
                    "NODE_TEST_CONTEXT": "must-not-leak"
                }
            }),
        )
        .expect("test result");

        assert_eq!(result["commandId"], "npm.test");
        assert_eq!(result["command"], "npm test");
        assert_eq!(result["executable"], "npm");
        assert_eq!(result["args"], json!(["test", "--", "unit"]));
        assert_eq!(result["testStatus"], "passed");
        assert!(result["stdout"]
            .as_str()
            .expect("stdout")
            .contains("fake npm test -- unit"));
    }

    #[cfg(unix)]
    #[test]
    fn test_run_cargo_backends_use_rust_live_command_mapping() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let bin = temp.path().join("bin");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::create_dir(&bin).expect("bin dir");
        write_fake_executable(
            &bin.join("cargo"),
            "#!/bin/sh\nif [ -n \"$SECRET_TOKEN\" ]; then exit 7; fi\necho fake cargo \"$@\"\n",
        );
        let path_env = format!(
            "{}:{}",
            bin.to_string_lossy(),
            std::env::var("PATH").unwrap_or_default()
        );

        let check_result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "cargo.check",
                "timeoutMs": 5000,
                "env": {
                    "PATH": path_env,
                    "SECRET_TOKEN": "must-not-leak"
                }
            }),
        )
        .expect("cargo check result");
        let test_result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "cargo.test",
                "timeoutMs": 5000,
                "env": {
                    "PATH": path_env,
                    "SECRET_TOKEN": "must-not-leak"
                }
            }),
        )
        .expect("cargo test result");

        assert_eq!(check_result["command"], "cargo check");
        assert_eq!(check_result["args"], json!(["check"]));
        assert_eq!(check_result["testStatus"], "passed");
        assert!(check_result["stdout"]
            .as_str()
            .expect("stdout")
            .contains("fake cargo check"));
        assert_eq!(test_result["command"], "cargo test");
        assert_eq!(test_result["args"], json!(["test"]));
        assert_eq!(test_result["testStatus"], "passed");
        assert!(test_result["stdout"]
            .as_str()
            .expect("stdout")
            .contains("fake cargo test"));
    }

    #[test]
    fn test_run_disallowed_command_fails_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");

        let error = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "python.test"
            }),
        )
        .expect_err("unknown command should fail closed");

        assert_eq!(error.code, "test_run_command_not_allowed");
    }

    #[test]
    fn file_apply_patch_writes_and_binds_agentgres_admission() {
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
        assert_eq!(response["workload_observation"]["result"]["changed"], true);
        assert_eq!(
            response["router_admission"]["authoritative_transition"],
            true
        );
        assert_eq!(
            response["workload_dispatch"]["schema_version"],
            WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION,
        );
        assert_eq!(
            response["workload_dispatch"]["module_ref"],
            "file.apply_patch"
        );
        assert_eq!(response["workload_dispatch"]["transport"], "workload_grpc");
        assert!(response["workload_dispatch"]["evidence_refs"]
            .as_array()
            .expect("workload dispatch evidence")
            .iter()
            .any(|value| value == "rust_workload_client_step_module_dispatch"));
        assert!(response["result"]["workflow_projection"]["evidence_refs"]
            .as_array()
            .expect("projection evidence")
            .iter()
            .any(|value| value == "rust_workload_client_step_module_dispatch"));
        assert_eq!(
            response["result"]["agentgres_operation_refs"][0],
            response["agentgres_admission"]["operation_ref"],
        );
        assert!(response["result"]["state_root_after"]
            .as_str()
            .expect("state root")
            .starts_with("state://workspace/"));
        assert!(response["receipt_binding"]["expected_heads"]
            .as_array()
            .expect("expected heads")
            .first()
            .and_then(Value::as_str)
            .expect("expected head")
            .starts_with("head://workspace/"));
        assert_eq!(
            response["agentgres_admission"]["state_root_after"],
            response["result"]["state_root_after"],
        );
        assert_eq!(
            response["projection_record"]["status"],
            response["result"]["workflow_projection"]["status"],
        );
    }

    #[test]
    fn file_apply_patch_dry_run_has_no_agentgres_transition() {
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
        assert_eq!(response["workload_observation"]["result"]["changed"], true);
        assert_eq!(
            response["router_admission"]["authoritative_transition"],
            true
        );
        assert_eq!(response["result"]["agentgres_operation_refs"], json!([]));
        assert_eq!(response["agentgres_admission"], Value::Null);
        assert_eq!(response["result"]["state_root_after"], Value::Null);
    }

    #[test]
    fn artifact_read_uses_prefetched_data_plane_payload() {
        let request = bridge_request(
            "artifact.read",
            "/tmp",
            json!({
                "artifactId": "artifact_alpha",
                "rustWorkloadDataPlane": {
                    "schemaVersion": "ioi.runtime.coding-tool-data-plane.v1",
                    "source": "daemon_artifact_store",
                    "operation": "artifact.read",
                    "artifactId": "artifact_alpha",
                    "result": {
                        "schemaVersion": "ioi.runtime.coding-tool-result.v1",
                        "artifactId": "artifact_alpha",
                        "artifactRef": "artifact_alpha",
                        "artifactRefs": ["artifact_alpha"],
                        "content": "hello artifact\n",
                        "contentHash": "prefetch-hash",
                        "fullContentHash": "full-hash",
                        "offsetBytes": 0,
                        "lengthBytes": 15,
                        "totalBytes": 15,
                        "truncated": false,
                        "receiptRefs": ["receipt_artifact_prefetch"],
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
            response["workload_observation"]["result"]["dataPlaneSource"],
            "daemon_artifact_store"
        );
        assert_eq!(
            response["workload_observation"]["result"]["shellFallbackUsed"],
            false
        );
        assert_eq!(
            response["workload_observation"]["result"]["contentHash"]
                .as_str()
                .expect("content hash")
                .len(),
            64
        );
        assert_ne!(
            response["workload_observation"]["result"]["contentHash"],
            "prefetch-hash"
        );
        assert_eq!(
            response["result"]["artifact_refs"],
            json!(["artifact_alpha"])
        );
        assert!(response["result"]["receipt_refs"]
            .as_array()
            .expect("receipt refs")
            .iter()
            .any(|value| value == "receipt_artifact_prefetch"));
        assert_eq!(response["agentgres_admission"], Value::Null);
        assert_eq!(
            response["projection_record"]["status"],
            response["result"]["workflow_projection"]["status"],
        );
    }

    #[test]
    fn tool_retrieve_result_uses_prefetched_data_plane_payload() {
        let request = bridge_request(
            "tool.retrieve_result",
            "/tmp",
            json!({
                "toolCallId": "tool_patch",
                "channel": "stdout",
                "rustWorkloadDataPlane": {
                    "schemaVersion": "ioi.runtime.coding-tool-data-plane.v1",
                    "source": "daemon_artifact_store",
                    "operation": "tool.retrieve_result",
                    "query": {
                        "toolCallId": "tool_patch",
                        "channel": "stdout"
                    },
                    "result": {
                        "schemaVersion": "ioi.runtime.coding-tool-result.v1",
                        "toolCallId": "tool_patch",
                        "artifactId": "artifact_result",
                        "artifactRef": "artifact_result",
                        "artifactRefs": ["artifact_result"],
                        "channel": "stdout",
                        "content": "stored stdout\n",
                        "contentHash": "prefetch-hash",
                        "fullContentHash": "full-hash",
                        "availableArtifacts": [{
                            "artifactId": "artifact_result",
                            "channel": "stdout"
                        }],
                        "receiptRefs": ["receipt_tool_result_prefetch"],
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
            response["workload_observation"]["result"]["toolCallId"],
            "tool_patch"
        );
        assert_eq!(
            response["workload_observation"]["result"]["contentHash"]
                .as_str()
                .expect("content hash")
                .len(),
            64
        );
        assert_eq!(
            response["result"]["artifact_refs"],
            json!(["artifact_result"])
        );
        assert!(response["result"]["receipt_refs"]
            .as_array()
            .expect("receipt refs")
            .iter()
            .any(|value| value == "receipt_tool_result_prefetch"));
        assert_eq!(response["agentgres_admission"], Value::Null);
    }

    #[test]
    fn artifact_read_requires_prefetched_data_plane_payload() {
        let request = bridge_request(
            "artifact.read",
            "/tmp",
            json!({
                "artifactId": "artifact_alpha"
            }),
        );

        let error = artifact_read_response(request).expect_err("missing payload should fail");

        assert_eq!(error.code, "data_plane_payload_required");
    }

    #[test]
    fn computer_use_request_lease_records_wallet_gated_act_request() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Open the browser and click the sign in button.",
                "lane": "native_browser",
                "session_mode": "controlled_relaunch",
                "action_kind": "click",
                "url": "https://example.test"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["lane"],
            "native_browser"
        );
        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["authority_scope"],
            "computer_use.native_browser.act"
        );
        assert_eq!(
            response["workload_observation"]["result"]["approval_required_before_execution"],
            true
        );
        assert_eq!(
            response["workload_observation"]["result"]["wallet_network_authority_boundary"]
                ["authority_layer"],
            "wallet.network"
        );
        assert_eq!(
            response["workload_observation"]["result"]["thread_tool"]["tool_name"],
            "ioi.computer_use.native_browser"
        );
        assert!(response["workload_observation"]["result"]["request_ref"]
            .as_str()
            .expect("request ref")
            .starts_with("computer_use_lease_request_"));
        assert!(response["result"]["receipt_refs"]
            .as_array()
            .expect("receipt refs")
            .iter()
            .any(|value| {
                value
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("receipt_computer_use_lease_request_")
            }));
        assert_eq!(response["agentgres_admission"], Value::Null);
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_lane_alias() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the lane through a retired alias.",
                "computerUseLane": "sandboxed_hosted",
                "action_kind": "inspect"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["lane"],
            "native_browser"
        );
        assert_eq!(
            response["workload_observation"]["result"]["thread_tool"]["tool_name"],
            "ioi.computer_use.native_browser"
        );
        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["authority_scope"],
            "computer_use.native_browser.read"
        );
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_action_kind_alias() {
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

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["action_kind"],
            "inspect"
        );
        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["authority_scope"],
            "computer_use.native_browser.read"
        );
        assert_eq!(
            response["workload_observation"]["result"]["approval_required_before_execution"],
            false
        );
        assert_eq!(
            response["workload_observation"]["result"]["wallet_network_authority_boundary"]
                ["required_before_execution"],
            false
        );
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_approval_alias() {
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

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["authority_scope"],
            "computer_use.native_browser.act"
        );
        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["approval_ref"],
            Value::Null
        );
        assert_eq!(
            response["workload_observation"]["result"]["approval_required_before_execution"],
            true
        );
        assert_eq!(
            response["workload_observation"]["result"]["wallet_network_authority_boundary"]
                ["required_before_execution"],
            true
        );
    }

    #[test]
    fn computer_use_request_lease_records_unavailable_provider_fail_closed() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Open a hosted sandbox.",
                "lane": "sandboxed_hosted",
                "session_mode": "hosted_sandbox",
                "sandbox_provider": "local_container",
                "action_kind": "inspect"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["provider_id"],
            "ioi.computer_use.sandboxed_hosted.local_container"
        );
        assert_eq!(
            response["workload_observation"]["result"]["thread_tool"]["tool_name"],
            Value::Null
        );
        assert!(
            response["workload_observation"]["result"]["thread_tool"]["unavailable_reason"]
                .as_str()
                .expect("unavailable reason")
                .contains("no container runtime adapter")
        );
        assert_eq!(
            response["workload_observation"]["result"]["approval_required_before_execution"],
            false
        );
        assert_eq!(response["agentgres_admission"], Value::Null);
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_provider_aliases() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the provider through retired aliases.",
                "lane": "sandboxed_hosted",
                "session_mode": "local_sandbox",
                "sandboxProvider": "local_container",
                "providerKind": "local_container",
                "action_kind": "inspect"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["provider_id"],
            "ioi.computer_use.sandboxed_hosted.local_fixture"
        );
        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["provider_kind"],
            "local_fixture"
        );
        assert_eq!(
            response["workload_observation"]["result"]["thread_tool"]["tool_name"],
            "ioi.computer_use.sandboxed_hosted"
        );
        assert_eq!(
            response["workload_observation"]["result"]["thread_tool"]["unavailable_reason"],
            Value::Null
        );
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_target_ref_alias() {
        let retired_alias_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the target through a retired alias.",
                "lane": "native_browser",
                "action_kind": "inspect",
                "targetRef": "target_retired"
            }),
        );
        let baseline_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the target through a retired alias.",
                "lane": "native_browser",
                "action_kind": "inspect"
            }),
        );

        let retired_alias_response = computer_use_request_lease_response(retired_alias_request)
            .expect("retired alias lease request response");
        let baseline_response =
            computer_use_request_lease_response(baseline_request).expect("baseline response");

        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["request_ref"],
            baseline_response["workload_observation"]["result"]["request_ref"]
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["thread_tool"]["input"]
                ["target_ref"],
            Value::Null
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["lease_request"]
                ["authority_scope"],
            "computer_use.native_browser.read"
        );
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_session_mode_alias() {
        let retired_alias_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the session mode through a retired alias.",
                "lane": "sandboxed_hosted",
                "sessionMode": "hosted_sandbox",
                "action_kind": "inspect"
            }),
        );
        let baseline_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the session mode through a retired alias.",
                "lane": "sandboxed_hosted",
                "action_kind": "inspect"
            }),
        );

        let retired_alias_response = computer_use_request_lease_response(retired_alias_request)
            .expect("retired alias lease request response");
        let baseline_response =
            computer_use_request_lease_response(baseline_request).expect("baseline response");

        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["request_ref"],
            baseline_response["workload_observation"]["result"]["request_ref"]
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["lease_request"]
                ["session_mode"],
            "local_sandbox"
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["thread_tool"]["input"]
                ["session_mode"],
            "local_sandbox"
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["thread_tool"]["tool_name"],
            "ioi.computer_use.sandboxed_hosted"
        );
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_observation_retention_alias() {
        let retired_alias_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer retention through a retired alias.",
                "lane": "native_browser",
                "action_kind": "inspect",
                "observationRetentionMode": "local_raw_artifacts"
            }),
        );
        let canonical_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Use canonical retention.",
                "lane": "native_browser",
                "action_kind": "inspect",
                "observation_retention_mode": "local_raw_artifacts"
            }),
        );

        let retired_alias_response = computer_use_request_lease_response(retired_alias_request)
            .expect("retired alias lease request response");
        let canonical_response =
            computer_use_request_lease_response(canonical_request).expect("canonical response");

        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["thread_tool"]["input"]
                ["observation_retention_mode"],
            "prompt_visible_summary_only"
        );
        assert_eq!(
            canonical_response["workload_observation"]["result"]["thread_tool"]["input"]
                ["observation_retention_mode"],
            "local_raw_artifacts"
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["lease_request"]
                ["authority_scope"],
            "computer_use.native_browser.read"
        );
    }

    #[test]
    fn computer_use_request_lease_binds_canonical_receipt_and_request_refs() {
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
            "workspaceRoot",
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
        for retired_field in [
            "sessionMode",
            "actionKind",
            "authorityScope",
            "repoAuthorityScope",
            "sharedClipboardPolicy",
            "artifactPolicy",
            "approvalRef",
            "failClosedWhenUnavailable",
            "providerId",
            "providerKind",
            "walletNetworkAuthorityRequiredBeforeExecution",
        ] {
            assert!(
                workload_result["lease_request"]
                    .get(retired_field)
                    .is_none(),
                "retired lease_request field {retired_field} must not be emitted"
            );
        }
        for retired_field in ["toolPack", "toolName", "unavailableReason"] {
            assert!(
                workload_result["thread_tool"].get(retired_field).is_none(),
                "retired thread_tool field {retired_field} must not be emitted"
            );
        }
        for retired_field in [
            "actionKind",
            "sessionMode",
            "targetRef",
            "approvalRef",
            "observationRetentionMode",
        ] {
            assert!(
                workload_result["thread_tool"]["input"]
                    .get(retired_field)
                    .is_none(),
                "retired thread_tool input field {retired_field} must not be emitted"
            );
        }
    }

    #[test]
    fn lsp_diagnostics_node_check_reports_clean_javascript() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("ok.mjs"), "const value = 1;\n").expect("fixture file");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.check",
                "path": "ok.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["backend"], "node.check");
        assert_eq!(result["resolvedCommandId"], "node.check");
        assert_eq!(result["diagnosticStatus"], "clean");
        assert_eq!(result["diagnosticCount"], 0);
        assert_eq!(result["paths"], json!(["ok.mjs"]));
        assert_eq!(result["exitCode"], 0);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn lsp_diagnostics_node_check_reports_syntax_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("broken.mjs"), "const = ;\n").expect("fixture file");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.check",
                "path": "broken.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["backend"], "node.check");
        assert_eq!(result["diagnosticStatus"], "findings");
        assert_eq!(result["diagnosticCount"], 1);
        assert_ne!(result["exitCode"], 0);
        assert_eq!(result["diagnostics"][0]["path"], "broken.mjs");
        assert_eq!(result["diagnostics"][0]["severity"], "error");
    }

    #[test]
    fn lsp_diagnostics_auto_routes_javascript_to_node_check() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("ok.mjs"), "const value = 1;\n").expect("fixture file");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "auto",
                "path": "ok.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["backend"], "node.check");
        assert_eq!(result["resolvedCommandId"], "node.check");
        assert_eq!(result["diagnosticStatus"], "clean");
        assert_eq!(result["fallbackUsed"], false);
    }

    #[cfg(unix)]
    #[test]
    fn lsp_diagnostics_typescript_check_reports_tsc_diagnostic() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let source_dir = workspace.join("src");
        let bin = workspace.join("node_modules").join(".bin");
        fs::create_dir_all(&source_dir).expect("source dir");
        fs::create_dir_all(&bin).expect("bin dir");
        fs::write(
            workspace.join("tsconfig.json"),
            r#"{"compilerOptions":{"strict":true},"include":["src/**/*.ts"]}"#,
        )
        .expect("tsconfig");
        fs::write(
            source_dir.join("broken.ts"),
            "const value: number = 'oops';\n",
        )
        .expect("ts fixture");
        write_fake_executable(
            &bin.join("tsc"),
            "#!/bin/sh\necho \"src/broken.ts(1,7): error TS2322: Type 'string' is not assignable to type 'number'.\"\nexit 2\n",
        );

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "typescript.check",
                "path": "src/broken.ts",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["backend"], "typescript.project.check");
        assert_eq!(result["resolvedCommandId"], "typescript.check");
        assert_eq!(
            result["command"],
            "tsc --noEmit --pretty false -p tsconfig.json"
        );
        assert_eq!(result["backendStatus"], "available");
        assert_eq!(result["diagnosticStatus"], "findings");
        assert_eq!(result["diagnosticCount"], 1);
        assert_eq!(result["diagnostics"][0]["path"], "src/broken.ts");
        assert_eq!(result["diagnostics"][0]["code"], "TS2322");
        assert_eq!(result["diagnostics"][0]["line"], 1);
        assert_eq!(result["diagnostics"][0]["column"], 7);
        assert_eq!(result["projectContext"]["tsconfigPath"], "tsconfig.json");
        assert_eq!(result["projectContext"]["tscAvailable"], true);
    }

    #[test]
    fn lsp_diagnostics_auto_typescript_degrades_without_local_tsc() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let source_dir = workspace.join("src");
        fs::create_dir_all(&source_dir).expect("source dir");
        fs::write(
            workspace.join("tsconfig.json"),
            r#"{"compilerOptions":{"strict":true},"include":["src/**/*.ts"]}"#,
        )
        .expect("tsconfig");
        fs::write(
            source_dir.join("broken.ts"),
            "const value: number = 'oops';\n",
        )
        .expect("ts fixture");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "auto",
                "path": "src/broken.ts",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["backend"], "typescript.project.check");
        assert_eq!(result["resolvedCommandId"], "typescript.check");
        assert_eq!(result["backendStatus"], "degraded");
        assert_eq!(result["backendReason"], "typescript_executable_missing");
        assert_eq!(result["diagnosticStatus"], "degraded");
        assert_eq!(result["projectContext"]["tscAvailable"], false);
        assert_eq!(result["fallbackUsed"], false);
    }

    #[test]
    fn git_diff_reads_bounded_workspace_diff() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        run_test_git(&workspace, &["init"]);
        run_test_git(&workspace, &["config", "user.email", "test@example.com"]);
        run_test_git(&workspace, &["config", "user.name", "IOI Test"]);
        fs::write(workspace.join("README.md"), "before\n").expect("fixture file");
        run_test_git(&workspace, &["add", "README.md"]);
        run_test_git(&workspace, &["commit", "-m", "initial"]);
        fs::write(workspace.join("README.md"), "before\nafter\n").expect("updated file");

        let result = inspect_git_diff(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "path": "README.md",
                "maxBytes": 4096
            }),
        )
        .expect("diff result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["paths"], json!(["README.md"]));
        assert_eq!(result["git"]["available"], true);
        assert!(result["diff"].as_str().expect("diff").contains("+after"));
        assert!(result["stat"].as_str().expect("stat").contains("README.md"));
        assert_eq!(result["diffHash"].as_str().expect("hash").len(), 64);
        assert_eq!(result["truncated"], false);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn git_diff_rejects_paths_outside_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");

        let error = inspect_git_diff(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "path": "../outside.txt"
            }),
        )
        .expect_err("outside path should fail");

        assert_eq!(error.code, "path_outside_workspace");
    }

    #[test]
    fn file_inspect_reads_workspace_file_preview() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("README.md"), "# IOI\nsecond line\n").expect("fixture file");

        let result = inspect_workspace_path(
            workspace.to_str().expect("utf8 path"),
            "README.md",
            &json!({
                "maxBytes": 128,
                "previewLines": 1
            }),
        )
        .expect("inspect result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["path"], "README.md");
        assert_eq!(result["kind"], "file");
        assert_eq!(result["preview"], "# IOI");
        assert_eq!(result["previewLineCount"], 1);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn file_inspect_rejects_paths_outside_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(temp.path().join("outside.txt"), "outside").expect("outside fixture");

        let error = inspect_workspace_path(
            workspace.to_str().expect("utf8 path"),
            "../outside.txt",
            &json!({}),
        )
        .expect_err("outside path should fail");

        assert_eq!(error.code, "path_outside_workspace");
    }

    fn run_test_git(workspace: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(workspace)
            .args(args)
            .output()
            .expect("git command");
        assert!(
            output.status.success(),
            "git {:?} failed: {}{}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn bridge_request(
        tool_id: &str,
        workspace_root: &str,
        input: Value,
    ) -> StepModuleBridgeRequest {
        let invocation = serde_json::from_value(json!({
            "schema_version": "ioi.step_module_invocation.v1",
            "invocation_id": format!("invocation://test/{tool_id}"),
            "run_id": "run:test",
            "task_id": "task:test",
            "thread_id": "thread:test",
            "workflow_graph_id": "graph:test",
            "workflow_node_id": format!("node:test:{tool_id}"),
            "context_chamber_ref": null,
            "action_proposal_ref": format!("action:test:{tool_id}"),
            "gate_result_ref": format!("gate:test:{tool_id}"),
            "module_ref": {
                "kind": "workload_job",
                "id": tool_id,
                "version": "test",
                "manifest_ref": null
            },
            "actor": {
                "actor_id": "runtime:hypervisor-daemon",
                "runtime_node_ref": "node://local"
            },
            "authority": {
                "authority_grant_refs": [],
                "policy_hash": "sha256:policy",
                "primitive_capabilities": ["prim:fs.apply_patch", "prim:fs.write"],
                "authority_scopes": ["scope:workspace.write"],
                "approval_ref": "approval:test"
            },
            "input": {
                "input_hash": "sha256:input",
                "expected_schema_ref": format!("schema://coding-tool/{tool_id}/input"),
                "context_refs": [],
                "artifact_refs": [],
                "payload_refs": [],
                "state_root_before": null,
                "projection_watermark": null,
                "data_plane_handle": null
            },
            "custody": {
                "privacy_profile": "internal",
                "plaintext_policy": {
                    "node_plaintext_allowed": true,
                    "declassification_required": false
                },
                "custody_proof_ref": null,
                "leakage_profile_ref": null
            },
            "execution": {
                "backend": "workload_grpc",
                "idempotency_key": format!("idempotency:test:{tool_id}"),
                "deadline_ms": 60000,
                "resource_lease_ref": null,
                "retry_policy_ref": null
            }
        }))
        .expect("test invocation");
        StepModuleBridgeRequest {
            schema_version: COMMAND_SCHEMA_VERSION.to_string(),
            operation: "run_coding_tool_step_module".to_string(),
            backend: "rust_workload_live".to_string(),
            invocation,
            workspace_root: Some(workspace_root.to_string()),
            input,
        }
    }

    #[cfg(unix)]
    fn write_fake_executable(path: &Path, content: &str) {
        fs::write(path, content).expect("fake executable");
        let mut permissions = fs::metadata(path)
            .expect("fake executable metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("fake executable permissions");
    }
}
