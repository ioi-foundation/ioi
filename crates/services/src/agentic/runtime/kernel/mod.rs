//! Shared bounded-runtime kernel primitives.
//!
//! New runtime code should use chat/artifact, graph, workflow, connector, and
//! plugin language. Legacy surface names are treated as compatibility debt.

pub mod agentgres_admission;
pub mod agentgres_protocol;
pub mod approval;
pub mod authority;
pub mod capability;
pub mod coding_tool_artifact;
pub mod coding_tool_computer_use;
pub mod coding_tool_event;
pub mod coding_tool_execution;
pub mod coding_tool_step_module;
pub mod coding_tool_workspace;
pub mod ctee;
pub mod deadline;
pub mod evidence;
pub mod governed_admission;
pub mod governed_receipt;
pub mod inference;
pub mod intent;
pub mod intervention;
pub mod invocation;
pub mod marketplace;
pub mod model_mount;
pub mod model_mount_receipt;
pub mod plan;
pub mod policy;
pub mod profile;
pub mod projection;
pub mod receipt_binder;
pub mod repository_workflow;
pub mod runtime_computer_use;
pub mod runtime_conversation_artifact_control;
pub mod runtime_conversation_artifact_projection;
pub mod runtime_diagnostics_repair_control;
pub mod runtime_diagnostics_repair_policy;
pub mod runtime_diagnostics_repair_projection;
pub mod runtime_doctor_report;
pub mod runtime_lifecycle;
pub mod runtime_managed_session_control;
pub mod runtime_mcp_serve;
pub mod runtime_memory_control;
pub mod runtime_memory_projection;
pub mod runtime_subagent_control;
pub mod runtime_subagent_projection;
pub mod runtime_thread_event;
pub mod runtime_thread_fork_control;
pub mod runtime_tool_catalog;
pub mod runtime_workflow_edit_control;
pub mod runtime_workspace_change_control;
pub mod scope;
pub mod settlement;
pub mod skill_hook_registry;
pub mod step_module;
pub mod step_router;
pub mod studio_intent_frame;
pub mod trace;
pub mod workspace_restore;

use agentgres_admission::{
    AgentgresAdmissionCore, AgentgresAdmissionError, AgentgresAdmissionRecord,
    AgentgresOperationProposal, RuntimeAgentStateCommitRecord, RuntimeAgentStateCommitRequest,
    RuntimeArtifactStateCommitRecord, RuntimeArtifactStateCommitRequest,
    RuntimeMemoryStateCommitRecord, RuntimeMemoryStateCommitRequest,
    RuntimeModelMountReceiptStateCommitRecord, RuntimeModelMountReceiptStateCommitRequest,
    RuntimeModelMountRecordStateCommitRecord, RuntimeModelMountRecordStateCommitRequest,
    RuntimeRunStateCommitRecord, RuntimeRunStateCommitRequest,
    RuntimeRunStatePersistedCommitRecord, RuntimeStatePersistenceRecord,
    RuntimeStatePersistenceRequest, RuntimeStateRecordMaterializationRecord,
    RuntimeStateRecordMaterializationRequest, RuntimeStateStorageWriteRecord,
    RuntimeStateStorageWriteSetRecord, RuntimeStateStorageWriteSetRequest,
    RuntimeStateTransitionRecord, RuntimeStateTransitionRequest, RuntimeStateWrittenRecord,
    RuntimeSubagentStateCommitRecord, RuntimeSubagentStateCommitRequest,
    StorageBackendWriteAdmissionRecord, StorageBackendWriteProposal,
};
use approval::{
    ApprovalDecisionAuthorityCore, ApprovalDecisionAuthorityError, ApprovalDecisionAuthorityRecord,
    ApprovalDecisionAuthorityRequest, ApprovalDecisionStateUpdateCore,
    ApprovalDecisionStateUpdateError, ApprovalDecisionStateUpdateRecord,
    ApprovalDecisionStateUpdateRequest, ApprovalQueueProjectionCore, ApprovalQueueProjectionError,
    ApprovalQueueProjectionRecord, ApprovalQueueProjectionRequest, ApprovalRequestAuthorityCore,
    ApprovalRequestAuthorityError, ApprovalRequestAuthorityRecord, ApprovalRequestAuthorityRequest,
    ApprovalRequestStateUpdateCore, ApprovalRequestStateUpdateError,
    ApprovalRequestStateUpdateRecord, ApprovalRequestStateUpdateRequest,
    ApprovalRevokeStateUpdateCore, ApprovalRevokeStateUpdateError, ApprovalRevokeStateUpdateRecord,
    ApprovalRevokeStateUpdateRequest, ApprovalScopeContext, AuthorityScopeMatcher,
    CodingToolApprovalBlockCore, CodingToolApprovalBlockError, CodingToolApprovalBlockRecord,
    CodingToolApprovalBlockRequest, CodingToolApprovalCore, CodingToolApprovalError,
    CodingToolApprovalPlan, CodingToolApprovalRequest, CodingToolApprovalSatisfactionCore,
    CodingToolApprovalSatisfactionError, CodingToolApprovalSatisfactionProjectionCore,
    CodingToolApprovalSatisfactionProjectionError, CodingToolApprovalSatisfactionProjectionRecord,
    CodingToolApprovalSatisfactionProjectionRequest, CodingToolApprovalSatisfactionRecord,
    CodingToolApprovalSatisfactionRequest, ScopeMatchDecision,
};
use authority::{
    ExternalCapabilityExitAuthorityRecord, ExternalCapabilityExitRequest, WalletAuthorityCore,
    WalletAuthorityError,
};
use capability::CapabilityLeaseDecision;
use coding_tool_artifact::{
    plan_runtime_coding_tool_artifact_drafts, project_runtime_coding_tool_artifact_read,
    RuntimeCodingToolArtifactDraftPlanCommandError, RuntimeCodingToolArtifactDraftPlanRequest,
    RuntimeCodingToolArtifactReadProjectionCommandError,
    RuntimeCodingToolArtifactReadProjectionRequest,
};
use coding_tool_event::{
    CodingToolCommandStreamAdmissionCore, CodingToolCommandStreamAdmissionError,
    CodingToolCommandStreamAdmissionRecord, CodingToolCommandStreamAdmissionRequest,
    CodingToolResultEnvelopePlanCore, CodingToolResultEnvelopePlanError,
    CodingToolResultEnvelopePlanRecord, CodingToolResultEnvelopePlanRequest,
    CodingToolResultEventAdmissionCore, CodingToolResultEventAdmissionError,
    CodingToolResultEventAdmissionRecord, CodingToolResultEventAdmissionRequest,
    PostEditDiagnosticsFeedbackPlanCore, PostEditDiagnosticsFeedbackPlanError,
    PostEditDiagnosticsFeedbackPlanRecord, PostEditDiagnosticsFeedbackPlanRequest,
};
use coding_tool_step_module::{
    run_coding_tool_step_module, CodingToolStepModuleRunError, CodingToolStepModuleRunRequest,
};
use ctee::{
    CteeNodeTrust, CteePrivateWorkspaceError, CteePrivateWorkspaceExecutionRecord,
    CteePrivateWorkspaceReceipt, PrivateWorkspaceCteeModule,
};
use evidence::ReceiptManifestKind;
use invocation::ToolInvocationEnvelope;
use marketplace::{
    MarketplaceAdmissionError, MarketplaceServiceContract, WorkerServicePackageInvocationCore,
    WorkerServicePackageInvocationRecord, WorkerServicePackageInvocationRequest,
};
use model_mount::{
    plan_model_mount_backend_lifecycle, plan_model_mount_backend_process,
    plan_model_mount_conversation_state, plan_model_mount_route_control_required,
    plan_model_mount_stream_cancel, plan_model_mount_stream_completion, plan_model_mount_tokenizer,
    plan_model_mount_tokenizer_required, ModelMountAcceptedReceiptHeadRequest,
    ModelMountAcceptedReceiptTransitionRequest, ModelMountArtifactEndpointPlan,
    ModelMountArtifactEndpointRequest, ModelMountBackendLifecycleRequest,
    ModelMountBackendProcessPlanRequest, ModelMountCapabilityTokenControlPlan,
    ModelMountCapabilityTokenControlRequest, ModelMountCatalogProviderControlPlan,
    ModelMountCatalogProviderControlRequest, ModelMountConversationStateRequest, ModelMountCore,
    ModelMountError, ModelMountInstanceLifecycleRequest, ModelMountInstanceLifecycleResult,
    ModelMountInvocationAdmissionRecord, ModelMountInvocationAdmissionRequest,
    ModelMountMcpWorkflowPlan, ModelMountMcpWorkflowRequest, ModelMountProviderControlPlan,
    ModelMountProviderControlRequest, ModelMountProviderExecutionRecord,
    ModelMountProviderExecutionRequest, ModelMountProviderInventoryRequest,
    ModelMountProviderInventoryResult, ModelMountProviderInvocationRequest,
    ModelMountProviderInvocationResult, ModelMountProviderLifecycleRequest,
    ModelMountProviderLifecycleResult, ModelMountProviderResultAdmissionRecord,
    ModelMountProviderResultAdmissionRequest, ModelMountProviderStreamInvocationResult,
    ModelMountReadProjectionError, ModelMountReadProjectionPlan, ModelMountReadProjectionRequest,
    ModelMountReceiptGatePlan, ModelMountReceiptGateRequest, ModelMountRouteControlPlan,
    ModelMountRouteControlRequest, ModelMountRouteControlRequiredRequest,
    ModelMountRouteDecisionRecord, ModelMountRouteDecisionRequest, ModelMountRuntimeEnginePlan,
    ModelMountRuntimeEngineRequest, ModelMountRuntimeSurveyPlan, ModelMountRuntimeSurveyRequest,
    ModelMountStorageControlPlan, ModelMountStorageControlRequest, ModelMountStreamCancelRequest,
    ModelMountStreamCompletionRequest, ModelMountTokenizerRequest,
    ModelMountTokenizerRequiredRequest, ModelMountVaultControlPlan, ModelMountVaultControlRequest,
};
use model_mount_receipt::{
    bind_model_mount_invocation_receipt, plan_model_mount_accepted_receipt_head,
    plan_model_mount_accepted_receipt_transition, ModelMountInvocationReceiptBindingRequest,
    ModelMountReceiptError,
};
use plan::{validate_plan, ExecutablePlan, PlanValidationError};
use policy::{
    AgentCreateStateUpdateCore, AgentCreateStateUpdateError, AgentCreateStateUpdateRecord,
    AgentCreateStateUpdateRequest, AgentDeleteStateUpdateCore, AgentDeleteStateUpdateError,
    AgentDeleteStateUpdateRecord, AgentDeleteStateUpdateRequest, AgentStatusStateUpdateCore,
    AgentStatusStateUpdateError, AgentStatusStateUpdateRecord, AgentStatusStateUpdateRequest,
    CodingToolBudgetBlockCore, CodingToolBudgetBlockError, CodingToolBudgetBlockRecord,
    CodingToolBudgetBlockRequest, CodingToolBudgetRecoveryControlCore,
    CodingToolBudgetRecoveryControlError, CodingToolBudgetRecoveryControlRecord,
    CodingToolBudgetRecoveryControlRequest, CodingToolBudgetRecoveryStateUpdateCore,
    CodingToolBudgetRecoveryStateUpdateError, CodingToolBudgetRecoveryStateUpdateRecord,
    CodingToolBudgetRecoveryStateUpdateRequest, CompactionPolicyCore, CompactionPolicyError,
    CompactionPolicyRecord, CompactionPolicyRequest, ContextBudgetPolicyCore,
    ContextBudgetPolicyError, ContextBudgetPolicyRecord, ContextBudgetPolicyRequest,
    ContextCompactionPlanCore, ContextCompactionPlanError, ContextCompactionPlanRecord,
    ContextCompactionPlanRequest, ContextCompactionStateUpdateCore,
    ContextCompactionStateUpdateError, ContextCompactionStateUpdateRecord,
    ContextCompactionStateUpdateRequest, DiagnosticsOperatorOverrideStateUpdateCore,
    DiagnosticsOperatorOverrideStateUpdateError, DiagnosticsOperatorOverrideStateUpdateRecord,
    DiagnosticsOperatorOverrideStateUpdateRequest, DiagnosticsRepairAdmissionRequiredCore,
    DiagnosticsRepairAdmissionRequiredError, DiagnosticsRepairAdmissionRequiredRecord,
    DiagnosticsRepairAdmissionRequiredRequest, LifecycleAdmissionRequiredCore,
    LifecycleAdmissionRequiredError, LifecycleAdmissionRequiredRecord,
    LifecycleAdmissionRequiredRequest, McpControlAgentStateUpdateCore,
    McpControlAgentStateUpdateError, McpControlAgentStateUpdateRecord,
    McpControlAgentStateUpdateRequest, McpLiveResultReplayCore, McpLiveResultReplayError,
    McpLiveResultReplayRecord, McpLiveResultReplayRequest, McpManagerCatalogProjectionCore,
    McpManagerCatalogProjectionError, McpManagerCatalogProjectionRecord,
    McpManagerCatalogProjectionRequest, McpManagerCatalogSummaryProjectionCore,
    McpManagerCatalogSummaryProjectionError, McpManagerCatalogSummaryProjectionRecord,
    McpManagerCatalogSummaryProjectionRequest, McpManagerStatusProjectionCore,
    McpManagerStatusProjectionError, McpManagerStatusProjectionRecord,
    McpManagerStatusProjectionRequest, McpManagerValidationProjectionCore,
    McpManagerValidationProjectionError, McpManagerValidationProjectionRecord,
    McpManagerValidationProjectionRequest, McpServerValidationCore, McpServerValidationError,
    McpServerValidationInputCore, McpServerValidationInputError, McpServerValidationInputRecord,
    McpServerValidationInputRequest, McpServerValidationRecord, McpServerValidationRequest,
    McpToolFetchProjectionCore, McpToolFetchProjectionRecord, McpToolFetchProjectionRequest,
    McpToolProjectionError, McpToolSearchProjectionCore, McpToolSearchProjectionRecord,
    McpToolSearchProjectionRequest, MemoryManagerStatusProjectionCore,
    MemoryManagerStatusProjectionError, MemoryManagerStatusProjectionRecord,
    MemoryManagerStatusProjectionRequest, MemoryManagerValidationProjectionCore,
    MemoryManagerValidationProjectionError, MemoryManagerValidationProjectionRecord,
    MemoryManagerValidationProjectionRequest, OperatorInterruptStateUpdateCore,
    OperatorInterruptStateUpdateError, OperatorInterruptStateUpdateRecord,
    OperatorInterruptStateUpdateRequest, OperatorSteerStateUpdateCore,
    OperatorSteerStateUpdateError, OperatorSteerStateUpdateRecord, OperatorSteerStateUpdateRequest,
    OperatorTurnControlAdmissionRequiredCore, OperatorTurnControlAdmissionRequiredError,
    OperatorTurnControlAdmissionRequiredRecord, OperatorTurnControlAdmissionRequiredRequest,
    RunCancelAdmissionRequiredCore, RunCancelAdmissionRequiredError,
    RunCancelAdmissionRequiredRecord, RunCancelAdmissionRequiredRequest, RunCancelStateUpdateCore,
    RunCancelStateUpdateError, RunCancelStateUpdateRecord, RunCancelStateUpdateRequest,
    RunCreateStateUpdateCore, RunCreateStateUpdateError, RunCreateStateUpdateRecord,
    RunCreateStateUpdateRequest, RuntimeBridgeThreadControlAgentStateUpdateCore,
    RuntimeBridgeThreadControlAgentStateUpdateError,
    RuntimeBridgeThreadControlAgentStateUpdateRecord,
    RuntimeBridgeThreadControlAgentStateUpdateRequest,
    RuntimeBridgeThreadStartAgentStateUpdateCore, RuntimeBridgeThreadStartAgentStateUpdateError,
    RuntimeBridgeThreadStartAgentStateUpdateRecord,
    RuntimeBridgeThreadStartAgentStateUpdateRequest, RuntimeBridgeTurnRunStateUpdateCore,
    RuntimeBridgeTurnRunStateUpdateError, RuntimeBridgeTurnRunStateUpdateRecord,
    RuntimeBridgeTurnRunStateUpdateRequest, RuntimeTaskJobCancelStateUpdateCore,
    RuntimeTaskJobCancelStateUpdateError, RuntimeTaskJobCancelStateUpdateRecord,
    RuntimeTaskJobCancelStateUpdateRequest, RuntimeTaskJobCreateStateUpdateCore,
    RuntimeTaskJobCreateStateUpdateError, RuntimeTaskJobCreateStateUpdateRecord,
    RuntimeTaskJobCreateStateUpdateRequest, RuntimeTaskJobProjectionCore,
    RuntimeTaskJobProjectionError, RuntimeTaskJobProjectionRecord, RuntimeTaskJobProjectionRequest,
    SubagentRecordStateUpdateCore, SubagentRecordStateUpdateError, SubagentRecordStateUpdateRecord,
    SubagentRecordStateUpdateRequest, ThreadControlAgentStateUpdateCore,
    ThreadControlAgentStateUpdateError, ThreadControlAgentStateUpdateRecord,
    ThreadControlAgentStateUpdateRequest, ThreadCreateStateUpdateCore,
    ThreadCreateStateUpdateError, ThreadCreateStateUpdateRecord, ThreadCreateStateUpdateRequest,
    ThreadMemoryAgentStateUpdateCore, ThreadMemoryAgentStateUpdateError,
    ThreadMemoryAgentStateUpdateRecord, ThreadMemoryAgentStateUpdateRequest,
    ThreadTurnAdmissionRequiredCore, ThreadTurnAdmissionRequiredError,
    ThreadTurnAdmissionRequiredRecord, ThreadTurnAdmissionRequiredRequest,
    WorkflowEditAdmissionRequiredCore, WorkflowEditAdmissionRequiredError,
    WorkflowEditAdmissionRequiredRecord, WorkflowEditAdmissionRequiredRequest,
    WorkspaceTrustControlStateUpdateCore, WorkspaceTrustControlStateUpdateError,
    WorkspaceTrustControlStateUpdateRecord, WorkspaceTrustControlStateUpdateRequest,
};
use profile::{RuntimeProfileConfig, RuntimeProfileValidator, RuntimeProfileViolation};
use projection::{ProjectionError, RustProjectionCore, StepModuleProjectionRecord};
use receipt_binder::{
    AcceptedReceiptAppendRecord, AcceptedReceiptAppendRequest, ReceiptBinder, ReceiptBindingError,
    StepModuleReceiptBinding,
};
use repository_workflow::{
    RepositoryWorkflowProjectionRequest, RepositoryWorkflowProjectionError,
    RepositoryWorkflowProjectionCore, RepositoryWorkflowProjectionRecord,
};
use runtime_computer_use::{
    RuntimeComputerUseProjectionCommandError, RuntimeComputerUseProjectionCore,
    RuntimeComputerUseProjectionRecord, RuntimeComputerUseProjectionRequest,
};
use runtime_conversation_artifact_control::{
    RuntimeConversationArtifactControlCommandError, RuntimeConversationArtifactControlCore,
    RuntimeConversationArtifactControlRecord, RuntimeConversationArtifactControlRequest,
};
use runtime_conversation_artifact_projection::{
    RuntimeConversationArtifactProjectionCommandError, RuntimeConversationArtifactProjectionCore,
    RuntimeConversationArtifactProjectionRecord, RuntimeConversationArtifactProjectionRequest,
};
use runtime_diagnostics_repair_control::{
    RuntimeDiagnosticsRepairControlCommandError, RuntimeDiagnosticsRepairControlCore,
    RuntimeDiagnosticsRepairControlRecord, RuntimeDiagnosticsRepairControlRequest,
    RuntimeDiagnosticsRepairRetryResultProjectionCore,
    RuntimeDiagnosticsRepairRetryResultProjectionRecord,
    RuntimeDiagnosticsRepairRetryResultProjectionRequest, RuntimeDiagnosticsRepairRetryRunCore,
    RuntimeDiagnosticsRepairRetryRunRecord, RuntimeDiagnosticsRepairRetryRunRequest,
};
use runtime_diagnostics_repair_policy::{
    RuntimeDiagnosticsRepairPolicyCommandError, RuntimeDiagnosticsRepairPolicyCore,
    RuntimeDiagnosticsRepairPolicyRecord, RuntimeDiagnosticsRepairPolicyRequest,
};
use runtime_diagnostics_repair_projection::{
    RuntimeDiagnosticsRepairProjectionCommandError, RuntimeDiagnosticsRepairProjectionCore,
    RuntimeDiagnosticsRepairProjectionRecord, RuntimeDiagnosticsRepairProjectionRequest,
};
use runtime_doctor_report::{
    RuntimeDoctorReportProjectionCommandError, RuntimeDoctorReportProjectionCore,
    RuntimeDoctorReportProjectionRecord, RuntimeDoctorReportProjectionRequest,
};
use runtime_lifecycle::{
    RuntimeLifecycleProjectionRequest, RuntimeLifecycleProjectionError,
    RuntimeLifecycleProjectionCore, RuntimeLifecycleProjectionRecord,
};
use runtime_managed_session_control::{
    RuntimeManagedSessionCommandError, RuntimeManagedSessionControlCore,
    RuntimeManagedSessionControlRecord, RuntimeManagedSessionControlRequest,
    RuntimeManagedSessionProjectionCore, RuntimeManagedSessionProjectionRecord,
    RuntimeManagedSessionProjectionRequest,
};
use runtime_mcp_serve::{
    RuntimeMcpServeError, RuntimeMcpServeToolCallPlanCore, RuntimeMcpServeToolCallPlanRecord,
    RuntimeMcpServeToolCallPlanRequest, RuntimeMcpServeToolResultProjectionRecord,
    RuntimeMcpServeToolResultProjectionRequest,
};
use runtime_memory_control::{
    RuntimeMemoryControlCommandError, RuntimeMemoryControlCore, RuntimeMemoryControlRecord,
    RuntimeMemoryControlRequest,
};
use runtime_memory_projection::{
    RuntimeMemoryProjectionBridgeRequest, RuntimeMemoryProjectionCommandError,
    RuntimeMemoryProjectionCore, RuntimeMemoryProjectionRecord,
};
use runtime_subagent_control::{
    RuntimeSubagentControlCommandError, RuntimeSubagentControlCore, RuntimeSubagentControlRecord,
    RuntimeSubagentControlRequest,
};
use runtime_subagent_projection::{
    RuntimeSubagentProjectionCommandError, RuntimeSubagentProjectionCore,
    RuntimeSubagentProjectionRecord, RuntimeSubagentProjectionRequest,
};
use runtime_thread_event::{
    RuntimeThreadEventAdmissionCore, RuntimeThreadEventAdmissionError,
    RuntimeThreadEventAdmissionRecord, RuntimeThreadEventAdmissionRequest,
    RuntimeThreadEventProjectionRecord, RuntimeThreadEventProjectionRequest,
    RuntimeThreadEventReplayRecord, RuntimeThreadEventReplayRequest,
    RuntimeThreadTurnProjectionRecord, RuntimeThreadTurnProjectionRequest,
};
use runtime_thread_fork_control::{
    RuntimeThreadForkCommandError, RuntimeThreadForkControlCore, RuntimeThreadForkControlRecord,
    RuntimeThreadForkControlRequest,
};
use runtime_tool_catalog::{
    RuntimeToolCatalogProjectionRequest, RuntimeToolCatalogProjectionError,
    RuntimeToolCatalogProjectionCore, RuntimeToolCatalogProjectionRecord,
};
use runtime_workflow_edit_control::{
    RuntimeWorkflowEditControlCommandError, RuntimeWorkflowEditControlCore,
    RuntimeWorkflowEditControlRecord, RuntimeWorkflowEditControlRequest,
};
use runtime_workspace_change_control::{
    RuntimeWorkspaceChangeCommandError, RuntimeWorkspaceChangeControlCore,
    RuntimeWorkspaceChangeControlRecord, RuntimeWorkspaceChangeControlRequest,
    RuntimeWorkspaceChangeProjectionCore, RuntimeWorkspaceChangeProjectionRecord,
    RuntimeWorkspaceChangeProjectionRequest,
};
use settlement::{
    ArtifactPromotionReceipt, L1SettlementAdmissionError, L1SettlementAdmissionRecord,
    L1SettlementAttempt, L1SettlementTriggerGuard, PromotionValidationError,
    SettlementReceiptBundleV2,
};
use skill_hook_registry::{
    SkillHookRegistryProjectionError, SkillHookRegistryProjectionCore,
    SkillHookRegistryProjectionRecord, SkillHookRegistryProjectionRequest,
};
use step_module::{StepModuleInvocation, StepModuleResult, StepModuleValidationError};
use step_router::{
    StepModuleExecutionAdmissionRecord, StepModuleRouterCore, StepModuleRouterError,
};
use studio_intent_frame::{
    StudioIntentFrameProjectionCore, StudioIntentFrameProjectionError,
    StudioIntentFrameProjectionRecord, StudioIntentFrameProjectionRequest,
};
use workspace_restore::{
    apply_workspace_snapshot_restore_protocol_response,
    preview_workspace_snapshot_restore_protocol_response,
    project_workspace_snapshot_content_package_protocol_response,
    project_workspace_snapshot_list_protocol_response, WorkspaceRestoreApplyPolicyCore,
    WorkspaceRestoreApplyPolicyError, WorkspaceRestoreApplyPolicyPlan,
    WorkspaceRestoreApplyPolicyRequest, WorkspaceRestoreOperationError,
    WorkspaceRestoreOperationRecord, WorkspaceRestoreOperationsCore,
    WorkspaceRestoreOperationsRequest, WorkspaceSnapshotCaptureCore,
    WorkspaceSnapshotCaptureRequest, WorkspaceSnapshotCaptureResult,
    WorkspaceSnapshotContentPackageProtocolRequest, WorkspaceSnapshotListProtocolRequest,
    WorkspaceSnapshotRestoreProtocolRequest,
};

use ioi_types::app::ApprovalAuthority;

#[derive(Debug, Default, Clone)]
pub struct RuntimeKernelService;

impl RuntimeKernelService {
    pub fn new() -> Self {
        Self
    }

    pub fn validate_plan(&self, plan: &ExecutablePlan) -> Result<(), Vec<PlanValidationError>> {
        validate_plan(plan)
    }

    pub fn validate_approval_scope(
        &self,
        authority: &ApprovalAuthority,
        context: &ApprovalScopeContext,
    ) -> ScopeMatchDecision {
        AuthorityScopeMatcher::evaluate(authority, context)
    }

    pub fn plan_coding_tool_approval_manifest(
        &self,
        request: &CodingToolApprovalRequest,
    ) -> Result<CodingToolApprovalPlan, CodingToolApprovalError> {
        CodingToolApprovalCore.plan_manifest(request)
    }

    pub fn plan_coding_tool_approval_satisfaction(
        &self,
        request: &CodingToolApprovalSatisfactionRequest,
    ) -> Result<CodingToolApprovalSatisfactionRecord, CodingToolApprovalSatisfactionError> {
        CodingToolApprovalSatisfactionCore.plan(request)
    }

    pub fn project_coding_tool_approval_satisfaction(
        &self,
        request: &CodingToolApprovalSatisfactionProjectionRequest,
    ) -> Result<
        CodingToolApprovalSatisfactionProjectionRecord,
        CodingToolApprovalSatisfactionProjectionError,
    > {
        CodingToolApprovalSatisfactionProjectionCore.project(request)
    }

    pub fn plan_coding_tool_approval_block(
        &self,
        request: &CodingToolApprovalBlockRequest,
    ) -> Result<CodingToolApprovalBlockRecord, CodingToolApprovalBlockError> {
        CodingToolApprovalBlockCore.plan(request)
    }

    pub fn project_approval_queue(
        &self,
        request: &ApprovalQueueProjectionRequest,
    ) -> Result<ApprovalQueueProjectionRecord, ApprovalQueueProjectionError> {
        ApprovalQueueProjectionCore.project(request)
    }

    pub fn authorize_approval_request(
        &self,
        request: &ApprovalRequestAuthorityRequest,
    ) -> Result<ApprovalRequestAuthorityRecord, ApprovalRequestAuthorityError> {
        ApprovalRequestAuthorityCore.authorize(request)
    }

    pub fn authorize_approval_decision(
        &self,
        request: &ApprovalDecisionAuthorityRequest,
    ) -> Result<ApprovalDecisionAuthorityRecord, ApprovalDecisionAuthorityError> {
        ApprovalDecisionAuthorityCore.authorize(request)
    }

    pub fn admit_coding_tool_result_event(
        &self,
        request: &CodingToolResultEventAdmissionRequest,
    ) -> Result<CodingToolResultEventAdmissionRecord, CodingToolResultEventAdmissionError> {
        CodingToolResultEventAdmissionCore.admit(request)
    }

    pub fn plan_coding_tool_result_envelope(
        &self,
        request: &CodingToolResultEnvelopePlanRequest,
    ) -> Result<CodingToolResultEnvelopePlanRecord, CodingToolResultEnvelopePlanError> {
        CodingToolResultEnvelopePlanCore.plan(request)
    }

    pub fn plan_runtime_coding_tool_artifact_drafts(
        &self,
        request: &RuntimeCodingToolArtifactDraftPlanRequest,
    ) -> Result<serde_json::Value, RuntimeCodingToolArtifactDraftPlanCommandError> {
        plan_runtime_coding_tool_artifact_drafts(request)
    }

    pub fn project_runtime_coding_tool_artifact_read(
        &self,
        request: &RuntimeCodingToolArtifactReadProjectionRequest,
    ) -> Result<serde_json::Value, RuntimeCodingToolArtifactReadProjectionCommandError> {
        project_runtime_coding_tool_artifact_read(request)
    }

    pub fn admit_coding_tool_command_stream_events(
        &self,
        request: &CodingToolCommandStreamAdmissionRequest,
    ) -> Result<CodingToolCommandStreamAdmissionRecord, CodingToolCommandStreamAdmissionError> {
        CodingToolCommandStreamAdmissionCore.admit(request)
    }

    pub fn admit_runtime_thread_event(
        &self,
        request: &RuntimeThreadEventAdmissionRequest,
    ) -> Result<RuntimeThreadEventAdmissionRecord, RuntimeThreadEventAdmissionError> {
        RuntimeThreadEventAdmissionCore.admit(request)
    }

    pub fn project_runtime_thread_events(
        &self,
        request: &RuntimeThreadEventProjectionRequest,
    ) -> Result<RuntimeThreadEventProjectionRecord, RuntimeThreadEventAdmissionError> {
        RuntimeThreadEventAdmissionCore.project(request)
    }

    pub fn project_runtime_thread_event_replay(
        &self,
        request: &RuntimeThreadEventReplayRequest,
    ) -> Result<RuntimeThreadEventReplayRecord, RuntimeThreadEventAdmissionError> {
        RuntimeThreadEventAdmissionCore.replay(request)
    }

    pub fn project_runtime_thread_turn_projection(
        &self,
        request: &RuntimeThreadTurnProjectionRequest,
    ) -> Result<RuntimeThreadTurnProjectionRecord, RuntimeThreadEventAdmissionError> {
        RuntimeThreadEventAdmissionCore.project_thread_turn(request)
    }

    pub fn plan_post_edit_diagnostics_feedback(
        &self,
        request: &PostEditDiagnosticsFeedbackPlanRequest,
    ) -> Result<PostEditDiagnosticsFeedbackPlanRecord, PostEditDiagnosticsFeedbackPlanError> {
        PostEditDiagnosticsFeedbackPlanCore.plan(request)
    }

    pub fn plan_approval_request_state_update(
        &self,
        request: &ApprovalRequestStateUpdateRequest,
    ) -> Result<ApprovalRequestStateUpdateRecord, ApprovalRequestStateUpdateError> {
        ApprovalRequestStateUpdateCore.plan(request)
    }

    pub fn plan_approval_decision_state_update(
        &self,
        request: &ApprovalDecisionStateUpdateRequest,
    ) -> Result<ApprovalDecisionStateUpdateRecord, ApprovalDecisionStateUpdateError> {
        ApprovalDecisionStateUpdateCore.plan(request)
    }

    pub fn plan_approval_revoke_state_update(
        &self,
        request: &ApprovalRevokeStateUpdateRequest,
    ) -> Result<ApprovalRevokeStateUpdateRecord, ApprovalRevokeStateUpdateError> {
        ApprovalRevokeStateUpdateCore.plan(request)
    }

    pub fn evaluate_context_budget_policy(
        &self,
        request: &ContextBudgetPolicyRequest,
    ) -> Result<ContextBudgetPolicyRecord, ContextBudgetPolicyError> {
        ContextBudgetPolicyCore.evaluate(request)
    }

    pub fn evaluate_coding_tool_budget_policy(
        &self,
        request: &ContextBudgetPolicyRequest,
    ) -> Result<ContextBudgetPolicyRecord, ContextBudgetPolicyError> {
        self.evaluate_context_budget_policy(request)
    }

    pub fn plan_coding_tool_budget_block(
        &self,
        request: &CodingToolBudgetBlockRequest,
    ) -> Result<CodingToolBudgetBlockRecord, CodingToolBudgetBlockError> {
        CodingToolBudgetBlockCore.plan(request)
    }

    pub fn evaluate_compaction_policy(
        &self,
        request: &CompactionPolicyRequest,
    ) -> Result<CompactionPolicyRecord, CompactionPolicyError> {
        CompactionPolicyCore.evaluate(request)
    }

    pub fn plan_context_compaction(
        &self,
        request: &ContextCompactionPlanRequest,
    ) -> Result<ContextCompactionPlanRecord, ContextCompactionPlanError> {
        ContextCompactionPlanCore.plan(request)
    }

    pub fn plan_context_compaction_state_update(
        &self,
        request: &ContextCompactionStateUpdateRequest,
    ) -> Result<ContextCompactionStateUpdateRecord, ContextCompactionStateUpdateError> {
        ContextCompactionStateUpdateCore.plan(request)
    }

    pub fn plan_coding_tool_budget_recovery_state_update(
        &self,
        request: &CodingToolBudgetRecoveryStateUpdateRequest,
    ) -> Result<CodingToolBudgetRecoveryStateUpdateRecord, CodingToolBudgetRecoveryStateUpdateError>
    {
        CodingToolBudgetRecoveryStateUpdateCore.plan(request)
    }

    pub fn plan_coding_tool_budget_recovery_control(
        &self,
        request: &CodingToolBudgetRecoveryControlRequest,
    ) -> Result<CodingToolBudgetRecoveryControlRecord, CodingToolBudgetRecoveryControlError> {
        CodingToolBudgetRecoveryControlCore.plan(request)
    }

    pub fn plan_workflow_edit_admission_required(
        &self,
        request: &WorkflowEditAdmissionRequiredRequest,
    ) -> Result<WorkflowEditAdmissionRequiredRecord, WorkflowEditAdmissionRequiredError> {
        WorkflowEditAdmissionRequiredCore.plan(request)
    }

    pub fn plan_diagnostics_repair_admission_required(
        &self,
        request: &DiagnosticsRepairAdmissionRequiredRequest,
    ) -> Result<DiagnosticsRepairAdmissionRequiredRecord, DiagnosticsRepairAdmissionRequiredError>
    {
        DiagnosticsRepairAdmissionRequiredCore.plan(request)
    }

    pub fn plan_diagnostics_operator_override_state_update(
        &self,
        request: &DiagnosticsOperatorOverrideStateUpdateRequest,
    ) -> Result<
        DiagnosticsOperatorOverrideStateUpdateRecord,
        DiagnosticsOperatorOverrideStateUpdateError,
    > {
        DiagnosticsOperatorOverrideStateUpdateCore.plan(request)
    }

    pub fn plan_operator_interrupt_state_update(
        &self,
        request: &OperatorInterruptStateUpdateRequest,
    ) -> Result<OperatorInterruptStateUpdateRecord, OperatorInterruptStateUpdateError> {
        OperatorInterruptStateUpdateCore.plan(request)
    }

    pub fn plan_operator_steer_state_update(
        &self,
        request: &OperatorSteerStateUpdateRequest,
    ) -> Result<OperatorSteerStateUpdateRecord, OperatorSteerStateUpdateError> {
        OperatorSteerStateUpdateCore.plan(request)
    }

    pub fn plan_operator_turn_control_admission_required(
        &self,
        request: &OperatorTurnControlAdmissionRequiredRequest,
    ) -> Result<OperatorTurnControlAdmissionRequiredRecord, OperatorTurnControlAdmissionRequiredError>
    {
        OperatorTurnControlAdmissionRequiredCore.plan(request)
    }

    pub fn plan_run_cancel_state_update(
        &self,
        request: &RunCancelStateUpdateRequest,
    ) -> Result<RunCancelStateUpdateRecord, RunCancelStateUpdateError> {
        RunCancelStateUpdateCore.plan(request)
    }

    pub fn plan_run_cancel_admission_required(
        &self,
        request: &RunCancelAdmissionRequiredRequest,
    ) -> Result<RunCancelAdmissionRequiredRecord, RunCancelAdmissionRequiredError> {
        RunCancelAdmissionRequiredCore.plan(request)
    }

    pub fn plan_runtime_task_job_cancel_state_update(
        &self,
        request: &RuntimeTaskJobCancelStateUpdateRequest,
    ) -> Result<RuntimeTaskJobCancelStateUpdateRecord, RuntimeTaskJobCancelStateUpdateError> {
        RuntimeTaskJobCancelStateUpdateCore.plan(request)
    }

    pub fn plan_runtime_task_job_create_state_update(
        &self,
        request: &RuntimeTaskJobCreateStateUpdateRequest,
    ) -> Result<RuntimeTaskJobCreateStateUpdateRecord, RuntimeTaskJobCreateStateUpdateError> {
        RuntimeTaskJobCreateStateUpdateCore.plan(request)
    }

    pub fn project_runtime_task_job_projection(
        &self,
        request: &RuntimeTaskJobProjectionRequest,
    ) -> Result<RuntimeTaskJobProjectionRecord, RuntimeTaskJobProjectionError> {
        RuntimeTaskJobProjectionCore.project(request)
    }

    pub fn project_skill_hook_registry(
        &self,
        request: &SkillHookRegistryProjectionRequest,
    ) -> Result<SkillHookRegistryProjectionRecord, SkillHookRegistryProjectionError> {
        SkillHookRegistryProjectionCore::default().project(request.clone())
    }

    pub fn project_repository_workflow(
        &self,
        request: &RepositoryWorkflowProjectionRequest,
    ) -> Result<RepositoryWorkflowProjectionRecord, RepositoryWorkflowProjectionError> {
        RepositoryWorkflowProjectionCore::default().project(request.clone())
    }

    pub fn project_runtime_tool_catalog(
        &self,
        request: &RuntimeToolCatalogProjectionRequest,
    ) -> Result<RuntimeToolCatalogProjectionRecord, RuntimeToolCatalogProjectionError> {
        RuntimeToolCatalogProjectionCore::default().project(request.clone())
    }

    pub fn project_runtime_lifecycle(
        &self,
        request: &RuntimeLifecycleProjectionRequest,
    ) -> Result<RuntimeLifecycleProjectionRecord, RuntimeLifecycleProjectionError> {
        RuntimeLifecycleProjectionCore::default().project(request.clone())
    }

    pub fn project_runtime_doctor_report(
        &self,
        request: &RuntimeDoctorReportProjectionRequest,
    ) -> Result<RuntimeDoctorReportProjectionRecord, RuntimeDoctorReportProjectionCommandError>
    {
        RuntimeDoctorReportProjectionCore::default().project(request.clone())
    }

    pub fn project_runtime_computer_use(
        &self,
        request: &RuntimeComputerUseProjectionRequest,
    ) -> Result<RuntimeComputerUseProjectionRecord, RuntimeComputerUseProjectionCommandError> {
        RuntimeComputerUseProjectionCore::default().project(request.clone())
    }

    pub fn project_studio_intent_frame(
        &self,
        request: &StudioIntentFrameProjectionRequest,
    ) -> Result<StudioIntentFrameProjectionRecord, StudioIntentFrameProjectionError> {
        StudioIntentFrameProjectionCore::default().project(request.clone())
    }

    pub fn project_runtime_memory_projection(
        &self,
        request: &RuntimeMemoryProjectionBridgeRequest,
    ) -> Result<RuntimeMemoryProjectionRecord, RuntimeMemoryProjectionCommandError> {
        RuntimeMemoryProjectionCore.project(request)
    }

    pub fn plan_runtime_memory_control(
        &self,
        request: &RuntimeMemoryControlRequest,
    ) -> Result<RuntimeMemoryControlRecord, RuntimeMemoryControlCommandError> {
        RuntimeMemoryControlCore.plan(request)
    }

    pub fn plan_runtime_workflow_edit_control(
        &self,
        request: &RuntimeWorkflowEditControlRequest,
    ) -> Result<RuntimeWorkflowEditControlRecord, RuntimeWorkflowEditControlCommandError> {
        RuntimeWorkflowEditControlCore.plan(request)
    }

    pub fn project_runtime_managed_session_projection(
        &self,
        request: &RuntimeManagedSessionProjectionRequest,
    ) -> Result<RuntimeManagedSessionProjectionRecord, RuntimeManagedSessionCommandError> {
        RuntimeManagedSessionProjectionCore.project(request)
    }

    pub fn plan_runtime_managed_session_control(
        &self,
        request: &RuntimeManagedSessionControlRequest,
    ) -> Result<RuntimeManagedSessionControlRecord, RuntimeManagedSessionCommandError> {
        RuntimeManagedSessionControlCore.plan(request)
    }

    pub fn project_runtime_workspace_change_projection(
        &self,
        request: &RuntimeWorkspaceChangeProjectionRequest,
    ) -> Result<RuntimeWorkspaceChangeProjectionRecord, RuntimeWorkspaceChangeCommandError> {
        RuntimeWorkspaceChangeProjectionCore.project(request)
    }

    pub fn plan_runtime_workspace_change_control(
        &self,
        request: &RuntimeWorkspaceChangeControlRequest,
    ) -> Result<RuntimeWorkspaceChangeControlRecord, RuntimeWorkspaceChangeCommandError> {
        RuntimeWorkspaceChangeControlCore.plan(request)
    }

    pub fn plan_runtime_thread_fork_control(
        &self,
        request: &RuntimeThreadForkControlRequest,
    ) -> Result<RuntimeThreadForkControlRecord, RuntimeThreadForkCommandError> {
        RuntimeThreadForkControlCore.plan(request)
    }

    pub fn plan_runtime_diagnostics_repair_control(
        &self,
        request: &RuntimeDiagnosticsRepairControlRequest,
    ) -> Result<RuntimeDiagnosticsRepairControlRecord, RuntimeDiagnosticsRepairControlCommandError>
    {
        RuntimeDiagnosticsRepairControlCore.plan(request)
    }

    pub fn plan_runtime_diagnostics_repair_retry_run(
        &self,
        request: &RuntimeDiagnosticsRepairRetryRunRequest,
    ) -> Result<RuntimeDiagnosticsRepairRetryRunRecord, RuntimeDiagnosticsRepairControlCommandError>
    {
        RuntimeDiagnosticsRepairRetryRunCore.plan(request)
    }

    pub fn project_runtime_diagnostics_repair_retry_result(
        &self,
        request: &RuntimeDiagnosticsRepairRetryResultProjectionRequest,
    ) -> Result<
        RuntimeDiagnosticsRepairRetryResultProjectionRecord,
        RuntimeDiagnosticsRepairControlCommandError,
    > {
        RuntimeDiagnosticsRepairRetryResultProjectionCore.project(request)
    }

    pub fn project_runtime_diagnostics_repair_projection(
        &self,
        request: &RuntimeDiagnosticsRepairProjectionRequest,
    ) -> Result<
        RuntimeDiagnosticsRepairProjectionRecord,
        RuntimeDiagnosticsRepairProjectionCommandError,
    > {
        RuntimeDiagnosticsRepairProjectionCore.project(request)
    }

    pub fn project_runtime_diagnostics_repair_policy(
        &self,
        request: &RuntimeDiagnosticsRepairPolicyRequest,
    ) -> Result<RuntimeDiagnosticsRepairPolicyRecord, RuntimeDiagnosticsRepairPolicyCommandError>
    {
        RuntimeDiagnosticsRepairPolicyCore.project(request)
    }

    pub fn project_runtime_conversation_artifact_projection(
        &self,
        request: &RuntimeConversationArtifactProjectionRequest,
    ) -> Result<
        RuntimeConversationArtifactProjectionRecord,
        RuntimeConversationArtifactProjectionCommandError,
    > {
        RuntimeConversationArtifactProjectionCore.project(request)
    }

    pub fn plan_runtime_conversation_artifact_control(
        &self,
        request: &RuntimeConversationArtifactControlRequest,
    ) -> Result<
        RuntimeConversationArtifactControlRecord,
        RuntimeConversationArtifactControlCommandError,
    > {
        RuntimeConversationArtifactControlCore::default().plan(request)
    }

    pub fn project_runtime_subagent_projection(
        &self,
        request: &RuntimeSubagentProjectionRequest,
    ) -> Result<RuntimeSubagentProjectionRecord, RuntimeSubagentProjectionCommandError> {
        RuntimeSubagentProjectionCore::default().project(request)
    }

    pub fn plan_runtime_subagent_control(
        &self,
        request: &RuntimeSubagentControlRequest,
    ) -> Result<RuntimeSubagentControlRecord, RuntimeSubagentControlCommandError> {
        RuntimeSubagentControlCore::default().plan(request)
    }

    pub fn plan_thread_control_agent_state_update(
        &self,
        request: &ThreadControlAgentStateUpdateRequest,
    ) -> Result<ThreadControlAgentStateUpdateRecord, ThreadControlAgentStateUpdateError> {
        ThreadControlAgentStateUpdateCore.plan(request)
    }

    pub fn plan_thread_turn_admission_required(
        &self,
        request: &ThreadTurnAdmissionRequiredRequest,
    ) -> Result<ThreadTurnAdmissionRequiredRecord, ThreadTurnAdmissionRequiredError> {
        ThreadTurnAdmissionRequiredCore.plan(request)
    }

    pub fn plan_lifecycle_admission_required(
        &self,
        request: &LifecycleAdmissionRequiredRequest,
    ) -> Result<LifecycleAdmissionRequiredRecord, LifecycleAdmissionRequiredError> {
        LifecycleAdmissionRequiredCore.plan(request)
    }

    pub fn plan_workspace_trust_control_state_update(
        &self,
        request: &WorkspaceTrustControlStateUpdateRequest,
    ) -> Result<WorkspaceTrustControlStateUpdateRecord, WorkspaceTrustControlStateUpdateError> {
        WorkspaceTrustControlStateUpdateCore.plan(request)
    }

    pub fn plan_mcp_control_agent_state_update(
        &self,
        request: &McpControlAgentStateUpdateRequest,
    ) -> Result<McpControlAgentStateUpdateRecord, McpControlAgentStateUpdateError> {
        McpControlAgentStateUpdateCore.plan(request)
    }

    pub fn project_mcp_live_result_replay(
        &self,
        request: &McpLiveResultReplayRequest,
    ) -> Result<McpLiveResultReplayRecord, McpLiveResultReplayError> {
        McpLiveResultReplayCore.project(request)
    }

    pub fn plan_runtime_mcp_serve_tool_call(
        &self,
        request: &RuntimeMcpServeToolCallPlanRequest,
    ) -> Result<RuntimeMcpServeToolCallPlanRecord, RuntimeMcpServeError> {
        RuntimeMcpServeToolCallPlanCore.plan(request)
    }

    pub fn project_runtime_mcp_serve_tool_result(
        &self,
        request: &RuntimeMcpServeToolResultProjectionRequest,
    ) -> Result<RuntimeMcpServeToolResultProjectionRecord, RuntimeMcpServeError> {
        RuntimeMcpServeToolCallPlanCore.project_result(request)
    }

    pub fn validate_mcp_servers(
        &self,
        request: &McpServerValidationRequest,
    ) -> Result<McpServerValidationRecord, McpServerValidationError> {
        McpServerValidationCore.validate(request)
    }

    pub fn project_mcp_server_validation_input(
        &self,
        request: &McpServerValidationInputRequest,
    ) -> Result<McpServerValidationInputRecord, McpServerValidationInputError> {
        McpServerValidationInputCore.project(request)
    }

    pub fn plan_mcp_manager_validation_projection(
        &self,
        request: &McpManagerValidationProjectionRequest,
    ) -> Result<McpManagerValidationProjectionRecord, McpManagerValidationProjectionError> {
        McpManagerValidationProjectionCore.project(request)
    }

    pub fn plan_mcp_manager_status_projection(
        &self,
        request: &McpManagerStatusProjectionRequest,
    ) -> Result<McpManagerStatusProjectionRecord, McpManagerStatusProjectionError> {
        McpManagerStatusProjectionCore.project(request)
    }

    pub fn plan_memory_manager_validation_projection(
        &self,
        request: &MemoryManagerValidationProjectionRequest,
    ) -> Result<MemoryManagerValidationProjectionRecord, MemoryManagerValidationProjectionError>
    {
        MemoryManagerValidationProjectionCore.project(request)
    }

    pub fn plan_memory_manager_status_projection(
        &self,
        request: &MemoryManagerStatusProjectionRequest,
    ) -> Result<MemoryManagerStatusProjectionRecord, MemoryManagerStatusProjectionError> {
        MemoryManagerStatusProjectionCore.project(request)
    }

    pub fn plan_mcp_manager_catalog_projection(
        &self,
        request: &McpManagerCatalogProjectionRequest,
    ) -> Result<McpManagerCatalogProjectionRecord, McpManagerCatalogProjectionError> {
        McpManagerCatalogProjectionCore.project(request)
    }

    pub fn plan_mcp_manager_catalog_summary_projection(
        &self,
        request: &McpManagerCatalogSummaryProjectionRequest,
    ) -> Result<McpManagerCatalogSummaryProjectionRecord, McpManagerCatalogSummaryProjectionError>
    {
        McpManagerCatalogSummaryProjectionCore.project(request)
    }

    pub fn project_mcp_tool_search_projection(
        &self,
        request: &McpToolSearchProjectionRequest,
    ) -> Result<McpToolSearchProjectionRecord, McpToolProjectionError> {
        McpToolSearchProjectionCore.project(request)
    }

    pub fn project_mcp_tool_fetch_projection(
        &self,
        request: &McpToolFetchProjectionRequest,
    ) -> Result<McpToolFetchProjectionRecord, McpToolProjectionError> {
        McpToolFetchProjectionCore.project(request)
    }

    pub fn plan_thread_memory_agent_state_update(
        &self,
        request: &ThreadMemoryAgentStateUpdateRequest,
    ) -> Result<ThreadMemoryAgentStateUpdateRecord, ThreadMemoryAgentStateUpdateError> {
        ThreadMemoryAgentStateUpdateCore.plan(request)
    }

    pub fn plan_runtime_bridge_thread_start_agent_state_update(
        &self,
        request: &RuntimeBridgeThreadStartAgentStateUpdateRequest,
    ) -> Result<
        RuntimeBridgeThreadStartAgentStateUpdateRecord,
        RuntimeBridgeThreadStartAgentStateUpdateError,
    > {
        RuntimeBridgeThreadStartAgentStateUpdateCore.plan(request)
    }

    pub fn plan_runtime_bridge_thread_control_agent_state_update(
        &self,
        request: &RuntimeBridgeThreadControlAgentStateUpdateRequest,
    ) -> Result<
        RuntimeBridgeThreadControlAgentStateUpdateRecord,
        RuntimeBridgeThreadControlAgentStateUpdateError,
    > {
        RuntimeBridgeThreadControlAgentStateUpdateCore.plan(request)
    }

    pub fn plan_runtime_bridge_turn_run_state_update(
        &self,
        request: &RuntimeBridgeTurnRunStateUpdateRequest,
    ) -> Result<RuntimeBridgeTurnRunStateUpdateRecord, RuntimeBridgeTurnRunStateUpdateError> {
        RuntimeBridgeTurnRunStateUpdateCore.plan(request)
    }

    pub fn plan_subagent_record_state_update(
        &self,
        request: &SubagentRecordStateUpdateRequest,
    ) -> Result<SubagentRecordStateUpdateRecord, SubagentRecordStateUpdateError> {
        SubagentRecordStateUpdateCore.plan(request)
    }

    pub fn plan_thread_create_state_update(
        &self,
        request: &ThreadCreateStateUpdateRequest,
    ) -> Result<ThreadCreateStateUpdateRecord, ThreadCreateStateUpdateError> {
        ThreadCreateStateUpdateCore.plan(request)
    }

    pub fn plan_agent_create_state_update(
        &self,
        request: &AgentCreateStateUpdateRequest,
    ) -> Result<AgentCreateStateUpdateRecord, AgentCreateStateUpdateError> {
        AgentCreateStateUpdateCore.plan(request)
    }

    pub fn plan_run_create_state_update(
        &self,
        request: &RunCreateStateUpdateRequest,
    ) -> Result<RunCreateStateUpdateRecord, RunCreateStateUpdateError> {
        RunCreateStateUpdateCore.plan(request)
    }

    pub fn plan_agent_status_state_update(
        &self,
        request: &AgentStatusStateUpdateRequest,
    ) -> Result<AgentStatusStateUpdateRecord, AgentStatusStateUpdateError> {
        AgentStatusStateUpdateCore.plan(request)
    }

    pub fn plan_agent_delete_state_update(
        &self,
        request: &AgentDeleteStateUpdateRequest,
    ) -> Result<AgentDeleteStateUpdateRecord, AgentDeleteStateUpdateError> {
        AgentDeleteStateUpdateCore.plan(request)
    }

    pub fn issue_capability_lease(
        &self,
        lease_hash: [u8; 32],
        scope: impl Into<String>,
        satisfied: bool,
        reason: Option<String>,
    ) -> CapabilityLeaseDecision {
        CapabilityLeaseDecision {
            lease_hash,
            satisfied,
            scope: scope.into(),
            reason,
        }
    }

    pub fn authorize_external_capability_exit(
        &self,
        request: &ExternalCapabilityExitRequest,
    ) -> Result<ExternalCapabilityExitAuthorityRecord, WalletAuthorityError> {
        WalletAuthorityCore.authorize_external_capability_exit(request)
    }

    pub fn admit_model_mount_route_decision(
        &self,
        request: &ModelMountRouteDecisionRequest,
    ) -> Result<ModelMountRouteDecisionRecord, ModelMountError> {
        ModelMountCore.admit_route_decision(request)
    }

    pub fn admit_model_mount_invocation(
        &self,
        request: &ModelMountInvocationAdmissionRequest,
    ) -> Result<ModelMountInvocationAdmissionRecord, ModelMountError> {
        ModelMountCore.admit_invocation(request)
    }

    pub fn admit_model_mount_provider_execution(
        &self,
        request: &ModelMountProviderExecutionRequest,
    ) -> Result<ModelMountProviderExecutionRecord, ModelMountError> {
        ModelMountCore.admit_provider_execution(request)
    }

    pub fn invoke_model_mount_provider(
        &self,
        request: &ModelMountProviderInvocationRequest,
    ) -> Result<ModelMountProviderInvocationResult, ModelMountError> {
        ModelMountCore.invoke_provider(request)
    }

    pub fn invoke_model_mount_provider_stream(
        &self,
        request: &ModelMountProviderInvocationRequest,
    ) -> Result<ModelMountProviderStreamInvocationResult, ModelMountError> {
        ModelMountCore.invoke_provider_stream(request)
    }

    pub fn plan_model_mount_provider_lifecycle(
        &self,
        request: &ModelMountProviderLifecycleRequest,
    ) -> Result<ModelMountProviderLifecycleResult, ModelMountError> {
        ModelMountCore.plan_provider_lifecycle(request)
    }

    pub fn plan_model_mount_provider_inventory(
        &self,
        request: &ModelMountProviderInventoryRequest,
    ) -> Result<ModelMountProviderInventoryResult, ModelMountError> {
        ModelMountCore.plan_provider_inventory(request)
    }

    pub fn plan_model_mount_instance_lifecycle(
        &self,
        request: &ModelMountInstanceLifecycleRequest,
    ) -> Result<ModelMountInstanceLifecycleResult, ModelMountError> {
        ModelMountCore.plan_instance_lifecycle(request)
    }

    pub fn admit_model_mount_provider_result(
        &self,
        request: &ModelMountProviderResultAdmissionRequest,
    ) -> Result<ModelMountProviderResultAdmissionRecord, ModelMountError> {
        ModelMountCore.admit_provider_result(request)
    }

    pub fn plan_model_mount_backend_process(
        &self,
        request: &ModelMountBackendProcessPlanRequest,
    ) -> Result<serde_json::Value, ModelMountError> {
        plan_model_mount_backend_process(request)
    }

    pub fn plan_model_mount_backend_lifecycle(
        &self,
        request: &ModelMountBackendLifecycleRequest,
    ) -> Result<serde_json::Value, ModelMountError> {
        plan_model_mount_backend_lifecycle(request)
    }

    pub fn plan_model_mount_artifact_endpoint(
        &self,
        request: &ModelMountArtifactEndpointRequest,
    ) -> Result<ModelMountArtifactEndpointPlan, ModelMountError> {
        ModelMountCore.plan_artifact_endpoint(request)
    }

    pub fn plan_model_mount_mcp_workflow(
        &self,
        request: &ModelMountMcpWorkflowRequest,
    ) -> Result<ModelMountMcpWorkflowPlan, ModelMountError> {
        ModelMountCore.plan_mcp_workflow(request)
    }

    pub fn plan_model_mount_storage_control(
        &self,
        request: &ModelMountStorageControlRequest,
    ) -> Result<ModelMountStorageControlPlan, ModelMountError> {
        ModelMountCore.plan_storage_control(request)
    }

    pub fn plan_model_mount_tokenizer_required(
        &self,
        request: &ModelMountTokenizerRequiredRequest,
    ) -> Result<serde_json::Value, ModelMountError> {
        plan_model_mount_tokenizer_required(request)
    }

    pub fn plan_model_mount_route_control_required(
        &self,
        request: &ModelMountRouteControlRequiredRequest,
    ) -> Result<serde_json::Value, ModelMountError> {
        plan_model_mount_route_control_required(request)
    }

    pub fn plan_model_mount_tokenizer(
        &self,
        request: &ModelMountTokenizerRequest,
    ) -> Result<serde_json::Value, ModelMountError> {
        plan_model_mount_tokenizer(request)
    }

    pub fn plan_model_mount_conversation_state(
        &self,
        request: &ModelMountConversationStateRequest,
    ) -> Result<serde_json::Value, ModelMountError> {
        plan_model_mount_conversation_state(request)
    }

    pub fn plan_model_mount_stream_completion(
        &self,
        request: &ModelMountStreamCompletionRequest,
    ) -> Result<serde_json::Value, ModelMountError> {
        plan_model_mount_stream_completion(request)
    }

    pub fn plan_model_mount_stream_cancel(
        &self,
        request: &ModelMountStreamCancelRequest,
    ) -> Result<serde_json::Value, ModelMountError> {
        plan_model_mount_stream_cancel(request)
    }

    pub fn plan_model_mount_route_control(
        &self,
        request: &ModelMountRouteControlRequest,
    ) -> Result<ModelMountRouteControlPlan, ModelMountError> {
        ModelMountCore.plan_route_control(request)
    }

    pub fn plan_model_mount_runtime_engine(
        &self,
        request: &ModelMountRuntimeEngineRequest,
    ) -> Result<ModelMountRuntimeEnginePlan, ModelMountError> {
        ModelMountCore.plan_runtime_engine(request)
    }

    pub fn plan_model_mount_runtime_survey(
        &self,
        request: &ModelMountRuntimeSurveyRequest,
    ) -> Result<ModelMountRuntimeSurveyPlan, ModelMountError> {
        ModelMountCore.plan_runtime_survey(request)
    }

    pub fn plan_model_mount_read_projection(
        &self,
        request: &ModelMountReadProjectionRequest,
    ) -> Result<ModelMountReadProjectionPlan, ModelMountReadProjectionError> {
        ModelMountCore.plan_read_projection(request)
    }

    pub fn plan_model_mount_catalog_provider_control(
        &self,
        request: &ModelMountCatalogProviderControlRequest,
    ) -> Result<ModelMountCatalogProviderControlPlan, ModelMountError> {
        ModelMountCore.plan_catalog_provider_control(request)
    }

    pub fn plan_model_mount_provider_control(
        &self,
        request: &ModelMountProviderControlRequest,
    ) -> Result<ModelMountProviderControlPlan, ModelMountError> {
        ModelMountCore.plan_provider_control(request)
    }

    pub fn plan_model_mount_capability_token_control(
        &self,
        request: &ModelMountCapabilityTokenControlRequest,
    ) -> Result<ModelMountCapabilityTokenControlPlan, ModelMountError> {
        ModelMountCore.plan_capability_token_control(request)
    }

    pub fn plan_model_mount_vault_control(
        &self,
        request: &ModelMountVaultControlRequest,
    ) -> Result<ModelMountVaultControlPlan, ModelMountError> {
        ModelMountCore.plan_vault_control(request)
    }

    pub fn plan_model_mount_receipt_gate(
        &self,
        request: &ModelMountReceiptGateRequest,
    ) -> Result<ModelMountReceiptGatePlan, ModelMountError> {
        ModelMountCore.plan_receipt_gate(request)
    }

    pub fn plan_model_mount_accepted_receipt_head(
        &self,
        request: &ModelMountAcceptedReceiptHeadRequest,
    ) -> Result<serde_json::Value, ModelMountReceiptError> {
        plan_model_mount_accepted_receipt_head(request)
    }

    pub fn plan_model_mount_accepted_receipt_transition(
        &self,
        request: &ModelMountAcceptedReceiptTransitionRequest,
    ) -> Result<serde_json::Value, ModelMountReceiptError> {
        plan_model_mount_accepted_receipt_transition(request)
    }

    pub fn bind_model_mount_invocation_receipt(
        &self,
        request: &ModelMountInvocationReceiptBindingRequest,
    ) -> Result<serde_json::Value, ModelMountReceiptError> {
        bind_model_mount_invocation_receipt(request)
    }

    pub fn validate_tool_invocation(
        &self,
        envelope: &ToolInvocationEnvelope,
    ) -> Result<(), String> {
        if envelope.tool_name.trim().is_empty() {
            return Err("tool_invocation_missing_tool_name".to_string());
        }
        envelope
            .base
            .required_receipt_manifest
            .verify()
            .map_err(|error| format!("tool_invocation_receipt_manifest_invalid:{error}"))?;
        if envelope.base.idempotency_key.trim().is_empty() {
            return Err("tool_invocation_missing_idempotency_key".to_string());
        }
        Ok(())
    }

    pub fn validate_step_module_invocation(
        &self,
        invocation: &StepModuleInvocation,
    ) -> Result<(), Vec<StepModuleValidationError>> {
        invocation.validate()
    }

    pub fn validate_step_module_result(
        &self,
        result: &StepModuleResult,
    ) -> Result<(), Vec<StepModuleValidationError>> {
        result.validate()
    }

    pub fn admit_step_module_execution(
        &self,
        invocation: &StepModuleInvocation,
        result: &StepModuleResult,
    ) -> Result<StepModuleExecutionAdmissionRecord, StepModuleRouterError> {
        StepModuleRouterCore.admit_execution(invocation, result)
    }

    pub fn run_coding_tool_step_module(
        &self,
        request: &CodingToolStepModuleRunRequest,
    ) -> Result<serde_json::Value, CodingToolStepModuleRunError> {
        run_coding_tool_step_module(request.clone())
    }

    pub fn bind_step_module_result(
        &self,
        invocation: &StepModuleInvocation,
        result: &StepModuleResult,
        expected_heads: Vec<String>,
    ) -> Result<StepModuleReceiptBinding, ReceiptBindingError> {
        ReceiptBinder.bind_step_module_result(invocation, result, expected_heads)
    }

    pub fn append_accepted_receipt(
        &self,
        request: &AcceptedReceiptAppendRequest,
        binding: &StepModuleReceiptBinding,
    ) -> Result<AcceptedReceiptAppendRecord, ReceiptBindingError> {
        ReceiptBinder.append_accepted_receipt(request, binding)
    }

    pub fn admit_agentgres_operation(
        &self,
        proposal: &AgentgresOperationProposal,
        binding: &StepModuleReceiptBinding,
    ) -> Result<AgentgresAdmissionRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.admit(proposal, binding)
    }

    pub fn admit_storage_backend_write(
        &self,
        proposal: &StorageBackendWriteProposal,
    ) -> Result<StorageBackendWriteAdmissionRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.admit_storage_backend_write(proposal)
    }

    pub fn plan_runtime_state_transition(
        &self,
        request: &RuntimeStateTransitionRequest,
    ) -> Result<RuntimeStateTransitionRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.plan_runtime_state_transition(request)
    }

    pub fn plan_runtime_state_storage_writes(
        &self,
        request: &RuntimeStateStorageWriteSetRequest,
    ) -> Result<RuntimeStateStorageWriteSetRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.plan_runtime_state_storage_writes(request)
    }

    pub fn materialize_runtime_state_records(
        &self,
        request: &RuntimeStateRecordMaterializationRequest,
    ) -> Result<RuntimeStateRecordMaterializationRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.materialize_runtime_state_records(request)
    }

    pub fn plan_runtime_state_persistence(
        &self,
        request: &RuntimeStatePersistenceRequest,
    ) -> Result<RuntimeStatePersistenceRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.plan_runtime_state_persistence(request)
    }

    pub fn commit_runtime_run_state(
        &self,
        request: &RuntimeRunStateCommitRequest,
    ) -> Result<RuntimeRunStateCommitRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.commit_runtime_run_state(request)
    }

    pub fn commit_runtime_run_state_to_dir(
        &self,
        state_dir: &str,
        request: &RuntimeRunStateCommitRequest,
    ) -> Result<RuntimeRunStatePersistedCommitRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.commit_runtime_run_state_to_dir(state_dir, request)
    }

    pub fn persist_runtime_state_storage_record(
        &self,
        state_root: &std::path::Path,
        record: &RuntimeStateStorageWriteRecord,
        payload: &serde_json::Value,
    ) -> Result<RuntimeStateWrittenRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.persist_runtime_state_storage_record(state_root, record, payload)
    }

    pub fn commit_runtime_agent_state(
        &self,
        request: &RuntimeAgentStateCommitRequest,
    ) -> Result<RuntimeAgentStateCommitRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.commit_runtime_agent_state(request)
    }

    pub fn commit_runtime_memory_state(
        &self,
        request: &RuntimeMemoryStateCommitRequest,
    ) -> Result<RuntimeMemoryStateCommitRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.commit_runtime_memory_state(request)
    }

    pub fn commit_runtime_subagent_state(
        &self,
        request: &RuntimeSubagentStateCommitRequest,
    ) -> Result<RuntimeSubagentStateCommitRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.commit_runtime_subagent_state(request)
    }

    pub fn commit_runtime_artifact_state(
        &self,
        request: &RuntimeArtifactStateCommitRequest,
    ) -> Result<RuntimeArtifactStateCommitRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.commit_runtime_artifact_state(request)
    }

    pub fn commit_runtime_model_mount_record_state(
        &self,
        request: &RuntimeModelMountRecordStateCommitRequest,
    ) -> Result<RuntimeModelMountRecordStateCommitRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.commit_runtime_model_mount_record_state(request)
    }

    pub fn commit_runtime_model_mount_receipt_state(
        &self,
        request: &RuntimeModelMountReceiptStateCommitRequest,
    ) -> Result<RuntimeModelMountReceiptStateCommitRecord, AgentgresAdmissionError> {
        AgentgresAdmissionCore.commit_runtime_model_mount_receipt_state(request)
    }

    pub fn validate_private_workspace_ctee_invocation(
        &self,
        invocation: &StepModuleInvocation,
        node_trust: &CteeNodeTrust,
    ) -> Result<CteePrivateWorkspaceReceipt, CteePrivateWorkspaceError> {
        PrivateWorkspaceCteeModule.validate_invocation(invocation, node_trust)
    }

    pub fn execute_private_workspace_ctee_action(
        &self,
        invocation: &StepModuleInvocation,
        node_trust: &CteeNodeTrust,
    ) -> Result<CteePrivateWorkspaceExecutionRecord, CteePrivateWorkspaceError> {
        PrivateWorkspaceCteeModule.execute_and_admit(invocation, node_trust)
    }

    pub fn project_step_module_result(
        &self,
        invocation: &StepModuleInvocation,
        result: &StepModuleResult,
        binding: &StepModuleReceiptBinding,
    ) -> Result<StepModuleProjectionRecord, ProjectionError> {
        RustProjectionCore.project_step_module_result(invocation, result, binding)
    }

    pub fn reject_workflow_compositor_accepted_truth_attempt(&self) -> Result<(), ProjectionError> {
        RustProjectionCore.reject_workflow_compositor_accepted_truth_attempt()
    }

    pub fn validate_receipt_manifest(
        &self,
        manifest: &ReceiptManifestKind,
    ) -> Result<[u8; 32], Vec<&'static str>> {
        let missing = manifest.missing_required_evidence();
        if !missing.is_empty() {
            return Err(missing);
        }
        manifest
            .canonical_hash()
            .map_err(|_| vec!["canonical_hash"])
    }

    pub fn validate_artifact_promotion(
        &self,
        receipt: &ArtifactPromotionReceipt,
    ) -> Result<(), PromotionValidationError> {
        receipt.validate()
    }

    pub fn settlement_hash(&self, bundle: &SettlementReceiptBundleV2) -> Result<[u8; 32], String> {
        bundle.compute_settlement_hash()
    }

    pub fn admit_l1_settlement_attempt(
        &self,
        attempt: &L1SettlementAttempt,
    ) -> Result<L1SettlementAdmissionRecord, L1SettlementAdmissionError> {
        L1SettlementTriggerGuard.admit(attempt)
    }

    pub fn validate_runtime_profile(
        &self,
        config: &RuntimeProfileConfig,
    ) -> Result<(), Vec<RuntimeProfileViolation>> {
        RuntimeProfileValidator::validate(config)
    }

    pub fn validate_marketplace_contract(
        &self,
        contract: &MarketplaceServiceContract,
    ) -> Result<(), MarketplaceAdmissionError> {
        contract.validate()
    }

    pub fn admit_worker_service_package_invocation(
        &self,
        request: &WorkerServicePackageInvocationRequest,
    ) -> Result<WorkerServicePackageInvocationRecord, MarketplaceAdmissionError> {
        WorkerServicePackageInvocationCore.admit_invocation(request)
    }

    pub fn plan_workspace_restore_apply_policy(
        &self,
        request: &WorkspaceRestoreApplyPolicyRequest,
    ) -> Result<WorkspaceRestoreApplyPolicyPlan, WorkspaceRestoreApplyPolicyError> {
        WorkspaceRestoreApplyPolicyCore.plan_apply_policy(request)
    }

    pub fn preview_workspace_restore_operations(
        &self,
        request: &WorkspaceRestoreOperationsRequest,
    ) -> Result<Vec<WorkspaceRestoreOperationRecord>, WorkspaceRestoreOperationError> {
        WorkspaceRestoreOperationsCore.preview_operations(request)
    }

    pub fn apply_workspace_restore_operations(
        &self,
        request: &WorkspaceRestoreOperationsRequest,
    ) -> Result<Vec<WorkspaceRestoreOperationRecord>, WorkspaceRestoreOperationError> {
        WorkspaceRestoreOperationsCore.apply_operations(request)
    }

    pub fn capture_workspace_snapshot_files(
        &self,
        request: &WorkspaceSnapshotCaptureRequest,
    ) -> Result<WorkspaceSnapshotCaptureResult, WorkspaceRestoreOperationError> {
        WorkspaceSnapshotCaptureCore.capture_files(request)
    }

    pub fn project_workspace_snapshot_list(
        &self,
        request: WorkspaceSnapshotListProtocolRequest,
    ) -> Result<serde_json::Value, workspace_restore::WorkspaceRestoreProtocolError> {
        project_workspace_snapshot_list_protocol_response(request)
    }

    pub fn project_workspace_snapshot_content_package(
        &self,
        request: WorkspaceSnapshotContentPackageProtocolRequest,
    ) -> Result<serde_json::Value, workspace_restore::WorkspaceRestoreProtocolError> {
        project_workspace_snapshot_content_package_protocol_response(request)
    }

    pub fn preview_workspace_snapshot_restore(
        &self,
        request: WorkspaceSnapshotRestoreProtocolRequest,
    ) -> Result<serde_json::Value, workspace_restore::WorkspaceRestoreProtocolError> {
        preview_workspace_snapshot_restore_protocol_response(request)
    }

    pub fn apply_workspace_snapshot_restore(
        &self,
        request: WorkspaceSnapshotRestoreProtocolRequest,
    ) -> Result<serde_json::Value, workspace_restore::WorkspaceRestoreProtocolError> {
        apply_workspace_snapshot_restore_protocol_response(request)
    }
}
