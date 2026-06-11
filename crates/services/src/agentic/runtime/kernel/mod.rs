//! Shared bounded-runtime kernel primitives.
//!
//! New runtime code should use chat/artifact, graph, workflow, connector, and
//! plugin language. Legacy surface names are treated as compatibility debt.

pub mod agentgres_admission;
pub mod approval;
pub mod authority;
pub mod capability;
pub mod coding_tool_execution;
pub mod command_protocol;
pub mod ctee;
pub mod deadline;
pub mod evidence;
pub mod inference;
pub mod intent;
pub mod intervention;
pub mod invocation;
pub mod marketplace;
pub mod model_mount;
pub mod plan;
pub mod policy;
pub mod profile;
pub mod projection;
pub mod receipt_binder;
pub mod scope;
pub mod settlement;
pub mod step_module;
pub mod step_router;
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
    ApprovalDecisionStateUpdateCore, ApprovalDecisionStateUpdateError,
    ApprovalDecisionStateUpdateRecord, ApprovalDecisionStateUpdateRequest,
    ApprovalRequestStateUpdateCore, ApprovalRequestStateUpdateError,
    ApprovalRequestStateUpdateRecord, ApprovalRequestStateUpdateRequest,
    ApprovalRevokeStateUpdateCore, ApprovalRevokeStateUpdateError, ApprovalRevokeStateUpdateRecord,
    ApprovalRevokeStateUpdateRequest, ApprovalScopeContext, AuthorityScopeMatcher,
    CodingToolApprovalCore, CodingToolApprovalError, CodingToolApprovalPlan,
    CodingToolApprovalRequest, ScopeMatchDecision,
};
use authority::{
    ExternalCapabilityExitAuthorityRecord, ExternalCapabilityExitRequest, WalletAuthorityCore,
    WalletAuthorityError,
};
use capability::CapabilityLeaseDecision;
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
    ModelMountCore, ModelMountError, ModelMountInstanceLifecycleRequest,
    ModelMountInstanceLifecycleResult, ModelMountInvocationAdmissionRecord,
    ModelMountInvocationAdmissionRequest, ModelMountProviderExecutionRecord,
    ModelMountProviderExecutionRequest, ModelMountProviderInventoryRequest,
    ModelMountProviderInventoryResult, ModelMountProviderInvocationRequest,
    ModelMountProviderInvocationResult, ModelMountProviderLifecycleRequest,
    ModelMountProviderLifecycleResult, ModelMountProviderResultAdmissionRecord,
    ModelMountProviderResultAdmissionRequest, ModelMountProviderStreamInvocationResult,
    ModelMountRouteDecisionRecord, ModelMountRouteDecisionRequest,
};
use plan::{validate_plan, ExecutablePlan, PlanValidationError};
use policy::{
    AgentCreateStateUpdateCore, AgentCreateStateUpdateError, AgentCreateStateUpdateRecord,
    AgentCreateStateUpdateRequest, AgentStatusStateUpdateCore, AgentStatusStateUpdateError,
    AgentStatusStateUpdateRecord, AgentStatusStateUpdateRequest,
    CodingToolBudgetRecoveryAdmissionRequiredCore, CodingToolBudgetRecoveryAdmissionRequiredError,
    CodingToolBudgetRecoveryAdmissionRequiredRecord,
    CodingToolBudgetRecoveryAdmissionRequiredRequest, CodingToolBudgetRecoveryStateUpdateCore,
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
    DiagnosticsRepairAdmissionRequiredRequest, McpControlAgentStateUpdateCore,
    McpControlAgentStateUpdateError, McpControlAgentStateUpdateRecord,
    McpControlAgentStateUpdateRequest, McpManagerCatalogProjectionCore,
    McpManagerCatalogProjectionError, McpManagerCatalogProjectionRecord,
    McpManagerCatalogProjectionRequest, McpManagerCatalogSummaryProjectionCore,
    McpManagerCatalogSummaryProjectionError, McpManagerCatalogSummaryProjectionRecord,
    McpManagerCatalogSummaryProjectionRequest, McpManagerStatusProjectionCore,
    McpManagerStatusProjectionError, McpManagerStatusProjectionRecord,
    McpManagerStatusProjectionRequest, McpManagerValidationProjectionCore,
    McpManagerValidationProjectionError, McpManagerValidationProjectionRecord,
    McpManagerValidationProjectionRequest, McpServerValidationCore, McpServerValidationError,
    McpServerValidationRecord, McpServerValidationRequest, MemoryManagerStatusProjectionCore,
    MemoryManagerStatusProjectionError, MemoryManagerStatusProjectionRecord,
    MemoryManagerStatusProjectionRequest, MemoryManagerValidationProjectionCore,
    MemoryManagerValidationProjectionError, MemoryManagerValidationProjectionRecord,
    MemoryManagerValidationProjectionRequest, OperatorInterruptStateUpdateCore,
    OperatorInterruptStateUpdateError, OperatorInterruptStateUpdateRecord,
    OperatorInterruptStateUpdateRequest, OperatorSteerStateUpdateCore,
    OperatorSteerStateUpdateError, OperatorSteerStateUpdateRecord, OperatorSteerStateUpdateRequest,
    RepositoryWorkflowProjectionRequiredCore, RepositoryWorkflowProjectionRequiredError,
    RepositoryWorkflowProjectionRequiredRecord, RepositoryWorkflowProjectionRequiredRequest,
    RunCancelAdmissionRequiredCore, RunCancelAdmissionRequiredError,
    RunCancelAdmissionRequiredRecord, RunCancelAdmissionRequiredRequest, RunCancelStateUpdateCore,
    RunCancelStateUpdateError, RunCancelStateUpdateRecord, RunCancelStateUpdateRequest,
    RunCreateStateUpdateCore, RunCreateStateUpdateError, RunCreateStateUpdateRecord,
    RunCreateStateUpdateRequest, RuntimeBridgeThreadStartAgentStateUpdateCore,
    RuntimeBridgeThreadStartAgentStateUpdateError, RuntimeBridgeThreadStartAgentStateUpdateRecord,
    RuntimeBridgeThreadStartAgentStateUpdateRequest, RuntimeBridgeTurnRunStateUpdateCore,
    RuntimeBridgeTurnRunStateUpdateError, RuntimeBridgeTurnRunStateUpdateRecord,
    RuntimeBridgeTurnRunStateUpdateRequest, RuntimeLifecycleProjectionRequiredCore,
    RuntimeLifecycleProjectionRequiredError, RuntimeLifecycleProjectionRequiredRecord,
    RuntimeLifecycleProjectionRequiredRequest, RuntimeToolCatalogProjectionRequiredCore,
    RuntimeToolCatalogProjectionRequiredError, RuntimeToolCatalogProjectionRequiredRecord,
    RuntimeToolCatalogProjectionRequiredRequest, SkillHookRegistryProjectionRequiredCore,
    SkillHookRegistryProjectionRequiredError, SkillHookRegistryProjectionRequiredRecord,
    SkillHookRegistryProjectionRequiredRequest, SubagentRecordStateUpdateCore,
    SubagentRecordStateUpdateError, SubagentRecordStateUpdateRecord,
    SubagentRecordStateUpdateRequest, ThreadControlAgentStateUpdateCore,
    ThreadControlAgentStateUpdateError, ThreadControlAgentStateUpdateRecord,
    ThreadControlAgentStateUpdateRequest, ThreadMemoryAgentStateUpdateCore,
    ThreadMemoryAgentStateUpdateError, ThreadMemoryAgentStateUpdateRecord,
    ThreadMemoryAgentStateUpdateRequest, WorkflowEditAdmissionRequiredCore,
    WorkflowEditAdmissionRequiredError, WorkflowEditAdmissionRequiredRecord,
    WorkflowEditAdmissionRequiredRequest,
};
use profile::{RuntimeProfileConfig, RuntimeProfileValidator, RuntimeProfileViolation};
use projection::{ProjectionError, RustProjectionCore, StepModuleProjectionRecord};
use receipt_binder::{
    AcceptedReceiptAppendRecord, AcceptedReceiptAppendRequest, ReceiptBinder, ReceiptBindingError,
    StepModuleReceiptBinding,
};
use settlement::{
    ArtifactPromotionReceipt, L1SettlementAdmissionError, L1SettlementAdmissionRecord,
    L1SettlementAttempt, L1SettlementTriggerGuard, PromotionValidationError,
    SettlementReceiptBundleV2,
};
use step_module::{StepModuleInvocation, StepModuleResult, StepModuleValidationError};
use step_router::{
    StepModuleExecutionAdmissionRecord, StepModuleRouterCore, StepModuleRouterError,
};
use workspace_restore::{
    WorkspaceRestoreApplyPolicyCore, WorkspaceRestoreApplyPolicyError,
    WorkspaceRestoreApplyPolicyPlan, WorkspaceRestoreApplyPolicyRequest,
    WorkspaceRestoreOperationError, WorkspaceRestoreOperationRecord,
    WorkspaceRestoreOperationsCore, WorkspaceRestoreOperationsRequest,
    WorkspaceSnapshotCaptureCore, WorkspaceSnapshotCaptureRequest, WorkspaceSnapshotCaptureResult,
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

    pub fn plan_coding_tool_budget_recovery_admission_required(
        &self,
        request: &CodingToolBudgetRecoveryAdmissionRequiredRequest,
    ) -> Result<
        CodingToolBudgetRecoveryAdmissionRequiredRecord,
        CodingToolBudgetRecoveryAdmissionRequiredError,
    > {
        CodingToolBudgetRecoveryAdmissionRequiredCore.plan(request)
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

    pub fn plan_skill_hook_registry_projection_required(
        &self,
        request: &SkillHookRegistryProjectionRequiredRequest,
    ) -> Result<SkillHookRegistryProjectionRequiredRecord, SkillHookRegistryProjectionRequiredError>
    {
        SkillHookRegistryProjectionRequiredCore.plan(request)
    }

    pub fn plan_repository_workflow_projection_required(
        &self,
        request: &RepositoryWorkflowProjectionRequiredRequest,
    ) -> Result<RepositoryWorkflowProjectionRequiredRecord, RepositoryWorkflowProjectionRequiredError>
    {
        RepositoryWorkflowProjectionRequiredCore.plan(request)
    }

    pub fn plan_runtime_tool_catalog_projection_required(
        &self,
        request: &RuntimeToolCatalogProjectionRequiredRequest,
    ) -> Result<RuntimeToolCatalogProjectionRequiredRecord, RuntimeToolCatalogProjectionRequiredError>
    {
        RuntimeToolCatalogProjectionRequiredCore.plan(request)
    }

    pub fn plan_runtime_lifecycle_projection_required(
        &self,
        request: &RuntimeLifecycleProjectionRequiredRequest,
    ) -> Result<RuntimeLifecycleProjectionRequiredRecord, RuntimeLifecycleProjectionRequiredError>
    {
        RuntimeLifecycleProjectionRequiredCore.plan(request)
    }

    pub fn plan_thread_control_agent_state_update(
        &self,
        request: &ThreadControlAgentStateUpdateRequest,
    ) -> Result<ThreadControlAgentStateUpdateRecord, ThreadControlAgentStateUpdateError> {
        ThreadControlAgentStateUpdateCore.plan(request)
    }

    pub fn plan_mcp_control_agent_state_update(
        &self,
        request: &McpControlAgentStateUpdateRequest,
    ) -> Result<McpControlAgentStateUpdateRecord, McpControlAgentStateUpdateError> {
        McpControlAgentStateUpdateCore.plan(request)
    }

    pub fn validate_mcp_servers(
        &self,
        request: &McpServerValidationRequest,
    ) -> Result<McpServerValidationRecord, McpServerValidationError> {
        McpServerValidationCore.validate(request)
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
}
