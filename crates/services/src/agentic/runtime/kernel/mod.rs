//! Shared bounded-runtime kernel primitives.
//!
//! New runtime code should use chat/artifact, graph, workflow, connector, and
//! plugin language. Legacy surface names are treated as compatibility debt.

pub mod agentgres_admission;
pub mod approval;
pub mod authority;
pub mod capability;
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
    AgentgresOperationProposal, RuntimeRunStateCommitRecord, RuntimeRunStateCommitRequest,
    RuntimeStatePersistenceRecord, RuntimeStatePersistenceRequest,
    RuntimeStateRecordMaterializationRecord, RuntimeStateRecordMaterializationRequest,
    RuntimeStateStorageWriteSetRecord, RuntimeStateStorageWriteSetRequest,
    RuntimeStateTransitionRecord, RuntimeStateTransitionRequest,
    StorageBackendWriteAdmissionRecord, StorageBackendWriteProposal,
};
use approval::{
    ApprovalScopeContext, AuthorityScopeMatcher, CodingToolApprovalCore, CodingToolApprovalError,
    CodingToolApprovalPlan, CodingToolApprovalRequest, ScopeMatchDecision,
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
    CompactionPolicyCore, CompactionPolicyError, CompactionPolicyRecord, CompactionPolicyRequest,
    ContextBudgetPolicyCore, ContextBudgetPolicyError, ContextBudgetPolicyRecord,
    ContextBudgetPolicyRequest,
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
        expected_heads: Vec<String>,
    ) -> Result<CteePrivateWorkspaceExecutionRecord, CteePrivateWorkspaceError> {
        PrivateWorkspaceCteeModule.execute_and_admit(invocation, node_trust, expected_heads)
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
