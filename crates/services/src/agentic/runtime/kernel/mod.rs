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
pub mod runtime_artifact_availability_incident_admission;
pub mod runtime_code_editor_adapter_launch_plan_admission;
pub mod runtime_computer_use;
pub mod runtime_conversation_artifact_control;
pub mod runtime_conversation_artifact_projection;
pub mod runtime_diagnostics_repair_control;
pub mod runtime_diagnostics_repair_policy;
pub mod runtime_diagnostics_repair_projection;
pub mod runtime_doctor_report;
pub mod runtime_effect_compatibility_gateway;
pub mod runtime_goal_run_admission;
pub mod runtime_harness_profile_mutation_admission;
pub mod runtime_harness_session_binding_admission;
pub mod runtime_harness_session_terminal_attach_admission;
pub mod runtime_hypervisor_approved_operation_admission;
pub mod runtime_hypervisor_environment_status_projection;
pub mod runtime_hypervisor_project_create;
pub mod runtime_hypervisor_session_launch_recipe_admission;
pub mod runtime_hypervisor_workspace_diff_projection;
pub mod runtime_lifecycle;
pub mod runtime_managed_session_control;
pub mod runtime_managed_worker_instance_lifecycle_admission;
pub mod runtime_mcp_serve;
pub mod runtime_memory_command;
pub mod runtime_memory_control;
pub mod runtime_memory_projection;
pub mod runtime_model_route_mutation_admission;
pub mod runtime_model_weight_custody_admission;
pub mod runtime_physical_action_intent_admission;
pub mod runtime_private_workspace_mount_admission;
pub mod runtime_service_composition_receipt_bundle_admission;
pub mod runtime_subagent_control;
pub mod runtime_subagent_projection;
pub mod runtime_thread_event;
pub mod runtime_thread_fork_control;
pub mod runtime_tool_catalog;
pub mod runtime_worker_package_install_admission;
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
    ApprovalDecisionAuthorityRequest, ApprovalScopeContext, AuthorityScopeMatcher,
    ScopeMatchDecision,
};
use authority::{
    ExternalCapabilityExitAuthorityRecord, ExternalCapabilityExitRequest, WalletAuthorityCore,
    WalletAuthorityError,
};
use ctee::{
    CteeNodeTrust, CteePrivateWorkspaceError, CteePrivateWorkspaceReceipt,
    PrivateWorkspaceCteeModule,
};
use evidence::ReceiptManifestKind;
use invocation::ToolInvocationEnvelope;
use model_mount::{
    ModelMountAcceptedReceiptHeadRequest, ModelMountAcceptedReceiptTransitionRequest,
    ModelMountCore, ModelMountError, ModelMountReceiptGatePlan, ModelMountReceiptGateRequest,
};
use model_mount_receipt::{
    bind_model_mount_invocation_receipt, plan_model_mount_accepted_receipt_head,
    plan_model_mount_accepted_receipt_transition, ModelMountInvocationReceiptBindingRequest,
    ModelMountReceiptError,
};
use plan::{validate_plan, ExecutablePlan, PlanValidationError};
use projection::{ProjectionError, RustProjectionCore};
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

use ioi_types::app::ApprovalAuthority;

pub use runtime_effect_compatibility_gateway::RuntimeEffectCompatibilityGateway;

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

    pub fn authorize_approval_decision(
        &self,
        request: &ApprovalDecisionAuthorityRequest,
    ) -> Result<ApprovalDecisionAuthorityRecord, ApprovalDecisionAuthorityError> {
        ApprovalDecisionAuthorityCore.authorize(request)
    }

    pub fn authorize_external_capability_exit(
        &self,
        request: &ExternalCapabilityExitRequest,
    ) -> Result<ExternalCapabilityExitAuthorityRecord, WalletAuthorityError> {
        WalletAuthorityCore.authorize_external_capability_exit(request)
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
}
