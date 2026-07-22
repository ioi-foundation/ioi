//! Owner-qualified runtime owner surface extracted from RuntimeKernelService.
//!
//! This service contains no authority issuer or Agentgres writer. Consequential
//! outputs must re-enter the trusted admission/authority/receipt spine.

use super::kernel::{
    approval::*, coding_tool_artifact::*, coding_tool_event::*, marketplace::*, model_mount::*,
    policy::*, profile::*, runtime_artifact_availability_incident_admission,
    runtime_code_editor_adapter_launch_plan_admission, runtime_conversation_artifact_control::*,
    runtime_diagnostics_repair_control::*, runtime_goal_run_admission,
    runtime_harness_profile_mutation_admission, runtime_harness_session_binding_admission,
    runtime_harness_session_terminal_attach_admission,
    runtime_hypervisor_approved_operation_admission, runtime_hypervisor_project_create,
    runtime_hypervisor_session_launch_recipe_admission, runtime_managed_session_control::*,
    runtime_managed_worker_instance_lifecycle_admission, runtime_mcp_serve::*,
    runtime_memory_command::*, runtime_memory_control::*, runtime_model_route_mutation_admission,
    runtime_model_weight_custody_admission, runtime_physical_action_intent_admission,
    runtime_private_workspace_mount_admission,
    runtime_service_composition_receipt_bundle_admission, runtime_subagent_control::*,
    runtime_thread_event::*, runtime_thread_fork_control::*,
    runtime_worker_package_install_admission, runtime_workflow_edit_control::*,
    runtime_workspace_change_control::*, workspace_restore::*,
};

#[derive(Debug, Default, Clone)]
pub struct RuntimeOwnerServices;

impl RuntimeOwnerServices {
    pub fn new() -> Self {
        Self
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

    pub fn plan_model_mount_backend_process(
        &self,
        request: &ModelMountBackendProcessPlanRequest,
    ) -> Result<serde_json::Value, ModelMountError> {
        plan_model_mount_backend_process(request)
    }

    pub fn plan_model_mount_backend_process_materialization(
        &self,
        request: &ModelMountBackendProcessMaterializationRequest,
    ) -> Result<ModelMountBackendProcessMaterializationPlan, ModelMountError> {
        plan_model_mount_backend_process_materialization(request)
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

    pub fn plan_model_mount_provider_auth_materialization(
        &self,
        request: &ModelMountProviderAuthMaterializationRequest,
    ) -> Result<ModelMountProviderAuthMaterializationPlan, ModelMountError> {
        ModelMountCore.plan_provider_auth_materialization(request)
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

    pub fn plan_coding_tool_approval_block(
        &self,
        request: &CodingToolApprovalBlockRequest,
    ) -> Result<CodingToolApprovalBlockRecord, CodingToolApprovalBlockError> {
        CodingToolApprovalBlockCore.plan(request)
    }

    pub fn authorize_approval_request(
        &self,
        request: &ApprovalRequestAuthorityRequest,
    ) -> Result<ApprovalRequestAuthorityRecord, ApprovalRequestAuthorityError> {
        ApprovalRequestAuthorityCore.authorize(request)
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

    /// Validate + canonicalize a model-route-mutation governance admission (pure: asserts the
    /// caller bound the required wallet/credential/custody/privacy/receipt refs).

    pub fn admit_model_route_mutation(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<
        serde_json::Value,
        runtime_model_route_mutation_admission::RuntimeModelRouteMutationAdmissionError,
    > {
        runtime_model_route_mutation_admission::RuntimeModelRouteMutationAdmissionCore
            .admit(request, now_iso)
    }

    /// IOI Agent strategy planner (pure, deterministic v1): decides direct vs goal_run for a
    /// launch, with eligible/excluded harnesses and reason codes.

    pub fn select_ioi_agent_execution(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, runtime_goal_run_admission::RuntimeGoalRunAdmissionError> {
        runtime_goal_run_admission::RuntimeGoalRunAdmissionCore.select_ioi_agent_execution(request)
    }

    /// Validate + canonicalize a GoalRun creation admission (pure: bounded invocation budget,
    /// real session/project binding, the orchestrate scope, receipts required).

    pub fn admit_goal_run(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<serde_json::Value, runtime_goal_run_admission::RuntimeGoalRunAdmissionError> {
        runtime_goal_run_admission::RuntimeGoalRunAdmissionCore.admit_goal_run(request, now_iso)
    }

    /// Pure RoleTopology selection for the parallel_implement_reconcile policy — excludes
    /// ineligible implementers with explicit reason codes (the run continues as a partial).

    pub fn select_goal_run_role_topology(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, runtime_goal_run_admission::RuntimeGoalRunAdmissionError> {
        runtime_goal_run_admission::RuntimeGoalRunAdmissionCore.select_role_topology(request)
    }

    /// Validate + canonicalize a single GoalRun harness invocation (pure fail-closed gate:
    /// active + runnable + execution-wired + available route + local-or-accepted trust).

    pub fn admit_goal_run_harness_invocation(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<serde_json::Value, runtime_goal_run_admission::RuntimeGoalRunAdmissionError> {
        runtime_goal_run_admission::RuntimeGoalRunAdmissionCore
            .admit_harness_invocation(request, now_iso)
    }

    /// Validate + canonicalize a GoalRun reconciliation (pure: verified-candidate selection or
    /// an explicit blocked partial; receipts required; the only lane into the target workspace).

    pub fn admit_goal_run_reconciliation(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<serde_json::Value, runtime_goal_run_admission::RuntimeGoalRunAdmissionError> {
        runtime_goal_run_admission::RuntimeGoalRunAdmissionCore
            .admit_reconciliation(request, now_iso)
    }

    /// Validate + canonicalize a harness-profile-mutation governance admission (pure: asserts the
    /// harness authority scope, adapter posture, provider-trust acceptance for non-local trust,
    /// and — for session binding — a wired execution lane, passing runnability probe, and model
    /// route are bound).

    pub fn admit_harness_profile_mutation(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<
        serde_json::Value,
        runtime_harness_profile_mutation_admission::RuntimeHarnessProfileMutationAdmissionError,
    > {
        runtime_harness_profile_mutation_admission::RuntimeHarnessProfileMutationAdmissionCore
            .admit(request, now_iso)
    }

    /// Validate + canonicalize a model-weight-custody governance admission (pure: asserts the
    /// weight-class lane + required controls/scopes/attestation/customer-boundary refs).

    pub fn admit_model_weight_custody(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<
        serde_json::Value,
        runtime_model_weight_custody_admission::RuntimeModelWeightCustodyAdmissionError,
    > {
        runtime_model_weight_custody_admission::RuntimeModelWeightCustodyAdmissionCore
            .admit(request, now_iso)
    }

    /// Validate + canonicalize a worker-package-install governance admission (pure: asserts the
    /// manifest / ontology / surfaces / primitive + authority requirements / policy + receipt +
    /// evidence + artifact refs / wallet approval / mode-specific install-right + managed-instance
    /// + physical-action safety envelope are bound and no vertical pack forks runtime truth).

    pub fn admit_worker_package_install(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<
        serde_json::Value,
        runtime_worker_package_install_admission::RuntimeWorkerPackageInstallAdmissionError,
    > {
        runtime_worker_package_install_admission::RuntimeWorkerPackageInstallAdmissionCore
            .admit(request, now_iso)
    }

    /// Validate + canonicalize a physical-action-intent governance admission (pure: actuator-
    /// affecting work is admitted only through the daemon-owned safety / supervision / emergency-
    /// stop / receipt envelope, never as a generic tool call).

    pub fn admit_physical_action_intent(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<
        serde_json::Value,
        runtime_physical_action_intent_admission::RuntimePhysicalActionIntentAdmissionError,
    > {
        runtime_physical_action_intent_admission::RuntimePhysicalActionIntentAdmissionCore
            .admit(request, now_iso)
    }

    /// Validate + canonicalize a private-workspace-mount governance admission (pure: asserts the
    /// custody-class / mount-target / execution-privacy lane is admissible and the required
    /// controls / scopes / attestation / wallet / declassification refs are bound).

    pub fn admit_private_workspace_mount(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<
        serde_json::Value,
        runtime_private_workspace_mount_admission::RuntimePrivateWorkspaceMountAdmissionError,
    > {
        runtime_private_workspace_mount_admission::RuntimePrivateWorkspaceMountAdmissionCore
            .admit(request, now_iso)
    }

    /// Validate + canonicalize a service-composition-receipt-bundle governance admission (pure:
    /// asserts the contribution/verifier/policy/routing/dispute/Agentgres/receipt refs + delivery
    /// evidence are bound, provider logs are not the sole dispute truth, and unsafe-plaintext
    /// exceptions are wallet-approved + never auto settlement-ready).

    pub fn admit_service_composition_receipt_bundle(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<
        serde_json::Value,
        runtime_service_composition_receipt_bundle_admission::RuntimeServiceCompositionReceiptBundleAdmissionError,
    >{
        runtime_service_composition_receipt_bundle_admission::RuntimeServiceCompositionReceiptBundleAdmissionCore
            .admit(request, now_iso)
    }

    /// Validate + canonicalize a Hypervisor project-create request into a project-state record
    /// (pure: the daemon persists it + assembles the project-state projection over all projects).

    pub fn plan_hypervisor_project_create(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<
        serde_json::Value,
        runtime_hypervisor_project_create::RuntimeHypervisorProjectCreateError,
    > {
        runtime_hypervisor_project_create::RuntimeHypervisorProjectCreateCore.plan(request, now_iso)
    }

    /// Project a canonical `HypervisorEnvironmentStatus` from real transitions (pure: the daemon
    /// gathers the component phases + readiness checks and this canonicalizes the shape).
    /// Derive a typed `HypervisorWorkspaceInitializer` from an initializer spec request (pure).
    /// Project a workspace-diff (`changed_file_groups`) from `git status` + `git diff --numstat`
    /// output (pure parse + folder grouping; the daemon runs git).
    /// Project a workspace-diff from daemon-walked filesystem records (pure folder grouping).
    /// Workspace-diff projection for a session with no workspace yet (no fake work).
    /// Validate + canonicalize a Hypervisor approved-operation governance admission (pure: asserts
    /// a daemon-authored proposal carries wallet approval/lease + required scopes + Agentgres/
    /// receipt/state-root refs + family-specific targets, and emits the admission + execution plan).

    pub fn admit_hypervisor_approved_operation(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<
        serde_json::Value,
        runtime_hypervisor_approved_operation_admission::RuntimeHypervisorApprovedOperationAdmissionError,
    >{
        runtime_hypervisor_approved_operation_admission::RuntimeHypervisorApprovedOperationAdmissionCore
            .admit(request, now_iso)
    }

    /// Validate + canonicalize a harness-session-terminal-attach governance admission (pure:
    /// validates the daemon-admitted spawn + readiness records and composes the client-attach
    /// contract + transcript projection; the client may create/write the host PTY only after this).

    pub fn admit_harness_session_terminal_attach(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<
        serde_json::Value,
        runtime_harness_session_terminal_attach_admission::RuntimeHarnessSessionTerminalAttachAdmissionError,
    >{
        runtime_harness_session_terminal_attach_admission::RuntimeHarnessSessionTerminalAttachAdmissionCore
            .admit(request, now_iso)
    }

    /// Validate + canonicalize an artifact-availability-incident governance admission (pure:
    /// asserts the artifact/payload/backend + Agentgres/incident/affected-object refs are bound,
    /// kind-specific hash/CID evidence is present, lifecycle-state material is bound, and payload
    /// bytes are never silently mutated; returns the incident + a derived agentgres_operation).

    pub fn admit_artifact_availability_incident(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<
        serde_json::Value,
        runtime_artifact_availability_incident_admission::RuntimeArtifactAvailabilityIncidentAdmissionError,
    >{
        runtime_artifact_availability_incident_admission::RuntimeArtifactAvailabilityIncidentAdmissionCore
            .admit(request, now_iso)
    }

    /// Validate + canonicalize a code-editor-adapter-launch-plan governance admission (pure:
    /// asserts the refs / connection / control metadata match the connection kind, no durable
    /// secret release, and the adapter claims no runtime truth).

    pub fn admit_code_editor_adapter_launch_plan(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<
        serde_json::Value,
        runtime_code_editor_adapter_launch_plan_admission::RuntimeCodeEditorAdapterLaunchPlanAdmissionError,
    >{
        runtime_code_editor_adapter_launch_plan_admission::RuntimeCodeEditorAdapterLaunchPlanAdmissionCore
            .admit(request, now_iso)
    }

    /// Validate + canonicalize a managed-worker-instance lifecycle-transition governance admission
    /// (pure: asserts the transition is permitted by the canonical state machine and its per-state
    /// authority / archive / restore / export / deletion / payment-lapse controls + policies +
    /// receipts are bound).

    pub fn admit_managed_worker_instance_lifecycle_transition(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<
        serde_json::Value,
        runtime_managed_worker_instance_lifecycle_admission::RuntimeManagedWorkerInstanceLifecycleAdmissionError,
    >{
        runtime_managed_worker_instance_lifecycle_admission::RuntimeManagedWorkerInstanceLifecycleAdmissionCore
            .admit(request, now_iso)
    }

    /// Validate + canonicalize a harness-session-binding governance admission (pure: asserts the
    /// harness selection, model route, workspace-mount policy, privacy posture, authority scopes,
    /// receipts, and daemon runtime-truth boundary are bound before harness launch).

    pub fn admit_harness_session_binding(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<
        serde_json::Value,
        runtime_harness_session_binding_admission::RuntimeHarnessSessionBindingAdmissionError,
    > {
        runtime_harness_session_binding_admission::RuntimeHarnessSessionBindingAdmissionCore
            .admit(request, now_iso)
    }

    /// Validate + canonicalize a Hypervisor session-launch-recipe governance admission (pure:
    /// asserts the recipe + target binding agree, bind the route/model/privacy/authority/
    /// receipt/Agentgres refs, and require daemon gates + daemon-runtime truth).

    pub fn admit_hypervisor_session_launch_recipe(
        &self,
        request: &serde_json::Value,
        now_iso: &str,
    ) -> Result<
        serde_json::Value,
        runtime_hypervisor_session_launch_recipe_admission::RuntimeHypervisorSessionLaunchRecipeAdmissionError,
    >{
        runtime_hypervisor_session_launch_recipe_admission::RuntimeHypervisorSessionLaunchRecipeAdmissionCore
            .admit(request, now_iso)
    }

    pub fn plan_runtime_memory_command(
        &self,
        request: &RuntimeMemoryCommandPlanRequest,
    ) -> Result<RuntimeMemoryCommandPlanRecord, RuntimeMemoryCommandPlanError> {
        RuntimeMemoryCommandPlanCore.plan(request)
    }

    pub fn plan_runtime_memory_control(
        &self,
        request: &RuntimeMemoryControlApiRequest,
    ) -> Result<RuntimeMemoryControlRecord, RuntimeMemoryControlApiError> {
        RuntimeMemoryControlCore.plan(request)
    }

    pub fn plan_runtime_workflow_edit_control(
        &self,
        request: &RuntimeWorkflowEditControlRequest,
    ) -> Result<RuntimeWorkflowEditControlRecord, RuntimeWorkflowEditControlCommandError> {
        RuntimeWorkflowEditControlCore.plan(request)
    }

    pub fn plan_runtime_managed_session_control(
        &self,
        request: &RuntimeManagedSessionControlRequest,
    ) -> Result<RuntimeManagedSessionControlRecord, RuntimeManagedSessionCommandError> {
        RuntimeManagedSessionControlCore.plan(request)
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

    pub fn plan_runtime_conversation_artifact_control(
        &self,
        request: &RuntimeConversationArtifactControlRequest,
    ) -> Result<
        RuntimeConversationArtifactControlRecord,
        RuntimeConversationArtifactControlCommandError,
    > {
        RuntimeConversationArtifactControlCore::default().plan(request)
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

    pub fn plan_runtime_mcp_serve_tool_call(
        &self,
        request: &RuntimeMcpServeToolCallPlanRequest,
    ) -> Result<RuntimeMcpServeToolCallPlanRecord, RuntimeMcpServeError> {
        RuntimeMcpServeToolCallPlanCore.plan(request)
    }

    pub fn validate_mcp_servers(
        &self,
        request: &McpServerValidationRequest,
    ) -> Result<McpServerValidationRecord, McpServerValidationError> {
        McpServerValidationCore.validate(request)
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

    pub fn plan_model_mount_invocation_authority(
        &self,
        request: &ModelMountInvocationAuthorityRequest,
    ) -> Result<serde_json::Value, ModelMountError> {
        plan_model_mount_invocation_authority(request)
    }

    pub fn admit_model_mount_provider_execution(
        &self,
        request: &ModelMountProviderExecutionRequest,
    ) -> Result<ModelMountProviderExecutionRecord, ModelMountError> {
        ModelMountCore.admit_provider_execution(request)
    }

    pub fn admit_model_mount_provider_result(
        &self,
        request: &ModelMountProviderResultAdmissionRequest,
    ) -> Result<ModelMountProviderResultAdmissionRecord, ModelMountError> {
        ModelMountCore.admit_provider_result(request)
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
}
