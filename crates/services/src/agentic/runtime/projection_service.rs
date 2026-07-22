//! Owner-qualified read/projection surface extracted from RuntimeKernelService.
//!
//! This service contains no authority issuer or Agentgres writer. Consequential
//! outputs must re-enter the trusted admission/authority/receipt spine.

use super::kernel::{
    approval::*,
    coding_tool_artifact::*,
    model_mount::*,
    policy::*,
    projection::*,
    receipt_binder::*,
    repository_workflow::*,
    runtime_computer_use::*,
    runtime_conversation_artifact_projection::*,
    runtime_diagnostics_repair_control::*,
    runtime_diagnostics_repair_policy::*,
    runtime_diagnostics_repair_projection::*,
    runtime_doctor_report::*,
    runtime_hypervisor_environment_status_projection, runtime_hypervisor_workspace_diff_projection,
    runtime_lifecycle::*,
    runtime_managed_session_control::*,
    runtime_mcp_serve::*,
    runtime_memory_projection::*,
    runtime_subagent_projection::*,
    runtime_thread_event::*,
    runtime_tool_catalog::*,
    runtime_workspace_change_control::*,
    skill_hook_registry::*,
    step_module::*,
    studio_intent_frame::*,
    workspace_restore::{self, *},
};

#[derive(Debug, Default, Clone)]
pub struct RuntimeProjectionService;

impl RuntimeProjectionService {
    pub fn new() -> Self {
        Self
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

    pub fn project_approval_queue(
        &self,
        request: &ApprovalQueueProjectionRequest,
    ) -> Result<ApprovalQueueProjectionRecord, ApprovalQueueProjectionError> {
        ApprovalQueueProjectionCore.project(request)
    }

    pub fn project_runtime_coding_tool_artifact_read(
        &self,
        request: &RuntimeCodingToolArtifactReadProjectionRequest,
    ) -> Result<serde_json::Value, RuntimeCodingToolArtifactReadProjectionCommandError> {
        project_runtime_coding_tool_artifact_read(request)
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

    pub fn project_hypervisor_environment_status(
        &self,
        input: &serde_json::Value,
    ) -> serde_json::Value {
        runtime_hypervisor_environment_status_projection::build_hypervisor_environment_status(input)
    }

    pub fn derive_hypervisor_workspace_initializer(
        &self,
        input: &serde_json::Value,
    ) -> serde_json::Value {
        runtime_hypervisor_environment_status_projection::derive_workspace_initializer(input)
    }

    pub fn project_hypervisor_workspace_diff_from_git(
        &self,
        workspace_root: &str,
        numstat_stdout: &str,
        status_stdout: &str,
    ) -> serde_json::Value {
        runtime_hypervisor_workspace_diff_projection::workspace_diff_from_git(
            workspace_root,
            numstat_stdout,
            status_stdout,
        )
    }

    pub fn project_hypervisor_workspace_diff_from_records(
        &self,
        workspace_root: &str,
        source: &str,
        records: &[serde_json::Value],
    ) -> serde_json::Value {
        runtime_hypervisor_workspace_diff_projection::workspace_diff_from_records(
            workspace_root,
            source,
            records,
        )
    }

    pub fn project_hypervisor_workspace_diff_absent(&self) -> serde_json::Value {
        runtime_hypervisor_workspace_diff_projection::workspace_diff_absent()
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
        request: &RuntimeMemoryProjectionApiRequest,
    ) -> Result<RuntimeMemoryProjectionRecord, RuntimeMemoryProjectionApiError> {
        RuntimeMemoryProjectionCore.project(request)
    }

    pub fn project_runtime_managed_session_projection(
        &self,
        request: &RuntimeManagedSessionProjectionRequest,
    ) -> Result<RuntimeManagedSessionProjectionRecord, RuntimeManagedSessionCommandError> {
        RuntimeManagedSessionProjectionCore.project(request)
    }

    pub fn project_runtime_workspace_change_projection(
        &self,
        request: &RuntimeWorkspaceChangeProjectionRequest,
    ) -> Result<RuntimeWorkspaceChangeProjectionRecord, RuntimeWorkspaceChangeCommandError> {
        RuntimeWorkspaceChangeProjectionCore.project(request)
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

    pub fn project_runtime_subagent_projection(
        &self,
        request: &RuntimeSubagentProjectionRequest,
    ) -> Result<RuntimeSubagentProjectionRecord, RuntimeSubagentProjectionCommandError> {
        RuntimeSubagentProjectionCore::default().project(request)
    }

    pub fn project_mcp_live_result_replay(
        &self,
        request: &McpLiveResultReplayRequest,
    ) -> Result<McpLiveResultReplayRecord, McpLiveResultReplayError> {
        McpLiveResultReplayCore.project(request)
    }

    pub fn project_runtime_mcp_serve_tool_result(
        &self,
        request: &RuntimeMcpServeToolResultProjectionRequest,
    ) -> Result<RuntimeMcpServeToolResultProjectionRecord, RuntimeMcpServeError> {
        RuntimeMcpServeToolCallPlanCore.project_result(request)
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

    pub fn plan_model_mount_read_projection(
        &self,
        request: &ModelMountReadProjectionRequest,
    ) -> Result<ModelMountReadProjectionPlan, ModelMountReadProjectionError> {
        ModelMountCore.plan_read_projection(request)
    }

    pub fn project_step_module_result(
        &self,
        invocation: &StepModuleInvocation,
        result: &StepModuleResult,
        binding: &StepModuleReceiptBinding,
    ) -> Result<StepModuleProjectionRecord, ProjectionError> {
        RustProjectionCore.project_step_module_result(invocation, result, binding)
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
}
