use serde::Deserialize;

pub const STEP_MODULE_COMMAND_SCHEMA_VERSION: &str = "ioi.step_module.command_bridge.v1";
pub const DAEMON_CORE_COMMAND_SCHEMA_VERSION: &str = "ioi.runtime.daemon_core.command.v1";
pub const COMMAND_SCHEMA_VERSION: &str = DAEMON_CORE_COMMAND_SCHEMA_VERSION;

pub const DAEMON_CORE_OPERATIONS: &[&str] = &[
    "run_coding_tool_step_module",
    "admit_model_mount_invocation",
    "admit_model_mount_provider_execution",
    "execute_model_mount_provider_invocation",
    "execute_model_mount_provider_stream_invocation",
    "plan_model_mount_provider_lifecycle",
    "plan_model_mount_provider_inventory",
    "plan_model_mount_instance_lifecycle",
    "admit_model_mount_provider_result",
    "plan_model_mount_backend_process",
    "plan_model_mount_backend_lifecycle",
    "plan_model_mount_artifact_endpoint",
    "plan_model_mount_storage_control",
    "plan_model_mount_mcp_workflow",
    "plan_model_mount_server_control",
    "plan_model_mount_runtime_engine",
    "plan_model_mount_runtime_survey",
    "plan_model_mount_tokenizer_required",
    "plan_model_mount_route_control_required",
    "plan_model_mount_route_control",
    "plan_model_mount_catalog_provider_control",
    "plan_model_mount_provider_control",
    "plan_model_mount_capability_token_control",
    "plan_model_mount_vault_control",
    "plan_model_mount_receipt_gate",
    "plan_model_mount_tokenizer",
    "plan_model_mount_conversation_state",
    "plan_model_mount_stream_completion",
    "plan_model_mount_stream_cancel",
    "plan_model_mount_accepted_receipt_head",
    "plan_model_mount_accepted_receipt_transition",
    "bind_model_mount_invocation_receipt",
    "plan_model_mount_read_projection",
    "plan_coding_tool_result_envelope",
    "plan_runtime_coding_tool_artifact_drafts",
    "project_runtime_coding_tool_artifact_read",
    "plan_post_edit_diagnostics_feedback",
    "plan_workflow_edit_admission_required",
    "plan_diagnostics_repair_admission_required",
    "plan_runtime_diagnostics_repair_control",
    "plan_runtime_diagnostics_repair_retry_run",
    "project_runtime_diagnostics_repair_projection",
    "project_runtime_diagnostics_repair_policy",
    "plan_runtime_task_job_cancel_state_update",
    "plan_runtime_task_job_create_state_update",
    "project_runtime_task_job_projection",
    "project_skill_hook_registry",
    "project_repository_workflow",
    "project_runtime_tool_catalog",
    "project_runtime_lifecycle",
    "plan_runtime_mcp_serve_tool_call",
    "project_runtime_mcp_serve_tool_result",
    "plan_runtime_workflow_edit_control",
    "project_runtime_managed_session_projection",
    "plan_runtime_managed_session_control",
    "project_runtime_workspace_change_projection",
    "plan_runtime_workspace_change_control",
    "plan_runtime_thread_fork_control",
    "plan_runtime_conversation_artifact_control",
    "project_runtime_conversation_artifact_projection",
    "project_runtime_subagent_projection",
    "plan_runtime_subagent_control",
    "plan_lifecycle_admission_required",
    "plan_thread_turn_admission_required",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOperation {
    RunCodingToolStepModule,
    AdmitModelMountInvocation,
    AdmitModelMountProviderExecution,
    ExecuteModelMountProviderInvocation,
    ExecuteModelMountProviderStreamInvocation,
    PlanModelMountProviderLifecycle,
    PlanModelMountProviderInventory,
    PlanModelMountInstanceLifecycle,
    AdmitModelMountProviderResult,
    PlanModelMountBackendProcess,
    PlanModelMountBackendLifecycle,
    PlanModelMountArtifactEndpoint,
    PlanModelMountStorageControl,
    PlanModelMountMcpWorkflow,
    PlanModelMountServerControl,
    PlanModelMountRuntimeEngine,
    PlanModelMountRuntimeSurvey,
    PlanModelMountTokenizerRequired,
    PlanModelMountRouteControlRequired,
    PlanModelMountRouteControl,
    PlanModelMountCatalogProviderControl,
    PlanModelMountProviderControl,
    PlanModelMountCapabilityTokenControl,
    PlanModelMountVaultControl,
    PlanModelMountReceiptGate,
    PlanModelMountTokenizer,
    PlanModelMountConversationState,
    PlanModelMountStreamCompletion,
    PlanModelMountStreamCancel,
    PlanModelMountAcceptedReceiptHead,
    PlanModelMountAcceptedReceiptTransition,
    BindModelMountInvocationReceipt,
    PlanModelMountReadProjection,
    PlanCodingToolResultEnvelope,
    PlanRuntimeCodingToolArtifactDrafts,
    ProjectRuntimeCodingToolArtifactRead,
    PlanPostEditDiagnosticsFeedback,
    PlanWorkflowEditAdmissionRequired,
    PlanDiagnosticsRepairAdmissionRequired,
    PlanRuntimeDiagnosticsRepairControl,
    PlanRuntimeDiagnosticsRepairRetryRun,
    ProjectRuntimeDiagnosticsRepairProjection,
    ProjectRuntimeDiagnosticsRepairPolicy,
    PlanRuntimeTaskJobCancelStateUpdate,
    PlanRuntimeTaskJobCreateStateUpdate,
    ProjectRuntimeTaskJobProjection,
    ProjectSkillHookRegistry,
    ProjectRepositoryWorkflow,
    ProjectRuntimeToolCatalog,
    ProjectRuntimeLifecycle,
    PlanRuntimeMcpServeToolCall,
    ProjectRuntimeMcpServeToolResult,
    PlanRuntimeWorkflowEditControl,
    ProjectRuntimeManagedSessionProjection,
    PlanRuntimeManagedSessionControl,
    ProjectRuntimeWorkspaceChangeProjection,
    PlanRuntimeWorkspaceChangeControl,
    PlanRuntimeThreadForkControl,
    PlanRuntimeConversationArtifactControl,
    ProjectRuntimeConversationArtifactProjection,
    ProjectRuntimeSubagentProjection,
    PlanRuntimeSubagentControl,
    PlanLifecycleAdmissionRequired,
    PlanThreadTurnAdmissionRequired,
}

impl CommandOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RunCodingToolStepModule => "run_coding_tool_step_module",
            Self::AdmitModelMountInvocation => "admit_model_mount_invocation",
            Self::AdmitModelMountProviderExecution => "admit_model_mount_provider_execution",
            Self::ExecuteModelMountProviderInvocation => "execute_model_mount_provider_invocation",
            Self::ExecuteModelMountProviderStreamInvocation => {
                "execute_model_mount_provider_stream_invocation"
            }
            Self::PlanModelMountProviderLifecycle => "plan_model_mount_provider_lifecycle",
            Self::PlanModelMountProviderInventory => "plan_model_mount_provider_inventory",
            Self::PlanModelMountInstanceLifecycle => "plan_model_mount_instance_lifecycle",
            Self::AdmitModelMountProviderResult => "admit_model_mount_provider_result",
            Self::PlanModelMountBackendProcess => "plan_model_mount_backend_process",
            Self::PlanModelMountBackendLifecycle => "plan_model_mount_backend_lifecycle",
            Self::PlanModelMountArtifactEndpoint => "plan_model_mount_artifact_endpoint",
            Self::PlanModelMountStorageControl => "plan_model_mount_storage_control",
            Self::PlanModelMountMcpWorkflow => "plan_model_mount_mcp_workflow",
            Self::PlanModelMountServerControl => "plan_model_mount_server_control",
            Self::PlanModelMountRuntimeEngine => "plan_model_mount_runtime_engine",
            Self::PlanModelMountRuntimeSurvey => "plan_model_mount_runtime_survey",
            Self::PlanModelMountTokenizerRequired => "plan_model_mount_tokenizer_required",
            Self::PlanModelMountRouteControlRequired => "plan_model_mount_route_control_required",
            Self::PlanModelMountRouteControl => "plan_model_mount_route_control",
            Self::PlanModelMountCatalogProviderControl => {
                "plan_model_mount_catalog_provider_control"
            }
            Self::PlanModelMountProviderControl => "plan_model_mount_provider_control",
            Self::PlanModelMountCapabilityTokenControl => {
                "plan_model_mount_capability_token_control"
            }
            Self::PlanModelMountVaultControl => "plan_model_mount_vault_control",
            Self::PlanModelMountReceiptGate => "plan_model_mount_receipt_gate",
            Self::PlanModelMountTokenizer => "plan_model_mount_tokenizer",
            Self::PlanModelMountConversationState => "plan_model_mount_conversation_state",
            Self::PlanModelMountStreamCompletion => "plan_model_mount_stream_completion",
            Self::PlanModelMountStreamCancel => "plan_model_mount_stream_cancel",
            Self::PlanModelMountAcceptedReceiptHead => "plan_model_mount_accepted_receipt_head",
            Self::PlanModelMountAcceptedReceiptTransition => {
                "plan_model_mount_accepted_receipt_transition"
            }
            Self::BindModelMountInvocationReceipt => "bind_model_mount_invocation_receipt",
            Self::PlanModelMountReadProjection => "plan_model_mount_read_projection",
            Self::PlanCodingToolResultEnvelope => "plan_coding_tool_result_envelope",
            Self::PlanRuntimeCodingToolArtifactDrafts => "plan_runtime_coding_tool_artifact_drafts",
            Self::ProjectRuntimeCodingToolArtifactRead => {
                "project_runtime_coding_tool_artifact_read"
            }
            Self::PlanPostEditDiagnosticsFeedback => "plan_post_edit_diagnostics_feedback",
            Self::PlanWorkflowEditAdmissionRequired => "plan_workflow_edit_admission_required",
            Self::PlanDiagnosticsRepairAdmissionRequired => {
                "plan_diagnostics_repair_admission_required"
            }
            Self::PlanRuntimeDiagnosticsRepairControl => "plan_runtime_diagnostics_repair_control",
            Self::PlanRuntimeDiagnosticsRepairRetryRun => {
                "plan_runtime_diagnostics_repair_retry_run"
            }
            Self::ProjectRuntimeDiagnosticsRepairProjection => {
                "project_runtime_diagnostics_repair_projection"
            }
            Self::ProjectRuntimeDiagnosticsRepairPolicy => {
                "project_runtime_diagnostics_repair_policy"
            }
            Self::PlanRuntimeTaskJobCancelStateUpdate => {
                "plan_runtime_task_job_cancel_state_update"
            }
            Self::PlanRuntimeTaskJobCreateStateUpdate => {
                "plan_runtime_task_job_create_state_update"
            }
            Self::ProjectRuntimeTaskJobProjection => "project_runtime_task_job_projection",
            Self::ProjectSkillHookRegistry => "project_skill_hook_registry",
            Self::ProjectRepositoryWorkflow => "project_repository_workflow",
            Self::ProjectRuntimeToolCatalog => "project_runtime_tool_catalog",
            Self::ProjectRuntimeLifecycle => "project_runtime_lifecycle",
            Self::PlanRuntimeMcpServeToolCall => "plan_runtime_mcp_serve_tool_call",
            Self::ProjectRuntimeMcpServeToolResult => "project_runtime_mcp_serve_tool_result",
            Self::PlanRuntimeWorkflowEditControl => "plan_runtime_workflow_edit_control",
            Self::ProjectRuntimeManagedSessionProjection => {
                "project_runtime_managed_session_projection"
            }
            Self::PlanRuntimeManagedSessionControl => "plan_runtime_managed_session_control",
            Self::ProjectRuntimeWorkspaceChangeProjection => {
                "project_runtime_workspace_change_projection"
            }
            Self::PlanRuntimeWorkspaceChangeControl => "plan_runtime_workspace_change_control",
            Self::PlanRuntimeThreadForkControl => "plan_runtime_thread_fork_control",
            Self::PlanRuntimeConversationArtifactControl => {
                "plan_runtime_conversation_artifact_control"
            }
            Self::ProjectRuntimeConversationArtifactProjection => {
                "project_runtime_conversation_artifact_projection"
            }
            Self::ProjectRuntimeSubagentProjection => "project_runtime_subagent_projection",
            Self::PlanRuntimeSubagentControl => "plan_runtime_subagent_control",
            Self::PlanLifecycleAdmissionRequired => "plan_lifecycle_admission_required",
            Self::PlanThreadTurnAdmissionRequired => "plan_thread_turn_admission_required",
        }
    }

    pub fn schema_version(self) -> &'static str {
        DAEMON_CORE_COMMAND_SCHEMA_VERSION
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCommandEnvelope<'a> {
    pub operation: &'a str,
    pub command_operation: CommandOperation,
    pub schema_version: &'static str,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CommandEnvelope {
    #[serde(rename = "schema_version")]
    pub schema_version: String,
    pub operation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandProtocolError {
    code: &'static str,
    message: String,
}

impl CommandProtocolError {
    fn operation_unknown(operation: &str) -> Self {
        Self {
            code: "operation_unknown",
            message: format!("unknown bridge operation {operation}"),
        }
    }

    fn schema_version_invalid(expected: &str, received: &str) -> Self {
        Self {
            code: "schema_version_invalid",
            message: format!("expected {expected} but received {received}"),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn into_parts(self) -> (&'static str, String) {
        (self.code, self.message)
    }
}

pub fn command_operation(operation: &str) -> Option<CommandOperation> {
    match operation {
        "run_coding_tool_step_module" => Some(CommandOperation::RunCodingToolStepModule),
        "admit_model_mount_invocation" => Some(CommandOperation::AdmitModelMountInvocation),
        "admit_model_mount_provider_execution" => {
            Some(CommandOperation::AdmitModelMountProviderExecution)
        }
        "execute_model_mount_provider_invocation" => {
            Some(CommandOperation::ExecuteModelMountProviderInvocation)
        }
        "execute_model_mount_provider_stream_invocation" => {
            Some(CommandOperation::ExecuteModelMountProviderStreamInvocation)
        }
        "plan_model_mount_provider_lifecycle" => {
            Some(CommandOperation::PlanModelMountProviderLifecycle)
        }
        "plan_model_mount_provider_inventory" => {
            Some(CommandOperation::PlanModelMountProviderInventory)
        }
        "plan_model_mount_instance_lifecycle" => {
            Some(CommandOperation::PlanModelMountInstanceLifecycle)
        }
        "admit_model_mount_provider_result" => {
            Some(CommandOperation::AdmitModelMountProviderResult)
        }
        "plan_model_mount_backend_process" => Some(CommandOperation::PlanModelMountBackendProcess),
        "plan_model_mount_backend_lifecycle" => {
            Some(CommandOperation::PlanModelMountBackendLifecycle)
        }
        "plan_model_mount_artifact_endpoint" => {
            Some(CommandOperation::PlanModelMountArtifactEndpoint)
        }
        "plan_model_mount_storage_control" => Some(CommandOperation::PlanModelMountStorageControl),
        "plan_model_mount_mcp_workflow" => Some(CommandOperation::PlanModelMountMcpWorkflow),
        "plan_model_mount_server_control" => Some(CommandOperation::PlanModelMountServerControl),
        "plan_model_mount_runtime_engine" => Some(CommandOperation::PlanModelMountRuntimeEngine),
        "plan_model_mount_runtime_survey" => Some(CommandOperation::PlanModelMountRuntimeSurvey),
        "plan_model_mount_tokenizer_required" => {
            Some(CommandOperation::PlanModelMountTokenizerRequired)
        }
        "plan_model_mount_route_control_required" => {
            Some(CommandOperation::PlanModelMountRouteControlRequired)
        }
        "plan_model_mount_route_control" => Some(CommandOperation::PlanModelMountRouteControl),
        "plan_model_mount_catalog_provider_control" => {
            Some(CommandOperation::PlanModelMountCatalogProviderControl)
        }
        "plan_model_mount_provider_control" => {
            Some(CommandOperation::PlanModelMountProviderControl)
        }
        "plan_model_mount_capability_token_control" => {
            Some(CommandOperation::PlanModelMountCapabilityTokenControl)
        }
        "plan_model_mount_vault_control" => Some(CommandOperation::PlanModelMountVaultControl),
        "plan_model_mount_receipt_gate" => Some(CommandOperation::PlanModelMountReceiptGate),
        "plan_model_mount_tokenizer" => Some(CommandOperation::PlanModelMountTokenizer),
        "plan_model_mount_conversation_state" => {
            Some(CommandOperation::PlanModelMountConversationState)
        }
        "plan_model_mount_stream_completion" => {
            Some(CommandOperation::PlanModelMountStreamCompletion)
        }
        "plan_model_mount_stream_cancel" => Some(CommandOperation::PlanModelMountStreamCancel),
        "plan_model_mount_accepted_receipt_head" => {
            Some(CommandOperation::PlanModelMountAcceptedReceiptHead)
        }
        "plan_model_mount_accepted_receipt_transition" => {
            Some(CommandOperation::PlanModelMountAcceptedReceiptTransition)
        }
        "bind_model_mount_invocation_receipt" => {
            Some(CommandOperation::BindModelMountInvocationReceipt)
        }
        "plan_model_mount_read_projection" => Some(CommandOperation::PlanModelMountReadProjection),
        "plan_coding_tool_result_envelope" => Some(CommandOperation::PlanCodingToolResultEnvelope),
        "plan_runtime_coding_tool_artifact_drafts" => {
            Some(CommandOperation::PlanRuntimeCodingToolArtifactDrafts)
        }
        "project_runtime_coding_tool_artifact_read" => {
            Some(CommandOperation::ProjectRuntimeCodingToolArtifactRead)
        }
        "plan_post_edit_diagnostics_feedback" => {
            Some(CommandOperation::PlanPostEditDiagnosticsFeedback)
        }
        "plan_workflow_edit_admission_required" => {
            Some(CommandOperation::PlanWorkflowEditAdmissionRequired)
        }
        "plan_diagnostics_repair_admission_required" => {
            Some(CommandOperation::PlanDiagnosticsRepairAdmissionRequired)
        }
        "plan_runtime_diagnostics_repair_control" => {
            Some(CommandOperation::PlanRuntimeDiagnosticsRepairControl)
        }
        "plan_runtime_diagnostics_repair_retry_run" => {
            Some(CommandOperation::PlanRuntimeDiagnosticsRepairRetryRun)
        }
        "project_runtime_diagnostics_repair_projection" => {
            Some(CommandOperation::ProjectRuntimeDiagnosticsRepairProjection)
        }
        "project_runtime_diagnostics_repair_policy" => {
            Some(CommandOperation::ProjectRuntimeDiagnosticsRepairPolicy)
        }
        "plan_runtime_task_job_cancel_state_update" => {
            Some(CommandOperation::PlanRuntimeTaskJobCancelStateUpdate)
        }
        "plan_runtime_task_job_create_state_update" => {
            Some(CommandOperation::PlanRuntimeTaskJobCreateStateUpdate)
        }
        "project_runtime_task_job_projection" => {
            Some(CommandOperation::ProjectRuntimeTaskJobProjection)
        }
        "project_skill_hook_registry" => Some(CommandOperation::ProjectSkillHookRegistry),
        "project_repository_workflow" => Some(CommandOperation::ProjectRepositoryWorkflow),
        "project_runtime_tool_catalog" => Some(CommandOperation::ProjectRuntimeToolCatalog),
        "project_runtime_lifecycle" => Some(CommandOperation::ProjectRuntimeLifecycle),
        "plan_runtime_mcp_serve_tool_call" => Some(CommandOperation::PlanRuntimeMcpServeToolCall),
        "project_runtime_mcp_serve_tool_result" => {
            Some(CommandOperation::ProjectRuntimeMcpServeToolResult)
        }
        "plan_runtime_workflow_edit_control" => {
            Some(CommandOperation::PlanRuntimeWorkflowEditControl)
        }
        "project_runtime_managed_session_projection" => {
            Some(CommandOperation::ProjectRuntimeManagedSessionProjection)
        }
        "plan_runtime_managed_session_control" => {
            Some(CommandOperation::PlanRuntimeManagedSessionControl)
        }
        "project_runtime_workspace_change_projection" => {
            Some(CommandOperation::ProjectRuntimeWorkspaceChangeProjection)
        }
        "plan_runtime_workspace_change_control" => {
            Some(CommandOperation::PlanRuntimeWorkspaceChangeControl)
        }
        "plan_runtime_thread_fork_control" => Some(CommandOperation::PlanRuntimeThreadForkControl),
        "plan_runtime_conversation_artifact_control" => {
            Some(CommandOperation::PlanRuntimeConversationArtifactControl)
        }
        "project_runtime_conversation_artifact_projection" => {
            Some(CommandOperation::ProjectRuntimeConversationArtifactProjection)
        }
        "project_runtime_subagent_projection" => {
            Some(CommandOperation::ProjectRuntimeSubagentProjection)
        }
        "plan_runtime_subagent_control" => Some(CommandOperation::PlanRuntimeSubagentControl),
        "plan_lifecycle_admission_required" => {
            Some(CommandOperation::PlanLifecycleAdmissionRequired)
        }
        "plan_thread_turn_admission_required" => {
            Some(CommandOperation::PlanThreadTurnAdmissionRequired)
        }
        _ => None,
    }
}

pub fn expected_command_schema_version(operation: &str) -> Option<&'static str> {
    command_operation(operation).map(CommandOperation::schema_version)
}

pub fn validate_command_envelope<'a>(
    operation: &'a str,
    schema_version: &str,
) -> Result<ValidatedCommandEnvelope<'a>, CommandProtocolError> {
    let command_operation = command_operation(operation)
        .ok_or_else(|| CommandProtocolError::operation_unknown(operation))?;
    let expected_schema_version = command_operation.schema_version();
    if schema_version != expected_schema_version {
        return Err(CommandProtocolError::schema_version_invalid(
            expected_schema_version,
            schema_version,
        ));
    }

    Ok(ValidatedCommandEnvelope {
        operation,
        command_operation,
        schema_version: expected_schema_version,
    })
}

pub fn validate_command_envelope_payload<'a>(
    envelope: &'a CommandEnvelope,
) -> Result<ValidatedCommandEnvelope<'a>, CommandProtocolError> {
    validate_command_envelope(&envelope.operation, &envelope.schema_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coding_tool_step_module_operation_uses_daemon_core_command_schema() {
        assert_eq!(
            command_operation("run_coding_tool_step_module"),
            Some(CommandOperation::RunCodingToolStepModule)
        );
        assert_eq!(
            expected_command_schema_version("run_coding_tool_step_module"),
            Some(DAEMON_CORE_COMMAND_SCHEMA_VERSION)
        );
    }

    #[test]
    fn daemon_core_operations_use_daemon_core_command_schema() {
        for operation in [
            "plan_workflow_edit_admission_required",
            "plan_coding_tool_result_envelope",
            "plan_runtime_coding_tool_artifact_drafts",
            "project_runtime_coding_tool_artifact_read",
            "plan_post_edit_diagnostics_feedback",
            "project_runtime_diagnostics_repair_policy",
            "plan_lifecycle_admission_required",
            "plan_thread_turn_admission_required",
            "plan_runtime_task_job_create_state_update",
            "project_runtime_task_job_projection",
            "project_runtime_tool_catalog",
            "plan_runtime_mcp_serve_tool_call",
            "project_runtime_mcp_serve_tool_result",
            "project_runtime_managed_session_projection",
            "plan_runtime_managed_session_control",
            "project_runtime_workspace_change_projection",
            "plan_runtime_workspace_change_control",
            "plan_runtime_thread_fork_control",
            "plan_runtime_conversation_artifact_control",
            "project_runtime_diagnostics_repair_projection",
            "project_runtime_conversation_artifact_projection",
            "project_runtime_subagent_projection",
            "plan_model_mount_server_control",
            "plan_model_mount_runtime_survey",
            "plan_model_mount_artifact_endpoint",
            "plan_model_mount_storage_control",
            "plan_model_mount_mcp_workflow",
            "plan_model_mount_catalog_provider_control",
            "plan_model_mount_provider_control",
            "plan_model_mount_capability_token_control",
            "plan_model_mount_vault_control",
            "plan_model_mount_receipt_gate",
            "plan_model_mount_conversation_state",
            "plan_model_mount_stream_completion",
        ] {
            assert_eq!(
                expected_command_schema_version(operation),
                Some(DAEMON_CORE_COMMAND_SCHEMA_VERSION)
            );
        }
    }

    #[test]
    fn mcp_control_catalog_command_transport_is_retired() {
        for operation in [
            "plan_mcp_control_agent_state_update",
            "project_mcp_live_result_replay",
            "validate_mcp_servers",
            "project_mcp_server_validation_input",
            "plan_mcp_manager_status_projection",
            "plan_mcp_manager_validation_projection",
            "plan_mcp_manager_catalog_projection",
            "plan_mcp_manager_catalog_summary_projection",
            "project_mcp_tool_search_projection",
            "project_mcp_tool_fetch_projection",
        ] {
            assert_eq!(command_operation(operation), None);
            assert_eq!(expected_command_schema_version(operation), None);
            assert_eq!(
                validate_command_envelope(operation, DAEMON_CORE_COMMAND_SCHEMA_VERSION)
                    .unwrap_err()
                    .code(),
                "operation_unknown"
            );
        }
    }

    #[test]
    fn model_mount_route_decision_command_transport_is_retired() {
        assert_eq!(command_operation("admit_model_mount_route_decision"), None);
        assert_eq!(
            expected_command_schema_version("admit_model_mount_route_decision"),
            None
        );
        assert_eq!(
            validate_command_envelope(
                "admit_model_mount_route_decision",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            )
            .unwrap_err()
            .code(),
            "operation_unknown"
        );
    }

    #[test]
    fn unknown_operation_has_no_command_schema() {
        assert_eq!(expected_command_schema_version("unknown_operation"), None);
        assert_eq!(
            validate_command_envelope("unknown_operation", STEP_MODULE_COMMAND_SCHEMA_VERSION)
                .unwrap_err()
                .code(),
            "operation_unknown"
        );
    }

    #[test]
    fn context_lifecycle_command_transport_is_retired() {
        for operation in [
            "evaluate_context_budget_policy",
            "evaluate_coding_tool_budget_policy",
            "plan_coding_tool_budget_block",
            "evaluate_compaction_policy",
            "plan_context_compaction",
            "plan_context_compaction_state_update",
        ] {
            assert_eq!(command_operation(operation), None);
            assert_eq!(expected_command_schema_version(operation), None);
        }
    }

    #[test]
    fn runtime_control_command_transport_is_retired() {
        for operation in [
            "plan_coding_tool_budget_recovery_state_update",
            "plan_coding_tool_budget_recovery_control",
            "plan_diagnostics_operator_override_state_update",
            "plan_operator_turn_control_admission_required",
            "plan_operator_interrupt_state_update",
            "plan_operator_steer_state_update",
            "plan_run_cancel_state_update",
            "plan_run_cancel_admission_required",
        ] {
            assert_eq!(command_operation(operation), None);
            assert_eq!(expected_command_schema_version(operation), None);
        }
    }

    #[test]
    fn thread_lifecycle_state_update_command_transport_is_retired() {
        for operation in [
            "plan_thread_control_agent_state_update",
            "plan_runtime_bridge_thread_start_agent_state_update",
            "plan_runtime_bridge_thread_control_agent_state_update",
            "plan_runtime_bridge_turn_run_state_update",
            "plan_subagent_record_state_update",
            "plan_thread_create_state_update",
            "plan_agent_create_state_update",
            "plan_agent_status_state_update",
            "plan_agent_delete_state_update",
            "plan_run_create_state_update",
        ] {
            assert_eq!(command_operation(operation), None);
            assert_eq!(expected_command_schema_version(operation), None);
        }
    }

    #[test]
    fn external_capability_authority_command_transport_is_retired() {
        assert_eq!(
            command_operation("authorize_external_capability_exit"),
            None
        );
        assert_eq!(
            expected_command_schema_version("authorize_external_capability_exit"),
            None
        );
    }

    #[test]
    fn ctee_private_workspace_command_transport_is_retired() {
        assert_eq!(
            command_operation("execute_private_workspace_ctee_action"),
            None
        );
        assert_eq!(
            expected_command_schema_version("execute_private_workspace_ctee_action"),
            None
        );
    }

    #[test]
    fn worker_service_package_command_transport_is_retired() {
        assert_eq!(
            command_operation("admit_worker_service_package_invocation"),
            None
        );
        assert_eq!(
            expected_command_schema_version("admit_worker_service_package_invocation"),
            None
        );
    }

    #[test]
    fn governed_admission_command_transport_is_retired() {
        for operation in [
            "admit_l1_settlement_attempt",
            "admit_governed_runtime_improvement_proposal",
        ] {
            assert_eq!(command_operation(operation), None);
            assert_eq!(expected_command_schema_version(operation), None);
        }
    }

    #[test]
    fn approval_command_transport_is_retired() {
        for operation in [
            "plan_coding_tool_approval_manifest",
            "project_coding_tool_approval_satisfaction",
            "plan_coding_tool_approval_satisfaction",
            "plan_coding_tool_approval_block",
            "project_approval_queue",
            "authorize_approval_decision",
            "plan_approval_request_state_update",
            "plan_approval_decision_state_update",
            "plan_approval_revoke_state_update",
        ] {
            assert_eq!(command_operation(operation), None);
            assert_eq!(expected_command_schema_version(operation), None);
        }
    }

    #[test]
    fn workspace_restore_command_transport_is_retired() {
        for operation in [
            "plan_workspace_restore_apply_policy",
            "preview_workspace_restore_operations",
            "apply_workspace_restore_operations",
            "capture_workspace_snapshot_files",
            "project_workspace_snapshot_list",
            "project_workspace_snapshot_content_package",
            "preview_workspace_snapshot_restore",
            "apply_workspace_snapshot_restore",
        ] {
            assert_eq!(command_operation(operation), None);
            assert_eq!(expected_command_schema_version(operation), None);
        }
    }

    #[test]
    fn runtime_agentgres_command_transport_is_retired() {
        for operation in [
            "admit_storage_backend_write",
            "admit_coding_tool_result_event",
            "admit_coding_tool_command_stream_events",
            "admit_runtime_thread_event",
            "project_runtime_thread_events",
            "project_runtime_thread_event_replay",
            "project_runtime_thread_turn_projection",
            "commit_runtime_run_state",
            "commit_runtime_agent_state",
            "commit_runtime_memory_state",
            "commit_runtime_subagent_state",
            "commit_runtime_artifact_state",
            "commit_runtime_receipt_state",
            "commit_runtime_mcp_live_result_state",
            "commit_runtime_model_mount_record_state",
            "commit_runtime_model_mount_receipt_state",
        ] {
            assert_eq!(command_operation(operation), None);
            assert_eq!(expected_command_schema_version(operation), None);
        }
    }

    #[test]
    fn workspace_trust_command_transport_is_retired() {
        let operation = "plan_workspace_trust_control_state_update";
        assert_eq!(command_operation(operation), None);
        assert_eq!(expected_command_schema_version(operation), None);
    }

    #[test]
    fn thread_memory_command_transport_is_retired() {
        for operation in [
            "project_runtime_memory_projection",
            "plan_runtime_memory_control",
            "plan_memory_manager_status_projection",
            "plan_memory_manager_validation_projection",
            "plan_thread_memory_agent_state_update",
        ] {
            assert_eq!(command_operation(operation), None);
            assert_eq!(expected_command_schema_version(operation), None);
        }
    }

    #[test]
    fn command_envelope_rejects_retired_schema_version_alias() {
        let canonical: CommandEnvelope = serde_json::from_value(serde_json::json!({
            "schema_version": COMMAND_SCHEMA_VERSION,
            "operation": "run_coding_tool_step_module"
        }))
        .expect("canonical command envelope");

        assert_eq!(canonical.schema_version, COMMAND_SCHEMA_VERSION);

        let retired_alias = serde_json::from_value::<CommandEnvelope>(serde_json::json!({
            "schemaVersion": COMMAND_SCHEMA_VERSION,
            "operation": "run_coding_tool_step_module"
        }));

        assert!(
            retired_alias.is_err(),
            "Rust command intake must require canonical schema_version"
        );
    }

    #[test]
    fn daemon_core_operation_rejects_step_module_command_schema() {
        let error = validate_command_envelope(
            "admit_model_mount_invocation",
            STEP_MODULE_COMMAND_SCHEMA_VERSION,
        )
        .expect_err("schema mismatch should fail closed");

        assert_eq!(error.code(), "schema_version_invalid");
        assert!(error.message().contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message().contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn daemon_core_catalog_rejects_step_module_command_schema() {
        for operation in DAEMON_CORE_OPERATIONS {
            let error = validate_command_envelope(operation, STEP_MODULE_COMMAND_SCHEMA_VERSION)
                .expect_err("daemon-core operation must reject StepModule schema");

            assert_eq!(error.code(), "schema_version_invalid");
            assert!(error.message().contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
            assert!(error.message().contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
        }
    }

    #[test]
    fn coding_tool_step_module_operation_rejects_retired_step_module_command_schema() {
        let error = validate_command_envelope(
            "run_coding_tool_step_module",
            STEP_MODULE_COMMAND_SCHEMA_VERSION,
        )
        .expect_err("Rust command protocol rejects retired StepModule schema before dispatch");

        assert_eq!(error.code(), "schema_version_invalid");
        assert!(error.message().contains(DAEMON_CORE_COMMAND_SCHEMA_VERSION));
        assert!(error.message().contains(STEP_MODULE_COMMAND_SCHEMA_VERSION));
    }

    #[test]
    fn command_catalog_operations_have_daemon_core_schema() {
        for operation in DAEMON_CORE_OPERATIONS {
            let command_operation =
                command_operation(operation).expect("daemon-core operation has typed identity");
            assert_eq!(command_operation.as_str(), *operation);
            assert_eq!(
                expected_command_schema_version(operation),
                Some(DAEMON_CORE_COMMAND_SCHEMA_VERSION)
            );
        }
    }

    #[test]
    fn validate_command_envelope_returns_rust_owned_operation_schema() {
        let step_module = validate_command_envelope(
            "run_coding_tool_step_module",
            DAEMON_CORE_COMMAND_SCHEMA_VERSION,
        )
        .expect("coding-tool StepModule command envelope");
        assert_eq!(step_module.operation, "run_coding_tool_step_module");
        assert_eq!(
            step_module.command_operation,
            CommandOperation::RunCodingToolStepModule
        );
        assert_eq!(
            step_module.schema_version,
            DAEMON_CORE_COMMAND_SCHEMA_VERSION
        );

        let daemon_core = validate_command_envelope(
            "admit_model_mount_invocation",
            DAEMON_CORE_COMMAND_SCHEMA_VERSION,
        )
        .expect("daemon-core command envelope");
        assert_eq!(daemon_core.operation, "admit_model_mount_invocation");
        assert_eq!(
            daemon_core.command_operation,
            CommandOperation::AdmitModelMountInvocation
        );
        assert_eq!(
            daemon_core.schema_version,
            DAEMON_CORE_COMMAND_SCHEMA_VERSION
        );
    }

    #[test]
    fn command_envelope_requires_canonical_schema_version_field() {
        let canonical: CommandEnvelope = serde_json::from_value(serde_json::json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "run_coding_tool_step_module"
        }))
        .expect("canonical command envelope");

        let validated =
            validate_command_envelope_payload(&canonical).expect("validated command envelope");
        assert_eq!(
            validated.command_operation,
            CommandOperation::RunCodingToolStepModule
        );

        let retired_alias = serde_json::from_value::<CommandEnvelope>(serde_json::json!({
            "schemaVersion": STEP_MODULE_COMMAND_SCHEMA_VERSION,
            "operation": "run_coding_tool_step_module"
        }));

        assert!(
            retired_alias.is_err(),
            "Rust command envelope must require canonical schema_version"
        );
    }

    #[test]
    fn validate_command_envelope_rejects_schema_mismatch() {
        let error = validate_command_envelope(
            "admit_model_mount_invocation",
            STEP_MODULE_COMMAND_SCHEMA_VERSION,
        )
        .expect_err("schema mismatch should fail closed");

        assert_eq!(error.code(), "schema_version_invalid");
        assert_eq!(
            error.message(),
            "expected ioi.runtime.daemon_core.command.v1 but received ioi.step_module.command_bridge.v1"
        );
    }
}
