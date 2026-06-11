use serde::Deserialize;

pub const STEP_MODULE_COMMAND_SCHEMA_VERSION: &str = "ioi.step_module.command_bridge.v1";
pub const DAEMON_CORE_COMMAND_SCHEMA_VERSION: &str = "ioi.runtime.daemon_core.command.v1";
pub const COMMAND_SCHEMA_VERSION: &str = STEP_MODULE_COMMAND_SCHEMA_VERSION;

pub const STEP_MODULE_OPERATIONS: &[&str] = &["run_coding_tool_step_module"];

pub const DAEMON_CORE_OPERATIONS: &[&str] = &[
    "admit_storage_backend_write",
    "admit_model_mount_route_decision",
    "admit_model_mount_invocation",
    "admit_model_mount_provider_execution",
    "execute_model_mount_provider_invocation",
    "execute_model_mount_provider_stream_invocation",
    "plan_model_mount_provider_lifecycle",
    "plan_model_mount_provider_inventory",
    "plan_model_mount_instance_lifecycle",
    "admit_model_mount_provider_result",
    "plan_model_mount_backend_process",
    "plan_model_mount_backend_lifecycle_required",
    "plan_model_mount_server_control_required",
    "plan_model_mount_runtime_engine_required",
    "plan_model_mount_tokenizer_required",
    "plan_model_mount_route_control_required",
    "plan_model_mount_accepted_receipt_head",
    "plan_model_mount_accepted_receipt_transition",
    "bind_model_mount_invocation_receipt",
    "plan_model_mount_read_projection",
    "admit_worker_service_package_invocation",
    "commit_runtime_run_state",
    "commit_runtime_agent_state",
    "commit_runtime_memory_state",
    "commit_runtime_subagent_state",
    "commit_runtime_artifact_state",
    "commit_runtime_model_mount_record_state",
    "commit_runtime_model_mount_receipt_state",
    "authorize_external_capability_exit",
    "execute_private_workspace_ctee_action",
    "admit_l1_settlement_attempt",
    "admit_governed_runtime_improvement_proposal",
    "plan_workspace_restore_apply_policy",
    "preview_workspace_restore_operations",
    "apply_workspace_restore_operations",
    "capture_workspace_snapshot_files",
    "plan_coding_tool_approval_manifest",
    "plan_approval_request_state_update",
    "plan_approval_decision_state_update",
    "plan_approval_revoke_state_update",
    "evaluate_context_budget_policy",
    "evaluate_coding_tool_budget_policy",
    "evaluate_compaction_policy",
    "plan_context_compaction",
    "plan_context_compaction_state_update",
    "plan_coding_tool_budget_recovery_state_update",
    "plan_coding_tool_budget_recovery_admission_required",
    "plan_workflow_edit_admission_required",
    "plan_diagnostics_repair_admission_required",
    "plan_diagnostics_operator_override_state_update",
    "plan_operator_turn_control_admission_required",
    "plan_operator_interrupt_state_update",
    "plan_operator_steer_state_update",
    "plan_run_cancel_state_update",
    "plan_run_cancel_admission_required",
    "plan_skill_hook_registry_projection_required",
    "plan_repository_workflow_projection_required",
    "plan_runtime_tool_catalog_projection_required",
    "plan_runtime_lifecycle_projection_required",
    "plan_thread_turn_admission_required",
    "plan_thread_control_agent_state_update",
    "plan_mcp_control_agent_state_update",
    "validate_mcp_servers",
    "project_mcp_server_validation_input",
    "plan_mcp_manager_status_projection",
    "plan_mcp_manager_validation_projection",
    "plan_memory_manager_status_projection",
    "plan_memory_manager_validation_projection",
    "plan_mcp_manager_catalog_projection",
    "plan_mcp_manager_catalog_summary_projection",
    "plan_thread_memory_agent_state_update",
    "plan_runtime_bridge_thread_start_agent_state_update",
    "plan_runtime_bridge_turn_run_state_update",
    "plan_subagent_record_state_update",
    "plan_agent_create_state_update",
    "plan_agent_status_state_update",
    "plan_run_create_state_update",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandFamily {
    StepModule,
    DaemonCore,
}

impl CommandFamily {
    pub fn schema_version(self) -> &'static str {
        match self {
            Self::StepModule => STEP_MODULE_COMMAND_SCHEMA_VERSION,
            Self::DaemonCore => DAEMON_CORE_COMMAND_SCHEMA_VERSION,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOperation {
    RunCodingToolStepModule,
    AdmitStorageBackendWrite,
    AdmitModelMountRouteDecision,
    AdmitModelMountInvocation,
    AdmitModelMountProviderExecution,
    ExecuteModelMountProviderInvocation,
    ExecuteModelMountProviderStreamInvocation,
    PlanModelMountProviderLifecycle,
    PlanModelMountProviderInventory,
    PlanModelMountInstanceLifecycle,
    AdmitModelMountProviderResult,
    PlanModelMountBackendProcess,
    PlanModelMountBackendLifecycleRequired,
    PlanModelMountServerControlRequired,
    PlanModelMountRuntimeEngineRequired,
    PlanModelMountTokenizerRequired,
    PlanModelMountRouteControlRequired,
    PlanModelMountAcceptedReceiptHead,
    PlanModelMountAcceptedReceiptTransition,
    BindModelMountInvocationReceipt,
    PlanModelMountReadProjection,
    AdmitWorkerServicePackageInvocation,
    CommitRuntimeRunState,
    CommitRuntimeAgentState,
    CommitRuntimeMemoryState,
    CommitRuntimeSubagentState,
    CommitRuntimeArtifactState,
    CommitRuntimeModelMountRecordState,
    CommitRuntimeModelMountReceiptState,
    AuthorizeExternalCapabilityExit,
    ExecutePrivateWorkspaceCteeAction,
    AdmitL1SettlementAttempt,
    AdmitGovernedRuntimeImprovementProposal,
    PlanWorkspaceRestoreApplyPolicy,
    PreviewWorkspaceRestoreOperations,
    ApplyWorkspaceRestoreOperations,
    CaptureWorkspaceSnapshotFiles,
    PlanCodingToolApprovalManifest,
    PlanApprovalRequestStateUpdate,
    PlanApprovalDecisionStateUpdate,
    PlanApprovalRevokeStateUpdate,
    EvaluateContextBudgetPolicy,
    EvaluateCodingToolBudgetPolicy,
    EvaluateCompactionPolicy,
    PlanContextCompaction,
    PlanContextCompactionStateUpdate,
    PlanCodingToolBudgetRecoveryStateUpdate,
    PlanCodingToolBudgetRecoveryAdmissionRequired,
    PlanWorkflowEditAdmissionRequired,
    PlanDiagnosticsRepairAdmissionRequired,
    PlanDiagnosticsOperatorOverrideStateUpdate,
    PlanOperatorTurnControlAdmissionRequired,
    PlanOperatorInterruptStateUpdate,
    PlanOperatorSteerStateUpdate,
    PlanRunCancelStateUpdate,
    PlanRunCancelAdmissionRequired,
    PlanSkillHookRegistryProjectionRequired,
    PlanRepositoryWorkflowProjectionRequired,
    PlanRuntimeToolCatalogProjectionRequired,
    PlanRuntimeLifecycleProjectionRequired,
    PlanThreadTurnAdmissionRequired,
    PlanThreadControlAgentStateUpdate,
    PlanMcpControlAgentStateUpdate,
    ValidateMcpServers,
    ProjectMcpServerValidationInput,
    PlanMcpManagerStatusProjection,
    PlanMcpManagerValidationProjection,
    PlanMemoryManagerStatusProjection,
    PlanMemoryManagerValidationProjection,
    PlanMcpManagerCatalogProjection,
    PlanMcpManagerCatalogSummaryProjection,
    PlanThreadMemoryAgentStateUpdate,
    PlanRuntimeBridgeThreadStartAgentStateUpdate,
    PlanRuntimeBridgeTurnRunStateUpdate,
    PlanSubagentRecordStateUpdate,
    PlanAgentCreateStateUpdate,
    PlanAgentStatusStateUpdate,
    PlanRunCreateStateUpdate,
}

impl CommandOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RunCodingToolStepModule => "run_coding_tool_step_module",
            Self::AdmitStorageBackendWrite => "admit_storage_backend_write",
            Self::AdmitModelMountRouteDecision => "admit_model_mount_route_decision",
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
            Self::PlanModelMountBackendLifecycleRequired => {
                "plan_model_mount_backend_lifecycle_required"
            }
            Self::PlanModelMountServerControlRequired => "plan_model_mount_server_control_required",
            Self::PlanModelMountRuntimeEngineRequired => "plan_model_mount_runtime_engine_required",
            Self::PlanModelMountTokenizerRequired => "plan_model_mount_tokenizer_required",
            Self::PlanModelMountRouteControlRequired => "plan_model_mount_route_control_required",
            Self::PlanModelMountAcceptedReceiptHead => "plan_model_mount_accepted_receipt_head",
            Self::PlanModelMountAcceptedReceiptTransition => {
                "plan_model_mount_accepted_receipt_transition"
            }
            Self::BindModelMountInvocationReceipt => "bind_model_mount_invocation_receipt",
            Self::PlanModelMountReadProjection => "plan_model_mount_read_projection",
            Self::AdmitWorkerServicePackageInvocation => "admit_worker_service_package_invocation",
            Self::CommitRuntimeRunState => "commit_runtime_run_state",
            Self::CommitRuntimeAgentState => "commit_runtime_agent_state",
            Self::CommitRuntimeMemoryState => "commit_runtime_memory_state",
            Self::CommitRuntimeSubagentState => "commit_runtime_subagent_state",
            Self::CommitRuntimeArtifactState => "commit_runtime_artifact_state",
            Self::CommitRuntimeModelMountRecordState => "commit_runtime_model_mount_record_state",
            Self::CommitRuntimeModelMountReceiptState => "commit_runtime_model_mount_receipt_state",
            Self::AuthorizeExternalCapabilityExit => "authorize_external_capability_exit",
            Self::ExecutePrivateWorkspaceCteeAction => "execute_private_workspace_ctee_action",
            Self::AdmitL1SettlementAttempt => "admit_l1_settlement_attempt",
            Self::AdmitGovernedRuntimeImprovementProposal => {
                "admit_governed_runtime_improvement_proposal"
            }
            Self::PlanWorkspaceRestoreApplyPolicy => "plan_workspace_restore_apply_policy",
            Self::PreviewWorkspaceRestoreOperations => "preview_workspace_restore_operations",
            Self::ApplyWorkspaceRestoreOperations => "apply_workspace_restore_operations",
            Self::CaptureWorkspaceSnapshotFiles => "capture_workspace_snapshot_files",
            Self::PlanCodingToolApprovalManifest => "plan_coding_tool_approval_manifest",
            Self::PlanApprovalRequestStateUpdate => "plan_approval_request_state_update",
            Self::PlanApprovalDecisionStateUpdate => "plan_approval_decision_state_update",
            Self::PlanApprovalRevokeStateUpdate => "plan_approval_revoke_state_update",
            Self::EvaluateContextBudgetPolicy => "evaluate_context_budget_policy",
            Self::EvaluateCodingToolBudgetPolicy => "evaluate_coding_tool_budget_policy",
            Self::EvaluateCompactionPolicy => "evaluate_compaction_policy",
            Self::PlanContextCompaction => "plan_context_compaction",
            Self::PlanContextCompactionStateUpdate => "plan_context_compaction_state_update",
            Self::PlanCodingToolBudgetRecoveryStateUpdate => {
                "plan_coding_tool_budget_recovery_state_update"
            }
            Self::PlanCodingToolBudgetRecoveryAdmissionRequired => {
                "plan_coding_tool_budget_recovery_admission_required"
            }
            Self::PlanWorkflowEditAdmissionRequired => "plan_workflow_edit_admission_required",
            Self::PlanDiagnosticsRepairAdmissionRequired => {
                "plan_diagnostics_repair_admission_required"
            }
            Self::PlanDiagnosticsOperatorOverrideStateUpdate => {
                "plan_diagnostics_operator_override_state_update"
            }
            Self::PlanOperatorTurnControlAdmissionRequired => {
                "plan_operator_turn_control_admission_required"
            }
            Self::PlanOperatorInterruptStateUpdate => "plan_operator_interrupt_state_update",
            Self::PlanOperatorSteerStateUpdate => "plan_operator_steer_state_update",
            Self::PlanRunCancelStateUpdate => "plan_run_cancel_state_update",
            Self::PlanRunCancelAdmissionRequired => "plan_run_cancel_admission_required",
            Self::PlanSkillHookRegistryProjectionRequired => {
                "plan_skill_hook_registry_projection_required"
            }
            Self::PlanRepositoryWorkflowProjectionRequired => {
                "plan_repository_workflow_projection_required"
            }
            Self::PlanRuntimeToolCatalogProjectionRequired => {
                "plan_runtime_tool_catalog_projection_required"
            }
            Self::PlanRuntimeLifecycleProjectionRequired => {
                "plan_runtime_lifecycle_projection_required"
            }
            Self::PlanThreadTurnAdmissionRequired => "plan_thread_turn_admission_required",
            Self::PlanThreadControlAgentStateUpdate => "plan_thread_control_agent_state_update",
            Self::PlanMcpControlAgentStateUpdate => "plan_mcp_control_agent_state_update",
            Self::ValidateMcpServers => "validate_mcp_servers",
            Self::ProjectMcpServerValidationInput => "project_mcp_server_validation_input",
            Self::PlanMcpManagerStatusProjection => "plan_mcp_manager_status_projection",
            Self::PlanMcpManagerValidationProjection => "plan_mcp_manager_validation_projection",
            Self::PlanMemoryManagerStatusProjection => "plan_memory_manager_status_projection",
            Self::PlanMemoryManagerValidationProjection => {
                "plan_memory_manager_validation_projection"
            }
            Self::PlanMcpManagerCatalogProjection => "plan_mcp_manager_catalog_projection",
            Self::PlanMcpManagerCatalogSummaryProjection => {
                "plan_mcp_manager_catalog_summary_projection"
            }
            Self::PlanThreadMemoryAgentStateUpdate => "plan_thread_memory_agent_state_update",
            Self::PlanRuntimeBridgeThreadStartAgentStateUpdate => {
                "plan_runtime_bridge_thread_start_agent_state_update"
            }
            Self::PlanRuntimeBridgeTurnRunStateUpdate => {
                "plan_runtime_bridge_turn_run_state_update"
            }
            Self::PlanSubagentRecordStateUpdate => "plan_subagent_record_state_update",
            Self::PlanAgentCreateStateUpdate => "plan_agent_create_state_update",
            Self::PlanAgentStatusStateUpdate => "plan_agent_status_state_update",
            Self::PlanRunCreateStateUpdate => "plan_run_create_state_update",
        }
    }

    pub fn command_family(self) -> CommandFamily {
        match self {
            Self::RunCodingToolStepModule => CommandFamily::StepModule,
            _ => CommandFamily::DaemonCore,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCommandEnvelope<'a> {
    pub operation: &'a str,
    pub command_operation: CommandOperation,
    pub command_family: CommandFamily,
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

pub fn command_family(operation: &str) -> Option<CommandFamily> {
    command_operation(operation).map(CommandOperation::command_family)
}

pub fn command_operation(operation: &str) -> Option<CommandOperation> {
    match operation {
        "run_coding_tool_step_module" => Some(CommandOperation::RunCodingToolStepModule),
        "admit_storage_backend_write" => Some(CommandOperation::AdmitStorageBackendWrite),
        "admit_model_mount_route_decision" => Some(CommandOperation::AdmitModelMountRouteDecision),
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
        "plan_model_mount_backend_lifecycle_required" => {
            Some(CommandOperation::PlanModelMountBackendLifecycleRequired)
        }
        "plan_model_mount_server_control_required" => {
            Some(CommandOperation::PlanModelMountServerControlRequired)
        }
        "plan_model_mount_runtime_engine_required" => {
            Some(CommandOperation::PlanModelMountRuntimeEngineRequired)
        }
        "plan_model_mount_tokenizer_required" => {
            Some(CommandOperation::PlanModelMountTokenizerRequired)
        }
        "plan_model_mount_route_control_required" => {
            Some(CommandOperation::PlanModelMountRouteControlRequired)
        }
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
        "admit_worker_service_package_invocation" => {
            Some(CommandOperation::AdmitWorkerServicePackageInvocation)
        }
        "commit_runtime_run_state" => Some(CommandOperation::CommitRuntimeRunState),
        "commit_runtime_agent_state" => Some(CommandOperation::CommitRuntimeAgentState),
        "commit_runtime_memory_state" => Some(CommandOperation::CommitRuntimeMemoryState),
        "commit_runtime_subagent_state" => Some(CommandOperation::CommitRuntimeSubagentState),
        "commit_runtime_artifact_state" => Some(CommandOperation::CommitRuntimeArtifactState),
        "commit_runtime_model_mount_record_state" => {
            Some(CommandOperation::CommitRuntimeModelMountRecordState)
        }
        "commit_runtime_model_mount_receipt_state" => {
            Some(CommandOperation::CommitRuntimeModelMountReceiptState)
        }
        "authorize_external_capability_exit" => {
            Some(CommandOperation::AuthorizeExternalCapabilityExit)
        }
        "execute_private_workspace_ctee_action" => {
            Some(CommandOperation::ExecutePrivateWorkspaceCteeAction)
        }
        "admit_l1_settlement_attempt" => Some(CommandOperation::AdmitL1SettlementAttempt),
        "admit_governed_runtime_improvement_proposal" => {
            Some(CommandOperation::AdmitGovernedRuntimeImprovementProposal)
        }
        "plan_workspace_restore_apply_policy" => {
            Some(CommandOperation::PlanWorkspaceRestoreApplyPolicy)
        }
        "preview_workspace_restore_operations" => {
            Some(CommandOperation::PreviewWorkspaceRestoreOperations)
        }
        "apply_workspace_restore_operations" => {
            Some(CommandOperation::ApplyWorkspaceRestoreOperations)
        }
        "capture_workspace_snapshot_files" => Some(CommandOperation::CaptureWorkspaceSnapshotFiles),
        "plan_coding_tool_approval_manifest" => {
            Some(CommandOperation::PlanCodingToolApprovalManifest)
        }
        "plan_approval_request_state_update" => {
            Some(CommandOperation::PlanApprovalRequestStateUpdate)
        }
        "plan_approval_decision_state_update" => {
            Some(CommandOperation::PlanApprovalDecisionStateUpdate)
        }
        "plan_approval_revoke_state_update" => {
            Some(CommandOperation::PlanApprovalRevokeStateUpdate)
        }
        "evaluate_context_budget_policy" => Some(CommandOperation::EvaluateContextBudgetPolicy),
        "evaluate_coding_tool_budget_policy" => {
            Some(CommandOperation::EvaluateCodingToolBudgetPolicy)
        }
        "evaluate_compaction_policy" => Some(CommandOperation::EvaluateCompactionPolicy),
        "plan_context_compaction" => Some(CommandOperation::PlanContextCompaction),
        "plan_context_compaction_state_update" => {
            Some(CommandOperation::PlanContextCompactionStateUpdate)
        }
        "plan_coding_tool_budget_recovery_state_update" => {
            Some(CommandOperation::PlanCodingToolBudgetRecoveryStateUpdate)
        }
        "plan_coding_tool_budget_recovery_admission_required" => {
            Some(CommandOperation::PlanCodingToolBudgetRecoveryAdmissionRequired)
        }
        "plan_workflow_edit_admission_required" => {
            Some(CommandOperation::PlanWorkflowEditAdmissionRequired)
        }
        "plan_diagnostics_repair_admission_required" => {
            Some(CommandOperation::PlanDiagnosticsRepairAdmissionRequired)
        }
        "plan_diagnostics_operator_override_state_update" => {
            Some(CommandOperation::PlanDiagnosticsOperatorOverrideStateUpdate)
        }
        "plan_operator_turn_control_admission_required" => {
            Some(CommandOperation::PlanOperatorTurnControlAdmissionRequired)
        }
        "plan_operator_interrupt_state_update" => {
            Some(CommandOperation::PlanOperatorInterruptStateUpdate)
        }
        "plan_operator_steer_state_update" => Some(CommandOperation::PlanOperatorSteerStateUpdate),
        "plan_run_cancel_state_update" => Some(CommandOperation::PlanRunCancelStateUpdate),
        "plan_run_cancel_admission_required" => {
            Some(CommandOperation::PlanRunCancelAdmissionRequired)
        }
        "plan_skill_hook_registry_projection_required" => {
            Some(CommandOperation::PlanSkillHookRegistryProjectionRequired)
        }
        "plan_repository_workflow_projection_required" => {
            Some(CommandOperation::PlanRepositoryWorkflowProjectionRequired)
        }
        "plan_runtime_tool_catalog_projection_required" => {
            Some(CommandOperation::PlanRuntimeToolCatalogProjectionRequired)
        }
        "plan_runtime_lifecycle_projection_required" => {
            Some(CommandOperation::PlanRuntimeLifecycleProjectionRequired)
        }
        "plan_thread_turn_admission_required" => {
            Some(CommandOperation::PlanThreadTurnAdmissionRequired)
        }
        "plan_thread_control_agent_state_update" => {
            Some(CommandOperation::PlanThreadControlAgentStateUpdate)
        }
        "plan_mcp_control_agent_state_update" => {
            Some(CommandOperation::PlanMcpControlAgentStateUpdate)
        }
        "validate_mcp_servers" => Some(CommandOperation::ValidateMcpServers),
        "project_mcp_server_validation_input" => {
            Some(CommandOperation::ProjectMcpServerValidationInput)
        }
        "plan_mcp_manager_status_projection" => {
            Some(CommandOperation::PlanMcpManagerStatusProjection)
        }
        "plan_mcp_manager_validation_projection" => {
            Some(CommandOperation::PlanMcpManagerValidationProjection)
        }
        "plan_memory_manager_status_projection" => {
            Some(CommandOperation::PlanMemoryManagerStatusProjection)
        }
        "plan_memory_manager_validation_projection" => {
            Some(CommandOperation::PlanMemoryManagerValidationProjection)
        }
        "plan_mcp_manager_catalog_projection" => {
            Some(CommandOperation::PlanMcpManagerCatalogProjection)
        }
        "plan_mcp_manager_catalog_summary_projection" => {
            Some(CommandOperation::PlanMcpManagerCatalogSummaryProjection)
        }
        "plan_thread_memory_agent_state_update" => {
            Some(CommandOperation::PlanThreadMemoryAgentStateUpdate)
        }
        "plan_runtime_bridge_thread_start_agent_state_update" => {
            Some(CommandOperation::PlanRuntimeBridgeThreadStartAgentStateUpdate)
        }
        "plan_runtime_bridge_turn_run_state_update" => {
            Some(CommandOperation::PlanRuntimeBridgeTurnRunStateUpdate)
        }
        "plan_subagent_record_state_update" => {
            Some(CommandOperation::PlanSubagentRecordStateUpdate)
        }
        "plan_agent_create_state_update" => Some(CommandOperation::PlanAgentCreateStateUpdate),
        "plan_agent_status_state_update" => Some(CommandOperation::PlanAgentStatusStateUpdate),
        "plan_run_create_state_update" => Some(CommandOperation::PlanRunCreateStateUpdate),
        _ => None,
    }
}

pub fn expected_command_schema_version(operation: &str) -> Option<&'static str> {
    command_family(operation).map(CommandFamily::schema_version)
}

pub fn validate_command_envelope<'a>(
    operation: &'a str,
    schema_version: &str,
) -> Result<ValidatedCommandEnvelope<'a>, CommandProtocolError> {
    let command_operation = command_operation(operation)
        .ok_or_else(|| CommandProtocolError::operation_unknown(operation))?;
    let command_family = command_operation.command_family();
    let expected_schema_version = command_family.schema_version();
    if schema_version != expected_schema_version {
        return Err(CommandProtocolError::schema_version_invalid(
            expected_schema_version,
            schema_version,
        ));
    }

    Ok(ValidatedCommandEnvelope {
        operation,
        command_operation,
        command_family,
        schema_version: expected_schema_version,
    })
}

pub fn validate_command_envelope_payload<'a>(
    envelope: &'a CommandEnvelope,
) -> Result<ValidatedCommandEnvelope<'a>, CommandProtocolError> {
    validate_command_envelope(&envelope.operation, &envelope.schema_version)
}

pub fn is_step_module_operation(operation: &str) -> bool {
    command_family(operation) == Some(CommandFamily::StepModule)
}

pub fn is_daemon_core_operation(operation: &str) -> bool {
    command_family(operation) == Some(CommandFamily::DaemonCore)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_module_operation_uses_step_module_command_schema() {
        assert_eq!(
            command_family("run_coding_tool_step_module"),
            Some(CommandFamily::StepModule)
        );
        assert_eq!(
            command_operation("run_coding_tool_step_module"),
            Some(CommandOperation::RunCodingToolStepModule)
        );
        assert_eq!(
            expected_command_schema_version("run_coding_tool_step_module"),
            Some(STEP_MODULE_COMMAND_SCHEMA_VERSION)
        );
        assert!(is_step_module_operation("run_coding_tool_step_module"));
        assert!(!is_daemon_core_operation("run_coding_tool_step_module"));
    }

    #[test]
    fn daemon_core_operations_use_daemon_core_command_schema() {
        for operation in [
            "admit_model_mount_route_decision",
            "authorize_external_capability_exit",
            "execute_private_workspace_ctee_action",
            "plan_workflow_edit_admission_required",
            "validate_mcp_servers",
            "plan_mcp_manager_catalog_summary_projection",
            "commit_runtime_run_state",
            "plan_thread_turn_admission_required",
            "plan_thread_control_agent_state_update",
            "plan_operator_turn_control_admission_required",
        ] {
            assert_eq!(command_family(operation), Some(CommandFamily::DaemonCore));
            assert_eq!(
                expected_command_schema_version(operation),
                Some(DAEMON_CORE_COMMAND_SCHEMA_VERSION)
            );
            assert!(is_daemon_core_operation(operation));
            assert!(!is_step_module_operation(operation));
        }
    }

    #[test]
    fn unknown_operation_has_no_command_schema_family() {
        assert_eq!(command_family("unknown_operation"), None);
        assert_eq!(expected_command_schema_version("unknown_operation"), None);
        assert_eq!(
            validate_command_envelope("unknown_operation", STEP_MODULE_COMMAND_SCHEMA_VERSION)
                .unwrap_err()
                .code(),
            "operation_unknown"
        );
        assert!(!is_step_module_operation("unknown_operation"));
        assert!(!is_daemon_core_operation("unknown_operation"));
    }

    #[test]
    fn command_catalog_operations_have_schema_families() {
        for operation in STEP_MODULE_OPERATIONS {
            let command_operation =
                command_operation(operation).expect("step module operation has typed identity");
            assert_eq!(command_operation.as_str(), *operation);
            assert_eq!(command_family(operation), Some(CommandFamily::StepModule));
            assert_eq!(
                command_operation.command_family(),
                CommandFamily::StepModule
            );
            assert_eq!(
                expected_command_schema_version(operation),
                Some(STEP_MODULE_COMMAND_SCHEMA_VERSION)
            );
        }
        for operation in DAEMON_CORE_OPERATIONS {
            let command_operation =
                command_operation(operation).expect("daemon-core operation has typed identity");
            assert_eq!(command_operation.as_str(), *operation);
            assert_eq!(command_family(operation), Some(CommandFamily::DaemonCore));
            assert_eq!(
                command_operation.command_family(),
                CommandFamily::DaemonCore
            );
            assert_eq!(
                expected_command_schema_version(operation),
                Some(DAEMON_CORE_COMMAND_SCHEMA_VERSION)
            );
        }
    }

    #[test]
    fn validate_command_envelope_returns_rust_owned_family() {
        let step_module = validate_command_envelope(
            "run_coding_tool_step_module",
            STEP_MODULE_COMMAND_SCHEMA_VERSION,
        )
        .expect("step module command envelope");
        assert_eq!(step_module.operation, "run_coding_tool_step_module");
        assert_eq!(
            step_module.command_operation,
            CommandOperation::RunCodingToolStepModule
        );
        assert_eq!(step_module.command_family, CommandFamily::StepModule);
        assert_eq!(
            step_module.schema_version,
            STEP_MODULE_COMMAND_SCHEMA_VERSION
        );

        let daemon_core = validate_command_envelope(
            "admit_model_mount_route_decision",
            DAEMON_CORE_COMMAND_SCHEMA_VERSION,
        )
        .expect("daemon-core command envelope");
        assert_eq!(daemon_core.operation, "admit_model_mount_route_decision");
        assert_eq!(
            daemon_core.command_operation,
            CommandOperation::AdmitModelMountRouteDecision
        );
        assert_eq!(daemon_core.command_family, CommandFamily::DaemonCore);
        assert_eq!(
            daemon_core.schema_version,
            DAEMON_CORE_COMMAND_SCHEMA_VERSION
        );
    }

    #[test]
    fn command_envelope_requires_canonical_schema_version_field() {
        let canonical: CommandEnvelope = serde_json::from_value(serde_json::json!({
            "schema_version": STEP_MODULE_COMMAND_SCHEMA_VERSION,
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
    fn validate_command_envelope_rejects_schema_family_mismatch() {
        let error = validate_command_envelope(
            "admit_model_mount_route_decision",
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
