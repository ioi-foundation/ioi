use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::io::{self, Read};

use super::{
    agentgres_command::*, approval::*, authority::*, coding_tool_artifact::*, coding_tool_event::*,
    coding_tool_step_module::*, command_protocol::CommandOperation, governed_admission::*,
    governed_receipt::*, model_mount::*, model_mount_receipt::*, policy::*, repository_workflow::*,
    runtime_conversation_artifact_control::*, runtime_conversation_artifact_projection::*,
    runtime_diagnostics_repair_control::*, runtime_diagnostics_repair_policy::*,
    runtime_diagnostics_repair_projection::*, runtime_lifecycle::*,
    runtime_managed_session_control::*, runtime_mcp_serve::*, runtime_memory_control::*,
    runtime_memory_projection::*, runtime_subagent_control::*, runtime_subagent_projection::*,
    runtime_thread_event::*, runtime_thread_fork_control::*, runtime_tool_catalog::*,
    runtime_workflow_edit_control::*, runtime_workspace_change_control::*, skill_hook_registry::*,
    workspace_restore::*,
};

#[derive(Debug, Clone)]
pub struct CommandDispatchError {
    code: &'static str,
    message: String,
}

impl CommandDispatchError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone)]
pub struct CommandTransportError {
    code: &'static str,
    message: String,
}

impl CommandTransportError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

pub fn run_daemon_core_command_response_from_stdin() -> Value {
    match run_daemon_core_command_from_stdin() {
        Ok(response) => json!({ "ok": true, "result": response }),
        Err(error) => json!({
            "ok": false,
            "error": {
                "code": error.code(),
                "message": error.message(),
            }
        }),
    }
}

pub fn run_daemon_core_command_from_stdin() -> Result<Value, CommandTransportError> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| CommandTransportError::new("stdin_read_failed", error.to_string()))?;
    run_daemon_core_command_from_json_str(&input)
}

pub fn run_daemon_core_command_from_json_str(input: &str) -> Result<Value, CommandTransportError> {
    let raw_request: Value = serde_json::from_str(input)
        .map_err(|error| CommandTransportError::new("request_json_invalid", error.to_string()))?;
    run_daemon_core_command_from_value(raw_request)
}

pub fn run_daemon_core_command_from_value(
    raw_request: Value,
) -> Result<Value, CommandTransportError> {
    let envelope: super::command_protocol::CommandEnvelope =
        serde_json::from_value(raw_request.clone()).map_err(|error| {
            CommandTransportError::new("request_json_invalid", error.to_string())
        })?;
    let validated =
        super::command_protocol::validate_command_envelope_payload(&envelope).map_err(|error| {
            let (code, message) = error.into_parts();
            CommandTransportError::new(code, message)
        })?;

    dispatch_command_operation_response(validated.command_operation, raw_request)
        .map_err(|error| CommandTransportError::new(error.code(), error.message().to_string()))
}

pub fn dispatch_command_operation_response(
    command_operation: CommandOperation,
    raw_request: Value,
) -> Result<Value, CommandDispatchError> {
    match command_operation {
        CommandOperation::RunCodingToolStepModule => {
            run_coding_tool_step_module_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::AdmitModelMountRouteDecision => {
            admit_model_mount_route_decision_response(decode(raw_request)?).map_err(|error| {
                CommandDispatchError::new(
                    "model_mount_route_decision_rejected",
                    format!("{error:?}"),
                )
            })
        }
        CommandOperation::AdmitModelMountInvocation => {
            admit_model_mount_invocation_response(decode(raw_request)?).map_err(|error| {
                CommandDispatchError::new("model_mount_invocation_rejected", format!("{error:?}"))
            })
        }
        CommandOperation::AdmitModelMountProviderExecution => {
            admit_model_mount_provider_execution_response(decode(raw_request)?).map_err(|error| {
                CommandDispatchError::new(
                    "model_mount_provider_execution_rejected",
                    format!("{error:?}"),
                )
            })
        }
        CommandOperation::ExecuteModelMountProviderInvocation => {
            execute_model_mount_provider_invocation_response(decode(raw_request)?).map_err(
                |error| {
                    CommandDispatchError::new(
                        "model_mount_provider_invocation_rejected",
                        format!("{error:?}"),
                    )
                },
            )
        }
        CommandOperation::ExecuteModelMountProviderStreamInvocation => {
            execute_model_mount_provider_stream_invocation_response(decode(raw_request)?).map_err(
                |error| {
                    CommandDispatchError::new(
                        "model_mount_provider_stream_invocation_rejected",
                        format!("{error:?}"),
                    )
                },
            )
        }
        CommandOperation::PlanModelMountProviderLifecycle => {
            plan_model_mount_provider_lifecycle_response(decode(raw_request)?).map_err(|error| {
                model_mount_error("model_mount_provider_lifecycle_rejected", error)
            })
        }
        CommandOperation::PlanModelMountProviderInventory => {
            plan_model_mount_provider_inventory_response(decode(raw_request)?).map_err(|error| {
                model_mount_error("model_mount_provider_inventory_rejected", error)
            })
        }
        CommandOperation::PlanModelMountInstanceLifecycle => {
            plan_model_mount_instance_lifecycle_response(decode(raw_request)?).map_err(|error| {
                model_mount_error("model_mount_instance_lifecycle_rejected", error)
            })
        }
        CommandOperation::AdmitModelMountProviderResult => {
            admit_model_mount_provider_result_response(decode(raw_request)?).map_err(|error| {
                CommandDispatchError::new(
                    "model_mount_provider_result_rejected",
                    format!("{error:?}"),
                )
            })
        }
        CommandOperation::PlanModelMountBackendProcess => {
            plan_model_mount_backend_process_response(decode(raw_request)?).map_err(|error| {
                model_mount_error("model_mount_backend_process_plan_rejected", error)
            })
        }
        CommandOperation::PlanModelMountBackendLifecycle => {
            plan_model_mount_backend_lifecycle_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_backend_lifecycle_invalid", error))
        }
        CommandOperation::PlanModelMountArtifactEndpoint => {
            plan_model_mount_artifact_endpoint_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_artifact_endpoint_invalid", error))
        }
        CommandOperation::PlanModelMountStorageControl => {
            plan_model_mount_storage_control_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_storage_control_invalid", error))
        }
        CommandOperation::PlanModelMountMcpWorkflow => {
            plan_model_mount_mcp_workflow_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_mcp_workflow_invalid", error))
        }
        CommandOperation::PlanModelMountServerControl => {
            plan_model_mount_server_control_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_server_control_invalid", error))
        }
        CommandOperation::PlanModelMountRuntimeEngine => {
            plan_model_mount_runtime_engine_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_runtime_engine_invalid", error))
        }
        CommandOperation::PlanModelMountRuntimeSurvey => {
            plan_model_mount_runtime_survey_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_runtime_survey_invalid", error))
        }
        CommandOperation::PlanModelMountTokenizerRequired => {
            plan_model_mount_tokenizer_required_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_tokenizer_required_invalid", error))
        }
        CommandOperation::PlanModelMountRouteControlRequired => {
            plan_model_mount_route_control_required_response(decode(raw_request)?).map_err(
                |error| model_mount_error("model_mount_route_control_required_invalid", error),
            )
        }
        CommandOperation::PlanModelMountRouteControl => {
            plan_model_mount_route_control_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_route_control_invalid", error))
        }
        CommandOperation::PlanModelMountCatalogProviderControl => {
            plan_model_mount_catalog_provider_control_response(decode(raw_request)?).map_err(
                |error| model_mount_error("model_mount_catalog_provider_control_invalid", error),
            )
        }
        CommandOperation::PlanModelMountProviderControl => {
            plan_model_mount_provider_control_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_provider_control_invalid", error))
        }
        CommandOperation::PlanModelMountCapabilityTokenControl => {
            plan_model_mount_capability_token_control_response(decode(raw_request)?).map_err(
                |error| model_mount_error("model_mount_capability_token_control_invalid", error),
            )
        }
        CommandOperation::PlanModelMountVaultControl => {
            plan_model_mount_vault_control_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_vault_control_invalid", error))
        }
        CommandOperation::PlanModelMountReceiptGate => {
            plan_model_mount_receipt_gate_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_receipt_gate_invalid", error))
        }
        CommandOperation::PlanModelMountTokenizer => {
            plan_model_mount_tokenizer_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_tokenizer_invalid", error))
        }
        CommandOperation::PlanModelMountConversationState => {
            plan_model_mount_conversation_state_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_conversation_state_invalid", error))
        }
        CommandOperation::PlanModelMountStreamCompletion => {
            plan_model_mount_stream_completion_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_stream_completion_invalid", error))
        }
        CommandOperation::PlanModelMountStreamCancel => {
            plan_model_mount_stream_cancel_response(decode(raw_request)?)
                .map_err(|error| model_mount_error("model_mount_stream_cancel_invalid", error))
        }
        CommandOperation::PlanModelMountAcceptedReceiptHead => {
            plan_model_mount_accepted_receipt_head_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanModelMountAcceptedReceiptTransition => {
            plan_model_mount_accepted_receipt_transition_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::BindModelMountInvocationReceipt => {
            bind_model_mount_invocation_receipt_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanModelMountReadProjection => {
            plan_model_mount_read_projection_response(decode(raw_request)?)
                .map_err(CommandDispatchError::from)
        }
        CommandOperation::ExecutePrivateWorkspaceCteeAction => {
            execute_private_workspace_ctee_action_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::AdmitWorkerServicePackageInvocation => {
            admit_worker_service_package_invocation_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::AdmitL1SettlementAttempt => {
            admit_l1_settlement_attempt_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::AdmitGovernedRuntimeImprovementProposal => {
            admit_governed_runtime_improvement_proposal_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanWorkspaceRestoreApplyPolicy => {
            plan_workspace_restore_apply_policy_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PreviewWorkspaceRestoreOperations => {
            preview_workspace_restore_operations_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ApplyWorkspaceRestoreOperations => {
            apply_workspace_restore_operations_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::CaptureWorkspaceSnapshotFiles => {
            capture_workspace_snapshot_files_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ProjectWorkspaceSnapshotList => {
            project_workspace_snapshot_list_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ProjectWorkspaceSnapshotContentPackage => {
            project_workspace_snapshot_content_package_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PreviewWorkspaceSnapshotRestore => {
            preview_workspace_snapshot_restore_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ApplyWorkspaceSnapshotRestore => {
            apply_workspace_snapshot_restore_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanCodingToolApprovalManifest => {
            plan_coding_tool_approval_manifest_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ProjectCodingToolApprovalSatisfaction => {
            project_coding_tool_approval_satisfaction_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanCodingToolApprovalSatisfaction => {
            plan_coding_tool_approval_satisfaction_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanCodingToolApprovalBlock => {
            plan_coding_tool_approval_block_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ProjectApprovalQueue => {
            project_approval_queue_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::AuthorizeApprovalDecision => {
            authorize_approval_decision_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::AdmitCodingToolResultEvent => {
            admit_coding_tool_result_event_response(decode(raw_request)?).map_err(|error| {
                CommandDispatchError::new(
                    "coding_tool_result_event_admission_rejected",
                    format!("{error:?}"),
                )
            })
        }
        CommandOperation::PlanCodingToolResultEnvelope => {
            plan_coding_tool_result_envelope_response(decode(raw_request)?).map_err(|error| {
                CommandDispatchError::new(
                    "coding_tool_result_envelope_plan_rejected",
                    format!("{error:?}"),
                )
            })
        }
        CommandOperation::PlanRuntimeCodingToolArtifactDrafts => {
            plan_runtime_coding_tool_artifact_drafts_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::ProjectRuntimeCodingToolArtifactRead => {
            project_runtime_coding_tool_artifact_read_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::AdmitCodingToolCommandStreamEvents => {
            admit_coding_tool_command_stream_events_response(decode(raw_request)?).map_err(
                |error| {
                    CommandDispatchError::new(
                        "coding_tool_command_stream_admission_rejected",
                        format!("{error:?}"),
                    )
                },
            )
        }
        CommandOperation::AdmitRuntimeThreadEvent => {
            admit_runtime_thread_event_response(decode(raw_request)?).map_err(|error| {
                CommandDispatchError::new(
                    "runtime_thread_event_admission_rejected",
                    format!("{error:?}"),
                )
            })
        }
        CommandOperation::ProjectRuntimeThreadEvents => {
            project_runtime_thread_events_response(decode(raw_request)?).map_err(|error| {
                CommandDispatchError::new(
                    "runtime_thread_event_projection_rejected",
                    format!("{error:?}"),
                )
            })
        }
        CommandOperation::ProjectRuntimeThreadEventReplay => {
            project_runtime_thread_event_replay_response(decode(raw_request)?).map_err(|error| {
                CommandDispatchError::new(
                    "runtime_thread_event_replay_rejected",
                    format!("{error:?}"),
                )
            })
        }
        CommandOperation::ProjectRuntimeThreadTurnProjection => {
            project_runtime_thread_turn_projection_response(decode(raw_request)?).map_err(|error| {
                CommandDispatchError::new(
                    "runtime_thread_turn_projection_rejected",
                    format!("{error:?}"),
                )
            })
        }
        CommandOperation::PlanPostEditDiagnosticsFeedback => {
            plan_post_edit_diagnostics_feedback_response(decode(raw_request)?).map_err(|error| {
                CommandDispatchError::new(
                    "post_edit_diagnostics_feedback_plan_rejected",
                    format!("{error:?}"),
                )
            })
        }
        CommandOperation::PlanApprovalRequestStateUpdate => {
            plan_approval_request_state_update_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanApprovalDecisionStateUpdate => {
            plan_approval_decision_state_update_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanApprovalRevokeStateUpdate => {
            plan_approval_revoke_state_update_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::AuthorizeExternalCapabilityExit => {
            authorize_external_capability_exit_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::EvaluateContextBudgetPolicy => {
            evaluate_context_budget_policy_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::EvaluateCodingToolBudgetPolicy => {
            evaluate_coding_tool_budget_policy_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanCodingToolBudgetBlock => {
            plan_coding_tool_budget_block_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::EvaluateCompactionPolicy => {
            evaluate_compaction_policy_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanContextCompaction => {
            plan_context_compaction_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanContextCompactionStateUpdate => {
            plan_context_compaction_state_update_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanCodingToolBudgetRecoveryStateUpdate => {
            plan_coding_tool_budget_recovery_state_update_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanCodingToolBudgetRecoveryControl => {
            plan_coding_tool_budget_recovery_control_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanWorkflowEditAdmissionRequired => {
            plan_workflow_edit_admission_required_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanDiagnosticsRepairAdmissionRequired => {
            plan_diagnostics_repair_admission_required_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanRuntimeDiagnosticsRepairControl => {
            plan_runtime_diagnostics_repair_control_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanRuntimeDiagnosticsRepairRetryRun => {
            plan_runtime_diagnostics_repair_retry_run_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::ProjectRuntimeDiagnosticsRepairProjection => {
            project_runtime_diagnostics_repair_projection_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::ProjectRuntimeDiagnosticsRepairPolicy => {
            project_runtime_diagnostics_repair_policy_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanDiagnosticsOperatorOverrideStateUpdate => {
            plan_diagnostics_operator_override_state_update_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanOperatorTurnControlAdmissionRequired => {
            plan_operator_turn_control_admission_required_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanOperatorInterruptStateUpdate => {
            plan_operator_interrupt_state_update_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanOperatorSteerStateUpdate => {
            plan_operator_steer_state_update_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanRunCancelStateUpdate => {
            plan_run_cancel_state_update_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanRunCancelAdmissionRequired => {
            plan_run_cancel_admission_required_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanRuntimeTaskJobCancelStateUpdate => {
            plan_runtime_task_job_cancel_state_update_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanRuntimeTaskJobCreateStateUpdate => {
            plan_runtime_task_job_create_state_update_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::ProjectRuntimeTaskJobProjection => {
            project_runtime_task_job_projection_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ProjectSkillHookRegistry => {
            project_skill_hook_registry_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ProjectRepositoryWorkflow => {
            project_repository_workflow_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ProjectRuntimeToolCatalog => {
            project_runtime_tool_catalog_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ProjectRuntimeLifecycle => {
            project_runtime_lifecycle_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ProjectRuntimeMemoryProjection => {
            project_runtime_memory_projection_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanRuntimeMemoryControl => {
            plan_runtime_memory_control_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanRuntimeMcpServeToolCall => {
            plan_runtime_mcp_serve_tool_call_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ProjectRuntimeMcpServeToolResult => {
            project_runtime_mcp_serve_tool_result_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanRuntimeWorkflowEditControl => {
            plan_runtime_workflow_edit_control_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ProjectRuntimeManagedSessionProjection => {
            project_runtime_managed_session_projection_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanRuntimeManagedSessionControl => {
            plan_runtime_managed_session_control_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ProjectRuntimeWorkspaceChangeProjection => {
            project_runtime_workspace_change_projection_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanRuntimeWorkspaceChangeControl => {
            plan_runtime_workspace_change_control_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanRuntimeThreadForkControl => {
            plan_runtime_thread_fork_control_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanRuntimeConversationArtifactControl => {
            plan_runtime_conversation_artifact_control_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::ProjectRuntimeConversationArtifactProjection => {
            project_runtime_conversation_artifact_projection_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::ProjectRuntimeSubagentProjection => {
            project_runtime_subagent_projection_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanRuntimeSubagentControl => {
            plan_runtime_subagent_control_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanLifecycleAdmissionRequired => {
            plan_lifecycle_admission_required_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanThreadTurnAdmissionRequired => {
            plan_thread_turn_admission_required_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanThreadControlAgentStateUpdate => {
            plan_thread_control_agent_state_update_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanWorkspaceTrustControlStateUpdate => {
            plan_workspace_trust_control_state_update_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanMcpControlAgentStateUpdate => {
            plan_mcp_control_agent_state_update_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ProjectMcpLiveResultReplay => {
            project_mcp_live_result_replay_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ValidateMcpServers => {
            validate_mcp_servers_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ProjectMcpServerValidationInput => {
            project_mcp_server_validation_input_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanMcpManagerStatusProjection => {
            plan_mcp_manager_status_projection_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanMcpManagerValidationProjection => {
            plan_mcp_manager_validation_projection_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanMemoryManagerStatusProjection => {
            plan_memory_manager_status_projection_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanMemoryManagerValidationProjection => {
            plan_memory_manager_validation_projection_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanMcpManagerCatalogProjection => {
            plan_mcp_manager_catalog_projection_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanMcpManagerCatalogSummaryProjection => {
            plan_mcp_manager_catalog_summary_projection_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::ProjectMcpToolSearchProjection => {
            project_mcp_tool_search_projection_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::ProjectMcpToolFetchProjection => {
            project_mcp_tool_fetch_projection_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanThreadMemoryAgentStateUpdate => {
            plan_thread_memory_agent_state_update_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanRuntimeBridgeThreadStartAgentStateUpdate => {
            plan_runtime_bridge_thread_start_agent_state_update_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanRuntimeBridgeThreadControlAgentStateUpdate => {
            plan_runtime_bridge_thread_control_agent_state_update_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanRuntimeBridgeTurnRunStateUpdate => {
            plan_runtime_bridge_turn_run_state_update_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::PlanSubagentRecordStateUpdate => {
            plan_subagent_record_state_update_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanThreadCreateStateUpdate => {
            plan_thread_create_state_update_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanAgentCreateStateUpdate => {
            plan_agent_create_state_update_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanAgentStatusStateUpdate => {
            plan_agent_status_state_update_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanAgentDeleteStateUpdate => {
            plan_agent_delete_state_update_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::PlanRunCreateStateUpdate => {
            plan_run_create_state_update_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::AdmitStorageBackendWrite => {
            admit_storage_backend_write_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::CommitRuntimeRunState => {
            commit_runtime_run_state_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::CommitRuntimeAgentState => {
            commit_runtime_agent_state_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::CommitRuntimeMemoryState => {
            commit_runtime_memory_state_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::CommitRuntimeSubagentState => {
            commit_runtime_subagent_state_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::CommitRuntimeArtifactState => {
            commit_runtime_artifact_state_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::CommitRuntimeReceiptState => {
            commit_runtime_receipt_state_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::CommitRuntimeMcpLiveResultState => {
            commit_runtime_mcp_live_result_state_response(decode(raw_request)?).map_err(Into::into)
        }
        CommandOperation::CommitRuntimeModelMountRecordState => {
            commit_runtime_model_mount_record_state_response(decode(raw_request)?)
                .map_err(Into::into)
        }
        CommandOperation::CommitRuntimeModelMountReceiptState => {
            commit_runtime_model_mount_receipt_state_response(decode(raw_request)?)
                .map_err(Into::into)
        }
    }
}

fn decode<T: DeserializeOwned>(raw_request: Value) -> Result<T, CommandDispatchError> {
    serde_json::from_value(raw_request)
        .map_err(|error| CommandDispatchError::new("request_json_invalid", error.to_string()))
}

fn model_mount_error(code: &'static str, error: ModelMountError) -> CommandDispatchError {
    CommandDispatchError::new(code, format!("{error:?}"))
}

macro_rules! command_error_from {
    ($error_type:ty) => {
        impl From<$error_type> for CommandDispatchError {
            fn from(error: $error_type) -> Self {
                Self::new(error.code(), error.message().to_string())
            }
        }
    };
}

command_error_from!(AgentgresCommandError);
command_error_from!(ApprovalCommandError);
command_error_from!(AuthorityCommandError);
command_error_from!(CodingToolStepModuleCommandError);
command_error_from!(GovernedAdmissionError);
command_error_from!(GovernedReceiptError);
command_error_from!(RuntimeCodingToolArtifactDraftPlanCommandError);
command_error_from!(RuntimeCodingToolArtifactReadProjectionCommandError);
command_error_from!(ModelMountReceiptError);
command_error_from!(AdmissionRequiredCommandError);
command_error_from!(ContextPolicyCommandError);
command_error_from!(CodingToolBudgetRecoveryCommandError);
command_error_from!(OperatorControlCommandError);
command_error_from!(RunCancelCommandError);
command_error_from!(RuntimeTaskJobCancelCommandError);
command_error_from!(RuntimeTaskJobCreateCommandError);
command_error_from!(RuntimeTaskJobProjectionCommandError);
command_error_from!(SkillHookRegistryProjectionCommandError);
command_error_from!(RepositoryWorkflowProjectionCommandError);
command_error_from!(RuntimeLifecycleProjectionCommandError);
command_error_from!(RuntimeDiagnosticsRepairControlCommandError);
command_error_from!(RuntimeDiagnosticsRepairProjectionCommandError);
command_error_from!(RuntimeDiagnosticsRepairPolicyCommandError);
command_error_from!(RuntimeManagedSessionCommandError);
command_error_from!(RuntimeMemoryControlCommandError);
command_error_from!(RuntimeMemoryProjectionCommandError);
command_error_from!(RuntimeMcpServeCommandError);
command_error_from!(RuntimeWorkspaceChangeCommandError);
command_error_from!(RuntimeThreadForkCommandError);
command_error_from!(RuntimeConversationArtifactControlCommandError);
command_error_from!(RuntimeConversationArtifactProjectionCommandError);
command_error_from!(RuntimeSubagentControlCommandError);
command_error_from!(RuntimeSubagentProjectionCommandError);
command_error_from!(RuntimeWorkflowEditControlCommandError);
command_error_from!(ThreadLifecycleCommandError);
command_error_from!(WorkspaceTrustControlCommandError);
command_error_from!(RuntimeToolCatalogProjectionCommandError);
command_error_from!(McpMemoryCommandError);
command_error_from!(WorkspaceRestoreCommandError);

impl From<ModelMountReadProjectionError> for CommandDispatchError {
    fn from(error: ModelMountReadProjectionError) -> Self {
        Self::new(error.code, error.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::command_protocol::DAEMON_CORE_COMMAND_SCHEMA_VERSION;

    #[test]
    fn command_transport_rejects_invalid_json() {
        let error = run_daemon_core_command_from_json_str("{not-json").unwrap_err();
        assert_eq!(error.code(), "request_json_invalid");
    }

    #[test]
    fn command_transport_rejects_retired_schema_version_alias() {
        let request = json!({
            "schemaVersion": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "run_coding_tool_step_module"
        });
        let error = run_daemon_core_command_from_value(request).unwrap_err();
        assert_eq!(error.code(), "request_json_invalid");
    }

    #[test]
    fn command_transport_rejects_unknown_operation_before_dispatch() {
        let request = json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "unknown_operation"
        });
        let error = run_daemon_core_command_from_value(request).unwrap_err();
        assert_eq!(error.code(), "operation_unknown");
    }
}
