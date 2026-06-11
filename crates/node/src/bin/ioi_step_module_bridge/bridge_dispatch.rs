use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, Read};

use super::*;

#[derive(Debug, Deserialize)]
pub(super) struct BridgeEnvelope {
    #[serde(rename = "schema_version")]
    pub(super) schema_version: String,
    pub(super) operation: String,
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

pub(super) fn run_bridge() -> Result<Value, BridgeError> {
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
        "plan_model_mount_backend_lifecycle_required" => {
            let request: ModelMountBackendLifecycleRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_backend_lifecycle_required(request)
        }
        "plan_model_mount_server_control_required" => {
            let request: ModelMountServerControlRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_server_control_required(request)
        }
        "plan_model_mount_runtime_engine_required" => {
            let request: ModelMountRuntimeEngineRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_runtime_engine_required(request)
        }
        "plan_model_mount_tokenizer_required" => {
            let request: ModelMountTokenizerRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_tokenizer_required(request)
        }
        "plan_model_mount_route_control_required" => {
            let request: ModelMountRouteControlRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_route_control_required(request)
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
        "plan_coding_tool_budget_recovery_admission_required" => {
            let request: CodingToolBudgetRecoveryAdmissionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_coding_tool_budget_recovery_admission_required(request)
        }
        "plan_workflow_edit_admission_required" => {
            let request: WorkflowEditAdmissionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_workflow_edit_admission_required(request)
        }
        "plan_diagnostics_repair_admission_required" => {
            let request: DiagnosticsRepairAdmissionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_diagnostics_repair_admission_required(request)
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
        "plan_run_cancel_admission_required" => {
            let request: RunCancelAdmissionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_run_cancel_admission_required(request)
        }
        "plan_skill_hook_registry_projection_required" => {
            let request: SkillHookRegistryProjectionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_skill_hook_registry_projection_required(request)
        }
        "plan_repository_workflow_projection_required" => {
            let request: RepositoryWorkflowProjectionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_repository_workflow_projection_required(request)
        }
        "plan_runtime_tool_catalog_projection_required" => {
            let request: RuntimeToolCatalogProjectionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_runtime_tool_catalog_projection_required(request)
        }
        "plan_runtime_lifecycle_projection_required" => {
            let request: RuntimeLifecycleProjectionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_runtime_lifecycle_projection_required(request)
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

pub(super) fn expected_command_schema_version(operation: &str) -> &'static str {
    if is_daemon_core_operation(operation) {
        DAEMON_CORE_COMMAND_SCHEMA_VERSION
    } else {
        STEP_MODULE_COMMAND_SCHEMA_VERSION
    }
}

pub(super) fn is_daemon_core_operation(operation: &str) -> bool {
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
            | "plan_model_mount_backend_lifecycle_required"
            | "plan_model_mount_server_control_required"
            | "plan_model_mount_runtime_engine_required"
            | "plan_model_mount_tokenizer_required"
            | "plan_model_mount_route_control_required"
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
            | "plan_coding_tool_budget_recovery_admission_required"
            | "plan_diagnostics_repair_admission_required"
            | "plan_diagnostics_operator_override_state_update"
            | "plan_operator_interrupt_state_update"
            | "plan_operator_steer_state_update"
            | "plan_run_cancel_state_update"
            | "plan_run_cancel_admission_required"
            | "plan_skill_hook_registry_projection_required"
            | "plan_repository_workflow_projection_required"
            | "plan_runtime_tool_catalog_projection_required"
            | "plan_runtime_lifecycle_projection_required"
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
