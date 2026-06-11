use serde_json::Value;

use super::*;

pub(super) fn dispatch_bridge_operation(
    operation: &str,
    command_family: CommandFamily,
    raw_request: Value,
) -> Result<Value, BridgeError> {
    match (command_family, operation) {
        (CommandFamily::StepModule, "run_coding_tool_step_module") => {
            let request: StepModuleBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            run_coding_tool_step_module(request)
        }
        (CommandFamily::DaemonCore, "admit_model_mount_route_decision") => {
            let request: ModelMountRouteDecisionBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_model_mount_route_decision(request)
        }
        (CommandFamily::DaemonCore, "admit_model_mount_invocation") => {
            let request: ModelMountInvocationAdmissionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_model_mount_invocation(request)
        }
        (CommandFamily::DaemonCore, "admit_model_mount_provider_execution") => {
            let request: ModelMountProviderExecutionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_model_mount_provider_execution(request)
        }
        (CommandFamily::DaemonCore, "execute_model_mount_provider_invocation") => {
            let request: ModelMountProviderInvocationBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            execute_model_mount_provider_invocation(request)
        }
        (CommandFamily::DaemonCore, "execute_model_mount_provider_stream_invocation") => {
            let request: ModelMountProviderInvocationBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            execute_model_mount_provider_stream_invocation(request)
        }
        (CommandFamily::DaemonCore, "plan_model_mount_provider_lifecycle") => {
            let request: ModelMountProviderLifecycleBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_provider_lifecycle(request)
        }
        (CommandFamily::DaemonCore, "plan_model_mount_provider_inventory") => {
            let request: ModelMountProviderInventoryBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_provider_inventory(request)
        }
        (CommandFamily::DaemonCore, "plan_model_mount_instance_lifecycle") => {
            let request: ModelMountInstanceLifecycleBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_instance_lifecycle(request)
        }
        (CommandFamily::DaemonCore, "admit_model_mount_provider_result") => {
            let request: ModelMountProviderResultAdmissionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_model_mount_provider_result(request)
        }
        (CommandFamily::DaemonCore, "plan_model_mount_backend_process") => {
            let request: ModelMountBackendProcessPlanBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_backend_process(request)
        }
        (CommandFamily::DaemonCore, "plan_model_mount_backend_lifecycle_required") => {
            let request: ModelMountBackendLifecycleRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_backend_lifecycle_required(request)
        }
        (CommandFamily::DaemonCore, "plan_model_mount_server_control_required") => {
            let request: ModelMountServerControlRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_server_control_required(request)
        }
        (CommandFamily::DaemonCore, "plan_model_mount_runtime_engine_required") => {
            let request: ModelMountRuntimeEngineRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_runtime_engine_required(request)
        }
        (CommandFamily::DaemonCore, "plan_model_mount_tokenizer_required") => {
            let request: ModelMountTokenizerRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_tokenizer_required(request)
        }
        (CommandFamily::DaemonCore, "plan_model_mount_route_control_required") => {
            let request: ModelMountRouteControlRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_route_control_required(request)
        }
        (CommandFamily::DaemonCore, "plan_model_mount_accepted_receipt_head") => {
            let request: ModelMountAcceptedReceiptHeadBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_accepted_receipt_head(request)
        }
        (CommandFamily::DaemonCore, "plan_model_mount_accepted_receipt_transition") => {
            let request: ModelMountAcceptedReceiptTransitionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_accepted_receipt_transition(request)
        }
        (CommandFamily::DaemonCore, "bind_model_mount_invocation_receipt") => {
            let request: ModelMountInvocationReceiptBindingBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            bind_model_mount_invocation_receipt(request)
        }
        (CommandFamily::DaemonCore, "plan_model_mount_read_projection") => {
            let request: ModelMountReadProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_read_projection(request)
        }
        (CommandFamily::DaemonCore, "execute_private_workspace_ctee_action") => {
            let request: CteePrivateWorkspaceBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            execute_private_workspace_ctee_action(request)
        }
        (CommandFamily::DaemonCore, "admit_worker_service_package_invocation") => {
            let request: WorkerServicePackageInvocationBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_worker_service_package_invocation(request)
        }
        (CommandFamily::DaemonCore, "admit_l1_settlement_attempt") => {
            let request: L1SettlementAdmissionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_l1_settlement_attempt(request)
        }
        (CommandFamily::DaemonCore, "admit_governed_runtime_improvement_proposal") => {
            let request: GovernedRuntimeImprovementBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_governed_runtime_improvement_proposal(request)
        }
        (CommandFamily::DaemonCore, "plan_workspace_restore_apply_policy") => {
            let request: WorkspaceRestoreApplyPolicyBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_workspace_restore_apply_policy(request)
        }
        (CommandFamily::DaemonCore, "preview_workspace_restore_operations") => {
            let request: WorkspaceRestoreOperationsBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            preview_workspace_restore_operations(request)
        }
        (CommandFamily::DaemonCore, "apply_workspace_restore_operations") => {
            let request: WorkspaceRestoreOperationsBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            apply_workspace_restore_operations(request)
        }
        (CommandFamily::DaemonCore, "capture_workspace_snapshot_files") => {
            let request: WorkspaceSnapshotCaptureBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            capture_workspace_snapshot_files(request)
        }
        (CommandFamily::DaemonCore, "plan_coding_tool_approval_manifest") => {
            let request: CodingToolApprovalBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_coding_tool_approval_manifest(request)
        }
        (CommandFamily::DaemonCore, "plan_approval_request_state_update") => {
            let request: ApprovalRequestStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_approval_request_state_update(request)
        }
        (CommandFamily::DaemonCore, "plan_approval_decision_state_update") => {
            let request: ApprovalDecisionStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_approval_decision_state_update(request)
        }
        (CommandFamily::DaemonCore, "plan_approval_revoke_state_update") => {
            let request: ApprovalRevokeStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_approval_revoke_state_update(request)
        }
        (CommandFamily::DaemonCore, "authorize_external_capability_exit") => {
            let request: ExternalCapabilityExitAuthorityBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            authorize_external_capability_exit(request)
        }
        (CommandFamily::DaemonCore, "evaluate_context_budget_policy") => {
            let request: ContextBudgetPolicyBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            evaluate_context_budget_policy(request)
        }
        (CommandFamily::DaemonCore, "evaluate_coding_tool_budget_policy") => {
            let request: ContextBudgetPolicyBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            evaluate_coding_tool_budget_policy(request)
        }
        (CommandFamily::DaemonCore, "evaluate_compaction_policy") => {
            let request: CompactionPolicyBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            evaluate_compaction_policy(request)
        }
        (CommandFamily::DaemonCore, "plan_context_compaction") => {
            let request: ContextCompactionPlanBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_context_compaction(request)
        }
        (CommandFamily::DaemonCore, "plan_context_compaction_state_update") => {
            let request: ContextCompactionStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_context_compaction_state_update(request)
        }
        (CommandFamily::DaemonCore, "plan_coding_tool_budget_recovery_state_update") => {
            let request: CodingToolBudgetRecoveryStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_coding_tool_budget_recovery_state_update(request)
        }
        (CommandFamily::DaemonCore, "plan_coding_tool_budget_recovery_admission_required") => {
            let request: CodingToolBudgetRecoveryAdmissionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_coding_tool_budget_recovery_admission_required(request)
        }
        (CommandFamily::DaemonCore, "plan_workflow_edit_admission_required") => {
            let request: WorkflowEditAdmissionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_workflow_edit_admission_required(request)
        }
        (CommandFamily::DaemonCore, "plan_diagnostics_repair_admission_required") => {
            let request: DiagnosticsRepairAdmissionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_diagnostics_repair_admission_required(request)
        }
        (CommandFamily::DaemonCore, "plan_diagnostics_operator_override_state_update") => {
            let request: DiagnosticsOperatorOverrideStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_diagnostics_operator_override_state_update(request)
        }
        (CommandFamily::DaemonCore, "plan_operator_interrupt_state_update") => {
            let request: OperatorInterruptStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_operator_interrupt_state_update(request)
        }
        (CommandFamily::DaemonCore, "plan_operator_steer_state_update") => {
            let request: OperatorSteerStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_operator_steer_state_update(request)
        }
        (CommandFamily::DaemonCore, "plan_run_cancel_state_update") => {
            let request: RunCancelStateUpdateBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_run_cancel_state_update(request)
        }
        (CommandFamily::DaemonCore, "plan_run_cancel_admission_required") => {
            let request: RunCancelAdmissionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_run_cancel_admission_required(request)
        }
        (CommandFamily::DaemonCore, "plan_skill_hook_registry_projection_required") => {
            let request: SkillHookRegistryProjectionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_skill_hook_registry_projection_required(request)
        }
        (CommandFamily::DaemonCore, "plan_repository_workflow_projection_required") => {
            let request: RepositoryWorkflowProjectionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_repository_workflow_projection_required(request)
        }
        (CommandFamily::DaemonCore, "plan_runtime_tool_catalog_projection_required") => {
            let request: RuntimeToolCatalogProjectionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_runtime_tool_catalog_projection_required(request)
        }
        (CommandFamily::DaemonCore, "plan_runtime_lifecycle_projection_required") => {
            let request: RuntimeLifecycleProjectionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_runtime_lifecycle_projection_required(request)
        }
        (CommandFamily::DaemonCore, "plan_thread_control_agent_state_update") => {
            let request: ThreadControlAgentStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_thread_control_agent_state_update(request)
        }
        (CommandFamily::DaemonCore, "plan_mcp_control_agent_state_update") => {
            let request: McpControlAgentStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_mcp_control_agent_state_update(request)
        }
        (CommandFamily::DaemonCore, "validate_mcp_servers") => {
            let request: McpServerValidationBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            validate_mcp_servers(request)
        }
        (CommandFamily::DaemonCore, "project_mcp_server_validation_input") => {
            let request: McpServerValidationInputBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            project_mcp_server_validation_input(request)
        }
        (CommandFamily::DaemonCore, "plan_mcp_manager_status_projection") => {
            let request: McpManagerStatusProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_mcp_manager_status_projection(request)
        }
        (CommandFamily::DaemonCore, "plan_mcp_manager_validation_projection") => {
            let request: McpManagerValidationProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_mcp_manager_validation_projection(request)
        }
        (CommandFamily::DaemonCore, "plan_memory_manager_status_projection") => {
            let request: MemoryManagerStatusProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_memory_manager_status_projection(request)
        }
        (CommandFamily::DaemonCore, "plan_memory_manager_validation_projection") => {
            let request: MemoryManagerValidationProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_memory_manager_validation_projection(request)
        }
        (CommandFamily::DaemonCore, "plan_mcp_manager_catalog_projection") => {
            let request: McpManagerCatalogProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_mcp_manager_catalog_projection(request)
        }
        (CommandFamily::DaemonCore, "plan_mcp_manager_catalog_summary_projection") => {
            let request: McpManagerCatalogSummaryProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_mcp_manager_catalog_summary_projection(request)
        }
        (CommandFamily::DaemonCore, "plan_thread_memory_agent_state_update") => {
            let request: ThreadMemoryAgentStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_thread_memory_agent_state_update(request)
        }
        (CommandFamily::DaemonCore, "plan_runtime_bridge_thread_start_agent_state_update") => {
            let request: RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_runtime_bridge_thread_start_agent_state_update(request)
        }
        (CommandFamily::DaemonCore, "plan_runtime_bridge_turn_run_state_update") => {
            let request: RuntimeBridgeTurnRunStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_runtime_bridge_turn_run_state_update(request)
        }
        (CommandFamily::DaemonCore, "plan_subagent_record_state_update") => {
            let request: SubagentRecordStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_subagent_record_state_update(request)
        }
        (CommandFamily::DaemonCore, "plan_agent_create_state_update") => {
            let request: AgentCreateStateUpdateBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_agent_create_state_update(request)
        }
        (CommandFamily::DaemonCore, "plan_agent_status_state_update") => {
            let request: AgentStatusStateUpdateBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_agent_status_state_update(request)
        }
        (CommandFamily::DaemonCore, "plan_run_create_state_update") => {
            let request: RunCreateStateUpdateBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_run_create_state_update(request)
        }
        (CommandFamily::DaemonCore, "admit_storage_backend_write") => {
            let request: StorageBackendWriteBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_storage_backend_write(request)
        }
        (CommandFamily::DaemonCore, "commit_runtime_run_state") => {
            let request: RuntimeRunStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_run_state(request)
        }
        (CommandFamily::DaemonCore, "commit_runtime_agent_state") => {
            let request: RuntimeAgentStateCommitBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_agent_state(request)
        }
        (CommandFamily::DaemonCore, "commit_runtime_memory_state") => {
            let request: RuntimeMemoryStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_memory_state(request)
        }
        (CommandFamily::DaemonCore, "commit_runtime_subagent_state") => {
            let request: RuntimeSubagentStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_subagent_state(request)
        }
        (CommandFamily::DaemonCore, "commit_runtime_artifact_state") => {
            let request: RuntimeArtifactStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_artifact_state(request)
        }
        (CommandFamily::DaemonCore, "commit_runtime_model_mount_record_state") => {
            let request: RuntimeModelMountRecordStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_model_mount_record_state(request)
        }
        (CommandFamily::DaemonCore, "commit_runtime_model_mount_receipt_state") => {
            let request: RuntimeModelMountReceiptStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_model_mount_receipt_state(request)
        }
        (_, other) => Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {other}"),
        )),
    }
}
