use serde_json::Value;

use super::*;

pub(super) fn dispatch_bridge_operation(
    command_operation: CommandOperation,
    raw_request: Value,
) -> Result<Value, BridgeError> {
    match command_operation {
        CommandOperation::RunCodingToolStepModule => {
            let request: StepModuleBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            run_coding_tool_step_module(request)
        }
        CommandOperation::AdmitModelMountRouteDecision => {
            let request: ModelMountRouteDecisionBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_model_mount_route_decision(request)
        }
        CommandOperation::AdmitModelMountInvocation => {
            let request: ModelMountInvocationAdmissionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_model_mount_invocation(request)
        }
        CommandOperation::AdmitModelMountProviderExecution => {
            let request: ModelMountProviderExecutionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_model_mount_provider_execution(request)
        }
        CommandOperation::ExecuteModelMountProviderInvocation => {
            let request: ModelMountProviderInvocationBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            execute_model_mount_provider_invocation(request)
        }
        CommandOperation::ExecuteModelMountProviderStreamInvocation => {
            let request: ModelMountProviderInvocationBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            execute_model_mount_provider_stream_invocation(request)
        }
        CommandOperation::PlanModelMountProviderLifecycle => {
            let request: ModelMountProviderLifecycleBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_provider_lifecycle(request)
        }
        CommandOperation::PlanModelMountProviderInventory => {
            let request: ModelMountProviderInventoryBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_provider_inventory(request)
        }
        CommandOperation::PlanModelMountInstanceLifecycle => {
            let request: ModelMountInstanceLifecycleBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_instance_lifecycle(request)
        }
        CommandOperation::AdmitModelMountProviderResult => {
            let request: ModelMountProviderResultAdmissionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_model_mount_provider_result(request)
        }
        CommandOperation::PlanModelMountBackendProcess => {
            let request: ModelMountBackendProcessPlanBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_backend_process(request)
        }
        CommandOperation::PlanModelMountBackendLifecycleRequired => {
            let request: ModelMountBackendLifecycleRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_backend_lifecycle_required(request)
        }
        CommandOperation::PlanModelMountServerControlRequired => {
            let request: ModelMountServerControlRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_server_control_required(request)
        }
        CommandOperation::PlanModelMountRuntimeEngineRequired => {
            let request: ModelMountRuntimeEngineRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_runtime_engine_required(request)
        }
        CommandOperation::PlanModelMountTokenizerRequired => {
            let request: ModelMountTokenizerRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_tokenizer_required(request)
        }
        CommandOperation::PlanModelMountRouteControlRequired => {
            let request: ModelMountRouteControlRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_route_control_required(request)
        }
        CommandOperation::PlanModelMountAcceptedReceiptHead => {
            let request: ModelMountAcceptedReceiptHeadBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_accepted_receipt_head(request)
        }
        CommandOperation::PlanModelMountAcceptedReceiptTransition => {
            let request: ModelMountAcceptedReceiptTransitionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_accepted_receipt_transition(request)
        }
        CommandOperation::BindModelMountInvocationReceipt => {
            let request: ModelMountInvocationReceiptBindingBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            bind_model_mount_invocation_receipt(request)
        }
        CommandOperation::PlanModelMountReadProjection => {
            let request: ModelMountReadProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_model_mount_read_projection(request)
        }
        CommandOperation::ExecutePrivateWorkspaceCteeAction => {
            let request: CteePrivateWorkspaceBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            execute_private_workspace_ctee_action(request)
        }
        CommandOperation::AdmitWorkerServicePackageInvocation => {
            let request: WorkerServicePackageInvocationBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_worker_service_package_invocation(request)
        }
        CommandOperation::AdmitL1SettlementAttempt => {
            let request: L1SettlementAdmissionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_l1_settlement_attempt(request)
        }
        CommandOperation::AdmitGovernedRuntimeImprovementProposal => {
            let request: GovernedRuntimeImprovementBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_governed_runtime_improvement_proposal(request)
        }
        CommandOperation::PlanWorkspaceRestoreApplyPolicy => {
            let request: WorkspaceRestoreApplyPolicyBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_workspace_restore_apply_policy(request)
        }
        CommandOperation::PreviewWorkspaceRestoreOperations => {
            let request: WorkspaceRestoreOperationsBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            preview_workspace_restore_operations(request)
        }
        CommandOperation::ApplyWorkspaceRestoreOperations => {
            let request: WorkspaceRestoreOperationsBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            apply_workspace_restore_operations(request)
        }
        CommandOperation::CaptureWorkspaceSnapshotFiles => {
            let request: WorkspaceSnapshotCaptureBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            capture_workspace_snapshot_files(request)
        }
        CommandOperation::PlanCodingToolApprovalManifest => {
            let request: CodingToolApprovalBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_coding_tool_approval_manifest(request)
        }
        CommandOperation::PlanApprovalRequestStateUpdate => {
            let request: ApprovalRequestStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_approval_request_state_update(request)
        }
        CommandOperation::PlanApprovalDecisionStateUpdate => {
            let request: ApprovalDecisionStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_approval_decision_state_update(request)
        }
        CommandOperation::PlanApprovalRevokeStateUpdate => {
            let request: ApprovalRevokeStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_approval_revoke_state_update(request)
        }
        CommandOperation::AuthorizeExternalCapabilityExit => {
            let request: ExternalCapabilityExitAuthorityBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            authorize_external_capability_exit(request)
        }
        CommandOperation::EvaluateContextBudgetPolicy => {
            let request: ContextBudgetPolicyBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            evaluate_context_budget_policy(request)
        }
        CommandOperation::EvaluateCodingToolBudgetPolicy => {
            let request: ContextBudgetPolicyBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            evaluate_coding_tool_budget_policy(request)
        }
        CommandOperation::EvaluateCompactionPolicy => {
            let request: CompactionPolicyBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            evaluate_compaction_policy(request)
        }
        CommandOperation::PlanContextCompaction => {
            let request: ContextCompactionPlanBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_context_compaction(request)
        }
        CommandOperation::PlanContextCompactionStateUpdate => {
            let request: ContextCompactionStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_context_compaction_state_update(request)
        }
        CommandOperation::PlanCodingToolBudgetRecoveryStateUpdate => {
            let request: CodingToolBudgetRecoveryStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_coding_tool_budget_recovery_state_update(request)
        }
        CommandOperation::PlanCodingToolBudgetRecoveryAdmissionRequired => {
            let request: CodingToolBudgetRecoveryAdmissionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_coding_tool_budget_recovery_admission_required(request)
        }
        CommandOperation::PlanWorkflowEditAdmissionRequired => {
            let request: WorkflowEditAdmissionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_workflow_edit_admission_required(request)
        }
        CommandOperation::PlanDiagnosticsRepairAdmissionRequired => {
            let request: DiagnosticsRepairAdmissionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_diagnostics_repair_admission_required(request)
        }
        CommandOperation::PlanDiagnosticsOperatorOverrideStateUpdate => {
            let request: DiagnosticsOperatorOverrideStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_diagnostics_operator_override_state_update(request)
        }
        CommandOperation::PlanOperatorTurnControlAdmissionRequired => {
            let request: OperatorTurnControlAdmissionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_operator_turn_control_admission_required(request)
        }
        CommandOperation::PlanOperatorInterruptStateUpdate => {
            let request: OperatorInterruptStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_operator_interrupt_state_update(request)
        }
        CommandOperation::PlanOperatorSteerStateUpdate => {
            let request: OperatorSteerStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_operator_steer_state_update(request)
        }
        CommandOperation::PlanRunCancelStateUpdate => {
            let request: RunCancelStateUpdateBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_run_cancel_state_update(request)
        }
        CommandOperation::PlanRunCancelAdmissionRequired => {
            let request: RunCancelAdmissionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_run_cancel_admission_required(request)
        }
        CommandOperation::PlanSkillHookRegistryProjectionRequired => {
            let request: SkillHookRegistryProjectionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_skill_hook_registry_projection_required(request)
        }
        CommandOperation::PlanRepositoryWorkflowProjectionRequired => {
            let request: RepositoryWorkflowProjectionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_repository_workflow_projection_required(request)
        }
        CommandOperation::PlanRuntimeToolCatalogProjectionRequired => {
            let request: RuntimeToolCatalogProjectionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_runtime_tool_catalog_projection_required(request)
        }
        CommandOperation::PlanRuntimeLifecycleProjectionRequired => {
            let request: RuntimeLifecycleProjectionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_runtime_lifecycle_projection_required(request)
        }
        CommandOperation::PlanLifecycleAdmissionRequired => {
            let request: LifecycleAdmissionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_lifecycle_admission_required(request)
        }
        CommandOperation::PlanThreadTurnAdmissionRequired => {
            let request: ThreadTurnAdmissionRequiredBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_thread_turn_admission_required(request)
        }
        CommandOperation::PlanThreadControlAgentStateUpdate => {
            let request: ThreadControlAgentStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_thread_control_agent_state_update(request)
        }
        CommandOperation::PlanMcpControlAgentStateUpdate => {
            let request: McpControlAgentStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_mcp_control_agent_state_update(request)
        }
        CommandOperation::ValidateMcpServers => {
            let request: McpServerValidationBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            validate_mcp_servers(request)
        }
        CommandOperation::ProjectMcpServerValidationInput => {
            let request: McpServerValidationInputBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            project_mcp_server_validation_input(request)
        }
        CommandOperation::PlanMcpManagerStatusProjection => {
            let request: McpManagerStatusProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_mcp_manager_status_projection(request)
        }
        CommandOperation::PlanMcpManagerValidationProjection => {
            let request: McpManagerValidationProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_mcp_manager_validation_projection(request)
        }
        CommandOperation::PlanMemoryManagerStatusProjection => {
            let request: MemoryManagerStatusProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_memory_manager_status_projection(request)
        }
        CommandOperation::PlanMemoryManagerValidationProjection => {
            let request: MemoryManagerValidationProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_memory_manager_validation_projection(request)
        }
        CommandOperation::PlanMcpManagerCatalogProjection => {
            let request: McpManagerCatalogProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_mcp_manager_catalog_projection(request)
        }
        CommandOperation::PlanMcpManagerCatalogSummaryProjection => {
            let request: McpManagerCatalogSummaryProjectionBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_mcp_manager_catalog_summary_projection(request)
        }
        CommandOperation::PlanThreadMemoryAgentStateUpdate => {
            let request: ThreadMemoryAgentStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_thread_memory_agent_state_update(request)
        }
        CommandOperation::PlanRuntimeBridgeThreadStartAgentStateUpdate => {
            let request: RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_runtime_bridge_thread_start_agent_state_update(request)
        }
        CommandOperation::PlanRuntimeBridgeTurnRunStateUpdate => {
            let request: RuntimeBridgeTurnRunStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_runtime_bridge_turn_run_state_update(request)
        }
        CommandOperation::PlanSubagentRecordStateUpdate => {
            let request: SubagentRecordStateUpdateBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_subagent_record_state_update(request)
        }
        CommandOperation::PlanAgentCreateStateUpdate => {
            let request: AgentCreateStateUpdateBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_agent_create_state_update(request)
        }
        CommandOperation::PlanAgentStatusStateUpdate => {
            let request: AgentStatusStateUpdateBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_agent_status_state_update(request)
        }
        CommandOperation::PlanRunCreateStateUpdate => {
            let request: RunCreateStateUpdateBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            plan_run_create_state_update(request)
        }
        CommandOperation::AdmitStorageBackendWrite => {
            let request: StorageBackendWriteBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            admit_storage_backend_write(request)
        }
        CommandOperation::CommitRuntimeRunState => {
            let request: RuntimeRunStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_run_state(request)
        }
        CommandOperation::CommitRuntimeAgentState => {
            let request: RuntimeAgentStateCommitBridgeRequest = serde_json::from_value(raw_request)
                .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_agent_state(request)
        }
        CommandOperation::CommitRuntimeMemoryState => {
            let request: RuntimeMemoryStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_memory_state(request)
        }
        CommandOperation::CommitRuntimeSubagentState => {
            let request: RuntimeSubagentStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_subagent_state(request)
        }
        CommandOperation::CommitRuntimeArtifactState => {
            let request: RuntimeArtifactStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_artifact_state(request)
        }
        CommandOperation::CommitRuntimeModelMountRecordState => {
            let request: RuntimeModelMountRecordStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_model_mount_record_state(request)
        }
        CommandOperation::CommitRuntimeModelMountReceiptState => {
            let request: RuntimeModelMountReceiptStateCommitBridgeRequest =
                serde_json::from_value(raw_request)
                    .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
            commit_runtime_model_mount_receipt_state(request)
        }
    }
}
