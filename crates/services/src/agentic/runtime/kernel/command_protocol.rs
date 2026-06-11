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
    "plan_operator_interrupt_state_update",
    "plan_operator_steer_state_update",
    "plan_run_cancel_state_update",
    "plan_run_cancel_admission_required",
    "plan_skill_hook_registry_projection_required",
    "plan_repository_workflow_projection_required",
    "plan_runtime_tool_catalog_projection_required",
    "plan_runtime_lifecycle_projection_required",
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

pub fn command_family(operation: &str) -> Option<CommandFamily> {
    if STEP_MODULE_OPERATIONS.contains(&operation) {
        Some(CommandFamily::StepModule)
    } else if DAEMON_CORE_OPERATIONS.contains(&operation) {
        Some(CommandFamily::DaemonCore)
    } else {
        None
    }
}

pub fn expected_command_schema_version(operation: &str) -> Option<&'static str> {
    command_family(operation).map(CommandFamily::schema_version)
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
            "plan_thread_control_agent_state_update",
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
        assert!(!is_step_module_operation("unknown_operation"));
        assert!(!is_daemon_core_operation("unknown_operation"));
    }

    #[test]
    fn command_catalog_operations_have_schema_families() {
        for operation in STEP_MODULE_OPERATIONS {
            assert_eq!(command_family(operation), Some(CommandFamily::StepModule));
            assert_eq!(
                expected_command_schema_version(operation),
                Some(STEP_MODULE_COMMAND_SCHEMA_VERSION)
            );
        }
        for operation in DAEMON_CORE_OPERATIONS {
            assert_eq!(command_family(operation), Some(CommandFamily::DaemonCore));
            assert_eq!(
                expected_command_schema_version(operation),
                Some(DAEMON_CORE_COMMAND_SCHEMA_VERSION)
            );
        }
    }
}
