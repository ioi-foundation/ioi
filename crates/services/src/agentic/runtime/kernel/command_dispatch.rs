use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::io::{self, Read};

use super::{
    approval::*, coding_tool_artifact::*, coding_tool_event::*, coding_tool_step_module::*,
    command_protocol::CommandOperation, model_mount::*, model_mount_receipt::*, policy::*,
    repository_workflow::*, runtime_conversation_artifact_control::*,
    runtime_conversation_artifact_projection::*, runtime_diagnostics_repair_control::*,
    runtime_diagnostics_repair_policy::*, runtime_diagnostics_repair_projection::*,
    runtime_lifecycle::*, runtime_managed_session_control::*, runtime_memory_control::*,
    runtime_memory_projection::*, runtime_subagent_control::*, runtime_subagent_projection::*,
    runtime_thread_fork_control::*, runtime_tool_catalog::*, runtime_workflow_edit_control::*,
    runtime_workspace_change_control::*, skill_hook_registry::*,
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
        CommandOperation::PlanPostEditDiagnosticsFeedback => {
            plan_post_edit_diagnostics_feedback_response(decode(raw_request)?).map_err(|error| {
                CommandDispatchError::new(
                    "post_edit_diagnostics_feedback_plan_rejected",
                    format!("{error:?}"),
                )
            })
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
    }
}

fn decode<T: DeserializeOwned>(raw_request: Value) -> Result<T, CommandDispatchError> {
    serde_json::from_value(raw_request)
        .map_err(|error| CommandDispatchError::new("request_json_invalid", error.to_string()))
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

command_error_from!(ApprovalCommandError);
command_error_from!(CodingToolStepModuleCommandError);
command_error_from!(RuntimeCodingToolArtifactDraftPlanCommandError);
command_error_from!(RuntimeCodingToolArtifactReadProjectionCommandError);
command_error_from!(ModelMountReceiptError);
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
