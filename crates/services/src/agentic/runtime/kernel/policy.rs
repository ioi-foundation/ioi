use crate::agentic::rules::Verdict;
use serde::{Deserialize, Serialize};

mod admission_required;
mod coding_tool_budget_recovery;
mod context_lifecycle;
mod mcp_memory;
mod operator_control;
mod projection_required;
mod run_cancel;
mod thread_lifecycle;

pub use admission_required::{
    plan_diagnostics_repair_admission_required_response,
    plan_workflow_edit_admission_required_response, AdmissionRequiredCommandError,
    DiagnosticsRepairAdmissionRequiredBridgeRequest, DiagnosticsRepairAdmissionRequiredCore,
    DiagnosticsRepairAdmissionRequiredError, DiagnosticsRepairAdmissionRequiredRecord,
    DiagnosticsRepairAdmissionRequiredRequest, WorkflowEditAdmissionRequiredBridgeRequest,
    WorkflowEditAdmissionRequiredCore, WorkflowEditAdmissionRequiredError,
    WorkflowEditAdmissionRequiredRecord, WorkflowEditAdmissionRequiredRequest,
};
pub use coding_tool_budget_recovery::{
    CodingToolBudgetRecoveryAdmissionRequiredCore, CodingToolBudgetRecoveryAdmissionRequiredError,
    CodingToolBudgetRecoveryAdmissionRequiredRecord,
    CodingToolBudgetRecoveryAdmissionRequiredRequest, CodingToolBudgetRecoveryStateUpdateCore,
    CodingToolBudgetRecoveryStateUpdateError, CodingToolBudgetRecoveryStateUpdateRecord,
    CodingToolBudgetRecoveryStateUpdateRequest,
};
pub use context_lifecycle::{
    evaluate_coding_tool_budget_policy_response, evaluate_compaction_policy_response,
    evaluate_context_budget_policy_response, plan_context_compaction_response,
    plan_context_compaction_state_update_response, CompactionPolicyActions,
    CompactionPolicyApproval, CompactionPolicyBridgeRequest, CompactionPolicyCompact,
    CompactionPolicyCore, CompactionPolicyError, CompactionPolicyRecord, CompactionPolicyRequest,
    ContextBudgetCheck, ContextBudgetDecision, ContextBudgetPolicyBridgeRequest,
    ContextBudgetPolicyCore, ContextBudgetPolicyError, ContextBudgetPolicyRecord,
    ContextBudgetPolicyRequest, ContextBudgetThresholds, ContextBudgetUsageSummary,
    ContextCompactionPlanBridgeRequest, ContextCompactionPlanCore, ContextCompactionPlanError,
    ContextCompactionPlanRecord, ContextCompactionPlanRequest,
    ContextCompactionStateUpdateBridgeRequest, ContextCompactionStateUpdateCore,
    ContextCompactionStateUpdateError, ContextCompactionStateUpdateRecord,
    ContextCompactionStateUpdateRequest, ContextPolicyCommandError,
};
pub use mcp_memory::{
    McpControlAgentStateUpdateCore, McpControlAgentStateUpdateError,
    McpControlAgentStateUpdateRecord, McpControlAgentStateUpdateRequest,
    McpManagerCatalogProjectionCore, McpManagerCatalogProjectionError,
    McpManagerCatalogProjectionRecord, McpManagerCatalogProjectionRequest,
    McpManagerCatalogSummaryProjectionCore, McpManagerCatalogSummaryProjectionError,
    McpManagerCatalogSummaryProjectionRecord, McpManagerCatalogSummaryProjectionRequest,
    McpManagerStatusProjectionCore, McpManagerStatusProjectionError,
    McpManagerStatusProjectionRecord, McpManagerStatusProjectionRequest,
    McpManagerValidationProjectionCore, McpManagerValidationProjectionError,
    McpManagerValidationProjectionRecord, McpManagerValidationProjectionRequest,
    McpServerValidationCore, McpServerValidationError, McpServerValidationInputCore,
    McpServerValidationInputError, McpServerValidationInputRecord, McpServerValidationInputRequest,
    McpServerValidationRecord, McpServerValidationRequest, MemoryManagerStatusProjectionCore,
    MemoryManagerStatusProjectionError, MemoryManagerStatusProjectionRecord,
    MemoryManagerStatusProjectionRequest, MemoryManagerValidationProjectionCore,
    MemoryManagerValidationProjectionError, MemoryManagerValidationProjectionRecord,
    MemoryManagerValidationProjectionRequest, ThreadMemoryAgentStateUpdateCore,
    ThreadMemoryAgentStateUpdateError, ThreadMemoryAgentStateUpdateRecord,
    ThreadMemoryAgentStateUpdateRequest,
};
pub use operator_control::{
    DiagnosticsOperatorOverrideStateUpdateCore, DiagnosticsOperatorOverrideStateUpdateError,
    DiagnosticsOperatorOverrideStateUpdateRecord, DiagnosticsOperatorOverrideStateUpdateRequest,
    OperatorInterruptStateUpdateCore, OperatorInterruptStateUpdateError,
    OperatorInterruptStateUpdateRecord, OperatorInterruptStateUpdateRequest,
    OperatorSteerStateUpdateCore, OperatorSteerStateUpdateError, OperatorSteerStateUpdateRecord,
    OperatorSteerStateUpdateRequest, OperatorTurnControlAdmissionRequiredCore,
    OperatorTurnControlAdmissionRequiredError, OperatorTurnControlAdmissionRequiredRecord,
    OperatorTurnControlAdmissionRequiredRequest,
};
pub use projection_required::{
    plan_repository_workflow_projection_required_response,
    plan_runtime_lifecycle_projection_required_response,
    plan_runtime_tool_catalog_projection_required_response,
    plan_skill_hook_registry_projection_required_response, ProjectionRequiredCommandError,
    RepositoryWorkflowProjectionRequiredBridgeRequest, RepositoryWorkflowProjectionRequiredCore,
    RepositoryWorkflowProjectionRequiredError, RepositoryWorkflowProjectionRequiredRecord,
    RepositoryWorkflowProjectionRequiredRequest, RuntimeLifecycleProjectionRequiredBridgeRequest,
    RuntimeLifecycleProjectionRequiredCore, RuntimeLifecycleProjectionRequiredError,
    RuntimeLifecycleProjectionRequiredRecord, RuntimeLifecycleProjectionRequiredRequest,
    RuntimeToolCatalogProjectionRequiredBridgeRequest, RuntimeToolCatalogProjectionRequiredCore,
    RuntimeToolCatalogProjectionRequiredError, RuntimeToolCatalogProjectionRequiredRecord,
    RuntimeToolCatalogProjectionRequiredRequest, SkillHookRegistryProjectionRequiredBridgeRequest,
    SkillHookRegistryProjectionRequiredCore, SkillHookRegistryProjectionRequiredError,
    SkillHookRegistryProjectionRequiredRecord, SkillHookRegistryProjectionRequiredRequest,
};
pub use run_cancel::{
    RunCancelAdmissionRequiredCore, RunCancelAdmissionRequiredError,
    RunCancelAdmissionRequiredRecord, RunCancelAdmissionRequiredRequest, RunCancelStateUpdateCore,
    RunCancelStateUpdateError, RunCancelStateUpdateRecord, RunCancelStateUpdateRequest,
};
pub use thread_lifecycle::{
    plan_agent_create_state_update_response, plan_agent_status_state_update_response,
    plan_lifecycle_admission_required_response, plan_run_create_state_update_response,
    plan_runtime_bridge_thread_start_agent_state_update_response,
    plan_runtime_bridge_turn_run_state_update_response, plan_subagent_record_state_update_response,
    plan_thread_control_agent_state_update_response, plan_thread_turn_admission_required_response,
    AgentCreateStateUpdateBridgeRequest, AgentCreateStateUpdateCore, AgentCreateStateUpdateError,
    AgentCreateStateUpdateRecord, AgentCreateStateUpdateRequest,
    AgentStatusStateUpdateBridgeRequest, AgentStatusStateUpdateCore, AgentStatusStateUpdateError,
    AgentStatusStateUpdateRecord, AgentStatusStateUpdateRequest,
    LifecycleAdmissionRequiredBridgeRequest, LifecycleAdmissionRequiredCore,
    LifecycleAdmissionRequiredError, LifecycleAdmissionRequiredRecord,
    LifecycleAdmissionRequiredRequest, RunCreateStateUpdateBridgeRequest, RunCreateStateUpdateCore,
    RunCreateStateUpdateError, RunCreateStateUpdateRecord, RunCreateStateUpdateRequest,
    RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest,
    RuntimeBridgeThreadStartAgentStateUpdateCore, RuntimeBridgeThreadStartAgentStateUpdateError,
    RuntimeBridgeThreadStartAgentStateUpdateRecord,
    RuntimeBridgeThreadStartAgentStateUpdateRequest, RuntimeBridgeTurnRunStateUpdateBridgeRequest,
    RuntimeBridgeTurnRunStateUpdateCore, RuntimeBridgeTurnRunStateUpdateError,
    RuntimeBridgeTurnRunStateUpdateRecord, RuntimeBridgeTurnRunStateUpdateRequest,
    SubagentRecordStateUpdateBridgeRequest, SubagentRecordStateUpdateCore,
    SubagentRecordStateUpdateError, SubagentRecordStateUpdateRecord,
    SubagentRecordStateUpdateRequest, ThreadControlAgentStateUpdateBridgeRequest,
    ThreadControlAgentStateUpdateCore, ThreadControlAgentStateUpdateError,
    ThreadControlAgentStateUpdateRecord, ThreadControlAgentStateUpdateRequest,
    ThreadLifecycleCommandError, ThreadTurnAdmissionRequiredBridgeRequest,
    ThreadTurnAdmissionRequiredCore, ThreadTurnAdmissionRequiredError,
    ThreadTurnAdmissionRequiredRecord, ThreadTurnAdmissionRequiredRequest,
};

pub const CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.context-budget-policy-request.v1";
pub const CONTEXT_BUDGET_POLICY_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.context-budget-policy.v1";
pub const CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-budget-policy-request.v1";
pub const CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-budget-recovery-state-update-request.v1";
pub const CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-budget-recovery-state-update.v1";
pub const CODING_TOOL_BUDGET_RECOVERY_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-budget-recovery-admission-required-request.v1";
pub const CODING_TOOL_BUDGET_RECOVERY_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-budget-recovery-admission-required.v1";
pub const DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-operator-override-state-update-request.v1";
pub const DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-operator-override-state-update.v1";
pub const OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.operator-turn-control-admission-required-request.v1";
pub const OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.operator-turn-control-admission-required.v1";
pub const OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.operator-interrupt-state-update-request.v1";
pub const OPERATOR_INTERRUPT_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.operator-interrupt-state-update.v1";
pub const OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.operator-steer-state-update-request.v1";
pub const OPERATOR_STEER_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.operator-steer-state-update.v1";
pub const RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.run-cancel-state-update-request.v1";
pub const RUN_CANCEL_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.run-cancel-state-update.v1";
pub const RUN_CANCEL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.run-cancel-admission-required-request.v1";
pub const RUN_CANCEL_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.run-cancel-admission-required.v1";
pub const SKILL_HOOK_REGISTRY_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.skill-hook-registry-projection-required-request.v1";
pub const SKILL_HOOK_REGISTRY_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.skill-hook-registry-projection-required.v1";
pub const REPOSITORY_WORKFLOW_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.repository-workflow-projection-required-request.v1";
pub const REPOSITORY_WORKFLOW_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.repository-workflow-projection-required.v1";
pub const RUNTIME_TOOL_CATALOG_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.tool-catalog-projection-required-request.v1";
pub const RUNTIME_TOOL_CATALOG_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.tool-catalog-projection-required.v1";
pub const RUNTIME_LIFECYCLE_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.lifecycle-projection-required-request.v1";
pub const RUNTIME_LIFECYCLE_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.lifecycle-projection-required.v1";
pub const THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-control-agent-state-update-request.v1";
pub const THREAD_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-control-agent-state-update.v1";
pub const THREAD_TURN_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-turn-admission-required-request.v1";
pub const THREAD_TURN_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-turn-admission-required.v1";
pub const LIFECYCLE_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.lifecycle-admission-required-request.v1";
pub const LIFECYCLE_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.lifecycle-admission-required.v1";
pub const AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.agent-create-state-update-request.v1";
pub const AGENT_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.agent-create-state-update.v1";
pub const RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.run-create-state-update-request.v1";
pub const RUN_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.run-create-state-update.v1";
pub const AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.agent-status-state-update-request.v1";
pub const AGENT_STATUS_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.agent-status-state-update.v1";
pub const MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-control-agent-state-update-request.v1";
pub const MCP_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-control-agent-state-update.v1";
pub const MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-server-validation-request.v1";
pub const MCP_SERVER_VALIDATION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-server-validation.v1";
pub const MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-server-validation-input-request.v1";
pub const MCP_SERVER_VALIDATION_INPUT_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-server-validation-input.v1";
pub const MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-validation-projection-request.v1";
pub const MCP_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-validation.v1";
pub const MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-status-projection-request.v1";
pub const MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-status.v1";
pub const MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-catalog-projection-request.v1";
pub const MCP_MANAGER_CATALOG_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-catalog-projection.v1";
pub const MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-catalog-summary-projection-request.v1";
pub const MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-catalog-summary.v1";
pub const MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.memory-manager-validation-projection-request.v1";
pub const MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.memory-manager-validation.v1";
pub const MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.memory-manager-status-projection-request.v1";
pub const MEMORY_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.memory-manager-status.v1";
pub const THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-memory-agent-state-update-request.v1";
pub const THREAD_MEMORY_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-memory-agent-state-update.v1";
pub const RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.runtime-bridge-thread-start-agent-state-update-request.v1";
pub const RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.runtime-bridge-thread-start-agent-state-update.v1";
pub const RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.runtime-bridge-turn-run-state-update-request.v1";
pub const RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.runtime-bridge-turn-run-state-update.v1";
pub const SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.subagent-record-state-update-request.v1";
pub const SUBAGENT_RECORD_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.subagent-record-state-update.v1";
pub const COMPACTION_POLICY_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.compaction-policy-request.v1";
pub const COMPACTION_POLICY_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.compaction-policy.v1";
pub const CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.context-compaction-plan-request.v1";
pub const CONTEXT_COMPACTION_PLAN_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.context-compaction-plan.v1";
pub const CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.context-compaction-state-update-request.v1";
pub const CONTEXT_COMPACTION_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.context-compaction-state-update.v1";
pub const CONTEXT_COMPACTION_PAYLOAD_SCHEMA_VERSION: &str = "ioi.runtime.context-compaction.v1";
pub const WORKFLOW_EDIT_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.workflow-edit-admission-required-request.v1";
pub const WORKFLOW_EDIT_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.workflow-edit-admission-required.v1";
pub const DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-repair-admission-required-request.v1";
pub const DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-repair-admission-required.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluationRecord {
    pub verdict: Verdict,
    #[serde(default)]
    pub matched_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_policy_used: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pii_decision_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_eval_trace_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_eval_hash: Option<[u8; 32]>,
}

impl PolicyEvaluationRecord {
    pub fn matched_rules_for_decision(&self) -> Vec<String> {
        let mut rules = self.matched_rule_ids.clone();
        if rules.is_empty() {
            if let Some(default_policy) = &self.default_policy_used {
                rules.push(format!("default:{}", default_policy));
            }
        }
        if let Some(hash) = self.pii_decision_hash {
            rules.push(format!("pii:{}", hex::encode(hash)));
        }
        rules
    }
}
