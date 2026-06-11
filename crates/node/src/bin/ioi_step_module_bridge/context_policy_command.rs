use ioi_services::agentic::runtime::kernel::policy::{
    evaluate_coding_tool_budget_policy_response as core_evaluate_coding_tool_budget_policy,
    evaluate_compaction_policy_response as core_evaluate_compaction_policy,
    evaluate_context_budget_policy_response as core_evaluate_context_budget_policy,
    plan_context_compaction_response as core_plan_context_compaction,
    plan_context_compaction_state_update_response as core_plan_context_compaction_state_update,
    ContextPolicyCommandError,
};
use serde_json::Value;

use super::BridgeError;
pub(super) use ioi_services::agentic::runtime::kernel::policy::{
    CompactionPolicyBridgeRequest, ContextBudgetPolicyBridgeRequest,
    ContextCompactionPlanBridgeRequest, ContextCompactionStateUpdateBridgeRequest,
};

pub(super) fn evaluate_context_budget_policy(
    request: ContextBudgetPolicyBridgeRequest,
) -> Result<Value, BridgeError> {
    core_evaluate_context_budget_policy(request).map_err(bridge_error)
}

pub(super) fn evaluate_coding_tool_budget_policy(
    request: ContextBudgetPolicyBridgeRequest,
) -> Result<Value, BridgeError> {
    core_evaluate_coding_tool_budget_policy(request).map_err(bridge_error)
}

pub(super) fn evaluate_compaction_policy(
    request: CompactionPolicyBridgeRequest,
) -> Result<Value, BridgeError> {
    core_evaluate_compaction_policy(request).map_err(bridge_error)
}

pub(super) fn plan_context_compaction(
    request: ContextCompactionPlanBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_context_compaction(request).map_err(bridge_error)
}

pub(super) fn plan_context_compaction_state_update(
    request: ContextCompactionStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_context_compaction_state_update(request).map_err(bridge_error)
}

fn bridge_error(error: ContextPolicyCommandError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}
