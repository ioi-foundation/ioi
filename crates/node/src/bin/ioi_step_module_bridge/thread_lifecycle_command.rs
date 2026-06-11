use ioi_services::agentic::runtime::kernel::policy::{
    plan_agent_create_state_update_response as core_plan_agent_create_state_update,
    plan_agent_status_state_update_response as core_plan_agent_status_state_update,
    plan_lifecycle_admission_required_response as core_plan_lifecycle_admission_required,
    plan_run_create_state_update_response as core_plan_run_create_state_update,
    plan_runtime_bridge_thread_start_agent_state_update_response as core_plan_runtime_bridge_thread_start_agent_state_update,
    plan_runtime_bridge_turn_run_state_update_response as core_plan_runtime_bridge_turn_run_state_update,
    plan_subagent_record_state_update_response as core_plan_subagent_record_state_update,
    plan_thread_control_agent_state_update_response as core_plan_thread_control_agent_state_update,
    plan_thread_turn_admission_required_response as core_plan_thread_turn_admission_required,
    ThreadLifecycleCommandError,
};
use serde_json::Value;

use super::BridgeError;

pub(super) use ioi_services::agentic::runtime::kernel::policy::{
    AgentCreateStateUpdateBridgeRequest, AgentStatusStateUpdateBridgeRequest,
    LifecycleAdmissionRequiredBridgeRequest, RunCreateStateUpdateBridgeRequest,
    RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest,
    RuntimeBridgeTurnRunStateUpdateBridgeRequest, SubagentRecordStateUpdateBridgeRequest,
    ThreadControlAgentStateUpdateBridgeRequest, ThreadTurnAdmissionRequiredBridgeRequest,
};

pub(super) fn plan_runtime_bridge_thread_start_agent_state_update(
    request: RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_runtime_bridge_thread_start_agent_state_update(request).map_err(bridge_error)
}

pub(super) fn plan_runtime_bridge_turn_run_state_update(
    request: RuntimeBridgeTurnRunStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_runtime_bridge_turn_run_state_update(request).map_err(bridge_error)
}

pub(super) fn plan_subagent_record_state_update(
    request: SubagentRecordStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_subagent_record_state_update(request).map_err(bridge_error)
}

pub(super) fn plan_thread_control_agent_state_update(
    request: ThreadControlAgentStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_thread_control_agent_state_update(request).map_err(bridge_error)
}

pub(super) fn plan_thread_turn_admission_required(
    request: ThreadTurnAdmissionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_thread_turn_admission_required(request).map_err(bridge_error)
}

pub(super) fn plan_lifecycle_admission_required(
    request: LifecycleAdmissionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_lifecycle_admission_required(request).map_err(bridge_error)
}

pub(super) fn plan_agent_create_state_update(
    request: AgentCreateStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_agent_create_state_update(request).map_err(bridge_error)
}

pub(super) fn plan_agent_status_state_update(
    request: AgentStatusStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_agent_status_state_update(request).map_err(bridge_error)
}

pub(super) fn plan_run_create_state_update(
    request: RunCreateStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_run_create_state_update(request).map_err(bridge_error)
}

fn bridge_error(error: ThreadLifecycleCommandError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}
