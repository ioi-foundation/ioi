use ioi_services::agentic::runtime::kernel::policy::{
    plan_coding_tool_budget_recovery_admission_required_response as core_plan_coding_tool_budget_recovery_admission_required,
    plan_coding_tool_budget_recovery_state_update_response as core_plan_coding_tool_budget_recovery_state_update,
    plan_diagnostics_operator_override_state_update_response as core_plan_diagnostics_operator_override_state_update,
    plan_operator_interrupt_state_update_response as core_plan_operator_interrupt_state_update,
    plan_operator_steer_state_update_response as core_plan_operator_steer_state_update,
    plan_operator_turn_control_admission_required_response as core_plan_operator_turn_control_admission_required,
    plan_run_cancel_admission_required_response as core_plan_run_cancel_admission_required,
    plan_run_cancel_state_update_response as core_plan_run_cancel_state_update,
    CodingToolBudgetRecoveryCommandError, OperatorControlCommandError, RunCancelCommandError,
};
use serde_json::Value;

use super::BridgeError;

pub(super) use ioi_services::agentic::runtime::kernel::policy::{
    CodingToolBudgetRecoveryAdmissionRequiredBridgeRequest,
    CodingToolBudgetRecoveryStateUpdateBridgeRequest,
    DiagnosticsOperatorOverrideStateUpdateBridgeRequest, OperatorInterruptStateUpdateBridgeRequest,
    OperatorSteerStateUpdateBridgeRequest, OperatorTurnControlAdmissionRequiredBridgeRequest,
    RunCancelAdmissionRequiredBridgeRequest, RunCancelStateUpdateBridgeRequest,
};

pub(super) fn plan_coding_tool_budget_recovery_state_update(
    request: CodingToolBudgetRecoveryStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_coding_tool_budget_recovery_state_update(request).map_bridge_error()
}

pub(super) fn plan_coding_tool_budget_recovery_admission_required(
    request: CodingToolBudgetRecoveryAdmissionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_coding_tool_budget_recovery_admission_required(request).map_bridge_error()
}

pub(super) fn plan_diagnostics_operator_override_state_update(
    request: DiagnosticsOperatorOverrideStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_diagnostics_operator_override_state_update(request).map_bridge_error()
}

pub(super) fn plan_operator_turn_control_admission_required(
    request: OperatorTurnControlAdmissionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_operator_turn_control_admission_required(request).map_bridge_error()
}

pub(super) fn plan_operator_interrupt_state_update(
    request: OperatorInterruptStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_operator_interrupt_state_update(request).map_bridge_error()
}

pub(super) fn plan_operator_steer_state_update(
    request: OperatorSteerStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_operator_steer_state_update(request).map_bridge_error()
}

pub(super) fn plan_run_cancel_state_update(
    request: RunCancelStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_run_cancel_state_update(request).map_bridge_error()
}

pub(super) fn plan_run_cancel_admission_required(
    request: RunCancelAdmissionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_run_cancel_admission_required(request).map_bridge_error()
}

fn bridge_error(error: CodingToolBudgetRecoveryCommandError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}

fn bridge_error_operator_control(error: OperatorControlCommandError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}

fn bridge_error_run_cancel(error: RunCancelCommandError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}

trait IntoBridgeError {
    fn into_bridge_error(self) -> BridgeError;
}

impl IntoBridgeError for CodingToolBudgetRecoveryCommandError {
    fn into_bridge_error(self) -> BridgeError {
        bridge_error(self)
    }
}

impl IntoBridgeError for OperatorControlCommandError {
    fn into_bridge_error(self) -> BridgeError {
        bridge_error_operator_control(self)
    }
}

impl IntoBridgeError for RunCancelCommandError {
    fn into_bridge_error(self) -> BridgeError {
        bridge_error_run_cancel(self)
    }
}

trait BridgeResult<T> {
    fn map_bridge_error(self) -> Result<T, BridgeError>;
}

impl<T, E> BridgeResult<T> for Result<T, E>
where
    E: IntoBridgeError,
{
    fn map_bridge_error(self) -> Result<T, BridgeError> {
        self.map_err(IntoBridgeError::into_bridge_error)
    }
}
