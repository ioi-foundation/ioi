use ioi_services::agentic::runtime::kernel::policy::{
    CodingToolBudgetRecoveryAdmissionRequiredCore,
    CodingToolBudgetRecoveryAdmissionRequiredRequest, CodingToolBudgetRecoveryStateUpdateCore,
    CodingToolBudgetRecoveryStateUpdateRequest, DiagnosticsOperatorOverrideStateUpdateCore,
    DiagnosticsOperatorOverrideStateUpdateRequest, OperatorInterruptStateUpdateCore,
    OperatorInterruptStateUpdateRequest, OperatorSteerStateUpdateCore,
    OperatorSteerStateUpdateRequest, OperatorTurnControlAdmissionRequiredCore,
    OperatorTurnControlAdmissionRequiredRequest, RunCancelAdmissionRequiredCore,
    RunCancelAdmissionRequiredRequest, RunCancelStateUpdateCore, RunCancelStateUpdateRequest,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::BridgeError;

#[derive(Debug, Deserialize)]
pub(super) struct CodingToolBudgetRecoveryStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: CodingToolBudgetRecoveryStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct CodingToolBudgetRecoveryAdmissionRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: CodingToolBudgetRecoveryAdmissionRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct DiagnosticsOperatorOverrideStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: DiagnosticsOperatorOverrideStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct OperatorTurnControlAdmissionRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: OperatorTurnControlAdmissionRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct OperatorInterruptStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: OperatorInterruptStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct OperatorSteerStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: OperatorSteerStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RunCancelStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: RunCancelStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RunCancelAdmissionRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: RunCancelAdmissionRequiredRequest,
}

pub(super) fn plan_coding_tool_budget_recovery_state_update(
    request: CodingToolBudgetRecoveryStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = CodingToolBudgetRecoveryStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "coding_tool_budget_recovery_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_coding_tool_budget_recovery_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "run": record.run.clone(),
    }))
}

pub(super) fn plan_coding_tool_budget_recovery_admission_required(
    request: CodingToolBudgetRecoveryAdmissionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = CodingToolBudgetRecoveryAdmissionRequiredCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "coding_tool_budget_recovery_admission_required_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_coding_tool_budget_recovery_admission_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "status_code": record.status_code,
        "code": record.code.clone(),
        "message": record.message.clone(),
        "rust_core_boundary": record.rust_core_boundary.clone(),
        "operation_kind": record.operation_kind.clone(),
        "details": record.details.clone(),
    }))
}

pub(super) fn plan_diagnostics_operator_override_state_update(
    request: DiagnosticsOperatorOverrideStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = DiagnosticsOperatorOverrideStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "diagnostics_operator_override_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_diagnostics_operator_override_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "run": record.run.clone(),
    }))
}

pub(super) fn plan_operator_turn_control_admission_required(
    request: OperatorTurnControlAdmissionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = OperatorTurnControlAdmissionRequiredCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "operator_turn_control_admission_required_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_operator_turn_control_admission_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "status_code": record.status_code,
        "code": record.code.clone(),
        "message": record.message.clone(),
        "rust_core_boundary": record.rust_core_boundary.clone(),
        "operation": record.operation.clone(),
        "operation_kind": record.operation_kind.clone(),
        "details": record.details.clone(),
    }))
}

pub(super) fn plan_operator_interrupt_state_update(
    request: OperatorInterruptStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = OperatorInterruptStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "operator_interrupt_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_operator_interrupt_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "stop_condition": record.stop_condition.clone(),
        "run": record.run.clone(),
    }))
}

pub(super) fn plan_operator_steer_state_update(
    request: OperatorSteerStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = OperatorSteerStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("operator_steer_state_update_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_operator_steer_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "run": record.run.clone(),
    }))
}

pub(super) fn plan_run_cancel_state_update(
    request: RunCancelStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = RunCancelStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("run_cancel_state_update_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_run_cancel_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "stop_condition": record.stop_condition.clone(),
        "runtime_task": record.runtime_task.clone(),
        "runtime_job": record.runtime_job.clone(),
        "runtime_checklist": record.runtime_checklist.clone(),
        "run": record.run.clone(),
    }))
}

pub(super) fn plan_run_cancel_admission_required(
    request: RunCancelAdmissionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = RunCancelAdmissionRequiredCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "run_cancel_admission_required_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_run_cancel_admission_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "status_code": record.status_code,
        "code": record.code.clone(),
        "message": record.message.clone(),
        "rust_core_boundary": record.rust_core_boundary.clone(),
        "operation_kind": record.operation_kind.clone(),
        "details": record.details.clone(),
    }))
}
