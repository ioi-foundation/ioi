use ioi_services::agentic::runtime::kernel::policy::{
    CodingToolBudgetRecoveryAdmissionRequiredCore,
    CodingToolBudgetRecoveryAdmissionRequiredRequest, CodingToolBudgetRecoveryStateUpdateCore,
    CodingToolBudgetRecoveryStateUpdateRequest, DiagnosticsOperatorOverrideStateUpdateCore,
    DiagnosticsOperatorOverrideStateUpdateRequest, OperatorInterruptStateUpdateCore,
    OperatorInterruptStateUpdateRequest, OperatorSteerStateUpdateCore,
    OperatorSteerStateUpdateRequest, RunCancelAdmissionRequiredCore,
    RunCancelAdmissionRequiredRequest, RunCancelStateUpdateCore, RunCancelStateUpdateRequest,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{BridgeError, DAEMON_CORE_COMMAND_SCHEMA_VERSION};

#[derive(Debug, Deserialize)]
pub(super) struct CodingToolBudgetRecoveryStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: CodingToolBudgetRecoveryStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct CodingToolBudgetRecoveryAdmissionRequiredBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: CodingToolBudgetRecoveryAdmissionRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct DiagnosticsOperatorOverrideStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: DiagnosticsOperatorOverrideStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct OperatorInterruptStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: OperatorInterruptStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct OperatorSteerStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: OperatorSteerStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RunCancelStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: RunCancelStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RunCancelAdmissionRequiredBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: RunCancelAdmissionRequiredRequest,
}

pub(super) fn plan_coding_tool_budget_recovery_state_update(
    request: CodingToolBudgetRecoveryStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_coding_tool_budget_recovery_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
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
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_coding_tool_budget_recovery_admission_required" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
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
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_diagnostics_operator_override_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
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

pub(super) fn plan_operator_interrupt_state_update(
    request: OperatorInterruptStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_operator_interrupt_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
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
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_operator_steer_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
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
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_run_cancel_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
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
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_run_cancel_admission_required" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
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
