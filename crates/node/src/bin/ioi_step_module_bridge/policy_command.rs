use ioi_services::agentic::runtime::kernel::policy::{
    DiagnosticsRepairAdmissionRequiredCore, DiagnosticsRepairAdmissionRequiredRequest,
    WorkflowEditAdmissionRequiredCore, WorkflowEditAdmissionRequiredRequest,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{BridgeError, DAEMON_CORE_COMMAND_SCHEMA_VERSION};

#[derive(Debug, Deserialize)]
pub(super) struct WorkflowEditAdmissionRequiredBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: WorkflowEditAdmissionRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct DiagnosticsRepairAdmissionRequiredBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: DiagnosticsRepairAdmissionRequiredRequest,
}

pub(super) fn plan_workflow_edit_admission_required(
    request: WorkflowEditAdmissionRequiredBridgeRequest,
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
    if request.operation != "plan_workflow_edit_admission_required" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = WorkflowEditAdmissionRequiredCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "workflow_edit_admission_required_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_workflow_edit_admission_required_command",
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

pub(super) fn plan_diagnostics_repair_admission_required(
    request: DiagnosticsRepairAdmissionRequiredBridgeRequest,
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
    if request.operation != "plan_diagnostics_repair_admission_required" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = DiagnosticsRepairAdmissionRequiredCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "diagnostics_repair_admission_required_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_diagnostics_repair_admission_required_command",
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
