use ioi_services::agentic::runtime::kernel::policy::{
    plan_diagnostics_repair_admission_required_response as core_plan_diagnostics_repair_admission_required,
    plan_workflow_edit_admission_required_response as core_plan_workflow_edit_admission_required,
    AdmissionRequiredCommandError,
};
use serde_json::Value;

use super::BridgeError;
pub(super) use ioi_services::agentic::runtime::kernel::policy::{
    DiagnosticsRepairAdmissionRequiredBridgeRequest, WorkflowEditAdmissionRequiredBridgeRequest,
};

pub(super) fn plan_workflow_edit_admission_required(
    request: WorkflowEditAdmissionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_workflow_edit_admission_required(request).map_err(bridge_error)
}

pub(super) fn plan_diagnostics_repair_admission_required(
    request: DiagnosticsRepairAdmissionRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_diagnostics_repair_admission_required(request).map_err(bridge_error)
}

fn bridge_error(error: AdmissionRequiredCommandError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}
