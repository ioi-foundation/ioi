use ioi_services::agentic::runtime::kernel::ctee::{CteeNodeTrust, PrivateWorkspaceCteeModule};
use ioi_services::agentic::runtime::kernel::marketplace::{
    WorkerServicePackageInvocationCore, WorkerServicePackageInvocationRequest,
};
use ioi_services::agentic::runtime::kernel::receipt_binder::{
    AcceptedReceiptAppendIssuer, AcceptedReceiptAppendRequest, ReceiptBinder,
    ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::step_module::{
    StepModuleBackend, StepModuleInvocation, StepModuleKind,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::BridgeError;

#[derive(Debug, Deserialize)]
pub(super) struct CteePrivateWorkspaceBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    invocation: StepModuleInvocation,
    node_trust: CteeNodeTrust,
    #[serde(default)]
    expected_heads: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct WorkerServicePackageInvocationBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: WorkerServicePackageInvocationRequest,
}

pub(super) fn execute_private_workspace_ctee_action(
    request: CteePrivateWorkspaceBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.invocation.module_ref.kind != StepModuleKind::PrivateWorkspaceCteeAction
        || request.invocation.execution.backend != StepModuleBackend::CteeOperator
    {
        return Err(BridgeError::new(
            "ctee_step_module_required",
            "private workspace cTEE execution requires a ctee_operator StepModule invocation"
                .to_string(),
        ));
    }
    PrivateWorkspaceCteeModule
        .reject_caller_supplied_expected_heads(&request.expected_heads)
        .map_err(|error| BridgeError::new("ctee_execution_invalid", format!("{error:?}")))?;
    let record = PrivateWorkspaceCteeModule
        .execute_and_admit(&request.invocation, &request.node_trust)
        .map_err(|error| BridgeError::new("ctee_execution_invalid", format!("{error:?}")))?;
    let accepted_receipt_append = ReceiptBinder
        .append_accepted_receipt(
            &AcceptedReceiptAppendRequest {
                schema_version: ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION.to_string(),
                receipt_ref: record.receipt.receipt_ref.clone(),
                invocation_id: record.result.invocation_id.clone(),
                receipt_binding_ref: record.receipt_binding.binding_hash.clone(),
                issuer: AcceptedReceiptAppendIssuer::RustReceiptCore,
                state_root_before: record.receipt_binding.state_root_before.clone(),
                state_root_after: record.receipt_binding.state_root_after.clone(),
                resulting_head: record.receipt_binding.resulting_head.clone(),
            },
            &record.receipt_binding,
        )
        .map_err(|error| {
            BridgeError::new("accepted_receipt_append_invalid", format!("{error:?}"))
        })?;
    let receipt_refs = record.result.receipt_refs.clone();
    let evidence_refs = record.projection.evidence_refs.clone();
    Ok(json!({
        "source": "rust_ctee_private_workspace_command",
        "backend": request.backend.unwrap_or_else(|| "ctee_operator".to_string()),
        "record": record.clone(),
        "receipt": record.receipt.clone(),
        "result": record.result.clone(),
        "receipt_binding": record.receipt_binding.clone(),
        "accepted_receipt_append": accepted_receipt_append,
        "agentgres_admission": record.agentgres_admission.clone(),
        "projection_record": record.projection.clone(),
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
    }))
}

pub(super) fn admit_worker_service_package_invocation(
    request: WorkerServicePackageInvocationBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = WorkerServicePackageInvocationCore
        .admit_invocation(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "worker_service_package_invocation_invalid",
                format!("{error:?}"),
            )
        })?;
    let receipt_ref = record.receipt_refs.first().cloned().ok_or_else(|| {
        BridgeError::new(
            "receipt_ref_required",
            "worker/service package invocation requires a receipt ref".to_string(),
        )
    })?;
    let accepted_receipt_append = ReceiptBinder
        .append_accepted_receipt(
            &AcceptedReceiptAppendRequest {
                schema_version: ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION.to_string(),
                receipt_ref,
                invocation_id: record.invocation_id.clone(),
                receipt_binding_ref: record.receipt_binding.binding_hash.clone(),
                issuer: AcceptedReceiptAppendIssuer::RustReceiptCore,
                state_root_before: record.receipt_binding.state_root_before.clone(),
                state_root_after: record.receipt_binding.state_root_after.clone(),
                resulting_head: record.receipt_binding.resulting_head.clone(),
            },
            &record.receipt_binding,
        )
        .map_err(|error| {
            BridgeError::new("accepted_receipt_append_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_worker_service_package_invocation_command",
        "backend": request.backend.unwrap_or_else(|| "rust_package_invocation".to_string()),
        "record": record.clone(),
        "router_admission": record.router_admission.clone(),
        "receipt_binding": record.receipt_binding.clone(),
        "accepted_receipt_append": accepted_receipt_append,
        "agentgres_admission": record.agentgres_admission.clone(),
        "projection_record": record.projection.clone(),
        "receipt_refs": record.receipt_refs.clone(),
        "artifact_refs": record.artifact_refs.clone(),
        "payload_refs": record.payload_refs.clone(),
        "authority_grant_refs": record.authority_grant_refs.clone(),
    }))
}
