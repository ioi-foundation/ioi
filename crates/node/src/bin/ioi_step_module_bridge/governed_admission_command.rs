use ioi_services::agentic::evolution::{GovernedEvolutionCore, GovernedRuntimeImprovementProposal};
use ioi_services::agentic::runtime::kernel::ctee::{CteeNodeTrust, PrivateWorkspaceCteeModule};
use ioi_services::agentic::runtime::kernel::marketplace::{
    WorkerServicePackageInvocationCore, WorkerServicePackageInvocationRequest,
};
use ioi_services::agentic::runtime::kernel::receipt_binder::{
    AcceptedReceiptAppendIssuer, AcceptedReceiptAppendRequest, ReceiptBinder,
    ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::settlement::{
    L1SettlementAttempt, L1SettlementTriggerGuard,
};
use ioi_services::agentic::runtime::kernel::step_module::{
    StepModuleBackend, StepModuleInvocation, StepModuleKind,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{BridgeError, DAEMON_CORE_COMMAND_SCHEMA_VERSION};

#[derive(Debug, Deserialize)]
pub(super) struct CteePrivateWorkspaceBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    invocation: StepModuleInvocation,
    node_trust: CteeNodeTrust,
    #[serde(default)]
    expected_heads: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct WorkerServicePackageInvocationBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: WorkerServicePackageInvocationRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct L1SettlementAdmissionBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    attempt: L1SettlementAttempt,
}

#[derive(Debug, Deserialize)]
pub(super) struct GovernedRuntimeImprovementBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    proposal: GovernedRuntimeImprovementProposal,
}

pub(super) fn execute_private_workspace_ctee_action(
    request: CteePrivateWorkspaceBridgeRequest,
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
    if request.operation != "execute_private_workspace_ctee_action" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
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
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "admit_worker_service_package_invocation" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
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

pub(super) fn admit_l1_settlement_attempt(
    request: L1SettlementAdmissionBridgeRequest,
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
    if request.operation != "admit_l1_settlement_attempt" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = L1SettlementTriggerGuard
        .admit(&request.attempt)
        .map_err(|error| {
            BridgeError::new("l1_settlement_admission_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_l1_settlement_guard_command",
        "backend": request.backend.unwrap_or_else(|| "l1_settlement_guard".to_string()),
        "record": record.clone(),
        "settlement_ref": record.settlement_ref,
        "domain_ref": record.domain_ref,
        "state_root_ref": record.state_root_ref,
        "trigger_refs": record.trigger_refs,
        "receipt_refs": record.receipt_refs,
        "admission_hash": record.admission_hash,
    }))
}

pub(super) fn admit_governed_runtime_improvement_proposal(
    request: GovernedRuntimeImprovementBridgeRequest,
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
    if request.operation != "admit_governed_runtime_improvement_proposal" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = GovernedEvolutionCore
        .admit_proposal(&request.proposal)
        .map_err(|error| {
            BridgeError::new("governed_runtime_improvement_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_governed_meta_improvement_command",
        "backend": request.backend.unwrap_or_else(|| "rust_governed_evolution".to_string()),
        "record": record.clone(),
        "proposal_id": record.proposal_id.clone(),
        "target_ref": record.target_ref.clone(),
        "candidate_ref": record.candidate_ref.clone(),
        "admission_hash": record.admission_hash.clone(),
        "agentgres_operation_ref": record.agentgres_operation_ref.clone(),
        "expected_heads": record.expected_heads.clone(),
        "state_root_before": record.state_root_before.clone(),
        "state_root_after": record.state_root_after.clone(),
        "resulting_head": record.resulting_head.clone(),
        "eval_receipt_refs": record.eval_receipt_refs.clone(),
        "verifier_receipt_refs": record.verifier_receipt_refs.clone(),
        "approval_ref": record.approval_ref.clone(),
        "rollback_ref": record.rollback_ref.clone(),
    }))
}
