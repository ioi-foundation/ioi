use ioi_services::agentic::runtime::kernel::agentgres_admission::{
    AgentgresAdmissionCore, AgentgresOperationProposal, AGENTGRES_ADMISSION_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::model_mount::{
    ModelMountAcceptedReceiptHeadRequest, ModelMountAcceptedReceiptTransition,
    ModelMountAcceptedReceiptTransitionRequest, ModelMountCore,
};
use ioi_services::agentic::runtime::kernel::projection::RustProjectionCore;
use ioi_services::agentic::runtime::kernel::receipt_binder::{
    AcceptedReceiptAppendIssuer, AcceptedReceiptAppendRequest, ReceiptBinder,
    ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::step_module::{
    StepModuleBackend, StepModuleInvocation, StepModuleKind, StepModuleResult,
};
use ioi_services::agentic::runtime::kernel::step_router::StepModuleRouterCore;
use serde::Deserialize;
use serde_json::{json, Value};

use super::BridgeError;

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountAcceptedReceiptHeadBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountAcceptedReceiptHeadRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountAcceptedReceiptTransitionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountAcceptedReceiptTransitionRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountInvocationReceiptBindingBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    invocation: StepModuleInvocation,
    result: StepModuleResult,
    #[serde(default)]
    expected_heads: Vec<String>,
    #[serde(default)]
    accepted_receipt_transition: Option<ModelMountAcceptedReceiptTransition>,
    #[serde(default)]
    receipt_ref: Option<String>,
}

pub(super) fn plan_model_mount_accepted_receipt_head(
    request: ModelMountAcceptedReceiptHeadBridgeRequest,
) -> Result<Value, BridgeError> {
    let head = ModelMountCore
        .plan_accepted_receipt_head(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_accepted_receipt_head_rejected",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_model_mount_accepted_receipt_head_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_accepted_receipt_head".to_string()),
        "head": head.clone(),
        "sequence": head.sequence,
        "head_ref": head.head_ref,
        "state_root": head.state_root,
        "projection_watermark": head.projection_watermark,
        "head_hash": head.head_hash,
        "evidence_refs": head.evidence_refs,
    }))
}

pub(super) fn plan_model_mount_accepted_receipt_transition(
    request: ModelMountAcceptedReceiptTransitionBridgeRequest,
) -> Result<Value, BridgeError> {
    let transition = ModelMountCore
        .plan_accepted_receipt_transition(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_accepted_receipt_transition_rejected",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_model_mount_accepted_receipt_transition_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_accepted_receipt_transition".to_string()),
        "transition": transition.clone(),
        "operation_id": transition.operation_id,
        "operation_ref": transition.operation_ref,
        "expected_heads": transition.expected_heads,
        "state_root_before": transition.state_root_before,
        "state_root_after": transition.state_root_after,
        "resulting_head": transition.resulting_head,
        "projection_watermark": transition.projection_watermark,
        "transition_hash": transition.transition_hash,
        "evidence_refs": transition.evidence_refs,
    }))
}

pub(super) fn bind_model_mount_invocation_receipt(
    request: ModelMountInvocationReceiptBindingBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.invocation.module_ref.kind != StepModuleKind::ModelMount
        || request.invocation.execution.backend != StepModuleBackend::ModelMount
    {
        return Err(BridgeError::new(
            "model_mount_step_module_required",
            "model invocation receipt binding requires a model_mount StepModule invocation"
                .to_string(),
        ));
    }
    if !request.expected_heads.is_empty() {
        return Err(BridgeError::new(
            "model_mount_caller_supplied_expected_heads",
            "model mount invocation expected heads must come from the Rust accepted-receipt transition planner".to_string(),
        ));
    }
    let expected_heads = if request.result.agentgres_operation_refs.is_empty() {
        vec![]
    } else {
        let transition = request.accepted_receipt_transition.as_ref().ok_or_else(|| {
            BridgeError::new(
                "model_mount_accepted_receipt_transition_required",
                "model invocation Agentgres admission requires a Rust-planned accepted receipt transition".to_string(),
            )
        })?;
        ModelMountCore
            .validate_accepted_receipt_transition(transition)
            .map_err(|error| {
                BridgeError::new(
                    "model_mount_accepted_receipt_transition_invalid",
                    format!("{error:?}"),
                )
            })?;
        let operation_ref = request
            .result
            .agentgres_operation_refs
            .first()
            .cloned()
            .unwrap_or_default();
        if operation_ref != transition.operation_ref
            || request.result.state_root_after.as_deref()
                != Some(transition.state_root_after.as_str())
            || request.result.resulting_head.as_deref() != Some(transition.resulting_head.as_str())
            || request.invocation.input.state_root_before.as_deref()
                != Some(transition.state_root_before.as_str())
        {
            return Err(BridgeError::new(
                "model_mount_accepted_receipt_transition_mismatch",
                "model invocation StepModule result must match the Rust-planned accepted receipt transition".to_string(),
            ));
        }
        transition.expected_heads.clone()
    };
    let router_admission = StepModuleRouterCore
        .admit_execution(&request.invocation, &request.result)
        .map_err(|error| BridgeError::new("router_admission_invalid", format!("{error:?}")))?;
    let receipt_binding = ReceiptBinder
        .bind_step_module_result(&request.invocation, &request.result, expected_heads)
        .map_err(|error| BridgeError::new("receipt_binding_invalid", format!("{error:?}")))?;
    let receipt_ref = request
        .receipt_ref
        .clone()
        .or_else(|| request.result.receipt_refs.first().cloned())
        .ok_or_else(|| {
            BridgeError::new(
                "receipt_ref_required",
                "model invocation receipt binding requires a receipt ref".to_string(),
            )
        })?;
    let accepted_receipt_append = ReceiptBinder
        .append_accepted_receipt(
            &AcceptedReceiptAppendRequest {
                schema_version: ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION.to_string(),
                receipt_ref: receipt_ref.clone(),
                invocation_id: request.invocation.invocation_id.clone(),
                receipt_binding_ref: receipt_binding.binding_hash.clone(),
                issuer: AcceptedReceiptAppendIssuer::RustReceiptCore,
                state_root_before: receipt_binding.state_root_before.clone(),
                state_root_after: receipt_binding.state_root_after.clone(),
                resulting_head: receipt_binding.resulting_head.clone(),
            },
            &receipt_binding,
        )
        .map_err(|error| {
            BridgeError::new("accepted_receipt_append_invalid", format!("{error:?}"))
        })?;
    let agentgres_admission = if request.result.agentgres_operation_refs.is_empty() {
        Value::Null
    } else {
        let proposal = AgentgresOperationProposal {
            schema_version: AGENTGRES_ADMISSION_SCHEMA_VERSION.to_string(),
            operation_ref: request
                .result
                .agentgres_operation_refs
                .first()
                .cloned()
                .unwrap_or_default(),
            invocation_id: request.result.invocation_id.clone(),
            receipt_binding_ref: receipt_binding.binding_hash.clone(),
            receipt_refs: request.result.receipt_refs.clone(),
            artifact_refs: request.result.artifact_refs.clone(),
            payload_refs: request.result.payload_refs.clone(),
            expected_heads: receipt_binding.expected_heads.clone(),
            state_root_before: receipt_binding.state_root_before.clone(),
            state_root_after: request.result.state_root_after.clone(),
            resulting_head: request.result.resulting_head.clone(),
        };
        match AgentgresAdmissionCore.admit(&proposal, &receipt_binding) {
            Ok(record) => json!(record),
            Err(error) => {
                return Err(BridgeError::new(
                    "agentgres_admission_invalid",
                    format!("{error:?}"),
                ));
            }
        }
    };
    let projection_record = RustProjectionCore
        .project_step_module_result(&request.invocation, &request.result, &receipt_binding)
        .map_err(|error| BridgeError::new("projection_record_invalid", format!("{error:?}")))?;
    let receipt_refs = request.result.receipt_refs.clone();
    let binding_hash = receipt_binding.binding_hash.clone();
    let append_hash = accepted_receipt_append.append_hash.clone();
    Ok(json!({
        "source": "rust_model_mount_receipt_binding_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_live".to_string()),
        "invocation": request.invocation,
        "result": request.result,
        "router_admission": router_admission,
        "receipt_binding": receipt_binding,
        "accepted_receipt_append": accepted_receipt_append,
        "agentgres_admission": agentgres_admission,
        "projection_record": projection_record,
        "receipt_refs": receipt_refs,
        "evidence_refs": [
            "rust_receipt_binder_core",
            binding_hash,
            append_hash,
        ],
    }))
}
