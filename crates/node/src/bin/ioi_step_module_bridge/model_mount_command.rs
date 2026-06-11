use ioi_services::agentic::runtime::kernel::agentgres_admission::{
    AgentgresAdmissionCore, AgentgresOperationProposal, AGENTGRES_ADMISSION_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::model_mount::{
    ModelMountAcceptedReceiptHeadRequest, ModelMountAcceptedReceiptTransition,
    ModelMountAcceptedReceiptTransitionRequest, ModelMountBackendLifecycleRequiredRequest,
    ModelMountBackendProcessPlanRequest, ModelMountCore, ModelMountInstanceLifecycleRequest,
    ModelMountInvocationAdmissionRequest, ModelMountProviderExecutionRequest,
    ModelMountProviderInventoryRequest, ModelMountProviderInvocationRequest,
    ModelMountProviderLifecycleRequest, ModelMountProviderResultAdmissionRequest,
    ModelMountReadProjectionRequest, ModelMountRouteControlRequiredRequest,
    ModelMountRouteDecisionRequest, ModelMountRuntimeEngineRequiredRequest,
    ModelMountServerControlRequiredRequest, ModelMountTokenizerRequiredRequest,
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

use super::{BridgeError, MODEL_MOUNT_RUNTIME_SCHEMA_VERSION};

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountRouteDecisionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountRouteDecisionRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountInvocationAdmissionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountInvocationAdmissionRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountProviderExecutionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountProviderExecutionRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountProviderInvocationBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountProviderInvocationRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountProviderLifecycleBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountProviderLifecycleRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountProviderInventoryBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountProviderInventoryRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountInstanceLifecycleBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountInstanceLifecycleRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountProviderResultAdmissionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountProviderResultAdmissionRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountBackendProcessPlanBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountBackendProcessPlanRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountBackendLifecycleRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountBackendLifecycleRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountServerControlRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountServerControlRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountRuntimeEngineRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountRuntimeEngineRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountTokenizerRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountTokenizerRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountRouteControlRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountRouteControlRequiredRequest,
}

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

#[derive(Debug, Deserialize)]
pub(super) struct ModelMountReadProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountReadProjectionRequest,
}

pub(super) fn admit_model_mount_route_decision(
    request: ModelMountRouteDecisionBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = ModelMountCore
        .admit_route_decision(&request.request)
        .map_err(|error| {
            BridgeError::new("model_mount_route_decision_rejected", format!("{error:?}"))
        })?;
    let accepted_receipt_record = rust_authored_route_selection_receipt(&record)?;
    Ok(json!({
        "source": "rust_model_mount_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_live".to_string()),
        "record": record,
        "route_decision_ref": record.route_decision_ref,
        "route_decision_hash": record.route_decision_hash,
        "receipt_refs": record.receipt_refs,
        "accepted_receipt_record": accepted_receipt_record,
        "evidence_refs": [
            "rust_model_mount_core",
            record.route_decision_ref,
        ],
    }))
}

fn rust_authored_route_selection_receipt(
    record: &ioi_services::agentic::runtime::kernel::model_mount::ModelMountRouteDecisionRecord,
) -> Result<Value, BridgeError> {
    let receipt_ref = record.receipt_refs.first().ok_or_else(|| {
        BridgeError::new(
            "model_mount_route_receipt_missing",
            "route decision missing receipt ref".to_string(),
        )
    })?;
    let receipt_id = receipt_ref
        .strip_prefix("receipt://")
        .unwrap_or(receipt_ref.as_str())
        .to_string();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| {
            BridgeError::new("model_mount_route_receipt_time_failed", error.to_string())
        })?
        .as_secs();
    Ok(json!({
        "id": receipt_id,
        "runId": null,
        "kind": "model_route_selection",
        "summary": format!("Route {} selected {}.", record.route_ref, record.model_ref),
        "redaction": "none",
        "evidenceRefs": [
            "model_router",
            "rust_model_mount_core",
            "rust_daemon_core_model_route_selection_receipt",
            record.route_ref,
            record.endpoint_ref,
            record.route_decision_ref,
        ],
        "createdAt": format!("unix:{created_at}"),
        "details": {
            "rust_daemon_core_receipt_author": "ModelMountCore.admit_route_decision",
            "route_id": record.route_ref,
            "selected_model": record.model_ref,
            "endpoint_id": record.endpoint_ref,
            "provider_id": record.provider_ref,
            "capability": record.capability,
            "policy_hash": record.policy_hash,
            "response_id": null,
            "previous_response_id": null,
            "model_route_decision_schema_version": record.schema_version,
            "model_route_decision_event_kind": "model_route_decision",
            "model_route_decision_id": record.idempotency_key,
            "model_route_decision": {
                "decision_id": record.idempotency_key,
                "route_id": record.route_ref,
                "selected_model": record.model_ref,
                "selected_endpoint_id": record.endpoint_ref,
                "provider_id": record.provider_ref,
                "capability": record.capability,
                "policy_hash": record.policy_hash,
            },
            "model_mount_route_decision_schema_version": record.schema_version,
            "model_mount_route_decision_ref": record.route_decision_ref,
            "model_mount_route_decision_hash": record.route_decision_hash,
            "model_mount_route_decision_source": "rust_model_mount_command",
            "model_mount_route_decision_backend": "rust_model_mount_live",
            "model_mount_route_decision_receipt_refs": record.receipt_refs,
            "model_mount_route_decision": record,
            "workflow_graph_id": record.workflow_graph_ref,
            "workflow_node_id": record.workflow_node_ref,
            "workflow_node_type": null,
        },
        "schemaVersion": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
    }))
}

pub(super) fn admit_model_mount_invocation(
    request: ModelMountInvocationAdmissionBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = ModelMountCore
        .admit_invocation(&request.request)
        .map_err(|error| {
            BridgeError::new("model_mount_invocation_rejected", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_model_mount_invocation_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_live".to_string()),
        "record": record,
        "invocation_admission_ref": record.invocation_admission_ref,
        "invocation_admission_hash": record.invocation_admission_hash,
        "receipt_refs": record.receipt_refs,
        "evidence_refs": [
            "rust_model_mount_core",
            record.invocation_admission_ref,
        ],
    }))
}

pub(super) fn admit_model_mount_provider_execution(
    request: ModelMountProviderExecutionBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = ModelMountCore
        .admit_provider_execution(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_provider_execution_rejected",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_model_mount_provider_execution_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_live".to_string()),
        "record": record,
        "provider_execution_ref": record.provider_execution_ref,
        "provider_execution_hash": record.provider_execution_hash,
        "receipt_refs": record.receipt_refs,
        "evidence_refs": [
            "rust_model_mount_core",
            record.provider_execution_ref,
        ],
    }))
}

pub(super) fn execute_model_mount_provider_invocation(
    request: ModelMountProviderInvocationBridgeRequest,
) -> Result<Value, BridgeError> {
    let result = ModelMountCore
        .invoke_provider(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_provider_invocation_rejected",
                format!("{error:?}"),
            )
        })?;
    let output_text = result.output_text.clone();
    let token_count = result.token_count.clone();
    let provider_response_kind = result.provider_response_kind.clone();
    let execution_backend = result.execution_backend.clone();
    let backend_id = result.backend_id.clone();
    let provider_execution_ref = result.provider_execution_ref.clone();
    let provider_execution_hash = result.provider_execution_hash.clone();
    let invocation_hash = result.invocation_hash.clone();
    let evidence_refs = result.evidence_refs.clone();
    Ok(json!({
        "source": "rust_model_mount_provider_invocation_command",
        "backend": request.backend.unwrap_or_else(|| execution_backend.clone()),
        "result": result,
        "outputText": output_text.clone(),
        "output_text": output_text,
        "tokenCount": token_count.clone(),
        "token_count": token_count,
        "providerResponse": null,
        "provider_response": null,
        "providerResponseKind": provider_response_kind.clone(),
        "provider_response_kind": provider_response_kind,
        "execution_backend": execution_backend,
        "backendId": backend_id.clone(),
        "backend_id": backend_id,
        "provider_execution_ref": provider_execution_ref,
        "provider_execution_hash": provider_execution_hash,
        "invocation_hash": invocation_hash,
        "evidence_refs": evidence_refs,
    }))
}

pub(super) fn execute_model_mount_provider_stream_invocation(
    request: ModelMountProviderInvocationBridgeRequest,
) -> Result<Value, BridgeError> {
    let result = ModelMountCore
        .invoke_provider_stream(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_provider_stream_invocation_rejected",
                format!("{error:?}"),
            )
        })?;
    let output_text = result.output_text.clone();
    let token_count = result.token_count.clone();
    let provider_response_kind = result.provider_response_kind.clone();
    let execution_backend = result.execution_backend.clone();
    let backend_id = result.backend_id.clone();
    let stream_format = result.stream_format.clone();
    let stream_kind = result.stream_kind.clone();
    let stream_chunks = result.stream_chunks.clone();
    let provider_execution_ref = result.provider_execution_ref.clone();
    let provider_execution_hash = result.provider_execution_hash.clone();
    let invocation_hash = result.invocation_hash.clone();
    let evidence_refs = result.evidence_refs.clone();
    Ok(json!({
        "source": "rust_model_mount_provider_stream_invocation_command",
        "backend": request.backend.unwrap_or_else(|| execution_backend.clone()),
        "result": result,
        "outputText": output_text.clone(),
        "output_text": output_text,
        "tokenCount": token_count.clone(),
        "token_count": token_count,
        "providerResponse": null,
        "provider_response": null,
        "providerResponseKind": provider_response_kind.clone(),
        "provider_response_kind": provider_response_kind,
        "execution_backend": execution_backend,
        "backendId": backend_id.clone(),
        "backend_id": backend_id,
        "streamFormat": stream_format.clone(),
        "stream_format": stream_format,
        "streamKind": stream_kind.clone(),
        "stream_kind": stream_kind,
        "streamChunks": stream_chunks.clone(),
        "stream_chunks": stream_chunks,
        "provider_execution_ref": provider_execution_ref,
        "provider_execution_hash": provider_execution_hash,
        "invocation_hash": invocation_hash,
        "evidence_refs": evidence_refs,
    }))
}

pub(super) fn plan_model_mount_provider_lifecycle(
    request: ModelMountProviderLifecycleBridgeRequest,
) -> Result<Value, BridgeError> {
    let result = ModelMountCore
        .plan_provider_lifecycle(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_provider_lifecycle_rejected",
                format!("{error:?}"),
            )
        })?;
    let status = result.status.clone();
    let backend = result.backend.clone();
    let backend_id = result.backend_id.clone();
    let driver = result.driver.clone();
    let execution_backend = result.execution_backend.clone();
    let lifecycle_hash = result.lifecycle_hash.clone();
    let evidence_refs = result.evidence_refs.clone();
    Ok(json!({
        "source": "rust_model_mount_provider_lifecycle_command",
        "backend": request.backend.unwrap_or_else(|| execution_backend.clone()),
        "result": result,
        "status": status,
        "backend_id": backend_id,
        "provider_backend": backend,
        "driver": driver,
        "execution_backend": execution_backend,
        "lifecycle_hash": lifecycle_hash,
        "evidence_refs": evidence_refs,
    }))
}

pub(super) fn plan_model_mount_provider_inventory(
    request: ModelMountProviderInventoryBridgeRequest,
) -> Result<Value, BridgeError> {
    let result = ModelMountCore
        .plan_provider_inventory(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_provider_inventory_rejected",
                format!("{error:?}"),
            )
        })?;
    let status = result.status.clone();
    let backend = result.backend.clone();
    let backend_id = result.backend_id.clone();
    let driver = result.driver.clone();
    let execution_backend = result.execution_backend.clone();
    let item_refs = result.item_refs.clone();
    let item_count = result.item_count;
    let inventory_hash = result.inventory_hash.clone();
    let evidence_refs = result.evidence_refs.clone();
    Ok(json!({
        "source": "rust_model_mount_provider_inventory_command",
        "backend": request.backend.unwrap_or_else(|| execution_backend.clone()),
        "result": result,
        "status": status,
        "backend_id": backend_id,
        "provider_backend": backend,
        "driver": driver,
        "execution_backend": execution_backend,
        "item_refs": item_refs,
        "item_count": item_count,
        "inventory_hash": inventory_hash,
        "evidence_refs": evidence_refs,
    }))
}

pub(super) fn plan_model_mount_instance_lifecycle(
    request: ModelMountInstanceLifecycleBridgeRequest,
) -> Result<Value, BridgeError> {
    let result = ModelMountCore
        .plan_instance_lifecycle(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_instance_lifecycle_rejected",
                format!("{error:?}"),
            )
        })?;
    let status = result.status.clone();
    let backend_id = result.backend_id.clone();
    let driver = result.driver.clone();
    let execution_backend = result.execution_backend.clone();
    let provider_lifecycle_hash = result.provider_lifecycle_hash.clone();
    let instance_lifecycle_hash = result.instance_lifecycle_hash.clone();
    let evidence_refs = result.evidence_refs.clone();
    Ok(json!({
        "source": "rust_model_mount_instance_lifecycle_command",
        "backend": request.backend.unwrap_or_else(|| execution_backend.clone()),
        "result": result,
        "status": status,
        "backendId": backend_id.clone(),
        "backend_id": backend_id,
        "driver": driver,
        "execution_backend": execution_backend,
        "provider_lifecycle_hash": provider_lifecycle_hash,
        "instance_lifecycle_hash": instance_lifecycle_hash,
        "evidence_refs": evidence_refs,
    }))
}

pub(super) fn admit_model_mount_provider_result(
    request: ModelMountProviderResultAdmissionBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = ModelMountCore
        .admit_provider_result(&request.request)
        .map_err(|error| {
            BridgeError::new("model_mount_provider_result_rejected", format!("{error:?}"))
        })?;
    let provider_result_ref = record.provider_result_ref.clone();
    let provider_result_hash = record.provider_result_hash.clone();
    let receipt_refs = record.receipt_refs.clone();
    let evidence_refs = record.evidence_refs.clone();
    Ok(json!({
        "source": "rust_model_mount_provider_result_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_live".to_string()),
        "record": record,
        "provider_result_ref": provider_result_ref,
        "provider_result_hash": provider_result_hash,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
    }))
}

pub(super) fn plan_model_mount_backend_process(
    request: ModelMountBackendProcessPlanBridgeRequest,
) -> Result<Value, BridgeError> {
    let plan = ModelMountCore
        .plan_backend_process(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_backend_process_plan_rejected",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_model_mount_backend_process_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_backend_process".to_string()),
        "result": plan.clone(),
        "supports_supervision": plan.supports_supervision,
        "supervisor_kind": plan.supervisor_kind,
        "public_args": plan.public_args,
        "spawn_args": plan.spawn_args,
        "spawn_required": plan.spawn_required,
        "spawn_status": plan.spawn_status,
        "plan_hash": plan.plan_hash,
        "evidence_refs": plan.evidence_refs,
    }))
}

pub(super) fn plan_model_mount_backend_lifecycle_required(
    request: ModelMountBackendLifecycleRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = ModelMountCore
        .plan_backend_lifecycle_required(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_backend_lifecycle_required_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_model_mount_backend_lifecycle_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_backend_lifecycle_required".to_string()),
        "record": record.clone(),
        "status": record.status,
        "status_code": record.status_code,
        "code": record.code,
        "message": record.message,
        "rust_core_boundary": record.rust_core_boundary,
        "operation_kind": record.operation_kind,
        "details": record.details,
    }))
}

pub(super) fn plan_model_mount_server_control_required(
    request: ModelMountServerControlRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = ModelMountCore
        .plan_server_control_required(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_server_control_required_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_model_mount_server_control_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_server_control_required".to_string()),
        "record": record.clone(),
        "status": record.status,
        "status_code": record.status_code,
        "code": record.code,
        "message": record.message,
        "rust_core_boundary": record.rust_core_boundary,
        "operation_kind": record.operation_kind,
        "details": record.details,
    }))
}

pub(super) fn plan_model_mount_runtime_engine_required(
    request: ModelMountRuntimeEngineRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = ModelMountCore
        .plan_runtime_engine_required(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_runtime_engine_required_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_model_mount_runtime_engine_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_runtime_engine_required".to_string()),
        "record": record.clone(),
        "status": record.status,
        "status_code": record.status_code,
        "code": record.code,
        "message": record.message,
        "rust_core_boundary": record.rust_core_boundary,
        "operation_kind": record.operation_kind,
        "details": record.details,
    }))
}

pub(super) fn plan_model_mount_tokenizer_required(
    request: ModelMountTokenizerRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = ModelMountCore
        .plan_tokenizer_required(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_tokenizer_required_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_model_mount_tokenizer_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_tokenizer_required".to_string()),
        "record": record.clone(),
        "status": record.status,
        "status_code": record.status_code,
        "code": record.code,
        "message": record.message,
        "rust_core_boundary": record.rust_core_boundary,
        "operation": record.operation,
        "details": record.details,
    }))
}

pub(super) fn plan_model_mount_route_control_required(
    request: ModelMountRouteControlRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = ModelMountCore
        .plan_route_control_required(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "model_mount_route_control_required_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_model_mount_route_control_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_route_control_required".to_string()),
        "record": record.clone(),
        "status": record.status,
        "status_code": record.status_code,
        "code": record.code,
        "message": record.message,
        "rust_core_boundary": record.rust_core_boundary,
        "operation": record.operation,
        "operation_kind": record.operation_kind,
        "details": record.details,
    }))
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

pub(super) fn plan_model_mount_read_projection(
    request: ModelMountReadProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    let plan = ModelMountCore
        .plan_read_projection(&request.request)
        .map_err(|error| BridgeError::new(error.code, error.message))?;
    Ok(json!({
        "source": "rust_model_mount_read_projection_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_read_projection".to_string()),
        "projection_kind": plan.projection_kind,
        "projection": plan.projection,
        "evidence_refs": plan.evidence_refs,
    }))
}
