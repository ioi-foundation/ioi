use ioi_services::agentic::runtime::kernel::model_mount::{
    plan_model_mount_backend_lifecycle_required_response as core_plan_model_mount_backend_lifecycle_required,
    plan_model_mount_backend_process_response as core_plan_model_mount_backend_process,
    plan_model_mount_instance_lifecycle_response as core_plan_model_mount_instance_lifecycle,
    plan_model_mount_provider_inventory_response as core_plan_model_mount_provider_inventory,
    plan_model_mount_provider_lifecycle_response as core_plan_model_mount_provider_lifecycle,
    plan_model_mount_read_projection_response as core_plan_model_mount_read_projection,
    plan_model_mount_route_control_required_response as core_plan_model_mount_route_control_required,
    plan_model_mount_runtime_engine_required_response as core_plan_model_mount_runtime_engine_required,
    plan_model_mount_server_control_required_response as core_plan_model_mount_server_control_required,
    plan_model_mount_tokenizer_required_response as core_plan_model_mount_tokenizer_required,
    ModelMountCore, ModelMountError, ModelMountInvocationAdmissionRequest,
    ModelMountProviderExecutionRequest, ModelMountProviderInvocationRequest,
    ModelMountProviderResultAdmissionRequest, ModelMountReadProjectionError,
    ModelMountRouteDecisionRequest,
};
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
pub(super) struct ModelMountProviderResultAdmissionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountProviderResultAdmissionRequest,
}

pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountBackendLifecycleRequiredBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountBackendProcessPlanBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountInstanceLifecycleBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountProviderInventoryBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountProviderLifecycleBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountReadProjectionBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountRouteControlRequiredBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountRuntimeEngineRequiredBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountServerControlRequiredBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountTokenizerRequiredBridgeRequest;

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
    core_plan_model_mount_provider_lifecycle(request)
        .map_err(|error| model_mount_bridge_error("model_mount_provider_lifecycle_rejected", error))
}

pub(super) fn plan_model_mount_provider_inventory(
    request: ModelMountProviderInventoryBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_provider_inventory(request)
        .map_err(|error| model_mount_bridge_error("model_mount_provider_inventory_rejected", error))
}

pub(super) fn plan_model_mount_instance_lifecycle(
    request: ModelMountInstanceLifecycleBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_instance_lifecycle(request)
        .map_err(|error| model_mount_bridge_error("model_mount_instance_lifecycle_rejected", error))
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
    core_plan_model_mount_backend_process(request).map_err(|error| {
        model_mount_bridge_error("model_mount_backend_process_plan_rejected", error)
    })
}

pub(super) fn plan_model_mount_backend_lifecycle_required(
    request: ModelMountBackendLifecycleRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_backend_lifecycle_required(request).map_err(|error| {
        model_mount_bridge_error("model_mount_backend_lifecycle_required_invalid", error)
    })
}

pub(super) fn plan_model_mount_server_control_required(
    request: ModelMountServerControlRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_server_control_required(request).map_err(|error| {
        model_mount_bridge_error("model_mount_server_control_required_invalid", error)
    })
}

pub(super) fn plan_model_mount_runtime_engine_required(
    request: ModelMountRuntimeEngineRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_runtime_engine_required(request).map_err(|error| {
        model_mount_bridge_error("model_mount_runtime_engine_required_invalid", error)
    })
}

pub(super) fn plan_model_mount_tokenizer_required(
    request: ModelMountTokenizerRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_tokenizer_required(request)
        .map_err(|error| model_mount_bridge_error("model_mount_tokenizer_required_invalid", error))
}

pub(super) fn plan_model_mount_route_control_required(
    request: ModelMountRouteControlRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_route_control_required(request).map_err(|error| {
        model_mount_bridge_error("model_mount_route_control_required_invalid", error)
    })
}

pub(super) fn plan_model_mount_read_projection(
    request: ModelMountReadProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_read_projection(request).map_err(read_projection_bridge_error)
}

fn read_projection_bridge_error(error: ModelMountReadProjectionError) -> BridgeError {
    BridgeError::new(error.code, error.message)
}

fn model_mount_bridge_error(code: &'static str, error: ModelMountError) -> BridgeError {
    BridgeError::new(code, format!("{error:?}"))
}
