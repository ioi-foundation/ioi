use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{
    accepted_receipt::{
        plan_accepted_receipt_transition, ModelMountAcceptedReceiptTransitionRequest,
    },
    non_empty_string, push_unique_ref, require_non_empty, sha256_hex, trimmed_string,
    ModelMountError, MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION,
    MODEL_MOUNT_CONVERSATION_STATE_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_CONVERSATION_STATE_SCHEMA_VERSION, MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
    MODEL_MOUNT_STREAM_CANCEL_PLAN_SCHEMA_VERSION, MODEL_MOUNT_STREAM_CANCEL_SCHEMA_VERSION,
    MODEL_MOUNT_STREAM_COMPLETION_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_STREAM_COMPLETION_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountConversationStateRequest {
    pub schema_version: String,
    pub operation: String,
    pub response_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_message_count: Option<u64>,
    pub kind: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_decision_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_receipt_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_receipt_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_receipt_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_text: Option<String>,
    #[serde(default)]
    pub token_count: Value,
    #[serde(default)]
    pub continuation_safety: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountConversationStatePlan {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    pub source: String,
    pub record_dir: String,
    pub record_id: String,
    pub record: Value,
    pub receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub conversation_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountStreamCompletionRequest {
    pub schema_version: String,
    pub operation: String,
    pub response_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_message_count: Option<u64>,
    pub kind: String,
    pub stream_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    pub receipt_id: String,
    pub current_sequence: u64,
    pub current_head_ref: String,
    pub current_state_root: String,
    pub invocation_receipt_ref: String,
    pub route_decision_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_receipt_ref: Option<String>,
    pub route_ref: String,
    pub endpoint_ref: String,
    pub provider_ref: String,
    pub model_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_text: Option<String>,
    #[serde(default)]
    pub token_count: Value,
    #[serde(default)]
    pub provider_usage: Value,
    #[serde(default)]
    pub provider_result: Value,
    #[serde(default)]
    pub provider_stream_shape_summary: Value,
    #[serde(default)]
    pub chunks_forwarded: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_response_kind: Option<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountStreamCompletionPlan {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    pub source: String,
    pub record_dir: String,
    pub record_id: String,
    pub record: Value,
    pub receipt: Value,
    pub receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub stream_completion_hash: String,
    pub conversation_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountStreamCancelRequest {
    pub schema_version: String,
    pub operation: String,
    pub response_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_message_count: Option<u64>,
    pub kind: String,
    pub stream_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    pub receipt_id: String,
    pub current_sequence: u64,
    pub current_head_ref: String,
    pub current_state_root: String,
    pub invocation_receipt_ref: String,
    pub route_decision_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_receipt_ref: Option<String>,
    pub route_ref: String,
    pub endpoint_ref: String,
    pub provider_ref: String,
    pub model_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_text: Option<String>,
    #[serde(default)]
    pub token_count: Value,
    #[serde(default)]
    pub provider_usage: Value,
    #[serde(default)]
    pub provider_result: Value,
    #[serde(default)]
    pub provider_stream_shape_summary: Value,
    #[serde(default)]
    pub frames_written: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_response_kind: Option<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountStreamCancelPlan {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    pub source: String,
    pub record_dir: String,
    pub record_id: String,
    pub record: Value,
    pub receipt: Value,
    pub receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub stream_cancel_hash: String,
    pub conversation_hash: String,
}

impl ModelMountConversationStateRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_CONVERSATION_STATE_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_CONVERSATION_STATE_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation", &self.operation)?;
        if self.operation != "model_conversation_state_write" {
            return Err(ModelMountError::UnsupportedConversationOperation);
        }
        require_non_empty("response_id", &self.response_id)?;
        require_non_empty("kind", &self.kind)?;
        require_non_empty("status", &self.status)?;
        require_option("route_ref", &self.route_ref)?;
        require_option("endpoint_ref", &self.endpoint_ref)?;
        require_option("provider_ref", &self.provider_ref)?;
        require_option("model_ref", &self.model_ref)?;
        if receipt_refs_for_conversation(self)?.is_empty() {
            return Err(ModelMountError::MissingReceiptRef);
        }
        Ok(())
    }
}

impl ModelMountStreamCompletionRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_STREAM_COMPLETION_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_STREAM_COMPLETION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation", &self.operation)?;
        if self.operation != "model_stream_completion" {
            return Err(ModelMountError::UnsupportedConversationOperation);
        }
        require_non_empty("response_id", &self.response_id)?;
        require_non_empty("kind", &self.kind)?;
        require_non_empty("stream_kind", &self.stream_kind)?;
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_non_empty("current_head_ref", &self.current_head_ref)?;
        require_non_empty("current_state_root", &self.current_state_root)?;
        require_non_empty("invocation_receipt_ref", &self.invocation_receipt_ref)?;
        require_non_empty("route_decision_ref", &self.route_decision_ref)?;
        require_non_empty("route_ref", &self.route_ref)?;
        require_non_empty("endpoint_ref", &self.endpoint_ref)?;
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("model_ref", &self.model_ref)?;
        if receipt_refs_for_stream(self).is_empty() {
            return Err(ModelMountError::MissingReceiptRef);
        }
        Ok(())
    }
}

impl ModelMountStreamCancelRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_STREAM_CANCEL_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_STREAM_CANCEL_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation", &self.operation)?;
        if self.operation != "model_stream_cancel" {
            return Err(ModelMountError::UnsupportedConversationOperation);
        }
        require_non_empty("response_id", &self.response_id)?;
        require_non_empty("kind", &self.kind)?;
        require_non_empty("stream_kind", &self.stream_kind)?;
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_non_empty("current_head_ref", &self.current_head_ref)?;
        require_non_empty("current_state_root", &self.current_state_root)?;
        require_non_empty("invocation_receipt_ref", &self.invocation_receipt_ref)?;
        require_non_empty("route_decision_ref", &self.route_decision_ref)?;
        require_non_empty("route_ref", &self.route_ref)?;
        require_non_empty("endpoint_ref", &self.endpoint_ref)?;
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("model_ref", &self.model_ref)?;
        if receipt_refs_for_cancel(self).is_empty() {
            return Err(ModelMountError::MissingReceiptRef);
        }
        Ok(())
    }
}

pub fn plan_model_mount_conversation_state(
    request: &ModelMountConversationStateRequest,
) -> Result<Value, ModelMountError> {
    let plan = plan_conversation_state(request)?;
    let record_dir = plan.record_dir.clone();
    let record_id = plan.record_id.clone();
    let record = plan.record.clone();
    let receipt_refs = plan.receipt_refs.clone();
    let evidence_refs = plan.evidence_refs.clone();
    let conversation_hash = plan.conversation_hash.clone();
    let operation = plan.operation.clone();
    let operation_kind = plan.operation_kind.clone();
    let rust_core_boundary = plan.rust_core_boundary.clone();
    Ok(json!({
        "source": "rust_daemon_core.model_mount.conversation_state",
        "plan": plan,
        "record_dir": record_dir,
        "record_id": record_id,
        "record": record,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "conversation_hash": conversation_hash,
        "operation": operation,
        "operation_kind": operation_kind,
        "rust_core_boundary": rust_core_boundary,
    }))
}

pub fn plan_model_mount_stream_completion(
    request: &ModelMountStreamCompletionRequest,
) -> Result<Value, ModelMountError> {
    let plan = plan_stream_completion(request)?;
    let record_dir = plan.record_dir.clone();
    let record_id = plan.record_id.clone();
    let record = plan.record.clone();
    let receipt = plan.receipt.clone();
    let receipt_refs = plan.receipt_refs.clone();
    let evidence_refs = plan.evidence_refs.clone();
    let stream_completion_hash = plan.stream_completion_hash.clone();
    let conversation_hash = plan.conversation_hash.clone();
    let operation = plan.operation.clone();
    let operation_kind = plan.operation_kind.clone();
    let rust_core_boundary = plan.rust_core_boundary.clone();
    Ok(json!({
        "source": "rust_daemon_core.model_mount.stream_completion",
        "plan": plan,
        "record_dir": record_dir,
        "record_id": record_id,
        "record": record,
        "receipt": receipt,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "stream_completion_hash": stream_completion_hash,
        "conversation_hash": conversation_hash,
        "operation": operation,
        "operation_kind": operation_kind,
        "rust_core_boundary": rust_core_boundary,
    }))
}

pub fn plan_model_mount_stream_cancel(
    request: &ModelMountStreamCancelRequest,
) -> Result<Value, ModelMountError> {
    let plan = plan_stream_cancel(request)?;
    let record_dir = plan.record_dir.clone();
    let record_id = plan.record_id.clone();
    let record = plan.record.clone();
    let receipt = plan.receipt.clone();
    let receipt_refs = plan.receipt_refs.clone();
    let evidence_refs = plan.evidence_refs.clone();
    let stream_cancel_hash = plan.stream_cancel_hash.clone();
    let conversation_hash = plan.conversation_hash.clone();
    let operation = plan.operation.clone();
    let operation_kind = plan.operation_kind.clone();
    let rust_core_boundary = plan.rust_core_boundary.clone();
    Ok(json!({
        "source": "rust_daemon_core.model_mount.stream_cancel",
        "plan": plan,
        "record_dir": record_dir,
        "record_id": record_id,
        "record": record,
        "receipt": receipt,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "stream_cancel_hash": stream_cancel_hash,
        "conversation_hash": conversation_hash,
        "operation": operation,
        "operation_kind": operation_kind,
        "rust_core_boundary": rust_core_boundary,
    }))
}

pub(super) fn plan_conversation_state(
    request: &ModelMountConversationStateRequest,
) -> Result<ModelMountConversationStatePlan, ModelMountError> {
    request.validate()?;
    let receipt_refs = receipt_refs_for_conversation(request)?;
    let evidence_refs = conversation_evidence_refs();
    let source = source_for(
        request.source.as_ref(),
        "rust_daemon_core.model_mount.conversation_state",
    );
    let input_hash = text_hash(request.input_text.as_deref())?;
    let output_hash = text_hash(request.output_text.as_deref())?;
    let record_id = trimmed_string(&request.response_id, "response_id")?;
    let root_response_id = request
        .root_response_id
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .or_else(|| {
            request
                .previous_response_id
                .as_ref()
                .and_then(|value| non_empty_string(value))
        })
        .unwrap_or_else(|| record_id.clone());
    let message_count = request
        .previous_message_count
        .unwrap_or(0)
        .saturating_add(1);
    let generated_at = generated_at_for(request.generated_at.as_ref());
    let conversation_hash = conversation_state_hash(json!({
        "operation": request.operation,
        "response_id": request.response_id,
        "previous_response_id": request.previous_response_id,
        "root_response_id": root_response_id,
        "message_count": message_count,
        "kind": request.kind,
        "status": request.status,
        "route_ref": request.route_ref,
        "endpoint_ref": request.endpoint_ref,
        "provider_ref": request.provider_ref,
        "model_ref": request.model_ref,
        "instance_ref": request.instance_ref,
        "route_decision_ref": request.route_decision_ref,
        "receipt_refs": receipt_refs,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "token_count": request.token_count,
        "continuation_safety": request.continuation_safety,
    }))?;
    let record = json!({
        "id": record_id,
        "object": "ioi.model_mount_conversation_state",
        "status": request.status,
        "kind": request.kind,
        "response_id": request.response_id,
        "previous_response_id": request.previous_response_id,
        "root_response_id": root_response_id,
        "message_count": message_count,
        "route_id": request.route_ref,
        "endpoint_id": request.endpoint_ref,
        "provider_id": request.provider_ref,
        "selected_model": request.model_ref,
        "instance_id": request.instance_ref,
        "route_decision_ref": request.route_decision_ref,
        "route_receipt_ref": request.route_receipt_ref,
        "receipt_id": request.invocation_receipt_ref,
        "invocation_receipt_ref": request.invocation_receipt_ref,
        "stream_receipt_ref": request.stream_receipt_ref,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "token_count": request.token_count,
        "continuation": request.continuation_safety,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "rust_core_boundary": "model_mount.conversation",
        "source": source,
        "conversation_hash": conversation_hash,
        "created_at": generated_at,
        "updated_at": generated_at,
    });
    Ok(ModelMountConversationStatePlan {
        schema_version: MODEL_MOUNT_CONVERSATION_STATE_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_conversation_state_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.conversation".to_string(),
        operation: request.operation.clone(),
        operation_kind: "model_mount.conversation.state_write".to_string(),
        source,
        record_dir: "model-conversations".to_string(),
        record_id,
        record,
        receipt_refs,
        evidence_refs,
        conversation_hash,
    })
}

pub(super) fn plan_stream_completion(
    request: &ModelMountStreamCompletionRequest,
) -> Result<ModelMountStreamCompletionPlan, ModelMountError> {
    request.validate()?;
    let receipt_refs = receipt_refs_for_stream(request);
    let evidence_refs = stream_completion_evidence_refs();
    let source = source_for(
        request.source.as_ref(),
        "rust_daemon_core.model_mount.stream_completion",
    );
    let input_hash = text_hash(request.input_text.as_deref())?;
    let output_hash = text_hash(request.output_text.as_deref())?;
    let receipt_ref = receipt_ref(&request.receipt_id);
    let transition =
        plan_accepted_receipt_transition(&ModelMountAcceptedReceiptTransitionRequest {
            schema_version: MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION.to_string(),
            current_sequence: request.current_sequence,
            current_head_ref: request.current_head_ref.clone(),
            current_state_root: request.current_state_root.clone(),
            receipt_id: request.receipt_id.clone(),
            receipt_kind: "model_invocation_stream_completed".to_string(),
            route_decision_ref: Some(request.route_decision_ref.clone()),
            invocation_admission_ref: Some(request.invocation_receipt_ref.clone()),
            invocation_admission_hash: None,
            input_hash: Some(input_hash.clone()),
            output_hash: Some(output_hash.clone()),
        })?;
    let root_response_id = request
        .root_response_id
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .or_else(|| {
            request
                .previous_response_id
                .as_ref()
                .and_then(|value| non_empty_string(value))
        })
        .unwrap_or_else(|| request.response_id.clone());
    let message_count = request
        .previous_message_count
        .unwrap_or(0)
        .saturating_add(1);
    let generated_at = generated_at_for(request.generated_at.as_ref());
    let stream_completion_hash = conversation_state_hash(json!({
        "operation": request.operation,
        "response_id": request.response_id,
        "receipt_id": request.receipt_id,
        "invocation_receipt_ref": request.invocation_receipt_ref,
        "route_decision_ref": request.route_decision_ref,
        "chunks_forwarded": request.chunks_forwarded,
        "finish_reason": request.finish_reason,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "transition": transition,
        "provider_usage": request.provider_usage,
        "provider_result": request.provider_result,
        "provider_stream_shape_summary": request.provider_stream_shape_summary,
    }))?;
    let conversation_hash = conversation_state_hash(json!({
        "operation": "model_conversation_state_write",
        "response_id": request.response_id,
        "previous_response_id": request.previous_response_id,
        "root_response_id": root_response_id,
        "message_count": message_count,
        "kind": request.kind,
        "status": "completed",
        "route_ref": request.route_ref,
        "endpoint_ref": request.endpoint_ref,
        "provider_ref": request.provider_ref,
        "model_ref": request.model_ref,
        "instance_ref": request.instance_ref,
        "route_decision_ref": request.route_decision_ref,
        "receipt_refs": receipt_refs,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "token_count": token_count_for_stream(request),
        "stream_completion_hash": stream_completion_hash,
    }))?;
    let record_id = request.response_id.clone();
    let record = json!({
        "id": record_id,
        "object": "ioi.model_mount_conversation_state",
        "status": "completed",
        "kind": request.kind,
        "stream_kind": request.stream_kind,
        "response_id": request.response_id,
        "previous_response_id": request.previous_response_id,
        "root_response_id": root_response_id,
        "message_count": message_count,
        "route_id": request.route_ref,
        "endpoint_id": request.endpoint_ref,
        "provider_id": request.provider_ref,
        "selected_model": request.model_ref,
        "instance_id": request.instance_ref,
        "route_decision_ref": request.route_decision_ref,
        "route_receipt_ref": request.route_receipt_ref,
        "receipt_id": request.invocation_receipt_ref,
        "invocation_receipt_ref": request.invocation_receipt_ref,
        "stream_receipt_ref": receipt_ref,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "token_count": token_count_for_stream(request),
        "provider_usage": request.provider_usage,
        "chunks_forwarded": request.chunks_forwarded,
        "finish_reason": request.finish_reason,
        "provider_response_kind": request.provider_response_kind,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "rust_core_boundary": "model_mount.conversation",
        "source": source,
        "conversation_hash": conversation_hash,
        "stream_completion_hash": stream_completion_hash,
        "created_at": generated_at,
        "updated_at": generated_at,
    });
    let receipt = stream_completion_receipt(
        request,
        &transition,
        &receipt_ref,
        &receipt_refs,
        &evidence_refs,
        &input_hash,
        &output_hash,
        &stream_completion_hash,
        &conversation_hash,
        &generated_at,
    )?;
    Ok(ModelMountStreamCompletionPlan {
        schema_version: MODEL_MOUNT_STREAM_COMPLETION_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_stream_completion_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.conversation".to_string(),
        operation: request.operation.clone(),
        operation_kind: "model_mount.conversation.stream_completion".to_string(),
        source,
        record_dir: "model-conversations".to_string(),
        record_id,
        record,
        receipt,
        receipt_refs,
        evidence_refs,
        stream_completion_hash,
        conversation_hash,
    })
}

pub(super) fn plan_stream_cancel(
    request: &ModelMountStreamCancelRequest,
) -> Result<ModelMountStreamCancelPlan, ModelMountError> {
    request.validate()?;
    let receipt_refs = receipt_refs_for_cancel(request);
    let evidence_refs = stream_cancel_evidence_refs();
    let source = source_for(
        request.source.as_ref(),
        "rust_daemon_core.model_mount.stream_cancel",
    );
    let input_hash = text_hash(request.input_text.as_deref())?;
    let output_hash = text_hash(request.output_text.as_deref())?;
    let receipt_ref = receipt_ref(&request.receipt_id);
    let transition =
        plan_accepted_receipt_transition(&ModelMountAcceptedReceiptTransitionRequest {
            schema_version: MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION.to_string(),
            current_sequence: request.current_sequence,
            current_head_ref: request.current_head_ref.clone(),
            current_state_root: request.current_state_root.clone(),
            receipt_id: request.receipt_id.clone(),
            receipt_kind: "model_invocation_stream_canceled".to_string(),
            route_decision_ref: Some(request.route_decision_ref.clone()),
            invocation_admission_ref: Some(request.invocation_receipt_ref.clone()),
            invocation_admission_hash: None,
            input_hash: Some(input_hash.clone()),
            output_hash: Some(output_hash.clone()),
        })?;
    let root_response_id = request
        .root_response_id
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .or_else(|| {
            request
                .previous_response_id
                .as_ref()
                .and_then(|value| non_empty_string(value))
        })
        .unwrap_or_else(|| request.response_id.clone());
    let message_count = request
        .previous_message_count
        .unwrap_or(0)
        .saturating_add(1);
    let generated_at = generated_at_for(request.generated_at.as_ref());
    let stream_cancel_hash = conversation_state_hash(json!({
        "operation": request.operation,
        "response_id": request.response_id,
        "receipt_id": request.receipt_id,
        "invocation_receipt_ref": request.invocation_receipt_ref,
        "route_decision_ref": request.route_decision_ref,
        "frames_written": request.frames_written,
        "cancel_reason": request.cancel_reason,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "transition": transition,
        "provider_usage": request.provider_usage,
        "provider_result": request.provider_result,
        "provider_stream_shape_summary": request.provider_stream_shape_summary,
    }))?;
    let conversation_hash = conversation_state_hash(json!({
        "operation": "model_conversation_state_write",
        "response_id": request.response_id,
        "previous_response_id": request.previous_response_id,
        "root_response_id": root_response_id,
        "message_count": message_count,
        "kind": request.kind,
        "status": "canceled",
        "route_ref": request.route_ref,
        "endpoint_ref": request.endpoint_ref,
        "provider_ref": request.provider_ref,
        "model_ref": request.model_ref,
        "instance_ref": request.instance_ref,
        "route_decision_ref": request.route_decision_ref,
        "receipt_refs": receipt_refs,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "token_count": token_count_for_cancel(request),
        "stream_cancel_hash": stream_cancel_hash,
    }))?;
    let record_id = request.response_id.clone();
    let record = json!({
        "id": record_id,
        "object": "ioi.model_mount_conversation_state",
        "status": "canceled",
        "kind": request.kind,
        "stream_kind": request.stream_kind,
        "response_id": request.response_id,
        "previous_response_id": request.previous_response_id,
        "root_response_id": root_response_id,
        "message_count": message_count,
        "route_id": request.route_ref,
        "endpoint_id": request.endpoint_ref,
        "provider_id": request.provider_ref,
        "selected_model": request.model_ref,
        "instance_id": request.instance_ref,
        "route_decision_ref": request.route_decision_ref,
        "route_receipt_ref": request.route_receipt_ref,
        "receipt_id": request.invocation_receipt_ref,
        "invocation_receipt_ref": request.invocation_receipt_ref,
        "stream_receipt_ref": receipt_ref,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "token_count": token_count_for_cancel(request),
        "provider_usage": request.provider_usage,
        "frames_written": request.frames_written,
        "cancel_reason": cancel_reason_for(request),
        "stream_source": stream_source_for(request),
        "provider_response_kind": request.provider_response_kind,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "rust_core_boundary": "model_mount.conversation",
        "source": source,
        "conversation_hash": conversation_hash,
        "stream_cancel_hash": stream_cancel_hash,
        "created_at": generated_at,
        "updated_at": generated_at,
    });
    let receipt = stream_cancel_receipt(
        request,
        &transition,
        &receipt_ref,
        &receipt_refs,
        &evidence_refs,
        &input_hash,
        &output_hash,
        &stream_cancel_hash,
        &conversation_hash,
        &generated_at,
    )?;
    Ok(ModelMountStreamCancelPlan {
        schema_version: MODEL_MOUNT_STREAM_CANCEL_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_stream_cancel_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.conversation".to_string(),
        operation: request.operation.clone(),
        operation_kind: "model_mount.conversation.stream_cancel".to_string(),
        source,
        record_dir: "model-conversations".to_string(),
        record_id,
        record,
        receipt,
        receipt_refs,
        evidence_refs,
        stream_cancel_hash,
        conversation_hash,
    })
}

fn stream_cancel_receipt(
    request: &ModelMountStreamCancelRequest,
    transition: &super::accepted_receipt::ModelMountAcceptedReceiptTransition,
    receipt_ref: &str,
    receipt_refs: &[String],
    evidence_refs: &[String],
    input_hash: &str,
    output_hash: &str,
    stream_cancel_hash: &str,
    conversation_hash: &str,
    generated_at: &str,
) -> Result<Value, ModelMountError> {
    let receipt_binding_ref = prefixed_hash(
        "receipt_binding",
        json!({
            "receipt_ref": receipt_ref,
            "operation_ref": transition.operation_ref,
            "response_id": request.response_id,
            "stream_cancel_hash": stream_cancel_hash,
        }),
    )?;
    let accepted_receipt_append_hash = prefixed_hash(
        "accepted_receipt_append",
        json!({
            "receipt_ref": receipt_ref,
            "receipt_binding_ref": receipt_binding_ref,
            "operation_ref": transition.operation_ref,
            "state_root_after": transition.state_root_after,
        }),
    )?;
    let agentgres_admission_hash = prefixed_hash(
        "agentgres_admission",
        json!({
            "operation_ref": transition.operation_ref,
            "expected_heads": transition.expected_heads,
            "state_root_before": transition.state_root_before,
            "state_root_after": transition.state_root_after,
            "resulting_head": transition.resulting_head,
        }),
    )?;
    let step_module_invocation = json!({
        "schema_version": "ioi.step_module.invocation.v1",
        "invocation_id": format!("model-stream-cancel://{}", request.receipt_id),
        "backend": "model_mount",
        "operation": request.operation,
        "input": {
            "state_root_before": transition.state_root_before,
            "response_id": request.response_id,
            "route_ref": request.route_ref,
            "endpoint_ref": request.endpoint_ref,
            "provider_ref": request.provider_ref,
            "model_ref": request.model_ref,
            "route_decision_ref": request.route_decision_ref,
            "invocation_receipt_ref": request.invocation_receipt_ref,
            "receipt_ref": receipt_ref,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "frames_written": request.frames_written,
            "cancel_reason": cancel_reason_for(request),
        },
    });
    let step_module_result = json!({
        "schema_version": "ioi.step_module.result.v1",
        "status": "accepted",
        "agentgres_operation_refs": [transition.operation_ref],
        "receipt_refs": receipt_refs,
        "state_root_after": transition.state_root_after,
        "resulting_head": transition.resulting_head,
        "projection_watermark": transition.projection_watermark,
        "stream_cancel_hash": stream_cancel_hash,
    });
    let receipt_binding = json!({
        "schema_version": "ioi.step_module_receipt_binding.v1",
        "receipt_ref": receipt_ref,
        "binding_hash": receipt_binding_ref,
        "receipt_refs": receipt_refs,
    });
    let accepted_receipt_append = json!({
        "schema_version": "ioi.accepted_receipt_append.v1",
        "receipt_ref": receipt_ref,
        "receipt_binding_ref": receipt_binding_ref,
        "append_hash": accepted_receipt_append_hash,
    });
    let agentgres_admission = json!({
        "schema_version": "ioi.agentgres_admission.v1",
        "operation_ref": transition.operation_ref,
        "expected_heads": transition.expected_heads,
        "state_root_before": transition.state_root_before,
        "state_root_after": transition.state_root_after,
        "resulting_head": transition.resulting_head,
        "admission_hash": agentgres_admission_hash,
    });
    let details = json!({
        "rust_daemon_core_receipt_author": "ModelMountCore.plan_model_mount_stream_cancel",
        "invocation_kind": "model_mount.invocation.stream_canceled",
        "stream_status": "canceled",
        "stream_source": stream_source_for(request),
        "response_id": request.response_id,
        "previous_response_id": request.previous_response_id,
        "route_id": request.route_ref,
        "route_receipt_id": request.route_receipt_ref,
        "selected_model": request.model_ref,
        "endpoint_id": request.endpoint_ref,
        "provider_id": request.provider_ref,
        "instance_id": request.instance_ref,
        "receipt_id": request.invocation_receipt_ref,
        "stream_receipt_ref": receipt_ref,
        "model_mount_route_decision_ref": request.route_decision_ref,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "token_count": token_count_for_cancel(request),
        "provider_usage": request.provider_usage,
        "provider_response_kind": request.provider_response_kind,
        "frames_written": request.frames_written,
        "cancel_reason": cancel_reason_for(request),
        "provider_stream_shape_summary": request.provider_stream_shape_summary,
        "model_mount_stream_cancel_hash": stream_cancel_hash,
        "model_mount_conversation_state_hash": conversation_hash,
        "model_mount_receipt_binding_ref": receipt_binding_ref,
        "model_mount_receipt_binding": receipt_binding,
        "model_mount_accepted_receipt_append_hash": accepted_receipt_append_hash,
        "model_mount_accepted_receipt_append": accepted_receipt_append,
        "model_mount_agentgres_operation_ref": transition.operation_ref,
        "model_mount_agentgres_admission_hash": agentgres_admission_hash,
        "model_mount_agentgres_admission": agentgres_admission,
        "model_mount_agentgres_state_root_before": transition.state_root_before,
        "model_mount_agentgres_state_root_after": transition.state_root_after,
        "model_mount_agentgres_resulting_head": transition.resulting_head,
        "model_mount_step_module_invocation": step_module_invocation,
        "model_mount_step_module_result": step_module_result,
        "model_mount_accepted_receipt_transition": transition,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
    });
    Ok(json!({
        "id": request.receipt_id,
        "runId": Value::Null,
        "kind": "model_invocation_stream_canceled",
        "summary": format!(
            "{} stream canceled through {} to {}.",
            request.stream_kind, request.route_ref, request.model_ref
        ),
        "redaction": "redacted",
        "evidenceRefs": cancel_receipt_evidence_refs(request, evidence_refs, &receipt_binding_ref, &accepted_receipt_append_hash),
        "createdAt": generated_at,
        "schemaVersion": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
        "details": details,
    }))
}

fn stream_completion_receipt(
    request: &ModelMountStreamCompletionRequest,
    transition: &super::accepted_receipt::ModelMountAcceptedReceiptTransition,
    receipt_ref: &str,
    receipt_refs: &[String],
    evidence_refs: &[String],
    input_hash: &str,
    output_hash: &str,
    stream_completion_hash: &str,
    conversation_hash: &str,
    generated_at: &str,
) -> Result<Value, ModelMountError> {
    let receipt_binding_ref = prefixed_hash(
        "receipt_binding",
        json!({
            "receipt_ref": receipt_ref,
            "operation_ref": transition.operation_ref,
            "response_id": request.response_id,
            "stream_completion_hash": stream_completion_hash,
        }),
    )?;
    let accepted_receipt_append_hash = prefixed_hash(
        "accepted_receipt_append",
        json!({
            "receipt_ref": receipt_ref,
            "receipt_binding_ref": receipt_binding_ref,
            "operation_ref": transition.operation_ref,
            "state_root_after": transition.state_root_after,
        }),
    )?;
    let agentgres_admission_hash = prefixed_hash(
        "agentgres_admission",
        json!({
            "operation_ref": transition.operation_ref,
            "expected_heads": transition.expected_heads,
            "state_root_before": transition.state_root_before,
            "state_root_after": transition.state_root_after,
            "resulting_head": transition.resulting_head,
        }),
    )?;
    let step_module_invocation = json!({
        "schema_version": "ioi.step_module.invocation.v1",
        "invocation_id": format!("model-stream-completion://{}", request.receipt_id),
        "backend": "model_mount",
        "operation": request.operation,
        "input": {
            "state_root_before": transition.state_root_before,
            "response_id": request.response_id,
            "route_ref": request.route_ref,
            "endpoint_ref": request.endpoint_ref,
            "provider_ref": request.provider_ref,
            "model_ref": request.model_ref,
            "route_decision_ref": request.route_decision_ref,
            "invocation_receipt_ref": request.invocation_receipt_ref,
            "receipt_ref": receipt_ref,
            "input_hash": input_hash,
            "output_hash": output_hash,
        },
    });
    let step_module_result = json!({
        "schema_version": "ioi.step_module.result.v1",
        "status": "accepted",
        "agentgres_operation_refs": [transition.operation_ref],
        "receipt_refs": receipt_refs,
        "state_root_after": transition.state_root_after,
        "resulting_head": transition.resulting_head,
        "projection_watermark": transition.projection_watermark,
        "stream_completion_hash": stream_completion_hash,
    });
    let receipt_binding = json!({
        "schema_version": "ioi.step_module_receipt_binding.v1",
        "receipt_ref": receipt_ref,
        "binding_hash": receipt_binding_ref,
        "receipt_refs": receipt_refs,
    });
    let accepted_receipt_append = json!({
        "schema_version": "ioi.accepted_receipt_append.v1",
        "receipt_ref": receipt_ref,
        "receipt_binding_ref": receipt_binding_ref,
        "append_hash": accepted_receipt_append_hash,
    });
    let agentgres_admission = json!({
        "schema_version": "ioi.agentgres_admission.v1",
        "operation_ref": transition.operation_ref,
        "expected_heads": transition.expected_heads,
        "state_root_before": transition.state_root_before,
        "state_root_after": transition.state_root_after,
        "resulting_head": transition.resulting_head,
        "admission_hash": agentgres_admission_hash,
    });
    let details = json!({
        "rust_daemon_core_receipt_author": "ModelMountCore.plan_model_mount_stream_completion",
        "invocation_kind": "model_mount.invocation.stream_completed",
        "stream_status": "completed",
        "stream_source": "provider_native",
        "response_id": request.response_id,
        "previous_response_id": request.previous_response_id,
        "route_id": request.route_ref,
        "route_receipt_id": request.route_receipt_ref,
        "selected_model": request.model_ref,
        "endpoint_id": request.endpoint_ref,
        "provider_id": request.provider_ref,
        "instance_id": request.instance_ref,
        "receipt_id": request.invocation_receipt_ref,
        "stream_receipt_ref": receipt_ref,
        "model_mount_route_decision_ref": request.route_decision_ref,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "token_count": token_count_for_stream(request),
        "provider_usage": request.provider_usage,
        "provider_response_kind": request.provider_response_kind,
        "chunks_forwarded": request.chunks_forwarded,
        "finish_reason": request.finish_reason,
        "provider_stream_shape_summary": request.provider_stream_shape_summary,
        "model_mount_stream_completion_hash": stream_completion_hash,
        "model_mount_conversation_state_hash": conversation_hash,
        "model_mount_receipt_binding_ref": receipt_binding_ref,
        "model_mount_receipt_binding": receipt_binding,
        "model_mount_accepted_receipt_append_hash": accepted_receipt_append_hash,
        "model_mount_accepted_receipt_append": accepted_receipt_append,
        "model_mount_agentgres_operation_ref": transition.operation_ref,
        "model_mount_agentgres_admission_hash": agentgres_admission_hash,
        "model_mount_agentgres_admission": agentgres_admission,
        "model_mount_agentgres_state_root_before": transition.state_root_before,
        "model_mount_agentgres_state_root_after": transition.state_root_after,
        "model_mount_agentgres_resulting_head": transition.resulting_head,
        "model_mount_step_module_invocation": step_module_invocation,
        "model_mount_step_module_result": step_module_result,
        "model_mount_accepted_receipt_transition": transition,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
    });
    Ok(json!({
        "id": request.receipt_id,
        "runId": Value::Null,
        "kind": "model_invocation_stream_completed",
        "summary": format!(
            "{} stream completed through {} to {}.",
            request.stream_kind, request.route_ref, request.model_ref
        ),
        "redaction": "redacted",
        "evidenceRefs": receipt_evidence_refs(request, evidence_refs, &receipt_binding_ref, &accepted_receipt_append_hash),
        "createdAt": generated_at,
        "schemaVersion": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
        "details": details,
    }))
}

fn receipt_refs_for_conversation(
    request: &ModelMountConversationStateRequest,
) -> Result<Vec<String>, ModelMountError> {
    let mut refs = Vec::new();
    for value in &request.receipt_refs {
        push_unique_ref(&mut refs, value);
    }
    for value in [
        request.route_receipt_ref.as_deref(),
        request.invocation_receipt_ref.as_deref(),
        request.stream_receipt_ref.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        push_unique_ref(&mut refs, value);
    }
    Ok(refs)
}

fn receipt_refs_for_stream(request: &ModelMountStreamCompletionRequest) -> Vec<String> {
    let mut refs = Vec::new();
    for value in &request.receipt_refs {
        push_unique_ref(&mut refs, value);
    }
    push_unique_ref(&mut refs, &request.invocation_receipt_ref);
    if let Some(route_receipt_ref) = request.route_receipt_ref.as_deref() {
        push_unique_ref(&mut refs, route_receipt_ref);
    }
    push_unique_ref(&mut refs, &receipt_ref(&request.receipt_id));
    refs
}

fn receipt_refs_for_cancel(request: &ModelMountStreamCancelRequest) -> Vec<String> {
    let mut refs = Vec::new();
    for value in &request.receipt_refs {
        push_unique_ref(&mut refs, value);
    }
    push_unique_ref(&mut refs, &request.invocation_receipt_ref);
    if let Some(route_receipt_ref) = request.route_receipt_ref.as_deref() {
        push_unique_ref(&mut refs, route_receipt_ref);
    }
    push_unique_ref(&mut refs, &receipt_ref(&request.receipt_id));
    refs
}

fn token_count_for_stream(request: &ModelMountStreamCompletionRequest) -> Value {
    if !request.provider_usage.is_null() {
        request.provider_usage.clone()
    } else {
        request.token_count.clone()
    }
}

fn token_count_for_cancel(request: &ModelMountStreamCancelRequest) -> Value {
    if !request.provider_usage.is_null() {
        request.provider_usage.clone()
    } else {
        request.token_count.clone()
    }
}

fn cancel_reason_for(request: &ModelMountStreamCancelRequest) -> String {
    request
        .cancel_reason
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "client_disconnect".to_string())
}

fn stream_source_for(request: &ModelMountStreamCancelRequest) -> String {
    request
        .stream_source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "provider_native".to_string())
}

fn require_option(field: &'static str, value: &Option<String>) -> Result<(), ModelMountError> {
    value
        .as_ref()
        .ok_or(ModelMountError::MissingField(field))
        .and_then(|value| require_non_empty(field, value))
}

fn source_for(value: Option<&String>, fallback: &str) -> String {
    value
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| fallback.to_string())
}

fn generated_at_for(value: Option<&String>) -> String {
    value
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string())
}

fn text_hash(value: Option<&str>) -> Result<String, ModelMountError> {
    let value = value.unwrap_or_default();
    Ok(format!("sha256:{}", sha256_hex(value.as_bytes())?))
}

fn conversation_state_hash(value: Value) -> Result<String, ModelMountError> {
    let bytes = serde_json::to_vec(&value)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", sha256_hex(&bytes)?))
}

fn prefixed_hash(prefix: &str, value: Value) -> Result<String, ModelMountError> {
    let hash = conversation_state_hash(json!({
        "prefix": prefix,
        "value": value,
    }))?;
    Ok(format!("{prefix}:{}", hash.trim_start_matches("sha256:")))
}

fn receipt_ref(receipt_id: &str) -> String {
    if receipt_id.contains("://") {
        receipt_id.to_string()
    } else {
        format!("receipt://{receipt_id}")
    }
}

fn conversation_evidence_refs() -> Vec<String> {
    vec![
        "model_mount_conversation_state_rust_owned".to_string(),
        "rust_daemon_core_model_conversation_state".to_string(),
        "agentgres_model_conversation_truth_required".to_string(),
    ]
}

fn stream_completion_evidence_refs() -> Vec<String> {
    vec![
        "model_mount_stream_completion_rust_owned".to_string(),
        "rust_daemon_core_model_stream_completion".to_string(),
        "rust_model_mount_core".to_string(),
        "agentgres_model_conversation_truth_required".to_string(),
    ]
}

fn stream_cancel_evidence_refs() -> Vec<String> {
    vec![
        "model_mount_stream_cancel_rust_owned".to_string(),
        "rust_daemon_core_model_stream_cancel".to_string(),
        "agentgres_model_stream_cancel_truth_required".to_string(),
        "rust_model_mount_core".to_string(),
        "agentgres_model_conversation_truth_required".to_string(),
    ]
}

fn receipt_evidence_refs(
    request: &ModelMountStreamCompletionRequest,
    evidence_refs: &[String],
    receipt_binding_ref: &str,
    accepted_receipt_append_hash: &str,
) -> Vec<String> {
    let mut refs = vec![
        "model_router".to_string(),
        "rust_model_mount_core".to_string(),
        "model_mount_stream_completion_rust_owned".to_string(),
        "rust_daemon_core_model_stream_completion".to_string(),
        "rust_daemon_core_model_invocation_receipt".to_string(),
        "agentgres_model_conversation_truth_required".to_string(),
        request.route_decision_ref.clone(),
        request.invocation_receipt_ref.clone(),
        receipt_binding_ref.to_string(),
        accepted_receipt_append_hash.to_string(),
    ];
    for value in evidence_refs {
        push_unique_ref(&mut refs, value);
    }
    refs
}

fn cancel_receipt_evidence_refs(
    request: &ModelMountStreamCancelRequest,
    evidence_refs: &[String],
    receipt_binding_ref: &str,
    accepted_receipt_append_hash: &str,
) -> Vec<String> {
    let mut refs = vec![
        "model_router".to_string(),
        "rust_model_mount_core".to_string(),
        "model_mount_stream_cancel_rust_owned".to_string(),
        "rust_daemon_core_model_stream_cancel".to_string(),
        "rust_daemon_core_model_invocation_receipt".to_string(),
        "agentgres_model_stream_cancel_truth_required".to_string(),
        "agentgres_model_conversation_truth_required".to_string(),
        request.route_decision_ref.clone(),
        request.invocation_receipt_ref.clone(),
        receipt_binding_ref.to_string(),
        accepted_receipt_append_hash.to_string(),
    ];
    for value in evidence_refs {
        push_unique_ref(&mut refs, value);
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conversation_request() -> ModelMountConversationStateRequest {
        ModelMountConversationStateRequest {
            schema_version: MODEL_MOUNT_CONVERSATION_STATE_SCHEMA_VERSION.to_string(),
            operation: "model_conversation_state_write".to_string(),
            response_id: "resp.current".to_string(),
            previous_response_id: Some("resp.previous".to_string()),
            root_response_id: Some("resp.root".to_string()),
            previous_message_count: Some(4),
            kind: "responses".to_string(),
            status: "completed".to_string(),
            source: Some("runtime-daemon.model_mounting.conversation".to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            route_ref: Some("route.local".to_string()),
            endpoint_ref: Some("endpoint.local".to_string()),
            provider_ref: Some("provider.local".to_string()),
            model_ref: Some("llama-test".to_string()),
            instance_ref: Some("instance.local".to_string()),
            route_decision_ref: Some("model_mount://route_decision/test".to_string()),
            route_receipt_ref: Some("receipt://route".to_string()),
            invocation_receipt_ref: Some("receipt://invocation".to_string()),
            stream_receipt_ref: None,
            input_text: Some("hello".to_string()),
            output_text: Some("world".to_string()),
            token_count: json!({"total_tokens": 2}),
            continuation_safety: json!({"status": "accepted"}),
            receipt_refs: vec![],
        }
    }

    fn stream_request() -> ModelMountStreamCompletionRequest {
        ModelMountStreamCompletionRequest {
            schema_version: MODEL_MOUNT_STREAM_COMPLETION_SCHEMA_VERSION.to_string(),
            operation: "model_stream_completion".to_string(),
            response_id: "resp.stream".to_string(),
            previous_response_id: None,
            root_response_id: None,
            previous_message_count: None,
            kind: "responses".to_string(),
            stream_kind: "responses".to_string(),
            source: Some("runtime-daemon.model_mounting.stream_completion".to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            receipt_id: "receipt.stream".to_string(),
            current_sequence: 2,
            current_head_ref: "agentgres://model-mounting/accepted-receipts/head/2".to_string(),
            current_state_root: "sha256:state-2".to_string(),
            invocation_receipt_ref: "receipt://invocation".to_string(),
            route_decision_ref: "model_mount://route_decision/test".to_string(),
            route_receipt_ref: Some("receipt://route".to_string()),
            route_ref: "route.local".to_string(),
            endpoint_ref: "endpoint.local".to_string(),
            provider_ref: "provider.local".to_string(),
            model_ref: "llama-test".to_string(),
            instance_ref: Some("instance.local".to_string()),
            input_text: Some("hello".to_string()),
            output_text: Some("streamed world".to_string()),
            token_count: json!({"total_tokens": 3}),
            provider_usage: json!({"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}),
            provider_result: json!({"provider_response_kind": "openai.responses"}),
            provider_stream_shape_summary: json!({"frames_forwarded": 3}),
            chunks_forwarded: 3,
            finish_reason: Some("stop".to_string()),
            provider_response_kind: Some("openai.responses".to_string()),
            receipt_refs: vec![],
        }
    }

    fn stream_cancel_request() -> ModelMountStreamCancelRequest {
        ModelMountStreamCancelRequest {
            schema_version: MODEL_MOUNT_STREAM_CANCEL_SCHEMA_VERSION.to_string(),
            operation: "model_stream_cancel".to_string(),
            response_id: "resp.stream".to_string(),
            previous_response_id: None,
            root_response_id: None,
            previous_message_count: None,
            kind: "responses".to_string(),
            stream_kind: "responses".to_string(),
            source: Some("runtime-daemon.model_mounting.stream_cancel".to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            receipt_id: "receipt.stream-cancel".to_string(),
            current_sequence: 2,
            current_head_ref: "agentgres://model-mounting/accepted-receipts/head/2".to_string(),
            current_state_root: "sha256:state-2".to_string(),
            invocation_receipt_ref: "receipt://invocation".to_string(),
            route_decision_ref: "model_mount://route_decision/test".to_string(),
            route_receipt_ref: Some("receipt://route".to_string()),
            route_ref: "route.local".to_string(),
            endpoint_ref: "endpoint.local".to_string(),
            provider_ref: "provider.local".to_string(),
            model_ref: "llama-test".to_string(),
            instance_ref: Some("instance.local".to_string()),
            input_text: Some("hello".to_string()),
            output_text: Some("partial".to_string()),
            token_count: json!({"total_tokens": 3}),
            provider_usage: json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}),
            provider_result: json!({"provider_response_kind": "openai.responses"}),
            provider_stream_shape_summary: json!({"frames_forwarded": 1}),
            frames_written: 1,
            cancel_reason: Some("client_disconnect".to_string()),
            stream_source: Some("provider_native".to_string()),
            provider_response_kind: Some("openai.responses".to_string()),
            receipt_refs: vec![],
        }
    }

    #[test]
    fn rust_core_plans_model_conversation_state_record() {
        let plan = plan_conversation_state(&conversation_request()).expect("conversation plan");

        assert_eq!(plan.record_dir, "model-conversations");
        assert_eq!(plan.record_id, "resp.current");
        assert_eq!(plan.operation_kind, "model_mount.conversation.state_write");
        assert_eq!(plan.record["route_id"], "route.local");
        assert_eq!(plan.record["selected_model"], "llama-test");
        assert_eq!(plan.record["previous_response_id"], "resp.previous");
        assert_eq!(plan.record["root_response_id"], "resp.root");
        assert_eq!(plan.record["message_count"], 5);
        assert!(plan
            .evidence_refs
            .contains(&"model_mount_conversation_state_rust_owned".to_string()));
    }

    #[test]
    fn rust_core_plans_model_conversation_state_direct_api() {
        let response = plan_model_mount_conversation_state(&conversation_request())
            .expect("conversation state planned");

        assert_eq!(
            response["source"],
            "rust_daemon_core.model_mount.conversation_state"
        );
        assert!(response.get("backend").is_none());
        assert_eq!(response["record_dir"], "model-conversations");
        assert_eq!(response["record_id"], "resp.current");
        assert_eq!(response["rust_core_boundary"], "model_mount.conversation");
        assert_eq!(response["operation"], "model_conversation_state_write");
        assert_eq!(
            response["operation_kind"],
            "model_mount.conversation.state_write"
        );
        assert_eq!(response["record"]["selected_model"], "llama-test");
    }

    #[test]
    fn rust_core_plans_stream_completion_receipt_and_conversation_record() {
        let plan = plan_stream_completion(&stream_request()).expect("stream completion plan");

        assert_eq!(plan.record_dir, "model-conversations");
        assert_eq!(plan.record_id, "resp.stream");
        assert_eq!(
            plan.operation_kind,
            "model_mount.conversation.stream_completion"
        );
        assert_eq!(
            plan.record["stream_receipt_ref"],
            "receipt://receipt.stream"
        );
        assert_eq!(plan.receipt["kind"], "model_invocation_stream_completed");
        assert_eq!(
            plan.receipt["details"]["rust_daemon_core_receipt_author"],
            "ModelMountCore.plan_model_mount_stream_completion"
        );
        assert_eq!(
            plan.receipt["details"]["model_mount_agentgres_operation_ref"],
            plan.receipt["details"]["model_mount_step_module_result"]["agentgres_operation_refs"]
                [0]
        );
        assert_eq!(
            plan.receipt["details"]["model_mount_agentgres_state_root_after"],
            plan.receipt["details"]["model_mount_step_module_result"]["state_root_after"]
        );
        assert!(plan
            .evidence_refs
            .contains(&"model_mount_stream_completion_rust_owned".to_string()));
    }

    #[test]
    fn rust_core_plans_stream_completion_direct_api() {
        let response = plan_model_mount_stream_completion(&stream_request())
            .expect("stream completion planned");

        assert_eq!(
            response["source"],
            "rust_daemon_core.model_mount.stream_completion"
        );
        assert!(response.get("backend").is_none());
        assert_eq!(response["record_dir"], "model-conversations");
        assert_eq!(response["record_id"], "resp.stream");
        assert_eq!(
            response["receipt"]["kind"],
            "model_invocation_stream_completed"
        );
        assert_eq!(response["rust_core_boundary"], "model_mount.conversation");
        assert_eq!(response["operation"], "model_stream_completion");
        assert_eq!(
            response["operation_kind"],
            "model_mount.conversation.stream_completion"
        );
        assert_eq!(
            response["receipt"]["details"]["rust_daemon_core_receipt_author"],
            "ModelMountCore.plan_model_mount_stream_completion"
        );
    }

    #[test]
    fn rust_core_plans_stream_cancel_receipt_and_conversation_record() {
        let plan = plan_stream_cancel(&stream_cancel_request()).expect("stream cancel plan");

        assert_eq!(plan.record_dir, "model-conversations");
        assert_eq!(plan.record_id, "resp.stream");
        assert_eq!(
            plan.operation_kind,
            "model_mount.conversation.stream_cancel"
        );
        assert_eq!(plan.record["status"], "canceled");
        assert_eq!(plan.record["frames_written"], 1);
        assert_eq!(
            plan.record["stream_receipt_ref"],
            "receipt://receipt.stream-cancel"
        );
        assert_eq!(plan.receipt["kind"], "model_invocation_stream_canceled");
        assert_eq!(
            plan.receipt["details"]["rust_daemon_core_receipt_author"],
            "ModelMountCore.plan_model_mount_stream_cancel"
        );
        assert_eq!(
            plan.receipt["details"]["model_mount_agentgres_operation_ref"],
            plan.receipt["details"]["model_mount_step_module_result"]["agentgres_operation_refs"]
                [0]
        );
        assert_eq!(
            plan.receipt["details"]["model_mount_agentgres_state_root_after"],
            plan.receipt["details"]["model_mount_step_module_result"]["state_root_after"]
        );
        assert!(plan
            .evidence_refs
            .contains(&"model_mount_stream_cancel_rust_owned".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"agentgres_model_stream_cancel_truth_required".to_string()));
    }

    #[test]
    fn rust_core_plans_stream_cancel_direct_api() {
        let response = plan_model_mount_stream_cancel(&stream_cancel_request())
            .expect("stream cancel planned");

        assert_eq!(
            response["source"],
            "rust_daemon_core.model_mount.stream_cancel"
        );
        assert!(response.get("backend").is_none());
        assert_eq!(response["record_dir"], "model-conversations");
        assert_eq!(response["record_id"], "resp.stream");
        assert_eq!(response["record"]["status"], "canceled");
        assert_eq!(
            response["receipt"]["kind"],
            "model_invocation_stream_canceled"
        );
        assert_eq!(response["rust_core_boundary"], "model_mount.conversation");
        assert_eq!(response["operation"], "model_stream_cancel");
        assert_eq!(
            response["operation_kind"],
            "model_mount.conversation.stream_cancel"
        );
        assert_eq!(
            response["receipt"]["details"]["rust_daemon_core_receipt_author"],
            "ModelMountCore.plan_model_mount_stream_cancel"
        );
    }
}
