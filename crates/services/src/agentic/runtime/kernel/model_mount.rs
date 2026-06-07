use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION: &str = "ioi.model_mount.route_decision.v1";
pub const MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.model_mount.invocation_admission.v1";
pub const MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION: &str =
    "ioi.model_mount.provider_execution.v1";
pub const MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION: &str =
    "ioi.model_mount.provider_invocation.v1";
pub const MODEL_MOUNT_PROVIDER_STREAM_INVOCATION_SCHEMA_VERSION: &str =
    "ioi.model_mount.provider_stream_invocation.v1";
pub const MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION: &str =
    "ioi.model_mount.provider_lifecycle.v1";
pub const MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION: &str =
    "ioi.model_mount.provider_inventory.v1";
pub const MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION: &str =
    "ioi.model_mount.instance_lifecycle.v1";
pub const MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION: &str = "ioi.model_mount.provider_result.v1";
pub const MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.backend_process_plan.v1";
pub const MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_SCHEMA_VERSION: &str =
    "ioi.model_mount.accepted_receipt_head.v1";
pub const MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION: &str =
    "ioi.model_mount.accepted_receipt_transition.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelMountError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    MissingReceiptRef,
    MissingRouteReceiptRef,
    MissingInvocationReceiptRef,
    MissingProviderExecutionRouteReceiptRef,
    MissingProviderExecutionAdmission,
    ProviderExecutionHashMismatch,
    ProviderExecutionRefMismatch,
    ProviderResultOutputHashMismatch,
    UnsupportedProviderResultBackend,
    UnsupportedProviderInvocationBackend,
    UnsupportedProviderLifecycleAction,
    UnsupportedProviderLifecycleBackend,
    UnsupportedProviderInventoryAction,
    UnsupportedProviderInventoryBackend,
    UnsupportedInstanceLifecycleAction,
    UnsupportedInstanceLifecycleBackend,
    UnsupportedBackendProcessKind,
    InstanceLifecycleStatusMismatch,
    InvalidAcceptedReceiptSequence,
    InvalidAcceptedReceiptTransitionHash,
    StreamProviderInvocationUnsupported,
    UnresolvedAutoModel,
    PrivateWorkspaceMissingCustodyRef,
    PrivateWorkspacePlaintextNotAllowed,
    HashFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountRouteDecisionRequest {
    pub schema_version: String,
    pub route_ref: String,
    pub provider_ref: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub capability: String,
    pub policy_hash: String,
    pub idempotency_key: String,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_profile: Option<String>,
    #[serde(default)]
    pub node_plaintext_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_graph_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_node_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountRouteDecisionRecord {
    pub schema_version: String,
    pub route_decision_ref: String,
    pub route_ref: String,
    pub provider_ref: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub capability: String,
    pub policy_hash: String,
    pub idempotency_key: String,
    pub receipt_refs: Vec<String>,
    pub authority_grant_refs: Vec<String>,
    pub authority_receipt_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_profile: Option<String>,
    pub node_plaintext_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_graph_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_node_ref: Option<String>,
    pub route_decision_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountInvocationAdmissionRequest {
    pub schema_version: String,
    pub invocation_ref: String,
    pub route_decision_ref: String,
    pub route_receipt_ref: String,
    pub invocation_receipt_ref: String,
    pub route_ref: String,
    pub provider_ref: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub capability: String,
    pub invocation_kind: String,
    pub policy_hash: String,
    pub input_hash: String,
    pub output_hash: String,
    pub idempotency_key: String,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
    #[serde(default)]
    pub provider_auth_evidence_refs: Vec<String>,
    #[serde(default)]
    pub backend_evidence_refs: Vec<String>,
    #[serde(default)]
    pub tool_receipt_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_profile: Option<String>,
    #[serde(default)]
    pub node_plaintext_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_graph_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_node_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_response_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountInvocationAdmissionRecord {
    pub schema_version: String,
    pub invocation_admission_ref: String,
    pub invocation_ref: String,
    pub route_decision_ref: String,
    pub route_receipt_ref: String,
    pub invocation_receipt_ref: String,
    pub route_ref: String,
    pub provider_ref: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub capability: String,
    pub invocation_kind: String,
    pub policy_hash: String,
    pub input_hash: String,
    pub output_hash: String,
    pub idempotency_key: String,
    pub receipt_refs: Vec<String>,
    pub authority_grant_refs: Vec<String>,
    pub authority_receipt_refs: Vec<String>,
    pub provider_auth_evidence_refs: Vec<String>,
    pub backend_evidence_refs: Vec<String>,
    pub tool_receipt_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_profile: Option<String>,
    pub node_plaintext_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_graph_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_node_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_response_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_status: Option<String>,
    pub invocation_admission_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderExecutionRequest {
    pub schema_version: String,
    pub invocation_ref: String,
    pub route_decision_ref: String,
    pub route_receipt_ref: String,
    pub route_ref: String,
    pub provider_ref: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub capability: String,
    pub invocation_kind: String,
    pub policy_hash: String,
    pub input_hash: String,
    pub request_hash: String,
    pub idempotency_key: String,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
    #[serde(default)]
    pub provider_auth_evidence_refs: Vec<String>,
    #[serde(default)]
    pub backend_evidence_refs: Vec<String>,
    #[serde(default)]
    pub tool_receipt_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_profile: Option<String>,
    #[serde(default)]
    pub node_plaintext_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_graph_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_node_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_response_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderExecutionRecord {
    pub schema_version: String,
    pub provider_execution_ref: String,
    pub invocation_ref: String,
    pub route_decision_ref: String,
    pub route_receipt_ref: String,
    pub route_ref: String,
    pub provider_ref: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub capability: String,
    pub invocation_kind: String,
    pub policy_hash: String,
    pub input_hash: String,
    pub request_hash: String,
    pub idempotency_key: String,
    pub receipt_refs: Vec<String>,
    pub authority_grant_refs: Vec<String>,
    pub authority_receipt_refs: Vec<String>,
    pub provider_auth_evidence_refs: Vec<String>,
    pub backend_evidence_refs: Vec<String>,
    pub tool_receipt_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_profile: Option<String>,
    pub node_plaintext_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_graph_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_node_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_response_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_status: Option<String>,
    pub provider_execution_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderInvocationRequest {
    pub schema_version: String,
    pub provider_execution_ref: String,
    pub provider_execution_hash: String,
    pub route_decision_ref: String,
    pub route_receipt_ref: String,
    pub route_ref: String,
    pub provider_ref: String,
    pub provider_kind: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub capability: String,
    pub invocation_kind: String,
    pub input: String,
    pub request_hash: String,
    pub execution_backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_status: Option<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitted_provider_execution: Option<ModelMountProviderExecutionRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountTokenCount {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderInvocationResult {
    pub schema_version: String,
    pub provider_execution_ref: String,
    pub provider_execution_hash: String,
    pub route_decision_ref: String,
    pub route_receipt_ref: String,
    pub route_ref: String,
    pub provider_ref: String,
    pub provider_kind: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub capability: String,
    pub invocation_kind: String,
    pub request_hash: String,
    pub output_text: String,
    pub token_count: ModelMountTokenCount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_response_kind: Option<String>,
    pub backend: String,
    pub backend_id: String,
    pub execution_backend: String,
    pub evidence_refs: Vec<String>,
    pub invocation_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderStreamInvocationResult {
    pub schema_version: String,
    pub provider_execution_ref: String,
    pub provider_execution_hash: String,
    pub route_decision_ref: String,
    pub route_receipt_ref: String,
    pub route_ref: String,
    pub provider_ref: String,
    pub provider_kind: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub capability: String,
    pub invocation_kind: String,
    pub request_hash: String,
    pub output_text: String,
    pub token_count: ModelMountTokenCount,
    pub provider_response_kind: String,
    pub backend: String,
    pub backend_id: String,
    pub execution_backend: String,
    pub stream_format: String,
    pub stream_kind: String,
    pub stream_chunks: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub invocation_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderLifecycleRequest {
    pub schema_version: String,
    pub provider_ref: String,
    pub provider_kind: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub action: String,
    pub execution_backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_status: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub process_evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderLifecycleResult {
    pub schema_version: String,
    pub provider_ref: String,
    pub provider_kind: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub action: String,
    pub status: String,
    pub backend: String,
    pub backend_id: String,
    pub driver: String,
    pub execution_backend: String,
    pub evidence_refs: Vec<String>,
    pub lifecycle_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderInventoryRequest {
    pub schema_version: String,
    pub provider_ref: String,
    pub provider_kind: String,
    pub action: String,
    pub execution_backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_status: Option<String>,
    #[serde(default)]
    pub item_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderInventoryResult {
    pub schema_version: String,
    pub provider_ref: String,
    pub provider_kind: String,
    pub action: String,
    pub status: String,
    pub backend: String,
    pub backend_id: String,
    pub driver: String,
    pub execution_backend: String,
    pub item_refs: Vec<String>,
    pub item_count: usize,
    pub evidence_refs: Vec<String>,
    pub inventory_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountInstanceLifecycleRequest {
    pub schema_version: String,
    pub instance_ref: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub provider_ref: String,
    pub action: String,
    pub target_status: String,
    pub execution_backend: String,
    pub backend_ref: String,
    pub driver: String,
    pub provider_lifecycle_hash: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountInstanceLifecycleResult {
    pub schema_version: String,
    pub instance_ref: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub provider_ref: String,
    pub action: String,
    pub status: String,
    pub backend_id: String,
    pub driver: String,
    pub execution_backend: String,
    pub provider_lifecycle_hash: String,
    pub evidence_refs: Vec<String>,
    pub instance_lifecycle_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderResultAdmissionRequest {
    pub schema_version: String,
    pub provider_execution_ref: String,
    pub provider_execution_hash: String,
    pub route_decision_ref: String,
    pub route_receipt_ref: String,
    pub route_ref: String,
    pub provider_ref: String,
    pub provider_kind: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub capability: String,
    pub invocation_kind: String,
    pub request_hash: String,
    pub output_text: String,
    pub output_hash: String,
    pub token_count: ModelMountTokenCount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_response_kind: Option<String>,
    pub execution_backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_status: Option<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub provider_auth_evidence_refs: Vec<String>,
    #[serde(default)]
    pub backend_evidence_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitted_provider_execution: Option<ModelMountProviderExecutionRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountProviderResultAdmissionRecord {
    pub schema_version: String,
    pub provider_result_ref: String,
    pub provider_execution_ref: String,
    pub provider_execution_hash: String,
    pub route_decision_ref: String,
    pub route_receipt_ref: String,
    pub route_ref: String,
    pub provider_ref: String,
    pub provider_kind: String,
    pub endpoint_ref: String,
    pub model_ref: String,
    pub capability: String,
    pub invocation_kind: String,
    pub request_hash: String,
    pub output_hash: String,
    pub token_count: ModelMountTokenCount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_response_kind: Option<String>,
    pub execution_backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_status: Option<String>,
    pub receipt_refs: Vec<String>,
    pub provider_auth_evidence_refs: Vec<String>,
    pub backend_evidence_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub provider_result_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ModelMountBackendProcessLoadOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_model_len: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallel: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tensor_parallel_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtype: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_memory_utilization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default)]
    pub embeddings: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountBackendProcessPlanRequest {
    pub schema_version: String,
    pub backend_ref: String,
    pub backend_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(default)]
    pub binary_configured: bool,
    #[serde(default)]
    pub load_options: ModelMountBackendProcessLoadOptions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountBackendProcessPlan {
    pub schema_version: String,
    pub backend_ref: String,
    pub backend_kind: String,
    pub supports_supervision: bool,
    pub supervisor_kind: String,
    pub public_args: Vec<String>,
    pub spawn_args: Vec<String>,
    pub spawn_required: bool,
    pub spawn_status: String,
    pub evidence_refs: Vec<String>,
    pub plan_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountAcceptedReceiptHeadRequest {
    pub schema_version: String,
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountAcceptedReceiptHead {
    pub schema_version: String,
    pub sequence: u64,
    pub head_ref: String,
    pub state_root: String,
    pub projection_watermark: String,
    pub head_hash: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountAcceptedReceiptTransitionRequest {
    pub schema_version: String,
    pub current_sequence: u64,
    pub current_head_ref: String,
    pub current_state_root: String,
    pub receipt_id: String,
    pub receipt_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_decision_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_admission_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_admission_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountAcceptedReceiptTransition {
    pub schema_version: String,
    pub operation_id: String,
    pub operation_ref: String,
    pub expected_heads: Vec<String>,
    pub state_root_before: String,
    pub state_root_after: String,
    pub resulting_head: String,
    pub projection_watermark: String,
    pub transition_hash: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct ModelMountCore;

impl ModelMountCore {
    pub fn admit_route_decision(
        &self,
        request: &ModelMountRouteDecisionRequest,
    ) -> Result<ModelMountRouteDecisionRecord, ModelMountError> {
        request.validate()?;
        let mut record = ModelMountRouteDecisionRecord {
            schema_version: MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION.to_string(),
            route_decision_ref: String::new(),
            route_ref: request.route_ref.clone(),
            provider_ref: request.provider_ref.clone(),
            endpoint_ref: request.endpoint_ref.clone(),
            model_ref: request.model_ref.clone(),
            capability: request.capability.clone(),
            policy_hash: request.policy_hash.clone(),
            idempotency_key: request.idempotency_key.clone(),
            receipt_refs: request.receipt_refs.clone(),
            authority_grant_refs: request.authority_grant_refs.clone(),
            authority_receipt_refs: request.authority_receipt_refs.clone(),
            custody_ref: request.custody_ref.clone(),
            privacy_profile: request.privacy_profile.clone(),
            node_plaintext_allowed: request.node_plaintext_allowed,
            workflow_graph_ref: request.workflow_graph_ref.clone(),
            workflow_node_ref: request.workflow_node_ref.clone(),
            route_decision_hash: String::new(),
        };
        record.route_decision_hash = route_decision_hash(&record)?;
        record.route_decision_ref = format!(
            "model_mount://route_decision/{}",
            record
                .route_decision_hash
                .trim_start_matches("sha256:")
                .chars()
                .take(24)
                .collect::<String>()
        );
        Ok(record)
    }

    pub fn admit_invocation(
        &self,
        request: &ModelMountInvocationAdmissionRequest,
    ) -> Result<ModelMountInvocationAdmissionRecord, ModelMountError> {
        request.validate()?;
        let mut record = ModelMountInvocationAdmissionRecord {
            schema_version: MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION.to_string(),
            invocation_admission_ref: String::new(),
            invocation_ref: request.invocation_ref.clone(),
            route_decision_ref: request.route_decision_ref.clone(),
            route_receipt_ref: request.route_receipt_ref.clone(),
            invocation_receipt_ref: request.invocation_receipt_ref.clone(),
            route_ref: request.route_ref.clone(),
            provider_ref: request.provider_ref.clone(),
            endpoint_ref: request.endpoint_ref.clone(),
            model_ref: request.model_ref.clone(),
            capability: request.capability.clone(),
            invocation_kind: request.invocation_kind.clone(),
            policy_hash: request.policy_hash.clone(),
            input_hash: request.input_hash.clone(),
            output_hash: request.output_hash.clone(),
            idempotency_key: request.idempotency_key.clone(),
            receipt_refs: request.receipt_refs.clone(),
            authority_grant_refs: request.authority_grant_refs.clone(),
            authority_receipt_refs: request.authority_receipt_refs.clone(),
            provider_auth_evidence_refs: request.provider_auth_evidence_refs.clone(),
            backend_evidence_refs: request.backend_evidence_refs.clone(),
            tool_receipt_refs: request.tool_receipt_refs.clone(),
            custody_ref: request.custody_ref.clone(),
            privacy_profile: request.privacy_profile.clone(),
            node_plaintext_allowed: request.node_plaintext_allowed,
            workflow_graph_ref: request.workflow_graph_ref.clone(),
            workflow_node_ref: request.workflow_node_ref.clone(),
            response_ref: request.response_ref.clone(),
            previous_response_ref: request.previous_response_ref.clone(),
            stream_status: request.stream_status.clone(),
            invocation_admission_hash: String::new(),
        };
        record.invocation_admission_hash = invocation_admission_hash(&record)?;
        record.invocation_admission_ref = format!(
            "model_mount://invocation_admission/{}",
            record
                .invocation_admission_hash
                .trim_start_matches("sha256:")
                .chars()
                .take(24)
                .collect::<String>()
        );
        Ok(record)
    }

    pub fn admit_provider_execution(
        &self,
        request: &ModelMountProviderExecutionRequest,
    ) -> Result<ModelMountProviderExecutionRecord, ModelMountError> {
        request.validate()?;
        let mut record = ModelMountProviderExecutionRecord {
            schema_version: MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION.to_string(),
            provider_execution_ref: String::new(),
            invocation_ref: request.invocation_ref.clone(),
            route_decision_ref: request.route_decision_ref.clone(),
            route_receipt_ref: request.route_receipt_ref.clone(),
            route_ref: request.route_ref.clone(),
            provider_ref: request.provider_ref.clone(),
            endpoint_ref: request.endpoint_ref.clone(),
            model_ref: request.model_ref.clone(),
            capability: request.capability.clone(),
            invocation_kind: request.invocation_kind.clone(),
            policy_hash: request.policy_hash.clone(),
            input_hash: request.input_hash.clone(),
            request_hash: request.request_hash.clone(),
            idempotency_key: request.idempotency_key.clone(),
            receipt_refs: request.receipt_refs.clone(),
            authority_grant_refs: request.authority_grant_refs.clone(),
            authority_receipt_refs: request.authority_receipt_refs.clone(),
            provider_auth_evidence_refs: request.provider_auth_evidence_refs.clone(),
            backend_evidence_refs: request.backend_evidence_refs.clone(),
            tool_receipt_refs: request.tool_receipt_refs.clone(),
            custody_ref: request.custody_ref.clone(),
            privacy_profile: request.privacy_profile.clone(),
            node_plaintext_allowed: request.node_plaintext_allowed,
            workflow_graph_ref: request.workflow_graph_ref.clone(),
            workflow_node_ref: request.workflow_node_ref.clone(),
            response_ref: request.response_ref.clone(),
            previous_response_ref: request.previous_response_ref.clone(),
            stream_status: request.stream_status.clone(),
            provider_execution_hash: String::new(),
        };
        record.provider_execution_hash = provider_execution_hash(&record)?;
        record.provider_execution_ref = format!(
            "model_mount://provider_execution/{}",
            record
                .provider_execution_hash
                .trim_start_matches("sha256:")
                .chars()
                .take(24)
                .collect::<String>()
        );
        Ok(record)
    }

    pub fn invoke_provider(
        &self,
        request: &ModelMountProviderInvocationRequest,
    ) -> Result<ModelMountProviderInvocationResult, ModelMountError> {
        request.validate()?;
        let output_text = deterministic_provider_output(request)?;
        let token_count = estimate_tokens(&request.input, &output_text);
        let backend = provider_invocation_backend(request);
        let backend_id = provider_invocation_backend_id(request);
        let mut result = ModelMountProviderInvocationResult {
            schema_version: MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION.to_string(),
            provider_execution_ref: request.provider_execution_ref.clone(),
            provider_execution_hash: request.provider_execution_hash.clone(),
            route_decision_ref: request.route_decision_ref.clone(),
            route_receipt_ref: request.route_receipt_ref.clone(),
            route_ref: request.route_ref.clone(),
            provider_ref: request.provider_ref.clone(),
            provider_kind: request.provider_kind.clone(),
            endpoint_ref: request.endpoint_ref.clone(),
            model_ref: request.model_ref.clone(),
            capability: request.capability.clone(),
            invocation_kind: request.invocation_kind.clone(),
            request_hash: request.request_hash.clone(),
            output_text,
            token_count,
            provider_response_kind: Some(provider_invocation_response_kind(request)),
            backend,
            backend_id,
            execution_backend: request.execution_backend.clone(),
            evidence_refs: provider_invocation_evidence_refs(request),
            invocation_hash: String::new(),
        };
        result.invocation_hash = provider_invocation_hash(&result)?;
        Ok(result)
    }

    pub fn invoke_provider_stream(
        &self,
        request: &ModelMountProviderInvocationRequest,
    ) -> Result<ModelMountProviderStreamInvocationResult, ModelMountError> {
        request.validate_stream()?;
        let output_text = deterministic_native_local_output(
            &request.invocation_kind,
            &request.input,
            &request.model_ref,
        )?;
        let token_count = estimate_tokens(&request.input, &output_text);
        let stream_chunks = native_local_stream_chunks(&output_text, &token_count)?;
        let mut result = ModelMountProviderStreamInvocationResult {
            schema_version: MODEL_MOUNT_PROVIDER_STREAM_INVOCATION_SCHEMA_VERSION.to_string(),
            provider_execution_ref: request.provider_execution_ref.clone(),
            provider_execution_hash: request.provider_execution_hash.clone(),
            route_decision_ref: request.route_decision_ref.clone(),
            route_receipt_ref: request.route_receipt_ref.clone(),
            route_ref: request.route_ref.clone(),
            provider_ref: request.provider_ref.clone(),
            provider_kind: request.provider_kind.clone(),
            endpoint_ref: request.endpoint_ref.clone(),
            model_ref: request.model_ref.clone(),
            capability: request.capability.clone(),
            invocation_kind: request.invocation_kind.clone(),
            request_hash: request.request_hash.clone(),
            output_text,
            token_count,
            provider_response_kind: "rust_model_mount.native_local.stream".to_string(),
            backend: "autopilot.native_local.fixture".to_string(),
            backend_id: request
                .backend_ref
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("backend.autopilot.native-local.fixture")
                .to_string(),
            execution_backend: request.execution_backend.clone(),
            stream_format: "ioi_jsonl".to_string(),
            stream_kind: native_local_stream_kind(&request.invocation_kind),
            stream_chunks,
            evidence_refs: provider_stream_invocation_evidence_refs(request),
            invocation_hash: String::new(),
        };
        result.invocation_hash = provider_stream_invocation_hash(&result)?;
        Ok(result)
    }

    pub fn plan_provider_lifecycle(
        &self,
        request: &ModelMountProviderLifecycleRequest,
    ) -> Result<ModelMountProviderLifecycleResult, ModelMountError> {
        request.validate()?;
        let mut result = ModelMountProviderLifecycleResult {
            schema_version: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION.to_string(),
            provider_ref: request.provider_ref.clone(),
            provider_kind: request.provider_kind.clone(),
            endpoint_ref: request.endpoint_ref.clone(),
            model_ref: request.model_ref.clone(),
            action: request.action.clone(),
            status: provider_lifecycle_status(request)?,
            backend: provider_lifecycle_backend(request),
            backend_id: provider_lifecycle_backend_id(request),
            driver: provider_lifecycle_driver(request),
            execution_backend: request.execution_backend.clone(),
            evidence_refs: provider_lifecycle_evidence_refs(request),
            lifecycle_hash: String::new(),
        };
        result.lifecycle_hash = provider_lifecycle_hash(&result)?;
        Ok(result)
    }

    pub fn plan_provider_inventory(
        &self,
        request: &ModelMountProviderInventoryRequest,
    ) -> Result<ModelMountProviderInventoryResult, ModelMountError> {
        request.validate()?;
        let mut result = ModelMountProviderInventoryResult {
            schema_version: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION.to_string(),
            provider_ref: request.provider_ref.clone(),
            provider_kind: request.provider_kind.clone(),
            action: request.action.clone(),
            status: "listed".to_string(),
            backend: provider_inventory_backend(request),
            backend_id: provider_inventory_backend_id(request),
            driver: provider_inventory_driver(request),
            execution_backend: request.execution_backend.clone(),
            item_refs: request.item_refs.clone(),
            item_count: request.item_refs.len(),
            evidence_refs: provider_inventory_evidence_refs(request),
            inventory_hash: String::new(),
        };
        result.inventory_hash = provider_inventory_hash(&result)?;
        Ok(result)
    }

    pub fn plan_instance_lifecycle(
        &self,
        request: &ModelMountInstanceLifecycleRequest,
    ) -> Result<ModelMountInstanceLifecycleResult, ModelMountError> {
        request.validate()?;
        let mut result = ModelMountInstanceLifecycleResult {
            schema_version: MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION.to_string(),
            instance_ref: request.instance_ref.clone(),
            endpoint_ref: request.endpoint_ref.clone(),
            model_ref: request.model_ref.clone(),
            provider_ref: request.provider_ref.clone(),
            action: request.action.clone(),
            status: request.target_status.clone(),
            backend_id: request.backend_ref.clone(),
            driver: request.driver.clone(),
            execution_backend: request.execution_backend.clone(),
            provider_lifecycle_hash: request.provider_lifecycle_hash.clone(),
            evidence_refs: instance_lifecycle_evidence_refs(request),
            instance_lifecycle_hash: String::new(),
        };
        result.instance_lifecycle_hash = instance_lifecycle_hash(&result)?;
        Ok(result)
    }

    pub fn admit_provider_result(
        &self,
        request: &ModelMountProviderResultAdmissionRequest,
    ) -> Result<ModelMountProviderResultAdmissionRecord, ModelMountError> {
        request.validate()?;
        let mut record = ModelMountProviderResultAdmissionRecord {
            schema_version: MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION.to_string(),
            provider_result_ref: String::new(),
            provider_execution_ref: request.provider_execution_ref.clone(),
            provider_execution_hash: request.provider_execution_hash.clone(),
            route_decision_ref: request.route_decision_ref.clone(),
            route_receipt_ref: request.route_receipt_ref.clone(),
            route_ref: request.route_ref.clone(),
            provider_ref: request.provider_ref.clone(),
            provider_kind: request.provider_kind.clone(),
            endpoint_ref: request.endpoint_ref.clone(),
            model_ref: request.model_ref.clone(),
            capability: request.capability.clone(),
            invocation_kind: request.invocation_kind.clone(),
            request_hash: request.request_hash.clone(),
            output_hash: request.output_hash.clone(),
            token_count: request.token_count.clone(),
            provider_response_kind: request.provider_response_kind.clone(),
            execution_backend: request.execution_backend.clone(),
            backend_ref: request.backend_ref.clone(),
            stream_status: request.stream_status.clone(),
            receipt_refs: request.receipt_refs.clone(),
            provider_auth_evidence_refs: request.provider_auth_evidence_refs.clone(),
            backend_evidence_refs: request.backend_evidence_refs.clone(),
            evidence_refs: provider_result_evidence_refs(request),
            provider_result_hash: String::new(),
        };
        record.provider_result_hash = provider_result_hash(&record)?;
        record.provider_result_ref = format!(
            "model_mount://provider_result/{}",
            record
                .provider_result_hash
                .trim_start_matches("sha256:")
                .chars()
                .take(24)
                .collect::<String>()
        );
        Ok(record)
    }

    pub fn plan_backend_process(
        &self,
        request: &ModelMountBackendProcessPlanRequest,
    ) -> Result<ModelMountBackendProcessPlan, ModelMountError> {
        request.validate()?;
        let supports_supervision = backend_supports_supervision(&request.backend_kind);
        let mut plan = ModelMountBackendProcessPlan {
            schema_version: MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION.to_string(),
            backend_ref: request.backend_ref.clone(),
            backend_kind: request.backend_kind.clone(),
            supports_supervision,
            supervisor_kind: backend_supervisor_kind(request),
            public_args: backend_process_public_args(request)?,
            spawn_args: backend_process_spawn_args(request)?,
            spawn_required: backend_spawn_required(request, supports_supervision),
            spawn_status: backend_spawn_status(request, supports_supervision),
            evidence_refs: backend_process_evidence_refs(request, supports_supervision),
            plan_hash: String::new(),
        };
        plan.plan_hash = backend_process_plan_hash(&plan)?;
        Ok(plan)
    }

    pub fn plan_accepted_receipt_head(
        &self,
        request: &ModelMountAcceptedReceiptHeadRequest,
    ) -> Result<ModelMountAcceptedReceiptHead, ModelMountError> {
        request.validate()?;
        let mut head = ModelMountAcceptedReceiptHead {
            schema_version: MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_SCHEMA_VERSION.to_string(),
            sequence: request.sequence,
            head_ref: format!(
                "agentgres://model-mounting/accepted-receipts/head/{}",
                request.sequence
            ),
            state_root: model_mount_accepted_receipt_head_state_root(request.sequence)?,
            projection_watermark: format!("model-mounting-accepted-receipts:{}", request.sequence),
            head_hash: String::new(),
            evidence_refs: vec![
                "rust_model_mount_accepted_receipt_head".to_string(),
                "rust_agentgres_receipt_head_planner".to_string(),
            ],
        };
        head.head_hash = accepted_receipt_head_hash(&head)?;
        Ok(head)
    }

    pub fn plan_accepted_receipt_transition(
        &self,
        request: &ModelMountAcceptedReceiptTransitionRequest,
    ) -> Result<ModelMountAcceptedReceiptTransition, ModelMountError> {
        request.validate()?;
        let next_sequence = request
            .current_sequence
            .checked_add(1)
            .ok_or(ModelMountError::InvalidAcceptedReceiptSequence)?;
        let operation_id = format!(
            "op_{:08}_{}",
            next_sequence,
            accepted_receipt_operation_suffix(&request.receipt_kind)
        );
        let operation_ref = format!("agentgres://model-mounting/accepted-receipts/{operation_id}");
        let state_root_after =
            model_mount_accepted_receipt_state_root(request, next_sequence, &operation_ref)?;
        let mut transition = ModelMountAcceptedReceiptTransition {
            schema_version: MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION.to_string(),
            operation_id,
            operation_ref,
            expected_heads: vec![request.current_head_ref.clone()],
            state_root_before: request.current_state_root.clone(),
            state_root_after,
            resulting_head: format!(
                "agentgres://model-mounting/accepted-receipts/head/{next_sequence}"
            ),
            projection_watermark: format!("model-mounting-accepted-receipts:{next_sequence}"),
            transition_hash: String::new(),
            evidence_refs: vec![
                "rust_model_mount_accepted_receipt_transition".to_string(),
                "rust_agentgres_receipt_state_root_planner".to_string(),
            ],
        };
        transition.transition_hash = accepted_receipt_transition_hash(&transition)?;
        Ok(transition)
    }

    pub fn validate_accepted_receipt_transition(
        &self,
        transition: &ModelMountAcceptedReceiptTransition,
    ) -> Result<(), ModelMountError> {
        if transition.schema_version != MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION,
                actual: transition.schema_version.clone(),
            });
        }
        if transition.operation_ref.trim().is_empty() {
            return Err(ModelMountError::MissingField("operation_ref"));
        }
        if transition.expected_heads.is_empty() {
            return Err(ModelMountError::MissingField("expected_heads"));
        }
        if transition.state_root_before.trim().is_empty() {
            return Err(ModelMountError::MissingField("state_root_before"));
        }
        if transition.state_root_after.trim().is_empty() {
            return Err(ModelMountError::MissingField("state_root_after"));
        }
        if transition.resulting_head.trim().is_empty() {
            return Err(ModelMountError::MissingField("resulting_head"));
        }
        if accepted_receipt_transition_hash(transition)? != transition.transition_hash {
            return Err(ModelMountError::InvalidAcceptedReceiptTransitionHash);
        }
        Ok(())
    }
}

impl ModelMountBackendProcessPlanRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("backend_ref", &self.backend_ref)?;
        require_non_empty("backend_kind", &self.backend_kind)?;
        Ok(())
    }
}

impl ModelMountAcceptedReceiptHeadRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl ModelMountAcceptedReceiptTransitionRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("current_head_ref", &self.current_head_ref)?;
        require_non_empty("current_state_root", &self.current_state_root)?;
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_non_empty("receipt_kind", &self.receipt_kind)?;
        Ok(())
    }
}

impl ModelMountRouteDecisionRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("route_ref", &self.route_ref)?;
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("endpoint_ref", &self.endpoint_ref)?;
        require_non_empty("model_ref", &self.model_ref)?;
        require_non_empty("capability", &self.capability)?;
        require_non_empty("policy_hash", &self.policy_hash)?;
        require_non_empty("idempotency_key", &self.idempotency_key)?;
        if self
            .receipt_refs
            .iter()
            .all(|value| value.trim().is_empty())
        {
            return Err(ModelMountError::MissingReceiptRef);
        }
        for receipt_ref in &self.receipt_refs {
            require_non_empty("receipt_refs[]", receipt_ref)?;
        }
        if self.model_ref.trim().eq_ignore_ascii_case("auto") {
            return Err(ModelMountError::UnresolvedAutoModel);
        }
        if is_private_workspace_profile(self.privacy_profile.as_deref()) {
            if self
                .custody_ref
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
            {
                return Err(ModelMountError::PrivateWorkspaceMissingCustodyRef);
            }
            if self.node_plaintext_allowed {
                return Err(ModelMountError::PrivateWorkspacePlaintextNotAllowed);
            }
        }
        Ok(())
    }
}

impl ModelMountInvocationAdmissionRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("invocation_ref", &self.invocation_ref)?;
        require_non_empty("route_decision_ref", &self.route_decision_ref)?;
        require_non_empty("route_receipt_ref", &self.route_receipt_ref)?;
        require_non_empty("invocation_receipt_ref", &self.invocation_receipt_ref)?;
        require_non_empty("route_ref", &self.route_ref)?;
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("endpoint_ref", &self.endpoint_ref)?;
        require_non_empty("model_ref", &self.model_ref)?;
        require_non_empty("capability", &self.capability)?;
        require_non_empty("invocation_kind", &self.invocation_kind)?;
        require_non_empty("policy_hash", &self.policy_hash)?;
        require_non_empty("input_hash", &self.input_hash)?;
        require_non_empty("output_hash", &self.output_hash)?;
        require_non_empty("idempotency_key", &self.idempotency_key)?;
        validate_receipt_refs(&self.receipt_refs)?;
        if !self.receipt_refs.contains(&self.route_receipt_ref) {
            return Err(ModelMountError::MissingRouteReceiptRef);
        }
        if !self.receipt_refs.contains(&self.invocation_receipt_ref) {
            return Err(ModelMountError::MissingInvocationReceiptRef);
        }
        if self.model_ref.trim().eq_ignore_ascii_case("auto") {
            return Err(ModelMountError::UnresolvedAutoModel);
        }
        if is_private_workspace_profile(self.privacy_profile.as_deref()) {
            if self
                .custody_ref
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
            {
                return Err(ModelMountError::PrivateWorkspaceMissingCustodyRef);
            }
            if self.node_plaintext_allowed {
                return Err(ModelMountError::PrivateWorkspacePlaintextNotAllowed);
            }
        }
        Ok(())
    }
}

impl ModelMountProviderExecutionRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("invocation_ref", &self.invocation_ref)?;
        require_non_empty("route_decision_ref", &self.route_decision_ref)?;
        require_non_empty("route_receipt_ref", &self.route_receipt_ref)?;
        require_non_empty("route_ref", &self.route_ref)?;
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("endpoint_ref", &self.endpoint_ref)?;
        require_non_empty("model_ref", &self.model_ref)?;
        require_non_empty("capability", &self.capability)?;
        require_non_empty("invocation_kind", &self.invocation_kind)?;
        require_non_empty("policy_hash", &self.policy_hash)?;
        require_non_empty("input_hash", &self.input_hash)?;
        require_non_empty("request_hash", &self.request_hash)?;
        require_non_empty("idempotency_key", &self.idempotency_key)?;
        validate_receipt_refs(&self.receipt_refs)?;
        if !self.receipt_refs.contains(&self.route_receipt_ref) {
            return Err(ModelMountError::MissingProviderExecutionRouteReceiptRef);
        }
        if self.model_ref.trim().eq_ignore_ascii_case("auto") {
            return Err(ModelMountError::UnresolvedAutoModel);
        }
        if is_private_workspace_profile(self.privacy_profile.as_deref()) {
            if self
                .custody_ref
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
            {
                return Err(ModelMountError::PrivateWorkspaceMissingCustodyRef);
            }
            if self.node_plaintext_allowed {
                return Err(ModelMountError::PrivateWorkspacePlaintextNotAllowed);
            }
        }
        Ok(())
    }
}

impl ModelMountProviderInvocationRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("provider_execution_ref", &self.provider_execution_ref)?;
        require_non_empty("provider_execution_hash", &self.provider_execution_hash)?;
        require_non_empty("route_decision_ref", &self.route_decision_ref)?;
        require_non_empty("route_receipt_ref", &self.route_receipt_ref)?;
        require_non_empty("route_ref", &self.route_ref)?;
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("provider_kind", &self.provider_kind)?;
        require_non_empty("endpoint_ref", &self.endpoint_ref)?;
        require_non_empty("model_ref", &self.model_ref)?;
        require_non_empty("capability", &self.capability)?;
        require_non_empty("invocation_kind", &self.invocation_kind)?;
        require_non_empty("request_hash", &self.request_hash)?;
        require_non_empty("execution_backend", &self.execution_backend)?;
        validate_receipt_refs(&self.receipt_refs)?;
        if !self.receipt_refs.contains(&self.route_receipt_ref) {
            return Err(ModelMountError::MissingProviderExecutionRouteReceiptRef);
        }
        if matches!(self.stream_status.as_deref(), Some(value) if !value.trim().is_empty()) {
            return Err(ModelMountError::StreamProviderInvocationUnsupported);
        }
        if !is_migrated_provider_invocation_backend(self) {
            return Err(ModelMountError::UnsupportedProviderInvocationBackend);
        }
        let Some(admission) = self.admitted_provider_execution.as_ref() else {
            return Err(ModelMountError::MissingProviderExecutionAdmission);
        };
        if admission.provider_execution_ref != self.provider_execution_ref {
            return Err(ModelMountError::ProviderExecutionRefMismatch);
        }
        if admission.provider_execution_hash != self.provider_execution_hash {
            return Err(ModelMountError::ProviderExecutionHashMismatch);
        }
        if admission.route_decision_ref != self.route_decision_ref
            || admission.route_receipt_ref != self.route_receipt_ref
            || admission.provider_ref != self.provider_ref
            || admission.endpoint_ref != self.endpoint_ref
            || admission.model_ref != self.model_ref
            || admission.capability != self.capability
            || admission.invocation_kind != self.invocation_kind
            || admission.request_hash != self.request_hash
        {
            return Err(ModelMountError::ProviderExecutionRefMismatch);
        }
        Ok(())
    }

    pub fn validate_stream(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("provider_execution_ref", &self.provider_execution_ref)?;
        require_non_empty("provider_execution_hash", &self.provider_execution_hash)?;
        require_non_empty("route_decision_ref", &self.route_decision_ref)?;
        require_non_empty("route_receipt_ref", &self.route_receipt_ref)?;
        require_non_empty("route_ref", &self.route_ref)?;
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("provider_kind", &self.provider_kind)?;
        require_non_empty("endpoint_ref", &self.endpoint_ref)?;
        require_non_empty("model_ref", &self.model_ref)?;
        require_non_empty("capability", &self.capability)?;
        require_non_empty("invocation_kind", &self.invocation_kind)?;
        require_non_empty("request_hash", &self.request_hash)?;
        require_non_empty("execution_backend", &self.execution_backend)?;
        validate_receipt_refs(&self.receipt_refs)?;
        if !self.receipt_refs.contains(&self.route_receipt_ref) {
            return Err(ModelMountError::MissingProviderExecutionRouteReceiptRef);
        }
        if !matches!(self.stream_status.as_deref(), Some("started")) {
            return Err(ModelMountError::StreamProviderInvocationUnsupported);
        }
        if !is_native_local_provider_stream_invocation_backend(self) {
            return Err(ModelMountError::UnsupportedProviderInvocationBackend);
        }
        let Some(admission) = self.admitted_provider_execution.as_ref() else {
            return Err(ModelMountError::MissingProviderExecutionAdmission);
        };
        if admission.provider_execution_ref != self.provider_execution_ref {
            return Err(ModelMountError::ProviderExecutionRefMismatch);
        }
        if admission.provider_execution_hash != self.provider_execution_hash {
            return Err(ModelMountError::ProviderExecutionHashMismatch);
        }
        if admission.route_decision_ref != self.route_decision_ref
            || admission.route_receipt_ref != self.route_receipt_ref
            || admission.provider_ref != self.provider_ref
            || admission.endpoint_ref != self.endpoint_ref
            || admission.model_ref != self.model_ref
            || admission.capability != self.capability
            || admission.invocation_kind != self.invocation_kind
            || admission.request_hash != self.request_hash
            || admission.stream_status != self.stream_status
        {
            return Err(ModelMountError::ProviderExecutionRefMismatch);
        }
        Ok(())
    }
}

impl ModelMountProviderLifecycleRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("provider_kind", &self.provider_kind)?;
        require_non_empty("endpoint_ref", &self.endpoint_ref)?;
        require_non_empty("model_ref", &self.model_ref)?;
        require_non_empty("action", &self.action)?;
        require_non_empty("execution_backend", &self.execution_backend)?;
        if self.model_ref.trim().eq_ignore_ascii_case("auto") {
            return Err(ModelMountError::UnresolvedAutoModel);
        }
        if !matches!(self.action.trim(), "health" | "load" | "unload") {
            return Err(ModelMountError::UnsupportedProviderLifecycleAction);
        }
        if !is_native_local_provider_lifecycle_backend(self)
            && !is_fixture_provider_lifecycle_backend(self)
        {
            return Err(ModelMountError::UnsupportedProviderLifecycleBackend);
        }
        Ok(())
    }
}

impl ModelMountProviderInventoryRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("provider_kind", &self.provider_kind)?;
        require_non_empty("action", &self.action)?;
        require_non_empty("execution_backend", &self.execution_backend)?;
        if !matches!(self.action.trim(), "list_models" | "list_loaded") {
            return Err(ModelMountError::UnsupportedProviderInventoryAction);
        }
        if !is_native_local_provider_inventory_backend(self)
            && !is_fixture_provider_inventory_backend(self)
        {
            return Err(ModelMountError::UnsupportedProviderInventoryBackend);
        }
        for item_ref in &self.item_refs {
            require_non_empty("item_refs[]", item_ref)?;
        }
        Ok(())
    }
}

impl ModelMountInstanceLifecycleRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("instance_ref", &self.instance_ref)?;
        require_non_empty("endpoint_ref", &self.endpoint_ref)?;
        require_non_empty("model_ref", &self.model_ref)?;
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("action", &self.action)?;
        require_non_empty("target_status", &self.target_status)?;
        require_non_empty("execution_backend", &self.execution_backend)?;
        require_non_empty("backend_ref", &self.backend_ref)?;
        require_non_empty("driver", &self.driver)?;
        require_non_empty("provider_lifecycle_hash", &self.provider_lifecycle_hash)?;
        if self.execution_backend.trim() != "rust_model_mount_instance_lifecycle" {
            return Err(ModelMountError::UnsupportedInstanceLifecycleBackend);
        }
        match self.action.trim() {
            "load" if self.target_status.trim() == "loaded" => Ok(()),
            "unload" if self.target_status.trim() == "unloaded" => Ok(()),
            "evict" if self.target_status.trim() == "evicted" => Ok(()),
            "supersede" if self.target_status.trim() == "superseded" => Ok(()),
            "load" | "unload" | "evict" | "supersede" => {
                Err(ModelMountError::InstanceLifecycleStatusMismatch)
            }
            _ => Err(ModelMountError::UnsupportedInstanceLifecycleAction),
        }
    }
}

impl ModelMountProviderResultAdmissionRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("provider_execution_ref", &self.provider_execution_ref)?;
        require_non_empty("provider_execution_hash", &self.provider_execution_hash)?;
        require_non_empty("route_decision_ref", &self.route_decision_ref)?;
        require_non_empty("route_receipt_ref", &self.route_receipt_ref)?;
        require_non_empty("route_ref", &self.route_ref)?;
        require_non_empty("provider_ref", &self.provider_ref)?;
        require_non_empty("provider_kind", &self.provider_kind)?;
        require_non_empty("endpoint_ref", &self.endpoint_ref)?;
        require_non_empty("model_ref", &self.model_ref)?;
        require_non_empty("capability", &self.capability)?;
        require_non_empty("invocation_kind", &self.invocation_kind)?;
        require_non_empty("request_hash", &self.request_hash)?;
        require_non_empty("output_hash", &self.output_hash)?;
        require_non_empty("execution_backend", &self.execution_backend)?;
        validate_receipt_refs(&self.receipt_refs)?;
        if !self.receipt_refs.contains(&self.route_receipt_ref) {
            return Err(ModelMountError::MissingProviderExecutionRouteReceiptRef);
        }
        if self.execution_backend.trim() != "js_provider_driver_observation" {
            return Err(ModelMountError::UnsupportedProviderResultBackend);
        }
        let actual_output_hash = format!("sha256:{}", sha256_hex(self.output_text.as_bytes())?);
        if actual_output_hash != self.output_hash {
            return Err(ModelMountError::ProviderResultOutputHashMismatch);
        }
        let Some(admission) = self.admitted_provider_execution.as_ref() else {
            return Err(ModelMountError::MissingProviderExecutionAdmission);
        };
        if admission.provider_execution_ref != self.provider_execution_ref {
            return Err(ModelMountError::ProviderExecutionRefMismatch);
        }
        if admission.provider_execution_hash != self.provider_execution_hash {
            return Err(ModelMountError::ProviderExecutionHashMismatch);
        }
        if admission.route_decision_ref != self.route_decision_ref
            || admission.route_receipt_ref != self.route_receipt_ref
            || admission.provider_ref != self.provider_ref
            || admission.endpoint_ref != self.endpoint_ref
            || admission.model_ref != self.model_ref
            || admission.capability != self.capability
            || admission.invocation_kind != self.invocation_kind
            || admission.request_hash != self.request_hash
            || admission.stream_status != self.stream_status
        {
            return Err(ModelMountError::ProviderExecutionRefMismatch);
        }
        Ok(())
    }
}

fn is_private_workspace_profile(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim),
        Some("private_workspace_ctee") | Some("ctee_private_workspace")
    )
}

fn is_migrated_provider_invocation_backend(request: &ModelMountProviderInvocationRequest) -> bool {
    is_fixture_provider_invocation_backend(request)
        || is_native_local_provider_invocation_backend(request)
}

fn is_fixture_provider_invocation_backend(request: &ModelMountProviderInvocationRequest) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_fixture" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "local_folder" || driver == "fixture" || api_format == "ioi_fixture"
}

fn is_native_local_provider_invocation_backend(
    request: &ModelMountProviderInvocationRequest,
) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_native_local" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "ioi_native_local" || driver == "native_local" || api_format == "ioi_native"
}

fn is_native_local_provider_stream_invocation_backend(
    request: &ModelMountProviderInvocationRequest,
) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_native_local_stream" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "ioi_native_local" || driver == "native_local" || api_format == "ioi_native"
}

fn is_native_local_provider_lifecycle_backend(
    request: &ModelMountProviderLifecycleRequest,
) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_native_local_lifecycle" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "ioi_native_local" || driver == "native_local" || api_format == "ioi_native"
}

fn is_fixture_provider_lifecycle_backend(request: &ModelMountProviderLifecycleRequest) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_fixture_lifecycle" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "local_folder" || driver == "fixture" || api_format == "ioi_fixture"
}

fn is_native_local_provider_inventory_backend(
    request: &ModelMountProviderInventoryRequest,
) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_native_local_inventory" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "ioi_native_local" || driver == "native_local" || api_format == "ioi_native"
}

fn is_fixture_provider_inventory_backend(request: &ModelMountProviderInventoryRequest) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_fixture_inventory" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "local_folder" || driver == "fixture" || api_format == "ioi_fixture"
}

fn provider_lifecycle_status(
    request: &ModelMountProviderLifecycleRequest,
) -> Result<String, ModelMountError> {
    match request.action.trim() {
        "health" => {
            if matches!(
                request.provider_status.as_deref().map(str::trim),
                Some("blocked")
            ) {
                Ok("blocked".to_string())
            } else {
                Ok("available".to_string())
            }
        }
        "load" => Ok("loaded".to_string()),
        "unload" => Ok("unloaded".to_string()),
        _ => Err(ModelMountError::UnsupportedProviderLifecycleAction),
    }
}

fn provider_lifecycle_backend(request: &ModelMountProviderLifecycleRequest) -> String {
    if is_native_local_provider_lifecycle_backend(request) {
        "autopilot.native_local.fixture".to_string()
    } else {
        request
            .api_format
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("ioi_fixture")
            .to_string()
    }
}

fn provider_lifecycle_backend_id(request: &ModelMountProviderLifecycleRequest) -> String {
    if is_native_local_provider_lifecycle_backend(request) {
        return request
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("backend.autopilot.native-local.fixture")
            .to_string();
    }
    request
        .backend_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("backend.fixture")
        .to_string()
}

fn provider_lifecycle_driver(request: &ModelMountProviderLifecycleRequest) -> String {
    if is_native_local_provider_lifecycle_backend(request) {
        "native_local".to_string()
    } else {
        "fixture".to_string()
    }
}

fn provider_inventory_backend(request: &ModelMountProviderInventoryRequest) -> String {
    if is_native_local_provider_inventory_backend(request) {
        "autopilot.native_local.fixture".to_string()
    } else {
        request
            .api_format
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("ioi_fixture")
            .to_string()
    }
}

fn provider_inventory_backend_id(request: &ModelMountProviderInventoryRequest) -> String {
    if is_native_local_provider_inventory_backend(request) {
        return request
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("backend.autopilot.native-local.fixture")
            .to_string();
    }
    request
        .backend_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("backend.fixture")
        .to_string()
}

fn provider_inventory_driver(request: &ModelMountProviderInventoryRequest) -> String {
    if is_native_local_provider_inventory_backend(request) {
        "native_local".to_string()
    } else {
        "fixture".to_string()
    }
}

fn deterministic_provider_output(
    request: &ModelMountProviderInvocationRequest,
) -> Result<String, ModelMountError> {
    if is_native_local_provider_invocation_backend(request) {
        return deterministic_native_local_output(
            &request.invocation_kind,
            &request.input,
            &request.model_ref,
        );
    }
    deterministic_fixture_output(&request.invocation_kind, &request.input, &request.model_ref)
}

fn deterministic_fixture_output(
    invocation_kind: &str,
    input: &str,
    model_ref: &str,
) -> Result<String, ModelMountError> {
    let digest = sha256_hex(input.as_bytes())?;
    let digest = &digest[..12];
    if invocation_kind == "embeddings" {
        return Ok(format!("embedding:{model_ref}:{digest}"));
    }
    if invocation_kind == "rerank" {
        return Ok(format!("rerank:{model_ref}:{digest}"));
    }
    Ok(format!(
        "IOI model router fixture response from {model_ref}. input_hash={digest}"
    ))
}

fn deterministic_native_local_output(
    invocation_kind: &str,
    input: &str,
    model_ref: &str,
) -> Result<String, ModelMountError> {
    let digest = sha256_hex(input.as_bytes())?;
    let digest = &digest[..12];
    if invocation_kind == "embeddings" {
        return Ok(format!("native-local-embedding:{model_ref}:{digest}"));
    }
    if invocation_kind == "rerank" {
        return Ok(format!("native-local-rerank:{model_ref}:{digest}"));
    }
    Ok(format!(
        "Autopilot native local model response from {model_ref}. input_hash={digest}"
    ))
}

fn provider_invocation_backend(request: &ModelMountProviderInvocationRequest) -> String {
    if is_native_local_provider_invocation_backend(request) {
        return "autopilot.native_local.fixture".to_string();
    }
    request
        .api_format
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("ioi_fixture")
        .to_string()
}

fn provider_invocation_backend_id(request: &ModelMountProviderInvocationRequest) -> String {
    if is_native_local_provider_invocation_backend(request) {
        return request
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("backend.autopilot.native-local.fixture")
            .to_string();
    }
    request
        .backend_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("backend.fixture")
        .to_string()
}

fn provider_invocation_response_kind(request: &ModelMountProviderInvocationRequest) -> String {
    if is_native_local_provider_invocation_backend(request) {
        return "rust_model_mount.native_local".to_string();
    }
    "rust_model_mount.fixture".to_string()
}

fn native_local_stream_kind(invocation_kind: &str) -> String {
    if invocation_kind == "responses" {
        return "openai_responses_native_local".to_string();
    }
    "openai_chat_completions_native_local".to_string()
}

fn native_local_stream_chunks(
    output_text: &str,
    token_count: &ModelMountTokenCount,
) -> Result<Vec<String>, ModelMountError> {
    let mut text_chunks = Vec::new();
    let chars: Vec<char> = output_text.chars().collect();
    if chars.is_empty() {
        text_chunks.push(String::new());
    } else {
        for chunk in chars.chunks(64) {
            text_chunks.push(chunk.iter().collect::<String>());
        }
    }
    let mut records = Vec::new();
    for chunk in text_chunks {
        let record = serde_json::json!({
            "delta": chunk,
            "done": false,
        });
        records.push(
            serde_json::to_string(&record)
                .map_err(|error| ModelMountError::HashFailed(error.to_string()))?
                + "\n",
        );
    }
    let done = serde_json::json!({
        "delta": "",
        "done": true,
        "done_reason": "stop",
        "prompt_eval_count": token_count.prompt_tokens,
        "eval_count": token_count.completion_tokens,
    });
    records.push(
        serde_json::to_string(&done)
            .map_err(|error| ModelMountError::HashFailed(error.to_string()))?
            + "\n",
    );
    Ok(records)
}

fn estimate_tokens(input: &str, output: &str) -> ModelMountTokenCount {
    let prompt_tokens = estimated_token_count(input);
    let completion_tokens = estimated_token_count(output);
    ModelMountTokenCount {
        prompt_tokens,
        completion_tokens,
        total_tokens: prompt_tokens + completion_tokens,
    }
}

fn estimated_token_count(value: &str) -> u64 {
    let chars = value.chars().count() as u64;
    ((chars + 3) / 4).max(1)
}

fn provider_invocation_evidence_refs(request: &ModelMountProviderInvocationRequest) -> Vec<String> {
    let mut refs = vec![
        "rust_model_mount_provider_invocation".to_string(),
        request.provider_execution_ref.clone(),
    ];
    if is_native_local_provider_invocation_backend(request) {
        refs.push("rust_model_mount_native_local_backend".to_string());
        refs.push("autopilot_native_local_openai_compatible_serving".to_string());
        refs.push("deterministic_native_local_fixture".to_string());
    } else {
        refs.push("rust_model_mount_fixture_backend".to_string());
        refs.push("deterministic_fixture".to_string());
    }
    for evidence_ref in &request.evidence_refs {
        if !evidence_ref.trim().is_empty() && !refs.contains(evidence_ref) {
            refs.push(evidence_ref.clone());
        }
    }
    refs
}

fn provider_stream_invocation_evidence_refs(
    request: &ModelMountProviderInvocationRequest,
) -> Vec<String> {
    let mut refs = vec![
        "rust_model_mount_provider_stream_invocation".to_string(),
        "rust_model_mount_native_local_stream_backend".to_string(),
        "autopilot_native_local_openai_compatible_serving".to_string(),
        "deterministic_native_local_fixture".to_string(),
        request.provider_execution_ref.clone(),
    ];
    for evidence_ref in &request.evidence_refs {
        if !evidence_ref.trim().is_empty() && !refs.contains(evidence_ref) {
            refs.push(evidence_ref.clone());
        }
    }
    refs
}

fn provider_result_evidence_refs(
    request: &ModelMountProviderResultAdmissionRequest,
) -> Vec<String> {
    let mut refs = vec![
        "rust_model_mount_provider_result_admission".to_string(),
        "js_provider_driver_observation_bound".to_string(),
        request.provider_execution_ref.clone(),
    ];
    for evidence_ref in request
        .evidence_refs
        .iter()
        .chain(request.provider_auth_evidence_refs.iter())
        .chain(request.backend_evidence_refs.iter())
    {
        if !evidence_ref.trim().is_empty() && !refs.contains(evidence_ref) {
            refs.push(evidence_ref.clone());
        }
    }
    refs
}

fn provider_lifecycle_evidence_refs(request: &ModelMountProviderLifecycleRequest) -> Vec<String> {
    let mut refs = vec!["rust_model_mount_provider_lifecycle".to_string()];
    if is_native_local_provider_lifecycle_backend(request) {
        refs.push("rust_model_mount_native_local_lifecycle_backend".to_string());
        if matches!(request.action.trim(), "health" | "load") {
            refs.push("autopilot_native_local_backend_registry".to_string());
        }
        if matches!(request.action.trim(), "load" | "unload") {
            refs.push("autopilot_native_local_process_supervisor".to_string());
        }
        refs.push("deterministic_native_local_fixture".to_string());
    } else {
        refs.push("rust_model_mount_fixture_lifecycle_backend".to_string());
        refs.push("agentgres_model_registry_fixture".to_string());
        refs.push("deterministic_fixture".to_string());
    }
    for evidence_ref in request
        .process_evidence_refs
        .iter()
        .chain(request.evidence_refs.iter())
    {
        push_unique_ref(&mut refs, evidence_ref);
    }
    refs
}

fn provider_inventory_evidence_refs(request: &ModelMountProviderInventoryRequest) -> Vec<String> {
    let mut refs = vec!["rust_model_mount_provider_inventory".to_string()];
    if is_native_local_provider_inventory_backend(request) {
        refs.push("rust_model_mount_native_local_inventory_backend".to_string());
        refs.push("autopilot_native_local_backend_registry".to_string());
        if request.action.trim() == "list_loaded" {
            refs.push("autopilot_native_local_process_supervisor".to_string());
        }
        refs.push("deterministic_native_local_fixture".to_string());
    } else {
        refs.push("rust_model_mount_fixture_inventory_backend".to_string());
        refs.push("agentgres_model_registry_fixture".to_string());
        if request.action.trim() == "list_loaded" {
            refs.push("agentgres_model_instance_registry_fixture".to_string());
        }
        refs.push("deterministic_fixture".to_string());
    }
    for evidence_ref in &request.evidence_refs {
        push_unique_ref(&mut refs, evidence_ref);
    }
    refs
}

fn instance_lifecycle_evidence_refs(request: &ModelMountInstanceLifecycleRequest) -> Vec<String> {
    let mut refs = vec![
        "rust_model_mount_instance_lifecycle".to_string(),
        "rust_model_mount_provider_lifecycle_bound".to_string(),
        "agentgres_model_instance_registry_planned".to_string(),
    ];
    for evidence_ref in &request.evidence_refs {
        push_unique_ref(&mut refs, evidence_ref);
    }
    refs
}

fn backend_supports_supervision(backend_kind: &str) -> bool {
    matches!(
        backend_kind.trim(),
        "native_local" | "llama_cpp" | "ollama" | "vllm"
    )
}

fn backend_supervisor_kind(request: &ModelMountBackendProcessPlanRequest) -> String {
    if request.backend_kind.trim() == "native_local" {
        "deterministic_fixture_process".to_string()
    } else if backend_supports_supervision(&request.backend_kind) {
        "external_process".to_string()
    } else {
        "unsupported".to_string()
    }
}

fn backend_process_public_args(
    request: &ModelMountBackendProcessPlanRequest,
) -> Result<Vec<String>, ModelMountError> {
    let model_arg = request
        .model_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("runtime-engine-profile");
    let context_length = request
        .load_options
        .context_length
        .or(request.load_options.max_model_len);
    let parallel = request
        .load_options
        .parallel
        .or(request.load_options.tensor_parallel_size);
    let artifact_path_hash = request
        .artifact_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            sha256_hex(value.as_bytes()).map(|hash| hash.chars().take(16).collect::<String>())
        })
        .transpose()?;
    let mut args = Vec::new();
    match request.backend_kind.trim() {
        "llama_cpp" => {
            args.extend(["llama-server".to_string(), "--model".to_string()]);
            args.push(
                artifact_path_hash
                    .map(|hash| format!("artifact:{hash}"))
                    .unwrap_or_else(|| model_arg.to_string()),
            );
            if let Some(value) = context_length {
                args.extend(["--ctx-size".to_string(), value.to_string()]);
            }
            if let Some(value) = parallel {
                args.extend(["--parallel".to_string(), value.to_string()]);
            }
            if let Some(value) = option_trimmed(&request.load_options.gpu) {
                args.extend(["--gpu-layers".to_string(), llama_cpp_gpu_layers_arg(value)]);
            }
        }
        "vllm" => {
            args.extend(["vllm".to_string(), "serve".to_string()]);
            args.push(
                artifact_path_hash
                    .map(|hash| format!("artifact:{hash}"))
                    .unwrap_or_else(|| model_arg.to_string()),
            );
            if let Some(value) = context_length {
                args.extend(["--max-model-len".to_string(), value.to_string()]);
            }
            if let Some(value) = parallel {
                args.extend(["--tensor-parallel-size".to_string(), value.to_string()]);
            }
            if let Some(value) = option_trimmed(&request.load_options.dtype) {
                args.extend(["--dtype".to_string(), value.to_string()]);
            }
            if let Some(value) = option_trimmed(&request.load_options.gpu_memory_utilization) {
                args.extend(["--gpu-memory-utilization".to_string(), value.to_string()]);
            }
        }
        "ollama" => {
            args.extend(["ollama".to_string(), "serve".to_string()]);
        }
        "native_local" => {
            args.extend([
                "ioi-native-local-fixture".to_string(),
                "--model".to_string(),
                model_arg.to_string(),
            ]);
            if let Some(value) = context_length {
                args.extend(["--context".to_string(), value.to_string()]);
            }
            if let Some(value) = parallel {
                args.extend(["--parallel".to_string(), value.to_string()]);
            }
            if let Some(value) = option_trimmed(&request.load_options.gpu) {
                args.extend(["--gpu".to_string(), value.to_string()]);
            }
        }
        other => {
            args.extend([
                other.to_string(),
                "--model".to_string(),
                model_arg.to_string(),
            ]);
        }
    }
    if let Some(value) = option_trimmed(&request.load_options.identifier) {
        let hash = sha256_hex(value.as_bytes())?;
        args.extend(["--identifier".to_string(), hash.chars().take(12).collect()]);
    }
    Ok(args)
}

fn backend_process_spawn_args(
    request: &ModelMountBackendProcessPlanRequest,
) -> Result<Vec<String>, ModelMountError> {
    match request.backend_kind.trim() {
        "ollama" => Ok(vec!["serve".to_string()]),
        "vllm" => {
            let mut args = vec!["serve".to_string(), backend_spawn_model_arg(request)];
            let bind = backend_bind_address(request.base_url.as_deref());
            if let Some(host) = bind.0 {
                args.extend(["--host".to_string(), host]);
            }
            if let Some(port) = bind.1 {
                args.extend(["--port".to_string(), port]);
            }
            let context_length = request
                .load_options
                .max_model_len
                .or(request.load_options.context_length);
            let parallel = request
                .load_options
                .tensor_parallel_size
                .or(request.load_options.parallel);
            if let Some(value) = context_length {
                args.extend(["--max-model-len".to_string(), value.to_string()]);
            }
            if let Some(value) = parallel {
                args.extend(["--tensor-parallel-size".to_string(), value.to_string()]);
            }
            if let Some(value) = option_trimmed(&request.load_options.dtype) {
                args.extend(["--dtype".to_string(), value.to_string()]);
            }
            if let Some(value) = option_trimmed(&request.load_options.gpu_memory_utilization) {
                args.extend(["--gpu-memory-utilization".to_string(), value.to_string()]);
            }
            Ok(args)
        }
        "llama_cpp" => {
            let mut args = Vec::new();
            if let Some(model_path) = backend_model_path(request) {
                args.extend(["--model".to_string(), model_path]);
            }
            if let Some(value) = request.load_options.context_length {
                args.extend(["--ctx-size".to_string(), value.to_string()]);
            }
            if let Some(value) = request.load_options.parallel {
                args.extend(["--parallel".to_string(), value.to_string()]);
            }
            if let Some(value) = option_trimmed(&request.load_options.gpu) {
                args.extend([
                    "--n-gpu-layers".to_string(),
                    llama_cpp_gpu_layers_arg(value),
                ]);
            }
            if request.load_options.embeddings {
                args.push("--embedding".to_string());
            }
            let bind = backend_bind_address(request.base_url.as_deref());
            if let Some(host) = bind.0 {
                args.extend(["--host".to_string(), host]);
            }
            if let Some(port) = bind.1 {
                args.extend(["--port".to_string(), port]);
            }
            Ok(args)
        }
        _ => Ok(backend_process_public_args(request)?
            .into_iter()
            .skip(1)
            .collect()),
    }
}

fn backend_spawn_required(request: &ModelMountBackendProcessPlanRequest, supports: bool) -> bool {
    if !supports || request.backend_kind.trim() == "native_local" || !request.binary_configured {
        return false;
    }
    request.backend_kind.trim() != "llama_cpp" || backend_model_path(request).is_some()
}

fn backend_spawn_status(request: &ModelMountBackendProcessPlanRequest, supports: bool) -> String {
    if !supports || request.backend_kind.trim() == "native_local" {
        return "not_required".to_string();
    }
    if !request.binary_configured {
        return "binary_absent".to_string();
    }
    if request.backend_kind.trim() == "llama_cpp" && backend_model_path(request).is_none() {
        return "waiting_for_model".to_string();
    }
    "spawn_ready".to_string()
}

fn backend_process_evidence_refs(
    request: &ModelMountBackendProcessPlanRequest,
    supports: bool,
) -> Vec<String> {
    let mut refs = vec!["rust_model_mount_backend_process_plan".to_string()];
    if supports {
        refs.push(format!(
            "rust_model_mount_{}_backend_process",
            request.backend_kind.trim()
        ));
    } else {
        refs.push("rust_model_mount_backend_process_not_supervised".to_string());
    }
    refs.push(backend_spawn_status(request, supports));
    refs
}

fn backend_spawn_model_arg(request: &ModelMountBackendProcessPlanRequest) -> String {
    backend_model_path(request)
        .or_else(|| option_trimmed(&request.load_options.model).map(str::to_string))
        .or_else(|| {
            request
                .model_ref
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "runtime-engine-profile".to_string())
}

fn backend_model_path(request: &ModelMountBackendProcessPlanRequest) -> Option<String> {
    request
        .artifact_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| option_trimmed(&request.load_options.model_path).map(str::to_string))
}

fn backend_bind_address(base_url: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(base_url) = base_url.map(str::trim).filter(|value| !value.is_empty()) else {
        return (None, None);
    };
    let Some(authority) = base_url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
    else {
        return (None, None);
    };
    let mut parts = authority.rsplitn(2, ':');
    let port = parts
        .next()
        .filter(|value| value.chars().all(|c| c.is_ascii_digit()));
    let host = if port.is_some() {
        parts.next().unwrap_or(authority)
    } else {
        authority
    };
    (
        if host.is_empty() {
            None
        } else {
            Some(host.to_string())
        },
        port.map(str::to_string),
    )
}

fn llama_cpp_gpu_layers_arg(value: &str) -> String {
    if value == "auto" {
        "-1".to_string()
    } else {
        value.to_string()
    }
}

fn option_trimmed(value: &Option<String>) -> Option<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn push_unique_ref(refs: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if !value.is_empty() && !refs.iter().any(|existing| existing == value) {
        refs.push(value.to_string());
    }
}

fn validate_receipt_refs(receipt_refs: &[String]) -> Result<(), ModelMountError> {
    if receipt_refs.iter().all(|value| value.trim().is_empty()) {
        return Err(ModelMountError::MissingReceiptRef);
    }
    for receipt_ref in receipt_refs {
        require_non_empty("receipt_refs[]", receipt_ref)?;
    }
    Ok(())
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), ModelMountError> {
    if value.trim().is_empty() {
        Err(ModelMountError::MissingField(field))
    } else {
        Ok(())
    }
}

fn sha256_hex(bytes: &[u8]) -> Result<String, ModelMountError> {
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn route_decision_hash(record: &ModelMountRouteDecisionRecord) -> Result<String, ModelMountError> {
    let mut canonical = record.clone();
    canonical.route_decision_ref.clear();
    canonical.route_decision_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn invocation_admission_hash(
    record: &ModelMountInvocationAdmissionRecord,
) -> Result<String, ModelMountError> {
    let mut canonical = record.clone();
    canonical.invocation_admission_ref.clear();
    canonical.invocation_admission_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn provider_execution_hash(
    record: &ModelMountProviderExecutionRecord,
) -> Result<String, ModelMountError> {
    let mut canonical = record.clone();
    canonical.provider_execution_ref.clear();
    canonical.provider_execution_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn provider_invocation_hash(
    result: &ModelMountProviderInvocationResult,
) -> Result<String, ModelMountError> {
    let mut canonical = result.clone();
    canonical.invocation_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn provider_stream_invocation_hash(
    result: &ModelMountProviderStreamInvocationResult,
) -> Result<String, ModelMountError> {
    let mut canonical = result.clone();
    canonical.invocation_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn provider_lifecycle_hash(
    result: &ModelMountProviderLifecycleResult,
) -> Result<String, ModelMountError> {
    let mut canonical = result.clone();
    canonical.lifecycle_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn provider_inventory_hash(
    result: &ModelMountProviderInventoryResult,
) -> Result<String, ModelMountError> {
    let mut canonical = result.clone();
    canonical.inventory_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn instance_lifecycle_hash(
    result: &ModelMountInstanceLifecycleResult,
) -> Result<String, ModelMountError> {
    let mut canonical = result.clone();
    canonical.instance_lifecycle_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn provider_result_hash(
    record: &ModelMountProviderResultAdmissionRecord,
) -> Result<String, ModelMountError> {
    let mut canonical = record.clone();
    canonical.provider_result_ref.clear();
    canonical.provider_result_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn backend_process_plan_hash(
    plan: &ModelMountBackendProcessPlan,
) -> Result<String, ModelMountError> {
    let mut canonical = plan.clone();
    canonical.plan_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[derive(Serialize)]
struct ModelMountAcceptedReceiptHeadStateRootPayload {
    schema: &'static str,
    sequence: u64,
}

fn model_mount_accepted_receipt_head_state_root(sequence: u64) -> Result<String, ModelMountError> {
    let payload = ModelMountAcceptedReceiptHeadStateRootPayload {
        schema: "ioi.agentgres.model_mounting_state_root.v1",
        sequence,
    };
    let bytes = serde_json::to_vec(&payload)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn accepted_receipt_head_hash(
    head: &ModelMountAcceptedReceiptHead,
) -> Result<String, ModelMountError> {
    let mut canonical = head.clone();
    canonical.head_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[derive(Serialize)]
struct ModelMountAcceptedReceiptStateRootPayload<'a> {
    schema: &'static str,
    sequence: u64,
    previous_head: &'a str,
    operation_ref: &'a str,
    receipt_id: &'a str,
    receipt_kind: &'a str,
    route_decision_ref: Option<&'a str>,
    invocation_admission_ref: Option<&'a str>,
    invocation_admission_hash: Option<&'a str>,
    input_hash: Option<&'a str>,
    output_hash: Option<&'a str>,
}

fn model_mount_accepted_receipt_state_root(
    request: &ModelMountAcceptedReceiptTransitionRequest,
    next_sequence: u64,
    operation_ref: &str,
) -> Result<String, ModelMountError> {
    let payload = ModelMountAcceptedReceiptStateRootPayload {
        schema: "ioi.agentgres.model_mounting_state_root.v1",
        sequence: next_sequence,
        previous_head: &request.current_head_ref,
        operation_ref,
        receipt_id: &request.receipt_id,
        receipt_kind: &request.receipt_kind,
        route_decision_ref: request.route_decision_ref.as_deref(),
        invocation_admission_ref: request.invocation_admission_ref.as_deref(),
        invocation_admission_hash: request.invocation_admission_hash.as_deref(),
        input_hash: request.input_hash.as_deref(),
        output_hash: request.output_hash.as_deref(),
    };
    let bytes = serde_json::to_vec(&payload)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn accepted_receipt_transition_hash(
    transition: &ModelMountAcceptedReceiptTransition,
) -> Result<String, ModelMountError> {
    let mut canonical = transition.clone();
    canonical.transition_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn accepted_receipt_operation_suffix(receipt_kind: &str) -> String {
    let suffix = receipt_kind
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if suffix.is_empty() {
        "receipt".to_string()
    } else {
        suffix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ModelMountRouteDecisionRequest {
        ModelMountRouteDecisionRequest {
            schema_version: MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION.to_string(),
            route_ref: "model-route://default/local-first".to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            endpoint_ref: "endpoint://ioi-native-local/qwen3".to_string(),
            model_ref: "model://qwen/qwen3.5-9b".to_string(),
            capability: "chat".to_string(),
            policy_hash: "sha256:model-route-policy".to_string(),
            idempotency_key: "model-route:thread:test".to_string(),
            receipt_refs: vec!["receipt://model-route/qwen3".to_string()],
            authority_grant_refs: vec![],
            authority_receipt_refs: vec![],
            custody_ref: None,
            privacy_profile: Some("internal".to_string()),
            node_plaintext_allowed: false,
            workflow_graph_ref: Some("workflow://graph".to_string()),
            workflow_node_ref: Some("workflow://node/model-router".to_string()),
        }
    }

    fn invocation_request() -> ModelMountInvocationAdmissionRequest {
        ModelMountInvocationAdmissionRequest {
            schema_version: MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION.to_string(),
            invocation_ref: "model-invocation://response/test".to_string(),
            route_decision_ref: "model_mount://route_decision/test".to_string(),
            route_receipt_ref: "receipt://route/test".to_string(),
            invocation_receipt_ref: "receipt://invocation/test".to_string(),
            route_ref: "model-route://default/local-first".to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            endpoint_ref: "endpoint://ioi-native-local/qwen3".to_string(),
            model_ref: "model://qwen/qwen3.5-9b".to_string(),
            capability: "chat".to_string(),
            invocation_kind: "responses".to_string(),
            policy_hash: "sha256:model-route-policy".to_string(),
            input_hash: "sha256:input".to_string(),
            output_hash: "sha256:output".to_string(),
            idempotency_key: "model-invocation:thread:test".to_string(),
            receipt_refs: vec![
                "receipt://route/test".to_string(),
                "receipt://invocation/test".to_string(),
            ],
            authority_grant_refs: vec!["grant://wallet/model-chat".to_string()],
            authority_receipt_refs: vec!["receipt://wallet/model-chat".to_string()],
            provider_auth_evidence_refs: vec![],
            backend_evidence_refs: vec!["backend://native-local".to_string()],
            tool_receipt_refs: vec![],
            custody_ref: None,
            privacy_profile: Some("internal".to_string()),
            node_plaintext_allowed: false,
            workflow_graph_ref: Some("workflow://graph".to_string()),
            workflow_node_ref: Some("workflow://node/model-invocation".to_string()),
            response_ref: Some("response://test".to_string()),
            previous_response_ref: None,
            stream_status: None,
        }
    }

    fn provider_execution_request() -> ModelMountProviderExecutionRequest {
        ModelMountProviderExecutionRequest {
            schema_version: MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION.to_string(),
            invocation_ref: "model-provider-execution://response/test".to_string(),
            route_decision_ref: "model_mount://route_decision/test".to_string(),
            route_receipt_ref: "receipt://route/test".to_string(),
            route_ref: "model-route://default/local-first".to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            endpoint_ref: "endpoint://ioi-native-local/qwen3".to_string(),
            model_ref: "model://qwen/qwen3.5-9b".to_string(),
            capability: "chat".to_string(),
            invocation_kind: "responses".to_string(),
            policy_hash: "sha256:model-route-policy".to_string(),
            input_hash: "sha256:input".to_string(),
            request_hash: "sha256:request".to_string(),
            idempotency_key: "model-provider-execution:thread:test".to_string(),
            receipt_refs: vec!["receipt://route/test".to_string()],
            authority_grant_refs: vec!["grant://wallet/model-chat".to_string()],
            authority_receipt_refs: vec!["receipt://wallet/model-chat".to_string()],
            provider_auth_evidence_refs: vec![],
            backend_evidence_refs: vec!["backend://native-local".to_string()],
            tool_receipt_refs: vec![],
            custody_ref: None,
            privacy_profile: Some("internal".to_string()),
            node_plaintext_allowed: false,
            workflow_graph_ref: Some("workflow://graph".to_string()),
            workflow_node_ref: Some("workflow://node/model-provider-execution".to_string()),
            response_ref: Some("response://test".to_string()),
            previous_response_ref: None,
            stream_status: None,
        }
    }

    fn provider_invocation_request() -> ModelMountProviderInvocationRequest {
        let admission = ModelMountCore
            .admit_provider_execution(&provider_execution_request())
            .expect("provider execution admitted");
        ModelMountProviderInvocationRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION.to_string(),
            provider_execution_ref: admission.provider_execution_ref.clone(),
            provider_execution_hash: admission.provider_execution_hash.clone(),
            route_decision_ref: admission.route_decision_ref.clone(),
            route_receipt_ref: admission.route_receipt_ref.clone(),
            route_ref: admission.route_ref.clone(),
            provider_ref: admission.provider_ref.clone(),
            provider_kind: "local_folder".to_string(),
            endpoint_ref: admission.endpoint_ref.clone(),
            model_ref: admission.model_ref.clone(),
            capability: admission.capability.clone(),
            invocation_kind: admission.invocation_kind.clone(),
            input: "user: hello".to_string(),
            request_hash: admission.request_hash.clone(),
            execution_backend: "rust_model_mount_fixture".to_string(),
            api_format: Some("ioi_fixture".to_string()),
            driver: Some("fixture".to_string()),
            backend_ref: Some("backend.fixture".to_string()),
            stream_status: None,
            receipt_refs: admission.receipt_refs.clone(),
            evidence_refs: vec![admission.provider_execution_ref.clone()],
            admitted_provider_execution: Some(admission),
        }
    }

    fn provider_stream_invocation_request() -> ModelMountProviderInvocationRequest {
        let mut execution_request = provider_execution_request();
        execution_request.stream_status = Some("started".to_string());
        let admission = ModelMountCore
            .admit_provider_execution(&execution_request)
            .expect("stream provider execution admitted");
        ModelMountProviderInvocationRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION.to_string(),
            provider_execution_ref: admission.provider_execution_ref.clone(),
            provider_execution_hash: admission.provider_execution_hash.clone(),
            route_decision_ref: admission.route_decision_ref.clone(),
            route_receipt_ref: admission.route_receipt_ref.clone(),
            route_ref: admission.route_ref.clone(),
            provider_ref: admission.provider_ref.clone(),
            provider_kind: "ioi_native_local".to_string(),
            endpoint_ref: admission.endpoint_ref.clone(),
            model_ref: admission.model_ref.clone(),
            capability: admission.capability.clone(),
            invocation_kind: admission.invocation_kind.clone(),
            input: "user: hello".to_string(),
            request_hash: admission.request_hash.clone(),
            execution_backend: "rust_model_mount_native_local_stream".to_string(),
            api_format: Some("ioi_native".to_string()),
            driver: Some("native_local".to_string()),
            backend_ref: Some("backend.autopilot.native-local.fixture".to_string()),
            stream_status: admission.stream_status.clone(),
            receipt_refs: admission.receipt_refs.clone(),
            evidence_refs: vec![admission.provider_execution_ref.clone()],
            admitted_provider_execution: Some(admission),
        }
    }

    fn provider_lifecycle_request() -> ModelMountProviderLifecycleRequest {
        ModelMountProviderLifecycleRequest {
            schema_version: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            provider_kind: "ioi_native_local".to_string(),
            endpoint_ref: "endpoint://ioi-native-local/qwen3".to_string(),
            model_ref: "model://qwen/qwen3.5-9b".to_string(),
            action: "load".to_string(),
            execution_backend: "rust_model_mount_native_local_lifecycle".to_string(),
            api_format: Some("ioi_native".to_string()),
            driver: Some("native_local".to_string()),
            backend_ref: Some("backend.autopilot.native-local.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            evidence_refs: vec!["daemon_model_load_request".to_string()],
            process_evidence_refs: vec!["autopilot_native_local_process_started".to_string()],
        }
    }

    fn fixture_provider_lifecycle_request() -> ModelMountProviderLifecycleRequest {
        ModelMountProviderLifecycleRequest {
            schema_version: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://fixture".to_string(),
            provider_kind: "local_folder".to_string(),
            endpoint_ref: "endpoint://fixture/qwen3".to_string(),
            model_ref: "model://fixture/qwen3".to_string(),
            action: "health".to_string(),
            execution_backend: "rust_model_mount_fixture_lifecycle".to_string(),
            api_format: Some("ioi_fixture".to_string()),
            driver: Some("fixture".to_string()),
            backend_ref: Some("backend.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            evidence_refs: vec!["daemon_fixture_health_request".to_string()],
            process_evidence_refs: vec![],
        }
    }

    fn provider_inventory_request() -> ModelMountProviderInventoryRequest {
        ModelMountProviderInventoryRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            provider_kind: "ioi_native_local".to_string(),
            action: "list_loaded".to_string(),
            execution_backend: "rust_model_mount_native_local_inventory".to_string(),
            api_format: Some("ioi_native".to_string()),
            driver: Some("native_local".to_string()),
            backend_ref: Some("backend.autopilot.native-local.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            item_refs: vec!["model_instance://native/qwen3".to_string()],
            evidence_refs: vec!["daemon_native_local_list_loaded_request".to_string()],
        }
    }

    fn fixture_provider_inventory_request() -> ModelMountProviderInventoryRequest {
        ModelMountProviderInventoryRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://fixture".to_string(),
            provider_kind: "local_folder".to_string(),
            action: "list_models".to_string(),
            execution_backend: "rust_model_mount_fixture_inventory".to_string(),
            api_format: Some("ioi_fixture".to_string()),
            driver: Some("fixture".to_string()),
            backend_ref: Some("backend.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            item_refs: vec!["model://fixture/qwen3".to_string()],
            evidence_refs: vec!["daemon_fixture_list_models_request".to_string()],
        }
    }

    fn instance_lifecycle_request() -> ModelMountInstanceLifecycleRequest {
        ModelMountInstanceLifecycleRequest {
            schema_version: MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION.to_string(),
            instance_ref: "model_instance://native/qwen3".to_string(),
            endpoint_ref: "endpoint://ioi-native-local/qwen3".to_string(),
            model_ref: "model://qwen/qwen3.5-9b".to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            action: "load".to_string(),
            target_status: "loaded".to_string(),
            execution_backend: "rust_model_mount_instance_lifecycle".to_string(),
            backend_ref: "backend.autopilot.native-local.fixture".to_string(),
            driver: "native_local".to_string(),
            provider_lifecycle_hash: "sha256:provider-lifecycle".to_string(),
            evidence_refs: vec!["rust_model_mount_provider_lifecycle".to_string()],
        }
    }

    fn provider_result_admission_request() -> ModelMountProviderResultAdmissionRequest {
        let admission = ModelMountCore
            .admit_provider_execution(&provider_execution_request())
            .expect("provider execution admitted");
        let output_text = "hosted provider answer".to_string();
        let output_hash = format!(
            "sha256:{}",
            sha256_hex(output_text.as_bytes()).expect("output hash")
        );
        ModelMountProviderResultAdmissionRequest {
            schema_version: MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION.to_string(),
            provider_execution_ref: admission.provider_execution_ref.clone(),
            provider_execution_hash: admission.provider_execution_hash.clone(),
            route_decision_ref: admission.route_decision_ref.clone(),
            route_receipt_ref: admission.route_receipt_ref.clone(),
            route_ref: admission.route_ref.clone(),
            provider_ref: admission.provider_ref.clone(),
            provider_kind: "openai".to_string(),
            endpoint_ref: admission.endpoint_ref.clone(),
            model_ref: admission.model_ref.clone(),
            capability: admission.capability.clone(),
            invocation_kind: admission.invocation_kind.clone(),
            request_hash: admission.request_hash.clone(),
            output_text,
            output_hash,
            token_count: ModelMountTokenCount {
                prompt_tokens: 1,
                completion_tokens: 2,
                total_tokens: 3,
            },
            provider_response_kind: Some("openai.chat".to_string()),
            execution_backend: "js_provider_driver_observation".to_string(),
            backend_ref: Some("backend.openai-compatible".to_string()),
            stream_status: admission.stream_status.clone(),
            receipt_refs: admission.receipt_refs.clone(),
            provider_auth_evidence_refs: vec!["provider.auth".to_string()],
            backend_evidence_refs: vec!["backend.openai-compatible".to_string()],
            evidence_refs: vec![admission.provider_execution_ref.clone()],
            admitted_provider_execution: Some(admission),
        }
    }

    fn backend_process_plan_request() -> ModelMountBackendProcessPlanRequest {
        ModelMountBackendProcessPlanRequest {
            schema_version: MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION.to_string(),
            backend_ref: "backend.llama".to_string(),
            backend_kind: "llama_cpp".to_string(),
            base_url: Some("http://127.0.0.1:8091/v1".to_string()),
            model_ref: Some("model://qwen/qwen3.5-9b".to_string()),
            artifact_path: Some("/models/private/model.gguf".to_string()),
            binary_configured: true,
            load_options: ModelMountBackendProcessLoadOptions {
                context_length: Some(4096),
                parallel: Some(2),
                gpu: Some("auto".to_string()),
                identifier: Some("llama profile".to_string()),
                embeddings: true,
                ..Default::default()
            },
        }
    }

    fn accepted_receipt_transition_request() -> ModelMountAcceptedReceiptTransitionRequest {
        ModelMountAcceptedReceiptTransitionRequest {
            schema_version: MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION.to_string(),
            current_sequence: 0,
            current_head_ref: "agentgres://model-mounting/accepted-receipts/head/0".to_string(),
            current_state_root: "sha256:state-0".to_string(),
            receipt_id: "receipt.invoke".to_string(),
            receipt_kind: "model_invocation".to_string(),
            route_decision_ref: Some("model_mount://route_decision/test".to_string()),
            invocation_admission_ref: Some("model_mount://invocation_admission/test".to_string()),
            invocation_admission_hash: Some("sha256:invocation-test".to_string()),
            input_hash: Some("sha256:input".to_string()),
            output_hash: Some("sha256:output".to_string()),
        }
    }

    fn accepted_receipt_head_request() -> ModelMountAcceptedReceiptHeadRequest {
        ModelMountAcceptedReceiptHeadRequest {
            schema_version: MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_SCHEMA_VERSION.to_string(),
            sequence: 2,
        }
    }

    #[test]
    fn backend_process_plan_owns_supervision_args_and_readiness() {
        let plan = ModelMountCore
            .plan_backend_process(&backend_process_plan_request())
            .expect("backend process planned");

        assert_eq!(
            plan.schema_version,
            MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION
        );
        assert!(plan.supports_supervision);
        assert_eq!(plan.supervisor_kind, "external_process");
        assert_eq!(plan.spawn_status, "spawn_ready");
        assert!(plan.spawn_required);
        assert_eq!(plan.public_args[0], "llama-server");
        assert_eq!(plan.public_args[1], "--model");
        assert!(plan.public_args[2].starts_with("artifact:"));
        assert!(plan.public_args.contains(&"--gpu-layers".to_string()));
        assert!(plan.public_args.contains(&"-1".to_string()));
        assert_eq!(plan.spawn_args[0], "--model");
        assert_eq!(plan.spawn_args[1], "/models/private/model.gguf");
        assert!(plan.spawn_args.contains(&"--embedding".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"rust_model_mount_backend_process_plan".to_string()));
        assert!(plan.plan_hash.starts_with("sha256:"));
    }

    #[test]
    fn backend_process_plan_blocks_llama_spawn_without_model_artifact() {
        let mut request = backend_process_plan_request();
        request.artifact_path = None;
        request.load_options.model_path = None;

        let plan = ModelMountCore
            .plan_backend_process(&request)
            .expect("backend process planned");

        assert!(plan.supports_supervision);
        assert!(!plan.spawn_required);
        assert_eq!(plan.spawn_status, "waiting_for_model");
        assert!(!plan.spawn_args.contains(&"--model".to_string()));
    }

    #[test]
    fn accepted_receipt_transition_is_planned_in_rust_model_mount() {
        let transition = ModelMountCore
            .plan_accepted_receipt_transition(&accepted_receipt_transition_request())
            .expect("accepted receipt transition planned in Rust");

        assert_eq!(
            transition.schema_version,
            MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION
        );
        assert_eq!(transition.operation_id, "op_00000001_model_invocation");
        assert_eq!(
            transition.operation_ref,
            "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation"
        );
        assert_eq!(
            transition.expected_heads,
            vec!["agentgres://model-mounting/accepted-receipts/head/0".to_string()]
        );
        assert_eq!(transition.state_root_before, "sha256:state-0");
        assert!(transition.state_root_after.starts_with("sha256:"));
        assert_eq!(
            transition.resulting_head,
            "agentgres://model-mounting/accepted-receipts/head/1"
        );
        assert_eq!(
            transition.projection_watermark,
            "model-mounting-accepted-receipts:1"
        );
        assert!(transition.transition_hash.starts_with("sha256:"));
        assert!(transition
            .evidence_refs
            .contains(&"rust_model_mount_accepted_receipt_transition".to_string()));
        ModelMountCore
            .validate_accepted_receipt_transition(&transition)
            .expect("accepted receipt transition hash validates");
    }

    #[test]
    fn accepted_receipt_transition_rejects_tampered_hash() {
        let mut transition = ModelMountCore
            .plan_accepted_receipt_transition(&accepted_receipt_transition_request())
            .expect("accepted receipt transition planned in Rust");
        transition.resulting_head =
            "agentgres://model-mounting/accepted-receipts/head/tampered".to_string();

        let error = ModelMountCore
            .validate_accepted_receipt_transition(&transition)
            .expect_err("tampered accepted receipt transition fails");

        assert_eq!(error, ModelMountError::InvalidAcceptedReceiptTransitionHash);
    }

    #[test]
    fn accepted_receipt_head_is_planned_in_rust_model_mount() {
        let head = ModelMountCore
            .plan_accepted_receipt_head(&accepted_receipt_head_request())
            .expect("accepted receipt head planned in Rust");

        assert_eq!(
            head.schema_version,
            MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_SCHEMA_VERSION
        );
        assert_eq!(head.sequence, 2);
        assert_eq!(
            head.head_ref,
            "agentgres://model-mounting/accepted-receipts/head/2"
        );
        assert!(head.state_root.starts_with("sha256:"));
        assert_eq!(
            head.projection_watermark,
            "model-mounting-accepted-receipts:2"
        );
        assert!(head.head_hash.starts_with("sha256:"));
        assert!(head
            .evidence_refs
            .contains(&"rust_model_mount_accepted_receipt_head".to_string()));
    }

    #[test]
    fn accepted_receipt_head_rejects_wrong_schema() {
        let mut request = accepted_receipt_head_request();
        request.schema_version = "ioi.model_mount.legacy_head.v1".to_string();

        let error = ModelMountCore
            .plan_accepted_receipt_head(&request)
            .expect_err("accepted receipt head requires the canonical schema");

        assert_eq!(
            error,
            ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_SCHEMA_VERSION,
                actual: "ioi.model_mount.legacy_head.v1".to_string(),
            }
        );
    }

    #[test]
    fn accepted_receipt_transition_rejects_missing_head() {
        let mut request = accepted_receipt_transition_request();
        request.current_head_ref.clear();

        let error = ModelMountCore
            .plan_accepted_receipt_transition(&request)
            .expect_err("accepted receipt transition requires the current head");

        assert_eq!(error, ModelMountError::MissingField("current_head_ref"));
    }

    #[test]
    fn backend_process_plan_supports_vllm_bind_spawn_args() {
        let mut request = backend_process_plan_request();
        request.backend_ref = "backend.vllm".to_string();
        request.backend_kind = "vllm".to_string();
        request.base_url = Some("http://0.0.0.0:8092/v1".to_string());
        request.artifact_path = None;
        request.load_options = ModelMountBackendProcessLoadOptions {
            model_path: Some("/models/raw/vllm".to_string()),
            max_model_len: Some(16384),
            tensor_parallel_size: Some(2),
            dtype: Some("bfloat16".to_string()),
            ..Default::default()
        };

        let plan = ModelMountCore
            .plan_backend_process(&request)
            .expect("vllm backend process planned");

        assert_eq!(
            plan.spawn_args,
            vec![
                "serve",
                "/models/raw/vllm",
                "--host",
                "0.0.0.0",
                "--port",
                "8092",
                "--max-model-len",
                "16384",
                "--tensor-parallel-size",
                "2",
                "--dtype",
                "bfloat16"
            ]
        );
        assert_eq!(plan.spawn_status, "spawn_ready");
    }

    #[test]
    fn admits_resolved_model_route_decision() {
        let record = ModelMountCore
            .admit_route_decision(&request())
            .expect("route decision admitted");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION
        );
        assert_eq!(record.model_ref, "model://qwen/qwen3.5-9b");
        assert_eq!(record.receipt_refs, vec!["receipt://model-route/qwen3"]);
        assert!(record.route_decision_hash.starts_with("sha256:"));
        assert!(record
            .route_decision_ref
            .starts_with("model_mount://route_decision/"));
    }

    #[test]
    fn rejects_unresolved_auto_model_before_provider_invocation() {
        let mut request = request();
        request.model_ref = "auto".to_string();

        let error = ModelMountCore
            .admit_route_decision(&request)
            .expect_err("auto must be resolved before provider invocation");

        assert_eq!(error, ModelMountError::UnresolvedAutoModel);
    }

    #[test]
    fn route_decision_requires_receipt_refs() {
        let mut request = request();
        request.receipt_refs.clear();

        let error = ModelMountCore
            .admit_route_decision(&request)
            .expect_err("route decision must be receipt bound");

        assert_eq!(error, ModelMountError::MissingReceiptRef);

        request.receipt_refs = vec![" ".to_string()];
        let error = ModelMountCore
            .admit_route_decision(&request)
            .expect_err("route decision cannot use a blank receipt ref");

        assert_eq!(error, ModelMountError::MissingReceiptRef);
    }

    #[test]
    fn private_workspace_route_requires_ctee_custody_without_plaintext() {
        let mut request = request();
        request.privacy_profile = Some("private_workspace_ctee".to_string());
        request.node_plaintext_allowed = true;

        let error = ModelMountCore
            .admit_route_decision(&request)
            .expect_err("private workspace route requires custody ref first");

        assert_eq!(error, ModelMountError::PrivateWorkspaceMissingCustodyRef);

        request.custody_ref = Some("ctee://custody/private-workspace".to_string());
        let error = ModelMountCore
            .admit_route_decision(&request)
            .expect_err("private workspace route cannot allow plaintext");

        assert_eq!(error, ModelMountError::PrivateWorkspacePlaintextNotAllowed);

        request.node_plaintext_allowed = false;
        let record = ModelMountCore
            .admit_route_decision(&request)
            .expect("private cTEE route admitted");

        assert_eq!(
            record.custody_ref.as_deref(),
            Some("ctee://custody/private-workspace")
        );
    }

    #[test]
    fn admits_model_invocation_with_route_and_invocation_receipts() {
        let record = ModelMountCore
            .admit_invocation(&invocation_request())
            .expect("invocation admitted");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION
        );
        assert_eq!(
            record.route_decision_ref,
            "model_mount://route_decision/test"
        );
        assert_eq!(record.route_receipt_ref, "receipt://route/test");
        assert_eq!(record.invocation_receipt_ref, "receipt://invocation/test");
        assert!(record.invocation_admission_hash.starts_with("sha256:"));
        assert!(record
            .invocation_admission_ref
            .starts_with("model_mount://invocation_admission/"));
    }

    #[test]
    fn invocation_requires_bound_route_and_invocation_receipts() {
        let mut request = invocation_request();
        request.receipt_refs = vec![request.invocation_receipt_ref.clone()];

        let error = ModelMountCore
            .admit_invocation(&request)
            .expect_err("route receipt must be bound");

        assert_eq!(error, ModelMountError::MissingRouteReceiptRef);

        request.receipt_refs = vec![request.route_receipt_ref.clone()];
        let error = ModelMountCore
            .admit_invocation(&request)
            .expect_err("invocation receipt must be bound");

        assert_eq!(error, ModelMountError::MissingInvocationReceiptRef);

        request.receipt_refs.clear();
        let error = ModelMountCore
            .admit_invocation(&request)
            .expect_err("invocation admission requires receipts");

        assert_eq!(error, ModelMountError::MissingReceiptRef);
    }

    #[test]
    fn invocation_rejects_auto_model_before_receipt_admission() {
        let mut request = invocation_request();
        request.model_ref = "auto".to_string();

        let error = ModelMountCore
            .admit_invocation(&request)
            .expect_err("auto must be resolved before invocation admission");

        assert_eq!(error, ModelMountError::UnresolvedAutoModel);
    }

    #[test]
    fn private_workspace_invocation_requires_ctee_custody_without_plaintext() {
        let mut request = invocation_request();
        request.privacy_profile = Some("private_workspace_ctee".to_string());
        request.node_plaintext_allowed = true;

        let error = ModelMountCore
            .admit_invocation(&request)
            .expect_err("private workspace invocation requires custody ref first");

        assert_eq!(error, ModelMountError::PrivateWorkspaceMissingCustodyRef);

        request.custody_ref = Some("ctee://custody/private-workspace".to_string());
        let error = ModelMountCore
            .admit_invocation(&request)
            .expect_err("private workspace invocation cannot allow plaintext");

        assert_eq!(error, ModelMountError::PrivateWorkspacePlaintextNotAllowed);
    }

    #[test]
    fn admits_provider_execution_with_route_receipt_before_driver_call() {
        let record = ModelMountCore
            .admit_provider_execution(&provider_execution_request())
            .expect("provider execution admitted");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION
        );
        assert_eq!(
            record.route_decision_ref,
            "model_mount://route_decision/test"
        );
        assert_eq!(record.route_receipt_ref, "receipt://route/test");
        assert_eq!(record.request_hash, "sha256:request");
        assert!(record.provider_execution_hash.starts_with("sha256:"));
        assert!(record
            .provider_execution_ref
            .starts_with("model_mount://provider_execution/"));
    }

    #[test]
    fn provider_execution_requires_route_receipt_binding() {
        let mut request = provider_execution_request();
        request.receipt_refs.clear();

        let error = ModelMountCore
            .admit_provider_execution(&request)
            .expect_err("provider execution requires receipts");

        assert_eq!(error, ModelMountError::MissingReceiptRef);

        request.receipt_refs = vec!["receipt://other".to_string()];
        let error = ModelMountCore
            .admit_provider_execution(&request)
            .expect_err("provider execution requires the route receipt");

        assert_eq!(
            error,
            ModelMountError::MissingProviderExecutionRouteReceiptRef
        );
    }

    #[test]
    fn provider_execution_rejects_auto_model_before_driver_call() {
        let mut request = provider_execution_request();
        request.model_ref = "auto".to_string();

        let error = ModelMountCore
            .admit_provider_execution(&request)
            .expect_err("auto must be resolved before provider execution");

        assert_eq!(error, ModelMountError::UnresolvedAutoModel);
    }

    #[test]
    fn private_workspace_provider_execution_requires_ctee_custody_without_plaintext() {
        let mut request = provider_execution_request();
        request.privacy_profile = Some("private_workspace_ctee".to_string());
        request.node_plaintext_allowed = true;

        let error = ModelMountCore
            .admit_provider_execution(&request)
            .expect_err("private workspace provider execution requires custody ref first");

        assert_eq!(error, ModelMountError::PrivateWorkspaceMissingCustodyRef);

        request.custody_ref = Some("ctee://custody/private-workspace".to_string());
        let error = ModelMountCore
            .admit_provider_execution(&request)
            .expect_err("private workspace provider execution cannot allow plaintext");

        assert_eq!(error, ModelMountError::PrivateWorkspacePlaintextNotAllowed);
    }

    #[test]
    fn fixture_provider_invocation_executes_in_rust_model_mount() {
        let result = ModelMountCore
            .invoke_provider(&provider_invocation_request())
            .expect("fixture provider invocation executes in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION
        );
        assert_eq!(result.execution_backend, "rust_model_mount_fixture");
        assert_eq!(result.backend, "ioi_fixture");
        assert_eq!(result.backend_id, "backend.fixture");
        assert!(result
            .output_text
            .starts_with("IOI model router fixture response from model://qwen/qwen3.5-9b."));
        assert_eq!(
            result.token_count.total_tokens,
            result.token_count.prompt_tokens + result.token_count.completion_tokens
        );
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_provider_invocation".to_string()));
        assert!(result.invocation_hash.starts_with("sha256:"));
    }

    #[test]
    fn native_local_provider_invocation_executes_in_rust_model_mount() {
        let mut request = provider_invocation_request();
        request.execution_backend = "rust_model_mount_native_local".to_string();
        request.provider_kind = "ioi_native_local".to_string();
        request.api_format = Some("ioi_native".to_string());
        request.driver = Some("native_local".to_string());
        request.backend_ref = Some("backend.autopilot.native-local.fixture".to_string());
        request.admitted_provider_execution = Some(ModelMountProviderExecutionRecord {
            provider_ref: request.provider_ref.clone(),
            endpoint_ref: request.endpoint_ref.clone(),
            model_ref: request.model_ref.clone(),
            capability: request.capability.clone(),
            invocation_kind: request.invocation_kind.clone(),
            request_hash: request.request_hash.clone(),
            ..request
                .admitted_provider_execution
                .clone()
                .expect("admission")
        });

        let result = ModelMountCore
            .invoke_provider(&request)
            .expect("native-local provider invocation executes in Rust");

        assert_eq!(result.execution_backend, "rust_model_mount_native_local");
        assert_eq!(result.backend, "autopilot.native_local.fixture");
        assert_eq!(result.backend_id, "backend.autopilot.native-local.fixture");
        assert_eq!(
            result.provider_response_kind.as_deref(),
            Some("rust_model_mount.native_local")
        );
        assert!(result
            .output_text
            .starts_with("Autopilot native local model response from model://qwen/qwen3.5-9b."));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_native_local_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"deterministic_native_local_fixture".to_string()));
    }

    #[test]
    fn native_local_provider_stream_invocation_executes_in_rust_model_mount() {
        let request = provider_stream_invocation_request();
        let result = ModelMountCore
            .invoke_provider_stream(&request)
            .expect("native-local provider stream executes in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_PROVIDER_STREAM_INVOCATION_SCHEMA_VERSION
        );
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_native_local_stream"
        );
        assert_eq!(result.stream_format, "ioi_jsonl");
        assert_eq!(result.stream_kind, "openai_responses_native_local");
        assert_eq!(
            result.provider_response_kind,
            "rust_model_mount.native_local.stream"
        );
        assert_eq!(result.backend, "autopilot.native_local.fixture");
        assert_eq!(result.backend_id, "backend.autopilot.native-local.fixture");
        assert!(result
            .output_text
            .starts_with("Autopilot native local model response from model://qwen/qwen3.5-9b."));
        assert!(result.stream_chunks.len() >= 2);
        assert!(result.stream_chunks[0].contains("\"done\":false"));
        assert!(result
            .stream_chunks
            .last()
            .expect("done chunk")
            .contains("\"done\":true"));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_provider_stream_invocation".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_native_local_stream_backend".to_string()));
        assert!(result.invocation_hash.starts_with("sha256:"));
    }

    #[test]
    fn native_local_provider_lifecycle_is_planned_in_rust_model_mount() {
        let result = ModelMountCore
            .plan_provider_lifecycle(&provider_lifecycle_request())
            .expect("native-local provider lifecycle planned in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION
        );
        assert_eq!(result.action, "load");
        assert_eq!(result.status, "loaded");
        assert_eq!(result.backend, "autopilot.native_local.fixture");
        assert_eq!(result.backend_id, "backend.autopilot.native-local.fixture");
        assert_eq!(result.driver, "native_local");
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_native_local_lifecycle"
        );
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_provider_lifecycle".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_native_local_lifecycle_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"autopilot_native_local_process_started".to_string()));
        assert!(result.lifecycle_hash.starts_with("sha256:"));
    }

    #[test]
    fn native_local_provider_unload_lifecycle_is_planned_in_rust_model_mount() {
        let mut request = provider_lifecycle_request();
        request.action = "unload".to_string();
        request.evidence_refs.clear();

        let result = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect("native-local provider unload lifecycle planned in Rust");

        assert_eq!(result.action, "unload");
        assert_eq!(result.status, "unloaded");
        assert!(!result
            .evidence_refs
            .contains(&"autopilot_native_local_backend_registry".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"deterministic_native_local_fixture".to_string()));
    }

    #[test]
    fn native_local_provider_health_lifecycle_is_planned_in_rust_model_mount() {
        let mut request = provider_lifecycle_request();
        request.action = "health".to_string();
        request.evidence_refs = vec!["daemon_native_local_health_request".to_string()];
        request.process_evidence_refs.clear();

        let result = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect("native-local provider health planned in Rust");

        assert_eq!(result.action, "health");
        assert_eq!(result.status, "available");
        assert!(result
            .evidence_refs
            .contains(&"autopilot_native_local_backend_registry".to_string()));
        assert!(!result
            .evidence_refs
            .contains(&"autopilot_native_local_process_supervisor".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"deterministic_native_local_fixture".to_string()));

        request.provider_status = Some("blocked".to_string());
        let result = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect("blocked native-local provider health planned in Rust");

        assert_eq!(result.status, "blocked");
    }

    #[test]
    fn fixture_provider_lifecycle_is_planned_in_rust_model_mount() {
        let mut request = fixture_provider_lifecycle_request();

        let result = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect("fixture provider health planned in Rust");

        assert_eq!(result.action, "health");
        assert_eq!(result.status, "available");
        assert_eq!(result.backend, "ioi_fixture");
        assert_eq!(result.backend_id, "backend.fixture");
        assert_eq!(result.driver, "fixture");
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_fixture_lifecycle_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"agentgres_model_registry_fixture".to_string()));

        request.action = "load".to_string();
        let result = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect("fixture provider load planned in Rust");
        assert_eq!(result.status, "loaded");

        request.action = "unload".to_string();
        let result = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect("fixture provider unload planned in Rust");
        assert_eq!(result.status, "unloaded");
    }

    #[test]
    fn native_local_provider_lifecycle_rejects_unsupported_backend_and_action() {
        let mut request = provider_lifecycle_request();
        request.execution_backend = "daemon_js".to_string();

        let error = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect_err("lifecycle planner must reject JS backend");

        assert_eq!(error, ModelMountError::UnsupportedProviderLifecycleBackend);

        request = provider_lifecycle_request();
        request.action = "restart".to_string();
        let error = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect_err("lifecycle planner only supports explicit health/load/unload actions");

        assert_eq!(error, ModelMountError::UnsupportedProviderLifecycleAction);
    }

    #[test]
    fn native_local_provider_inventory_is_planned_in_rust_model_mount() {
        let result = ModelMountCore
            .plan_provider_inventory(&provider_inventory_request())
            .expect("native-local provider inventory planned in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION
        );
        assert_eq!(result.action, "list_loaded");
        assert_eq!(result.status, "listed");
        assert_eq!(result.backend, "autopilot.native_local.fixture");
        assert_eq!(result.backend_id, "backend.autopilot.native-local.fixture");
        assert_eq!(result.driver, "native_local");
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_native_local_inventory"
        );
        assert_eq!(result.item_count, 1);
        assert_eq!(
            result.item_refs,
            vec!["model_instance://native/qwen3".to_string()]
        );
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_provider_inventory".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_native_local_inventory_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"autopilot_native_local_process_supervisor".to_string()));
        assert!(result.inventory_hash.starts_with("sha256:"));
    }

    #[test]
    fn fixture_provider_inventory_is_planned_in_rust_model_mount() {
        let mut request = fixture_provider_inventory_request();

        let result = ModelMountCore
            .plan_provider_inventory(&request)
            .expect("fixture provider model inventory planned in Rust");

        assert_eq!(result.action, "list_models");
        assert_eq!(result.status, "listed");
        assert_eq!(result.backend, "ioi_fixture");
        assert_eq!(result.backend_id, "backend.fixture");
        assert_eq!(result.driver, "fixture");
        assert_eq!(result.item_count, 1);
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_fixture_inventory_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"agentgres_model_registry_fixture".to_string()));

        request.action = "list_loaded".to_string();
        request.item_refs = vec!["model_instance://fixture/qwen3".to_string()];
        let result = ModelMountCore
            .plan_provider_inventory(&request)
            .expect("fixture provider loaded inventory planned in Rust");
        assert_eq!(result.action, "list_loaded");
        assert!(result
            .evidence_refs
            .contains(&"agentgres_model_instance_registry_fixture".to_string()));
    }

    #[test]
    fn native_local_provider_inventory_rejects_unsupported_backend_and_action() {
        let mut request = provider_inventory_request();
        request.execution_backend = "daemon_js".to_string();

        let error = ModelMountCore
            .plan_provider_inventory(&request)
            .expect_err("inventory planner must reject JS backend");

        assert_eq!(error, ModelMountError::UnsupportedProviderInventoryBackend);

        request = provider_inventory_request();
        request.action = "scan".to_string();
        let error = ModelMountCore
            .plan_provider_inventory(&request)
            .expect_err("inventory planner only supports explicit listing actions");

        assert_eq!(error, ModelMountError::UnsupportedProviderInventoryAction);
    }

    #[test]
    fn model_instance_lifecycle_is_planned_in_rust_model_mount() {
        let result = ModelMountCore
            .plan_instance_lifecycle(&instance_lifecycle_request())
            .expect("model instance lifecycle planned in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION
        );
        assert_eq!(result.action, "load");
        assert_eq!(result.status, "loaded");
        assert_eq!(result.backend_id, "backend.autopilot.native-local.fixture");
        assert_eq!(result.driver, "native_local");
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_instance_lifecycle"
        );
        assert_eq!(result.provider_lifecycle_hash, "sha256:provider-lifecycle");
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_instance_lifecycle".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_provider_lifecycle_bound".to_string()));
        assert!(result.instance_lifecycle_hash.starts_with("sha256:"));
    }

    #[test]
    fn model_instance_unload_lifecycle_is_planned_in_rust_model_mount() {
        let mut request = instance_lifecycle_request();
        request.action = "unload".to_string();
        request.target_status = "unloaded".to_string();
        request.evidence_refs = vec!["rust_model_mount_fixture_lifecycle_backend".to_string()];

        let result = ModelMountCore
            .plan_instance_lifecycle(&request)
            .expect("model instance unload lifecycle planned in Rust");

        assert_eq!(result.action, "unload");
        assert_eq!(result.status, "unloaded");
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_fixture_lifecycle_backend".to_string()));
    }

    #[test]
    fn model_instance_eviction_and_supersede_lifecycle_are_planned_in_rust_model_mount() {
        let mut request = instance_lifecycle_request();
        request.action = "evict".to_string();
        request.target_status = "evicted".to_string();
        request.evidence_refs = vec!["model_idle_evict".to_string()];

        let result = ModelMountCore
            .plan_instance_lifecycle(&request)
            .expect("model instance eviction lifecycle planned in Rust");

        assert_eq!(result.action, "evict");
        assert_eq!(result.status, "evicted");
        assert!(result
            .evidence_refs
            .contains(&"model_idle_evict".to_string()));

        request = instance_lifecycle_request();
        request.action = "supersede".to_string();
        request.target_status = "superseded".to_string();
        request.evidence_refs = vec!["model_supersede".to_string()];

        let result = ModelMountCore
            .plan_instance_lifecycle(&request)
            .expect("model instance supersede lifecycle planned in Rust");

        assert_eq!(result.action, "supersede");
        assert_eq!(result.status, "superseded");
        assert!(result
            .evidence_refs
            .contains(&"model_supersede".to_string()));
    }

    #[test]
    fn model_instance_lifecycle_rejects_js_backend_and_status_drift() {
        let mut request = instance_lifecycle_request();
        request.execution_backend = "daemon_js".to_string();

        let error = ModelMountCore
            .plan_instance_lifecycle(&request)
            .expect_err("instance lifecycle planner must reject JS backend");

        assert_eq!(error, ModelMountError::UnsupportedInstanceLifecycleBackend);

        request = instance_lifecycle_request();
        request.target_status = "unloaded".to_string();
        let error = ModelMountCore
            .plan_instance_lifecycle(&request)
            .expect_err("load action must bind the loaded target status");

        assert_eq!(error, ModelMountError::InstanceLifecycleStatusMismatch);

        request = instance_lifecycle_request();
        request.action = "restart".to_string();
        let error = ModelMountCore
            .plan_instance_lifecycle(&request)
            .expect_err("instance lifecycle planner only supports canonical instance transitions");

        assert_eq!(error, ModelMountError::UnsupportedInstanceLifecycleAction);
    }

    #[test]
    fn fixture_provider_invocation_requires_bound_provider_execution() {
        let mut request = provider_invocation_request();
        request.admitted_provider_execution = None;

        let error = ModelMountCore
            .invoke_provider(&request)
            .expect_err("provider invocation requires the full admission record");

        assert_eq!(error, ModelMountError::MissingProviderExecutionAdmission);

        request = provider_invocation_request();
        let admitted_ref = request.provider_execution_ref.clone();
        request.provider_execution_ref = "model_mount://provider_execution/drifted".to_string();

        let error = ModelMountCore
            .invoke_provider(&request)
            .expect_err("provider execution ref must match admission");

        assert_eq!(error, ModelMountError::ProviderExecutionRefMismatch);

        request.provider_execution_ref = admitted_ref;
        request.provider_execution_hash = "sha256:drifted".to_string();
        let error = ModelMountCore
            .invoke_provider(&request)
            .expect_err("provider execution hash must match admission");

        assert_eq!(error, ModelMountError::ProviderExecutionHashMismatch);
    }

    #[test]
    fn provider_invocation_rejects_unmigrated_or_stream_backends() {
        let mut request = provider_invocation_request();
        request.provider_kind = "openai".to_string();
        request.driver = Some("openai_compatible".to_string());
        request.api_format = Some("openai".to_string());

        let error = ModelMountCore
            .invoke_provider(&request)
            .expect_err("only migrated provider backends execute in Rust");

        assert_eq!(error, ModelMountError::UnsupportedProviderInvocationBackend);

        let mut request = provider_invocation_request();
        request.stream_status = Some("started".to_string());
        let error = ModelMountCore
            .invoke_provider(&request)
            .expect_err("streaming provider execution remains a later slice");

        assert_eq!(error, ModelMountError::StreamProviderInvocationUnsupported);
    }

    #[test]
    fn native_local_provider_stream_invocation_rejects_unstarted_or_wrong_backends() {
        let mut request = provider_stream_invocation_request();
        request.stream_status = None;
        let error = ModelMountCore
            .invoke_provider_stream(&request)
            .expect_err("stream invocation requires started admission");

        assert_eq!(error, ModelMountError::StreamProviderInvocationUnsupported);

        let mut request = provider_stream_invocation_request();
        request.execution_backend = "js_provider_driver_observation".to_string();
        let error = ModelMountCore
            .invoke_provider_stream(&request)
            .expect_err("stream invocation requires Rust native-local stream backend");

        assert_eq!(error, ModelMountError::UnsupportedProviderInvocationBackend);
    }

    #[test]
    fn admits_unmigrated_provider_result_observation_bound_to_execution() {
        let record = ModelMountCore
            .admit_provider_result(&provider_result_admission_request())
            .expect("provider result observation admitted");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.execution_backend, "js_provider_driver_observation");
        assert_eq!(
            record.provider_response_kind.as_deref(),
            Some("openai.chat")
        );
        assert_eq!(record.output_hash.len(), "sha256:".len() + 64);
        assert!(record
            .provider_result_ref
            .starts_with("model_mount://provider_result/"));
        assert!(record.provider_result_hash.starts_with("sha256:"));
        assert!(record
            .evidence_refs
            .contains(&"rust_model_mount_provider_result_admission".to_string()));
    }

    #[test]
    fn admits_stream_start_provider_result_observation_bound_to_execution() {
        let mut execution_request = provider_execution_request();
        execution_request.stream_status = Some("started".to_string());
        let admission = ModelMountCore
            .admit_provider_execution(&execution_request)
            .expect("stream provider execution admitted");
        let output_text = String::new();
        let output_hash = format!(
            "sha256:{}",
            sha256_hex(output_text.as_bytes()).expect("output hash")
        );
        let request = ModelMountProviderResultAdmissionRequest {
            schema_version: MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION.to_string(),
            provider_execution_ref: admission.provider_execution_ref.clone(),
            provider_execution_hash: admission.provider_execution_hash.clone(),
            route_decision_ref: admission.route_decision_ref.clone(),
            route_receipt_ref: admission.route_receipt_ref.clone(),
            route_ref: admission.route_ref.clone(),
            provider_ref: admission.provider_ref.clone(),
            provider_kind: "ioi_native_local".to_string(),
            endpoint_ref: admission.endpoint_ref.clone(),
            model_ref: admission.model_ref.clone(),
            capability: admission.capability.clone(),
            invocation_kind: admission.invocation_kind.clone(),
            request_hash: admission.request_hash.clone(),
            output_text,
            output_hash,
            token_count: ModelMountTokenCount {
                prompt_tokens: 1,
                completion_tokens: 0,
                total_tokens: 1,
            },
            provider_response_kind: Some("native_local.responses.stream".to_string()),
            execution_backend: "js_provider_driver_observation".to_string(),
            backend_ref: Some("backend.autopilot.native-local.fixture".to_string()),
            stream_status: admission.stream_status.clone(),
            receipt_refs: admission.receipt_refs.clone(),
            provider_auth_evidence_refs: vec![],
            backend_evidence_refs: vec!["autopilot_native_local_provider_native_stream".to_string()],
            evidence_refs: vec![admission.provider_execution_ref.clone()],
            admitted_provider_execution: Some(admission),
        };

        let record = ModelMountCore
            .admit_provider_result(&request)
            .expect("stream provider result observation admitted");

        assert_eq!(record.stream_status.as_deref(), Some("started"));
        assert_eq!(
            record.provider_response_kind.as_deref(),
            Some("native_local.responses.stream")
        );
    }

    #[test]
    fn provider_result_admission_requires_bound_provider_execution() {
        let mut request = provider_result_admission_request();
        request.admitted_provider_execution = None;

        let error = ModelMountCore
            .admit_provider_result(&request)
            .expect_err("provider result requires the full admission record");

        assert_eq!(error, ModelMountError::MissingProviderExecutionAdmission);

        request = provider_result_admission_request();
        request.provider_execution_ref = "model_mount://provider_execution/drifted".to_string();
        let error = ModelMountCore
            .admit_provider_result(&request)
            .expect_err("provider result ref must match admission");

        assert_eq!(error, ModelMountError::ProviderExecutionRefMismatch);
    }

    #[test]
    fn provider_result_admission_rejects_hash_drift_or_wrong_backend() {
        let mut request = provider_result_admission_request();
        request.output_hash = "sha256:drifted".to_string();
        let error = ModelMountCore
            .admit_provider_result(&request)
            .expect_err("output hash must bind output text");

        assert_eq!(error, ModelMountError::ProviderResultOutputHashMismatch);

        let mut request = provider_result_admission_request();
        request.execution_backend = "rust_model_mount_fixture".to_string();
        let error = ModelMountCore
            .admit_provider_result(&request)
            .expect_err("fixture execution uses the provider invocation path");

        assert_eq!(error, ModelMountError::UnsupportedProviderResultBackend);
    }
}
