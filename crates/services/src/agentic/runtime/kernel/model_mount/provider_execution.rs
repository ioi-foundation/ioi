use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    require_non_empty, sha256_hex, validate_receipt_refs, ModelMountError,
    MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION, MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_STREAM_INVOCATION_SCHEMA_VERSION,
};

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
        validate_private_workspace(
            self.privacy_profile.as_deref(),
            &self.custody_ref,
            self.node_plaintext_allowed,
        )?;
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
        validate_provider_invocation_common(self)?;
        if matches!(self.stream_status.as_deref(), Some(value) if !value.trim().is_empty()) {
            return Err(ModelMountError::StreamProviderInvocationUnsupported);
        }
        if !is_migrated_provider_invocation_backend(self) {
            return Err(ModelMountError::UnsupportedProviderInvocationBackend);
        }
        validate_provider_execution_binding(self, false)
    }

    pub fn validate_stream(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        validate_provider_invocation_common(self)?;
        if !matches!(self.stream_status.as_deref(), Some("started")) {
            return Err(ModelMountError::StreamProviderInvocationUnsupported);
        }
        if !is_native_local_provider_stream_invocation_backend(self) {
            return Err(ModelMountError::UnsupportedProviderInvocationBackend);
        }
        validate_provider_execution_binding(self, true)
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
        if !is_rust_provider_result_backend(self) {
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

pub(super) fn admit_provider_execution(
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

pub(super) fn invoke_provider(
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

pub(super) fn invoke_provider_stream(
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

pub(super) fn admit_provider_result(
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

fn validate_private_workspace(
    privacy_profile: Option<&str>,
    custody_ref: &Option<String>,
    node_plaintext_allowed: bool,
) -> Result<(), ModelMountError> {
    if is_private_workspace_profile(privacy_profile) {
        if custody_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(ModelMountError::PrivateWorkspaceMissingCustodyRef);
        }
        if node_plaintext_allowed {
            return Err(ModelMountError::PrivateWorkspacePlaintextNotAllowed);
        }
    }
    Ok(())
}

fn is_private_workspace_profile(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim),
        Some("private_workspace_ctee") | Some("ctee_private_workspace")
    )
}

fn validate_provider_invocation_common(
    request: &ModelMountProviderInvocationRequest,
) -> Result<(), ModelMountError> {
    require_non_empty("provider_execution_ref", &request.provider_execution_ref)?;
    require_non_empty("provider_execution_hash", &request.provider_execution_hash)?;
    require_non_empty("route_decision_ref", &request.route_decision_ref)?;
    require_non_empty("route_receipt_ref", &request.route_receipt_ref)?;
    require_non_empty("route_ref", &request.route_ref)?;
    require_non_empty("provider_ref", &request.provider_ref)?;
    require_non_empty("provider_kind", &request.provider_kind)?;
    require_non_empty("endpoint_ref", &request.endpoint_ref)?;
    require_non_empty("model_ref", &request.model_ref)?;
    require_non_empty("capability", &request.capability)?;
    require_non_empty("invocation_kind", &request.invocation_kind)?;
    require_non_empty("request_hash", &request.request_hash)?;
    require_non_empty("execution_backend", &request.execution_backend)?;
    validate_receipt_refs(&request.receipt_refs)?;
    if !request.receipt_refs.contains(&request.route_receipt_ref) {
        return Err(ModelMountError::MissingProviderExecutionRouteReceiptRef);
    }
    Ok(())
}

fn validate_provider_execution_binding(
    request: &ModelMountProviderInvocationRequest,
    require_stream_status_match: bool,
) -> Result<(), ModelMountError> {
    let Some(admission) = request.admitted_provider_execution.as_ref() else {
        return Err(ModelMountError::MissingProviderExecutionAdmission);
    };
    if admission.provider_execution_ref != request.provider_execution_ref {
        return Err(ModelMountError::ProviderExecutionRefMismatch);
    }
    if admission.provider_execution_hash != request.provider_execution_hash {
        return Err(ModelMountError::ProviderExecutionHashMismatch);
    }
    if admission.route_decision_ref != request.route_decision_ref
        || admission.route_receipt_ref != request.route_receipt_ref
        || admission.provider_ref != request.provider_ref
        || admission.endpoint_ref != request.endpoint_ref
        || admission.model_ref != request.model_ref
        || admission.capability != request.capability
        || admission.invocation_kind != request.invocation_kind
        || admission.request_hash != request.request_hash
        || (require_stream_status_match && admission.stream_status != request.stream_status)
    {
        return Err(ModelMountError::ProviderExecutionRefMismatch);
    }
    Ok(())
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

fn is_rust_provider_result_backend(request: &ModelMountProviderResultAdmissionRequest) -> bool {
    match request.execution_backend.trim() {
        "rust_model_mount_fixture" => {
            let provider_kind = request.provider_kind.trim();
            provider_kind == "local_folder"
                || request
                    .provider_response_kind
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|kind| kind == "rust_model_mount.fixture")
        }
        "rust_model_mount_native_local" => request.provider_kind.trim() == "ioi_native_local",
        "rust_model_mount_native_local_stream" => {
            request.provider_kind.trim() == "ioi_native_local"
                && matches!(request.stream_status.as_deref(), Some("started"))
        }
        _ => false,
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
        "rust_model_mount_provider_result_backend_bound".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let admission = admit_provider_execution(&provider_execution_request())
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
        let admission = admit_provider_execution(&execution_request)
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

    fn provider_result_admission_request() -> ModelMountProviderResultAdmissionRequest {
        let admission = admit_provider_execution(&provider_execution_request())
            .expect("provider execution admitted");
        let output_text = "fixture provider answer".to_string();
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
            provider_kind: "local_folder".to_string(),
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
            provider_response_kind: Some("rust_model_mount.fixture".to_string()),
            execution_backend: "rust_model_mount_fixture".to_string(),
            backend_ref: Some("backend.fixture".to_string()),
            stream_status: admission.stream_status.clone(),
            receipt_refs: admission.receipt_refs.clone(),
            provider_auth_evidence_refs: vec![],
            backend_evidence_refs: vec!["rust_model_mount_fixture_backend".to_string()],
            evidence_refs: vec![admission.provider_execution_ref.clone()],
            admitted_provider_execution: Some(admission),
        }
    }

    #[test]
    fn admits_provider_execution_with_route_receipt_before_driver_call() {
        let record = admit_provider_execution(&provider_execution_request())
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

        let error =
            admit_provider_execution(&request).expect_err("provider execution requires receipts");

        assert_eq!(error, ModelMountError::MissingReceiptRef);

        request.receipt_refs = vec!["receipt://other".to_string()];
        let error = admit_provider_execution(&request)
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

        let error = admit_provider_execution(&request)
            .expect_err("auto must be resolved before provider execution");

        assert_eq!(error, ModelMountError::UnresolvedAutoModel);
    }

    #[test]
    fn private_workspace_provider_execution_requires_ctee_custody_without_plaintext() {
        let mut request = provider_execution_request();
        request.privacy_profile = Some("private_workspace_ctee".to_string());
        request.node_plaintext_allowed = true;

        let error = admit_provider_execution(&request)
            .expect_err("private workspace provider execution requires custody ref first");

        assert_eq!(error, ModelMountError::PrivateWorkspaceMissingCustodyRef);

        request.custody_ref = Some("ctee://custody/private-workspace".to_string());
        let error = admit_provider_execution(&request)
            .expect_err("private workspace provider execution cannot allow plaintext");

        assert_eq!(error, ModelMountError::PrivateWorkspacePlaintextNotAllowed);
    }

    #[test]
    fn fixture_provider_invocation_executes_in_rust_model_mount() {
        let result = invoke_provider(&provider_invocation_request())
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

        let result =
            invoke_provider(&request).expect("native-local provider invocation executes in Rust");

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
        let result = invoke_provider_stream(&request)
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
    fn fixture_provider_invocation_requires_bound_provider_execution() {
        let mut request = provider_invocation_request();
        request.admitted_provider_execution = None;

        let error = invoke_provider(&request)
            .expect_err("provider invocation requires the full admission record");

        assert_eq!(error, ModelMountError::MissingProviderExecutionAdmission);

        request = provider_invocation_request();
        let admitted_ref = request.provider_execution_ref.clone();
        request.provider_execution_ref = "model_mount://provider_execution/drifted".to_string();

        let error =
            invoke_provider(&request).expect_err("provider execution ref must match admission");

        assert_eq!(error, ModelMountError::ProviderExecutionRefMismatch);

        request.provider_execution_ref = admitted_ref;
        request.provider_execution_hash = "sha256:drifted".to_string();
        let error =
            invoke_provider(&request).expect_err("provider execution hash must match admission");

        assert_eq!(error, ModelMountError::ProviderExecutionHashMismatch);
    }

    #[test]
    fn provider_invocation_rejects_unmigrated_or_stream_backends() {
        let mut request = provider_invocation_request();
        request.provider_kind = "openai".to_string();
        request.driver = Some("openai_compatible".to_string());
        request.api_format = Some("openai".to_string());

        let error =
            invoke_provider(&request).expect_err("only migrated provider backends execute in Rust");

        assert_eq!(error, ModelMountError::UnsupportedProviderInvocationBackend);

        let mut request = provider_invocation_request();
        request.stream_status = Some("started".to_string());
        let error = invoke_provider(&request)
            .expect_err("streaming provider execution remains a later slice");

        assert_eq!(error, ModelMountError::StreamProviderInvocationUnsupported);
    }

    #[test]
    fn native_local_provider_stream_invocation_rejects_unstarted_or_wrong_backends() {
        let mut request = provider_stream_invocation_request();
        request.stream_status = None;
        let error = invoke_provider_stream(&request)
            .expect_err("stream invocation requires started admission");

        assert_eq!(error, ModelMountError::StreamProviderInvocationUnsupported);

        let mut request = provider_stream_invocation_request();
        request.execution_backend = "js_provider_driver_observation".to_string();
        let error = invoke_provider_stream(&request)
            .expect_err("stream invocation requires Rust native-local stream backend");

        assert_eq!(error, ModelMountError::UnsupportedProviderInvocationBackend);
    }

    #[test]
    fn admits_rust_provider_result_bound_to_execution() {
        let record = admit_provider_result(&provider_result_admission_request())
            .expect("Rust provider result admitted");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.execution_backend, "rust_model_mount_fixture");
        assert_eq!(
            record.provider_response_kind.as_deref(),
            Some("rust_model_mount.fixture")
        );
        assert_eq!(record.output_hash.len(), "sha256:".len() + 64);
        assert!(record
            .provider_result_ref
            .starts_with("model_mount://provider_result/"));
        assert!(record.provider_result_hash.starts_with("sha256:"));
        assert!(record
            .evidence_refs
            .contains(&"rust_model_mount_provider_result_admission".to_string()));
        assert!(record
            .evidence_refs
            .contains(&"rust_model_mount_provider_result_backend_bound".to_string()));
        assert!(!record
            .evidence_refs
            .iter()
            .any(|value| value == "js_provider_driver_observation_bound"));
    }

    #[test]
    fn admits_stream_start_rust_provider_result_bound_to_execution() {
        let mut execution_request = provider_execution_request();
        execution_request.stream_status = Some("started".to_string());
        let admission = admit_provider_execution(&execution_request)
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
            provider_response_kind: Some("rust_model_mount.native_local.stream".to_string()),
            execution_backend: "rust_model_mount_native_local_stream".to_string(),
            backend_ref: Some("backend.autopilot.native-local.fixture".to_string()),
            stream_status: admission.stream_status.clone(),
            receipt_refs: admission.receipt_refs.clone(),
            provider_auth_evidence_refs: vec![],
            backend_evidence_refs: vec!["autopilot_native_local_provider_native_stream".to_string()],
            evidence_refs: vec![admission.provider_execution_ref.clone()],
            admitted_provider_execution: Some(admission),
        };

        let record = admit_provider_result(&request).expect("stream Rust provider result admitted");

        assert_eq!(record.stream_status.as_deref(), Some("started"));
        assert_eq!(
            record.provider_response_kind.as_deref(),
            Some("rust_model_mount.native_local.stream")
        );
        assert_eq!(
            record.execution_backend,
            "rust_model_mount_native_local_stream"
        );
    }

    #[test]
    fn provider_result_admission_requires_bound_provider_execution() {
        let mut request = provider_result_admission_request();
        request.admitted_provider_execution = None;

        let error = admit_provider_result(&request)
            .expect_err("provider result requires the full admission record");

        assert_eq!(error, ModelMountError::MissingProviderExecutionAdmission);

        request = provider_result_admission_request();
        request.provider_execution_ref = "model_mount://provider_execution/drifted".to_string();
        let error =
            admit_provider_result(&request).expect_err("provider result ref must match admission");

        assert_eq!(error, ModelMountError::ProviderExecutionRefMismatch);
    }

    #[test]
    fn provider_result_admission_rejects_hash_drift_or_wrong_backend() {
        let mut request = provider_result_admission_request();
        request.output_hash = "sha256:drifted".to_string();
        let error = admit_provider_result(&request).expect_err("output hash must bind output text");

        assert_eq!(error, ModelMountError::ProviderResultOutputHashMismatch);

        let mut request = provider_result_admission_request();
        request.execution_backend = "js_provider_driver_observation".to_string();
        let error = admit_provider_result(&request)
            .expect_err("JS provider result observations are retired");

        assert_eq!(error, ModelMountError::UnsupportedProviderResultBackend);
    }
}
