use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    require_non_empty, sha256_hex, validate_receipt_refs, ModelMountError,
    MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION,
};

mod admission;
mod invocation;
mod stream;

pub use admission::{ModelMountProviderExecutionRecord, ModelMountProviderExecutionRequest};

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
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_auth_materialization_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_header_binding_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_header_materialization_status: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_auth_materialization_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_header_binding_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_header_materialization_status: Option<String>,
    #[serde(default)]
    pub provider_auth_evidence_refs: Vec<String>,
    #[serde(default)]
    pub backend_evidence_refs: Vec<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_auth_materialization_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_header_binding_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_header_materialization_status: Option<String>,
    pub stream_format: String,
    pub stream_kind: String,
    pub stream_chunks: Vec<String>,
    #[serde(default)]
    pub provider_auth_evidence_refs: Vec<String>,
    #[serde(default)]
    pub backend_evidence_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub invocation_hash: String,
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
        if is_hosted_provider_invocation_backend(self) {
            validate_provider_execution_binding(self, false)?;
            return validate_hosted_provider_invocation_gate(self);
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
        if is_hosted_provider_stream_invocation_backend(self) {
            validate_provider_execution_binding(self, true)?;
            return validate_hosted_provider_invocation_gate(self);
        }
        if !is_native_local_provider_stream_invocation_backend(self) {
            return Err(ModelMountError::UnsupportedProviderInvocationBackend);
        }
        validate_provider_execution_binding(self, true)
    }
}

pub(super) fn admit_provider_execution(
    request: &ModelMountProviderExecutionRequest,
) -> Result<ModelMountProviderExecutionRecord, ModelMountError> {
    admission::admit_provider_execution(request)
}

pub(super) fn invoke_provider(
    request: &ModelMountProviderInvocationRequest,
) -> Result<ModelMountProviderInvocationResult, ModelMountError> {
    invocation::invoke_provider(request)
}

pub(super) fn invoke_provider_stream(
    request: &ModelMountProviderInvocationRequest,
) -> Result<ModelMountProviderStreamInvocationResult, ModelMountError> {
    stream::invoke_provider_stream(request)
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

pub(super) fn is_migrated_provider_invocation_backend(
    request: &ModelMountProviderInvocationRequest,
) -> bool {
    is_fixture_provider_invocation_backend(request)
        || is_native_local_provider_invocation_backend(request)
        || is_hosted_provider_invocation_backend(request)
}

pub(super) fn is_hosted_provider_invocation_backend(
    request: &ModelMountProviderInvocationRequest,
) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_hosted_provider" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    matches!(
        provider_kind,
        "openai"
            | "anthropic"
            | "gemini"
            | "custom_http"
            | "openai_compatible"
            | "ollama"
            | "vllm"
            | "llama_cpp"
            | "lm_studio"
            | "depin_tee"
    ) || matches!(
        api_format,
        "openai" | "anthropic" | "gemini" | "custom" | "openai_compatible" | "ollama"
    ) || matches!(driver, "openai_compatible" | "hosted_provider")
}

pub(super) fn is_hosted_provider_stream_invocation_backend(
    request: &ModelMountProviderInvocationRequest,
) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_hosted_provider_stream" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    matches!(
        provider_kind,
        "openai"
            | "anthropic"
            | "gemini"
            | "custom_http"
            | "openai_compatible"
            | "ollama"
            | "vllm"
            | "llama_cpp"
            | "lm_studio"
            | "depin_tee"
    ) || matches!(
        api_format,
        "openai" | "anthropic" | "gemini" | "custom" | "openai_compatible" | "ollama"
    ) || matches!(driver, "openai_compatible" | "hosted_provider")
}

fn validate_hosted_provider_invocation_gate(
    request: &ModelMountProviderInvocationRequest,
) -> Result<(), ModelMountError> {
    let admission = request
        .admitted_provider_execution
        .as_ref()
        .ok_or(ModelMountError::MissingProviderExecutionAdmission)?;
    if refs_missing(&admission.authority_grant_refs)
        || refs_missing(&admission.authority_receipt_refs)
    {
        return Err(ModelMountError::HostedProviderInvocationMissingAuthority);
    }
    if !refs_contain(
        &admission.provider_auth_evidence_refs,
        "wallet_network_provider_vault_ref_bound",
    ) || !refs_contain(
        &admission.provider_auth_evidence_refs,
        "ctee_hosted_provider_secret_not_exposed",
    ) || !refs_contain(
        &admission.provider_auth_evidence_refs,
        "rust_provider_auth_materialization_bound",
    ) {
        return Err(ModelMountError::HostedProviderInvocationMissingAuthEvidence);
    }
    if request
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(ModelMountError::HostedProviderInvocationMissingEndpointUrl);
    }
    if request
        .provider_auth_materialization_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
        || request
            .outbound_header_binding_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        || request
            .auth_header_materialization_status
            .as_deref()
            .map(str::trim)
            != Some("rust_ctee_outbound_header_bound")
    {
        return Err(ModelMountError::HostedProviderInvocationMissingAuthMaterialization);
    }
    Ok(())
}

fn refs_missing(refs: &[String]) -> bool {
    refs.iter().all(|value| value.trim().is_empty())
}

fn refs_contain(refs: &[String], expected: &str) -> bool {
    refs.iter().any(|value| value.trim() == expected)
}

pub(super) fn is_fixture_provider_invocation_backend(
    request: &ModelMountProviderInvocationRequest,
) -> bool {
    if request.execution_backend.trim() != "rust_model_mount_fixture" {
        return false;
    }
    let provider_kind = request.provider_kind.trim();
    let api_format = request.api_format.as_deref().unwrap_or("").trim();
    let driver = request.driver.as_deref().unwrap_or("").trim();
    provider_kind == "local_folder" || driver == "fixture" || api_format == "ioi_fixture"
}

pub(super) fn is_native_local_provider_invocation_backend(
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

pub(super) fn is_native_local_provider_stream_invocation_backend(
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

pub(super) fn deterministic_provider_output(
    request: &ModelMountProviderInvocationRequest,
) -> Result<String, ModelMountError> {
    if is_native_local_provider_invocation_backend(request) {
        return deterministic_native_local_output(
            &request.invocation_kind,
            &request.input,
            &request.model_ref,
        );
    }
    if is_hosted_provider_invocation_backend(request) {
        return deterministic_hosted_provider_output(
            &request.invocation_kind,
            &request.input,
            &request.model_ref,
            &request.provider_kind,
        );
    }
    deterministic_fixture_output(&request.invocation_kind, &request.input, &request.model_ref)
}

pub(super) fn deterministic_fixture_output(
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

pub(super) fn deterministic_native_local_output(
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

pub(super) fn deterministic_hosted_provider_output(
    invocation_kind: &str,
    input: &str,
    model_ref: &str,
    provider_kind: &str,
) -> Result<String, ModelMountError> {
    let digest = sha256_hex(input.as_bytes())?;
    let digest = &digest[..12];
    if invocation_kind == "embeddings" {
        return Ok(format!("hosted-provider-embedding:{model_ref}:{digest}"));
    }
    if invocation_kind == "rerank" {
        return Ok(format!("hosted-provider-rerank:{model_ref}:{digest}"));
    }
    Ok(format!(
        "Rust hosted provider invocation contract for {model_ref} via {provider_kind}. input_hash={digest}"
    ))
}

pub(super) fn provider_invocation_backend(request: &ModelMountProviderInvocationRequest) -> String {
    if is_native_local_provider_invocation_backend(request) {
        return "autopilot.native_local.fixture".to_string();
    }
    if is_hosted_provider_invocation_backend(request) {
        return request
            .api_format
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("hosted_provider_transport")
            .to_string();
    }
    request
        .api_format
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("ioi_fixture")
        .to_string()
}

pub(super) fn provider_invocation_backend_id(
    request: &ModelMountProviderInvocationRequest,
) -> String {
    if is_native_local_provider_invocation_backend(request) {
        return request
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("backend.autopilot.native-local.fixture")
            .to_string();
    }
    if is_hosted_provider_invocation_backend(request) {
        return request
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!(
                    "backend.hosted.{}",
                    request
                        .provider_kind
                        .trim()
                        .chars()
                        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
                        .collect::<String>()
                        .trim_matches('-')
                        .to_string()
                )
            });
    }
    request
        .backend_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("backend.fixture")
        .to_string()
}

pub(super) fn provider_invocation_response_kind(
    request: &ModelMountProviderInvocationRequest,
) -> String {
    if is_native_local_provider_invocation_backend(request) {
        return "rust_model_mount.native_local".to_string();
    }
    if is_hosted_provider_invocation_backend(request) {
        return "rust_model_mount.hosted_provider".to_string();
    }
    "rust_model_mount.fixture".to_string()
}

pub(super) fn hosted_provider_base_url_hash(
    request: &ModelMountProviderInvocationRequest,
) -> Result<Option<String>, ModelMountError> {
    if !is_hosted_provider_invocation_backend(request)
        && !is_hosted_provider_stream_invocation_backend(request)
    {
        return Ok(None);
    }
    let Some(base_url) = request
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(ModelMountError::HostedProviderInvocationMissingEndpointUrl);
    };
    Ok(Some(format!("sha256:{}", sha256_hex(base_url.as_bytes())?)))
}

pub(super) fn estimate_tokens(input: &str, output: &str) -> ModelMountTokenCount {
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

pub(super) fn provider_invocation_evidence_refs(
    request: &ModelMountProviderInvocationRequest,
) -> Vec<String> {
    let mut refs = vec![
        "rust_model_mount_provider_invocation".to_string(),
        request.provider_execution_ref.clone(),
    ];
    if is_native_local_provider_invocation_backend(request) {
        refs.push("rust_model_mount_native_local_backend".to_string());
        refs.push("autopilot_native_local_openai_compatible_serving".to_string());
        refs.push("deterministic_native_local_fixture".to_string());
    } else if is_hosted_provider_invocation_backend(request) {
        refs.push("rust_model_mount_hosted_provider_backend".to_string());
        refs.push("rust_hosted_provider_invocation_transport_materialized".to_string());
        refs.push("rust_hosted_provider_endpoint_url_bound".to_string());
        refs.push("wallet_network_provider_transport_authority_bound".to_string());
        refs.push("ctee_hosted_provider_secret_not_exposed".to_string());
        refs.push("ctee_outbound_header_binding_ref_bound".to_string());
        refs.push("rust_provider_auth_materialization_bound".to_string());
        refs.push("hosted_provider_auth_header_materialized_by_rust".to_string());
        refs.push("hosted_provider_auth_header_materialization_contract_bound".to_string());
    } else {
        refs.push("rust_model_mount_fixture_backend".to_string());
        refs.push("deterministic_fixture".to_string());
    }
    for evidence_ref in provider_auth_evidence_refs(request)
        .iter()
        .chain(backend_evidence_refs(request).iter())
    {
        if !evidence_ref.trim().is_empty() && !refs.contains(evidence_ref) {
            refs.push(evidence_ref.clone());
        }
    }
    for evidence_ref in &request.evidence_refs {
        if !evidence_ref.trim().is_empty() && !refs.contains(evidence_ref) {
            refs.push(evidence_ref.clone());
        }
    }
    refs
}

pub(super) fn provider_auth_evidence_refs(
    request: &ModelMountProviderInvocationRequest,
) -> Vec<String> {
    if !is_hosted_provider_invocation_backend(request)
        && !is_hosted_provider_stream_invocation_backend(request)
    {
        return Vec::new();
    }
    request
        .admitted_provider_execution
        .as_ref()
        .map(|admission| admission.provider_auth_evidence_refs.clone())
        .unwrap_or_default()
}

pub(super) fn backend_evidence_refs(request: &ModelMountProviderInvocationRequest) -> Vec<String> {
    let mut refs = Vec::new();
    if is_native_local_provider_invocation_backend(request) {
        refs.push("rust_model_mount_native_local_backend".to_string());
        refs.push("autopilot_native_local_openai_compatible_serving".to_string());
        refs.push("deterministic_native_local_fixture".to_string());
    } else if is_hosted_provider_invocation_backend(request) {
        refs.push("rust_model_mount_hosted_provider_backend".to_string());
        refs.push("rust_hosted_provider_invocation_transport_materialized".to_string());
        refs.push("rust_hosted_provider_endpoint_url_bound".to_string());
        refs.push("ctee_outbound_header_binding_ref_bound".to_string());
        refs.push("rust_provider_auth_materialization_bound".to_string());
        refs.push("hosted_provider_auth_header_materialized_by_rust".to_string());
        refs.push("hosted_provider_auth_header_materialization_contract_bound".to_string());
        refs.push("hosted_provider_plaintext_secret_not_returned".to_string());
    } else if is_hosted_provider_stream_invocation_backend(request) {
        refs.push("rust_model_mount_hosted_provider_stream_backend".to_string());
        refs.push("rust_hosted_provider_stream_transport_materialized".to_string());
        refs.push("rust_hosted_provider_endpoint_url_bound".to_string());
        refs.push("ctee_outbound_header_binding_ref_bound".to_string());
        refs.push("rust_provider_auth_materialization_bound".to_string());
        refs.push("hosted_provider_auth_header_materialized_by_rust".to_string());
        refs.push("hosted_provider_auth_header_materialization_contract_bound".to_string());
        refs.push("hosted_provider_plaintext_secret_not_returned".to_string());
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

pub(super) fn provider_invocation_hash(
    result: &ModelMountProviderInvocationResult,
) -> Result<String, ModelMountError> {
    let mut canonical = result.clone();
    canonical.invocation_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

pub(super) fn provider_stream_invocation_hash(
    result: &ModelMountProviderStreamInvocationResult,
) -> Result<String, ModelMountError> {
    let mut canonical = result.clone();
    canonical.invocation_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::{
        MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION,
        MODEL_MOUNT_PROVIDER_STREAM_INVOCATION_SCHEMA_VERSION,
    };

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
            base_url: None,
            provider_auth_materialization_ref: None,
            outbound_header_binding_ref: None,
            auth_header_materialization_status: None,
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
            base_url: None,
            provider_auth_materialization_ref: None,
            outbound_header_binding_ref: None,
            auth_header_materialization_status: None,
            stream_status: admission.stream_status.clone(),
            receipt_refs: admission.receipt_refs.clone(),
            evidence_refs: vec![admission.provider_execution_ref.clone()],
            admitted_provider_execution: Some(admission),
        }
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
    fn rust_core_admits_model_mount_provider_execution_direct_api() {
        let record = admit_provider_execution(&provider_execution_request())
            .expect("provider execution admitted");

        assert_eq!(record.request_hash, "sha256:request");
        assert_eq!(record.route_receipt_ref, "receipt://route/test");
        assert!(record
            .provider_execution_ref
            .starts_with("model_mount://provider_execution/"));
        assert!(record.provider_execution_hash.starts_with("sha256:"));
    }

    #[test]
    fn rust_core_executes_model_mount_provider_invocation_direct_api() {
        let response =
            invoke_provider(&provider_invocation_request()).expect("provider invocation executed");

        assert_eq!(response.execution_backend, "rust_model_mount_fixture");
        assert!(response
            .output_text
            .starts_with("IOI model router fixture response"));
        assert_eq!(response.backend_id, "backend.fixture");
        assert!(response
            .provider_execution_ref
            .starts_with("model_mount://provider_execution/"));
        assert!(response.invocation_hash.starts_with("sha256:"));
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
    fn rust_core_executes_native_local_model_mount_provider_invocation_direct_api() {
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

        let response =
            invoke_provider(&request).expect("native-local provider invocation executed");

        assert_eq!(response.execution_backend, "rust_model_mount_native_local");
        assert_eq!(
            response.backend_id,
            "backend.autopilot.native-local.fixture"
        );
        assert_eq!(
            response.provider_response_kind.as_deref(),
            Some("rust_model_mount.native_local")
        );
        assert!(response
            .output_text
            .starts_with("Autopilot native local model response"));
        assert!(response
            .evidence_refs
            .contains(&"rust_model_mount_native_local_backend".to_string()));
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
    fn rust_core_executes_native_local_model_mount_provider_stream_direct_api() {
        let response = invoke_provider_stream(&provider_stream_invocation_request())
            .expect("native-local provider stream executed");

        assert_eq!(
            response.execution_backend,
            "rust_model_mount_native_local_stream"
        );
        assert_eq!(response.stream_format, "ioi_jsonl");
        assert_eq!(response.stream_kind, "openai_responses_native_local");
        assert_eq!(
            response.provider_response_kind,
            "rust_model_mount.native_local.stream"
        );
        assert!(response.stream_chunks.len() >= 2);
        assert!(response
            .evidence_refs
            .contains(&"rust_model_mount_native_local_stream_backend".to_string()));
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
    fn provider_invocation_executes_hosted_transport_contract_in_rust_owner() {
        let mut request = provider_invocation_request();
        request.execution_backend = "rust_model_mount_hosted_provider".to_string();
        request.provider_kind = "openai".to_string();
        request.driver = Some("openai_compatible".to_string());
        request.api_format = Some("openai".to_string());

        let error =
            invoke_provider(&request).expect_err("hosted provider auth evidence is required first");

        assert_eq!(
            error,
            ModelMountError::HostedProviderInvocationMissingAuthEvidence
        );

        let mut admitted = request
            .admitted_provider_execution
            .clone()
            .expect("provider execution admission");
        admitted.provider_auth_evidence_refs = vec![
            "rust_model_mount_hosted_provider_auth_gate".to_string(),
            "wallet_network_provider_vault_ref_bound".to_string(),
            "ctee_hosted_provider_secret_not_exposed".to_string(),
            "rust_provider_auth_materialization_bound".to_string(),
        ];
        request.admitted_provider_execution = Some(admitted.clone());

        let error =
            invoke_provider(&request).expect_err("hosted provider endpoint URL is required");

        assert_eq!(
            error,
            ModelMountError::HostedProviderInvocationMissingEndpointUrl
        );

        request.base_url = Some("https://api.openai.example/v1".to_string());

        let error = invoke_provider(&request)
            .expect_err("hosted provider auth materialization refs are required");

        assert_eq!(
            error,
            ModelMountError::HostedProviderInvocationMissingAuthMaterialization
        );

        request.provider_auth_materialization_ref = Some(
            "agentgres://model-mounting/model-provider-auth-materializations/provider.openai_auth_header"
                .to_string(),
        );
        request.outbound_header_binding_ref = Some(
            "provider_auth_header://provider.openai_auth_header#sha256:provider-auth".to_string(),
        );
        request.auth_header_materialization_status =
            Some("rust_ctee_outbound_header_bound".to_string());

        let result =
            invoke_provider(&request).expect("hosted provider invocation executes in Rust owner");

        assert_eq!(result.execution_backend, "rust_model_mount_hosted_provider");
        assert_eq!(result.backend, "openai");
        assert_eq!(
            result.provider_response_kind.as_deref(),
            Some("rust_model_mount.hosted_provider")
        );
        assert!(result
            .output_text
            .starts_with("Rust hosted provider invocation contract"));
        assert!(result
            .provider_auth_evidence_refs
            .contains(&"wallet_network_provider_vault_ref_bound".to_string()));
        assert!(result
            .backend_evidence_refs
            .contains(&"rust_hosted_provider_invocation_transport_materialized".to_string()));
        assert!(result
            .backend_evidence_refs
            .contains(&"rust_hosted_provider_endpoint_url_bound".to_string()));
        assert!(result
            .backend_evidence_refs
            .contains(&"ctee_outbound_header_binding_ref_bound".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_hosted_provider_backend".to_string()));
        assert!(result.base_url_hash.is_some());
        assert_eq!(
            result.auth_header_materialization_status.as_deref(),
            Some("rust_ctee_outbound_header_bound")
        );

        admitted.authority_grant_refs.clear();
        request.admitted_provider_execution = Some(admitted);
        let error =
            invoke_provider(&request).expect_err("hosted provider authority is required in Rust");

        assert_eq!(
            error,
            ModelMountError::HostedProviderInvocationMissingAuthority
        );
    }

    #[test]
    fn provider_invocation_rejects_unmigrated_or_stream_backends() {
        let mut request = provider_invocation_request();
        request.execution_backend = "js_provider_driver_observation".to_string();

        let error =
            invoke_provider(&request).expect_err("only Rust provider backends execute in Rust");

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
}
