use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    provider_execution::{ModelMountProviderExecutionRecord, ModelMountTokenCount},
    require_non_empty, sha256_hex, validate_receipt_refs, ModelMountError,
    MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION,
};

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

#[derive(Debug, Deserialize)]
pub struct ModelMountProviderResultAdmissionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountProviderResultAdmissionRequest,
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

pub fn admit_model_mount_provider_result_response(
    request: ModelMountProviderResultAdmissionBridgeRequest,
) -> Result<Value, ModelMountError> {
    let record = admit_provider_result(&request.request)?;
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
    use crate::agentic::runtime::kernel::model_mount::provider_execution::{
        admit_provider_execution, ModelMountProviderExecutionRequest,
    };
    use crate::agentic::runtime::kernel::model_mount::MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION;

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
