use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION: &str = "ioi.model_mount.route_decision.v1";
pub const MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.model_mount.invocation_admission.v1";
pub const MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION: &str =
    "ioi.model_mount.provider_execution.v1";
pub const MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION: &str =
    "ioi.model_mount.provider_invocation.v1";

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
    UnsupportedProviderInvocationBackend,
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

    pub fn invoke_fixture_provider(
        &self,
        request: &ModelMountProviderInvocationRequest,
    ) -> Result<ModelMountProviderInvocationResult, ModelMountError> {
        request.validate()?;
        let output_text = deterministic_fixture_output(
            &request.invocation_kind,
            &request.input,
            &request.model_ref,
        )?;
        let token_count = estimate_tokens(&request.input, &output_text);
        let backend = request
            .api_format
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("ioi_fixture")
            .to_string();
        let backend_id = request
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("backend.fixture")
            .to_string();
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
            provider_response_kind: Some("rust_model_mount.fixture".to_string()),
            backend,
            backend_id,
            execution_backend: "rust_model_mount_fixture".to_string(),
            evidence_refs: fixture_invocation_evidence_refs(request),
            invocation_hash: String::new(),
        };
        result.invocation_hash = provider_invocation_hash(&result)?;
        Ok(result)
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
        if !is_fixture_provider_invocation_backend(self) {
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
}

fn is_private_workspace_profile(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim),
        Some("private_workspace_ctee") | Some("ctee_private_workspace")
    )
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

fn fixture_invocation_evidence_refs(request: &ModelMountProviderInvocationRequest) -> Vec<String> {
    let mut refs = vec![
        "rust_model_mount_provider_invocation".to_string(),
        "rust_model_mount_fixture_backend".to_string(),
        "deterministic_fixture".to_string(),
        request.provider_execution_ref.clone(),
    ];
    for evidence_ref in &request.evidence_refs {
        if !evidence_ref.trim().is_empty() && !refs.contains(evidence_ref) {
            refs.push(evidence_ref.clone());
        }
    }
    refs
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
            .invoke_fixture_provider(&provider_invocation_request())
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
    fn fixture_provider_invocation_requires_bound_provider_execution() {
        let mut request = provider_invocation_request();
        request.admitted_provider_execution = None;

        let error = ModelMountCore
            .invoke_fixture_provider(&request)
            .expect_err("provider invocation requires the full admission record");

        assert_eq!(error, ModelMountError::MissingProviderExecutionAdmission);

        request = provider_invocation_request();
        let admitted_ref = request.provider_execution_ref.clone();
        request.provider_execution_ref = "model_mount://provider_execution/drifted".to_string();

        let error = ModelMountCore
            .invoke_fixture_provider(&request)
            .expect_err("provider execution ref must match admission");

        assert_eq!(error, ModelMountError::ProviderExecutionRefMismatch);

        request.provider_execution_ref = admitted_ref;
        request.provider_execution_hash = "sha256:drifted".to_string();
        let error = ModelMountCore
            .invoke_fixture_provider(&request)
            .expect_err("provider execution hash must match admission");

        assert_eq!(error, ModelMountError::ProviderExecutionHashMismatch);
    }

    #[test]
    fn fixture_provider_invocation_rejects_unmigrated_or_stream_backends() {
        let mut request = provider_invocation_request();
        request.provider_kind = "openai".to_string();
        request.driver = Some("openai_compatible".to_string());
        request.api_format = Some("openai".to_string());

        let error = ModelMountCore
            .invoke_fixture_provider(&request)
            .expect_err("only the fixture backend is migrated in this slice");

        assert_eq!(error, ModelMountError::UnsupportedProviderInvocationBackend);

        let mut request = provider_invocation_request();
        request.stream_status = Some("started".to_string());
        let error = ModelMountCore
            .invoke_fixture_provider(&request)
            .expect_err("streaming provider execution remains a later slice");

        assert_eq!(error, ModelMountError::StreamProviderInvocationUnsupported);
    }
}
