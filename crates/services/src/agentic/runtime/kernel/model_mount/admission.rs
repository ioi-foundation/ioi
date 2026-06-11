use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    require_non_empty, validate_receipt_refs, ModelMountError,
    MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION, MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION,
};

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
        validate_receipt_refs(&self.receipt_refs)?;
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
        validate_private_workspace(
            self.privacy_profile.as_deref(),
            &self.custody_ref,
            self.node_plaintext_allowed,
        )?;
        Ok(())
    }
}

pub(super) fn admit_route_decision(
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

pub(super) fn admit_invocation(
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
