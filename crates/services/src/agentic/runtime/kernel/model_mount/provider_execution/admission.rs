use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::super::{
    require_non_empty, validate_receipt_refs, ModelMountError,
    MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION,
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

    #[test]
    fn provider_execution_admission_child_module_owns_planner_surface() {
        let record = admit_provider_execution(&provider_execution_request())
            .expect("provider execution admitted");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION
        );
        assert!(record.provider_execution_hash.starts_with("sha256:"));
        assert!(record
            .provider_execution_ref
            .starts_with("model_mount://provider_execution/"));
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
}
