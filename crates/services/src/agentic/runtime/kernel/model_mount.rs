use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION: &str = "ioi.model_mount.route_decision.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelMountError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    MissingReceiptRef,
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

fn is_private_workspace_profile(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim),
        Some("private_workspace_ctee") | Some("ctee_private_workspace")
    )
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), ModelMountError> {
    if value.trim().is_empty() {
        Err(ModelMountError::MissingField(field))
    } else {
        Ok(())
    }
}

fn route_decision_hash(record: &ModelMountRouteDecisionRecord) -> Result<String, ModelMountError> {
    let mut canonical = record.clone();
    canonical.route_decision_ref.clear();
    canonical.route_decision_hash.clear();
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
}
