use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    require_non_empty, validate_receipt_refs, ModelMountError,
    MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION, MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION,
    MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
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

pub(super) fn rust_authored_route_selection_receipt(
    record: &ModelMountRouteDecisionRecord,
) -> Result<Value, ModelMountError> {
    let receipt_ref = record
        .receipt_refs
        .first()
        .ok_or(ModelMountError::MissingReceiptRef)?;
    let receipt_id = receipt_ref
        .strip_prefix("receipt://")
        .unwrap_or(receipt_ref.as_str())
        .to_string();
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn route_decision_request() -> ModelMountRouteDecisionRequest {
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

    fn invocation_admission_request() -> ModelMountInvocationAdmissionRequest {
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

    #[test]
    fn admits_resolved_model_route_decision() {
        let record =
            admit_route_decision(&route_decision_request()).expect("route decision admitted");

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
        let mut request = route_decision_request();
        request.model_ref = "auto".to_string();

        let error = admit_route_decision(&request)
            .expect_err("auto must be resolved before provider invocation");

        assert_eq!(error, ModelMountError::UnresolvedAutoModel);
    }

    #[test]
    fn route_decision_requires_receipt_refs() {
        let mut request = route_decision_request();
        request.receipt_refs.clear();

        let error =
            admit_route_decision(&request).expect_err("route decision must be receipt bound");

        assert_eq!(error, ModelMountError::MissingReceiptRef);

        request.receipt_refs = vec![" ".to_string()];
        let error = admit_route_decision(&request)
            .expect_err("route decision cannot use a blank receipt ref");

        assert_eq!(error, ModelMountError::MissingReceiptRef);
    }

    #[test]
    fn private_workspace_route_requires_ctee_custody_without_plaintext() {
        let mut request = route_decision_request();
        request.privacy_profile = Some("private_workspace_ctee".to_string());
        request.node_plaintext_allowed = true;

        let error = admit_route_decision(&request)
            .expect_err("private workspace route requires custody ref first");

        assert_eq!(error, ModelMountError::PrivateWorkspaceMissingCustodyRef);

        request.custody_ref = Some("ctee://custody/private-workspace".to_string());
        let error = admit_route_decision(&request)
            .expect_err("private workspace route cannot allow plaintext");

        assert_eq!(error, ModelMountError::PrivateWorkspacePlaintextNotAllowed);

        request.node_plaintext_allowed = false;
        let record = admit_route_decision(&request).expect("private cTEE route admitted");

        assert_eq!(
            record.custody_ref.as_deref(),
            Some("ctee://custody/private-workspace")
        );
    }

    #[test]
    fn admits_model_invocation_with_route_and_invocation_receipts() {
        let record =
            admit_invocation(&invocation_admission_request()).expect("invocation admitted");

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
    fn rust_core_admits_model_mount_invocation_direct_api() {
        let request: ModelMountInvocationAdmissionRequest = serde_json::from_value(json!({
            "schema_version": MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION,
            "invocation_ref": "model-invocation://response/test",
            "route_decision_ref": "model_mount://route_decision/test",
            "route_receipt_ref": "receipt://route/test",
            "invocation_receipt_ref": "receipt://invocation/test",
            "route_ref": "route.local-first",
            "provider_ref": "provider.local",
            "endpoint_ref": "endpoint.local",
            "model_ref": "model.local",
            "capability": "chat",
            "invocation_kind": "responses",
            "policy_hash": "sha256:policy",
            "input_hash": "sha256:input",
            "output_hash": "sha256:output",
            "idempotency_key": "model_invocation:test",
            "receipt_refs": ["receipt://route/test", "receipt://invocation/test"],
            "authority_grant_refs": ["grant://wallet/model-chat"],
            "authority_receipt_refs": ["receipt://wallet/model-chat"],
            "provider_auth_evidence_refs": [],
            "backend_evidence_refs": [],
            "tool_receipt_refs": [],
            "privacy_profile": "local_private",
            "node_plaintext_allowed": false
        }))
        .expect("direct invocation admission request");

        let record = admit_invocation(&request).expect("admitted");

        assert_eq!(record.model_ref, "model.local");
        assert_eq!(record.route_receipt_ref, "receipt://route/test");
        assert_eq!(record.invocation_receipt_ref, "receipt://invocation/test");
        assert_eq!(
            record.authority_grant_refs,
            vec!["grant://wallet/model-chat".to_string()]
        );
        assert!(record
            .invocation_admission_ref
            .starts_with("model_mount://invocation_admission/"));
    }

    #[test]
    fn invocation_requires_bound_route_and_invocation_receipts() {
        let mut request = invocation_admission_request();
        request.receipt_refs = vec![request.invocation_receipt_ref.clone()];

        let error = admit_invocation(&request).expect_err("route receipt must be bound");

        assert_eq!(error, ModelMountError::MissingRouteReceiptRef);

        request.receipt_refs = vec![request.route_receipt_ref.clone()];
        let error = admit_invocation(&request).expect_err("invocation receipt must be bound");

        assert_eq!(error, ModelMountError::MissingInvocationReceiptRef);

        request.receipt_refs.clear();
        let error = admit_invocation(&request).expect_err("invocation admission requires receipts");

        assert_eq!(error, ModelMountError::MissingReceiptRef);
    }

    #[test]
    fn invocation_rejects_auto_model_before_receipt_admission() {
        let mut request = invocation_admission_request();
        request.model_ref = "auto".to_string();

        let error = admit_invocation(&request)
            .expect_err("auto must be resolved before invocation admission");

        assert_eq!(error, ModelMountError::UnresolvedAutoModel);
    }

    #[test]
    fn private_workspace_invocation_requires_ctee_custody_without_plaintext() {
        let mut request = invocation_admission_request();
        request.privacy_profile = Some("private_workspace_ctee".to_string());
        request.node_plaintext_allowed = true;

        let error = admit_invocation(&request)
            .expect_err("private workspace invocation requires custody ref first");

        assert_eq!(error, ModelMountError::PrivateWorkspaceMissingCustodyRef);

        request.custody_ref = Some("ctee://custody/private-workspace".to_string());
        let error = admit_invocation(&request)
            .expect_err("private workspace invocation cannot allow plaintext");

        assert_eq!(error, ModelMountError::PrivateWorkspacePlaintextNotAllowed);
    }
}
