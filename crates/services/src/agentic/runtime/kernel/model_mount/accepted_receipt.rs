use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    require_non_empty, ModelMountError, MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_SCHEMA_VERSION,
    MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION,
};

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

pub(super) fn plan_accepted_receipt_head(
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

pub(super) fn plan_accepted_receipt_transition(
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

pub(super) fn validate_accepted_receipt_transition(
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
    fn accepted_receipt_transition_is_planned_in_rust_model_mount() {
        let transition = plan_accepted_receipt_transition(&accepted_receipt_transition_request())
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
        validate_accepted_receipt_transition(&transition)
            .expect("accepted receipt transition hash validates");
    }

    #[test]
    fn accepted_receipt_transition_rejects_tampered_hash() {
        let mut transition =
            plan_accepted_receipt_transition(&accepted_receipt_transition_request())
                .expect("accepted receipt transition planned in Rust");
        transition.resulting_head =
            "agentgres://model-mounting/accepted-receipts/head/tampered".to_string();

        let error = validate_accepted_receipt_transition(&transition)
            .expect_err("tampered accepted receipt transition fails");

        assert_eq!(error, ModelMountError::InvalidAcceptedReceiptTransitionHash);
    }

    #[test]
    fn accepted_receipt_head_is_planned_in_rust_model_mount() {
        let head = plan_accepted_receipt_head(&accepted_receipt_head_request())
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

        let error = plan_accepted_receipt_head(&request)
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

        let error = plan_accepted_receipt_transition(&request)
            .expect_err("accepted receipt transition requires the current head");

        assert_eq!(error, ModelMountError::MissingField("current_head_ref"));
    }
}
