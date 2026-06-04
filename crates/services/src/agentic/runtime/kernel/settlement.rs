use ioi_crypto::algorithms::hash::sha256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const L1_SETTLEMENT_ADMISSION_SCHEMA_VERSION: &str = "ioi.l1_settlement_admission.v1";
pub const L1_SETTLEMENT_WITHOUT_TRIGGER_NEGATIVE_CONFORMANCE: &str =
    "L1 settlement attempt without trigger fails";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptBundleV2 {
    pub settlement_hash: [u8; 32],
    pub request_hash: [u8; 32],
    pub committed_action_ref: [u8; 32],
    pub policy_decision_ref: [u8; 32],
    pub capability_lease_ref: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_grant_ref: Option<[u8; 32]>,
    pub invocation_envelope_ref: [u8; 32],
    #[serde(default)]
    pub observation_refs: Vec<[u8; 32]>,
    #[serde(default)]
    pub postcondition_refs: Vec<[u8; 32]>,
    #[serde(default)]
    pub artifact_refs: Vec<[u8; 32]>,
    #[serde(default)]
    pub trace_refs: Vec<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_manifest_ref: Option<[u8; 32]>,
}

#[derive(Debug, Serialize)]
struct SettlementReceiptBundleV2HashMaterial<'a> {
    request_hash: &'a [u8; 32],
    committed_action_ref: &'a [u8; 32],
    policy_decision_ref: &'a [u8; 32],
    capability_lease_ref: &'a [u8; 32],
    approval_grant_ref: &'a Option<[u8; 32]>,
    invocation_envelope_ref: &'a [u8; 32],
    observation_refs: &'a [[u8; 32]],
    postcondition_refs: &'a [[u8; 32]],
    artifact_refs: &'a [[u8; 32]],
    trace_refs: &'a [[u8; 32]],
    replay_manifest_ref: &'a Option<[u8; 32]>,
}

impl SettlementReceiptBundleV2 {
    pub fn compute_settlement_hash(&self) -> Result<[u8; 32], String> {
        let material = SettlementReceiptBundleV2HashMaterial {
            request_hash: &self.request_hash,
            committed_action_ref: &self.committed_action_ref,
            policy_decision_ref: &self.policy_decision_ref,
            capability_lease_ref: &self.capability_lease_ref,
            approval_grant_ref: &self.approval_grant_ref,
            invocation_envelope_ref: &self.invocation_envelope_ref,
            observation_refs: &self.observation_refs,
            postcondition_refs: &self.postcondition_refs,
            artifact_refs: &self.artifact_refs,
            trace_refs: &self.trace_refs,
            replay_manifest_ref: &self.replay_manifest_ref,
        };
        canonical_hash(&material)
    }

    pub fn verify(&self) -> Result<(), String> {
        let expected = self.compute_settlement_hash()?;
        if expected == self.settlement_hash {
            Ok(())
        } else {
            Err("settlement_receipt_bundle_v2_hash_mismatch".to_string())
        }
    }

    pub fn build(input: SettlementReceiptBundleV2Input) -> Result<Self, String> {
        let mut bundle = Self {
            settlement_hash: [0u8; 32],
            request_hash: input.request_hash,
            committed_action_ref: input.committed_action_ref,
            policy_decision_ref: input.policy_decision_ref,
            capability_lease_ref: input.capability_lease_ref,
            approval_grant_ref: input.approval_grant_ref,
            invocation_envelope_ref: input.invocation_envelope_ref,
            observation_refs: input.observation_refs,
            postcondition_refs: input.postcondition_refs,
            artifact_refs: input.artifact_refs,
            trace_refs: input.trace_refs,
            replay_manifest_ref: input.replay_manifest_ref,
        };
        bundle.settlement_hash = bundle.compute_settlement_hash()?;
        Ok(bundle)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementReceiptBundleV2Input {
    pub request_hash: [u8; 32],
    pub committed_action_ref: [u8; 32],
    pub policy_decision_ref: [u8; 32],
    pub capability_lease_ref: [u8; 32],
    pub approval_grant_ref: Option<[u8; 32]>,
    pub invocation_envelope_ref: [u8; 32],
    pub observation_refs: Vec<[u8; 32]>,
    pub postcondition_refs: Vec<[u8; 32]>,
    pub artifact_refs: Vec<[u8; 32]>,
    pub trace_refs: Vec<[u8; 32]>,
    pub replay_manifest_ref: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1SettlementAttempt {
    pub schema_version: String,
    pub settlement_ref: String,
    pub domain_ref: String,
    pub state_root_ref: String,
    #[serde(default)]
    pub trigger_refs: Vec<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1SettlementAdmissionRecord {
    pub schema_version: String,
    pub settlement_ref: String,
    pub domain_ref: String,
    pub state_root_ref: String,
    pub trigger_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub admission_hash: [u8; 32],
}

#[derive(Debug, Default, Clone)]
pub struct L1SettlementTriggerGuard;

impl L1SettlementTriggerGuard {
    pub fn admit(
        &self,
        attempt: &L1SettlementAttempt,
    ) -> Result<L1SettlementAdmissionRecord, L1SettlementAdmissionError> {
        attempt.validate()?;

        let mut record = L1SettlementAdmissionRecord {
            schema_version: L1_SETTLEMENT_ADMISSION_SCHEMA_VERSION.to_string(),
            settlement_ref: attempt.settlement_ref.clone(),
            domain_ref: attempt.domain_ref.clone(),
            state_root_ref: attempt.state_root_ref.clone(),
            trigger_refs: attempt.trigger_refs.clone(),
            receipt_refs: attempt.receipt_refs.clone(),
            admission_hash: [0u8; 32],
        };
        record.admission_hash = canonical_hash(&record)?;
        Ok(record)
    }
}

impl L1SettlementAttempt {
    pub fn validate(&self) -> Result<(), L1SettlementAdmissionError> {
        if self.schema_version != L1_SETTLEMENT_ADMISSION_SCHEMA_VERSION {
            return Err(L1SettlementAdmissionError::InvalidSchemaVersion {
                expected: L1_SETTLEMENT_ADMISSION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("settlement_ref", &self.settlement_ref)?;
        require_non_empty("domain_ref", &self.domain_ref)?;
        require_non_empty("state_root_ref", &self.state_root_ref)?;
        if self.trigger_refs.is_empty() {
            return Err(L1SettlementAdmissionError::MissingSettlementTrigger);
        }
        if self.receipt_refs.is_empty() {
            return Err(L1SettlementAdmissionError::MissingSettlementReceipt);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum L1SettlementAdmissionError {
    #[error("invalid L1 settlement schema version: expected {expected}, got {actual}")]
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    #[error("L1 settlement attempt missing field: {0}")]
    MissingField(&'static str),
    #[error("L1 settlement attempt missing trigger")]
    MissingSettlementTrigger,
    #[error("L1 settlement attempt missing settlement receipt")]
    MissingSettlementReceipt,
    #[error("L1 settlement admission hash failed: {0}")]
    HashFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactPromotionReceipt {
    pub artifact_id: String,
    #[serde(default)]
    pub artifact_hashes: Vec<[u8; 32]>,
    pub generation_strategy: String,
    #[serde(default)]
    pub candidate_refs: Vec<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winning_candidate_ref: Option<[u8; 32]>,
    #[serde(default)]
    pub merge_receipt_refs: Vec<[u8; 32]>,
    pub validation_hash: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub render_eval_hash: Option<[u8; 32]>,
    pub execution_envelope_hash: [u8; 32],
    #[serde(default)]
    pub settlement_refs: Vec<[u8; 32]>,
    pub promotion_decision: String,
    pub promotion_reason: String,
}

impl ArtifactPromotionReceipt {
    pub fn canonical_hash(&self) -> Result<[u8; 32], String> {
        canonical_hash(self)
    }

    pub fn validate(&self) -> Result<(), PromotionValidationError> {
        if self.artifact_id.trim().is_empty() {
            return Err(PromotionValidationError::MissingArtifactId);
        }
        if self.artifact_hashes.is_empty() {
            return Err(PromotionValidationError::MissingArtifactHash);
        }
        if self.candidate_refs.is_empty() {
            return Err(PromotionValidationError::MissingCandidateRefs);
        }
        if self.settlement_refs.is_empty() {
            return Err(PromotionValidationError::MissingSettlementRefs);
        }
        if self.promotion_decision.trim().is_empty() {
            return Err(PromotionValidationError::MissingPromotionDecision);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PromotionValidationError {
    #[error("artifact promotion missing artifact id")]
    MissingArtifactId,
    #[error("artifact promotion missing artifact hash")]
    MissingArtifactHash,
    #[error("artifact promotion missing candidate refs")]
    MissingCandidateRefs,
    #[error("artifact promotion missing settlement refs")]
    MissingSettlementRefs,
    #[error("artifact promotion missing promotion decision")]
    MissingPromotionDecision,
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), L1SettlementAdmissionError> {
    if value.trim().is_empty() {
        Err(L1SettlementAdmissionError::MissingField(field))
    } else {
        Ok(())
    }
}

fn canonical_hash<T>(value: &T) -> Result<[u8; 32], String>
where
    T: Serialize,
{
    let canonical = serde_jcs::to_vec(value).map_err(|error| error.to_string())?;
    sha256(&canonical).map_err(|error| error.to_string())
}

impl From<String> for L1SettlementAdmissionError {
    fn from(error: String) -> Self {
        Self::HashFailed(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt() -> L1SettlementAttempt {
        L1SettlementAttempt {
            schema_version: L1_SETTLEMENT_ADMISSION_SCHEMA_VERSION.to_string(),
            settlement_ref: "l1://settlement/marketplace-transaction".to_string(),
            domain_ref: "agentgres://domain/service-marketplace".to_string(),
            state_root_ref: "sha256:domain-state-root".to_string(),
            trigger_refs: vec!["l1-trigger://service-contract/payment".to_string()],
            receipt_refs: vec!["receipt://local-settlement/payment".to_string()],
        }
    }

    #[test]
    fn admits_l1_settlement_attempt_with_trigger() {
        let record = L1SettlementTriggerGuard
            .admit(&attempt())
            .expect("L1 trigger admission");

        assert_eq!(
            record.schema_version,
            L1_SETTLEMENT_ADMISSION_SCHEMA_VERSION
        );
        assert_eq!(
            record.trigger_refs,
            vec!["l1-trigger://service-contract/payment"]
        );
        assert_ne!(record.admission_hash, [0u8; 32]);
    }

    #[test]
    fn l1_settlement_attempt_without_trigger_fails() {
        assert_eq!(
            L1_SETTLEMENT_WITHOUT_TRIGGER_NEGATIVE_CONFORMANCE,
            "L1 settlement attempt without trigger fails"
        );

        let mut attempt = attempt();
        attempt.trigger_refs.clear();
        let error = L1SettlementTriggerGuard
            .admit(&attempt)
            .expect_err("trigger is required");

        assert_eq!(error, L1SettlementAdmissionError::MissingSettlementTrigger);
    }

    #[test]
    fn l1_settlement_attempt_requires_receipt() {
        let mut attempt = attempt();
        attempt.receipt_refs.clear();
        let error = L1SettlementTriggerGuard
            .admit(&attempt)
            .expect_err("settlement receipt is required");

        assert_eq!(error, L1SettlementAdmissionError::MissingSettlementReceipt);
    }
}
