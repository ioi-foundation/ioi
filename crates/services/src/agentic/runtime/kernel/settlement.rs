use ioi_crypto::algorithms::hash::sha256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

fn canonical_hash<T>(value: &T) -> Result<[u8; 32], String>
where
    T: Serialize,
{
    let canonical = serde_jcs::to_vec(value).map_err(|error| error.to_string())?;
    sha256(&canonical).map_err(|error| error.to_string())
}
