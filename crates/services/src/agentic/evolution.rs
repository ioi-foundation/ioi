// Path: crates/services/src/agentic/evolution.rs

//! The Evolution Service.
//!
//! Handles "Sovereign Updates" for local agents. Unlike `Governance`, which requires
//! consensus voting for network-wide changes, `Evolution` allows an owner to
//! atomically upgrade their own agents/services without permission from the network.

use async_trait::async_trait;
use ioi_api::services::UpgradableService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_macros::service_interface;
use ioi_types::app::agentic::AgentManifest;
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::ActiveServiceMeta;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GOVERNED_RUNTIME_IMPROVEMENT_SCHEMA_VERSION: &str = "ioi.governed_runtime_improvement.v1";

/// Parameters to evolve a specific agent.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct EvolveAgentParams {
    /// The ID of the service/agent to upgrade.
    pub target_service_id: String,
    /// The new manifest JSON string.
    pub new_manifest: String,
    /// The rationale/reason for this evolution (audit trail).
    pub rationale: String,
}

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeImprovementSurface {
    Skill,
    Module,
    Workflow,
    Route,
    Schema,
    Policy,
}

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GovernedRuntimeImprovementProposal {
    pub schema_version: String,
    pub proposal_id: String,
    pub target_ref: String,
    pub candidate_ref: String,
    pub surface: RuntimeImprovementSurface,
    pub source_trace_ref: String,
    #[serde(default)]
    pub eval_receipt_refs: Vec<String>,
    #[serde(default)]
    pub verifier_receipt_refs: Vec<String>,
    pub approval_ref: String,
    pub rollback_ref: String,
    pub agentgres_operation_ref: String,
    #[serde(default)]
    pub expected_heads: Vec<String>,
    pub state_root_before: String,
    pub state_root_after: String,
    pub resulting_head: String,
}

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GovernedRuntimeImprovementAdmissionRecord {
    pub schema_version: String,
    pub proposal_id: String,
    pub target_ref: String,
    pub candidate_ref: String,
    pub surface: RuntimeImprovementSurface,
    pub approval_ref: String,
    pub rollback_ref: String,
    pub agentgres_operation_ref: String,
    pub expected_heads: Vec<String>,
    pub state_root_before: String,
    pub state_root_after: String,
    pub resulting_head: String,
    pub eval_receipt_refs: Vec<String>,
    pub verifier_receipt_refs: Vec<String>,
    pub admission_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernedRuntimeImprovementError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingProposalId,
    MissingTargetRef,
    MissingCandidateRef,
    MissingSourceTraceRef,
    MissingEvalReceipt,
    MissingVerifierReceipt,
    MissingApprovalRef,
    MissingRollbackRef,
    MissingAgentgresOperationRef,
    MissingExpectedHeads,
    MissingStateRootBefore,
    MissingStateRootAfter,
    MissingResultingHead,
    HashFailed(String),
}

#[derive(Default, Debug, Clone)]
pub struct GovernedEvolutionCore;

#[derive(Default, Debug, Clone)]
pub struct EvolutionService;

#[async_trait]
impl UpgradableService for EvolutionService {
    async fn prepare_upgrade(&self, _new: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }
    async fn complete_upgrade(&self, _snap: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

#[service_interface(
    id = "evolution",
    abi_version = 1,
    state_schema = "v1",
    capabilities = ""
)]
impl EvolutionService {
    /// Atomically upgrades an agent if the signer is the owner/author.
    #[method]
    pub fn evolve(
        &self,
        state: &mut dyn StateAccess,
        params: EvolveAgentParams,
        ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        let service_id = &params.target_service_id;

        // 1. Fetch Current Metadata
        let meta_key = active_service_key(service_id);
        let meta_bytes = state
            .get(&meta_key)?
            .ok_or(TransactionError::Invalid(format!(
                "Target service '{}' not found",
                service_id
            )))?;

        let mut meta: ActiveServiceMeta = codec::from_bytes_canonical(&meta_bytes)?;

        // 2. Authorization Check (Sovereignty)
        // Only the documented author can evolve the agent.
        if let Some(author) = meta.author {
            if author != ctx.signer_account_id {
                return Err(TransactionError::UnauthorizedByCredentials);
            }
        } else {
            // If no author is set (e.g. system service), we default to fail-safe or governance check.
            // For now, strict fail-safe: unowned agents cannot be evolved by users.
            return Err(TransactionError::Invalid("Service has no owner".into()));
        }

        // 3. Verify Manifest Validity & Parse
        // We enforce that the new config parses as a valid AgentManifest.
        let _new_manifest_struct: AgentManifest = serde_json::from_str(&params.new_manifest)
            .map_err(|e| TransactionError::Invalid(format!("Invalid new manifest JSON: {}", e)))?;

        // 4. Update Evolution State (Versioned Storage)
        let new_gen = meta.generation_id + 1;

        // Canonical Key: evolution::manifest::{service_id}::{gen}
        let manifest_key = [
            b"evolution::manifest::",
            service_id.as_bytes(),
            b"::",
            &new_gen.to_le_bytes(),
        ]
        .concat();
        state.insert(&manifest_key, params.new_manifest.as_bytes())?;

        // Pointer Key: evolution::latest::{service_id} -> gen
        let latest_key = [b"evolution::latest::", service_id.as_bytes()].concat();
        state.insert(&latest_key, &new_gen.to_le_bytes())?;

        // Rationale Key: evolution::rationale::{service_id}::{gen}
        let rationale_key = [
            b"evolution::rationale::",
            service_id.as_bytes(),
            b"::",
            &new_gen.to_le_bytes(),
        ]
        .concat();
        state.insert(&rationale_key, params.rationale.as_bytes())?;

        // 5. Update Active Metadata
        meta.generation_id = new_gen;
        // In a real system, we'd hash the manifest. For now, we update the meta record.
        // Ideally, `artifact_hash` should reflect the new logic if code changed, but here we just update manifest.
        state.insert(&meta_key, &codec::to_bytes_canonical(&meta)?)?;

        log::info!(
            "Evolution: Evolved agent '{}' to Gen {}. Owner: 0x{}",
            service_id,
            new_gen,
            hex::encode(ctx.signer_account_id)
        );

        Ok(())
    }
}

impl EvolutionService {
    pub fn admit_governed_improvement(
        &self,
        proposal: &GovernedRuntimeImprovementProposal,
    ) -> Result<GovernedRuntimeImprovementAdmissionRecord, Vec<GovernedRuntimeImprovementError>>
    {
        GovernedEvolutionCore.admit_proposal(proposal)
    }
}

impl GovernedEvolutionCore {
    pub fn admit_proposal(
        &self,
        proposal: &GovernedRuntimeImprovementProposal,
    ) -> Result<GovernedRuntimeImprovementAdmissionRecord, Vec<GovernedRuntimeImprovementError>>
    {
        proposal.validate()?;
        let mut record = GovernedRuntimeImprovementAdmissionRecord {
            schema_version: GOVERNED_RUNTIME_IMPROVEMENT_SCHEMA_VERSION.to_string(),
            proposal_id: proposal.proposal_id.clone(),
            target_ref: proposal.target_ref.clone(),
            candidate_ref: proposal.candidate_ref.clone(),
            surface: proposal.surface.clone(),
            approval_ref: proposal.approval_ref.clone(),
            rollback_ref: proposal.rollback_ref.clone(),
            agentgres_operation_ref: proposal.agentgres_operation_ref.clone(),
            expected_heads: proposal.expected_heads.clone(),
            state_root_before: proposal.state_root_before.clone(),
            state_root_after: proposal.state_root_after.clone(),
            resulting_head: proposal.resulting_head.clone(),
            eval_receipt_refs: proposal.eval_receipt_refs.clone(),
            verifier_receipt_refs: proposal.verifier_receipt_refs.clone(),
            admission_hash: String::new(),
        };
        record.admission_hash =
            governed_improvement_admission_hash(&record).map_err(|error| vec![error])?;
        Ok(record)
    }
}

impl GovernedRuntimeImprovementProposal {
    pub fn validate(&self) -> Result<(), Vec<GovernedRuntimeImprovementError>> {
        let mut errors = Vec::new();
        if self.schema_version != GOVERNED_RUNTIME_IMPROVEMENT_SCHEMA_VERSION {
            errors.push(GovernedRuntimeImprovementError::InvalidSchemaVersion {
                expected: GOVERNED_RUNTIME_IMPROVEMENT_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty(
            &mut errors,
            "proposal_id",
            &self.proposal_id,
            GovernedRuntimeImprovementError::MissingProposalId,
        );
        require_non_empty(
            &mut errors,
            "target_ref",
            &self.target_ref,
            GovernedRuntimeImprovementError::MissingTargetRef,
        );
        require_non_empty(
            &mut errors,
            "candidate_ref",
            &self.candidate_ref,
            GovernedRuntimeImprovementError::MissingCandidateRef,
        );
        require_non_empty(
            &mut errors,
            "source_trace_ref",
            &self.source_trace_ref,
            GovernedRuntimeImprovementError::MissingSourceTraceRef,
        );
        require_non_empty(
            &mut errors,
            "approval_ref",
            &self.approval_ref,
            GovernedRuntimeImprovementError::MissingApprovalRef,
        );
        require_non_empty(
            &mut errors,
            "rollback_ref",
            &self.rollback_ref,
            GovernedRuntimeImprovementError::MissingRollbackRef,
        );
        require_non_empty(
            &mut errors,
            "agentgres_operation_ref",
            &self.agentgres_operation_ref,
            GovernedRuntimeImprovementError::MissingAgentgresOperationRef,
        );
        require_non_empty(
            &mut errors,
            "state_root_before",
            &self.state_root_before,
            GovernedRuntimeImprovementError::MissingStateRootBefore,
        );
        require_non_empty(
            &mut errors,
            "state_root_after",
            &self.state_root_after,
            GovernedRuntimeImprovementError::MissingStateRootAfter,
        );
        require_non_empty(
            &mut errors,
            "resulting_head",
            &self.resulting_head,
            GovernedRuntimeImprovementError::MissingResultingHead,
        );
        if self.eval_receipt_refs.is_empty() {
            errors.push(GovernedRuntimeImprovementError::MissingEvalReceipt);
        }
        if self.verifier_receipt_refs.is_empty() {
            errors.push(GovernedRuntimeImprovementError::MissingVerifierReceipt);
        }
        if self.expected_heads.is_empty() {
            errors.push(GovernedRuntimeImprovementError::MissingExpectedHeads);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn require_non_empty(
    errors: &mut Vec<GovernedRuntimeImprovementError>,
    _field: &'static str,
    value: &str,
    error: GovernedRuntimeImprovementError,
) {
    if value.trim().is_empty() {
        errors.push(error);
    }
}

fn governed_improvement_admission_hash(
    record: &GovernedRuntimeImprovementAdmissionRecord,
) -> Result<String, GovernedRuntimeImprovementError> {
    let mut canonical = record.clone();
    canonical.admission_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| GovernedRuntimeImprovementError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[cfg(test)]
mod governed_improvement_tests {
    use super::*;

    fn proposal() -> GovernedRuntimeImprovementProposal {
        GovernedRuntimeImprovementProposal {
            schema_version: GOVERNED_RUNTIME_IMPROVEMENT_SCHEMA_VERSION.to_string(),
            proposal_id: "proposal://runtime-improvement/skill-1".to_string(),
            target_ref: "skill://runtime-auditor/current".to_string(),
            candidate_ref: "skill-candidate://runtime-auditor/from-trace".to_string(),
            surface: RuntimeImprovementSurface::Skill,
            source_trace_ref: "trace://run/high-fitness".to_string(),
            eval_receipt_refs: vec!["receipt://eval/holdout-pass".to_string()],
            verifier_receipt_refs: vec!["receipt://verifier/regression-pass".to_string()],
            approval_ref: "approval://wallet/runtime-improvement".to_string(),
            rollback_ref: "rollback://skill/runtime-auditor/current".to_string(),
            agentgres_operation_ref: "agentgres://runtime-improvement/operations/skill-1"
                .to_string(),
            expected_heads: vec!["agentgres://runtime-improvement/head/before".to_string()],
            state_root_before: "sha256:before".to_string(),
            state_root_after: "sha256:after".to_string(),
            resulting_head: "agentgres://runtime-improvement/head/after".to_string(),
        }
    }

    #[test]
    fn governed_improvement_proposal_admits_eval_approval_rollback_and_agentgres() {
        let record = GovernedEvolutionCore
            .admit_proposal(&proposal())
            .expect("governed proposal admitted");

        assert_eq!(
            record.schema_version,
            GOVERNED_RUNTIME_IMPROVEMENT_SCHEMA_VERSION
        );
        assert_eq!(record.surface, RuntimeImprovementSurface::Skill);
        assert_eq!(
            record.eval_receipt_refs,
            vec!["receipt://eval/holdout-pass"]
        );
        assert_eq!(
            record.verifier_receipt_refs,
            vec!["receipt://verifier/regression-pass"]
        );
        assert_eq!(record.approval_ref, "approval://wallet/runtime-improvement");
        assert_eq!(
            record.rollback_ref,
            "rollback://skill/runtime-auditor/current"
        );
        assert_eq!(
            record.expected_heads,
            vec!["agentgres://runtime-improvement/head/before"]
        );
        assert!(record.admission_hash.starts_with("sha256:"));
    }

    #[test]
    fn direct_self_mutation_without_governed_proposal_fails_closed() {
        let mut proposal = proposal();
        proposal.eval_receipt_refs.clear();
        proposal.verifier_receipt_refs.clear();
        proposal.approval_ref.clear();
        proposal.rollback_ref.clear();
        proposal.expected_heads.clear();

        let errors = GovernedEvolutionCore
            .admit_proposal(&proposal)
            .expect_err("ungoverned self mutation must fail closed");

        assert!(errors.contains(&GovernedRuntimeImprovementError::MissingEvalReceipt));
        assert!(errors.contains(&GovernedRuntimeImprovementError::MissingVerifierReceipt));
        assert!(errors.contains(&GovernedRuntimeImprovementError::MissingApprovalRef));
        assert!(errors.contains(&GovernedRuntimeImprovementError::MissingRollbackRef));
        assert!(errors.contains(&GovernedRuntimeImprovementError::MissingExpectedHeads));
    }
}
