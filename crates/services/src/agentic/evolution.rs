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
use ioi_types::error::{TransactionError, UpgradeError};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GOVERNED_RUNTIME_IMPROVEMENT_SCHEMA_VERSION: &str = "ioi.governed_runtime_improvement.v1";
pub const DIRECT_EVOLUTION_MUTATION_RETIRED: &str =
    "direct EvolutionService::evolve manifest mutation is retired; use governed runtime-improvement proposal admission";

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
    #[serde(default)]
    pub agentgres_operation_ref: String,
    #[serde(default)]
    pub expected_heads: Vec<String>,
    #[serde(default)]
    pub state_root_before: String,
    #[serde(default)]
    pub state_root_after: String,
    #[serde(default)]
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
    CallerSuppliedAgentgresTruth,
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
    /// Legacy direct mutation entry point retained only as a fail-closed service boundary.
    #[method]
    pub fn evolve(
        &self,
        _state: &mut dyn StateAccess,
        _params: EvolveAgentParams,
        _ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        Err(TransactionError::Invalid(
            DIRECT_EVOLUTION_MUTATION_RETIRED.to_string(),
        ))
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
        let agentgres_truth =
            governed_improvement_agentgres_truth(proposal).map_err(|error| vec![error])?;
        let mut record = GovernedRuntimeImprovementAdmissionRecord {
            schema_version: GOVERNED_RUNTIME_IMPROVEMENT_SCHEMA_VERSION.to_string(),
            proposal_id: proposal.proposal_id.clone(),
            target_ref: proposal.target_ref.clone(),
            candidate_ref: proposal.candidate_ref.clone(),
            surface: proposal.surface.clone(),
            approval_ref: proposal.approval_ref.clone(),
            rollback_ref: proposal.rollback_ref.clone(),
            agentgres_operation_ref: agentgres_truth.agentgres_operation_ref,
            expected_heads: agentgres_truth.expected_heads,
            state_root_before: agentgres_truth.state_root_before,
            state_root_after: agentgres_truth.state_root_after,
            resulting_head: agentgres_truth.resulting_head,
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
        if !self.agentgres_operation_ref.trim().is_empty()
            || !self.expected_heads.is_empty()
            || !self.state_root_before.trim().is_empty()
            || !self.state_root_after.trim().is_empty()
            || !self.resulting_head.trim().is_empty()
        {
            errors.push(GovernedRuntimeImprovementError::CallerSuppliedAgentgresTruth);
        }
        if self.eval_receipt_refs.is_empty() {
            errors.push(GovernedRuntimeImprovementError::MissingEvalReceipt);
        }
        if self.verifier_receipt_refs.is_empty() {
            errors.push(GovernedRuntimeImprovementError::MissingVerifierReceipt);
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

struct GovernedImprovementAgentgresTruth {
    agentgres_operation_ref: String,
    expected_heads: Vec<String>,
    state_root_before: String,
    state_root_after: String,
    resulting_head: String,
}

fn governed_improvement_agentgres_truth(
    proposal: &GovernedRuntimeImprovementProposal,
) -> Result<GovernedImprovementAgentgresTruth, GovernedRuntimeImprovementError> {
    let proposal_hash = governed_improvement_proposal_hash(proposal)?;
    let suffix = proposal_hash
        .trim_start_matches("sha256:")
        .chars()
        .take(24)
        .collect::<String>();
    Ok(GovernedImprovementAgentgresTruth {
        agentgres_operation_ref: format!("agentgres://runtime-improvement/operations/{suffix}"),
        expected_heads: vec!["agentgres://runtime-improvement/head/current".to_string()],
        state_root_before: governed_improvement_state_root(proposal, "before", None)?,
        state_root_after: governed_improvement_state_root(proposal, "after", Some(&proposal_hash))?,
        resulting_head: format!("agentgres://runtime-improvement/head/{suffix}"),
    })
}

fn governed_improvement_proposal_hash(
    proposal: &GovernedRuntimeImprovementProposal,
) -> Result<String, GovernedRuntimeImprovementError> {
    let mut canonical = proposal.clone();
    canonical.agentgres_operation_ref.clear();
    canonical.expected_heads.clear();
    canonical.state_root_before.clear();
    canonical.state_root_after.clear();
    canonical.resulting_head.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| GovernedRuntimeImprovementError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[derive(Serialize)]
struct GovernedImprovementStateRootPayload<'a> {
    schema: &'static str,
    phase: &'a str,
    proposal_id: &'a str,
    target_ref: &'a str,
    candidate_ref: &'a str,
    approval_ref: &'a str,
    rollback_ref: &'a str,
    proposal_hash: Option<&'a str>,
}

fn governed_improvement_state_root(
    proposal: &GovernedRuntimeImprovementProposal,
    phase: &str,
    proposal_hash: Option<&str>,
) -> Result<String, GovernedRuntimeImprovementError> {
    let payload = GovernedImprovementStateRootPayload {
        schema: "ioi.agentgres.runtime_improvement_state_root.v1",
        phase,
        proposal_id: &proposal.proposal_id,
        target_ref: &proposal.target_ref,
        candidate_ref: &proposal.candidate_ref,
        approval_ref: &proposal.approval_ref,
        rollback_ref: &proposal.rollback_ref,
        proposal_hash,
    };
    let bytes = serde_json::to_vec(&payload)
        .map_err(|error| GovernedRuntimeImprovementError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[cfg(test)]
mod governed_improvement_tests {
    use super::*;
    use ioi_api::services::access::ServiceDirectory;
    use ioi_api::state::StateScanIter;
    use ioi_types::app::{AccountId, ChainId};
    use ioi_types::error::StateError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct CountingState {
        reads: AtomicUsize,
        writes: AtomicUsize,
    }

    impl StateAccess for CountingState {
        fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }

        fn insert(&mut self, _key: &[u8], _value: &[u8]) -> Result<(), StateError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn delete(&mut self, _key: &[u8]) -> Result<(), StateError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
            self.writes.fetch_add(updates.len(), Ordering::SeqCst);
            Ok(())
        }

        fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
            self.reads.fetch_add(keys.len(), Ordering::SeqCst);
            Ok(vec![None; keys.len()])
        }

        fn batch_apply(
            &mut self,
            inserts: &[(Vec<u8>, Vec<u8>)],
            deletes: &[Vec<u8>],
        ) -> Result<(), StateError> {
            self.writes
                .fetch_add(inserts.len() + deletes.len(), Ordering::SeqCst);
            Ok(())
        }

        fn prefix_scan(&self, _prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(std::iter::empty()))
        }
    }

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
            agentgres_operation_ref: String::new(),
            expected_heads: vec![],
            state_root_before: String::new(),
            state_root_after: String::new(),
            resulting_head: String::new(),
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
        assert!(record
            .agentgres_operation_ref
            .starts_with("agentgres://runtime-improvement/operations/"));
        assert_eq!(
            record.expected_heads,
            vec!["agentgres://runtime-improvement/head/current"]
        );
        assert!(record.state_root_before.starts_with("sha256:"));
        assert!(record.state_root_after.starts_with("sha256:"));
        assert!(record
            .resulting_head
            .starts_with("agentgres://runtime-improvement/head/"));
        assert!(record.admission_hash.starts_with("sha256:"));
    }

    #[test]
    fn governed_improvement_rejects_caller_supplied_agentgres_truth() {
        let mut proposal = proposal();
        proposal.agentgres_operation_ref =
            "agentgres://runtime-improvement/operations/client-supplied".to_string();
        proposal.expected_heads = vec!["agentgres://runtime-improvement/head/client".to_string()];
        proposal.state_root_before = "sha256:client-before".to_string();
        proposal.state_root_after = "sha256:client-after".to_string();
        proposal.resulting_head = "agentgres://runtime-improvement/head/client-after".to_string();

        let errors = GovernedEvolutionCore
            .admit_proposal(&proposal)
            .expect_err("client-supplied Agentgres truth must fail closed");

        assert!(errors.contains(&GovernedRuntimeImprovementError::CallerSuppliedAgentgresTruth));
    }

    #[test]
    fn direct_self_mutation_without_governed_proposal_fails_closed() {
        let mut proposal = proposal();
        proposal.eval_receipt_refs.clear();
        proposal.verifier_receipt_refs.clear();
        proposal.approval_ref.clear();
        proposal.rollback_ref.clear();

        let errors = GovernedEvolutionCore
            .admit_proposal(&proposal)
            .expect_err("ungoverned self mutation must fail closed");

        assert!(errors.contains(&GovernedRuntimeImprovementError::MissingEvalReceipt));
        assert!(errors.contains(&GovernedRuntimeImprovementError::MissingVerifierReceipt));
        assert!(errors.contains(&GovernedRuntimeImprovementError::MissingApprovalRef));
        assert!(errors.contains(&GovernedRuntimeImprovementError::MissingRollbackRef));
    }

    #[test]
    fn direct_evolve_manifest_mutation_is_retired_fail_closed() {
        let mut state = CountingState::default();
        let services = ServiceDirectory::default();
        let ctx = TxContext {
            block_height: 1,
            block_timestamp: 1,
            chain_id: ChainId(1),
            signer_account_id: AccountId([7; 32]),
            services: &services,
            simulation: false,
            is_internal: false,
        };

        let error = EvolutionService
            .evolve(
                &mut state,
                EvolveAgentParams {
                    target_service_id: "agent://legacy-evolve".to_string(),
                    new_manifest: "{}".to_string(),
                    rationale: "legacy direct mutation should fail closed".to_string(),
                },
                &ctx,
            )
            .expect_err("direct evolve mutation must be retired");

        match error {
            TransactionError::Invalid(message) => {
                assert_eq!(message, DIRECT_EVOLUTION_MUTATION_RETIRED);
            }
            other => panic!("unexpected direct evolve error: {other:?}"),
        }
        assert_eq!(state.reads.load(Ordering::SeqCst), 0);
        assert_eq!(state.writes.load(Ordering::SeqCst), 0);
    }
}
