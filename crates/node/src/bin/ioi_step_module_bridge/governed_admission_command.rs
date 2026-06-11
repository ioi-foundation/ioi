use ioi_services::agentic::evolution::{GovernedEvolutionCore, GovernedRuntimeImprovementProposal};
use ioi_services::agentic::runtime::kernel::settlement::{
    L1SettlementAttempt, L1SettlementTriggerGuard,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::BridgeError;

#[derive(Debug, Deserialize)]
pub(super) struct L1SettlementAdmissionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    attempt: L1SettlementAttempt,
}

#[derive(Debug, Deserialize)]
pub(super) struct GovernedRuntimeImprovementBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    proposal: GovernedRuntimeImprovementProposal,
}

pub(super) fn admit_l1_settlement_attempt(
    request: L1SettlementAdmissionBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = L1SettlementTriggerGuard
        .admit(&request.attempt)
        .map_err(|error| {
            BridgeError::new("l1_settlement_admission_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_l1_settlement_guard_command",
        "backend": request.backend.unwrap_or_else(|| "l1_settlement_guard".to_string()),
        "record": record.clone(),
        "settlement_ref": record.settlement_ref,
        "domain_ref": record.domain_ref,
        "state_root_ref": record.state_root_ref,
        "trigger_refs": record.trigger_refs,
        "receipt_refs": record.receipt_refs,
        "admission_hash": record.admission_hash,
    }))
}

pub(super) fn admit_governed_runtime_improvement_proposal(
    request: GovernedRuntimeImprovementBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = GovernedEvolutionCore
        .admit_proposal(&request.proposal)
        .map_err(|error| {
            BridgeError::new("governed_runtime_improvement_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_governed_meta_improvement_command",
        "backend": request.backend.unwrap_or_else(|| "rust_governed_evolution".to_string()),
        "record": record.clone(),
        "proposal_id": record.proposal_id.clone(),
        "target_ref": record.target_ref.clone(),
        "candidate_ref": record.candidate_ref.clone(),
        "admission_hash": record.admission_hash.clone(),
        "agentgres_operation_ref": record.agentgres_operation_ref.clone(),
        "expected_heads": record.expected_heads.clone(),
        "state_root_before": record.state_root_before.clone(),
        "state_root_after": record.state_root_after.clone(),
        "resulting_head": record.resulting_head.clone(),
        "eval_receipt_refs": record.eval_receipt_refs.clone(),
        "verifier_receipt_refs": record.verifier_receipt_refs.clone(),
        "approval_ref": record.approval_ref.clone(),
        "rollback_ref": record.rollback_ref.clone(),
    }))
}
