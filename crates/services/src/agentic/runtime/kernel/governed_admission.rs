use serde::Deserialize;
use serde_json::{json, Value};

use crate::agentic::evolution::{GovernedEvolutionCore, GovernedRuntimeImprovementProposal};

use super::settlement::{L1SettlementAttempt, L1SettlementTriggerGuard};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedAdmissionError {
    code: &'static str,
    message: String,
}

impl GovernedAdmissionError {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Deserialize)]
pub struct L1SettlementAdmissionBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub attempt: L1SettlementAttempt,
}

#[derive(Debug, Deserialize)]
pub struct GovernedRuntimeImprovementBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub proposal: GovernedRuntimeImprovementProposal,
}

pub fn admit_l1_settlement_attempt_response(
    request: L1SettlementAdmissionBridgeRequest,
) -> Result<Value, GovernedAdmissionError> {
    let record = L1SettlementTriggerGuard
        .admit(&request.attempt)
        .map_err(|error| {
            GovernedAdmissionError::new("l1_settlement_admission_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "schema_version": "ioi.runtime.l1_settlement_admission.v1",
        "object": "ioi.runtime_l1_settlement_admission",
        "status": "admitted",
        "settlement_admitted": true,
        "source": "rust_l1_settlement_guard_command",
        "backend": request.backend.unwrap_or_else(|| "l1_settlement_guard".to_string()),
        "thread_id": request.thread_id,
        "agent_id": request.agent_id,
        "record": record.clone(),
        "settlement_ref": record.settlement_ref,
        "domain_ref": record.domain_ref,
        "state_root_ref": record.state_root_ref,
        "trigger_refs": record.trigger_refs,
        "receipt_refs": record.receipt_refs,
        "admission_hash": record.admission_hash,
    }))
}

pub fn admit_governed_runtime_improvement_proposal_response(
    request: GovernedRuntimeImprovementBridgeRequest,
) -> Result<Value, GovernedAdmissionError> {
    let record = GovernedEvolutionCore
        .admit_proposal(&request.proposal)
        .map_err(|error| {
            GovernedAdmissionError::new(
                "governed_runtime_improvement_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "schema_version": "ioi.runtime.governed_improvement_admission.v1",
        "object": "ioi.runtime_governed_improvement_admission",
        "status": "admitted",
        "proposal_admitted": true,
        "mutation_executed": false,
        "source": "rust_governed_meta_improvement_command",
        "backend": request.backend.unwrap_or_else(|| "rust_governed_evolution".to_string()),
        "thread_id": request.thread_id,
        "agent_id": request.agent_id,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::evolution::{
        RuntimeImprovementSurface, GOVERNED_RUNTIME_IMPROVEMENT_SCHEMA_VERSION,
    };
    use crate::agentic::runtime::kernel::settlement::L1_SETTLEMENT_ADMISSION_SCHEMA_VERSION;

    #[test]
    fn rust_core_shapes_l1_settlement_response() {
        let response = admit_l1_settlement_attempt_response(L1SettlementAdmissionBridgeRequest {
            backend: Some("l1_settlement_guard".to_string()),
            thread_id: Some("thread:l1".to_string()),
            agent_id: Some("agent:l1".to_string()),
            attempt: L1SettlementAttempt {
                schema_version: L1_SETTLEMENT_ADMISSION_SCHEMA_VERSION.to_string(),
                settlement_ref: "l1://settlement/marketplace-transaction".to_string(),
                domain_ref: "domain://marketplace/services".to_string(),
                state_root_ref: "state-root://agentgres/marketplace/after".to_string(),
                trigger_refs: vec!["l1-trigger://service-contract/payment".to_string()],
                receipt_refs: vec!["receipt://local-settlement/payment".to_string()],
            },
        })
        .expect("L1 settlement response");

        assert_eq!(response["source"], "rust_l1_settlement_guard_command");
        assert_eq!(response["backend"], "l1_settlement_guard");
        assert_eq!(
            response["schema_version"],
            "ioi.runtime.l1_settlement_admission.v1"
        );
        assert_eq!(response["object"], "ioi.runtime_l1_settlement_admission");
        assert_eq!(response["status"], "admitted");
        assert_eq!(response["settlement_admitted"], true);
        assert_eq!(response["thread_id"], "thread:l1");
        assert_eq!(response["agent_id"], "agent:l1");
        assert_eq!(
            response["settlement_ref"],
            "l1://settlement/marketplace-transaction"
        );
        assert_eq!(
            response["record"]["receipt_refs"][0],
            "receipt://local-settlement/payment"
        );
    }

    #[test]
    fn rust_core_shapes_governed_improvement_response() {
        let response = admit_governed_runtime_improvement_proposal_response(
            GovernedRuntimeImprovementBridgeRequest {
                backend: Some("rust_governed_evolution".to_string()),
                thread_id: Some("thread:governed".to_string()),
                agent_id: Some("agent:governed".to_string()),
                proposal: GovernedRuntimeImprovementProposal {
                    schema_version: GOVERNED_RUNTIME_IMPROVEMENT_SCHEMA_VERSION.to_string(),
                    proposal_id: "proposal://runtime-improvement/core".to_string(),
                    target_ref: "skill://runtime-auditor/current".to_string(),
                    candidate_ref: "skill-candidate://runtime-auditor/from-trace".to_string(),
                    surface: RuntimeImprovementSurface::Skill,
                    source_trace_ref: "trace://runtime-improvement/high-fitness".to_string(),
                    eval_receipt_refs: vec!["receipt://eval/core-holdout-pass".to_string()],
                    verifier_receipt_refs: vec![
                        "receipt://verifier/core-regression-pass".to_string()
                    ],
                    approval_ref: "approval://wallet/runtime-improvement/core".to_string(),
                    rollback_ref: "rollback://skill/runtime-auditor/current".to_string(),
                    agentgres_operation_ref: String::new(),
                    expected_heads: vec![],
                    state_root_before: String::new(),
                    state_root_after: String::new(),
                    resulting_head: String::new(),
                },
            },
        )
        .expect("governed improvement response");

        assert_eq!(response["source"], "rust_governed_meta_improvement_command");
        assert_eq!(response["backend"], "rust_governed_evolution");
        assert_eq!(
            response["schema_version"],
            "ioi.runtime.governed_improvement_admission.v1"
        );
        assert_eq!(
            response["object"],
            "ioi.runtime_governed_improvement_admission"
        );
        assert_eq!(response["status"], "admitted");
        assert_eq!(response["proposal_admitted"], true);
        assert_eq!(response["mutation_executed"], false);
        assert_eq!(response["thread_id"], "thread:governed");
        assert_eq!(response["agent_id"], "agent:governed");
        assert_eq!(
            response["proposal_id"],
            "proposal://runtime-improvement/core"
        );
        assert!(response["agentgres_operation_ref"]
            .as_str()
            .expect("operation ref")
            .starts_with("agentgres://runtime-improvement/operations/"));
    }
}
