use super::step_module::{
    StepModuleInvocation, StepModuleResult, StepModuleStatus, StepModuleValidationError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const STEP_MODULE_RECEIPT_BINDING_SCHEMA_VERSION: &str = "ioi.step_module_receipt_binding.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptBindingError {
    InvalidInvocation(Vec<StepModuleValidationError>),
    InvalidResult(Vec<StepModuleValidationError>),
    InvocationResultMismatch,
    AcceptedResultMissingReceipt,
    AgentgresOperationMissingExpectedHeads,
    AgentgresOperationMissingStateBinding,
    StateRootAfterWithoutBefore,
    HashFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepModuleReceiptBinding {
    pub schema_version: String,
    pub invocation_id: String,
    pub receipt_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub payload_refs: Vec<String>,
    pub agentgres_operation_refs: Vec<String>,
    pub expected_heads: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resulting_head: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_watermark: Option<String>,
    pub binding_hash: String,
}

#[derive(Debug, Default, Clone)]
pub struct ReceiptBinder;

impl ReceiptBinder {
    pub fn bind_step_module_result(
        &self,
        invocation: &StepModuleInvocation,
        result: &StepModuleResult,
        expected_heads: Vec<String>,
    ) -> Result<StepModuleReceiptBinding, ReceiptBindingError> {
        invocation
            .validate()
            .map_err(ReceiptBindingError::InvalidInvocation)?;
        result
            .validate()
            .map_err(ReceiptBindingError::InvalidResult)?;
        if invocation.invocation_id != result.invocation_id {
            return Err(ReceiptBindingError::InvocationResultMismatch);
        }
        if matches!(
            result.status,
            StepModuleStatus::Success | StepModuleStatus::Partial
        ) && result.receipt_refs.is_empty()
        {
            return Err(ReceiptBindingError::AcceptedResultMissingReceipt);
        }
        if !result.agentgres_operation_refs.is_empty() {
            if expected_heads.is_empty() {
                return Err(ReceiptBindingError::AgentgresOperationMissingExpectedHeads);
            }
            if result.state_root_after.is_none() || result.resulting_head.is_none() {
                return Err(ReceiptBindingError::AgentgresOperationMissingStateBinding);
            }
        }
        if result.state_root_after.is_some() && invocation.input.state_root_before.is_none() {
            return Err(ReceiptBindingError::StateRootAfterWithoutBefore);
        }

        let mut binding = StepModuleReceiptBinding {
            schema_version: STEP_MODULE_RECEIPT_BINDING_SCHEMA_VERSION.to_string(),
            invocation_id: result.invocation_id.clone(),
            receipt_refs: result.receipt_refs.clone(),
            artifact_refs: result.artifact_refs.clone(),
            payload_refs: result.payload_refs.clone(),
            agentgres_operation_refs: result.agentgres_operation_refs.clone(),
            expected_heads,
            state_root_before: invocation.input.state_root_before.clone(),
            state_root_after: result.state_root_after.clone(),
            resulting_head: result.resulting_head.clone(),
            projection_watermark: invocation.input.projection_watermark.clone(),
            binding_hash: String::new(),
        };
        binding.binding_hash = binding_hash(&binding)?;
        Ok(binding)
    }
}

fn binding_hash(binding: &StepModuleReceiptBinding) -> Result<String, ReceiptBindingError> {
    let mut canonical = binding.clone();
    canonical.binding_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ReceiptBindingError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::step_module::{
        StepModuleActor, StepModuleAuthority, StepModuleBackend, StepModuleCustody,
        StepModuleExecution, StepModuleInput, StepModuleKind, StepModuleNext,
        StepModulePlaintextPolicy, StepModulePrivacyProfile, StepModuleProjectionStatus,
        StepModuleRef, StepModuleWorkflowProjection, STEP_MODULE_INVOCATION_SCHEMA_VERSION,
        STEP_MODULE_RESULT_SCHEMA_VERSION,
    };

    fn invocation() -> StepModuleInvocation {
        StepModuleInvocation {
            schema_version: STEP_MODULE_INVOCATION_SCHEMA_VERSION.to_string(),
            invocation_id: "invocation://receipt-test".to_string(),
            run_id: "run:test".to_string(),
            task_id: "task:test".to_string(),
            thread_id: None,
            workflow_graph_id: Some("workflow:test".to_string()),
            workflow_node_id: Some("node:test".to_string()),
            context_chamber_ref: None,
            action_proposal_ref: "action:test".to_string(),
            gate_result_ref: "gate:test".to_string(),
            module_ref: StepModuleRef {
                kind: StepModuleKind::WorkloadJob,
                id: "workspace.status".to_string(),
                version: "1".to_string(),
                manifest_ref: None,
            },
            actor: StepModuleActor {
                actor_id: "runtime:hypervisor-daemon".to_string(),
                runtime_node_ref: "node://local".to_string(),
            },
            authority: StepModuleAuthority {
                authority_grant_refs: vec![],
                policy_hash: "sha256:policy".to_string(),
                primitive_capabilities: vec!["prim:workspace.status".to_string()],
                authority_scopes: vec![],
                approval_ref: None,
            },
            input: StepModuleInput {
                input_hash: "sha256:input".to_string(),
                expected_schema_ref: "schema://coding-tool/workspace.status/input".to_string(),
                context_refs: vec![],
                artifact_refs: vec![],
                payload_refs: vec![],
                state_root_before: Some("sha256:before".to_string()),
                projection_watermark: Some("domain_seq:7".to_string()),
                data_plane_handle: None,
            },
            custody: StepModuleCustody {
                privacy_profile: StepModulePrivacyProfile::Internal,
                plaintext_policy: StepModulePlaintextPolicy {
                    node_plaintext_allowed: true,
                    declassification_required: false,
                },
                custody_proof_ref: None,
                leakage_profile_ref: None,
            },
            execution: StepModuleExecution {
                backend: StepModuleBackend::WorkloadGrpc,
                idempotency_key: "idem:test".to_string(),
                deadline_ms: 1_000,
                resource_lease_ref: None,
                retry_policy_ref: None,
            },
        }
    }

    fn result() -> StepModuleResult {
        StepModuleResult {
            schema_version: STEP_MODULE_RESULT_SCHEMA_VERSION.to_string(),
            invocation_id: "invocation://receipt-test".to_string(),
            status: StepModuleStatus::Success,
            execution_result_ref: "result:test".to_string(),
            normalized_observation_ref: "observation:test".to_string(),
            receipt_refs: vec!["receipt:test".to_string()],
            artifact_refs: vec!["artifact:test".to_string()],
            payload_refs: vec!["payload:test".to_string()],
            agentgres_operation_refs: vec!["agentgres://operation/test".to_string()],
            state_root_after: Some("sha256:after".to_string()),
            resulting_head: Some("sha256:head".to_string()),
            workflow_projection: StepModuleWorkflowProjection {
                workflow_graph_id: "workflow:test".to_string(),
                workflow_node_id: "node:test".to_string(),
                component_kind: "CodingToolNode".to_string(),
                status: StepModuleProjectionStatus::Shadow,
                attempt_id: "attempt:test".to_string(),
                evidence_refs: vec![],
                receipt_refs: vec!["receipt:test".to_string()],
            },
            next: StepModuleNext {
                model_reentry_required: false,
                verifier_required: false,
            },
        }
    }

    #[test]
    fn receipt_binder_binds_expected_heads_and_state_roots() {
        let binding = ReceiptBinder
            .bind_step_module_result(
                &invocation(),
                &result(),
                vec!["sha256:head-before".to_string()],
            )
            .expect("valid binding");

        assert_eq!(
            binding.schema_version,
            STEP_MODULE_RECEIPT_BINDING_SCHEMA_VERSION
        );
        assert_eq!(binding.state_root_before.as_deref(), Some("sha256:before"));
        assert_eq!(binding.state_root_after.as_deref(), Some("sha256:after"));
        assert_eq!(binding.resulting_head.as_deref(), Some("sha256:head"));
        assert_eq!(binding.expected_heads, vec!["sha256:head-before"]);
        assert!(binding.binding_hash.starts_with("sha256:"));
    }

    #[test]
    fn agentgres_operation_without_expected_heads_fails_closed() {
        let error = ReceiptBinder
            .bind_step_module_result(&invocation(), &result(), vec![])
            .expect_err("expected heads are required");

        assert_eq!(
            error,
            ReceiptBindingError::AgentgresOperationMissingExpectedHeads
        );
    }

    #[test]
    fn state_root_after_without_state_root_before_fails_closed() {
        let mut invocation = invocation();
        invocation.input.state_root_before = None;

        let error = ReceiptBinder
            .bind_step_module_result(
                &invocation,
                &result(),
                vec!["sha256:head-before".to_string()],
            )
            .expect_err("before root is required when after root exists");

        assert_eq!(error, ReceiptBindingError::StateRootAfterWithoutBefore);
    }
}
