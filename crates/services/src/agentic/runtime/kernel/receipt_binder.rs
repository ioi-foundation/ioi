use super::step_module::{
    StepModuleInvocation, StepModuleResult, StepModuleStatus, StepModuleValidationError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const STEP_MODULE_RECEIPT_BINDING_SCHEMA_VERSION: &str = "ioi.step_module_receipt_binding.v1";
pub const ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION: &str = "ioi.accepted_receipt_append.v1";
pub const DIRECT_ACCEPTED_RECEIPT_APPEND_NEGATIVE_CONFORMANCE: &str =
    "direct accepted receipt append outside the Rust core fails";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptBindingError {
    InvalidAcceptedReceiptAppendSchema {
        expected: &'static str,
        actual: String,
    },
    InvalidInvocation(Vec<StepModuleValidationError>),
    InvalidResult(Vec<StepModuleValidationError>),
    MissingField(&'static str),
    InvocationResultMismatch,
    AcceptedResultMissingReceipt,
    AgentgresOperationMissingExpectedHeads,
    AgentgresOperationMissingStateBinding,
    StateRootAfterWithoutBefore,
    DirectAcceptedReceiptAppendOutsideRustCore,
    ReceiptBindingHashMismatch,
    ReceiptNotBoundToResult,
    AcceptedReceiptStateRootMismatch,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptedReceiptAppendIssuer {
    RustReceiptCore,
    DaemonJsFacade,
    ExternalAdapter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedReceiptAppendRequest {
    pub schema_version: String,
    pub receipt_ref: String,
    pub invocation_id: String,
    pub receipt_binding_ref: String,
    pub issuer: AcceptedReceiptAppendIssuer,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resulting_head: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedReceiptAppendRecord {
    pub schema_version: String,
    pub receipt_ref: String,
    pub invocation_id: String,
    pub receipt_binding_ref: String,
    pub state_root_before: Option<String>,
    pub state_root_after: Option<String>,
    pub resulting_head: Option<String>,
    pub append_hash: String,
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

    pub fn append_accepted_receipt(
        &self,
        request: &AcceptedReceiptAppendRequest,
        binding: &StepModuleReceiptBinding,
    ) -> Result<AcceptedReceiptAppendRecord, ReceiptBindingError> {
        if request.schema_version != ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION {
            return Err(ReceiptBindingError::InvalidAcceptedReceiptAppendSchema {
                expected: ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION,
                actual: request.schema_version.clone(),
            });
        }
        require_non_empty("receipt_ref", &request.receipt_ref)?;
        require_non_empty("invocation_id", &request.invocation_id)?;
        require_non_empty("receipt_binding_ref", &request.receipt_binding_ref)?;
        if request.issuer != AcceptedReceiptAppendIssuer::RustReceiptCore {
            return Err(ReceiptBindingError::DirectAcceptedReceiptAppendOutsideRustCore);
        }
        if request.invocation_id != binding.invocation_id {
            return Err(ReceiptBindingError::InvocationResultMismatch);
        }
        if request.receipt_binding_ref != binding.binding_hash {
            return Err(ReceiptBindingError::ReceiptBindingHashMismatch);
        }
        if !binding.receipt_refs.contains(&request.receipt_ref) {
            return Err(ReceiptBindingError::ReceiptNotBoundToResult);
        }
        if request.state_root_before != binding.state_root_before
            || request.state_root_after != binding.state_root_after
            || request.resulting_head != binding.resulting_head
        {
            return Err(ReceiptBindingError::AcceptedReceiptStateRootMismatch);
        }

        let mut record = AcceptedReceiptAppendRecord {
            schema_version: ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION.to_string(),
            receipt_ref: request.receipt_ref.clone(),
            invocation_id: request.invocation_id.clone(),
            receipt_binding_ref: request.receipt_binding_ref.clone(),
            state_root_before: request.state_root_before.clone(),
            state_root_after: request.state_root_after.clone(),
            resulting_head: request.resulting_head.clone(),
            append_hash: String::new(),
        };
        record.append_hash = accepted_receipt_append_hash(&record)?;
        Ok(record)
    }
}

fn binding_hash(binding: &StepModuleReceiptBinding) -> Result<String, ReceiptBindingError> {
    let mut canonical = binding.clone();
    canonical.binding_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ReceiptBindingError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn accepted_receipt_append_hash(
    record: &AcceptedReceiptAppendRecord,
) -> Result<String, ReceiptBindingError> {
    let mut canonical = record.clone();
    canonical.append_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ReceiptBindingError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), ReceiptBindingError> {
    if value.trim().is_empty() {
        Err(ReceiptBindingError::MissingField(field))
    } else {
        Ok(())
    }
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

    fn append_request(binding: &StepModuleReceiptBinding) -> AcceptedReceiptAppendRequest {
        AcceptedReceiptAppendRequest {
            schema_version: ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION.to_string(),
            receipt_ref: "receipt:test".to_string(),
            invocation_id: binding.invocation_id.clone(),
            receipt_binding_ref: binding.binding_hash.clone(),
            issuer: AcceptedReceiptAppendIssuer::RustReceiptCore,
            state_root_before: binding.state_root_before.clone(),
            state_root_after: binding.state_root_after.clone(),
            resulting_head: binding.resulting_head.clone(),
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

    #[test]
    fn rust_receipt_core_appends_bound_accepted_receipt() {
        let binding = ReceiptBinder
            .bind_step_module_result(
                &invocation(),
                &result(),
                vec!["sha256:head-before".to_string()],
            )
            .expect("valid binding");

        let record = ReceiptBinder
            .append_accepted_receipt(&append_request(&binding), &binding)
            .expect("receipt append record");

        assert_eq!(
            record.schema_version,
            ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION
        );
        assert_eq!(record.receipt_ref, "receipt:test");
        assert_eq!(record.receipt_binding_ref, binding.binding_hash);
        assert!(record.append_hash.starts_with("sha256:"));
    }

    #[test]
    fn direct_accepted_receipt_append_outside_the_rust_core_fails() {
        assert_eq!(
            DIRECT_ACCEPTED_RECEIPT_APPEND_NEGATIVE_CONFORMANCE,
            "direct accepted receipt append outside the Rust core fails"
        );
        let binding = ReceiptBinder
            .bind_step_module_result(
                &invocation(),
                &result(),
                vec!["sha256:head-before".to_string()],
            )
            .expect("valid binding");
        let mut request = append_request(&binding);
        request.issuer = AcceptedReceiptAppendIssuer::DaemonJsFacade;

        let error = ReceiptBinder
            .append_accepted_receipt(&request, &binding)
            .expect_err("non-core append must fail");

        assert_eq!(
            error,
            ReceiptBindingError::DirectAcceptedReceiptAppendOutsideRustCore
        );
    }

    #[test]
    fn accepted_receipt_append_requires_receipt_binding_match() {
        let binding = ReceiptBinder
            .bind_step_module_result(
                &invocation(),
                &result(),
                vec!["sha256:head-before".to_string()],
            )
            .expect("valid binding");
        let mut request = append_request(&binding);
        request.receipt_binding_ref = "sha256:drifted-binding".to_string();

        let error = ReceiptBinder
            .append_accepted_receipt(&request, &binding)
            .expect_err("receipt binding hash must match");

        assert_eq!(error, ReceiptBindingError::ReceiptBindingHashMismatch);
    }
}
