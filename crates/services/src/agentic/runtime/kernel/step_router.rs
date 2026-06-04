use super::step_module::{
    StepModuleBackend, StepModuleInvocation, StepModuleProjectionStatus, StepModuleResult,
    StepModuleValidationError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const STEP_MODULE_ROUTER_ADMISSION_SCHEMA_VERSION: &str = "ioi.step_module_router_admission.v1";
pub const DIRECT_JS_AUTHORITATIVE_MUTATION_NEGATIVE_CONFORMANCE: &str =
    "direct JS authoritative mutation fails";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepModuleRouterError {
    InvalidInvocation(Vec<StepModuleValidationError>),
    InvalidResult(Vec<StepModuleValidationError>),
    InvocationResultMismatch,
    DirectJsAuthoritativeMutation,
    HashFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepModuleExecutionAdmissionRecord {
    pub schema_version: String,
    pub invocation_id: String,
    pub module_id: String,
    pub backend: StepModuleBackend,
    pub authoritative_transition: bool,
    pub receipt_refs: Vec<String>,
    pub agentgres_operation_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resulting_head: Option<String>,
    pub admission_hash: String,
}

#[derive(Debug, Default, Clone)]
pub struct StepModuleRouterCore;

impl StepModuleRouterCore {
    pub fn admit_execution(
        &self,
        invocation: &StepModuleInvocation,
        result: &StepModuleResult,
    ) -> Result<StepModuleExecutionAdmissionRecord, StepModuleRouterError> {
        invocation
            .validate()
            .map_err(StepModuleRouterError::InvalidInvocation)?;
        result
            .validate()
            .map_err(StepModuleRouterError::InvalidResult)?;
        if invocation.invocation_id != result.invocation_id {
            return Err(StepModuleRouterError::InvocationResultMismatch);
        }

        let authoritative_transition = is_authoritative_transition(result);
        if invocation.execution.backend == StepModuleBackend::DaemonJs && authoritative_transition {
            return Err(StepModuleRouterError::DirectJsAuthoritativeMutation);
        }

        let mut record = StepModuleExecutionAdmissionRecord {
            schema_version: STEP_MODULE_ROUTER_ADMISSION_SCHEMA_VERSION.to_string(),
            invocation_id: invocation.invocation_id.clone(),
            module_id: invocation.module_ref.id.clone(),
            backend: invocation.execution.backend.clone(),
            authoritative_transition,
            receipt_refs: result.receipt_refs.clone(),
            agentgres_operation_refs: result.agentgres_operation_refs.clone(),
            state_root_after: result.state_root_after.clone(),
            resulting_head: result.resulting_head.clone(),
            admission_hash: String::new(),
        };
        record.admission_hash = admission_hash(&record)?;
        Ok(record)
    }
}

fn is_authoritative_transition(result: &StepModuleResult) -> bool {
    !result.agentgres_operation_refs.is_empty()
        || result.state_root_after.is_some()
        || result.resulting_head.is_some()
        || result.workflow_projection.status == StepModuleProjectionStatus::Live
}

fn admission_hash(
    record: &StepModuleExecutionAdmissionRecord,
) -> Result<String, StepModuleRouterError> {
    let mut canonical = record.clone();
    canonical.admission_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| StepModuleRouterError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::step_module::{
        StepModuleActor, StepModuleAuthority, StepModuleCustody, StepModuleExecution,
        StepModuleInput, StepModuleKind, StepModuleNext, StepModulePlaintextPolicy,
        StepModulePrivacyProfile, StepModuleRef, StepModuleStatus, StepModuleWorkflowProjection,
        STEP_MODULE_INVOCATION_SCHEMA_VERSION, STEP_MODULE_RESULT_SCHEMA_VERSION,
    };

    fn invocation(backend: StepModuleBackend) -> StepModuleInvocation {
        StepModuleInvocation {
            schema_version: STEP_MODULE_INVOCATION_SCHEMA_VERSION.to_string(),
            invocation_id: "invocation://step-router-test".to_string(),
            run_id: "run:step-router".to_string(),
            task_id: "task:step-router".to_string(),
            thread_id: None,
            workflow_graph_id: Some("workflow:step-router".to_string()),
            workflow_node_id: Some("node:step-router".to_string()),
            context_chamber_ref: None,
            action_proposal_ref: "action:step-router".to_string(),
            gate_result_ref: "gate:step-router".to_string(),
            module_ref: StepModuleRef {
                kind: if backend == StepModuleBackend::DaemonJs {
                    StepModuleKind::DaemonNativeTool
                } else {
                    StepModuleKind::WorkloadJob
                },
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
                projection_watermark: Some("domain_seq:step-router".to_string()),
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
                backend,
                idempotency_key: "idem:step-router".to_string(),
                deadline_ms: 1_000,
                resource_lease_ref: None,
                retry_policy_ref: None,
            },
        }
    }

    fn result(status: StepModuleProjectionStatus) -> StepModuleResult {
        StepModuleResult {
            schema_version: STEP_MODULE_RESULT_SCHEMA_VERSION.to_string(),
            invocation_id: "invocation://step-router-test".to_string(),
            status: StepModuleStatus::Success,
            execution_result_ref: "result:step-router".to_string(),
            normalized_observation_ref: "observation:step-router".to_string(),
            receipt_refs: vec!["receipt:step-router".to_string()],
            artifact_refs: vec![],
            payload_refs: vec![],
            agentgres_operation_refs: vec![],
            state_root_after: None,
            resulting_head: None,
            workflow_projection: StepModuleWorkflowProjection {
                workflow_graph_id: "workflow:step-router".to_string(),
                workflow_node_id: "node:step-router".to_string(),
                component_kind: "CodingToolNode".to_string(),
                status,
                attempt_id: "attempt:step-router".to_string(),
                evidence_refs: vec![],
                receipt_refs: vec!["receipt:step-router".to_string()],
            },
            next: StepModuleNext {
                model_reentry_required: false,
                verifier_required: false,
            },
        }
    }

    fn authoritative_result() -> StepModuleResult {
        let mut result = result(StepModuleProjectionStatus::Live);
        result.agentgres_operation_refs = vec!["agentgres://operation/step-router".to_string()];
        result.state_root_after = Some("sha256:after".to_string());
        result.resulting_head = Some("sha256:head-after".to_string());
        result
    }

    #[test]
    fn daemon_js_shadow_projection_is_not_authoritative() {
        let record = StepModuleRouterCore
            .admit_execution(
                &invocation(StepModuleBackend::DaemonJs),
                &result(StepModuleProjectionStatus::Shadow),
            )
            .expect("projection-only JS facade is allowed");

        assert_eq!(record.backend, StepModuleBackend::DaemonJs);
        assert!(!record.authoritative_transition);
        assert!(record.admission_hash.starts_with("sha256:"));
    }

    #[test]
    fn direct_js_authoritative_mutation_fails() {
        assert_eq!(
            DIRECT_JS_AUTHORITATIVE_MUTATION_NEGATIVE_CONFORMANCE,
            "direct JS authoritative mutation fails"
        );

        let error = StepModuleRouterCore
            .admit_execution(
                &invocation(StepModuleBackend::DaemonJs),
                &authoritative_result(),
            )
            .expect_err("daemon_js cannot admit authoritative mutation");

        assert_eq!(error, StepModuleRouterError::DirectJsAuthoritativeMutation);
    }

    #[test]
    fn rust_workload_authoritative_transition_is_router_admitted() {
        let record = StepModuleRouterCore
            .admit_execution(
                &invocation(StepModuleBackend::WorkloadGrpc),
                &authoritative_result(),
            )
            .expect("Rust/workload backend can carry authoritative transition");

        assert_eq!(record.backend, StepModuleBackend::WorkloadGrpc);
        assert!(record.authoritative_transition);
        assert_eq!(
            record.agentgres_operation_refs,
            vec!["agentgres://operation/step-router"]
        );
    }
}
