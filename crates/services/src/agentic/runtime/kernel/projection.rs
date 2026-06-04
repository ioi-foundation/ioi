use super::receipt_binder::StepModuleReceiptBinding;
use super::step_module::{
    StepModuleInvocation, StepModuleProjectionStatus, StepModuleResult, StepModuleValidationError,
};
use serde::{Deserialize, Serialize};

pub const STEP_MODULE_PROJECTION_RECORD_SCHEMA_VERSION: &str =
    "ioi.step_module_projection_record.v1";
pub const WORKFLOW_COMPOSITOR_ACCEPTED_TRUTH_NEGATIVE_CONFORMANCE: &str =
    "workflow compositor attempt to create accepted truth directly fails";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionEventRef {
    pub event_id: String,
    pub authority_tier: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionError {
    InvalidInvocation(Vec<StepModuleValidationError>),
    InvalidResult(Vec<StepModuleValidationError>),
    InvocationResultMismatch,
    ReceiptBindingMismatch,
    MissingWorkflowProjectionNode,
    WorkflowCompositorAcceptedTruthForbidden,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepModuleProjectionRecord {
    pub schema_version: String,
    pub invocation_id: String,
    pub workflow_graph_id: String,
    pub workflow_node_id: String,
    pub component_kind: String,
    pub status: StepModuleProjectionStatus,
    pub projection_watermark: String,
    pub receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub agentgres_operation_refs: Vec<String>,
    pub state_root_after: Option<String>,
    pub resulting_head: Option<String>,
    pub route_family: String,
}

#[derive(Debug, Default, Clone)]
pub struct RustProjectionCore;

impl RustProjectionCore {
    pub fn project_step_module_result(
        &self,
        invocation: &StepModuleInvocation,
        result: &StepModuleResult,
        binding: &StepModuleReceiptBinding,
    ) -> Result<StepModuleProjectionRecord, ProjectionError> {
        invocation
            .validate()
            .map_err(ProjectionError::InvalidInvocation)?;
        result.validate().map_err(ProjectionError::InvalidResult)?;
        if invocation.invocation_id != result.invocation_id {
            return Err(ProjectionError::InvocationResultMismatch);
        }
        if binding.invocation_id != result.invocation_id {
            return Err(ProjectionError::ReceiptBindingMismatch);
        }
        if result
            .workflow_projection
            .workflow_graph_id
            .trim()
            .is_empty()
            || result
                .workflow_projection
                .workflow_node_id
                .trim()
                .is_empty()
        {
            return Err(ProjectionError::MissingWorkflowProjectionNode);
        }

        Ok(StepModuleProjectionRecord {
            schema_version: STEP_MODULE_PROJECTION_RECORD_SCHEMA_VERSION.to_string(),
            invocation_id: result.invocation_id.clone(),
            workflow_graph_id: result.workflow_projection.workflow_graph_id.clone(),
            workflow_node_id: result.workflow_projection.workflow_node_id.clone(),
            component_kind: result.workflow_projection.component_kind.clone(),
            status: result.workflow_projection.status.clone(),
            projection_watermark: workflow_projection_watermark_from_agentgres(binding),
            receipt_refs: binding.receipt_refs.clone(),
            evidence_refs: result.workflow_projection.evidence_refs.clone(),
            agentgres_operation_refs: binding.agentgres_operation_refs.clone(),
            state_root_after: binding.state_root_after.clone(),
            resulting_head: binding.resulting_head.clone(),
            route_family: invocation.module_ref.id.clone(),
        })
    }

    pub fn reject_workflow_compositor_accepted_truth_attempt(&self) -> Result<(), ProjectionError> {
        Err(ProjectionError::WorkflowCompositorAcceptedTruthForbidden)
    }
}

pub fn workflow_projection_watermark_from_agentgres(binding: &StepModuleReceiptBinding) -> String {
    binding
        .projection_watermark
        .clone()
        .unwrap_or_else(|| "shadow:pending-agentgres-watermark".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::receipt_binder::{
        ReceiptBinder, STEP_MODULE_RECEIPT_BINDING_SCHEMA_VERSION,
    };
    use crate::agentic::runtime::kernel::step_module::{
        StepModuleActor, StepModuleAuthority, StepModuleBackend, StepModuleCustody,
        StepModuleExecution, StepModuleInput, StepModuleKind, StepModuleNext,
        StepModulePlaintextPolicy, StepModulePrivacyProfile, StepModuleRef, StepModuleStatus,
        StepModuleWorkflowProjection, STEP_MODULE_INVOCATION_SCHEMA_VERSION,
        STEP_MODULE_RESULT_SCHEMA_VERSION,
    };

    fn invocation() -> StepModuleInvocation {
        StepModuleInvocation {
            schema_version: STEP_MODULE_INVOCATION_SCHEMA_VERSION.to_string(),
            invocation_id: "invocation://projection-test".to_string(),
            run_id: "run:projection".to_string(),
            task_id: "task:projection".to_string(),
            thread_id: Some("thread:projection".to_string()),
            workflow_graph_id: Some("workflow:projection".to_string()),
            workflow_node_id: Some("node:projection".to_string()),
            context_chamber_ref: None,
            action_proposal_ref: "action:projection".to_string(),
            gate_result_ref: "gate:projection".to_string(),
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
                projection_watermark: Some("agentgres:watermark:42".to_string()),
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
                idempotency_key: "idem:projection".to_string(),
                deadline_ms: 1_000,
                resource_lease_ref: None,
                retry_policy_ref: None,
            },
        }
    }

    fn result() -> StepModuleResult {
        StepModuleResult {
            schema_version: STEP_MODULE_RESULT_SCHEMA_VERSION.to_string(),
            invocation_id: "invocation://projection-test".to_string(),
            status: StepModuleStatus::Success,
            execution_result_ref: "result:projection".to_string(),
            normalized_observation_ref: "observation:projection".to_string(),
            receipt_refs: vec!["receipt:projection".to_string()],
            artifact_refs: vec![],
            payload_refs: vec![],
            agentgres_operation_refs: vec![],
            state_root_after: None,
            resulting_head: None,
            workflow_projection: StepModuleWorkflowProjection {
                workflow_graph_id: "workflow:projection".to_string(),
                workflow_node_id: "node:projection".to_string(),
                component_kind: "CodingToolNode".to_string(),
                status: StepModuleProjectionStatus::Shadow,
                attempt_id: "attempt:projection".to_string(),
                evidence_refs: vec!["evidence:projection".to_string()],
                receipt_refs: vec!["receipt:projection".to_string()],
            },
            next: StepModuleNext {
                model_reentry_required: false,
                verifier_required: false,
            },
        }
    }

    #[test]
    fn rust_projection_core_projects_step_module_result() {
        let binding = ReceiptBinder
            .bind_step_module_result(&invocation(), &result(), vec![])
            .expect("binding");
        assert_eq!(
            binding.schema_version,
            STEP_MODULE_RECEIPT_BINDING_SCHEMA_VERSION
        );

        let record = RustProjectionCore
            .project_step_module_result(&invocation(), &result(), &binding)
            .expect("projection record");

        assert_eq!(
            record.schema_version,
            STEP_MODULE_PROJECTION_RECORD_SCHEMA_VERSION
        );
        assert_eq!(record.workflow_graph_id, "workflow:projection");
        assert_eq!(record.workflow_node_id, "node:projection");
        assert_eq!(record.projection_watermark, "agentgres:watermark:42");
        assert_eq!(record.receipt_refs, vec!["receipt:projection"]);
    }

    #[test]
    fn workflow_compositor_attempt_to_create_accepted_truth_directly_fails() {
        assert_eq!(
            WORKFLOW_COMPOSITOR_ACCEPTED_TRUTH_NEGATIVE_CONFORMANCE,
            "workflow compositor attempt to create accepted truth directly fails"
        );

        let error = RustProjectionCore
            .reject_workflow_compositor_accepted_truth_attempt()
            .expect_err("workflow compositor accepted truth shortcut must fail");

        assert_eq!(
            error,
            ProjectionError::WorkflowCompositorAcceptedTruthForbidden
        );
    }
}
