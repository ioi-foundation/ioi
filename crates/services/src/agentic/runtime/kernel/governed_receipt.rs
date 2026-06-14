use serde::Deserialize;
use serde_json::{json, Value};

use super::ctee::{CteeNodeTrust, PrivateWorkspaceCteeModule};
use super::marketplace::{
    WorkerServicePackageInvocationCore, WorkerServicePackageInvocationRequest,
};
use super::receipt_binder::{
    AcceptedReceiptAppendIssuer, AcceptedReceiptAppendRequest, ReceiptBinder,
    ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION,
};
use super::step_module::{StepModuleBackend, StepModuleInvocation, StepModuleKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedReceiptError {
    code: &'static str,
    message: String,
}

impl GovernedReceiptError {
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
pub struct CteePrivateWorkspaceProtocolRequest {
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub invocation: StepModuleInvocation,
    pub node_trust: CteeNodeTrust,
    #[serde(default)]
    pub expected_heads: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct WorkerServicePackageInvocationBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub request: WorkerServicePackageInvocationRequest,
}

pub fn execute_private_workspace_ctee_action_protocol_response(
    request: CteePrivateWorkspaceProtocolRequest,
) -> Result<Value, GovernedReceiptError> {
    if request.invocation.module_ref.kind != StepModuleKind::PrivateWorkspaceCteeAction
        || request.invocation.execution.backend != StepModuleBackend::CteeOperator
    {
        return Err(GovernedReceiptError::new(
            "ctee_step_module_required",
            "private workspace cTEE execution requires a ctee_operator StepModule invocation"
                .to_string(),
        ));
    }
    PrivateWorkspaceCteeModule
        .reject_caller_supplied_expected_heads(&request.expected_heads)
        .map_err(|error| {
            GovernedReceiptError::new("ctee_execution_invalid", format!("{error:?}"))
        })?;
    let record = PrivateWorkspaceCteeModule
        .execute_and_admit(&request.invocation, &request.node_trust)
        .map_err(|error| {
            GovernedReceiptError::new("ctee_execution_invalid", format!("{error:?}"))
        })?;
    let accepted_receipt_append = ReceiptBinder
        .append_accepted_receipt(
            &AcceptedReceiptAppendRequest {
                schema_version: ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION.to_string(),
                receipt_ref: record.receipt.receipt_ref.clone(),
                invocation_id: record.result.invocation_id.clone(),
                receipt_binding_ref: record.receipt_binding.binding_hash.clone(),
                issuer: AcceptedReceiptAppendIssuer::RustReceiptCore,
                state_root_before: record.receipt_binding.state_root_before.clone(),
                state_root_after: record.receipt_binding.state_root_after.clone(),
                resulting_head: record.receipt_binding.resulting_head.clone(),
            },
            &record.receipt_binding,
        )
        .map_err(|error| {
            GovernedReceiptError::new("accepted_receipt_append_invalid", format!("{error:?}"))
        })?;
    let receipt_refs = record.result.receipt_refs.clone();
    let evidence_refs = record.projection.evidence_refs.clone();
    Ok(json!({
        "schema_version": "ioi.runtime.ctee_private_workspace_admission.v1",
        "object": "ioi.runtime_ctee_private_workspace_admission",
        "status": "admitted",
        "action_executed": true,
        "source": "rust_ctee_private_workspace_protocol",
        "backend": "ctee_operator",
        "thread_id": request.thread_id,
        "agent_id": request.agent_id,
        "invocation_id": record.result.invocation_id.clone(),
        "receipt_ref": record.receipt.receipt_ref.clone(),
        "record": record.clone(),
        "receipt": record.receipt.clone(),
        "result": record.result.clone(),
        "receipt_binding": record.receipt_binding.clone(),
        "accepted_receipt_append": accepted_receipt_append,
        "agentgres_admission": record.agentgres_admission.clone(),
        "projection_record": record.projection.clone(),
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
    }))
}

pub fn admit_worker_service_package_invocation_response(
    request: WorkerServicePackageInvocationBridgeRequest,
) -> Result<Value, GovernedReceiptError> {
    let record = WorkerServicePackageInvocationCore
        .admit_invocation(&request.request)
        .map_err(|error| {
            GovernedReceiptError::new(
                "worker_service_package_invocation_invalid",
                format!("{error:?}"),
            )
        })?;
    let receipt_ref = record.receipt_refs.first().cloned().ok_or_else(|| {
        GovernedReceiptError::new(
            "receipt_ref_required",
            "worker/service package invocation requires a receipt ref".to_string(),
        )
    })?;
    let accepted_receipt_append = ReceiptBinder
        .append_accepted_receipt(
            &AcceptedReceiptAppendRequest {
                schema_version: ACCEPTED_RECEIPT_APPEND_SCHEMA_VERSION.to_string(),
                receipt_ref,
                invocation_id: record.invocation_id.clone(),
                receipt_binding_ref: record.receipt_binding.binding_hash.clone(),
                issuer: AcceptedReceiptAppendIssuer::RustReceiptCore,
                state_root_before: record.receipt_binding.state_root_before.clone(),
                state_root_after: record.receipt_binding.state_root_after.clone(),
                resulting_head: record.receipt_binding.resulting_head.clone(),
            },
            &record.receipt_binding,
        )
        .map_err(|error| {
            GovernedReceiptError::new("accepted_receipt_append_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "schema_version": "ioi.runtime.worker_service_package_admission.v1",
        "object": "ioi.runtime_worker_service_package_admission",
        "status": "admitted",
        "invocation_admitted": true,
        "source": "rust_worker_service_package_invocation_command",
        "backend": request.backend.unwrap_or_else(|| "rust_package_invocation".to_string()),
        "thread_id": request.thread_id,
        "agent_id": request.agent_id,
        "record": record.clone(),
        "package_kind": record.package_kind.clone(),
        "package_ref": record.package_ref.clone(),
        "manifest_ref": record.manifest_ref.clone(),
        "invocation_id": record.invocation_id.clone(),
        "router_admission": record.router_admission.clone(),
        "receipt_binding": record.receipt_binding.clone(),
        "accepted_receipt_append": accepted_receipt_append,
        "agentgres_admission": record.agentgres_admission.clone(),
        "projection_record": record.projection.clone(),
        "receipt_refs": record.receipt_refs.clone(),
        "artifact_refs": record.artifact_refs.clone(),
        "payload_refs": record.payload_refs.clone(),
        "authority_grant_refs": record.authority_grant_refs.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::ctee::CteeNodeTrust;
    use crate::agentic::runtime::kernel::marketplace::{
        WorkerServicePackageKind, WORKER_SERVICE_PACKAGE_INVOCATION_SCHEMA_VERSION,
    };
    use crate::agentic::runtime::kernel::step_module::{
        StepModuleActor, StepModuleAuthority, StepModuleCustody, StepModuleExecution,
        StepModuleInput, StepModuleNext, StepModulePlaintextPolicy, StepModulePrivacyProfile,
        StepModuleProjectionStatus, StepModuleRef, StepModuleResult, StepModuleStatus,
        StepModuleWorkflowProjection, STEP_MODULE_INVOCATION_SCHEMA_VERSION,
        STEP_MODULE_RESULT_SCHEMA_VERSION,
    };

    fn ctee_invocation() -> StepModuleInvocation {
        StepModuleInvocation {
            schema_version: STEP_MODULE_INVOCATION_SCHEMA_VERSION.to_string(),
            invocation_id: "invocation://ctee.governed-receipt.test".to_string(),
            run_id: "run:ctee".to_string(),
            task_id: "task:ctee".to_string(),
            thread_id: Some("thread:ctee".to_string()),
            workflow_graph_id: Some("workflow.ctee".to_string()),
            workflow_node_id: Some("node.ctee.private-workspace".to_string()),
            context_chamber_ref: Some("chamber:ctee".to_string()),
            action_proposal_ref: "action:ctee:private-workspace".to_string(),
            gate_result_ref: "gate:ctee:private-workspace".to_string(),
            module_ref: StepModuleRef {
                kind: StepModuleKind::PrivateWorkspaceCteeAction,
                id: "private_workspace.mount".to_string(),
                version: "1".to_string(),
                manifest_ref: Some("module://ctee/private-workspace@1".to_string()),
            },
            actor: StepModuleActor {
                actor_id: "runtime:hypervisor-daemon".to_string(),
                runtime_node_ref: "node://private-workspace".to_string(),
            },
            authority: StepModuleAuthority {
                authority_grant_refs: vec!["grant://ctee/private-workspace".to_string()],
                policy_hash: "sha256:ctee-policy".to_string(),
                primitive_capabilities: vec!["prim:private_workspace.mount".to_string()],
                authority_scopes: vec!["scope:ctee.private_workspace".to_string()],
                approval_ref: Some("approval://declassify".to_string()),
            },
            input: StepModuleInput {
                input_hash: "sha256:ctee-input".to_string(),
                expected_schema_ref: "schema://ctee/private-workspace/input".to_string(),
                context_refs: vec!["context://workspace".to_string()],
                artifact_refs: vec![],
                payload_refs: vec!["payload://encrypted/private-workspace".to_string()],
                state_root_before: Some("sha256:ctee-before".to_string()),
                projection_watermark: Some("domain_seq:ctee-before".to_string()),
                data_plane_handle: None,
            },
            custody: StepModuleCustody {
                privacy_profile: StepModulePrivacyProfile::PrivateWorkspaceCtee,
                plaintext_policy: StepModulePlaintextPolicy {
                    node_plaintext_allowed: false,
                    declassification_required: true,
                },
                custody_proof_ref: Some("custody://proof".to_string()),
                leakage_profile_ref: Some("leakage://profile".to_string()),
            },
            execution: StepModuleExecution {
                backend: StepModuleBackend::CteeOperator,
                idempotency_key: "idem:ctee".to_string(),
                deadline_ms: 1_000,
                resource_lease_ref: Some("lease://ctee".to_string()),
                retry_policy_ref: None,
            },
        }
    }

    fn worker_invocation() -> StepModuleInvocation {
        StepModuleInvocation {
            schema_version: STEP_MODULE_INVOCATION_SCHEMA_VERSION.to_string(),
            invocation_id: "invocation://worker.governed-receipt.test".to_string(),
            run_id: "run:worker".to_string(),
            task_id: "task:worker".to_string(),
            thread_id: Some("thread:worker".to_string()),
            workflow_graph_id: Some("workflow.worker".to_string()),
            workflow_node_id: Some("node.worker".to_string()),
            context_chamber_ref: None,
            action_proposal_ref: "action:worker".to_string(),
            gate_result_ref: "gate:worker".to_string(),
            module_ref: StepModuleRef {
                kind: StepModuleKind::RustWasmServiceModule,
                id: "worker.test".to_string(),
                version: "1".to_string(),
                manifest_ref: Some("module://worker/test@1".to_string()),
            },
            actor: StepModuleActor {
                actor_id: "runtime:hypervisor-daemon".to_string(),
                runtime_node_ref: "node://local".to_string(),
            },
            authority: StepModuleAuthority {
                authority_grant_refs: vec!["grant://worker/test".to_string()],
                policy_hash: "sha256:worker-policy".to_string(),
                primitive_capabilities: vec!["prim:worker.invoke".to_string()],
                authority_scopes: vec![],
                approval_ref: None,
            },
            input: StepModuleInput {
                input_hash: "sha256:worker-input".to_string(),
                expected_schema_ref: "schema://worker/test/input".to_string(),
                context_refs: vec![],
                artifact_refs: vec![],
                payload_refs: vec!["payload://worker/input".to_string()],
                state_root_before: Some("sha256:worker-before".to_string()),
                projection_watermark: Some("domain_seq:worker-before".to_string()),
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
                backend: StepModuleBackend::RustWasm,
                idempotency_key: "idem:worker".to_string(),
                deadline_ms: 1_000,
                resource_lease_ref: None,
                retry_policy_ref: None,
            },
        }
    }

    fn worker_result() -> StepModuleResult {
        StepModuleResult {
            schema_version: STEP_MODULE_RESULT_SCHEMA_VERSION.to_string(),
            invocation_id: "invocation://worker.governed-receipt.test".to_string(),
            status: StepModuleStatus::Success,
            execution_result_ref: "result://worker/test".to_string(),
            normalized_observation_ref: "observation://worker/test".to_string(),
            receipt_refs: vec!["receipt://worker/test".to_string()],
            artifact_refs: vec!["artifact://worker/output".to_string()],
            payload_refs: vec!["payload://worker/output".to_string()],
            agentgres_operation_refs: vec![],
            state_root_after: None,
            resulting_head: None,
            workflow_projection: StepModuleWorkflowProjection {
                workflow_graph_id: "workflow.worker".to_string(),
                workflow_node_id: "node.worker".to_string(),
                component_kind: "WorkerServicePackageNode".to_string(),
                status: StepModuleProjectionStatus::Live,
                attempt_id: "attempt://worker/test".to_string(),
                evidence_refs: vec!["evidence://worker/test".to_string()],
                receipt_refs: vec!["receipt://worker/test".to_string()],
            },
            next: StepModuleNext {
                model_reentry_required: false,
                verifier_required: false,
            },
        }
    }

    #[test]
    fn rust_core_shapes_ctee_receipt_protocol_response() {
        let response = execute_private_workspace_ctee_action_protocol_response(
            CteePrivateWorkspaceProtocolRequest {
                thread_id: Some("thread:ctee".to_string()),
                agent_id: Some("agent:ctee".to_string()),
                invocation: ctee_invocation(),
                node_trust: CteeNodeTrust {
                    runtime_node_ref: "node://private-workspace".to_string(),
                    trusted_for_plaintext: true,
                    attestation_ref: Some("attestation://ctee".to_string()),
                },
                expected_heads: vec![],
            },
        )
        .expect("ctee response");

        assert_eq!(response["source"], "rust_ctee_private_workspace_protocol");
        assert_eq!(
            response["schema_version"],
            "ioi.runtime.ctee_private_workspace_admission.v1"
        );
        assert_eq!(
            response["object"],
            "ioi.runtime_ctee_private_workspace_admission"
        );
        assert_eq!(response["status"], "admitted");
        assert_eq!(response["action_executed"], true);
        assert_eq!(response["thread_id"], "thread:ctee");
        assert_eq!(response["agent_id"], "agent:ctee");
        assert_eq!(
            response["invocation_id"],
            "invocation://ctee.governed-receipt.test"
        );
        assert_eq!(response["receipt_ref"], response["receipt"]["receipt_ref"]);
        assert_eq!(
            response["accepted_receipt_append"]["receipt_ref"],
            response["receipt"]["receipt_ref"]
        );
        assert_eq!(
            response["projection_record"]["component_kind"],
            "PrivateWorkspaceCteeAction"
        );
    }

    #[test]
    fn rust_core_shapes_worker_service_package_receipt_response() {
        let response = admit_worker_service_package_invocation_response(
            WorkerServicePackageInvocationBridgeRequest {
                backend: Some("rust_package_invocation".to_string()),
                thread_id: Some("thread:worker".to_string()),
                agent_id: Some("agent:worker".to_string()),
                request: WorkerServicePackageInvocationRequest {
                    schema_version: WORKER_SERVICE_PACKAGE_INVOCATION_SCHEMA_VERSION.to_string(),
                    package_kind: WorkerServicePackageKind::WorkerPackage,
                    package_ref: "worker://test".to_string(),
                    manifest_ref: "module://worker/test@1".to_string(),
                    invocation: worker_invocation(),
                    result: worker_result(),
                    expected_heads: vec![],
                },
            },
        )
        .expect("worker response");

        assert_eq!(
            response["source"],
            "rust_worker_service_package_invocation_command"
        );
        assert_eq!(
            response["schema_version"],
            "ioi.runtime.worker_service_package_admission.v1"
        );
        assert_eq!(
            response["object"],
            "ioi.runtime_worker_service_package_admission"
        );
        assert_eq!(response["status"], "admitted");
        assert_eq!(response["invocation_admitted"], true);
        assert_eq!(response["thread_id"], "thread:worker");
        assert_eq!(response["agent_id"], "agent:worker");
        assert_eq!(response["package_kind"], "worker_package");
        assert_eq!(response["package_ref"], "worker://test");
        assert_eq!(response["manifest_ref"], "module://worker/test@1");
        assert_eq!(
            response["invocation_id"],
            "invocation://worker.governed-receipt.test"
        );
        assert_eq!(
            response["accepted_receipt_append"]["receipt_ref"],
            "receipt://worker/test"
        );
        assert_eq!(
            response["projection_record"]["component_kind"],
            "WorkerServicePackageNode"
        );
    }
}
